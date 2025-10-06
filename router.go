package main

import (
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	//"github.com/aeden/traceroute"
	"github.com/darren/gpac"
)

type ProxyRoute struct {
	name     string
	gateway  string
	iface    string
	net      string
	pacUrl   string
	pac      *gpac.Parser
	proxyUrl string
	user     string
	password string
}

var iface net.Interface
var defaultGw net.IP
var network *net.IPNet
var routes []*ProxyRoute
var timer *time.Timer
var forceRoute *ProxyRoute

var defaultTransport http.RoundTripper = &http.Transport{
	Proxy: nil,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}).DialContext,
	MaxIdleConns:          30,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   15 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

var defaultClient = &http.Client{Transport: defaultTransport}

func init() {
	discoverNetwork()

	const interval = time.Minute

	timer = time.NewTimer(interval)
	go func() {
		for {
			<-timer.C
			discoverNetwork()
			timer.Reset(interval)
		}
	}()
}

func loadRoutes() {
	routes = make([]*ProxyRoute, 0)
	for _, r := range configuration.Routes {
		var cfgCred *ConfigCredential
		var user string
		var password string
		if r.Credential != "" {
			cfgCred = GetCredential(r.Credential)
			if cfgCred != nil {
				user = cfgCred.User
				password = cfgCred.Password
			}
		}
		routes = append(routes, &ProxyRoute{
			name:     r.Name,
			gateway:  r.Gateway,
			iface:    r.IFace,
			net:      r.Net,
			pacUrl:   r.PacUrl,
			proxyUrl: r.ProxyUrl,
			user:     user,
			password: password,
		})
	}
	routes = append(routes, &ProxyRoute{
		name: "Direct",
	})
}

func discoverNetwork() {

	if dnsCache != nil {
		dnsCache.Purge()
	}

	var err error

	ip, diface, ipnet, err := FindGatewayAndNetwork()
	if err == nil {

		defaultGw = ip
		iface = diface
		network = ipnet

		log.Printf("Found default gateway (or local IP) %s, default interface %s with net %s", defaultGw.String(), iface.Name, network.String())

	} else {
		log.Printf("Unable to determine default interface: %+v", err)
	}

	//fmt.Printf("Default gateway: %s\n", defaultGw.String())

	/*ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, ni := range ifaces {
		fmt.Printf("Found interface %s [%s]\n", ni.Name, ni.HardwareAddr)
		addrs, err := ni.Addrs()
		if err != nil {
			fmt.Printf(" # error: %+v\n", err)
		} else {
			for _, a := range addrs {
				switch a.(type) {
				case *net.IPAddr:
					ip := a.(*net.IPAddr)
					fmt.Printf(" + addr: %s (%s) [%s]\n", ip.IP.String(), ip.IP.Mask(ip.IP.DefaultMask()).String(), ip.Network())
				case *net.IPNet:
					ip := a.(*net.IPNet)
					fmt.Printf(" + addr: %s (%s) [%s]\n", ip.IP.String(), ip.IP.Mask(ip.IP.DefaultMask()).String(), ip.Network())
				default:
					fmt.Printf(" + addr: %s [%s]\n", a.String(), a.Network())
				}
			}
		}
	}*/
}

func FindGatewayAndNetwork() (net.IP, net.Interface, *net.IPNet, error) {
	var ip net.IP
	var iface net.Interface

	ipFound := false
	ipIsLocal := false

	/*traceOpts := &traceroute.TracerouteOptions{}
	traceOpts.SetMaxHops(1)

	result, err := traceroute.Traceroute("8.8.8.8", traceOpts)
	if err != nil {
		log.Printf("Error: method traceroute failed: %+v", err)
	} else {
		ip = net.ParseIP(result.Hops[0].AddressString())
		ipFound = true
	}*/

	if !ipFound {
		oip, err := GetOutboundIP()
		if err != nil {
			log.Printf("Error: method UDP out failed: %+v", err)
			return ip, iface, nil, err
		} else {
			ip = oip
			ipFound = true
			ipIsLocal = true
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return ip, iface, nil, err
	}
	for _, liface := range interfaces {
		addrs, err := liface.Addrs()
		if err != nil {
			return ip, iface, nil, err
		}
		for _, addr := range addrs {
			_, ifaceIpNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				return ip, iface, nil, err
			}
			if ifaceIpNet.Contains(ip) {
				iface = liface
				if ipIsLocal {
					// Try to find gateway
				}
				return ip, iface, ifaceIpNet, nil
			}
		}
	}

	return ip, iface, nil, fmt.Errorf("unable to find ip and default interface")

}

func GetOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP, nil
}

func (p *ProxyRoute) Check() error {
	if p.pacUrl != "" && p.pac == nil {
		digest := md5.New()
		digestBytes := digest.Sum([]byte(p.pacUrl))
		cachedFile := GetCacheDir() + fmt.Sprintf("/pac-%x", digestBytes)
		f, err := os.Open(cachedFile)
		loadedFromCache := false
		if err == nil {
			defer f.Close()
			bytes, err := io.ReadAll(f)
			if err == nil {
				p.pac, err = gpac.New(string(bytes))
				if err != nil {
					return err
				}
				loadedFromCache = true
			}
		}
		if !loadedFromCache {
			resp, err := defaultClient.Get(p.pacUrl)
			if err != nil {
				return err
			}

			bytes, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return err
			}

			p.pac, err = gpac.New(string(bytes))
			if err != nil {
				return err
			} else {
				f, err := os.Create(cachedFile)
				if err == nil {
					defer f.Close()
					_, err := f.Write(bytes)
					if err != nil {
						log.Printf("Error caching PAC file: %+v", err)
					}
				} else {
					log.Printf("Error creating PAC cache file: %+v", err)
				}
			}
		}
	}

	return nil
}

func (p *ProxyRoute) IsApplicable() bool {
	if p.Check() != nil {
		return false
	}
	if p.gateway != "" && (defaultGw == nil || defaultGw.String() != p.gateway) {
		return false
	}
	if p.iface != "" && iface.Name != p.iface {
		return false
	}
	if p.net != "" && network.String() != p.net {
		return false
	}
	return true
}

func (p *ProxyRoute) FindProxy(urlStr string) *gpac.Proxy {
	if p.pac != nil {
		proxies, err := p.pac.FindProxy(urlStr)
		if err == nil {
			return proxies[0]
		}
	} else if p.proxyUrl != "" {
		pUrl, err := url.Parse(p.proxyUrl)
		if err != nil {
			return &gpac.Proxy{
				Type:    "PROXY",
				Address: p.proxyUrl,
			}
		}
		return &gpac.Proxy{
			Type:    "PROXY",
			Address: pUrl.Host,
		}
	}
	return &gpac.Proxy{
		Type: "DIRECT",
	}
}

func (p *ProxyRoute) Do(req *http.Request) (*http.Response, error) {
	if p.pac != nil {
		req.SetBasicAuth(p.user, p.password)
		return p.pac.Do(req)
	}
	newReq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, err
	}
	return defaultClient.Do(newReq)
}

func GetApplicableRoute() *ProxyRoute {
	if forceRoute != nil {
		err := forceRoute.Check()
		if err == nil {
			return forceRoute
		} else {
			log.Printf("Error checking route %s: %+v", forceRoute.name, err)
		}
	}
	for _, r := range routes {
		if r.IsApplicable() {
			return r
		}
	}
	return nil
}
