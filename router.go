package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/darren/gpac"
	"github.com/jackpal/gateway"
)

type ProxyRoute struct {
	gateway  string
	iface    string
	pacUrl   string
	pac      *gpac.Parser
	user     string
	password string
}

var iface net.IP
var defaultGw net.IP
var routes []*ProxyRoute
var timer *time.Timer

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
			gateway:  r.Gateway,
			pacUrl:   r.PacUrl,
			user:     user,
			password: password,
		})
	}
	routes = append(routes, &ProxyRoute{})
}

func discoverNetwork() {

	var err error

	iface, err = gateway.DiscoverInterface()
	if err != nil {
		fmt.Printf("Error for default interface: %+v\n", err)
	}
	//fmt.Printf("Default interface: %s\n", iface.String())
	defaultGw, err = gateway.DiscoverGateway()
	if err != nil {
		fmt.Printf("Error for default gateway: %+v\n", err)
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

func (p *ProxyRoute) Check() error {
	if p.pacUrl != "" && p.pac == nil {
		resp, err := http.DefaultClient.Get(p.pacUrl)
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
	return true
}

func (p *ProxyRoute) FindProxy(urlStr string) *gpac.Proxy {
	if p.pac != nil {
		proxies, err := p.pac.FindProxy(urlStr)
		if err == nil {
			return proxies[0]
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
	return http.DefaultClient.Do(newReq)
}

func GetApplicableRoute() *ProxyRoute {
	for _, r := range routes {
		if r.IsApplicable() {
			return r
		}
	}
	return nil
}
