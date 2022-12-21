package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Azure/go-ntlmssp"
	"github.com/getlantern/systray"
)

type MyRoundTripper struct {
	conn net.Conn
}

func main() {

	fmt.Println("Available interfaces:")
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			fmt.Printf(" - %s\n", iface.Name)
		}
	} else {
		fmt.Printf("Error: %+v\n", err)
	}

	loadConfiguration()

	go func() {

		server2, err := net.Listen("tcp", configuration.Address)
		if err != nil {
			log.Fatal(err)
		}
		for {
			c, err := server2.Accept()
			if err != nil {
				log.Printf("Error accepting connection: %+v", err)
				continue
			}
			go handleConn(c)
		}

	}()

	systray.Run(systrayReady, systrayExit)

}

func handleConn(c net.Conn) {
	br := bufio.NewReader(c)
	reader := textproto.NewReader(br)
	line, err := reader.ReadLine()
	if err != nil {
		log.Printf("Unexpected error: %+v", err)
		handleError(c, http.StatusBadRequest)
	} else {
		method, rest, ok := strings.Cut(line, " ")
		uri, proto, ok2 := strings.Cut(rest, " ")
		if !ok || !ok2 {
			log.Printf("Error parsing first line: %s %s %v %s %s %v", method, rest, ok, uri, proto, ok2)
			handleError(c, http.StatusBadRequest)
		} else {
			//log.Println(line)
			var pUrl *url.URL
			if method == "CONNECT" {
				pUrl, err = url.Parse("http://" + uri)
				if err != nil {
					handleError(c, http.StatusBadRequest)
					return
				}
			} else {
				pUrl, err = url.Parse(uri)
				if err != nil {
					handleError(c, http.StatusBadRequest)
					return
				}
			}

			route := GetApplicableRoute()

			proxy := route.FindProxy(pUrl.String())

			//log.Printf("Using %s for %s", proxy.Type, pUrl.String())

			pos := strings.Index(pUrl.Host, ":")
			if pos >= 0 {
				pos := strings.Index(pUrl.Host[pos+1:], ":")
				if pos >= 0 {
					if pUrl.Host[0] != '[' {
						pos := strings.LastIndex(pUrl.Host, ":")
						pUrl.Host = "[" + pUrl.Host[:pos] + "]" + pUrl.Host[pos:]
					}
				}
			}
			host, port, err := net.SplitHostPort(pUrl.Host)
			if err != nil {
				host = pUrl.Host
				port = "80"
			} else if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}

			oldHost := host

			ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip4", host)
			if err != nil {
				log.Printf("Error in DNS lookup for %s: %+v", host, err)
			} else if len(ips) > 0 {
				log.Printf("%s translated to %s", host, ips[0])
				host = ips[0].String()
			}

			log.Printf("Proxying %s (%s) through %s: %s", oldHost, host, proxy.Type, proxy.Address)

			if proxy.Type == "DIRECT" {

				upstream, err := net.Dial("tcp", host+":"+port)
				if err != nil {
					handleError(c, http.StatusBadGateway)
					log.Printf("Error connecting to %s:%s: %+v", host, port, err)
					return
				}
				if method == "CONNECT" {
					c.Write([]byte(proto + " 200 Connection Established\r\n\r\n"))
				} else {
					upstream.Write([]byte(method + " " + pUrl.Path + " " + proto + "\r\n"))
					for {
						line, _ = reader.ReadLine()
						upstream.Write([]byte(line + "\r\n"))
						if strings.TrimSpace(line) == "" {
							break
						}
					}
				}

				transfer(c, upstream)

			} else {

				upstream, err := net.Dial("tcp", proxy.Address)
				if err != nil {
					log.Printf("Erorr connecting to proxy %s: %+v", proxy.Address, err)
					handleError(c, http.StatusBadGateway)
					return
				}
				newReq, err := http.NewRequest("CONNECT", "http://"+host+":"+port, nil)
				if err != nil {
					log.Printf("Error creating connect request to %s:%s: %+v", host, port, err)
					handleError(c, http.StatusInternalServerError)
					return
				}
				newReq.Host = host + ":" + port
				if route.user != "" && route.password != "" {
					newReq.SetBasicAuth(route.user, route.password)
				}
				transp := ntlmssp.Negotiator{
					RoundTripper: MyRoundTripper{
						conn: upstream,
					},
				}
				resp, err := transp.RoundTrip(newReq)
				if err != nil {
					log.Printf("Error: %+v", err)
					handleError(c, http.StatusBadGateway)
					return
				}

				if resp.StatusCode == 200 {

					log.Printf("Got 200 for connecting to %s:%s through %s (%s)", host, port, proxy.Address, method)

					if method == "CONNECT" {
						c.Write([]byte(proto + " 200 Connection Established\r\n\r\n"))
					} else {
						upstream.Write([]byte(method + " " + pUrl.Path + " " + proto + "\r\n"))
						for {
							line, _ = reader.ReadLine()
							upstream.Write([]byte(line + "\r\n"))
							if strings.TrimSpace(line) == "" {
								break
							}
						}
					}
					transfer(c, upstream)

				} else {
					log.Printf("Error connecting to %s:%s through %s: %d", host, port, proxy.Address, resp.StatusCode)
					handleError(c, http.StatusBadGateway)
				}

			}
		}
	}
}

func handleError(c net.Conn, status int) {
	c.Write([]byte("HTTP/1.0 " + strconv.FormatInt(int64(status), 10) + " " + http.StatusText(status) + "\r\n"))
	c.Write([]byte("\r\n"))
	c.Close()
}

func (mrt MyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "" {
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
	}
	req.Write(mrt.conn)
	resp, err := http.ReadResponse(bufio.NewReader(mrt.conn), req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 407 {
		resp.StatusCode = 401
	}
	if resp.Header.Values("Proxy-Authenticate") != nil {
		for _, v := range resp.Header.Values("Proxy-Authenticate") {
			resp.Header.Add("WWW-Authenticate", v)
		}
	}
	return resp, err
}

func transfer(clientConn net.Conn, upstream net.Conn) {

	go func() {
		n, err := io.Copy(upstream, clientConn)
		if err != nil {
			//log.Printf("Error copying 1: %+v", err)
		} else if n >= 0 {
			//log.Printf("Transferred %d bytes from clientConn to conn", n)
		}
		upstream.Close()
	}()
	go func() {
		n, err := io.Copy(clientConn, upstream)
		if err != nil {
			//log.Printf("Error copying 2: %+v", err)
		} else if n >= 0 {
			//log.Printf("Transferred %d bytes from conn to clientConn", n)
		}
		clientConn.Close()
	}()

}

func systrayReady() {

	systray.SetTitle("Proxy")
	systray.SetTooltip("Go Smart Proxy")

	options := make([]*systray.MenuItem, 0)

	for i, r := range routes {
		mRoute := systray.AddMenuItemCheckbox(r.name, r.name, false)
		options = append(options, mRoute)
		go func(m *systray.MenuItem, cr int) {
			for {
				<-m.ClickedCh
				log.Printf("Forcing route %s", routes[cr].name)
				forceRoute = routes[cr]
				for _, m := range options {
					m.Uncheck()
				}
				mRoute.Check()
			}
		}(mRoute, i)
	}

	mAuto := systray.AddMenuItemCheckbox("Auto", "Auto", true)
	options = append(options, mAuto)
	go func() {
		for {
			<-mAuto.ClickedCh
			log.Printf("Forcing route Auto")
			forceRoute = nil
			for _, m := range options {
				m.Uncheck()
			}
			mAuto.Check()
		}
	}()

	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "Quit proxy")

	go systrayReact(mQuit)
}

func systrayExit() {

}

func systrayReact(quit *systray.MenuItem) {
	select {
	case <-quit.ClickedCh:
		os.Exit(0)
	}
}
