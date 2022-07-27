package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

type MyRoundTripper struct {
	conn net.Conn
}

func main() {

	loadConfiguration()

	server := &http.Server{
		Addr:         configuration.Address,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		Handler:      http.HandlerFunc(ProxyFunc()),
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}

}

func ProxyFunc() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		route := GetApplicableRoute()

		proxy := route.FindProxy(r.URL.String())
		var err error

		if r.Method == "CONNECT" {
			pos := strings.LastIndex(r.Host, ":")
			ip := r.Host[:pos]
			port := r.Host[pos+1:]
			pIp := net.ParseIP(ip)
			if pIp != nil && pIp.To4() == nil {
				//ip = "[" + ip + "]"
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var conn net.Conn
			if proxy.Type == "DIRECT" {
				conn, err = net.Dial("tcp", ip+":"+port)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}

				hijack(w, conn)

			} else {
				conn, err = net.Dial("tcp", proxy.Address)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				newReq, err := http.NewRequest(r.Method, ip+":"+port, nil)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				newReq.Host = ip + ":" + port
				newReq.SetBasicAuth(route.user, route.password)
				transp := ntlmssp.Negotiator{
					RoundTripper: MyRoundTripper{
						conn: conn,
					},
				}
				resp, err := transp.RoundTrip(newReq)
				if err != nil {
					log.Printf("Error: %+v", err)
					w.WriteHeader(http.StatusBadGateway)
					return
				}

				if resp.StatusCode == 200 {

					hijack(w, conn)

				} else {
					resp.Write(w)
				}
			}
		} else {
			if strings.Contains(r.Header.Get("Connection"), "Upgrade") {
				var conn net.Conn
				if proxy.Type == "DIRECT" {
					conn, err = net.Dial("tcp", r.Host)
					if err != nil {
						w.WriteHeader(http.StatusBadGateway)
						return
					}

					newReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					copyRequestHeaders(newReq, r)
					newReq.Write(conn)

					hijack(w, conn)

				} else {
					conn, err = net.Dial("tcp", proxy.Address)
					if err != nil {
						w.WriteHeader(http.StatusBadGateway)
						return
					}
					newReq, err := http.NewRequest("CONNECT", r.Host, nil)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					newReq.Host = r.Host
					newReq.SetBasicAuth(route.user, route.password)
					transp := ntlmssp.Negotiator{
						RoundTripper: MyRoundTripper{
							conn: conn,
						},
					}
					resp, err := transp.RoundTrip(newReq)
					if err != nil {
						log.Printf("Error: %+v", err)
						w.WriteHeader(http.StatusBadGateway)
						return
					}

					if resp.StatusCode == 200 {

						newReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
						if err != nil {
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
						copyRequestHeaders(newReq, r)
						newReq.Write(conn)

						hijack(w, conn)

					} else {
						resp.Write(w)
					}
				}
			} else {
				newReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				copyRequestHeaders(newReq, r)
				resp, err := route.Do(newReq)
				if err != nil {
					log.Printf("Error: %s", err)
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				copyResponseHeaders(w, resp)
				w.WriteHeader(resp.StatusCode)
				io.Copy(w, resp.Body)
				resp.Body.Close()
			}
		}
	}
}

func copyRequestHeaders(dest *http.Request, src *http.Request) {
	for k, vv := range src.Header {
		for _, v := range vv {
			if k == "Content-Encoding" || k == "Content-Length" || k == "Accept-Encoding" {

			} else {
				dest.Header.Add(k, v)
			}
		}
	}
}

func copyResponseHeaders(dest http.ResponseWriter, src *http.Response) {
	for k, vv := range src.Header {
		for _, v := range vv {
			if k == "Content-Encoding" || k == "Content-Length" {

			} else {
				dest.Header().Add(k, v)
			}
		}
	}
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

func hijack(w http.ResponseWriter, upstream net.Conn) {

	h, ok := w.(http.Hijacker)
	if ok {
		clientConn, _, err := h.Hijack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {

			clientConn.Write([]byte("HTTP/1.1 200 Connection Established\n\n"))

			clientConn.SetDeadline(time.Time{})

			transfer(clientConn, upstream)
		}
	}

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
