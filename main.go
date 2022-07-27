package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

type MyRoundTripper struct {
	conn net.Conn
}

type StatusCodeConverter struct {
	RoundTripper http.RoundTripper
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

				h, ok := w.(http.Hijacker)
				if ok {
					clientConn, _, err := h.Hijack()
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
					} else {

						clientConn.Write([]byte("HTTP/1.1 200 Connection Established\n\n"))

						clientConn.SetDeadline(time.Time{})

						transfer(clientConn, conn)

					}

				}
			} else {
				conn, err = net.Dial("tcp", proxy.Address)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				newReq := &http.Request{
					ProtoMajor: 1,
					ProtoMinor: 1,
					Method:     r.Method,
					URL:        &url.URL{Opaque: ip + ":" + port},
					Header:     http.Header{},
					Host:       ip + ":" + port,
				}
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
				//log.Printf("Request result: %d\n", resp.StatusCode)

				if resp.StatusCode == 200 {

					h, ok := w.(http.Hijacker)
					if ok {
						clientConn, _, err := h.Hijack()
						if err != nil {
							w.WriteHeader(http.StatusInternalServerError)
						} else {

							clientConn.Write([]byte("HTTP/1.1 200 Connection Established\n\n"))

							clientConn.SetDeadline(time.Time{})

							transfer(clientConn, conn)

						}

					}

				} else {
					resp.Write(w)
				}
			}
		} else {
			newReq := &http.Request{
				Method: r.Method,
				URL:    r.URL,
				Header: r.Header.Clone(),
				Body:   r.Body,
			}
			resp, err := route.Do(newReq)
			if err != nil {
				log.Printf("Error: %s", err)
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			for k, vv := range resp.Header {
				for _, v := range vv {
					if k == "Content-Encoding" && v == "gzip" {

					} else {
						resp.Header.Add(k, v)
					}
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			resp.Body.Close()
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

func (mrt StatusCodeConverter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "" {
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
	}
	resp, err := mrt.RoundTripper.RoundTrip(req)
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
	return resp, nil
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
