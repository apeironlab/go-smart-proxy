package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:webui/dist
var webuiDist embed.FS

// webUIHandler serves the embedded React web UI, with an SPA fallback to
// index.html for client-side routes.
func webUIHandler() http.Handler {
	dist, err := fs.Sub(webuiDist, "webui/dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		if f, err := dist.Open(path[1:]); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		index, err := fs.ReadFile(dist, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(index)
	})
}
