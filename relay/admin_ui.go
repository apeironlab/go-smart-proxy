package relay

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// The management interface is the web app in webui/admin, built into
// adminui/static (npm run build:admin in webui) and embedded here.
//
//go:embed all:adminui/static
var adminStatic embed.FS

func adminUI() http.Handler {
	root, err := fs.Sub(adminStatic, "adminui/static")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/admin")
		name = strings.TrimPrefix(name, "/")
		if name != "" && name != "index.html" {
			if f, err := root.Open(name); err == nil {
				st, serr := f.Stat()
				f.Close()
				if serr == nil && !st.IsDir() {
					h.Set("Cache-Control", "public, max-age=3600")
					r2 := r.Clone(r.Context())
					r2.URL.Path = "/" + name
					files.ServeHTTP(w, r2)
					return
				}
			}
		}
		// The app itself, also for client-side routes.
		b, err := fs.ReadFile(root, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		w.Write(b)
	})
}
