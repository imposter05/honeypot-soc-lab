/*
Hiten | 2026
static.go

Serves the built dashboard (frontend/dist) from the same loopback
port as the API, so one process and one address are enough. Unknown
paths fall back to index.html for client-side routing. When the
dashboard has not been built, a short page explains how to build it.
*/

package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const notBuiltPage = `<!doctype html><meta charset="utf-8"><title>Dashboard not built</title>
<body style="font-family:system-ui;max-width:40rem;margin:4rem auto;line-height:1.5">
<h1>Dashboard not built</h1>
<p>The API is running, but there is no built dashboard at the configured path.</p>
<p>Run <code>./scripts/build-local.sh</code>, or use <code>./scripts/dev.sh</code> and open
<code>http://127.0.0.1:5173</code> for the development server.</p>
<p>API health: <a href="/api/health">/api/health</a>, readiness: <a href="/api/ready">/api/ready</a>.</p>`

func (s *Server) staticHandler() http.Handler {
	root := s.d.Config.Paths.Frontend
	fs := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
		index := filepath.Join(root, "index.html")
		if _, err := os.Stat(index); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(notBuiltPage))
			return
		}
		clean := filepath.Clean("/" + r.URL.Path)
		if clean != "/" {
			if st, err := os.Stat(filepath.Join(root, clean)); err == nil && !st.IsDir() {
				if strings.HasPrefix(clean, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				fs.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, index)
	})
}
