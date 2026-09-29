/*
©AngelaMos | 2026
Modified by Hiten, 2026: the permissive CORS handler was replaced by
host and origin checks. Only loopback host names are accepted (which
blocks DNS rebinding), cross-origin requests must come from a listed
origin, and state-changing requests must send JSON, which a plain
HTML form on another site cannot do.

middleware.go
*/

package api

import (
	"bufio"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type statusWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	return n, err
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return h.Hijack()
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func requestLogger(logger *zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			lvl := logger.Debug()
			if r.Method != http.MethodGet || sw.status >= 400 {
				lvl = logger.Info()
			}
			lvl.Str("method", r.Method).Str("path", r.URL.Path).
				Int("status", sw.status).Dur("latency", time.Since(start)).
				Msg("api request")
		})
	}
}

func recoverer(logger *zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Interface("panic", rec).
						Str("path", r.URL.Path).Msg("recovered from panic")
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// requestGuard holds the allowed hosts and origins.
type requestGuard struct {
	hosts   map[string]bool
	origins map[string]bool
}

func newRequestGuard(managementHost string, port int, origins []string) *requestGuard {
	g := &requestGuard{hosts: map[string]bool{}, origins: map[string]bool{}}
	for _, h := range []string{managementHost, "127.0.0.1", "localhost", "::1"} {
		g.hosts[strings.ToLower(h)] = true
		g.origins[fmt.Sprintf("http://%s", net.JoinHostPort(h, fmt.Sprint(port)))] = true
	}
	for _, o := range origins {
		g.origins[strings.TrimRight(o, "/")] = true
	}
	return g
}

func (g *requestGuard) hostAllowed(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return g.hosts[strings.ToLower(strings.Trim(h, "[]"))]
}

// OriginAllowed reports whether a browser Origin may call the API.
func (g *requestGuard) OriginAllowed(origin string) bool {
	return g.origins[strings.TrimRight(origin, "/")]
}

func (g *requestGuard) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.hostAllowed(r.Host) {
			http.Error(w, "host not allowed; open the dashboard on 127.0.0.1 or localhost", http.StatusMisdirectedRequest)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !g.OriginAllowed(origin) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Analyst")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if mt != "application/json" {
				http.Error(w, "state-changing requests must send Content-Type: application/json", http.StatusUnsupportedMediaType)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}
