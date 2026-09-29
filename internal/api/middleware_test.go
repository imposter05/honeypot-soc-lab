package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestGuard(t *testing.T) {
	g := newRequestGuard("127.0.0.1", 8000, []string{"http://127.0.0.1:5173"})
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := g.middleware(ok)

	cases := []struct {
		name, method, host, origin, ctype string
		want                              int
	}{
		{"same host get", "GET", "127.0.0.1:8000", "", "", 200},
		{"localhost get", "GET", "localhost:8000", "", "", 200},
		{"dns rebinding host", "GET", "evil.test:8000", "", "", 421},
		{"foreign origin", "GET", "127.0.0.1:8000", "http://evil.test", "", 403},
		{"vite origin", "GET", "127.0.0.1:8000", "http://127.0.0.1:5173", "", 200},
		{"form post", "POST", "127.0.0.1:8000", "", "application/x-www-form-urlencoded", 415},
		{"json post", "POST", "127.0.0.1:8000", "", "application/json", 200},
		{"json post foreign origin", "POST", "127.0.0.1:8000", "http://evil.test", "application/json", 403},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "/api/x", strings.NewReader("{}"))
		r.Host = c.host
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.ctype != "" {
			r.Header.Set("Content-Type", c.ctype)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: got %d want %d", c.name, w.Code, c.want)
		}
	}
}
