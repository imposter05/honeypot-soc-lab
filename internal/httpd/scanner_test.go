package httpd

import "testing"

func TestDetectScanner(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)": "nikto",
		"sqlmap/1.8#stable (https://sqlmap.org)":                   "sqlmap",
		"Mozilla/5.0 (compatible; Nmap Scripting Engine)":          "nmap",
		"curl/8.5.0":             "",
		"Wget/1.21.4":            "",
		"python-requests/2.31.0": "",
		"Go-http-client/1.1":     "",
		"Mozilla/5.0 (X11; Linux x86_64) Firefox/128": "",
	}
	for ua, want := range cases {
		if got := DetectScanner(ua); got != want {
			t.Errorf("%q: got %q want %q", ua, got, want)
		}
	}
}
