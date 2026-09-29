/*
©AngelaMos | 2026
Modified by Hiten, 2026: general-purpose HTTP clients (curl, wget,
python-requests, Go-http-client, libwww-perl, scrapy) were removed,
because scripts and administrators use them for ordinary requests
and every such request was being reported as a scanner. They are
still recorded as client fingerprints on the observable. Matching
now uses an ordered list, so the result no longer depends on Go's
random map order when two patterns match.

scanner.go

Matches User-Agent headers against tools built for scanning. The
header is chosen by the client, so a match is a claim, not proof.
*/

package httpd

import "strings"

var scannerPatterns = []struct{ pattern, name string }{
	{"nuclei", "nuclei"},
	{"sqlmap", "sqlmap"},
	{"nikto", "nikto"},
	{"nmap scripting engine", "nmap"},
	{"nmap", "nmap"},
	{"zgrab", "zgrab"},
	{"masscan", "masscan"},
	{"gobuster", "gobuster"},
	{"dirbuster", "dirbuster"},
	{"feroxbuster", "feroxbuster"},
	{"wfuzz", "wfuzz"},
	{"ffuf", "ffuf"},
	{"burp", "burpsuite"},
	{"acunetix", "acunetix"},
	{"openvas", "openvas"},
	{"nessus", "nessus"},
	{"w3af", "w3af"},
	{"arachni", "arachni"},
	{"whatweb", "whatweb"},
	{"wpscan", "wpscan"},
	{"joomscan", "joomscan"},
	{"metasploit", "metasploit"},
	{"hydra", "hydra"},
	{"censysinspect", "censys"},
	{"censys", "censys"},
	{"shodan", "shodan"},
	{"netcraft", "netcraft"},
	{"projectdiscovery", "httpx"},
	{"testssl", "testssl"},
	{"sslscan", "sslscan"},
}

// DetectScanner returns the first matching tool name, or "".
func DetectScanner(userAgent string) string {
	lower := strings.ToLower(userAgent)
	for _, p := range scannerPatterns {
		if strings.Contains(lower, p.pattern) {
			return p.name
		}
	}
	return ""
}
