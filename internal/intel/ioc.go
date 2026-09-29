/*
©AngelaMos | 2026
Modified by Hiten, 2026: rewritten to return observables with the
original value, a normalised value, internal-address and claimed
flags. Invented confidence numbers were removed; an analyst sets
the status instead. Now called from the event processor.

ioc.go

Extracts observables from a stored event: the source address,
URLs and domains typed into shells or sent to services, client
software strings (which the client controls) and hashes of
uploaded files.
*/

package intel

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

var urlPattern = regexp.MustCompile(
	`(?i)\b(?:https?|ftp|tftp)://[^\s'"` + "`" + `<>|;]+`,
)

var hexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

type Extractor struct{}

func NewExtractor() *Extractor {
	return &Extractor{}
}

// Extract returns the observables in ev, deduplicated by type and
// normalised value.
func (e *Extractor) Extract(ev *types.Event) []*types.IOC {
	var out []*types.IOC
	seen := map[string]bool{}
	add := func(ioc *types.IOC) {
		if ioc == nil || ioc.Value == "" {
			return
		}
		k := ioc.Type.String() + "|" + ioc.Value
		if seen[k] {
			return
		}
		seen[k] = true
		ioc.FirstSeen, ioc.LastSeen = ev.Timestamp, ev.Timestamp
		ioc.SightCount = 1
		ioc.Status = types.ObservableObserved
		ioc.Source = "honeypot:" + ev.ServiceType.String()
		out = append(out, ioc)
	}

	add(sourceIP(ev))

	var data map[string]any
	if len(ev.ServiceData) > 0 {
		_ = json.Unmarshal(ev.ServiceData, &data)
	}
	str := func(k string) string {
		s, _ := data[k].(string)
		return s
	}

	for _, k := range []string{"command", "raw", "query", "body", "path", "arg"} {
		for _, raw := range urlPattern.FindAllString(str(k), -1) {
			u, host := NormalizeURL(raw)
			if u == "" {
				continue
			}
			add(&types.IOC{Type: types.IOCURL, Value: u, Original: raw,
				Tags: []string{"from:" + k}})
			if host == "" {
				continue
			}
			if addr, err := netip.ParseAddr(host); err == nil {
				add(ipIOC(addr, host, []string{"from:url"}))
			} else {
				add(&types.IOC{Type: types.IOCDomain, Value: host,
					Original: host, Tags: []string{"from:url"}})
			}
		}
	}

	if ua := str("user_agent"); ua != "" {
		tags := []string{"claimed-fingerprint"}
		if fam := ClassifyHTTPClient(ua); fam != "" {
			tags = append(tags, "client:"+fam)
		}
		add(&types.IOC{Type: types.IOCUserAgent, Value: ua,
			Original: ua, Claimed: true, Tags: tags})
	}

	if cv := str("client_version"); cv != "" {
		tags := []string{"claimed-fingerprint"}
		if fam := ClassifySSHClient(cv); fam != "" {
			tags = append(tags, "client:"+fam)
		}
		add(&types.IOC{Type: types.IOCSSHClient, Value: cv,
			Original: cv, Claimed: true, Tags: tags})
	}

	if ev.EventType == types.EventFileUpload {
		if h := strings.ToLower(str("sha256")); len(h) == 64 && hexPattern.MatchString(h) {
			add(&types.IOC{Type: types.IOCHashSHA256, Value: h, Original: h,
				Tags: []string{"uploaded-file"}})
		}
		if h := strings.ToLower(str("md5")); len(h) == 32 && hexPattern.MatchString(h) {
			add(&types.IOC{Type: types.IOCHashMD5, Value: h, Original: h,
				Tags: []string{"uploaded-file"}})
		}
	}

	return out
}

func sourceIP(ev *types.Event) *types.IOC {
	addr, err := netip.ParseAddr(ev.SourceIP)
	if err != nil {
		return nil
	}
	return ipIOC(addr, ev.SourceIP, []string{"role:source"})
}

func ipIOC(addr netip.Addr, original string, tags []string) *types.IOC {
	addr = addr.Unmap()
	t := types.IOCIPv4
	if addr.Is6() {
		t = types.IOCIPv6
	}
	return &types.IOC{
		Type:     t,
		Value:    addr.String(),
		Original: original,
		Internal: IsInternal(addr),
		Tags:     tags,
	}
}

// IsInternal reports addresses that only make sense inside a lab or
// private network. They stay available for investigation but are
// not exported as indicators by default.
func IsInternal(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsUnspecified() || a.IsMulticast()
}

// NormalizeURL trims punctuation that commonly sticks to URLs in
// shell text, lowercases the scheme and host and drops default
// ports. It returns the URL and its host, or "" if it does not parse.
func NormalizeURL(raw string) (string, string) {
	raw = strings.TrimRight(raw, ".,)]}\"'")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.Fragment = ""
	return u.String(), host
}

func mergeUnique(a, b []string) []string {
	set := make(map[string]bool, len(a)+len(b))
	var result []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !set[s] {
			set[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ExtractBulk extracts and merges observables from many events.
func ExtractBulk(events []*types.Event) []*types.IOC {
	ext := NewExtractor()
	seen := make(map[string]*types.IOC)
	var order []string
	for _, ev := range events {
		for _, ioc := range ext.Extract(ev) {
			key := ioc.Type.String() + ":" + ioc.Value
			if existing, ok := seen[key]; ok {
				existing.SightCount++
				if ioc.LastSeen.After(existing.LastSeen) {
					existing.LastSeen = ioc.LastSeen
				}
				if ioc.FirstSeen.Before(existing.FirstSeen) {
					existing.FirstSeen = ioc.FirstSeen
				}
				existing.Tags = mergeUnique(existing.Tags, ioc.Tags)
				continue
			}
			seen[key] = ioc
			order = append(order, key)
		}
	}
	result := make([]*types.IOC, 0, len(order))
	for _, k := range order {
		result = append(result, seen[k])
	}
	return result
}

func FilterIPs(iocs []*types.IOC) []*types.IOC {
	var ips []*types.IOC
	for _, ioc := range iocs {
		if ioc.Type == types.IOCIPv4 || ioc.Type == types.IOCIPv6 {
			ips = append(ips, ioc)
		}
	}
	return ips
}

func FilterByAge(iocs []*types.IOC, maxAge time.Duration) []*types.IOC {
	cutoff := time.Now().UTC().Add(-maxAge)
	var filtered []*types.IOC
	for _, ioc := range iocs {
		if ioc.LastSeen.After(cutoff) {
			filtered = append(filtered, ioc)
		}
	}
	return filtered
}

func HasTag(ioc *types.IOC, tag string) bool {
	for _, t := range ioc.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}
