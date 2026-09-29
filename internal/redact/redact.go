/*
Hiten | 2026
redact.go

Masks secrets in event data before it is shown or exported.

The database keeps the original values, because they are the
evidence. The API masks them by default; showing them needs an
explicit request (?reveal=secrets), which is logged, and case exports
record in the case history whether secrets were included.

What is masked:
  - fields named password, passwd, pwd, secret, token, api_key
  - HTTP Authorization, Proxy-Authorization and Cookie headers
  - form and query parameters whose name looks like a password,
    secret, token or key
  - the password part of URLs such as http://user:pass@host/
  - Redis AUTH arguments and CONFIG SET requirepass/masterauth values
  - quoted values after IDENTIFIED BY and PASSWORD in SQL
  - common command-line forms: --password=X, --password X, -pX for
    mysql, sshpass -p X, and user:password piped to chpasswd

Free text typed into the fake shell can contain secrets in forms not
listed here. Masking is a guard against casual exposure, not a
guarantee.
*/

package redact

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

// Mask replaces a secret. It does not reveal the length.
const Mask = "********"

var secretKey = regexp.MustCompile(`(?i)(^|[_\-.])(pass|passwd|password|pwd|secret|token|api[_\-]?key|apikey|auth[_\-]?key|access[_\-]?key)($|[_\-.])`)

var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
}

// IsSecretKey reports whether a field or parameter name looks like
// it holds a secret.
func IsSecretKey(k string) bool {
	return secretKey.MatchString(k) || strings.EqualFold(k, "pass") || strings.EqualFold(k, "pwd")
}

var textRules = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*://[^/\s:@]+:)[^@\s/]+@`), "${1}" + Mask + "@"},
	{regexp.MustCompile(`(?i)\b(AUTH)(\s+)(\S+)(\s+\S+)?`), "${1}${2}" + Mask},
	{regexp.MustCompile(`(?i)\b(CONFIG\s+SET\s+(?:requirepass|masterauth)\s+)\S+`), "${1}" + Mask},
	{regexp.MustCompile(`(?i)(IDENTIFIED\s+(?:WITH\s+\S+\s+)?BY\s+)'[^']*'`), "${1}'" + Mask + "'"},
	{regexp.MustCompile(`(?i)(PASSWORD\s*(?:=\s*)?(?:PASSWORD\s*)?\(?\s*)'[^']*'`), "${1}'" + Mask + "'"},
	{regexp.MustCompile(`(--password(?:=|\s+))\S+`), "${1}" + Mask},
	{regexp.MustCompile(`(\bmysql(?:dump|admin)?\b[^|;&\n]*\s-p)(\S+)`), "${1}" + Mask},
	{regexp.MustCompile(`(\bsshpass\s+-p\s*)\S+`), "${1}" + Mask},
	{regexp.MustCompile(`(\becho\s+['"]?[^:\s'"]+:)([^\s'"|]+)(['"]?\s*\|\s*(?:sudo\s+)?chpasswd)`), "${1}" + Mask + "${3}"},
}

// Text masks secrets in free text.
func Text(s string) string {
	for _, r := range textRules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// Params masks secret-looking parameters in a query string or a
// form body. Other text is passed through Text.
func Params(s string) string {
	if s == "" || !strings.Contains(s, "=") {
		return Text(s)
	}
	parts := strings.Split(s, "&")
	changed := false
	for i, p := range parts {
		k, _, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		name, err := url.QueryUnescape(k)
		if err != nil {
			name = k
		}
		if IsSecretKey(name) {
			parts[i] = k + "=" + Mask
			changed = true
		}
	}
	if changed {
		return strings.Join(parts, "&")
	}
	return Text(s)
}

// value masks one decoded JSON value found under key.
func value(key string, v any) any {
	switch t := v.(type) {
	case string:
		if IsSecretKey(key) && t != "" {
			return Mask
		}
		switch strings.ToLower(key) {
		case "query", "body":
			return Params(t)
		}
		return Text(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if strings.EqualFold(key, "headers") && sensitiveHeaders[strings.ToLower(k)] {
				out[k] = Mask
				continue
			}
			out[k] = value(k, x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = value(key, x)
		}
		return out
	}
	return v
}

// ServiceData returns masked service data. Invalid JSON is returned
// unchanged.
func ServiceData(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	out, err := json.Marshal(value("", m))
	if err != nil {
		return raw
	}
	return out
}

// Event returns a masked copy of ev. The original is not changed.
func Event(ev *types.Event) *types.Event {
	if ev == nil {
		return nil
	}
	c := *ev
	c.ServiceData = ServiceData(ev.ServiceData)
	return &c
}

// Events masks a list, returning new values.
func Events(evs []*types.Event) []*types.Event {
	out := make([]*types.Event, len(evs))
	for i, e := range evs {
		out[i] = Event(e)
	}
	return out
}

// Observable masks passwords inside URL values.
func Observable(o *types.IOC) *types.IOC {
	if o == nil {
		return nil
	}
	c := *o
	c.Value = Text(o.Value)
	c.Original = Text(o.Original)
	return &c
}

// MatchedValues masks detection matched values, which can quote
// commands.
func MatchedValues(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out, _ := value("", m).(map[string]any)
	return out
}
