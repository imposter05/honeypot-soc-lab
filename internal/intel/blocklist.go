/*
©AngelaMos | 2026
Modified by Hiten, 2026: every value is re-parsed as an IP before
it is written, so a bad record cannot inject text into an iptables
or nginx file; internal addresses are skipped; CSV uses proper
quoting.

blocklist.go

Blocklist export in plain text, iptables, nginx and CSV formats for
the observables an analyst selected.
*/

package intel

import (
	"encoding/csv"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	FormatPlain    = "plain"
	FormatIPTables = "iptables"
	FormatNginx    = "nginx"
	FormatCSV      = "csv"
)

// BlocklistResult is the file text plus what was left out and why.
type BlocklistResult struct {
	Text    string
	Written int
	Skipped map[string]int
}

// GenerateBlocklist writes the IP addresses in iocs. Non-IP
// records, unparseable values and (unless includeInternal) internal
// addresses are skipped and counted.
func GenerateBlocklist(iocs []*types.IOC, format string, includeInternal bool) BlocklistResult {
	res := BlocklistResult{Skipped: map[string]int{}}
	var ips []*types.IOC
	var addrs []netip.Addr
	for _, ioc := range iocs {
		if ioc.Type != types.IOCIPv4 && ioc.Type != types.IOCIPv6 {
			res.Skipped["not an IP address"]++
			continue
		}
		a, err := netip.ParseAddr(ioc.Value)
		if err != nil {
			res.Skipped["unparseable value"]++
			continue
		}
		if IsInternal(a) && !includeInternal {
			res.Skipped["internal address"]++
			continue
		}
		ips = append(ips, ioc)
		addrs = append(addrs, a)
	}
	res.Written = len(ips)

	var b strings.Builder
	header := func(title string) {
		fmt.Fprintf(&b, "# Honeypot SOC Investigation Lab - %s\n", title)
		fmt.Fprintf(&b, "# Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "# Entries: %d\n", len(ips))
		fmt.Fprintf(&b, "# Review before use. These addresses touched a decoy; that alone does not make them hostile.\n\n")
	}

	switch format {
	case FormatIPTables:
		header("iptables rules")
		for _, a := range addrs {
			cmd := "iptables"
			if a.Is6() {
				cmd = "ip6tables"
			}
			fmt.Fprintf(&b, "%s -A INPUT -s %s -j DROP\n", cmd, a)
		}
	case FormatNginx:
		header("nginx deny list")
		for _, a := range addrs {
			fmt.Fprintf(&b, "deny %s;\n", a)
		}
	case FormatCSV:
		w := csv.NewWriter(&b)
		_ = w.Write([]string{"ip", "type", "status", "internal", "first_seen",
			"last_seen", "sight_count", "source", "tags"})
		for i, ioc := range ips {
			_ = w.Write([]string{
				addrs[i].String(), ioc.Type.String(), ioc.Status,
				strconv.FormatBool(ioc.Internal),
				ioc.FirstSeen.UTC().Format(time.RFC3339),
				ioc.LastSeen.UTC().Format(time.RFC3339),
				strconv.Itoa(ioc.SightCount), ioc.Source,
				strings.Join(ioc.Tags, ";"),
			})
		}
		w.Flush()
	default:
		header("plain list")
		for _, a := range addrs {
			b.WriteString(a.String())
			b.WriteByte('\n')
		}
	}
	res.Text = b.String()
	return res
}

func SupportedFormats() []string {
	return []string{FormatPlain, FormatIPTables, FormatNginx, FormatCSV}
}
