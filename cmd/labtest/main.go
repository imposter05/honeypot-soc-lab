/*
Hiten | 2026
main.go

labtest runs the scenarios in scenarios/ against a running lab and
checks what the lab recorded.

Each scenario connects to the decoys with real protocol clients (SSH,
HTTP, FTP, Redis, MySQL, plain TCP) from its own loopback address,
waits for the events to be stored, then asks the API which
detections and observables appeared. It checks expected rules,
forbidden rules and expected observables, prints a summary, writes a
JSON report and stores the results through POST /api/lab/runs.

Every scenario runs from its own source address, and only from an
address the lab has not seen recently (see pickSources). On Linux any
127.x address works, so a random block is used. On macOS only
127.0.0.1 exists until aliases are added with
scripts/mac-loopback-aliases.sh; the runner then uses the pool
127.0.0.10-127.0.0.99. If it cannot find enough isolated addresses it
stops instead of sharing one.

Only point this at a lab you run. It is a test client, not a scanner.
*/

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

func main() {
	api := flag.String("api", "http://127.0.0.1:8000", "lab API base URL (must be loopback)")
	dir := flag.String("scenarios", "scenarios", "scenario directory")
	only := flag.String("only", "", "comma-separated scenario IDs to run")
	out := flag.String("out", "data/lab-runs", "directory for the JSON report")
	source := flag.String("source", "", "run one scenario from this address (needs -only with one ID)")
	pool := flag.String("pool", "", "use addresses from this range, for example 127.0.0.10-127.0.0.99 (default on macOS)")
	flag.Parse()

	if err := run(*api, *dir, *only, *out, *source, *pool); err != nil {
		fmt.Fprintln(os.Stderr, "labtest:", err)
		os.Exit(2)
	}
}

func run(api, dir, only, out, fixedSource, pool string) error {
	u, err := url.Parse(api)
	if err != nil {
		return err
	}
	if a, err := netip.ParseAddr(u.Hostname()); (err != nil && u.Hostname() != "localhost") || (err == nil && !a.IsLoopback()) {
		return fmt.Errorf("refusing to run against %s: labtest only targets a loopback lab", u.Host)
	}
	c := &client{base: strings.TrimRight(api, "/"), http: &http.Client{Timeout: 10 * time.Second}}

	sys, err := c.system()
	if err != nil {
		return fmt.Errorf("cannot reach the lab API at %s (is `hive serve` running?): %w", api, err)
	}
	scenarios, err := loadScenarios(dir, only)
	if err != nil {
		return err
	}
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenarios found in %s", dir)
	}

	runID := time.Now().UTC().Format("20060102T150405Z") + "-" + randHex(3)
	sources, note, err := pickSources(c, len(scenarios), fixedSource, pool, sys)
	if err != nil {
		return err
	}
	fmt.Printf("Run %s: %d scenario(s) against %s (ssh auth mode %s)\n", runID, len(scenarios), sys.Host, sys.SSHAuthMode)
	if note != "" {
		fmt.Println(note)
	}
	fmt.Println()

	var results []types.ScenarioRun
	for i, sc := range scenarios {
		res := sc.run(c, sys, runID, sources[i])
		results = append(results, res)
		status := "PASS"
		switch {
		case res.Skipped:
			status = "SKIP"
		case !res.Passed:
			status = "FAIL"
		}
		fmt.Printf("[%s] %-28s %-15s %s\n", status, sc.ID, res.SourceIP, summaryLine(res))
		for _, f := range res.Failures {
			fmt.Printf("       - %s\n", f)
		}
	}

	if err := os.MkdirAll(out, 0o700); err == nil {
		path := filepath.Join(out, runID+".json")
		b, _ := json.MarshalIndent(map[string]any{"run_id": runID, "api": api, "results": results}, "", "  ")
		if err := os.WriteFile(path, b, 0o600); err == nil {
			fmt.Printf("\nReport: %s\n", path)
		}
	}
	if err := c.post("/api/lab/runs", results); err != nil {
		fmt.Println("Could not store results in the lab:", err)
	}

	failed := 0
	for _, r := range results {
		if !r.Passed && !r.Skipped {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d scenario(s) failed", failed)
	}
	return nil
}

func summaryLine(r types.ScenarioRun) string {
	if r.Skipped {
		return r.RunnerNotes
	}
	rules, _ := r.Observed["rules"].([]string)
	return fmt.Sprintf("%v events, rules: %s", r.Observed["events"], orNone(strings.Join(rules, ", ")))
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Isolation. Rules keep state per source address (windows and
// suppression) and cases are grouped per source address. Two
// scenarios that share an address, or a scenario that reuses an
// address used recently, can change each other's results. So every
// scenario gets its own address, and an address is only used if the
// lab has seen nothing from it for longer than the longest rule
// window, suppression period and case grouping window.

const defaultPool = "127.0.0.10-127.0.0.99"

func pickSources(c *client, n int, fixed, pool string, sys *systemInfo) ([]string, string, error) {
	quiet, err := c.quietPeriod()
	if err != nil {
		return nil, "", fmt.Errorf("reading rule settings: %w", err)
	}

	if fixed != "" {
		if n != 1 {
			return nil, "", fmt.Errorf("-source runs a single scenario; add -only with one scenario ID")
		}
		if !canSendFrom(fixed, sys.Host) {
			return nil, "", fmt.Errorf("this system cannot send from %s", fixed)
		}
		if busy, err := c.recentlyUsed(fixed, quiet); err != nil || busy {
			return nil, "", fmt.Errorf("%s had lab activity in the last %s, so earlier results could affect this run; wait or choose another address", fixed, quiet)
		}
		return []string{fixed}, "", nil
	}

	if pool == "" {
		// Linux: any 127.x address works, so pick a fresh random /24.
		b := make([]byte, 2)
		_, _ = rand.Read(b)
		b[0] = b[0]%200 + 20
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("127.%d.%d.%d", b[0], b[1], i+10)
		}
		if canSendFrom(out[0], sys.Host) {
			for _, a := range out {
				if busy, err := c.recentlyUsed(a, quiet); err == nil && busy {
					return pickSources(c, n, fixed, pool, sys)
				}
			}
			return out, "", nil
		}
		pool = defaultPool
	}

	start, end, err := parsePool(pool)
	if err != nil {
		return nil, "", err
	}
	var out []string
	unusable, busy := 0, 0
	for a := start; a.Compare(end) <= 0 && len(out) < n; a = a.Next() {
		s := a.String()
		if !canSendFrom(s, sys.Host) {
			unusable++
			continue
		}
		if used, err := c.recentlyUsed(s, quiet); err != nil || used {
			busy++
			continue
		}
		out = append(out, s)
	}
	if len(out) < n {
		msg := fmt.Sprintf("need %d isolated source addresses from %s but found %d", n, pool, len(out))
		if unusable > 0 {
			msg += fmt.Sprintf("; %d cannot be used on this system (on macOS run: sudo ./scripts/mac-loopback-aliases.sh add)", unusable)
		}
		if busy > 0 {
			msg += fmt.Sprintf("; %d were used in the last %s (wait, or add more aliases with --count)", busy, quiet)
		}
		return nil, "", fmt.Errorf("%s", msg)
	}
	return out, fmt.Sprintf("Using %d addresses from %s, each quiet for at least %s.", n, pool, quiet), nil
}

func parsePool(p string) (netip.Addr, netip.Addr, error) {
	a, b, ok := strings.Cut(p, "-")
	if !ok {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("-pool must look like 127.0.0.10-127.0.0.99")
	}
	start, err1 := netip.ParseAddr(strings.TrimSpace(a))
	end, err2 := netip.ParseAddr(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || !start.IsLoopback() || !end.IsLoopback() || end.Less(start) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("-pool must be a loopback range like 127.0.0.10-127.0.0.99")
	}
	return start, end, nil
}

// canSendFrom checks that the system can open a connection from addr.
func canSendFrom(addr, host string) bool {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(addr)}, Timeout: 2 * time.Second}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, "9"))
	if conn != nil {
		_ = conn.Close()
	}
	// Connection refused means the address itself was usable.
	return err == nil || !errors.Is(err, syscall.EADDRNOTAVAIL)
}

// recentlyUsed asks the lab whether addr sent anything within d.
func (c *client) recentlyUsed(addr string, d time.Duration) (bool, error) {
	since := time.Now().UTC().Add(-d).Format(time.RFC3339)
	var p page[json.RawMessage]
	if err := c.get("/api/events?limit=1&source="+url.QueryEscape(addr)+"&since="+url.QueryEscape(since), &p); err != nil {
		return true, err
	}
	return p.Meta.Total > 0, nil
}

// quietPeriod is the longest time lab state for one source can last:
// the largest rule window or suppression period, or the case grouping
// window, plus one minute.
func (c *client) quietPeriod() (time.Duration, error) {
	var rules struct {
		Data struct {
			Rules []struct {
				Rule struct {
					SuppressFor time.Duration `json:"suppress_for"`
					Params      struct {
						Window time.Duration `json:"window"`
					} `json:"params"`
				} `json:"rule"`
			} `json:"rules"`
		} `json:"data"`
	}
	if err := c.get("/api/rules", &rules); err != nil {
		return 0, err
	}
	var sys struct {
		Data struct {
			CorrelationWindow time.Duration `json:"correlation_window"`
		} `json:"data"`
	}
	if err := c.get("/api/system", &sys); err != nil {
		return 0, err
	}
	longest := sys.Data.CorrelationWindow
	for _, r := range rules.Data.Rules {
		longest = max(longest, r.Rule.SuppressFor, r.Rule.Params.Window)
	}
	return longest + time.Minute, nil
}

// ---- API client ----------------------------------------------------------

type client struct {
	base string
	http *http.Client
}

type systemInfo struct {
	Host        string
	Ports       map[string]int
	SSHAuthMode string
}

func (c *client) get(path string, v any) error {
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s: %s: %s", path, resp.Status, b)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (c *client) post(path string, body any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Analyst", "labtest")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		m, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", resp.Status, m)
	}
	return nil
}

func (c *client) system() (*systemInfo, error) {
	var r struct {
		Data struct {
			Listeners []struct {
				Name, Address, State string
			} `json:"listeners"`
			SSHAuthMode string `json:"ssh_auth_mode"`
		} `json:"data"`
	}
	if err := c.get("/api/system", &r); err != nil {
		return nil, err
	}
	s := &systemInfo{Ports: map[string]int{}, SSHAuthMode: r.Data.SSHAuthMode}
	for _, l := range r.Data.Listeners {
		ap, err := netip.ParseAddrPort(l.Address)
		if err != nil || l.Name == "api" || l.State != "listening" {
			continue
		}
		s.Ports[l.Name] = int(ap.Port())
		s.Host = ap.Addr().String()
	}
	if s.Host == "" {
		return nil, fmt.Errorf("no decoy is listening")
	}
	return s, nil
}

func (s *systemInfo) addr(service string) (string, error) {
	p, ok := s.Ports[service]
	if !ok {
		return "", fmt.Errorf("%s decoy is not listening", service)
	}
	return net.JoinHostPort(s.Host, fmt.Sprint(p)), nil
}

type page[T any] struct {
	Data []T `json:"data"`
	Meta struct {
		Total int64 `json:"total"`
	} `json:"meta"`
}

type detectionRow struct {
	ID         int64     `json:"id"`
	RuleID     string    `json:"rule_id"`
	DetectedAt time.Time `json:"detected_at"`
}

type observableRow struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// waitForEvents polls until the event count for src stops changing.
func (c *client) waitForEvents(src string, since time.Time) int64 {
	q := "/api/events?limit=1&source=" + url.QueryEscape(src) + "&since=" + url.QueryEscape(since.Format(time.RFC3339))
	var last int64 = -1
	stable := 0
	for i := 0; i < 40 && stable < 3; i++ {
		time.Sleep(300 * time.Millisecond)
		var p page[json.RawMessage]
		if err := c.get(q, &p); err != nil {
			continue
		}
		if p.Meta.Total == last {
			stable++
		} else {
			stable, last = 0, p.Meta.Total
		}
	}
	return last
}

// ---- scenarios -------------------------------------------------------------

type scenario struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Kind        string `yaml:"kind"`
	Requires    struct {
		SSHAuthMode string `yaml:"ssh_auth_mode"`
	} `yaml:"requires"`
	Steps  []step `yaml:"steps"`
	Expect struct {
		Detections   []string        `yaml:"detections"`
		Forbidden    []string        `yaml:"forbidden"`
		NoDetections bool            `yaml:"no_detections"`
		Observables  []observableRow `yaml:"observables"`
		UploadHash   bool            `yaml:"upload_hash"`
		MinEvents    int64           `yaml:"min_events"`
	} `yaml:"expect"`
}

func loadScenarios(dir, only string) ([]*scenario, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	want := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		if id = strings.TrimSpace(id); id != "" {
			want[id] = true
		}
	}
	var out []*scenario
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var sc scenario
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&sc); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if sc.ID == "" || len(sc.Steps) == 0 {
			return nil, fmt.Errorf("%s: id and steps are required", f)
		}
		if len(want) == 0 || want[sc.ID] {
			out = append(out, &sc)
		}
	}
	return out, nil
}

func (sc *scenario) run(c *client, sys *systemInfo, runID, src string) types.ScenarioRun {
	res := types.ScenarioRun{
		RunID: runID, ScenarioID: sc.ID, Kind: sc.Kind, SourceIP: src,
		StartedAt: time.Now().UTC(),
		Expected: map[string]any{
			"detections": sc.Expect.Detections, "forbidden": sc.Expect.Forbidden,
			"no_detections": sc.Expect.NoDetections, "observables": sc.Expect.Observables,
			"min_events": sc.Expect.MinEvents,
		},
		Observed: map[string]any{},
	}
	defer func() { res.FinishedAt = time.Now().UTC() }()

	if m := sc.Requires.SSHAuthMode; m != "" && m != sys.SSHAuthMode {
		res.Skipped = true
		res.RunnerNotes = "needs ssh.auth_mode " + m + " (lab is " + sys.SSHAuthMode + ")"
		return res
	}

	// Start a second earlier so clock rounding cannot hide events.
	since := res.StartedAt.Add(-time.Second)
	r := &runner{sys: sys, src: src, runID: runID}
	for i, st := range sc.Steps {
		if err := r.do(st); err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("step %d: %v", i+1, err))
		}
	}

	events := c.waitForEvents(src, since)
	res.Observed["events"] = events

	var dets page[detectionRow]
	_ = c.get("/api/detections?limit=500&source="+url.QueryEscape(src), &dets)
	seen := map[string]bool{}
	var rules []string
	for _, d := range dets.Data {
		if d.DetectedAt.Before(since) || seen[d.RuleID] {
			continue
		}
		seen[d.RuleID] = true
		rules = append(rules, d.RuleID)
	}
	sort.Strings(rules)
	res.Observed["rules"] = rules

	if events < sc.Expect.MinEvents {
		res.Failures = append(res.Failures, fmt.Sprintf("expected at least %d events, got %d", sc.Expect.MinEvents, events))
	}
	for _, want := range sc.Expect.Detections {
		if !seen[want] {
			res.Failures = append(res.Failures, "expected detection "+want+" did not appear")
		}
	}
	for _, bad := range sc.Expect.Forbidden {
		if seen[bad] {
			res.Failures = append(res.Failures, "forbidden detection "+bad+" appeared")
		}
	}
	if sc.Expect.NoDetections && len(rules) > 0 {
		res.Failures = append(res.Failures, "expected no detections, got "+strings.Join(rules, ", "))
	}
	obs := append([]observableRow(nil), sc.Expect.Observables...)
	if sc.Expect.UploadHash && r.uploadSHA != "" {
		obs = append(obs, observableRow{Type: "sha256", Value: r.uploadSHA})
		res.Observed["upload_sha256"] = r.uploadSHA
	}
	var found []string
	for _, o := range obs {
		var p page[observableRow]
		_ = c.get("/api/observables?limit=50&q="+url.QueryEscape(o.Value), &p)
		ok := false
		for _, x := range p.Data {
			ok = ok || (x.Type == o.Type && x.Value == o.Value)
		}
		if ok {
			found = append(found, o.Type+":"+o.Value)
		} else {
			res.Failures = append(res.Failures, fmt.Sprintf("expected observable %s %s not found", o.Type, o.Value))
		}
	}
	res.Observed["observables"] = found
	res.Passed = len(res.Failures) == 0
	return res
}
