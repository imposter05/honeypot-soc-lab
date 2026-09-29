/*
Hiten | 2026
engine.go

Evaluates rules against events in the order they are stored.

Evaluate never changes the engine's state. It returns the matches
plus an Evaluation whose Apply method records the event in the rule
windows. The processor calls Apply only after the event and its
detections are committed to the database, so a failed write cannot
leave the engine counting an event that has no stored evidence.

Windows use the event timestamp, not the wall clock, so replayed
test events behave the same as live ones.
*/

package detection

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	maxEntriesPerKey = 500
	maxEvidenceRefs  = 50
	gcEvery          = 1000
)

type entry struct {
	ts    time.Time
	ref   types.EventRef
	value string
}

type window struct {
	span    time.Duration
	entries []entry
}

type suppression struct {
	until time.Time
	detID int64
}

// Match is one rule result for one event.
type Match struct {
	Detection types.Detection
	Evidence  []types.DetectionEvidence
	// Suppressed is true when the rule already fired for the same
	// group inside its suppression window. The store then adds the
	// event to ExistingID as a repeat instead of creating a new
	// detection.
	Suppressed bool
	ExistingID int64
}

// Evaluation holds the matches for one event and the pending state
// changes.
type Evaluation struct {
	Matches []Match
	engine  *Engine
	appends []pendingAppend
	sets    []pendingSuppress
}

type pendingAppend struct {
	key string
	win time.Duration
	e   entry
}

type pendingSuppress struct {
	key      string
	until    time.Time
	matchIdx int
}

// Apply records the event in the engine. ids holds the stored
// detection ID for each match, in order (0 for suppressed ones).
func (ev *Evaluation) Apply(ids []int64) {
	if ev.engine == nil {
		return
	}
	e := ev.engine
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, a := range ev.appends {
		w := e.state[a.key]
		if w == nil {
			w = &window{span: a.win}
			e.state[a.key] = w
		}
		w.entries = append(w.entries, a.e)
		cutoff := a.e.ts.Add(-w.span)
		w.entries = pruneBefore(w.entries, cutoff)
		if len(w.entries) > maxEntriesPerKey {
			w.entries = w.entries[len(w.entries)-maxEntriesPerKey:]
		}
	}
	for _, s := range ev.sets {
		var id int64
		if s.matchIdx < len(ids) {
			id = ids[s.matchIdx]
		}
		e.suppress[s.key] = &suppression{until: s.until, detID: id}
	}

	e.applied++
	if e.applied%gcEvery == 0 && len(ev.appends) > 0 {
		e.gc(ev.appends[0].e.ts)
	}
}

type Engine struct {
	mu       sync.Mutex
	rules    []*Rule
	state    map[string]*window
	suppress map[string]*suppression
	applied  int
}

func NewEngine(rs []*Rule) *Engine {
	return &Engine{
		rules:    rs,
		state:    make(map[string]*window),
		suppress: make(map[string]*suppression),
	}
}

func (e *Engine) Rules() []*Rule { return e.rules }

// Rule returns the rule with id, or nil.
func (e *Engine) Rule(id string) *Rule {
	for _, r := range e.rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// Evaluate runs every enabled rule against ev.
func (e *Engine) Evaluate(ev *types.Event) *Evaluation {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := &Evaluation{engine: e}
	f := fieldsOf(ev)

	for _, r := range e.rules {
		if !r.Enabled {
			continue
		}
		var m *Match
		switch r.Kind {
		case KindAuthVolume:
			m = e.evalAuthVolume(r, ev, f, out)
		case KindAuthFailureBurst:
			m = e.evalFailureBurst(r, ev, f, out)
		case KindFailuresThenSuccess:
			m = e.evalFailuresThenSuccess(r, ev, f, out)
		case KindHTTPSensitivePaths:
			m = e.evalHTTPPaths(r, ev, f, out)
		case KindMultiServiceContact:
			m = e.evalMultiService(r, ev, out)
		case KindDiscoverySequence:
			m = e.evalDiscovery(r, ev, f, out)
		case KindTransferCommand:
			m = e.evalTransfer(r, ev, f, out)
		case KindRedisConfigWrite:
			m = e.evalRedisWrite(r, ev, f, out)
		case KindSSHPortForward:
			m = e.evalPortForward(r, ev, f, out)
		case KindScannerUserAgent:
			m = e.evalScannerUA(r, ev, f, out)
		}
		if m != nil {
			out.Matches = append(out.Matches, *m)
		}
	}
	return out
}

// --- field access ---------------------------------------------------

type fields map[string]any

func fieldsOf(ev *types.Event) fields {
	f := fields{}
	if len(ev.ServiceData) > 0 {
		_ = json.Unmarshal(ev.ServiceData, &f)
	}
	return f
}

func (f fields) str(k string) string {
	if v, ok := f[k].(string); ok {
		return v
	}
	return ""
}

func serviceAllowed(r *Rule, ev *types.Event) bool {
	if len(r.Params.Services) == 0 {
		return true
	}
	for _, s := range r.Params.Services {
		if s == ev.ServiceType.String() {
			return true
		}
	}
	return false
}

func isAuth(ev *types.Event) bool {
	return ev.EventType == types.EventLoginSuccess ||
		ev.EventType == types.EventLoginFailed
}

// --- window helpers -------------------------------------------------

func pruneBefore(es []entry, cutoff time.Time) []entry {
	i := 0
	for i < len(es) && es[i].ts.Before(cutoff) {
		i++
	}
	return es[i:]
}

// inWindow returns stored entries for key that fall inside the
// window ending at now. The current event is not included.
func (e *Engine) inWindow(key string, now time.Time, span time.Duration) []entry {
	w := e.state[key]
	if w == nil {
		return nil
	}
	cutoff := now.Add(-span)
	var out []entry
	for _, en := range w.entries {
		if !en.ts.Before(cutoff) && !en.ts.After(now) {
			out = append(out, en)
		}
	}
	return out
}

func (e *Engine) gc(now time.Time) {
	for k, w := range e.state {
		if len(w.entries) == 0 ||
			w.entries[len(w.entries)-1].ts.Before(now.Add(-w.span)) {
			delete(e.state, k)
		}
	}
	for k, s := range e.suppress {
		if s.until.Before(now) {
			delete(e.suppress, k)
		}
	}
}

func distinctValues(es []entry) []string {
	seen := map[string]bool{}
	var out []string
	for _, en := range es {
		if !seen[en.value] {
			seen[en.value] = true
			out = append(out, en.value)
		}
	}
	return out
}

// --- building a match -----------------------------------------------

func (e *Engine) fire(
	r *Rule, ev *types.Event, group string, contributing []entry,
	values map[string]any, explanation string, out *Evaluation,
) *Match {
	sk := r.ID + "|" + group
	det := types.Detection{
		RuleID:        r.ID,
		RuleVersion:   r.Version,
		RuleName:      r.Name,
		Severity:      r.Severity,
		Confidence:    r.Confidence,
		SensorID:      ev.SensorID,
		SourceIP:      ev.SourceIP,
		SessionID:     ev.SessionID,
		ServiceType:   ev.ServiceType,
		GroupKey:      group,
		FirstSeen:     ev.Timestamp,
		LastSeen:      ev.Timestamp,
		DetectedAt:    ev.Timestamp,
		Explanation:   explanation,
		MatchedValues: values,
		MITRE:         append([]string(nil), r.MITRE...),
	}
	for _, c := range contributing {
		if c.ts.Before(det.FirstSeen) {
			det.FirstSeen = c.ts
		}
	}

	if s := e.suppress[sk]; s != nil && ev.Timestamp.Before(s.until) {
		return &Match{
			Detection:  det,
			Suppressed: true,
			ExistingID: s.detID,
			Evidence: []types.DetectionEvidence{
				{EventRef: ev.Ref(), Role: "repeat"},
			},
		}
	}

	var evidence []types.DetectionEvidence
	seen := map[types.EventRef]bool{ev.Ref(): true}
	start := 0
	if len(contributing) > maxEvidenceRefs {
		start = len(contributing) - maxEvidenceRefs
		values["evidence_truncated_from"] = len(contributing)
	}
	for _, c := range contributing[start:] {
		if seen[c.ref] {
			continue
		}
		seen[c.ref] = true
		evidence = append(evidence, types.DetectionEvidence{
			EventRef: c.ref, Role: "contributing",
		})
	}
	evidence = append(evidence, types.DetectionEvidence{
		EventRef: ev.Ref(), Role: "trigger",
	})

	out.sets = append(out.sets, pendingSuppress{
		key:      sk,
		until:    ev.Timestamp.Add(r.SuppressFor),
		matchIdx: len(out.Matches),
	})
	return &Match{Detection: det, Evidence: evidence}
}

func (out *Evaluation) remember(key string, span time.Duration, ev *types.Event, value string) {
	out.appends = append(out.appends, pendingAppend{
		key: key, win: span,
		e: entry{ts: ev.Timestamp, ref: ev.Ref(), value: value},
	})
}

func timeRange(es []entry, ev *types.Event) string {
	first := ev.Timestamp
	for _, e := range es {
		if e.ts.Before(first) {
			first = e.ts
		}
	}
	a, b := first.UTC().Format("15:04:05Z"), ev.Timestamp.UTC().Format("15:04:05Z")
	if a == b {
		return "at " + a
	}
	return fmt.Sprintf("between %s and %s", a, b)
}

// --- rule kinds -----------------------------------------------------

func (e *Engine) evalAuthVolume(r *Rule, ev *types.Event, f fields, out *Evaluation) *Match {
	if !isAuth(ev) || !serviceAllowed(r, ev) {
		return nil
	}
	group := ev.SensorID + "|" + ev.SourceIP + "|" + ev.ServiceType.String()
	key := r.ID + "|" + group
	prior := e.inWindow(key, ev.Timestamp, r.Params.Window)
	out.remember(key, r.Params.Window, ev, ev.EventType.String())

	all := append(prior, entry{ts: ev.Timestamp, ref: ev.Ref(), value: ev.EventType.String()})
	if len(all) < r.Params.Threshold {
		return nil
	}
	succ, fail := 0, 0
	for _, a := range all {
		if a.value == types.EventLoginFailed.String() {
			fail++
		} else {
			succ++
		}
	}
	values := map[string]any{
		"attempts": len(all), "successes": succ, "failures": fail,
		"threshold": r.Params.Threshold, "window": r.Params.Window.String(),
		"auth_mode": f.str("auth_mode"),
	}
	expl := fmt.Sprintf(
		"%d authentication attempts (%d accepted, %d rejected) from %s to %s on %s %s. Threshold is %d within %s.",
		len(all), succ, fail, ev.SourceIP, ev.ServiceType, ev.SensorID,
		timeRange(prior, ev), r.Params.Threshold, r.Params.Window)
	if m := f.str("auth_mode"); m != "" {
		expl += " SSH auth mode: " + m + "."
	}
	return e.fire(r, ev, group, prior, values, expl, out)
}

func (e *Engine) evalFailureBurst(r *Rule, ev *types.Event, f fields, out *Evaluation) *Match {
	if ev.EventType != types.EventLoginFailed || !serviceAllowed(r, ev) {
		return nil
	}
	group := ev.SensorID + "|" + ev.SourceIP + "|" + ev.ServiceType.String()
	key := r.ID + "|" + group
	prior := e.inWindow(key, ev.Timestamp, r.Params.Window)
	user := f.str("username")
	out.remember(key, r.Params.Window, ev, user)
	if len(prior)+1 < r.Params.Threshold {
		return nil
	}
	users := distinctValues(append(prior, entry{value: user}))
	values := map[string]any{
		"failures": len(prior) + 1, "usernames": users,
		"threshold": r.Params.Threshold, "window": r.Params.Window.String(),
		"auth_mode": f.str("auth_mode"),
	}
	expl := fmt.Sprintf(
		"%d rejected logins from %s to %s %s, using %d distinct username(s): %s. Threshold is %d within %s.",
		len(prior)+1, ev.SourceIP, ev.ServiceType, timeRange(prior, ev),
		len(users), strings.Join(users, ", "), r.Params.Threshold, r.Params.Window)
	return e.fire(r, ev, group, prior, values, expl, out)
}

func (e *Engine) evalFailuresThenSuccess(r *Rule, ev *types.Event, f fields, out *Evaluation) *Match {
	if !isAuth(ev) || !serviceAllowed(r, ev) {
		return nil
	}
	user := f.str("username")
	group := ev.SensorID + "|" + ev.SourceIP + "|" + ev.ServiceType.String() + "|" + user
	key := r.ID + "|" + group
	if ev.EventType == types.EventLoginFailed {
		out.remember(key, r.Params.Window, ev, user)
		return nil
	}
	prior := e.inWindow(key, ev.Timestamp, r.Params.Window)
	if len(prior) < r.Params.Threshold {
		return nil
	}
	values := map[string]any{
		"username": user, "failures_before_success": len(prior),
		"threshold": r.Params.Threshold, "window": r.Params.Window.String(),
		"auth_mode": f.str("auth_mode"),
	}
	expl := fmt.Sprintf(
		"%d rejected logins for account %q from %s to %s, then an accepted login for the same account at %s. Threshold is %d failures within %s before the success.",
		len(prior), user, ev.SourceIP, ev.ServiceType,
		ev.Timestamp.UTC().Format("15:04:05Z"), r.Params.Threshold, r.Params.Window)
	return e.fire(r, ev, group, prior, values, expl, out)
}

// NormalizePath lowercases and cleans an HTTP path for matching.
func NormalizePath(p string) string {
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	p = strings.ToLower(p)
	trailing := strings.HasSuffix(p, "/")
	p = path.Clean("/" + p)
	if trailing && p != "/" {
		p += "/"
	}
	return p
}

func sensitiveMatch(paths []string, p string) string {
	for _, want := range paths {
		w := strings.ToLower(want)
		if strings.HasSuffix(w, "/") {
			if strings.HasPrefix(p, w) || p+"/" == w {
				return w
			}
		} else if p == w {
			return w
		}
	}
	return ""
}

func (e *Engine) evalHTTPPaths(r *Rule, ev *types.Event, f fields, out *Evaluation) *Match {
	if ev.ServiceType != types.ServiceHTTP || ev.EventType != types.EventRequest {
		return nil
	}
	hit := sensitiveMatch(r.Params.Paths, NormalizePath(f.str("path")))
	if hit == "" {
		return nil
	}
	group := ev.SensorID + "|" + ev.SourceIP
	key := r.ID + "|" + group
	prior := e.inWindow(key, ev.Timestamp, r.Params.Window)
	out.remember(key, r.Params.Window, ev, hit)
	distinct := distinctValues(append(prior, entry{value: hit}))
	if len(distinct) < r.Params.Threshold {
		return nil
	}
	values := map[string]any{
		"distinct_paths": distinct, "requests": len(prior) + 1,
		"threshold": r.Params.Threshold, "window": r.Params.Window.String(),
	}
	expl := fmt.Sprintf(
		"%s requested %d distinct sensitive paths (%s) %s. Threshold is %d distinct paths within %s.",
		ev.SourceIP, len(distinct), strings.Join(distinct, ", "),
		timeRange(prior, ev), r.Params.Threshold, r.Params.Window)
	return e.fire(r, ev, group, prior, values, expl, out)
}

func (e *Engine) evalMultiService(r *Rule, ev *types.Event, out *Evaluation) *Match {
	switch ev.EventType {
	case types.EventConnect, types.EventRequest:
	default:
		return nil
	}
	svc := ev.ServiceType.String()
	group := ev.SensorID + "|" + ev.SourceIP
	key := r.ID + "|" + group
	prior := e.inWindow(key, ev.Timestamp, r.Params.Window)
	out.remember(key, r.Params.Window, ev, svc)

	distinct := distinctValues(append(prior, entry{value: svc}))
	if len(distinct) < r.Params.Threshold {
		return nil
	}
	// Only the first event per service is evidence; repeated
	// requests to one service add nothing.
	var firsts []entry
	seen := map[string]bool{svc: true}
	for _, p := range prior {
		if !seen[p.value] {
			seen[p.value] = true
			firsts = append(firsts, p)
		}
	}
	sort.Strings(distinct)
	values := map[string]any{
		"services": distinct, "threshold": r.Params.Threshold,
		"window": r.Params.Window.String(),
	}
	expl := fmt.Sprintf(
		"%s contacted %d different decoy services on %s (%s) %s. Threshold is %d services within %s.",
		ev.SourceIP, len(distinct), ev.SensorID, strings.Join(distinct, ", "),
		timeRange(firsts, ev), r.Params.Threshold, r.Params.Window)
	return e.fire(r, ev, group, firsts, values, expl, out)
}

func discoveryName(r *Rule, c SimpleCommand) string {
	for _, want := range r.Params.Commands {
		if c.Name == want {
			return c.Name
		}
	}
	switch c.Name {
	case "cat", "head", "tail", "less", "more":
		for _, a := range c.Args {
			for _, fr := range r.Params.FileReads {
				if a == fr {
					return c.Name + " " + fr
				}
			}
		}
	}
	return ""
}

func (e *Engine) evalDiscovery(r *Rule, ev *types.Event, f fields, out *Evaluation) *Match {
	if ev.ServiceType != types.ServiceSSH || ev.EventType != types.EventCommand {
		return nil
	}
	var names []string
	for _, c := range ParseCommandLine(f.str("command")) {
		if n := discoveryName(r, c); n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil
	}
	group := ev.SessionID
	key := r.ID + "|" + group
	prior := e.inWindow(key, ev.Timestamp, r.Params.Window)
	for _, n := range names {
		out.remember(key, r.Params.Window, ev, n)
	}
	all := append([]entry(nil), prior...)
	for _, n := range names {
		all = append(all, entry{value: n})
	}
	distinct := distinctValues(all)
	if len(distinct) < r.Params.Threshold {
		return nil
	}
	values := map[string]any{
		"commands": distinct, "threshold": r.Params.Threshold,
		"window": r.Params.Window.String(),
	}
	expl := fmt.Sprintf(
		"SSH session %s ran %d distinct discovery commands (%s) %s. Threshold is %d within one session and %s.",
		ev.SessionID, len(distinct), strings.Join(distinct, "; "),
		timeRange(prior, ev), r.Params.Threshold, r.Params.Window)
	return e.fire(r, ev, group, prior, values, expl, out)
}

var (
	urlArg  = regexp.MustCompile(`^(?i)(https?|ftp|tftp)://[^\s]+$`)
	hostArg = regexp.MustCompile(`^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}(:[0-9]+)?/\S*$|^[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?/\S*$`)
)

func (e *Engine) evalTransfer(r *Rule, ev *types.Event, f fields, out *Evaluation) *Match {
	if ev.ServiceType != types.ServiceSSH || ev.EventType != types.EventCommand {
		return nil
	}
	for _, c := range ParseCommandLine(f.str("command")) {
		isTool := false
		for _, t := range r.Params.Commands {
			if c.Name == t {
				isTool = true
			}
		}
		if !isTool {
			continue
		}
		for _, a := range c.Args {
			if !urlArg.MatchString(a) && !hostArg.MatchString(a) {
				continue
			}
			group := ev.SessionID + "|" + strings.ToLower(a)
			values := map[string]any{
				"command": c.Name, "target": a, "command_line": c.Raw,
			}
			expl := fmt.Sprintf(
				"SSH session %s ran %s with the target %s. The honeypot shell simulates the command; this shows an attempted transfer, not a completed download.",
				ev.SessionID, c.Name, a)
			return e.fire(r, ev, group, nil, values, expl, out)
		}
	}
	return nil
}

func (e *Engine) evalRedisWrite(r *Rule, ev *types.Event, f fields, out *Evaluation) *Match {
	if ev.ServiceType != types.ServiceRedis || ev.EventType != types.EventExploit {
		return nil
	}
	cmd := strings.ToUpper(f.str("command"))
	match := false
	for _, c := range r.Params.Commands {
		if strings.EqualFold(c, cmd) {
			match = true
		}
	}
	if !match {
		return nil
	}
	group := ev.SensorID + "|" + ev.SourceIP + "|" + cmd
	values := map[string]any{"command": cmd, "raw": f.str("raw")}
	expl := fmt.Sprintf(
		"%s sent the Redis command %q to the Redis decoy. The decoy does not apply configuration changes.",
		ev.SourceIP, f.str("raw"))
	return e.fire(r, ev, group, nil, values, expl, out)
}

func (e *Engine) evalPortForward(r *Rule, ev *types.Event, f fields, out *Evaluation) *Match {
	if ev.ServiceType != types.ServiceSSH || f.str("channel_type") != "direct-tcpip" {
		return nil
	}
	target := f.str("target")
	values := map[string]any{"channel_type": "direct-tcpip", "target": target}
	expl := fmt.Sprintf(
		"SSH session %s asked the server to open a forwarded TCP connection to %s. The request was refused.",
		ev.SessionID, orUnknown(target))
	return e.fire(r, ev, ev.SessionID, nil, values, expl, out)
}

func (e *Engine) evalScannerUA(r *Rule, ev *types.Event, f fields, out *Evaluation) *Match {
	if ev.EventType != types.EventScan || f.str("scanner") == "" {
		return nil
	}
	scanner := f.str("scanner")
	group := ev.SensorID + "|" + ev.SourceIP + "|" + scanner
	values := map[string]any{
		"scanner": scanner, "user_agent": f.str("user_agent"), "claimed": true,
	}
	expl := fmt.Sprintf(
		"%s sent a User-Agent that matches the %s scanner. The header is chosen by the client, so this is a claim, not proof of the tool used.",
		ev.SourceIP, scanner)
	return e.fire(r, ev, group, nil, values, expl, out)
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown target"
	}
	return s
}
