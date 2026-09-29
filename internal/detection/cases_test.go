/*
Hiten | 2026
cases_test.go

Runs the synthetic rule cases in testdata/detections/cases.yaml and
checks that every enabled rule has passing positive and negative
cases. These are unit tests on in-memory events; the lab runner in
cmd/labtest covers real network connections.
*/

package detection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

type caseEvent struct {
	At      time.Duration  `yaml:"at"`
	Service string         `yaml:"service"`
	Type    string         `yaml:"type"`
	Source  string         `yaml:"source"`
	Session string         `yaml:"session"`
	Data    map[string]any `yaml:"data"`
}

type ruleCase struct {
	Name     string      `yaml:"name"`
	Rule     string      `yaml:"rule"`
	Expect   string      `yaml:"expect"`
	Evidence int         `yaml:"evidence"`
	Events   []caseEvent `yaml:"events"`
}

func loadCases(t *testing.T) []ruleCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "detections", "cases.yaml"))
	if err != nil {
		t.Fatalf("reading cases: %v", err)
	}
	var doc struct {
		Cases []ruleCase `yaml:"cases"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing cases: %v", err)
	}
	return doc.Cases
}

var base = time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

func buildEvent(i int, ce caseEvent) *types.Event {
	svc, ok := types.ParseServiceType(ce.Service)
	if !ok {
		panic("unknown service " + ce.Service)
	}
	et, ok := types.ParseEventType(ce.Type)
	if !ok {
		panic("unknown event type " + ce.Type)
	}
	src := ce.Source
	if src == "" {
		src = "203.0.113.10"
	}
	sess := ce.Session
	if sess == "" {
		sess = "s1"
	}
	var raw json.RawMessage
	if ce.Data != nil {
		raw, _ = json.Marshal(ce.Data)
	}
	return &types.Event{
		ID:          fmt.Sprintf("ev-%03d", i),
		SessionID:   sess,
		SensorID:    "hive-01",
		Timestamp:   base.Add(ce.At),
		ServiceType: svc,
		EventType:   et,
		SourceIP:    src,
		ServiceData: raw,
	}
}

// runCase feeds the events through a fresh engine holding only the
// rule under test, applying each evaluation as the processor would.
func runCase(t *testing.T, all []*Rule, c ruleCase) []Match {
	t.Helper()
	var r *Rule
	for _, x := range all {
		if x.ID == c.Rule {
			r = x
		}
	}
	if r == nil {
		t.Fatalf("case %s names unknown rule %s", c.Name, c.Rule)
	}
	eng := NewEngine([]*Rule{r})
	var fired []Match
	var nextID int64 = 1
	for i, ce := range c.Events {
		ev := eng.Evaluate(buildEvent(i, ce))
		ids := make([]int64, len(ev.Matches))
		for j, m := range ev.Matches {
			if !m.Suppressed {
				ids[j] = nextID
				nextID++
				fired = append(fired, m)
			}
		}
		ev.Apply(ids)
	}
	return fired
}

func TestRuleCases(t *testing.T) {
	rs, _, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range loadCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			fired := runCase(t, rs, c)
			switch c.Expect {
			case "match":
				if len(fired) == 0 {
					t.Fatalf("expected %s to match, it did not", c.Rule)
				}
				d := fired[0]
				if d.Detection.Explanation == "" {
					t.Error("match has no explanation")
				}
				if c.Evidence > 0 && len(d.Evidence) != c.Evidence {
					t.Errorf("evidence refs = %d, want %d", len(d.Evidence), c.Evidence)
				}
				if d.Evidence[len(d.Evidence)-1].Role != "trigger" {
					t.Error("last evidence ref should be the trigger")
				}
			case "no_match":
				if len(fired) > 0 {
					t.Fatalf("expected no match, got: %s", fired[0].Detection.Explanation)
				}
			default:
				t.Fatalf("expect must be match or no_match, got %q", c.Expect)
			}
		})
	}
}

// Every enabled rule must name positive and negative cases that
// exist and use the right expectation.
func TestEveryRuleHasTests(t *testing.T) {
	rs, _, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ruleCase{}
	for _, c := range loadCases(t) {
		byName[c.Name] = c
	}
	for _, r := range rs {
		if !r.Enabled {
			continue
		}
		check := func(names []string, want string) {
			for _, n := range names {
				c, ok := byName[n]
				switch {
				case !ok:
					t.Errorf("%s lists test %q which is not in cases.yaml", r.ID, n)
				case c.Rule != r.ID:
					t.Errorf("%s lists test %q which belongs to %s", r.ID, n, c.Rule)
				case c.Expect != want:
					t.Errorf("%s lists %q as %s but it expects %s", r.ID, n, want, c.Expect)
				}
			}
		}
		check(r.Tests.Positive, "match")
		check(r.Tests.Negative, "no_match")
	}
}

func TestSuppressionAddsRepeats(t *testing.T) {
	rs, _, _ := LoadRules("")
	var r *Rule
	for _, x := range rs {
		if x.ID == "HLAB-AUTH-001" {
			r = x
		}
	}
	eng := NewEngine([]*Rule{r})
	var fired, repeats int
	for i := 0; i < 8; i++ {
		ev := eng.Evaluate(buildEvent(i, caseEvent{
			At: time.Duration(i) * time.Second, Service: "ssh", Type: "login.success",
		}))
		ids := make([]int64, len(ev.Matches))
		for j, m := range ev.Matches {
			if m.Suppressed {
				repeats++
				if m.ExistingID != 42 {
					t.Errorf("repeat should point at detection 42, got %d", m.ExistingID)
				}
			} else {
				fired++
				ids[j] = 42
			}
		}
		ev.Apply(ids)
	}
	if fired != 1 || repeats != 3 {
		t.Fatalf("fired=%d repeats=%d, want 1 and 3", fired, repeats)
	}
}

// If the processor never calls Apply (the database write failed),
// the event must not count toward later matches.
func TestUnappliedEventsAreNotCounted(t *testing.T) {
	rs, _, _ := LoadRules("")
	var r *Rule
	for _, x := range rs {
		if x.ID == "HLAB-AUTH-001" {
			r = x
		}
	}
	eng := NewEngine([]*Rule{r})
	for i := 0; i < 5; i++ {
		ev := eng.Evaluate(buildEvent(i, caseEvent{
			At: time.Duration(i) * time.Second, Service: "ssh", Type: "login.success",
		}))
		if i == 2 {
			continue // simulated failed commit
		}
		ev.Apply(make([]int64, len(ev.Matches)))
	}
	ev := eng.Evaluate(buildEvent(9, caseEvent{At: 6 * time.Second, Service: "ssh", Type: "login.success"}))
	if len(ev.Matches) != 1 {
		t.Fatalf("expected a match on the 5th stored event")
	}
	if n := len(ev.Matches[0].Evidence); n != 5 {
		t.Fatalf("evidence = %d, want 5 (the unapplied event must be absent)", n)
	}
}

func TestInvalidRulesRejected(t *testing.T) {
	_, err := ParseRules([]byte(`rules:
  - id: bad
    version: 0
    kind: nope
    severity: extreme
    confidence: 100
`))
	if err == nil {
		t.Fatal("expected validation error")
	}
}
