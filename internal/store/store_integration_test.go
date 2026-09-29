/*
Hiten | 2026
store_integration_test.go

Runs against a real, migrated PostgreSQL database. Skipped unless
HIVE_TEST_DSN is set, for example:

  HIVE_TEST_DSN=postgres://hive:hive@127.0.0.1:5432/hive_test?sslmode=disable \
    go test ./internal/store/

Each test uses its own random source address so it does not collide
with other data in the database.
*/

package store

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/detection"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

func testStore(t *testing.T) *PgxStore {
	t.Helper()
	dsn := os.Getenv("HIVE_TEST_DSN")
	if dsn == "" {
		t.Skip("HIVE_TEST_DSN not set")
	}
	cfg := config.Default().Database
	cfg.DSN = dsn
	s, err := NewPgxStore(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	ctx := context.Background()
	if v, err := s.SchemaVersion(ctx); err != nil || v < config.RequiredMigration {
		t.Skipf("database not migrated (version %d, err %v)", v, err)
	}
	if err := s.UpsertSensor(ctx, &types.Sensor{ID: "itest", Hostname: "itest",
		Services: []string{"ssh"}, StartedAt: time.Now(), Status: "active"}); err != nil {
		t.Fatal(err)
	}
	rules, _, _ := detection.LoadRules("")
	var rows []RuleRow
	for _, r := range rules {
		rows = append(rows, RuleRow{ID: r.ID, Version: r.Version, Name: r.Name, Enabled: true, Definition: []byte("{}")})
	}
	if err := s.SyncRules(ctx, rows); err != nil {
		t.Fatal(err)
	}
	return s
}

func randIP() string {
	return fmt.Sprintf("198.51.100.%d", rand.IntN(250)+1)
}

func testEvent(src string, ts time.Time) *types.Event {
	return &types.Event{
		ID: uuid.Must(uuid.NewV7()).String(), SessionID: "itest-" + src, SensorID: "itest",
		Timestamp: ts, ReceivedAt: time.Now().UTC(), ServiceType: types.ServiceSSH,
		EventType: types.EventLoginSuccess, SourceIP: src, SourcePort: 40000,
		DestIP: "127.0.0.1", DestPort: 2222, SchemaVersion: 1, Origin: "external",
		ServiceData: []byte(`{"username":"root","password":"x"}`),
	}
}

// Five logins trigger HLAB-AUTH-001; the sixth is a suppressed repeat
// added to the same detection.
func TestCommitDetectionsAndRepeats(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	rules, _, _ := detection.LoadRules("")
	eng := detection.NewEngine(rules)
	src := randIP()
	base := time.Now().UTC().Truncate(time.Second)

	var detID int64
	var lastSeq int64
	for i := 0; i < 6; i++ {
		ev := testEvent(src, base.Add(time.Duration(i)*time.Second))
		if err := s.EnsurePartitionFor(ctx, ev.Timestamp); err != nil {
			t.Fatal(err)
		}
		evl := eng.Evaluate(ev)
		res, err := s.CommitAnalysis(ctx, &Analysis{Event: ev, Matches: evl.Matches,
			Credential: &types.Credential{SessionID: ev.SessionID, Timestamp: ev.Timestamp,
				ServiceType: ev.ServiceType, SourceIP: src, Username: "root", Password: "x",
				AuthMethod: "password", Success: true}})
		if err != nil {
			t.Fatal(err)
		}
		if res.Seq <= lastSeq {
			t.Fatalf("seq did not increase: %d then %d", lastSeq, res.Seq)
		}
		lastSeq = res.Seq
		ids := make([]int64, len(res.Detections))
		for j, d := range res.Detections {
			if !evl.Matches[j].Suppressed {
				ids[j] = d.ID
				detID = d.ID
			}
		}
		evl.Apply(ids)
	}
	d, err := s.GetDetection(ctx, detID)
	if err != nil {
		t.Fatal(err)
	}
	if d.RuleID != "HLAB-AUTH-001" || d.SuppressedCount != 1 {
		t.Fatalf("detection %s suppressed=%d", d.RuleID, d.SuppressedCount)
	}
	roles := map[string]int{}
	for _, e := range d.Evidence {
		roles[e.Role]++
	}
	if roles["trigger"] != 1 || roles["contributing"] != 4 || roles["repeat"] != 1 {
		t.Fatalf("evidence roles %v", roles)
	}
	evs, err := s.EventsByRefs(ctx, []types.EventRef{d.Evidence[0].EventRef})
	if err != nil || len(evs) != 1 {
		t.Fatalf("evidence event not loadable: %v", err)
	}
}

// Old timestamps (replayed data) get their partition created.
func TestPartitionForOldMonth(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ts := time.Date(2024, 2, 10, 12, 0, 0, 0, time.UTC)
	if err := s.EnsurePartitionFor(ctx, ts); err != nil {
		t.Fatal(err)
	}
	ev := testEvent(randIP(), ts)
	if _, err := s.CommitAnalysis(ctx, &Analysis{Event: ev}); err != nil {
		t.Fatalf("insert into old month: %v", err)
	}
}

func TestCaseCorrelationAndHistory(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	src := randIP()
	now := time.Now().UTC()

	mk := func(at time.Time, rule string) types.Detection {
		ev := testEvent(src, at)
		_ = s.EnsurePartitionFor(ctx, at)
		res, err := s.CommitAnalysis(ctx, &Analysis{Event: ev, Matches: []detection.Match{{
			Detection: types.Detection{RuleID: rule, RuleVersion: 1, RuleName: rule,
				Severity: "medium", Confidence: "medium", SensorID: "itest", SourceIP: src,
				ServiceType: types.ServiceSSH, GroupKey: src, FirstSeen: at, LastSeen: at,
				DetectedAt: at, Explanation: "test", MatchedValues: map[string]any{}},
			Evidence: []types.DetectionEvidence{{EventRef: ev.Ref(), Role: "trigger"}},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return res.Detections[0]
	}

	a, err := s.AttachDetections(ctx, []types.Detection{mk(now, "HLAB-AUTH-001")}, 30*time.Minute, "test")
	if err != nil || len(a.Created) != 1 {
		t.Fatalf("first detection should create a case: %+v %v", a, err)
	}
	b, _ := s.AttachDetections(ctx, []types.Detection{mk(now.Add(5*time.Minute), "HLAB-NET-001")}, 30*time.Minute, "test")
	if len(b.Created) != 0 || b.CaseIDs[0] != a.Created[0] {
		t.Fatal("detection inside the window should join the open case")
	}
	c, _ := s.AttachDetections(ctx, []types.Detection{mk(now.Add(2*time.Hour), "HLAB-NET-001")}, 30*time.Minute, "test")
	if len(c.Created) != 1 {
		t.Fatal("detection outside the window should open a new case")
	}

	caseID := a.Created[0]
	closed := "closed"
	if _, err := s.UpdateCase(ctx, caseID, CasePatch{Status: &closed}, "test"); err == nil {
		t.Fatal("database must reject closing without verdict and reason")
	}
	verdict, reason := "expected-test", "integration test"
	if _, err := s.UpdateCase(ctx, caseID, CasePatch{Status: &closed, Verdict: &verdict, ClosureReason: &reason}, "test"); err != nil {
		t.Fatal(err)
	}
	h, _ := s.CaseHistory(ctx, caseID)
	if len(h) < 4 {
		t.Fatalf("expected history rows for create, links and changes, got %d", len(h))
	}
	if _, err := s.pool.Exec(ctx, `UPDATE case_history SET actor = 'x' WHERE case_id = $1`, caseID); err == nil {
		t.Fatal("case_history must reject UPDATE")
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM case_history WHERE case_id = $1`, caseID); err == nil {
		t.Fatal("case_history must reject DELETE")
	}
}

func TestActionDuplicateAndTransitions(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	src := randIP()
	now := time.Now().UTC()
	var caseID int64
	if err := s.pool.QueryRow(ctx, `INSERT INTO cases (title, severity, sensor_id, source_ip, first_activity, last_activity)
		VALUES ('t', 'high', 'itest', $1, $2, $2) RETURNING id`, src, now).Scan(&caseID); err != nil {
		t.Fatal(err)
	}
	a := &types.ResponseAction{CaseID: caseID, Playbook: "restrict-lab-source", SourceIP: src,
		SensorID: "itest", Services: []string{"ssh"}, Summary: "test"}
	first, err := s.CreateAction(ctx, a, "test")
	if err != nil {
		t.Fatal(err)
	}
	dup, err := s.CreateAction(ctx, a, "test")
	if !errors.Is(err, ErrDuplicate) || dup == nil || dup.ID != first.ID {
		t.Fatalf("second request should return the open action, got %v", err)
	}
	if _, err := s.Transition(ctx, first.ID, []string{types.ActionActive}, types.ActionReversed,
		"test", ActionUpdate{}, nil); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("reversing a pending action must fail, got %v", err)
	}
	if _, err := s.Transition(ctx, first.ID, []string{types.ActionPending}, types.ActionRejected,
		"test", ActionUpdate{Ended: true}, map[string]any{"reason": "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAction(ctx, a, "test"); err != nil {
		t.Fatalf("after rejection a new request is allowed: %v", err)
	}
}
