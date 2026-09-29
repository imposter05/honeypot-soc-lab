/*
Hiten | 2026
cases.go

Case correlation and validation rules.

Detections are grouped by sensor and source address within
cases.correlation_window. A shared address is not proof of a shared
actor (NAT, shared lab hosts), so the window stops cases growing
forever, and analysts can split or merge cases by hand. Both are
written to the case history.
*/

package cases

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type Store interface {
	AttachDetections(ctx context.Context, dets []types.Detection, window time.Duration, actor string) (*store.AttachResult, error)
}

// SeverityHook receives cases that were created or whose severity
// changed, as [before, after] (before is "" for a new case).
type SeverityHook func(ctx context.Context, changes map[int64][2]string)

type Manager struct {
	store  Store
	window time.Duration
	hook   SeverityHook
}

func NewManager(st Store, window time.Duration, hook SeverityHook) *Manager {
	return &Manager{store: st, window: window, hook: hook}
}

func (m *Manager) Attach(ctx context.Context, dets []types.Detection) ([]int64, error) {
	res, err := m.store.AttachDetections(ctx, dets, m.window, "correlator")
	if err != nil {
		return nil, err
	}
	if len(res.Severity) > 0 && m.hook != nil {
		m.hook(ctx, res.Severity)
	}
	return res.CaseIDs, nil
}

var (
	statuses = map[string]bool{types.CaseNew: true, types.CaseInvestigating: true, types.CaseClosed: true}
	verdicts = map[string]bool{
		types.VerdictSuspicious: true, types.VerdictBenign: true,
		types.VerdictExpectedTest: true, types.VerdictInsufficient: true,
	}
)

// ValidatePatch checks an analyst change against the current case.
func ValidatePatch(cur *types.Case, p store.CasePatch) error {
	var problems []string
	if cur.MergedInto != nil {
		return fmt.Errorf("this case was merged into %s; edit that case instead", store.CaseRef(*cur.MergedInto))
	}
	if p.Status != nil && !statuses[*p.Status] {
		problems = append(problems, "status must be new, investigating or closed")
	}
	if p.Verdict != nil && *p.Verdict != "" && !verdicts[*p.Verdict] {
		problems = append(problems, "verdict must be suspicious, benign, expected-test or insufficient-evidence")
	}
	if p.Severity != nil {
		if _, ok := config.SeverityRank[*p.Severity]; !ok {
			problems = append(problems, "severity must be low, medium, high or critical")
		}
	}
	if p.Title != nil && strings.TrimSpace(*p.Title) == "" {
		problems = append(problems, "title cannot be empty")
	}

	status := cur.Status
	if p.Status != nil {
		status = *p.Status
	}
	verdict := cur.Verdict
	if p.Verdict != nil {
		verdict = *p.Verdict
	}
	reason := cur.ClosureReason
	if p.ClosureReason != nil {
		reason = *p.ClosureReason
	}
	if status == types.CaseClosed {
		if verdict == "" {
			problems = append(problems, "closing a case needs a verdict")
		}
		if strings.TrimSpace(reason) == "" {
			problems = append(problems, "closing a case needs a closure explanation")
		}
	}
	if cur.Status == types.CaseClosed && p.Status != nil && *p.Status == types.CaseNew {
		problems = append(problems, "a closed case can be reopened to investigating, not new")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}
