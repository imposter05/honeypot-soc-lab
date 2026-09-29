package cases

import (
	"testing"

	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

func s(v string) *string { return &v }

func TestValidatePatch(t *testing.T) {
	open := &types.Case{Status: types.CaseInvestigating}
	closed := &types.Case{Status: types.CaseClosed, Verdict: "benign", ClosureReason: "lab test"}
	tests := []struct {
		name string
		cur  *types.Case
		p    store.CasePatch
		ok   bool
	}{
		{"close without verdict", open, store.CasePatch{Status: s("closed"), ClosureReason: s("x")}, false},
		{"close without reason", open, store.CasePatch{Status: s("closed"), Verdict: s("benign")}, false},
		{"close properly", open, store.CasePatch{Status: s("closed"), Verdict: s("expected-test"), ClosureReason: s("lab run 12")}, true},
		{"bad verdict", open, store.CasePatch{Verdict: s("evil")}, false},
		{"reopen to investigating", closed, store.CasePatch{Status: s("investigating")}, true},
		{"reopen to new", closed, store.CasePatch{Status: s("new")}, false},
		{"bad severity", open, store.CasePatch{Severity: s("urgent")}, false},
	}
	for _, tt := range tests {
		err := ValidatePatch(tt.cur, tt.p)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err=%v", tt.name, err)
		}
	}
}
