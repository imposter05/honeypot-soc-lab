/*
Hiten | 2026
cases.go

Incident (case) endpoints. Every change goes through the store,
which writes the case history in the same transaction.
*/

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CarterPerez-dev/hive/internal/cases"
	"github.com/CarterPerez-dev/hive/internal/redact"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	// pageSize is how many rows are read per query when a whole list
	// is needed. It is not a limit on the result.
	pageSize = 500
	// timelinePage is the default page size for the case timeline.
	timelinePage = 500
	// mdTimelineRows is how many events the Markdown report lists in
	// its table. The report states the full count and the JSON export
	// always has every event.
	mdTimelineRows = 500
)

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := pagination(r)
	list, total, err := s.d.Store.ListCases(r.Context(), store.CaseFilter{
		Status: q.Get("status"), Severity: q.Get("severity"), SourceIP: q.Get("source"),
		IncludeMerged: q.Get("merged") == "true", Limit: limit, Offset: offset,
	})
	if err != nil {
		s.storeError(w, err)
		return
	}
	writePage(w, list, total, limit, offset)
}

// caseBundle is everything the case page and exports show.
type caseBundle struct {
	Case        *types.Case              `json:"case"`
	Detections  []*types.Detection       `json:"detections"`
	Notes       []types.CaseNote         `json:"notes"`
	History     []types.CaseHistoryEntry `json:"history"`
	Evidence    []types.CaseEvent        `json:"added_evidence"`
	Actions     []*types.ResponseAction  `json:"actions"`
	Observables []*types.IOC             `json:"observables"`
	Timeline    []*types.Event           `json:"timeline,omitempty"`
	// TimelineTotal is the number of linked events; an export has
	// all of them in Timeline.
	TimelineTotal int                                  `json:"timeline_total,omitempty"`
	SecretsMasked bool                                 `json:"secrets_masked"`
	ActionLogs    map[int64][]types.ActionHistoryEntry `json:"action_history,omitempty"`
}

// loadCase reads a case and everything linked to it. Lists are read
// page by page until the end, so nothing is silently cut off.
// withTimeline also loads every linked event and each action's
// history (for exports). Secrets are masked unless reveal is true.
func (s *Server) loadCase(r *http.Request, id int64, withTimeline, reveal bool) (*caseBundle, error) {
	ctx := r.Context()
	b := &caseBundle{}
	var err error
	if b.Case, err = s.d.Store.GetCase(ctx, id); err != nil {
		return nil, err
	}
	for off := 0; ; off += pageSize {
		page, total, err := s.d.Store.ListDetections(ctx, store.DetectionFilter{CaseID: id, Limit: pageSize, Offset: off})
		if err != nil {
			return nil, err
		}
		b.Detections = append(b.Detections, page...)
		if int64(len(b.Detections)) >= total || len(page) == 0 {
			break
		}
	}
	for _, d := range b.Detections {
		if d.Evidence, err = s.d.Store.DetectionEvidence(ctx, d.ID); err != nil {
			return nil, err
		}
	}
	if b.Notes, err = s.d.Store.CaseNotes(ctx, id); err != nil {
		return nil, err
	}
	if b.History, err = s.d.Store.CaseHistory(ctx, id); err != nil {
		return nil, err
	}
	if b.Evidence, err = s.d.Store.CaseDirectEvents(ctx, id); err != nil {
		return nil, err
	}
	for off := 0; ; off += pageSize {
		page, total, err := s.d.Store.ListActions(ctx, store.ActionFilter{CaseID: id, Limit: pageSize, Offset: off})
		if err != nil {
			return nil, err
		}
		b.Actions = append(b.Actions, page...)
		if int64(len(b.Actions)) >= total || len(page) == 0 {
			break
		}
	}
	for off := 0; ; off += pageSize {
		page, total, err := s.d.Store.ListObservables(ctx, store.ObservableFilter{CaseID: id, Limit: pageSize, Offset: off})
		if err != nil {
			return nil, err
		}
		b.Observables = append(b.Observables, page...)
		if int64(len(b.Observables)) >= total || len(page) == 0 {
			break
		}
	}
	if withTimeline {
		refs, err := s.d.Store.CaseEventRefs(ctx, id)
		if err != nil {
			return nil, err
		}
		for start := 0; start < len(refs); start += pageSize {
			end := min(start+pageSize, len(refs))
			evs, err := s.d.Store.EventsByRefs(ctx, refs[start:end])
			if err != nil {
				return nil, err
			}
			b.Timeline = append(b.Timeline, evs...)
		}
		b.TimelineTotal = len(refs)
		b.ActionLogs = map[int64][]types.ActionHistoryEntry{}
		for _, a := range b.Actions {
			if b.ActionLogs[a.ID], err = s.d.Store.ActionHistory(ctx, a.ID); err != nil {
				return nil, err
			}
		}
	}
	if !reveal {
		b.Detections = redactDetections(b.Detections)
		b.Timeline = redact.Events(b.Timeline)
		for i, o := range b.Observables {
			b.Observables[i] = redact.Observable(o)
		}
	}
	b.SecretsMasked = !reveal
	return b, nil
}

func (s *Server) handleIncidentByID(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	b, err := s.loadCase(r, id, false, s.wantSecrets(r))
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, b)
}

// handleIncidentTimeline returns the case's events, oldest first, a
// page at a time. total is the number of linked events.
func (s *Server) handleIncidentTimeline(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	limit, offset := pagination(r)
	if r.URL.Query().Get("limit") == "" {
		limit = timelinePage
	}
	refs, err := s.d.Store.CaseEventRefs(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	total := len(refs)
	if offset > total {
		offset = total
	}
	end := min(offset+limit, total)
	evs, err := s.d.Store.EventsByRefs(r.Context(), refs[offset:end])
	if err != nil {
		s.storeError(w, err)
		return
	}
	if !s.wantSecrets(r) {
		evs = redact.Events(evs)
	}
	writePage(w, evs, int64(total), limit, offset)
}

type casePatchBody struct {
	Title            *string `json:"title"`
	Status           *string `json:"status"`
	Severity         *string `json:"severity"`
	Verdict          *string `json:"verdict"`
	ResponseDecision *string `json:"response_decision"`
	ClosureReason    *string `json:"closure_reason"`
}

func (s *Server) handleIncidentPatch(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	var body casePatchBody
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cur, err := s.d.Store.GetCase(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	p := store.CasePatch(body)
	if err := cases.ValidatePatch(cur, p); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	c, err := s.d.Store.UpdateCase(r.Context(), id, p, s.actor(r))
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, c)
}

func (s *Server) handleIncidentNote(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	var body struct {
		Body string `json:"body"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	text := strings.TrimSpace(body.Body)
	if text == "" || len(text) > 20000 {
		writeError(w, http.StatusBadRequest, "note must be 1 to 20000 characters")
		return
	}
	if _, err := s.d.Store.GetCase(r.Context(), id); err != nil {
		s.storeError(w, err)
		return
	}
	n, err := s.d.Store.AddCaseNote(r.Context(), id, s.actor(r), text)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope{Data: n})
}

func (s *Server) handleIncidentEvidence(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	var body struct {
		EventID string `json:"event_id"`
		Note    string `json:"note"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.d.Store.GetCase(r.Context(), id); err != nil {
		s.storeError(w, err)
		return
	}
	ev, err := s.d.Store.GetEvent(r.Context(), body.EventID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "event not found")
			return
		}
		s.storeError(w, err)
		return
	}
	if err := s.d.Store.AddCaseEvent(r.Context(), id, ev.Ref(), s.actor(r), body.Note); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "event is already linked to this case")
			return
		}
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope{Data: ev.Ref()})
}

func (s *Server) handleIncidentSplit(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	var body struct {
		DetectionIDs []int64 `json:"detection_ids"`
		Title        string  `json:"title"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(body.DetectionIDs) == 0 {
		writeError(w, http.StatusBadRequest, "choose the detections to move")
		return
	}
	newID, err := s.d.Store.SplitCase(r.Context(), id, body.DetectionIDs, body.Title, s.actor(r))
	if err != nil {
		s.storeError(w, err)
		return
	}
	c, err := s.d.Store.GetCase(r.Context(), newID)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope{Data: c})
}

func (s *Server) handleIncidentMerge(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	var body struct {
		FromCaseID int64 `json:"from_case_id"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.d.Store.MergeCase(r.Context(), id, body.FromCaseID, s.actor(r)); err != nil {
		s.storeError(w, err)
		return
	}
	c, err := s.d.Store.GetCase(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, c)
}

func (s *Server) handleIncidentRequestAction(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	c, err := s.d.Store.GetCase(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	a, err := s.d.Response.Request(r.Context(), c, s.actor(r))
	if errors.Is(err, store.ErrDuplicate) && a != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "an open restriction already exists for this source", "data": a,
		})
		return
	}
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, envelope{Data: a})
}

// handleIncidentExport returns the case as JSON or as a Markdown
// report and keeps a copy in the exports directory. Secrets are masked
// unless ?reveal=secrets is given. Every export is written to the case
// history with its format and whether secrets were included.
func (s *Server) handleIncidentExport(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid case id")
		return
	}
	reveal := s.wantSecrets(r)
	b, err := s.loadCase(r, id, true, reveal)
	if err != nil {
		s.storeError(w, err)
		return
	}
	format := r.URL.Query().Get("format")
	stamp := time.Now().UTC().Format("20060102T150405Z")
	var data []byte
	var name, ctype string
	switch format {
	case "", "json":
		format = "json"
		data, _ = json.MarshalIndent(map[string]any{
			"exported_at": time.Now().UTC(), "exported_by": s.actor(r),
			"generator": "Honeypot SOC Investigation Lab",
			"complete":  true,
			"counts": map[string]int{
				"events": len(b.Timeline), "detections": len(b.Detections),
				"observables": len(b.Observables), "actions": len(b.Actions),
				"notes": len(b.Notes), "history": len(b.History),
			},
			"secrets_masked": b.SecretsMasked,
			"case":           b,
		}, "", "  ")
		name, ctype = fmt.Sprintf("%s-%s.json", b.Case.Ref, stamp), "application/json"
	case "md", "markdown":
		format = "md"
		data = []byte(caseMarkdown(b, s.actor(r)))
		name, ctype = fmt.Sprintf("%s-%s.md", b.Case.Ref, stamp), "text/markdown; charset=utf-8"
	default:
		writeError(w, http.StatusBadRequest, "format must be json or md")
		return
	}
	if err := s.d.Store.RecordCaseExport(r.Context(), id, s.actor(r), map[string]any{
		"format": format, "file": name, "secrets_included": reveal, "events": len(b.Timeline),
	}); err != nil {
		s.storeError(w, err)
		return
	}
	if dir := s.d.Config.Paths.Exports; dir != "" {
		if err := os.MkdirAll(dir, 0o700); err == nil {
			_ = os.WriteFile(filepath.Join(dir, name), data, 0o600)
		}
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	_, _ = w.Write(data)
}

func caseMarkdown(b *caseBundle, actor string) string {
	c := b.Case
	var sb strings.Builder
	f := func(format string, a ...any) { fmt.Fprintf(&sb, format, a...) }
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05Z") }

	f("# %s: %s\n\n", c.Ref, c.Title)
	f("Exported %s by %s from the Honeypot SOC Investigation Lab.\n", ts(time.Now()), actor)
	f("This file lists what the lab recorded. Conclusions belong in the analyst sections.\n")
	if b.SecretsMasked {
		f("Passwords and other secrets are masked as %s.\n\n", redact.Mask)
	} else {
		f("**This export includes unmasked passwords and secrets.**\n\n")
	}
	f("| Field | Value |\n|---|---|\n")
	f("| Status | %s |\n| Severity | %s |\n| Verdict | %s |\n", c.Status, c.Severity, orDash(c.Verdict))
	f("| Source | %s |\n| Sensor | %s |\n", c.SourceIP, c.SensorID)
	f("| Activity | %s to %s |\n", ts(c.FirstActivity), ts(c.LastActivity))
	f("| Services | %s |\n| Sessions | %d |\n| Events | %d |\n", orDash(strings.Join(c.Services, ", ")), len(c.SessionIDs), c.EventCount)
	f("| Response decision | %s |\n| Closure reason | %s |\n\n", orDash(c.ResponseDecision), orDash(c.ClosureReason))

	f("## Detections\n\n")
	for _, d := range b.Detections {
		f("### %s v%d: %s (detection %d)\n\n", d.RuleID, d.RuleVersion, d.RuleName, d.ID)
		f("- Severity %s, confidence %s\n- Detected %s\n", d.Severity, d.Confidence, ts(d.DetectedAt))
		if len(d.MITRE) > 0 {
			f("- ATT&CK mapping: %s\n", strings.Join(d.MITRE, ", "))
		}
		if d.SuppressedCount > 0 {
			f("- Repeats inside the suppression window: %d\n", d.SuppressedCount)
		}
		f("\n%s\n\n", d.Explanation)
	}

	f("## Timeline\n\n")
	if len(b.Timeline) == 0 {
		f("No events linked.\n\n")
	} else {
		rows := b.Timeline
		if len(rows) > mdTimelineRows {
			f("The case has %d events. This table lists the first %d; the JSON export of this case contains all %d.\n\n",
				len(b.Timeline), mdTimelineRows, len(b.Timeline))
			rows = rows[:mdTimelineRows]
		} else {
			f("All %d linked events.\n\n", len(b.Timeline))
		}
		f("| Time (UTC) | Service | Event | Session | Detail |\n|---|---|---|---|---|\n")
		for _, e := range rows {
			f("| %s | %s | %s | %s | %s |\n", ts(e.Timestamp), e.ServiceType, e.EventType,
				shortID(e.SessionID), mdCell(eventSummary(e)))
		}
		f("\n")
	}

	f("## Observables\n\n")
	if len(b.Observables) == 0 {
		f("None.\n\n")
	} else {
		f("| Type | Value | Status | Notes |\n|---|---|---|---|\n")
		for _, o := range b.Observables {
			var notes []string
			if o.Internal {
				notes = append(notes, "internal address")
			}
			if o.Claimed {
				notes = append(notes, "client-controlled value")
			}
			f("| %s | %s | %s | %s |\n", o.Type, mdCell(o.Value), o.Status, strings.Join(notes, "; "))
		}
		f("\n")
	}

	f("## Response actions\n\n")
	if len(b.Actions) == 0 {
		f("None requested.\n\n")
	}
	for _, a := range b.Actions {
		f("- Action %d, %s, state %s. %s\n", a.ID, a.Playbook, a.State, a.Summary)
		for _, h := range b.ActionLogs[a.ID] {
			f("  - %s %s: %s -> %s\n", ts(h.At), h.Actor, orDash(h.From), h.To)
		}
	}
	f("\n## Analyst notes\n\n")
	if len(b.Notes) == 0 {
		f("None.\n\n")
	}
	for _, n := range b.Notes {
		f("**%s, %s**\n\n%s\n\n", n.Author, ts(n.At), n.Body)
	}
	f("## Case history\n\n")
	sort.Slice(b.History, func(i, j int) bool { return b.History[i].ID < b.History[j].ID })
	for _, h := range b.History {
		f("- %s %s %s\n", ts(h.At), h.Actor, h.Action)
	}
	return sb.String()
}

// redactDetections returns copies with commands in matched values masked.
func redactDetections(ds []*types.Detection) []*types.Detection {
	out := make([]*types.Detection, len(ds))
	for i, d := range ds {
		c := *d
		c.MatchedValues = redact.MatchedValues(d.MatchedValues)
		c.Explanation = redact.Text(d.Explanation)
		out[i] = &c
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

func eventSummary(e *types.Event) string {
	var d map[string]any
	_ = json.Unmarshal(e.ServiceData, &d)
	str := func(k string) string { v, _ := d[k].(string); return v }
	switch e.EventType {
	case types.EventCommand:
		if c := str("command"); c != "" {
			return strings.TrimSpace(c + " " + str("arg"))
		}
	case types.EventRequest:
		return fmt.Sprintf("%s %s", str("method"), str("path"))
	case types.EventLoginSuccess, types.EventLoginFailed:
		return "user " + str("username")
	case types.EventFileUpload:
		return fmt.Sprintf("%s sha256 %s", str("filename"), str("sha256"))
	}
	if r := str("raw"); r != "" {
		return r
	}
	return ""
}
