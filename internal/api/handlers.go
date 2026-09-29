/*
©AngelaMos | 2026
Modified by Hiten, 2026: rewritten. Lists are paginated on the
server with totals, filters are applied in SQL, readiness is
separate from liveness, sources replace "attackers" in the API, and
exports take an explicit selection with the count and skipped items
reported instead of a silent 500-record cap.

handlers.go
*/

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/intel"
	"github.com/CarterPerez-dev/hive/internal/redact"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

// ---- health -----------------------------------------------------------

// handleHealth answers as long as the process is running.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeData(w, map[string]any{
		"status":  "running",
		"version": config.ToolVersion,
		"sensor":  s.d.Config.Sensor.ID,
		"uptime":  time.Since(s.startedAt).Round(time.Second).String(),
	})
}

type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// handleReady reports whether the lab can collect and store events.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var checks []check

	if err := s.d.Store.Ping(ctx); err != nil {
		checks = append(checks, check{"database", false, "cannot reach PostgreSQL: " + err.Error()})
	} else {
		checks = append(checks, check{"database", true, "connected"})
		v, err := s.d.Store.SchemaVersion(ctx)
		ok := err == nil && v >= config.RequiredMigration
		detail := fmt.Sprintf("migration %d (need %d)", v, config.RequiredMigration)
		if err != nil {
			detail = "cannot read migration version: " + err.Error()
		}
		checks = append(checks, check{"schema", ok, detail})
	}

	if s.d.ServiceState != nil {
		for name, state := range s.d.ServiceState() {
			checks = append(checks, check{"service:" + name, state == "listening", state})
		}
	}

	ps := s.d.Processor.Stats()
	// Failing means the most recent write attempt failed. One stored
	// event after an outage makes the pipeline ready again.
	recentFail := !ps.LastErrorAt.IsZero() && ps.LastErrorAt.After(ps.LastStoredAt)
	pd := fmt.Sprintf("%d stored, %d failed, %d spooled", ps.Processed, ps.PersistFailures, ps.Spooled)
	if recentFail {
		pd += "; last error: " + ps.LastError
	}
	checks = append(checks, check{"pipeline", !recentFail, pd})

	bs := s.d.Bus.Stats()
	checks = append(checks, check{"queue", bs.Queued < bs.Capacity,
		fmt.Sprintf("%d of %d queued, %d dropped since start", bs.Queued, bs.Capacity, bs.Dropped)})

	sort.Slice(checks, func(i, j int) bool { return checks[i].Name < checks[j].Name })
	ready := true
	for _, c := range checks {
		ready = ready && c.OK
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, envelope{Data: map[string]any{"ready": ready, "checks": checks}})
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	cfg := s.d.Config
	var listeners []map[string]any
	for _, l := range cfg.Listeners() {
		host := cfg.Network.HoneypotHost
		if l.Name == "api" {
			host = cfg.Network.ManagementHost
		}
		state := "disabled"
		if l.Enabled {
			state = "configured"
		}
		if s.d.ServiceState != nil {
			if st, ok := s.d.ServiceState()[l.Name]; ok {
				state = st
			}
		}
		listeners = append(listeners, map[string]any{
			"name": l.Name, "address": config.Addr(host, l.Port), "state": state,
		})
	}
	schema, _ := s.d.Store.SchemaVersion(r.Context())
	writeData(w, map[string]any{
		"version":            config.ToolVersion,
		"sensor":             cfg.Sensor.ID,
		"config_source":      cfg.Source,
		"started_at":         s.startedAt,
		"schema_version":     schema,
		"required_schema":    config.RequiredMigration,
		"listeners":          listeners,
		"ssh_auth_mode":      cfg.SSH.AuthMode,
		"lab_ranges":         cfg.Lab.SourceRanges,
		"rules_source":       s.d.RulesSource,
		"geoip":              cfg.GeoIP.DBPath != "",
		"queue":              s.d.Bus.Stats(),
		"processor":          s.d.Processor.Stats(),
		"live":               s.d.Broadcaster.Stats(),
		"connections":        s.d.Guard.Stats(),
		"denylist":           s.d.Response.Denylist().List(),
		"limits":             cfg.Limits,
		"response_enabled":   cfg.Response.Enabled,
		"correlation_window": cfg.Cases.CorrelationWindow,
	})
}

// ---- stats ------------------------------------------------------------

func (s *Server) handleStatsOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since := sinceParam(r, 24*time.Hour)
	byService, err := s.d.Store.CountByService(ctx, since)
	if err != nil {
		s.storeError(w, err)
		return
	}
	byOrigin, err := s.d.Store.CountByOrigin(ctx, since)
	if err != nil {
		s.storeError(w, err)
		return
	}
	var total int64
	for _, n := range byService {
		total += n
	}
	_, openCases, err := s.d.Store.ListCases(ctx, store.CaseFilter{Status: "open", Limit: 1})
	if err != nil {
		s.storeError(w, err)
		return
	}
	_, detections, err := s.d.Store.ListDetections(ctx, store.DetectionFilter{Since: since, Limit: 1})
	if err != nil {
		s.storeError(w, err)
		return
	}
	_, pending, err := s.d.Store.ListActions(ctx, store.ActionFilter{State: types.ActionPending, Limit: 1})
	if err != nil {
		s.storeError(w, err)
		return
	}
	_, sources, err := s.d.Store.ListSources(ctx, since, 1, 0)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, map[string]any{
		"range_start":       since,
		"events":            total,
		"events_by_service": byService,
		"events_by_origin":  byOrigin,
		"open_cases":        openCases,
		"detections":        detections,
		"pending_actions":   pending,
		"sources":           sources,
		"active_sessions":   len(s.d.Tracker.Active()),
	})
}

func (s *Server) handleStatsCountries(w http.ResponseWriter, r *http.Request) {
	c, err := s.d.Store.CountByCountry(r.Context(), sinceParam(r, 24*time.Hour))
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, map[string]any{
		"countries":    c,
		"geoip_loaded": s.d.Config.GeoIP.DBPath != "",
		"note":         "Location comes from a GeoIP database and is approximate. Internal and loopback addresses have no location.",
	})
}

func (s *Server) handleStatsCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := s.d.Store.TopUsernames(ctx, 20)
	if err != nil {
		s.storeError(w, err)
		return
	}
	pw, err := s.d.Store.TopPasswords(ctx, 20)
	if err != nil {
		s.storeError(w, err)
		return
	}
	pairs, err := s.d.Store.TopPairs(ctx, 20)
	if err != nil {
		s.storeError(w, err)
		return
	}
	masked := !s.wantSecrets(r)
	if masked {
		for i := range pw {
			pw[i].Value = redact.Mask
		}
		for i := range pairs {
			pairs[i].Password = redact.Mask
		}
	}
	writeData(w, map[string]any{"usernames": users, "passwords": pw, "pairs": pairs, "secrets_masked": masked})
}

// ---- events -----------------------------------------------------------

func parseTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := pagination(r)
	after, _ := strconv.ParseInt(q.Get("after_seq"), 10, 64)
	f := store.EventFilter{
		SourceIP: q.Get("source"), Service: q.Get("service"), EventType: q.Get("type"),
		SessionID: q.Get("session"), Origin: q.Get("origin"),
		Since: parseTime(q.Get("since")), Until: parseTime(q.Get("until")),
		AfterSeq: after, Limit: limit, Offset: offset,
	}
	evs, total, err := s.d.Store.ListEvents(r.Context(), f)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writePage(w, s.eventsOut(r, evs), total, limit, offset)
}

func (s *Server) handleEventByID(w http.ResponseWriter, r *http.Request) {
	ev, err := s.d.Store.GetEvent(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.storeError(w, err)
		return
	}
	dets, err := s.d.Store.DetectionsForEvent(r.Context(), ev.Ref())
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := ev
	if !s.wantSecrets(r) {
		out = redact.Event(ev)
	}
	writeData(w, map[string]any{"event": out, "detections": s.detectionsOut(r, dets)})
}

// ---- sessions ---------------------------------------------------------

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	q := r.URL.Query()
	list, total, err := s.d.Store.ListSessions(r.Context(), store.SessionFilter{
		Service: q.Get("service"), SourceIP: q.Get("source"), Limit: limit, Offset: offset,
	})
	if err != nil {
		s.storeError(w, err)
		return
	}
	writePage(w, list, total, limit, offset)
}

func isValidSessionID(id string) bool {
	if len(id) < 8 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Server) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !isValidSessionID(id) {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	sess, err := s.d.Store.GetSession(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	evs, total, err := s.d.Store.ListEvents(r.Context(), store.EventFilter{
		SessionID: id, Ascending: true, Limit: 1000,
	})
	if err != nil {
		s.storeError(w, err)
		return
	}
	dets, _, err := s.d.Store.ListDetections(r.Context(), store.DetectionFilter{SessionID: id, Limit: 200})
	if err != nil {
		s.storeError(w, err)
		return
	}
	_, statErr := os.Stat(filepath.Join(s.d.Config.Paths.Replays, id+".cast"))
	writeData(w, map[string]any{
		"session": sess, "events": s.eventsOut(r, evs), "events_total": total,
		"detections": s.detectionsOut(r, dets), "has_replay": statErr == nil,
	})
}

func (s *Server) handleSessionReplay(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !isValidSessionID(id) {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	data, err := os.ReadFile(filepath.Join(s.d.Config.Paths.Replays, id+".cast"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no replay recorded for this session")
		return
	}
	w.Header().Set("Content-Type", "application/x-asciicast")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s.cast"`, id))
	_, _ = w.Write(data)
}

// ---- sources ----------------------------------------------------------

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	list, total, err := s.d.Store.ListSources(r.Context(), sinceParam(r, 7*24*time.Hour), limit, offset)
	if err != nil {
		s.storeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		out = append(out, sourceView(a))
	}
	writePage(w, out, total, limit, offset)
}

func sourceView(a *types.Attacker) map[string]any {
	internal := false
	if ip, err := netip.ParseAddr(a.IP); err == nil {
		internal = intel.IsInternal(ip)
	}
	var geo any
	if a.Geo.CountryCode != "" {
		geo = a.Geo
	}
	return map[string]any{
		"id": a.ID, "ip": a.IP, "internal": internal,
		"first_seen": a.FirstSeen, "last_seen": a.LastSeen,
		"total_events": a.TotalEvents, "total_sessions": a.TotalSessions,
		"geo": geo, "tags": a.Tags,
	}
}

func (s *Server) handleSourceByID(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid source id")
		return
	}
	a, err := s.d.Store.GetSource(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	sessions, _, err := s.d.Store.ListSessions(r.Context(), store.SessionFilter{SourceIP: a.IP, Limit: 100})
	if err != nil {
		s.storeError(w, err)
		return
	}
	cases, _, err := s.d.Store.ListCases(r.Context(), store.CaseFilter{SourceIP: a.IP, IncludeMerged: true, Limit: 50})
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, map[string]any{"source": sourceView(a), "sessions": sessions, "cases": cases})
}

// ---- detections and rules ----------------------------------------------

func (s *Server) handleDetections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := pagination(r)
	caseID, _ := strconv.ParseInt(q.Get("case"), 10, 64)
	list, total, err := s.d.Store.ListDetections(r.Context(), store.DetectionFilter{
		RuleID: q.Get("rule"), SourceIP: q.Get("source"), SessionID: q.Get("session"),
		CaseID: caseID, Severity: q.Get("severity"), Limit: limit, Offset: offset,
	})
	if err != nil {
		s.storeError(w, err)
		return
	}
	writePage(w, s.detectionsOut(r, list), total, limit, offset)
}

func (s *Server) handleDetectionByID(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid detection id")
		return
	}
	d, err := s.d.Store.GetDetection(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	refs := make([]types.EventRef, 0, len(d.Evidence))
	for _, e := range d.Evidence {
		refs = append(refs, e.EventRef)
	}
	evs, err := s.d.Store.EventsByRefs(r.Context(), refs)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, map[string]any{
		"detection": s.detectionsOut(r, []*types.Detection{d})[0],
		"events":    s.eventsOut(r, evs), "rule": s.d.Engine.Rule(d.RuleID),
	})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	stats, err := s.d.Store.RuleStats(r.Context())
	if err != nil {
		s.storeError(w, err)
		return
	}
	var out []map[string]any
	for _, rule := range s.d.Engine.Rules() {
		out = append(out, map[string]any{"rule": rule, "stats": stats[rule.ID]})
	}
	writeData(w, map[string]any{"source": s.d.RulesSource, "rules": out})
}

func (s *Server) handleMITRETechniques(w http.ResponseWriter, _ *http.Request) {
	writeData(w, s.d.Mitre.All())
}

func (s *Server) handleMITREHeatmap(w http.ResponseWriter, r *http.Request) {
	counts, err := s.d.Store.TechniqueCounts(r.Context(), sinceParam(r, 30*24*time.Hour))
	if err != nil {
		s.storeError(w, err)
		return
	}
	var out []map[string]any
	for _, c := range counts {
		row := map[string]any{"technique_id": c.TechniqueID, "count": c.Count}
		if t := s.d.Mitre.Get(c.TechniqueID); t != nil {
			row["name"], row["tactic"] = t.Name, t.Tactic
		}
		out = append(out, row)
	}
	writeData(w, out)
}

// ---- observables ------------------------------------------------------

func (s *Server) handleObservables(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset := pagination(r)
	f := store.ObservableFilter{
		Type: q.Get("type"), Status: q.Get("status"), Search: q.Get("q"),
		SessionID: q.Get("session"), Limit: limit, Offset: offset,
	}
	if v := q.Get("internal"); v != "" {
		b := v == "true"
		f.Internal = &b
	}
	if v, err := strconv.ParseInt(q.Get("case"), 10, 64); err == nil {
		f.CaseID = v
	}
	list, total, err := s.d.Store.ListObservables(r.Context(), f)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writePage(w, s.observablesOut(r, list), total, limit, offset)
}

func (s *Server) handleObservableByID(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid observable id")
		return
	}
	o, err := s.d.Store.GetObservable(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, s.observablesOut(r, []*types.IOC{o})[0])
}

var observableStatuses = map[string]bool{
	types.ObservableObserved: true, types.ObservableSuspicious: true,
	types.ObservableConfirmed: true, types.ObservableBenign: true,
}

func (s *Server) handleObservablePatch(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid observable id")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !observableStatuses[body.Status] {
		writeError(w, http.StatusBadRequest, "status must be observed, suspicious, confirmed or benign")
		return
	}
	if err := s.d.Store.SetObservableStatus(r.Context(), id, body.Status); err != nil {
		s.storeError(w, err)
		return
	}
	s.d.Logger.Info().Int64("observable_id", id).Str("status", body.Status).
		Str("actor", s.actor(r)).Msg("observable status changed")
	o, err := s.d.Store.GetObservable(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, s.observablesOut(r, []*types.IOC{o})[0])
}

type exportRequest struct {
	IDs             []int64 `json:"ids"`
	Format          string  `json:"format"`
	IncludeInternal bool    `json:"include_internal"`
	// RevealSecrets exports URL passwords unmasked. Off by default.
	RevealSecrets bool `json:"reveal_secrets"`
}

// handleObservableExport exports exactly the selected observables.
// Response headers report how many were written and skipped.
func (s *Server) handleObservableExport(w http.ResponseWriter, r *http.Request) {
	var req exportRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.IDs) == 0 {
		writeError(w, http.StatusBadRequest, "select at least one observable to export")
		return
	}
	if len(req.IDs) > maxExportItems {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d observables per export", maxExportItems))
		return
	}
	iocs, missing, err := s.d.Store.ObservablesByIDs(r.Context(), req.IDs)
	if err != nil {
		s.storeError(w, err)
		return
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")

	var body []byte
	var ctype, name string
	written, skipped := 0, map[string]int{}
	if len(missing) > 0 {
		skipped["not found"] = len(missing)
	}

	switch req.Format {
	case "stix":
		var sel []*types.IOC
		for _, o := range iocs {
			if o.Internal && !req.IncludeInternal {
				skipped["internal address"]++
				continue
			}
			sel = append(sel, o)
		}
		if !req.RevealSecrets {
			for i, o := range sel {
				sel[i] = redact.Observable(o)
			}
		}
		body, err = intel.GenerateSTIXBundle(sel)
		if err != nil {
			s.storeError(w, err)
			return
		}
		written, ctype, name = len(sel), "application/stix+json", "observables-"+stamp+".stix.json"
	case intel.FormatPlain, intel.FormatIPTables, intel.FormatNginx, intel.FormatCSV:
		res := intel.GenerateBlocklist(iocs, req.Format, req.IncludeInternal)
		for k, v := range res.Skipped {
			skipped[k] += v
		}
		body, written = []byte(res.Text), res.Written
		ctype, name = "text/plain; charset=utf-8", fmt.Sprintf("blocklist-%s-%s.txt", req.Format, stamp)
		if req.Format == intel.FormatCSV {
			ctype, name = "text/csv; charset=utf-8", "blocklist-"+stamp+".csv"
		}
	default:
		writeError(w, http.StatusBadRequest, "format must be stix, plain, iptables, nginx or csv")
		return
	}

	var parts []string
	for k, v := range skipped {
		parts = append(parts, fmt.Sprintf("%s=%d", strings.ReplaceAll(k, " ", "_"), v))
	}
	sort.Strings(parts)
	s.d.Logger.Info().Int("selected", len(req.IDs)).Int("written", written).
		Strs("skipped", parts).Str("format", req.Format).Str("actor", s.actor(r)).
		Msg("observables exported")

	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("X-Export-Selected", strconv.Itoa(len(req.IDs)))
	w.Header().Set("X-Export-Written", strconv.Itoa(written))
	w.Header().Set("X-Export-Skipped", strings.Join(parts, ","))
	w.Header().Set("Access-Control-Expose-Headers", "X-Export-Selected, X-Export-Written, X-Export-Skipped, Content-Disposition")
	_, _ = w.Write(body)
}

// ---- lab --------------------------------------------------------------

func (s *Server) handleLabRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.d.Store.ListScenarioRuns(r.Context(), 200)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, runs)
}

// handleLabRunsPost stores results reported by cmd/labtest. Rules
// never read these rows; they are only shown on the Lab page.
func (s *Server) handleLabRunsPost(w http.ResponseWriter, r *http.Request) {
	var runs []types.ScenarioRun
	if err := decode(r, &runs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(runs) == 0 || len(runs) > 500 {
		writeError(w, http.StatusBadRequest, "send 1 to 500 scenario results")
		return
	}
	for i := range runs {
		if runs[i].RunID == "" || runs[i].ScenarioID == "" {
			writeError(w, http.StatusBadRequest, "run_id and scenario_id are required")
			return
		}
		if err := s.d.Store.InsertScenarioRun(r.Context(), &runs[i]); err != nil {
			s.storeError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, envelope{Data: runs})
}

// wantSecrets reports whether the request asked for unmasked values
// with ?reveal=secrets. Each such request is logged with the analyst
// name and path.
func (s *Server) wantSecrets(r *http.Request) bool {
	if r.URL.Query().Get("reveal") != "secrets" {
		return false
	}
	s.d.Logger.Warn().Str("actor", s.actor(r)).Str("path", r.URL.Path).
		Msg("unmasked secrets requested")
	return true
}

func (s *Server) eventsOut(r *http.Request, evs []*types.Event) []*types.Event {
	if s.wantSecrets(r) {
		return evs
	}
	return redact.Events(evs)
}

func (s *Server) detectionsOut(r *http.Request, ds []*types.Detection) []*types.Detection {
	if s.wantSecrets(r) {
		return ds
	}
	return redactDetections(ds)
}

func (s *Server) observablesOut(r *http.Request, os []*types.IOC) []*types.IOC {
	if s.wantSecrets(r) {
		return os
	}
	out := make([]*types.IOC, len(os))
	for i, o := range os {
		out[i] = redact.Observable(o)
	}
	return out
}
