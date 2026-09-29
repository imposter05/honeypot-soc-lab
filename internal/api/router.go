/*
©AngelaMos | 2026
Modified by Hiten, 2026: binds to the management host (127.0.0.1
by default) instead of every interface, uses host and origin checks
instead of open CORS, separates liveness from readiness, and adds
the case, detection, observable, response and lab routes.

router.go
*/

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/detection"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/mitre"
	"github.com/CarterPerez-dev/hive/internal/netguard"
	"github.com/CarterPerez-dev/hive/internal/response"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/internal/store"
)

const (
	defaultPageLimit = 50
	maxPageLimit     = 500
	maxExportItems   = 5000
)

// Deps are the parts of the running application the API reads.
type Deps struct {
	Store       *store.PgxStore
	Bus         *event.Bus
	Processor   *event.Processor
	Broadcaster *event.Broadcaster
	Engine      *detection.Engine
	RulesSource string
	Response    *response.Manager
	Guard       *netguard.Guard
	Tracker     *session.Tracker
	Mitre       *mitre.Index
	Config      *config.Config
	Logger      *zerolog.Logger
	// ServiceState reports each listener's state.
	ServiceState func() map[string]string
}

type Server struct {
	d         Deps
	guard     *requestGuard
	router    *chi.Mux
	startedAt time.Time
}

func New(d Deps) *Server {
	s := &Server{
		d:         d,
		guard:     newRequestGuard(d.Config.Network.ManagementHost, d.Config.API.Port, d.Config.API.CORSOrigins),
		startedAt: time.Now().UTC(),
	}
	s.router = s.buildRouter()
	return s
}

func (s *Server) Name() string { return "api" }

func (s *Server) Handler() http.Handler { return s.router }

func (s *Server) Start(ctx context.Context) error {
	addr := s.d.Config.ManagementAddr()
	ln, err := netguard.Listen("api", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       s.d.Config.API.ReadTimeout,
		WriteTimeout:      s.d.Config.API.WriteTimeout,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	s.d.Logger.Info().Str("addr", addr).Msg("dashboard and API listening")
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("api server: %w", err)
	}
	return nil
}

func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(recoverer(s.d.Logger))
	r.Use(securityHeaders)
	r.Use(s.guard.middleware)
	r.Use(requestLogger(s.d.Logger))

	r.Route("/api", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/ready", s.handleReady)
		r.Get("/system", s.handleSystem)

		r.Get("/stats/overview", s.handleStatsOverview)
		r.Get("/stats/countries", s.handleStatsCountries)
		r.Get("/stats/credentials", s.handleStatsCredentials)

		r.Get("/events", s.handleEvents)
		r.Get("/events/{id}", s.handleEventByID)

		r.Get("/sessions", s.handleSessions)
		r.Get("/sessions/{id}", s.handleSessionByID)
		r.Get("/sessions/{id}/replay", s.handleSessionReplay)

		r.Get("/sources", s.handleSources)
		r.Get("/sources/{id}", s.handleSourceByID)

		r.Get("/detections", s.handleDetections)
		r.Get("/detections/{id}", s.handleDetectionByID)
		r.Get("/rules", s.handleRules)

		r.Get("/mitre/techniques", s.handleMITRETechniques)
		r.Get("/mitre/heatmap", s.handleMITREHeatmap)

		r.Get("/observables", s.handleObservables)
		r.Get("/observables/{id}", s.handleObservableByID)
		r.Patch("/observables/{id}", s.handleObservablePatch)
		r.Post("/observables/export", s.handleObservableExport)

		r.Get("/incidents", s.handleIncidents)
		r.Get("/incidents/{id}", s.handleIncidentByID)
		r.Patch("/incidents/{id}", s.handleIncidentPatch)
		r.Post("/incidents/{id}/notes", s.handleIncidentNote)
		r.Get("/incidents/{id}/timeline", s.handleIncidentTimeline)
		r.Post("/incidents/{id}/evidence", s.handleIncidentEvidence)
		r.Post("/incidents/{id}/split", s.handleIncidentSplit)
		r.Post("/incidents/{id}/merge", s.handleIncidentMerge)
		r.Get("/incidents/{id}/export", s.handleIncidentExport)
		r.Post("/incidents/{id}/actions", s.handleIncidentRequestAction)

		r.Get("/actions", s.handleActions)
		r.Get("/actions/{id}", s.handleActionByID)
		r.Post("/actions/{id}/approve", s.handleActionApprove)
		r.Post("/actions/{id}/reject", s.handleActionReject)
		r.Post("/actions/{id}/reverse", s.handleActionReverse)

		r.Get("/lab/runs", s.handleLabRuns)
		r.Post("/lab/runs", s.handleLabRunsPost)

		r.Get("/ws", s.handleWebSocket)
		r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusNotFound, "no such API route")
		})
	})

	if s.d.Config.API.ServeFrontend {
		r.Handle("/*", s.staticHandler())
	}
	return r
}

// ---- shared helpers ------------------------------------------------------

type envelope struct {
	Data any   `json:"data"`
	Meta *meta `json:"meta,omitempty"`
}

type meta struct {
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeData(w http.ResponseWriter, v any) {
	writeJSON(w, http.StatusOK, envelope{Data: v})
}

func writePage(w http.ResponseWriter, v any, total int64, limit, offset int) {
	writeJSON(w, http.StatusOK, envelope{Data: v, Meta: &meta{total, limit, offset}})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// storeError maps store errors to status codes. Other errors are
// logged and reported without internal detail.
func (s *Server) storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrInvalidTransition),
		errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, context.Canceled):
	default:
		s.d.Logger.Error().Err(err).Msg("api store error")
		writeError(w, http.StatusInternalServerError, "database error; see the server log")
	}
}

func pagination(r *http.Request) (int, int) {
	limit, offset := defaultPageLimit, 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, maxPageLimit)
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v >= 0 {
		offset = v
	}
	return limit, offset
}

func sinceParam(r *http.Request, def time.Duration) time.Time {
	d := def
	if v := r.URL.Query().Get("range"); v != "" {
		if pd, err := time.ParseDuration(v); err == nil && pd > 0 {
			d = pd
		}
	}
	if d == 0 {
		return time.Time{}
	}
	return time.Now().UTC().Add(-d)
}

func idParam(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	return id, err == nil && id > 0
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

// actor is the analyst name for audit records. The lab has no
// login; the name comes from the X-Analyst header or the config.
func (s *Server) actor(r *http.Request) string {
	if v := r.Header.Get("X-Analyst"); v != "" && len(v) <= 64 {
		return v
	}
	return s.d.Config.Cases.AnalystName
}
