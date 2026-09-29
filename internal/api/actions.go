/*
Hiten | 2026
actions.go

Response action endpoints for the restrict-lab-source playbook.
*/

package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CarterPerez-dev/hive/internal/store"
)

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	caseID, _ := strconv.ParseInt(r.URL.Query().Get("case"), 10, 64)
	list, total, err := s.d.Store.ListActions(r.Context(), store.ActionFilter{
		CaseID: caseID, State: r.URL.Query().Get("state"), Limit: limit, Offset: offset,
	})
	if err != nil {
		s.storeError(w, err)
		return
	}
	writePage(w, list, total, limit, offset)
}

func (s *Server) handleActionByID(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	a, err := s.d.Store.GetAction(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	h, err := s.d.Store.ActionHistory(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, map[string]any{"action": a, "history": h})
}

func (s *Server) handleActionApprove(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	var body struct {
		Services  []string `json:"services"`
		ExpiresIn string   `json:"expires_in"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var exp time.Duration
	if body.ExpiresIn != "" {
		d, err := time.ParseDuration(body.ExpiresIn)
		if err != nil || d <= 0 {
			writeError(w, http.StatusBadRequest, "expires_in must be a duration such as 30m or 2h")
			return
		}
		exp = d
	}
	a, err := s.d.Response.Approve(r.Context(), id, s.actor(r), body.Services, exp)
	if err != nil {
		if a == nil && !isStoreErr(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.storeError(w, err)
		return
	}
	writeData(w, a)
}

func (s *Server) handleActionReject(w http.ResponseWriter, r *http.Request) {
	s.decide(w, r, false)
}

func (s *Server) handleActionReverse(w http.ResponseWriter, r *http.Request) {
	s.decide(w, r, true)
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request, reverse bool) {
	id, ok := idParam(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid action id")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var err error
	if reverse {
		_, err = s.d.Response.Reverse(r.Context(), id, s.actor(r), body.Reason)
	} else {
		_, err = s.d.Response.Reject(r.Context(), id, s.actor(r), body.Reason)
	}
	if err != nil {
		if !isStoreErr(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.storeError(w, err)
		return
	}
	a, err := s.d.Store.GetAction(r.Context(), id)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeData(w, a)
}

func isStoreErr(err error) bool {
	return errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) ||
		errors.Is(err, store.ErrInvalidTransition) || errors.Is(err, store.ErrDuplicate) ||
		strings.Contains(err.Error(), "database") || strings.Contains(err.Error(), "SQLSTATE")
}
