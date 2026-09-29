/*
©AngelaMos | 2026
Modified by Hiten, 2026: callers get copies instead of shared
pointers, recently ended sessions stay readable for a few minutes so
the processor can fill ports on late events, and auth mode and
destination address are recorded.

tracker.go

Thread-safe active session tracker

Manages the lifecycle of honeypot sessions from connect to
disconnect. Each connection gets a unique session ID (UUID v7)
and is tracked in an in-memory map. Session metadata accumulates
as the attacker interacts: command counts, login status, MITRE
technique tags, and threat scores.
*/

package session

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const recentKeep = 5 * time.Minute

type ended struct {
	sess *types.Session
	at   time.Time
}

type Tracker struct {
	mu       sync.RWMutex
	sessions map[string]*types.Session
	recent   map[string]ended
	onStart  func(types.Session)
	onEnd    func(types.Session)
}

func NewTracker() *Tracker {
	return &Tracker{
		sessions: make(map[string]*types.Session),
		recent:   make(map[string]ended),
	}
}

func snapshot(s *types.Session) *types.Session {
	c := *s
	c.MITRETechniques = append([]string(nil), s.MITRETechniques...)
	c.Tags = append([]string(nil), s.Tags...)
	return &c
}

func (t *Tracker) SetOnStart(fn func(types.Session)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onStart = fn
}

func (t *Tracker) Start(
	sensorID string,
	serviceType types.ServiceType,
	sourceIP string,
	sourcePort int,
	destPort int,
) *types.Session {
	sess := &types.Session{
		ID:          uuid.Must(uuid.NewV7()).String(),
		SensorID:    sensorID,
		StartedAt:   time.Now().UTC(),
		ServiceType: serviceType,
		SourceIP:    sourceIP,
		SourcePort:  sourcePort,
		DestPort:    destPort,
	}

	t.mu.Lock()
	t.sessions[sess.ID] = sess
	onStart := t.onStart
	t.mu.Unlock()

	if onStart != nil {
		onStart(*snapshot(sess))
	}

	return snapshot(sess)
}

func (t *Tracker) SetOnEnd(fn func(types.Session)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onEnd = fn
}

func (t *Tracker) End(sessionID string) *types.Session {
	t.mu.Lock()
	sess, exists := t.sessions[sessionID]
	if !exists {
		t.mu.Unlock()
		return nil
	}

	now := time.Now().UTC()
	sess.EndedAt = &now
	delete(t.sessions, sessionID)
	t.recent[sessionID] = ended{sess: sess, at: now}
	for id, e := range t.recent {
		if now.Sub(e.at) > recentKeep {
			delete(t.recent, id)
		}
	}
	onEnd := t.onEnd
	snap := snapshot(sess)
	t.mu.Unlock()

	if onEnd != nil {
		onEnd(*snap)
	}

	return snap
}

// Get returns a copy of an active or recently ended session.
func (t *Tracker) Get(sessionID string) *types.Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if s, ok := t.sessions[sessionID]; ok {
		return snapshot(s)
	}
	if e, ok := t.recent[sessionID]; ok {
		return snapshot(e.sess)
	}
	return nil
}

func (t *Tracker) Active() []*types.Session {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*types.Session, 0, len(t.sessions))
	for _, sess := range t.sessions {
		result = append(result, snapshot(sess))
	}
	return result
}

// SetAuthMode records which SSH authentication mode applied.
func (t *Tracker) SetAuthMode(sessionID, mode string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if sess, ok := t.sessions[sessionID]; ok {
		sess.AuthMode = mode
	}
}

func (t *Tracker) IncrCommandCount(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if sess, exists := t.sessions[sessionID]; exists {
		sess.CommandCount++
	}
}

func (t *Tracker) SetLogin(
	sessionID string,
	success bool,
	username string,
	clientVersion string,
) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if sess, exists := t.sessions[sessionID]; exists {
		sess.LoginSuccess = success
		sess.Username = username
		sess.ClientVersion = clientVersion
	}
}

func (t *Tracker) AddTechnique(
	sessionID, techniqueID string,
) {
	t.mu.Lock()
	defer t.mu.Unlock()

	sess, exists := t.sessions[sessionID]
	if !exists {
		return
	}

	for _, t := range sess.MITRETechniques {
		if t == techniqueID {
			return
		}
	}
	sess.MITRETechniques = append(
		sess.MITRETechniques, techniqueID,
	)
}

func (t *Tracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}
