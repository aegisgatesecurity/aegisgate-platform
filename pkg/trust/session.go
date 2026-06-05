// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust Session Manager (v3.2.0 Phase 4)
//
// session.go adds request-lifecycle session semantics on top of the
// per-agent score engine (pkg/trust/score.Engine). The Engine keys
// everything by agentID (long-lived identity); this package keys by
// sessionID (short-lived request lifecycle: an MCP connection, an
// A2A agent-to-agent conversation, a proxy request, etc.).
//
// The two together give us:
//   - Engine.GetScore(agentID)   -> lifetime trust score for the agent
//   - Session.ScoreDelta(sessID) -> how much the score changed during
//                                   this specific request
//
// v3.2.0 Phase 4.2. The HTTP API in pkg/trust/api.go (Phase 4.3) and
// the protocol wiring in mcpserver/a2a/proxy/response (Phase 4.4) will
// both use this package.

package trust

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
	"github.com/google/uuid"
)

// ErrSessionNotFound is returned when a session ID has no live session.
var ErrSessionNotFound = errors.New("trust session not found")

// ErrSessionAlreadyEnded is returned when an operation is attempted on
// a session that has already been ended (closed).
var ErrSessionAlreadyEnded = errors.New("trust session already ended")

// Session represents a request-lifecycle trust session.
//
// Lifecycle:
//  1. Created via Manager.Start(agentID) — StartedAt is set
//  2. Events recorded via Manager.Record(sessionID, event)
//  3. Closed via Manager.End(sessionID) — EndedAt is set, session
//     stays in the map for historical queries but is no longer "live"
type Session struct {
	ID           string                 `json:"id"`
	AgentID      string                 `json:"agentId"`
	StartedAt    time.Time              `json:"startedAt"`
	EndedAt      time.Time              `json:"endedAt,omitempty"` // zero = still open
	InitialScore float64                `json:"initialScore"`      // snapshot at Start
	Events       []*score.BehaviorEvent `json:"events,omitempty"`  // events recorded during this session
	Metadata     map[string]string      `json:"metadata,omitempty"`
}

// IsActive returns true if the session has been started but not ended.
func (s *Session) IsActive() bool {
	return !s.StartedAt.IsZero() && s.EndedAt.IsZero()
}

// Duration returns the wall-clock duration of the session.
// If the session is still active, returns time since StartedAt.
func (s *Session) Duration() time.Duration {
	if s.StartedAt.IsZero() {
		return 0
	}
	end := s.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(s.StartedAt)
}

// EventCount returns the number of events recorded in this session.
func (s *Session) EventCount() int {
	return len(s.Events)
}

// Manager is the trust session manager. It is safe for concurrent use.
//
// Manager wraps a score.Engine and provides session-scoped queries on
// top of the agent-lifetime scoring.
//
// Phase 4.2: a customer using the v3.2.0 Trust pillar (Professional+)
// gets the Manager wired into their MCP/A2A/proxy/response paths
// (Phase 4.4). Below Pro+, the Manager exists in the code but is
// not invoked.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session // sessionID -> Session
	engine   *score.Engine
	// maxSessions caps the in-memory session history. When exceeded,
	// the oldest closed session is evicted (LRU-style). Default 10000.
	maxSessions int
	// maxSessionAge evicts closed sessions older than this. Default 24h.
	maxSessionAge time.Duration
}

// ManagerConfig configures the Manager.
type ManagerConfig struct {
	// MaxSessions caps the in-memory session history. 0 = unlimited.
	MaxSessions int
	// MaxSessionAge is the max age of closed sessions before eviction.
	// 0 = never evict.
	MaxSessionAge time.Duration
}

// DefaultManagerConfig returns sensible defaults.
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		MaxSessions:   10000,
		MaxSessionAge: 24 * time.Hour,
	}
}

// NewManager creates a new trust session manager wrapping an existing
// score.Engine. If config is nil, defaults are used.
func NewManager(engine *score.Engine, config *ManagerConfig) *Manager {
	if config == nil {
		config = DefaultManagerConfig()
	}
	if engine == nil {
		engine = score.NewEngine(nil)
	}
	return &Manager{
		sessions:      make(map[string]*Session),
		engine:        engine,
		maxSessions:   config.MaxSessions,
		maxSessionAge: config.MaxSessionAge,
	}
}

// Engine returns the underlying score.Engine (for callers that need
// direct access to lifetime scoring).
func (m *Manager) Engine() *score.Engine {
	return m.engine
}

// Start begins a new trust session for the given agent. Returns the
// new Session with its assigned ID.
//
// The session's InitialScore is a snapshot of the agent's current
// lifetime trust score at the moment the session starts. ScoreDelta
// can be computed by comparing this to the current score at End time.
func (m *Manager) Start(ctx context.Context, agentID string) (*Session, error) {
	if agentID == "" {
		return nil, errors.New("agent ID is required")
	}
	initialScore := 0.0
	if s, err := m.engine.GetScore(ctx, agentID); err == nil && s != nil {
		initialScore = s.Score
	}
	sess := &Session{
		ID:           uuid.New().String(),
		AgentID:      agentID,
		StartedAt:    time.Now().UTC(),
		InitialScore: initialScore,
		Events:       make([]*score.BehaviorEvent, 0, 16),
		Metadata:     make(map[string]string),
	}
	m.mu.Lock()
	m.sessions[sess.ID] = sess
	m.mu.Unlock()
	// Evict if over cap.
	m.evictIfNeeded()
	return sess, nil
}

// StartWithMetadata is like Start but also attaches initial metadata
// (e.g., source IP, MCP server name, A2A peer agent ID).
func (m *Manager) StartWithMetadata(ctx context.Context, agentID string, metadata map[string]string) (*Session, error) {
	sess, err := m.Start(ctx, agentID)
	if err != nil {
		return nil, err
	}
	for k, v := range metadata {
		sess.Metadata[k] = v
	}
	return sess, nil
}

// Get returns the session with the given ID. Returns ErrSessionNotFound
// if no such session exists.
func (m *Manager) Get(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return sess, nil
}

// End closes the session. Subsequent calls to Record on the same
// sessionID return ErrSessionAlreadyEnded. Returns the closed session
// (so the caller can read the final state).
func (m *Manager) End(ctx context.Context, sessionID string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if !sess.EndedAt.IsZero() {
		return sess, ErrSessionAlreadyEnded
	}
	sess.EndedAt = time.Now().UTC()
	return sess, nil
}

// Record appends a behavior event to the session AND forwards it to the
// underlying score.Engine (which updates the agent's lifetime score).
// Returns the recorded event with its assigned ID.
func (m *Manager) Record(ctx context.Context, sessionID string, eventType score.EventType, capability string, severity int, description string) (*score.BehaviorEvent, error) {
	m.mu.Lock()
	sess, ok := m.sessions[sessionID]
	m.mu.Unlock()
	if !ok {
		return nil, ErrSessionNotFound
	}
	if !sess.IsActive() {
		return nil, ErrSessionAlreadyEnded
	}
	// Forward to engine first (it may update the lifetime score).
	if err := m.engine.RecordEvent(ctx, sess.AgentID, eventType, capability, severity, description); err != nil {
		return nil, err
	}
	// Then append to the session.
	event := &score.BehaviorEvent{
		ID:          uuid.New().String(),
		AgentID:     sess.AgentID,
		Type:        eventType,
		Capability:  capability,
		Severity:    severity,
		Description: description,
		Timestamp:   time.Now().UTC(),
	}
	m.mu.Lock()
	sess.Events = append(sess.Events, event)
	m.mu.Unlock()
	return event, nil
}

// Score returns the agent's current lifetime trust score as observed
// during this session (live read from the engine).
func (m *Manager) Score(ctx context.Context, sessionID string) (*score.TrustScore, error) {
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrSessionNotFound
	}
	return m.engine.GetScore(ctx, sess.AgentID)
}

// ScoreDelta returns the change in trust score during this session
// (current score - initial score). Negative means the session eroded
// trust; positive means it built trust. Returns 0 for an active
// session whose first event hasn't moved the score yet.
func (m *Manager) ScoreDelta(ctx context.Context, sessionID string) (float64, error) {
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return 0, ErrSessionNotFound
	}
	current, err := m.engine.GetScore(ctx, sess.AgentID)
	if err != nil {
		return 0, err
	}
	if current == nil {
		return 0, nil
	}
	return current.Score - sess.InitialScore, nil
}

// List returns all sessions, optionally filtered to active-only.
// Sorted by StartedAt descending (newest first). Honors the
// maxSessionAge config: closed sessions older than maxSessionAge
// are excluded.
func (m *Manager) List(activeOnly bool) []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	cutoff := time.Now().Add(-m.maxSessionAge)
	for _, sess := range m.sessions {
		if activeOnly && !sess.IsActive() {
			continue
		}
		// Filter out closed sessions older than the cutoff.
		if !sess.IsActive() && !sess.EndedAt.IsZero() && sess.EndedAt.Before(cutoff) && m.maxSessionAge > 0 {
			continue
		}
		out = append(out, sess)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	return out
}

// ListByAgent returns all sessions for the given agent, sorted by
// StartedAt descending.
func (m *Manager) ListByAgent(agentID string, activeOnly bool) []*Session {
	all := m.List(activeOnly)
	out := make([]*Session, 0, len(all))
	for _, s := range all {
		if s.AgentID == agentID {
			out = append(out, s)
		}
	}
	return out
}

// ActiveCount returns the number of currently-open sessions.
func (m *Manager) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, s := range m.sessions {
		if s.IsActive() {
			n++
		}
	}
	return n
}

// TotalCount returns the total number of sessions in memory (active + closed).
func (m *Manager) TotalCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// evictIfNeeded evicts old closed sessions if we're over the cap.
// Called after Start to keep the in-memory map bounded.
func (m *Manager) evictIfNeeded() {
	if m.maxSessions <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) <= m.maxSessions {
		return
	}
	// Find closed sessions, oldest EndedAt first.
	type entry struct {
		id    string
		ended time.Time
	}
	var closed []entry
	for id, sess := range m.sessions {
		if !sess.IsActive() {
			closed = append(closed, entry{id: id, ended: sess.EndedAt})
		}
	}
	// Sort oldest first.
	sort.Slice(closed, func(i, j int) bool {
		if closed[i].ended.IsZero() {
			return false
		}
		if closed[j].ended.IsZero() {
			return true
		}
		return closed[i].ended.Before(closed[j].ended)
	})
	// Evict the oldest until under cap.
	excess := len(m.sessions) - m.maxSessions
	for i := 0; i < excess && i < len(closed); i++ {
		delete(m.sessions, closed[i].id)
	}
}
