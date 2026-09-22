// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// v4.5.0 Enhancement P1: Multi-Turn Attack Detection
// v4.5.1 Security Hardening: Session DoS Protection
//
// session_tracker.go tracks prompt sequences across a conversation to detect
// multi-turn attack patterns. It correlates L1/L2/L3 findings from individual
// prompts within the same session, identifying escalating or distributed attack
// strategies that would be undetectable in single-prompt scanning.
//
// Design:
//   - Sliding window of recent findings per session ID
//   - Escalation detection (severity increasing across turns)
//   - Pattern distribution analysis (same technique family across turns)
//   - Federated IOC correlation across session turns
//   - Configurable window size and TTL per session
//   - Hard memory limit (MaxSessions) to prevent DoS
// =========================================================================

package scanner

import (
	"sync"
	"time"
)

// SessionWindow is the maximum number of turns retained for analysis.
const SessionWindow = 10

// SessionTTL is the default time-to-live for inactive session tracking.
const SessionTTL = 30 * time.Minute

// MaxSessions is the hard limit on concurrent sessions to prevent DoS.
// When exceeded, the oldest session (by UpdatedAt) is evicted.
// Memory footprint: ~10KB per session (10 turns × ~1KB each)
// Total memory at limit: ~100MB
const MaxSessions = 10000

// TurnFinding is a finding snapshot associated with a specific turn.
type TurnFinding struct {
	TurnIndex int
	Timestamp time.Time
	Severity  string
	Technique string // L2 technique ID, if mapped
	PatternID string // L1 pattern ID, if matched
	MLScore   float64
	RawPrompt string // first N chars for context
}

// SessionState holds the tracked findings for a single conversation session.
type SessionState struct {
	SessionID string
	Turns     []TurnFinding
	UpdatedAt time.Time
	mu        sync.RWMutex
}

// SessionTracker tracks multi-turn conversation patterns for attack detection.
type SessionTracker struct {
	sessions map[string]*SessionState
	mu       sync.RWMutex
	window   int
	ttl      time.Duration
}

// NewSessionTracker creates a new SessionTracker with default configuration.
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		sessions: make(map[string]*SessionState),
		window:   SessionWindow,
		ttl:      SessionTTL,
	}
}

// evictOldest removes the oldest session (by UpdatedAt) to make room for new ones.
// Must be called with st.mu held (write lock).
func (st *SessionTracker) evictOldest() {
	var oldestID string
	var oldestTime time.Time

	for id, session := range st.sessions {
		session.mu.RLock()
		updated := session.UpdatedAt
		session.mu.RUnlock()

		if oldestID == "" || updated.Before(oldestTime) {
			oldestID = id
			oldestTime = updated
		}
	}

	if oldestID != "" {
		delete(st.sessions, oldestID)
	}
}

// RecordFinding adds a finding to the session's tracking window.
func (st *SessionTracker) RecordFinding(sessionID string, finding TurnFinding) {
	st.mu.Lock()
	session, ok := st.sessions[sessionID]
	if !ok {
		// Enforce hard memory limit before creating new session
		if len(st.sessions) >= MaxSessions {
			st.evictOldest()
		}
		session = &SessionState{
			SessionID: sessionID,
			Turns:     make([]TurnFinding, 0, st.window),
		}
		st.sessions[sessionID] = session
	}
	st.mu.Unlock()

	session.mu.Lock()
	defer session.mu.Unlock()

	if finding.Timestamp.IsZero() {
		finding.Timestamp = time.Now()
	}
	finding.TurnIndex = len(session.Turns)

	session.Turns = append(session.Turns, finding)
	if len(session.Turns) > st.window {
		session.Turns = session.Turns[len(session.Turns)-st.window:]
	}
	session.UpdatedAt = time.Now()
}

// AnalyzeSession evaluates the session's finding history for multi-turn attack patterns.
// Returns a MultiTurnResult describing detected escalation or distributed patterns.
