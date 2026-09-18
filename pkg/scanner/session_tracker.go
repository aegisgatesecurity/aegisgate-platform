// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// v4.5.0 Enhancement P1: Multi-Turn Attack Detection
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

// RecordFinding adds a finding to the session's tracking window.
func (st *SessionTracker) RecordFinding(sessionID string, finding TurnFinding) {
	st.mu.Lock()
	session, ok := st.sessions[sessionID]
	if !ok {
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
func (st *SessionTracker) AnalyzeSession(sessionID string) MultiTurnResult {
	st.mu.RLock()
	session, ok := st.sessions[sessionID]
	st.mu.RUnlock()

	if !ok {
		return MultiTurnResult{SessionID: sessionID, RiskLevel: MultiTurnRiskNone}
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	result := MultiTurnResult{
		SessionID: sessionID,
		TurnCount: len(session.Turns),
		RiskLevel: MultiTurnRiskNone,
	}

	if len(session.Turns) < 2 {
		return result
	}

	// Escalation detection: severity increasing across turns
	escalationScore := st.detectEscalation(session.Turns)
	// Technique repetition: same technique family across multiple turns
	repetitionScore := st.detectTechniqueRepetition(session.Turns)

	result.EscalationScore = escalationScore
	result.RepetitionScore = repetitionScore

	// Aggregate risk level
	totalScore := escalationScore + repetitionScore
	switch {
	case totalScore >= 0.7:
		result.RiskLevel = MultiTurnRiskHigh
	case totalScore >= 0.4:
		result.RiskLevel = MultiTurnRiskMedium
	case totalScore >= 0.2:
		result.RiskLevel = MultiTurnRiskLow
	}

	return result
}

// detectEscalation computes an escalation score (0.0–1.0) based on severity
// progression across turns. A rising severity trend indicates an attacker
// probing with increasingly aggressive techniques.
func (st *SessionTracker) detectEscalation(turns []TurnFinding) float64 {
	if len(turns) < 2 {
		return 0
	}

	severityOrder := map[string]int{
		"info":     0,
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	ascending := 0
	for i := 1; i < len(turns); i++ {
		prev := severityOrder[turns[i-1].Severity]
		curr := severityOrder[turns[i].Severity]
		if curr > prev {
			ascending++
		}
	}

	return float64(ascending) / float64(len(turns)-1)
}

// detectTechniqueRepetition computes a repetition score (0.0–1.0) based on
// how often the same L2 technique appears across multiple turns. Repeated
// use of the same technique family suggests a coordinated attack strategy.
func (st *SessionTracker) detectTechniqueRepetition(turns []TurnFinding) float64 {
	if len(turns) < 2 {
		return 0
	}

	techCounts := make(map[string]int)
	for _, t := range turns {
		if t.Technique != "" {
			techCounts[t.Technique]++
		}
	}

	maxRepeats := 0
	for _, count := range techCounts {
		if count > maxRepeats {
			maxRepeats = count
		}
	}

	return float64(maxRepeats) / float64(len(turns))
}

// CleanupExpired removes session tracking data that has exceeded the TTL.
func (st *SessionTracker) CleanupExpired() int {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	removed := 0
	for id, session := range st.sessions {
		session.mu.RLock()
		expired := now.Sub(session.UpdatedAt) > st.ttl
		session.mu.RUnlock()
		if expired {
			delete(st.sessions, id)
			removed++
		}
	}
	return removed
}

// MultiTurnRiskLevel classifies the overall risk of a multi-turn attack pattern.
type MultiTurnRiskLevel int

const (
	MultiTurnRiskNone MultiTurnRiskLevel = iota
	MultiTurnRiskLow
	MultiTurnRiskMedium
	MultiTurnRiskHigh
)

// MultiTurnResult is the analysis output for a tracked session.
type MultiTurnResult struct {
	SessionID       string
	TurnCount       int
	EscalationScore float64
	RepetitionScore float64
	RiskLevel       MultiTurnRiskLevel
}
