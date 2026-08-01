// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package proxy provides multi-turn attack detection integration for the proxy.
//
// MultiTurnMiddleware wraps the ml.MultiTurnDetector into the proxy pipeline,
// extracting per-turn signals from the existing detection pipeline results
// and feeding them into the cumulative scoring engine.
package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/ml"
	"github.com/aegisgatesecurity/aegisgate/pkg/scanner"
)

// MultiTurnMiddleware wraps the multi-turn detector for use in the proxy.
type MultiTurnMiddleware struct {
	detector *ml.MultiTurnDetector
}

// MultiTurnMiddlewareConfig holds configuration for the multi-turn middleware.
type MultiTurnMiddlewareConfig struct {
	// Enabled toggles multi-turn detection on/off. Default: true
	Enabled bool `json:"enabled"`

	// BlockThreshold is the cumulative score at which to block. Default: 75.0
	BlockThreshold float64 `json:"block_threshold"`

	// AlertThreshold is the cumulative score at which to alert. Default: 40.0
	AlertThreshold float64 `json:"alert_threshold"`

	// MaxSessions is the maximum number of concurrent conversation sessions to track. Default: 10000
	MaxSessions int `json:"max_sessions"`

	// SessionTTLMinutes is how long a session remains active without activity, in minutes. Default: 30
	SessionTTLMinutes int `json:"session_ttl_minutes"`

	// EnableLogging controls whether detection events are logged. Default: true
	EnableLogging bool `json:"enable_logging"`
}

// DefaultMultiTurnMiddlewareConfig returns sensible defaults.
func DefaultMultiTurnMiddlewareConfig() *MultiTurnMiddlewareConfig {
	return &MultiTurnMiddlewareConfig{
		Enabled:           true,
		BlockThreshold:    75.0,
		AlertThreshold:    40.0,
		MaxSessions:       10000,
		SessionTTLMinutes: 30,
		EnableLogging:     true,
	}
}

// NewMultiTurnMiddleware creates a new multi-turn middleware instance.
func NewMultiTurnMiddleware(config *MultiTurnMiddlewareConfig) *MultiTurnMiddleware {
	if config == nil {
		config = DefaultMultiTurnMiddlewareConfig()
	}

	ttl := 30 * time.Minute
	if config.SessionTTLMinutes > 0 {
		ttl = time.Duration(config.SessionTTLMinutes) * time.Minute
	}

	detector := ml.NewMultiTurnDetector(ml.MultiTurnConfig{
		MaxSessions:          config.MaxSessions,
		SessionTTL:           ttl,
		BlockThreshold:       config.BlockThreshold,
		AlertThreshold:       config.AlertThreshold,
		EscalationMultiplier: 1.5,
		RepetitionPenalty:    10.0,
		DecayRate:            0.15,
		EnableLogging:        config.EnableLogging,
		SignalWeights:        ml.DefaultSignalWeights(),
	})

	return &MultiTurnMiddleware{
		detector: detector,
	}
}

// AnalyzeRequest analyzes an incoming request for multi-turn attack patterns.
// It takes the detection results from the existing pipeline (scanner, ATLAS, ML)
// and feeds them into the multi-turn detector.
//
// Parameters:
//   - conversationID: unique identifier for the conversation (from request headers,
//     session cookie, or generated from client IP + user agent hash)
//   - role: the message role (user, system, assistant)
//   - content: the extracted message content
//   - scannerFindings: findings from the content scanner
//   - atlasFindings: findings from MITRE ATLAS compliance
//   - mlResult: results from the ML combined detector (may be nil if ML not enabled)
//
// Returns the multi-turn detection result, which includes cumulative score,
// whether to block/alert, matched attack chains, and escalation/repetition flags.
func (m *MultiTurnMiddleware) AnalyzeRequest(
	conversationID string,
	role string,
	content string,
	scannerFindings []scanner.Finding,
	atlasFindings []compliance.Finding,
	mlResult *ml.CombinedResult,
) *ml.MultiTurnResult {
	if !m.IsEnabled() {
		return nil
	}

	signals := buildTurnSignals(scannerFindings, atlasFindings, mlResult, role, content)

	result := m.detector.Analyze(conversationID, role, content, signals)

	if result.ShouldBlock {
		slog.Error("Multi-turn attack detected: blocking request",
			"session_id", result.SessionID,
			"turn", result.TurnNumber,
			"cumulative_score", fmt.Sprintf("%.1f", result.CumulativeScore),
			"turn_score", fmt.Sprintf("%.1f", result.TurnScore),
			"chains", strings.Join(result.MatchedChains, ", "),
			"escalation", result.EscalationDetected,
			"repetition", result.RepetitionDetected,
		)
	} else if result.ShouldAlert {
		slog.Warn("Multi-turn attack: alert threshold reached",
			"session_id", result.SessionID,
			"turn", result.TurnNumber,
			"cumulative_score", fmt.Sprintf("%.1f", result.CumulativeScore),
			"chains", strings.Join(result.MatchedChains, ", "),
		)
	}

	return result
}

// GetDetector returns the underlying multi-turn detector for direct access.
func (m *MultiTurnMiddleware) GetDetector() *ml.MultiTurnDetector {
	return m.detector
}

// IsEnabled returns whether multi-turn detection is enabled.
func (m *MultiTurnMiddleware) IsEnabled() bool {
	return m.detector != nil
}

// GetStats returns detection statistics.
func (m *MultiTurnMiddleware) GetStats() map[string]interface{} {
	if m.detector == nil {
		return map[string]interface{}{"enabled": false}
	}
	return m.detector.GetStats()
}

// ResetSession clears the multi-turn state for a conversation.
func (m *MultiTurnMiddleware) ResetSession(conversationID string) {
	if m.detector != nil {
		m.detector.ResetSession(conversationID)
	}
}

// GetSession returns the session state for a conversation.
func (m *MultiTurnMiddleware) GetSession(conversationID string) *ml.SessionState {
	if m.detector == nil {
		return nil
	}
	return m.detector.GetSession(conversationID)
}

// buildTurnSignals converts existing pipeline detection results into
// TurnSignals for the multi-turn detector.
func buildTurnSignals(
	scannerFindings []scanner.Finding,
	atlasFindings []compliance.Finding,
	mlResult *ml.CombinedResult,
	role string,
	content string,
) ml.TurnSignals {
	signals := ml.TurnSignals{
		Role:          role,
		ContentLength: len(content),
	}

	// Convert scanner findings to severity counts
	for _, f := range scannerFindings {
		if f.Pattern == nil {
			continue
		}
		switch f.Pattern.Severity {
		case scanner.Critical:
			signals.ScannerFindings.Critical++
		case scanner.High:
			signals.ScannerFindings.High++
		case scanner.Medium:
			signals.ScannerFindings.Medium++
		case scanner.Low:
			signals.ScannerFindings.Low++
		case scanner.Info:
			signals.ScannerFindings.Info++
		}
	}

	// Convert ATLAS findings to severity counts
	for _, f := range atlasFindings {
		switch f.Severity {
		case compliance.SeverityCritical:
			signals.ATLASFindings.Critical++
		case compliance.SeverityHigh:
			signals.ATLASFindings.High++
		case compliance.SeverityMedium:
			signals.ATLASFindings.Medium++
		case compliance.SeverityLow:
			signals.ATLASFindings.Low++
		case compliance.SeverityInfo:
			signals.ATLASFindings.Info++
		}
	}

	// Extract ML detection scores
	if mlResult != nil {
		signals.PromptInjectionScore = mlResult.PromptInjectionScore
		signals.TokenSmugglingScore = mlResult.TokenSmugglingScore
		signals.UnicodeAttackScore = mlResult.UnicodeAttackScore
		signals.ContextManipulationScore = mlResult.ContextScore
		signals.PromptInjectionPatterns = mlResult.AllMatchedPatterns
	}

	return signals
}

// ExtractConversationID derives a conversation identifier from the HTTP request.
// This uses the X-Conversation-ID header if present, otherwise falls back to
// a hash of client IP + User-Agent for session tracking.
func ExtractConversationID(r *http.Request) string {
	// Prefer explicit conversation ID header
	if convID := r.Header.Get("X-Conversation-ID"); convID != "" {
		return convID
	}

	// Fall back to X-Request-ID
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		return reqID
	}

	// Fall back to client IP + User-Agent hash (less ideal but functional)
	// This groups requests from the same client together
	ip := getClientIP(r)
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = "unknown"
	}
	return ip + "|" + ua
}
