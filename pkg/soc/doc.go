// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - SOC Incident Timeline (TODO-502)
//
// Package soc provides a SOC analyst's view of an
// AegisGate investigation: a chronological timeline
// of all events related to a single incident (a
// session or thread of activity).
//
// v0.1 ships:
//
//   - GetTimeline(ctx, sessionID): returns the
//     chronological list of events for a given
//     session, with cross-protocol correlation
//     annotations.
//   - Cross-protocol event types (HTTP, MCP, A2A,
//     ACP, ANP, computeruse).
//   - Read-only access to the correlation engine's
//     in-memory event store.
//   - No persistence (events are lost on process
//     restart; this is a v0.1 limitation).
//
// v0.1 does NOT ship:
//
//   - Persistence (use a database; v0.2).
//   - Real-time streaming (use a subscription API;
//     v0.2).
//   - Auto-correlation of patterns across events
//     (v0.1 just returns raw events; v0.2 uses
//     correlation.Analyze()).
//   - Per-agent timelines (only per-session in v0.1;
//     per-agent is a v0.2 addition).
//
// Data source: pkg/correlation.Engine. The engine
// has a SessionID field on every Event (unlike
// pkg/logging.Event, which doesn't), so the SOC
// timeline can filter by session directly.
//
// Wire target:
//
//   - GET /api/v1/soc/incidents/:id/timeline
//   - aegisgate soc timeline --incident=<session-id>
package soc

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
)

// =====================================================================
// TimelineEvent
// =====================================================================

// TimelineEvent is a single event in the SOC
// timeline. It is a flat, JSON-friendly view of
// the correlation engine's Event type, with
// additional cross-protocol correlation annotations.
type TimelineEvent struct {
	// ID is the event's unique identifier.
	ID string `json:"id"`
	// Timestamp is the event time.
	Timestamp time.Time `json:"timestamp"`
	// Protocol is the protocol pillar (http, mcp,
	// a2a, acp, anp, computeruse).
	Protocol string `json:"protocol"`
	// AgentID is the agent that emitted the event.
	AgentID string `json:"agent_id"`
	// SessionID is the session this event belongs to.
	SessionID string `json:"session_id"`
	// EventType is the event type (e.g., "request",
	// "error", "decision").
	EventType string `json:"event_type"`
	// Severity is the event severity (low, medium,
	// high, critical).
	Severity string `json:"severity"`
	// Decision is the AegisGate decision (allow,
	// block, require_approval, alert).
	Decision string `json:"decision,omitempty"`
	// Message is a human-readable message.
	Message string `json:"message,omitempty"`
	// Metadata is a free-form metadata map.
	Metadata map[string]string `json:"metadata,omitempty"`
	// MatchedPatterns is a list of correlation
	// patterns this event matched (e.g.,
	// "mcp_error_injection"). Populated by
	// GetTimeline via the correlation engine.
	MatchedPatterns []string `json:"matched_patterns,omitempty"`
}

// IsCritical returns true if the event's severity is
// "critical" or "high".
func (e *TimelineEvent) IsCritical() bool {
	return e != nil && (e.Severity == "critical" || e.Severity == "high")
}

// =====================================================================
// TimelineResult
// =====================================================================

// TimelineResult is the result of GetTimeline. It
// includes the events (sorted by timestamp) plus
// summary statistics.
type TimelineResult struct {
	// SessionID is the queried session ID.
	SessionID string `json:"session_id"`
	// AgentID is the agent associated with the
	// session (may be empty if no events have an
	// agent ID).
	AgentID string `json:"agent_id,omitempty"`
	// Events is the chronological list of events.
	Events []*TimelineEvent `json:"events"`
	// StartTime is the timestamp of the first event
	// (zero if no events).
	StartTime time.Time `json:"start_time,omitempty"`
	// EndTime is the timestamp of the last event
	// (zero if no events).
	EndTime time.Time `json:"end_time,omitempty"`
	// TotalCount is the number of events.
	TotalCount int `json:"total_count"`
	// ProtocolCounts maps protocol -> event count.
	ProtocolCounts map[string]int `json:"protocol_counts"`
	// SeverityCounts maps severity -> event count.
	SeverityCounts map[string]int `json:"severity_counts"`
	// HasCriticalEvents is true if any event is
	// critical or high severity.
	HasCriticalEvents bool `json:"has_critical_events"`
}

// =====================================================================
// Engine interface
// =====================================================================

// Engine is the interface that GetTimeline needs.
// The correlation.Engine satisfies this interface
// (it has a ListEventsBySession method).
//
// We use an interface (not the concrete type) to
// allow testing with mock engines (and to decouple
// the SOC package from the correlation package's
// internals).
type Engine interface {
	// ListEventsBySession returns all events for the
	// given session ID, across all agents.
	ListEventsBySession(ctx context.Context, sessionID string) ([]*correlation.Event, error)
}

// engineAdapter converts a correlation.Engine into
// the SOC Engine interface. This is a simple
// passthrough but it's a useful indirection for
// testing.
type engineAdapter struct {
	engine *correlation.Engine
}

func (a *engineAdapter) ListEventsBySession(ctx context.Context, sessionID string) ([]*correlation.Event, error) {
	return a.engine.ListEventsBySession(ctx, sessionID)
}

// WrapEngine adapts a concrete *correlation.Engine
// into the SOC Engine interface.
func WrapEngine(e *correlation.Engine) Engine {
	return &engineAdapter{engine: e}
}

// =====================================================================
// GetTimeline
// =====================================================================

// GetTimeline returns the chronological list of
// events for the given session ID. The result
// includes summary statistics (protocol counts,
// severity counts, critical-event flag).
//
// Errors:
//   - sessionID is empty
//   - the underlying engine returns an error
//   - ctx is cancelled
func GetTimeline(ctx context.Context, engine Engine, sessionID string) (*TimelineResult, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("soc: sessionID is required")
	}
	if engine == nil {
		return nil, fmt.Errorf("soc: engine is nil")
	}
	// Check context.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("soc: context: %w", err)
	}
	// Fetch events from the engine.
	correlationEvents, err := engine.ListEventsBySession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("soc: list events: %w", err)
	}
	// Convert correlation.Event to TimelineEvent.
	events := make([]*TimelineEvent, 0, len(correlationEvents))
	for _, ce := range correlationEvents {
		events = append(events, convertEvent(ce))
	}
	// Sort by timestamp ascending.
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	// Build the result.
	result := &TimelineResult{
		SessionID:      sessionID,
		Events:         events,
		TotalCount:     len(events),
		ProtocolCounts: make(map[string]int),
		SeverityCounts: make(map[string]int),
	}
	for _, evt := range events {
		result.ProtocolCounts[evt.Protocol]++
		result.SeverityCounts[evt.Severity]++
		if evt.IsCritical() {
			result.HasCriticalEvents = true
		}
		if result.AgentID == "" && evt.AgentID != "" {
			result.AgentID = evt.AgentID
		}
	}
	if len(events) > 0 {
		result.StartTime = events[0].Timestamp
		result.EndTime = events[len(events)-1].Timestamp
	}
	return result, nil
}

// convertEvent converts a correlation.Event to a
// TimelineEvent. This is the bridge between the
// correlation engine's internal representation
// and the SOC timeline's wire format.
func convertEvent(ce *correlation.Event) *TimelineEvent {
	if ce == nil {
		return nil
	}
	return &TimelineEvent{
		ID:        ce.ID,
		Timestamp: ce.Timestamp,
		Protocol:  ce.Protocol,
		AgentID:   ce.AgentID,
		SessionID: ce.SessionID,
		EventType: ce.EventType,
		Severity:  ce.Severity,
		Decision:  ce.Decision,
		Metadata:  ce.Metadata,
		// MatchedPatterns is populated by GetTimeline
		// via the correlation engine's Analyze method
		// in v0.2. v0.1 leaves it nil.
	}
}
