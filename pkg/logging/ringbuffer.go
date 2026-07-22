// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Audit Event Ring Buffer (v3.3.0+ Track 2)
//
// ringbuffer.go provides an in-memory ring buffer of audit events
// that implements the evidence.EventSource interface. It holds the
// last N events (default 10,000) in a thread-safe ring, and answers
// CountByType / CountBySeverity / CountByFramework queries over a
// time window.
//
// The buffer is the substrate for compliance evidence packages:
// without it, AuditAnchors.Source = "unavailable". With it,
// AuditAnchors.Source = "ring_buffer" and the manifest contains
// real event counts that auditors can correlate against the
// platform logs.
//
// v3.3.0+ Track 2.

package logging

import (
	"context"
	"strings"
	"sync"
	"time"
)

// DefaultCapacity is the default ring buffer capacity. Holds 10K events.
const DefaultCapacity = 10_000

// RingBuffer is a thread-safe bounded queue of audit events. It
// implements the evidence.EventSource interface (defined in
// pkg/evidence/types.go).
//
// When the buffer is full, the oldest event is overwritten. This
// is a deliberate trade-off: we never want audit logging to block
// the hot path, and we accept losing old events as the cost of
// bounded memory.
type RingBuffer struct {
	mu     sync.RWMutex
	events []Event
	cap    int
	head   int // index of next slot to write
	size   int // current number of valid entries (0 <= size <= cap)
}

// NewRingBuffer returns a RingBuffer with the given capacity.
// A capacity <= 0 defaults to DefaultCapacity (10K).
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &RingBuffer{
		events: make([]Event, capacity),
		cap:    capacity,
	}
}

// Add records an event in the buffer. If the buffer is full, the
// oldest event is overwritten. Add is safe for concurrent use.
//
// If e.Time is the zero value, Add stamps it with the current time
// so the event is included in time-window queries. This is the
// common case: callers construct events with Type, Severity, etc.
// but rarely set Time explicitly. The buffer is the authority on
// "when was this event recorded".
func (r *RingBuffer) Add(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[r.head] = e
	r.head = (r.head + 1) % r.cap
	if r.size < r.cap {
		r.size++
	}
}

// Size returns the current number of events in the buffer.
func (r *RingBuffer) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

// Capacity returns the maximum number of events the buffer can hold.
func (r *RingBuffer) Capacity() int {
	return r.cap
}

// snapshotInWindow returns a chronological copy of the events in
// the buffer that fall within the [start, end] window. The snapshot
// is built under the read lock and the time filter is applied after
// releasing the lock (acceptable for 10K buffers).
func (r *RingBuffer) snapshotInWindow(start, end time.Time) []Event {
	r.mu.RLock()
	snapshot := make([]Event, r.size)
	// Snapshot in chronological order (oldest first).
	startIdx := 0
	if r.size == r.cap {
		startIdx = r.head // head points to oldest when full
	}
	for i := 0; i < r.size; i++ {
		snapshot[i] = r.events[(startIdx+i)%r.cap]
	}
	r.mu.RUnlock()

	out := make([]Event, 0, len(snapshot))
	for _, e := range snapshot {
		if e.Time.IsZero() {
			continue // events without a time cannot be windowed
		}
		// Zero bounds mean "no bound" - the audit log search
		// feature (pkg/audit/handler.go) calls SnapshotBetween
		// with zero time.Time to mean "all events" (e.g., for
		// the /users/:user/timeline and /stats endpoints that
		// don't take a from/to filter). Without this guard,
		// the zero time (Jan 1, year 1) would filter out
		// every event as "after the upper bound".
		if !start.IsZero() && e.Time.Before(start) {
			continue
		}
		if !end.IsZero() && e.Time.After(end) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// CountByType returns event counts grouped by Event.Type within
// the [start, end] window. The window is inclusive on both ends.
// The context is accepted for evidence.EventSource compatibility but
// is not used (the buffer is fully in-memory and non-cancellable).
//
// This is one of the three EventSource methods.
func (r *RingBuffer) CountByType(_ context.Context, start, end time.Time) (map[string]int, error) {
	out := map[string]int{}
	for _, e := range r.snapshotInWindow(start, end) {
		out[e.Type]++
	}
	return out, nil
}

// CountBySeverity returns event counts grouped by Event.Severity
// within the [start, end] window. See CountByType for context handling.
func (r *RingBuffer) CountBySeverity(_ context.Context, start, end time.Time) (map[Severity]int, error) {
	out := map[Severity]int{}
	for _, e := range r.snapshotInWindow(start, end) {
		out[e.Severity]++
	}
	return out, nil
}

// CountByFramework returns event counts grouped by
// Event.ComplianceFramework within the [start, end] window.
func (r *RingBuffer) CountByFramework(_ context.Context, start, end time.Time) (map[string]int, error) {
	out := map[string]int{}
	for _, e := range r.snapshotInWindow(start, end) {
		out[e.ComplianceFramework]++
	}
	return out, nil
}

// CountByProtocol returns event counts grouped by the
// AegisGate protocol pillar. The protocol is derived from the
// Event.Type prefix (the convention is "protocol_descriptor",
// e.g., "mcp_tool_call", "a2a_message", "acp_capability",
// "anp_task", "anp_task_output", "response_scan" for HTTP).
// Events whose Type does not match a known protocol are
// counted under the empty string (""). This is the v3.4.0
// primitive that powers the cross-protocol evidence
// aggregation (c1) - a single signed assertion of activity
// across all 5 protocol pillars.
// SnapshotBetween returns the raw list of events in the
// [start, end] time window, in chronological order.
// This is the public counterpart to snapshotInWindow.
// v0.2 added (for the CISO Digest AuditLogSource): the
// audit log adapter needs to iterate over the events in
// the window to filter by severity (high/critical) and
// to derive the anomaly breakdowns by protocol.
func (r *RingBuffer) SnapshotBetween(start, end time.Time) []Event {
	return r.snapshotInWindow(start, end)
}

// The "response_scan" type (used by pkg/response/guard.go) is
// the HTTP protocol pillar. The convention is a best-effort
// parser, not a strict taxonomy: any Type starting with
// "mcp_" -> "mcp", "a2a_" -> "a2a", "acp_" -> "acp",
// "anp_" -> "anp", and everything else with a recognized
// prefix is mapped. The "response_scan" -> "http" mapping
// is explicit because response_scan was the v0 name.
func (r *RingBuffer) CountByProtocol(_ context.Context, start, end time.Time) (map[string]int, error) {
	out := map[string]int{}
	for _, e := range r.snapshotInWindow(start, end) {
		p := ProtocolFromEventType(e.Type)
		out[p]++
	}
	return out, nil
}

// protocolFromEventType derives the AegisGate protocol
// pillar from an event Type string. The convention is a
// best-effort parser: the Type starts with a protocol
// prefix followed by an underscore. The HTTP pillar is
// special-cased ("response_scan" -> "http") because that
// was the v0 name.
//
// Returns "" for events that do not match a known protocol.
// The empty string is a valid bucket in the ByProtocol map
// (so auditors can see "how many events did the platform
// emit that were NOT tagged with a protocol?").
func ProtocolFromEventType(t string) string {
	switch {
	case t == "response_scan":
		return "http"
	case strings.HasPrefix(t, "mcp_"):
		return "mcp"
	case strings.HasPrefix(t, "a2a_"):
		return "a2a"
	case strings.HasPrefix(t, "acp_"):
		return "acp"
	case strings.HasPrefix(t, "anp_"):
		return "anp"
	}
	return ""
}

// Clear removes all events from the buffer. Used by tests and by
// the daily-reset cron in demo mode.
func (r *RingBuffer) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.head = 0
	r.size = 0
	// Zero the slice to drop references to old events.
	for i := range r.events {
		r.events[i] = Event{}
	}
}
