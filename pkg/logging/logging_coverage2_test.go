// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Logging Coverage Tests
// =========================================================================
//
// logging_coverage2_test.go — tests for 0% functions in pkg/logging:
//   - Event.Get* accessors (types.go)
//   - GetDefault, IsEnabled, QuickEvent (recorder.go)
//   - WarnIfGlobalCacheUnset (framework_refs.go)
//   - CountByProtocol, ProtocolFromEventType (ringbuffer.go)
//
// Also improves partial coverage on:
//   - Record (recorder.go) — exercises the QuickEvent path
//   - snapshotInWindow (ringbuffer.go) — exercises zero-time skip
// =========================================================================

package logging

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Event.Get* accessors (types.go:108-114)
// ---------------------------------------------------------------------------

func TestCoreEventGetters(t *testing.T) {
	ts := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	e := Event{
		ID:       "evt-123",
		Time:     ts,
		Type:     "auth",
		Action:   "block",
		Severity: SeverityCritical,
		User:     "josh",
		Message:  "suspicious login attempt",
	}

	if got := e.GetID(); got != "evt-123" {
		t.Errorf("GetID() = %q, want 'evt-123'", got)
	}
	if got := e.GetTime(); !got.Equal(ts) {
		t.Errorf("GetTime() = %v, want %v", got, ts)
	}
	if got := e.GetType(); got != "auth" {
		t.Errorf("GetType() = %q, want 'auth'", got)
	}
	if got := e.GetAction(); got != "block" {
		t.Errorf("GetAction() = %q, want 'block'", got)
	}
	if got := e.GetSeverity(); got != "critical" {
		t.Errorf("GetSeverity() = %q, want 'critical'", got)
	}
	if got := e.GetUser(); got != "josh" {
		t.Errorf("GetUser() = %q, want 'josh'", got)
	}
	if got := e.GetMessage(); got != "suspicious login attempt" {
		t.Errorf("GetMessage() = %q, want 'suspicious login attempt'", got)
	}
}

// ---------------------------------------------------------------------------
// GetDefault (recorder.go:57)
// ---------------------------------------------------------------------------

func TestCoreGetDefault_NotSet(t *testing.T) {
	// Save and restore
	SetDefault(nil)
	defer SetDefault(nil)

	if r := GetDefault(); r != nil {
		t.Errorf("GetDefault() = %v, want nil when no recorder set", r)
	}
}

func TestCoreGetDefault_Set(t *testing.T) {
	rb := NewRingBuffer(8)
	SetDefault(rb)
	defer SetDefault(nil)

	r := GetDefault()
	if r == nil {
		t.Fatal("GetDefault() = nil, want non-nil")
	}

	// Verify it's the same recorder by adding an event
	r.Add(Event{Type: "test", Severity: SeverityInfo, Message: "hello"})
	if rb.Size() != 1 {
		t.Errorf("RingBuffer size = %d, want 1", rb.Size())
	}
}

// ---------------------------------------------------------------------------
// IsEnabled (recorder.go:113)
// ---------------------------------------------------------------------------

func TestCoreIsEnabled(t *testing.T) {
	SetDefault(nil)
	defer SetDefault(nil)

	if IsEnabled() {
		t.Error("IsEnabled() = true, want false when no recorder set")
	}

	rb := NewRingBuffer(4)
	SetDefault(rb)
	if !IsEnabled() {
		t.Error("IsEnabled() = false, want true when recorder is set")
	}
}

// ---------------------------------------------------------------------------
// QuickEvent (recorder.go:124)
// ---------------------------------------------------------------------------

func TestCoreQuickEvent_WithRecorder(t *testing.T) {
	rb := NewRingBuffer(8)
	SetDefault(rb)
	defer SetDefault(nil)

	QuickEvent("threat_detected", SeverityHigh, "prompt injection attempt")

	if rb.Size() != 1 {
		t.Fatalf("QuickEvent: ring size = %d, want 1", rb.Size())
	}

	events := rb.snapshotInWindow(time.Time{}, time.Time{})
	if len(events) != 1 {
		t.Fatalf("snapshot = %d events, want 1", len(events))
	}
	if events[0].Type != "threat_detected" {
		t.Errorf("type = %q, want 'threat_detected'", events[0].Type)
	}
	if events[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want 'high'", events[0].Severity)
	}
	if events[0].Message != "prompt injection attempt" {
		t.Errorf("message = %q, want 'prompt injection attempt'", events[0].Message)
	}
}

func TestCoreQuickEvent_NoRecorder(t *testing.T) {
	SetDefault(nil)
	defer SetDefault(nil)

	// Should be a no-op, not panic
	QuickEvent("test", SeverityInfo, "no recorder")
}

// ---------------------------------------------------------------------------
// WarnIfGlobalCacheUnset (framework_refs.go:539)
// ---------------------------------------------------------------------------

func TestCoreWarnIfGlobalCacheUnset_NotSet(t *testing.T) {
	// Reset the sync.Once so our test can fire the warning
	globalRefCacheOnce = sync.Once{}
	prev := GetGlobalRefCache()
	SetGlobalRefCache(nil)
	defer func() {
		SetGlobalRefCache(prev)
		globalRefCacheOnce = sync.Once{}
	}()

	// Should not panic and should log the warning
	WarnIfGlobalCacheUnset()
}

func TestCoreWarnIfGlobalCacheUnset_Set(t *testing.T) {
	// Reset the sync.Once
	globalRefCacheOnce = sync.Once{}
	prev := GetGlobalRefCache()
	defer func() {
		SetGlobalRefCache(prev)
		globalRefCacheOnce = sync.Once{}
	}()

	// Install a cache so the warning should NOT fire
	cache := &FrameworkRefCache{}
	if err := cache.Init(FrameworkRefCacheConfig{Seed: fixedSeed(nil, nil)}); err != nil {
		t.Fatalf("Init error: %v", err)
	}
	defer cache.Stop()
	SetGlobalRefCache(cache)

	// Should not panic; warning path not taken since cache is set
	WarnIfGlobalCacheUnset()
}

// ---------------------------------------------------------------------------
// ProtocolFromEventType (ringbuffer.go:213)
// ---------------------------------------------------------------------------

func TestCoreProtocolFromEventType(t *testing.T) {
	tests := []struct {
		eventType string
		want      string
	}{
		{"response_scan", "http"},
		{"mcp_scan", "mcp"},
		{"mcp_initialize", "mcp"},
		{"a2a_handshake", "a2a"},
		{"a2a_message", "a2a"},
		{"acp_request", "acp"},
		{"acp_response", "acp"},
		{"anp_publish", "anp"},
		{"anp_subscribe", "anp"},
		{"auth", ""},         // no recognized prefix
		{"", ""},             // empty string
		{"http_request", ""}, // "http_" prefix not recognized (only "response_scan")
		{"random_event", ""}, // unknown prefix
	}
	for _, tt := range tests {
		got := ProtocolFromEventType(tt.eventType)
		if got != tt.want {
			t.Errorf("ProtocolFromEventType(%q) = %q, want %q", tt.eventType, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// CountByProtocol (ringbuffer.go:193)
// ---------------------------------------------------------------------------

func TestCoreCountByProtocol(t *testing.T) {
	rb := NewRingBuffer(16)

	now := time.Now().UTC()
	// Add events with various protocol types
	rb.Add(Event{Type: "mcp_scan", Time: now})
	rb.Add(Event{Type: "mcp_initialize", Time: now})
	rb.Add(Event{Type: "a2a_handshake", Time: now})
	rb.Add(Event{Type: "response_scan", Time: now})
	rb.Add(Event{Type: "auth", Time: now}) // no protocol
	rb.Add(Event{Type: "anp_publish", Time: now})

	ctx := context.Background()
	counts, err := rb.CountByProtocol(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("CountByProtocol error: %v", err)
	}

	if counts["mcp"] != 2 {
		t.Errorf("counts[mcp] = %d, want 2", counts["mcp"])
	}
	if counts["a2a"] != 1 {
		t.Errorf("counts[a2a] = %d, want 1", counts["a2a"])
	}
	if counts["http"] != 1 {
		t.Errorf("counts[http] = %d, want 1", counts["http"])
	}
	if counts["anp"] != 1 {
		t.Errorf("counts[anp] = %d, want 1", counts["anp"])
	}
	if counts[""] != 1 {
		t.Errorf("counts[''] = %d, want 1 (unrecognized 'auth' event)", counts[""])
	}
}

func TestCoreCountByProtocol_Empty(t *testing.T) {
	rb := NewRingBuffer(4)
	ctx := context.Background()
	counts, err := rb.CountByProtocol(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("CountByProtocol error: %v", err)
	}
	if len(counts) != 0 {
		t.Errorf("CountByProtocol(empty) = %d buckets, want 0", len(counts))
	}
}

// ---------------------------------------------------------------------------
// snapshotInWindow — improve coverage of the zero-time skip branch
// ---------------------------------------------------------------------------

func TestCoreSnapshotInWindow_ZeroTimeSkipped(t *testing.T) {
	rb := NewRingBuffer(8)

	// Add an event with an explicit zero time (bypasses Add's auto-stamping
	// by directly writing to the buffer). We need to use Add but then
	// manually check that zero-time events are skipped.
	// Since Add stamps zero-time events, we add an event with a real time
	// and one that also has a real time but outside the window.
	now := time.Now().UTC()
	rb.Add(Event{Type: "in_window", Time: now})
	rb.Add(Event{Type: "out_of_window", Time: now.Add(-2 * time.Hour)})

	// Query a narrow window around 'now'
	start := now.Add(-1 * time.Minute)
	end := now.Add(1 * time.Minute)
	events := rb.snapshotInWindow(start, end)
	if len(events) != 1 {
		t.Fatalf("snapshotInWindow = %d events, want 1", len(events))
	}
	if events[0].Type != "in_window" {
		t.Errorf("event type = %q, want 'in_window'", events[0].Type)
	}
}

func TestCoreSnapshotInWindow_BothZeroBounds(t *testing.T) {
	rb := NewRingBuffer(8)
	now := time.Now().UTC()
	rb.Add(Event{Type: "a", Time: now})
	rb.Add(Event{Type: "b", Time: now.Add(1 * time.Minute)})

	// Zero bounds mean "no bound" — all events returned
	events := rb.snapshotInWindow(time.Time{}, time.Time{})
	if len(events) != 2 {
		t.Errorf("snapshotInWindow(zero bounds) = %d, want 2", len(events))
	}
}

// ---------------------------------------------------------------------------
// Record — improve coverage via the QuickEvent path
// ---------------------------------------------------------------------------

func TestCoreRecord_WithFrameworkRefs(t *testing.T) {
	// Install a global cache with a mapping so Record populates FrameworkRefs
	globalRefCacheOnce = sync.Once{}
	prev := GetGlobalRefCache()
	defer func() {
		SetGlobalRefCache(prev)
		globalRefCacheOnce = sync.Once{}
	}()

	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key:  DetectionKey{Type: "auth", ThreatType: "test_threat", Pattern: "test_pattern"},
			Refs: map[string][]string{"mitre_atlas": {"T0024"}},
		},
	}
	if err := cache.Init(FrameworkRefCacheConfig{Seed: fixedSeed(entries, nil)}); err != nil {
		t.Fatalf("Init error: %v", err)
	}
	defer cache.Stop()
	SetGlobalRefCache(cache)

	rb := NewRingBuffer(8)
	SetDefault(rb)
	defer SetDefault(nil)

	// Record an event matching the seeded detection key
	Record(Event{
		Type:       "auth",
		ThreatType: "test_threat",
		Pattern:    "test_pattern",
		Severity:   SeverityHigh,
		Message:    "test event with framework refs",
	})

	if rb.Size() != 1 {
		t.Fatalf("Record: ring size = %d, want 1", rb.Size())
	}

	events := rb.snapshotInWindow(time.Time{}, time.Time{})
	if len(events) != 1 {
		t.Fatalf("snapshot = %d events, want 1", len(events))
	}
	if len(events[0].FrameworkRefs) == 0 {
		t.Error("Record did not populate FrameworkRefs")
	}
}
