// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - SIEM Dispatcher tests (v3.5.0+, Tier 2 TODO-404)
//
// siem_dispatcher_test.go covers the audit package's
// SIEMDispatcher: a thin bridge between the platform's
// evidence.EventSource and the upstream siem.Manager.
//
// The tests are white-box (package audit) so we can poke at
// the unexported pollOnce method and the dispatcher stats.
// The tests use a real RingBuffer as the EventSource (it
// implements evidence.EventSource) and a real siem.Manager
// (no platforms configured; the Manager still accepts and
// routes events internally, even with no clients).

package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/siem"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

// newTestManager builds a minimal siem.Manager for tests. The
// manager has no platforms configured (Manager.Send will
// succeed with no clients because the events go into the
// internal channel and are silently dropped when there are
// no platform clients). This is the simplest possible
// configuration that exercises the dispatcher's send path.
func newTestManager(t *testing.T) *siem.Manager {
	t.Helper()
	// Use a minimal config with no platforms. The Manager
	// is started so the internal event-processing goroutine
	// is running, but with no clients there is nothing to
	// actually send to.
	mgr, err := siem.NewManager(siem.Config{
		Global: siem.GlobalConfig{
			AppName: "aegisgate-test",
		},
		Buffer: siem.BufferConfig{
			MaxSize: 1000,
		},
	})
	if err != nil {
		t.Fatalf("siem.NewManager: %v", err)
	}
	mgr.Start()
	t.Cleanup(mgr.Stop)
	return mgr
}

// newTestRingBuffer builds a *logging.RingBuffer (which
// implements evidence.EventSource) and seeds it with a few
// events so the dispatcher's poll cycle has something to
// read.
func newTestRingBuffer(t *testing.T, events []logging.Event) *logging.RingBuffer {
	t.Helper()
	ring := logging.NewRingBuffer(1000)
	for _, e := range events {
		ring.Add(e)
	}
	t.Cleanup(ring.Clear)
	return ring
}

// --------------------------------------------------------------------
// NewSIEMDispatcher validation
// --------------------------------------------------------------------

func TestNewSIEMDispatcher_RequiresFields(t *testing.T) {
	t.Parallel()
	if _, err := NewSIEMDispatcher(SIEMDispatcherConfig{}); err == nil {
		t.Error("expected error on empty config")
	}
	mgr := newTestManager(t)
	if _, err := NewSIEMDispatcher(SIEMDispatcherConfig{Manager: mgr}); err == nil {
		t.Error("expected error on missing EventSource")
	}
}

func TestNewSIEMDispatcher_AppliesDefaults(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	ring := newTestRingBuffer(t, nil)
	d, err := NewSIEMDispatcher(SIEMDispatcherConfig{
		Manager:     mgr,
		EventSource: ring,
	})
	if err != nil {
		t.Fatalf("NewSIEMDispatcher: %v", err)
	}
	if d.cfg.PollInterval != 1*time.Second {
		t.Errorf("PollInterval = %v, want 1s (default)", d.cfg.PollInterval)
	}
	if d.cfg.BatchSize != 100 {
		t.Errorf("BatchSize = %d, want 100 (default)", d.cfg.BatchSize)
	}
	if d.cfg.Source != "aegisgate" {
		t.Errorf("Source = %q, want aegisgate (default)", d.cfg.Source)
	}
}

// --------------------------------------------------------------------
// pollOnce
// --------------------------------------------------------------------

func TestPollOnce_EmptyEventSource(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	ring := newTestRingBuffer(t, nil)
	d, err := NewSIEMDispatcher(SIEMDispatcherConfig{
		Manager:     mgr,
		EventSource: ring,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Poll once over an empty time window. The function
	// should return nil (no error) and update the stats
	// without sending any events.
	now := time.Now()
	if err := d.pollOnce(context.Background(), now.Add(-time.Hour), now); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	stats := d.Stats()
	if stats.EventsForwarded != 0 {
		t.Errorf("EventsForwarded = %d, want 0 (empty source)", stats.EventsForwarded)
	}
}

func TestPollOnce_ForwardsEvents(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	// Seed 5 events: 3 of type "proxy_response" at high,
	// 2 of type "anomaly_score" at critical.
	now := time.Now()
	events := []logging.Event{
		{Type: "proxy_response", Severity: logging.SeverityHigh, Time: now.Add(-5 * time.Minute)},
		{Type: "proxy_response", Severity: logging.SeverityHigh, Time: now.Add(-4 * time.Minute)},
		{Type: "proxy_response", Severity: logging.SeverityHigh, Time: now.Add(-3 * time.Minute)},
		{Type: "anomaly_score", Severity: logging.SeverityCritical, Time: now.Add(-2 * time.Minute)},
		{Type: "anomaly_score", Severity: logging.SeverityCritical, Time: now.Add(-1 * time.Minute)},
	}
	ring := newTestRingBuffer(t, events)
	d, err := NewSIEMDispatcher(SIEMDispatcherConfig{
		Manager:     mgr,
		EventSource: ring,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Poll over a window that includes all 5 events.
	if err := d.pollOnce(context.Background(), now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	stats := d.Stats()
	// The dispatcher emits one siem.Event per (type) bucket
	// (the severity is derived from the global bySev rollup,
	// not per-type). So we expect 2 events forwarded (one for
	// proxy_response, one for anomaly_score).
	if stats.EventsForwarded != 2 {
		t.Errorf("EventsForwarded = %d, want 2 (one per type bucket)", stats.EventsForwarded)
	}
	if stats.LastPollTime.IsZero() {
		t.Error("LastPollTime not set")
	}
}

// TestPollOnce_ZeroStartWindow covers the "start is zero"
// guard. Without this guard, the CountBy* methods would
// return all events since the dawn of time, which is
// expensive. The pollOnce function uses a non-zero start
// (the earliest representable time) when the caller passes
// the zero value.
func TestPollOnce_ZeroStartWindow(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	ring := newTestRingBuffer(t, nil)
	d, err := NewSIEMDispatcher(SIEMDispatcherConfig{
		Manager:     mgr,
		EventSource: ring,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Zero start; non-zero end.
	end := time.Now()
	if err := d.pollOnce(context.Background(), time.Time{}, end); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	// Should not panic; should produce no events.
	if got := d.Stats().EventsForwarded; got != 0 {
		t.Errorf("EventsForwarded = %d, want 0", got)
	}
}

// TestPollOnce_ContextNotRespected covers the documented
// behavior: the RingBuffer's CountBy* methods do NOT
// respect context cancellation (the context parameter is
// present only for evidence.EventSource interface
// compatibility). The dispatcher's pollOnce therefore
// does not return an error on a cancelled context, but
// the Run loop's context IS used for the loop's own
// cancellation via the select case on runCtx.Done().
//
// This test is a regression guard: if someone changes the
// RingBuffer to honor context, the dispatcher's pollOnce
// will start returning errors, and this test will catch
// the change. Update the assertion to match the new
// behavior in that case.
func TestPollOnce_ContextNotRespected(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	ring := newTestRingBuffer(t, nil)
	d, err := NewSIEMDispatcher(SIEMDispatcherConfig{
		Manager:     mgr,
		EventSource: ring,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	now := time.Now()
	// The RingBuffer ignores ctx, so pollOnce succeeds.
	if err := d.pollOnce(ctx, now.Add(-time.Hour), now); err != nil {
		t.Errorf("pollOnce on cancelled context: got error %v, want nil (RingBuffer ignores ctx)", err)
	}
}

// --------------------------------------------------------------------
// Run / Stop
// --------------------------------------------------------------------

func TestSIEMDispatcher_StartStop(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	ring := newTestRingBuffer(t, nil)
	d, err := NewSIEMDispatcher(SIEMDispatcherConfig{
		Manager:      mgr,
		EventSource:  ring,
		PollInterval: 50 * time.Millisecond, // fast poll
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runErr error
	var runWg sync.WaitGroup
	runWg.Add(1)
	go func() {
		defer runWg.Done()
		runErr = d.Run(ctx)
	}()
	// Let the poll loop run a few times.
	time.Sleep(200 * time.Millisecond)
	d.Stop()
	runWg.Wait()
	if runErr != context.Canceled {
		t.Errorf("Run returned %v, want context.Canceled", runErr)
	}
}

func TestSIEMDispatcher_RunTwiceIsError(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	ring := newTestRingBuffer(t, nil)
	d, err := NewSIEMDispatcher(SIEMDispatcherConfig{
		Manager:      mgr,
		EventSource:  ring,
		PollInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var firstErr error
	var firstWg sync.WaitGroup
	firstWg.Add(1)
	go func() {
		defer firstWg.Done()
		firstErr = d.Run(ctx)
	}()
	// Wait for the first Run to actually start.
	time.Sleep(50 * time.Millisecond)
	// Try to start a second Run; should return error.
	if err := d.Run(ctx); err == nil {
		t.Error("expected error on second Run, got nil")
	}
	cancel()
	firstWg.Wait()
	_ = firstErr
}

// TestSIEMDispatcher_StopIsIdempotent verifies that Stop can
// be called multiple times without panicking.
func TestSIEMDispatcher_StopIsIdempotent(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	ring := newTestRingBuffer(t, nil)
	d, err := NewSIEMDispatcher(SIEMDispatcherConfig{
		Manager:     mgr,
		EventSource: ring,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = d.Run(ctx)
	}()
	time.Sleep(50 * time.Millisecond)
	d.Stop()
	d.Stop() // second call: should be safe
	wg.Wait()
}

// --------------------------------------------------------------------
// Helpers (loggingEventToSIEM, pickHighestSeverity,
// loggingToSIEMSeverity)
// --------------------------------------------------------------------

func TestLoggingEventToSIEM(t *testing.T) {
	t.Parallel()
	ts := time.Now()
	evt := loggingEventToSIEM("aegisgate", "proxy_response", siem.SeverityHigh, 42, ts)
	if evt.Source != "aegisgate" {
		t.Errorf("Source = %q, want aegisgate", evt.Source)
	}
	if evt.Type != "proxy_response" {
		t.Errorf("Type = %q, want proxy_response", evt.Type)
	}
	if evt.Severity != siem.SeverityHigh {
		t.Errorf("Severity = %q, want high", evt.Severity)
	}
	if evt.Attributes["count"] != "42" {
		t.Errorf("count attribute = %q, want 42", evt.Attributes["count"])
	}
	if evt.Category != siem.CategoryAudit {
		t.Errorf("Category = %q, want audit", evt.Category)
	}
	if evt.Message == "" {
		t.Error("Message empty")
	}
}

func TestPickHighestSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   map[siem.Severity]int
		want siem.Severity
	}{
		{
			name: "critical wins",
			in:   map[siem.Severity]int{siem.SeverityLow: 5, siem.SeverityCritical: 1, siem.SeverityHigh: 3},
			want: siem.SeverityCritical,
		},
		{
			name: "high wins over medium/low/info",
			in:   map[siem.Severity]int{siem.SeverityInfo: 10, siem.SeverityMedium: 5, siem.SeverityHigh: 2},
			want: siem.SeverityHigh,
		},
		{
			name: "empty map -> info",
			in:   map[siem.Severity]int{},
			want: siem.SeverityInfo,
		},
		{
			name: "all zero -> info (no positives)",
			in:   map[siem.Severity]int{siem.SeverityHigh: 0, siem.SeverityLow: 0},
			want: siem.SeverityInfo,
		},
		{
			name: "fallback: any non-zero",
			in:   map[siem.Severity]int{siem.Severity("custom"): 5},
			want: siem.Severity("custom"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pickHighestSeverity(tc.in)
			if got != tc.want {
				t.Errorf("pickHighestSeverity = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoggingToSIEMSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   logging.Severity
		want siem.Severity
	}{
		{logging.SeverityCritical, siem.SeverityCritical},
		{logging.SeverityHigh, siem.SeverityHigh},
		{logging.SeverityMedium, siem.SeverityMedium},
		{logging.SeverityLow, siem.SeverityLow},
		{logging.SeverityInfo, siem.SeverityInfo},
		{logging.Severity("unknown"), siem.SeverityInfo},
		{logging.Severity(""), siem.SeverityInfo},
	}
	for _, tc := range cases {
		got := loggingToSIEMSeverity(tc.in)
		if got != tc.want {
			t.Errorf("loggingToSIEMSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------
// Stats
// --------------------------------------------------------------------

func TestSIEMDispatcher_StatsInitial(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	ring := newTestRingBuffer(t, nil)
	d, err := NewSIEMDispatcher(SIEMDispatcherConfig{
		Manager:     mgr,
		EventSource: ring,
	})
	if err != nil {
		t.Fatal(err)
	}
	stats := d.Stats()
	if stats.EventsPolled != 0 {
		t.Errorf("EventsPolled = %d, want 0", stats.EventsPolled)
	}
	if stats.EventsForwarded != 0 {
		t.Errorf("EventsForwarded = %d, want 0", stats.EventsForwarded)
	}
	if stats.EventsDropped != 0 {
		t.Errorf("EventsDropped = %d, want 0", stats.EventsDropped)
	}
}
