// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Tier 1 (TODO-401) IOC <-> FrameworkRefCache integration
//
// framework_refs_integration_test.go verifies the end-to-end flow
// from logging.Record() (which populates Event.FrameworkRefs) through
// the IOC Producer (the platform's global recorder) and into the
// IOC Store + a test-side recorder that captures the events the
// Producer fans out to. This is the "every IOC event gets
// cross-framework context" wire-up that the user requested in
// TODO-401.
//
// The test is in package ioc (white-box) so it can inspect the
// Producer's unexported inner recorder via a test-side shim that
// implements logging.Recorder. It uses a deterministic custom seed
// rather than the default table so the assertions do not depend on
// the default seed's contents evolving.

package ioc

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// testSeedFn returns a Seed function with the given entries. The
// counter is incremented on every call and is useful for asserting
// that the cache was consulted (or not) the expected number of
// times.
func testSeedFn(entries []logging.FrameworkRefEntry, counter *int64) func() ([]logging.FrameworkRefEntry, error) {
	return func() ([]logging.FrameworkRefEntry, error) {
		if counter != nil {
			atomic.AddInt64(counter, 1)
		}
		out := make([]logging.FrameworkRefEntry, len(entries))
		copy(out, entries)
		return out, nil
	}
}

// installFrameworkRefCache is a white-box helper that installs a
// FrameworkRefCache with a custom seed as the process-wide global,
// then registers a t.Cleanup to restore the previous state. It
// returns the *int64 counter that is incremented on every Seed
// call.
func installFrameworkRefCache(t *testing.T, entries []logging.FrameworkRefEntry) *int64 {
	t.Helper()
	var counter int64
	cache := &logging.FrameworkRefCache{}
	if err := cache.Init(logging.FrameworkRefCacheConfig{
		TTL:  1 * time.Hour, // long TTL so the test does not race the ticker
		Seed: testSeedFn(entries, &counter),
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)

	// Save + restore the previous global.
	prev := logging.GetGlobalRefCache()
	logging.SetGlobalRefCache(cache)
	t.Cleanup(func() { logging.SetGlobalRefCache(prev) })

	return &counter
}

// captureRecorder is a logging.Recorder implementation that
// appends every Add() to a slice. It is safe for concurrent use;
// the IOC test suite does not need a ring buffer's overwrite
// semantics for these single-shot integration tests.
type captureRecorder struct {
	mu     sync.Mutex
	events []logging.Event
}

func (c *captureRecorder) Add(e logging.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureRecorder) snapshot() []logging.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]logging.Event, len(c.events))
	copy(out, c.events)
	return out
}

// installProducerAsGlobal installs a Producer wrapping the given
// store as the process-wide logging recorder, with a capture
// recorder as the inner sink. Registers t.Cleanup to restore the
// previous recorder. Returns the Producer and the capture
// recorder (so the test can inspect the events that the Producer's
// fanOut path delivered to it).
func installProducerAsGlobal(t *testing.T, store *Store) (*Producer, *captureRecorder) {
	t.Helper()
	cap := &captureRecorder{}
	producer := NewProducer(ProducerConfig{}, store)
	producer.SetEnabled(true)
	producer.Attach(cap)

	prev := logging.GetDefault()
	logging.SetDefault(producer)
	t.Cleanup(func() { logging.SetDefault(prev) })

	return producer, cap
}

// --------------------------------------------------------------------
// End-to-end: logging.Record() -> Producer -> captureRecorder (and Store)
// --------------------------------------------------------------------

// TestIntegration_RecordEvent_PropagatesFrameworkRefs verifies the
// TODO-401 wire-up: a logged event flows through the global
// recorder (Producer) and arrives at the inner capture recorder
// with its FrameworkRefs field populated.
func TestIntegration_RecordEvent_PropagatesFrameworkRefs(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	producer, cap := installProducerAsGlobal(t, store)

	// Custom seed keyed to anomaly_score (the IOC allow-list
	// type) with ThreatType=prompt_injection.
	entries := []logging.FrameworkRefEntry{
		{
			Key: logging.DetectionKey{
				Type:       "anomaly_score",
				ThreatType: "prompt_injection",
				Pattern:    "DAN",
			},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0051"},
				"owasp_llm":   {"LLM01"},
				"cwe":         {"CWE-1427"},
			},
		},
	}
	seedCounter := installFrameworkRefCache(t, entries)

	// Record an event through the public API. This is the same
	// path subsystems (HTTP proxy, MCP, A2A, etc.) use.
	logging.Record(logging.Event{
		Type:       "anomaly_score",
		Severity:   logging.SeverityHigh,
		ThreatType: "prompt_injection",
		Pattern:    "DAN",
		Message:    "jailbreak attempt",
	})

	// The seed was consulted at least once (Init calls it
	// synchronously).
	if c := atomic.LoadInt64(seedCounter); c < 1 {
		t.Errorf("seed called %d times, want >= 1", c)
	}

	// The Producer's stats should show the event was processed.
	stats := producer.Stats()
	if stats.EventsObserved != 1 {
		t.Errorf("EventsObserved = %d, want 1", stats.EventsObserved)
	}
	if stats.EventsRecorded != 1 {
		t.Errorf("EventsRecorded = %d, want 1", stats.EventsRecorded)
	}
	if stats.EventsRejected != 0 {
		t.Errorf("EventsRejected = %d, want 0", stats.EventsRejected)
	}

	// The IOC store received the detection.
	if store.Size() != 1 {
		t.Errorf("IOC store size = %d, want 1", store.Size())
	}

	// The inner capture recorder received the event with
	// FrameworkRefs populated. This is the TODO-401 assertion.
	events := cap.snapshot()
	if len(events) != 1 {
		t.Fatalf("captured events = %d, want 1", len(events))
	}
	refs := events[0].FrameworkRefs
	if len(refs) != 3 {
		t.Fatalf("Event.FrameworkRefs = %#v, want 3 entries", refs)
	}
	if ids := refs["mitre_atlas"]; len(ids) != 1 || ids[0] != "AML.T0051" {
		t.Errorf("mitre_atlas = %v, want [AML.T0051]", ids)
	}
	if ids := refs["owasp_llm"]; len(ids) != 1 || ids[0] != "LLM01" {
		t.Errorf("owasp_llm = %v, want [LLM01]", ids)
	}
	if ids := refs["cwe"]; len(ids) != 1 || ids[0] != "CWE-1427" {
		t.Errorf("cwe = %v, want [CWE-1427]", ids)
	}
}

// TestIntegration_RecordEvent_NoCache_LeavesFrameworkRefsEmpty
// verifies the negative case: without a global cache, Record() does
// not panic and FrameworkRefs stays empty.
func TestIntegration_RecordEvent_NoCache_LeavesFrameworkRefsEmpty(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	_, cap := installProducerAsGlobal(t, store)

	// Make sure the global cache is nil.
	prev := logging.GetGlobalRefCache()
	logging.SetGlobalRefCache(nil)
	t.Cleanup(func() { logging.SetGlobalRefCache(prev) })

	logging.Record(logging.Event{
		Type:       "anomaly_score",
		Severity:   logging.SeverityHigh,
		ThreatType: "prompt_injection",
		Pattern:    "DAN",
		Message:    "jailbreak attempt",
	})

	events := cap.snapshot()
	if len(events) != 1 {
		t.Fatalf("captured events = %d, want 1", len(events))
	}
	if len(events[0].FrameworkRefs) != 0 {
		t.Errorf("Event.FrameworkRefs = %v, want empty (no global cache)", events[0].FrameworkRefs)
	}
}

// TestIntegration_RecordEvent_UnknownDetection_LeavesFrameworkRefsEmpty
// verifies that a detection tuple with no seed entry produces an
// empty (non-nil) FrameworkRefs map (not a panic, not a partial).
func TestIntegration_RecordEvent_UnknownDetection_LeavesFrameworkRefsEmpty(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	_, cap := installProducerAsGlobal(t, store)

	// Seed has only one entry; we record a different tuple.
	entries := []logging.FrameworkRefEntry{
		{
			Key: logging.DetectionKey{
				Type:       "anomaly_score",
				ThreatType: "prompt_injection",
				Pattern:    "DAN",
			},
			Refs: map[string][]string{
				"owasp_llm": {"LLM01"},
			},
		},
	}
	installFrameworkRefCache(t, entries)

	logging.Record(logging.Event{
		Type:       "anomaly_score", // matches
		Severity:   logging.SeverityHigh,
		ThreatType: "jailbreak", // does NOT match
		Pattern:    "unknown",   // does NOT match
		Message:    "no mapping",
	})

	events := cap.snapshot()
	if len(events) != 1 {
		t.Fatalf("captured events = %d, want 1", len(events))
	}
	if len(events[0].FrameworkRefs) != 0 {
		t.Errorf("Event.FrameworkRefs = %v, want empty (no seed hit)", events[0].FrameworkRefs)
	}
}
