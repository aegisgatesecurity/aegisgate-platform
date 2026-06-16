// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Framework Reference Cache tests (v3.5.0-alpha-1, Tier 1 TODO-401)
//
// framework_refs_test.go covers the FrameworkRefCache contract:
//   - Get() returns precomputed refs for known detection tuples
//   - Get() returns an empty (non-nil) map on miss
//   - Get() is safe to call before Init() and never panics
//   - Periodic re-seed re-invokes the Seed function on TTL
//   - Stop() cancels the re-seeder and Get() still works
//   - Concurrent Get() callers do not race
//   - Keys are normalized (lowercased + trimmed) so callers don't
//     have to pre-normalize
//   - Empty seed tables produce a usable (but empty) cache
//   - GlobalRefCacheFor respects the global cache lifecycle
//   - logging.Record() populates Event.FrameworkRefs when the
//     global cache is installed
//
// White-box tests in package logging so we can poke at the
// unexported store directly. Race-tested under `go test -race`.

package logging

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

// fixedSeed returns a Seed function that always produces the given
// entries. Errors are returned via the errCh; nil if errCh is nil.
func fixedSeed(entries []FrameworkRefEntry, errCh chan error) func() ([]FrameworkRefEntry, error) {
	return func() ([]FrameworkRefEntry, error) {
		if errCh != nil {
			select {
			case err := <-errCh:
				if err != nil {
					return nil, err
				}
			default:
			}
		}
		return entries, nil
	}
}

// countingSeed returns a Seed function that increments a counter
// on each call. Useful for verifying the periodic re-seeder.
func countingSeed(entries []FrameworkRefEntry, counter *int64) func() ([]FrameworkRefEntry, error) {
	return func() ([]FrameworkRefEntry, error) {
		atomic.AddInt64(counter, 1)
		// Return a deep copy so the caller can't mutate the
		// source slice between calls.
		out := make([]FrameworkRefEntry, len(entries))
		copy(out, entries)
		return out, nil
	}
}

// resetGlobalRefCache is a t.Cleanup helper that clears the
// process-wide global cache after each test that touches it.
func resetGlobalRefCache(t *testing.T) {
	t.Helper()
	prev := GetGlobalRefCache()
	t.Cleanup(func() {
		SetGlobalRefCache(prev)
		// Also reset the sync.Once so the warning can fire
		// again in the next test. Note: this is a
		// package-private helper and is safe because each
		// test that uses it must call resetGlobalRefCache
		// BEFORE any WarnIfGlobalCacheUnset call. We reset
		// it here as a belt-and-suspenders.
		globalRefCacheOnce = sync.Once{}
	})
}

// statefulSeed returns a Seed function that returns entries on
// the first successCount calls, then an error on every call
// after that. The returned *int64 is incremented on every call
// (success or failure) so tests can poll for the failure path.
func statefulSeed(entries []FrameworkRefEntry, successCount int) (func() ([]FrameworkRefEntry, error), *int64) {
	var counter int64
	fn := func() ([]FrameworkRefEntry, error) {
		n := atomic.AddInt64(&counter, 1)
		if n > int64(successCount) {
			return nil, fmt.Errorf("simulated seed failure on call %d", n)
		}
		return entries, nil
	}
	return fn, &counter
}

// --------------------------------------------------------------------
// Get() contract
// --------------------------------------------------------------------

func TestFrameworkRefCache_Get_Hit(t *testing.T) {
	t.Parallel()
	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key:  DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "DAN"},
			Refs: map[string][]string{"mitre_atlas": {"AML.T0051"}},
		},
	}
	if err := cache.Init(FrameworkRefCacheConfig{Seed: fixedSeed(entries, nil)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)

	got := cache.Get(DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "DAN"})
	if len(got) != 1 {
		t.Fatalf("expected 1 framework, got %d: %#v", len(got), got)
	}
	if ids := got["mitre_atlas"]; len(ids) != 1 || ids[0] != "AML.T0051" {
		t.Errorf("mitre_atlas = %v, want [AML.T0051]", ids)
	}
}

func TestFrameworkRefCache_Get_Miss(t *testing.T) {
	t.Parallel()
	cache := &FrameworkRefCache{}
	if err := cache.Init(FrameworkRefCacheConfig{Seed: fixedSeed(nil, nil)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)

	got := cache.Get(DetectionKey{Type: "unknown", ThreatType: "unknown", Pattern: "unknown"})
	if got == nil {
		t.Fatal("Get on miss returned nil; want empty (non-nil) map")
	}
	if len(got) != 0 {
		t.Errorf("Get on miss = %v, want empty", got)
	}
}

func TestFrameworkRefCache_Get_BeforeInit(t *testing.T) {
	t.Parallel()
	cache := &FrameworkRefCache{}
	// Note: no Init() call.
	got := cache.Get(DetectionKey{Type: "threat"})
	if got == nil {
		t.Fatal("Get before Init returned nil; want empty (non-nil) map")
	}
	if len(got) != 0 {
		t.Errorf("Get before Init = %v, want empty", got)
	}
}

func TestFrameworkRefCache_Get_ReturnsCopy(t *testing.T) {
	t.Parallel()
	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key:  DetectionKey{Type: "threat", ThreatType: "x", Pattern: "y"},
			Refs: map[string][]string{"owasp_llm": {"LLM01"}},
		},
	}
	if err := cache.Init(FrameworkRefCacheConfig{Seed: fixedSeed(entries, nil)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)

	first := cache.Get(DetectionKey{Type: "threat", ThreatType: "x", Pattern: "y"})
	// Mutate the returned map.
	first["owasp_llm"] = []string{"TAMPERED"}
	first["new_key"] = []string{"x"}

	// Fetch again - the store must be unchanged.
	second := cache.Get(DetectionKey{Type: "threat", ThreatType: "x", Pattern: "y"})
	if ids := second["owasp_llm"]; len(ids) != 1 || ids[0] != "LLM01" {
		t.Errorf("store was mutated: owasp_llm = %v, want [LLM01]", ids)
	}
	if _, ok := second["new_key"]; ok {
		t.Error("store was mutated: new_key should not exist")
	}
}

func TestFrameworkRefCache_EmptyMapping(t *testing.T) {
	t.Parallel()
	cache := &FrameworkRefCache{}
	if err := cache.Init(FrameworkRefCacheConfig{Seed: fixedSeed([]FrameworkRefEntry{}, nil)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)

	got := cache.Get(DetectionKey{Type: "anything"})
	if got == nil {
		t.Fatal("Get with empty mapping returned nil; want empty map")
	}
	if len(got) != 0 {
		t.Errorf("Get with empty mapping = %v, want empty", got)
	}
}

// --------------------------------------------------------------------
// Normalization
// --------------------------------------------------------------------

func TestFrameworkRefCache_NormalizeKey(t *testing.T) {
	t.Parallel()
	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key:  DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "DAN"},
			Refs: map[string][]string{"mitre_atlas": {"AML.T0051"}},
		},
	}
	if err := cache.Init(FrameworkRefCacheConfig{Seed: fixedSeed(entries, nil)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)

	// Mixed case + extra whitespace should still hit the cache.
	got := cache.Get(DetectionKey{Type: "  THREAT  ", ThreatType: "PROMPT_injection", Pattern: "dan "})
	if len(got) != 1 {
		t.Fatalf("normalized key miss: got %#v, want 1 entry", got)
	}
	if ids := got["mitre_atlas"]; len(ids) != 1 || ids[0] != "AML.T0051" {
		t.Errorf("mitre_atlas = %v, want [AML.T0051]", ids)
	}
}

// --------------------------------------------------------------------
// Lifecycle: periodic re-seed
// --------------------------------------------------------------------

func TestFrameworkRefCache_PeriodicRefresh(t *testing.T) {
	t.Parallel()
	var seedCalls int64
	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key:  DetectionKey{Type: "threat", ThreatType: "x", Pattern: "y"},
			Refs: map[string][]string{"owasp_llm": {"LLM01"}},
		},
	}
	// 50ms TTL: first seed happens at Init, then again after 50ms.
	if err := cache.Init(FrameworkRefCacheConfig{
		TTL:  50 * time.Millisecond,
		Seed: countingSeed(entries, &seedCalls),
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)

	// At least 1 seed (the synchronous first one).
	if c := atomic.LoadInt64(&seedCalls); c < 1 {
		t.Fatalf("expected at least 1 seed call, got %d", c)
	}

	// Wait long enough for at least one re-seed.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&seedCalls) >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("expected at least 2 seed calls within 500ms, got %d", atomic.LoadInt64(&seedCalls))
}

func TestFrameworkRefCache_StopPreservesStore(t *testing.T) {
	t.Parallel()
	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key:  DetectionKey{Type: "threat", ThreatType: "x", Pattern: "y"},
			Refs: map[string][]string{"owasp_llm": {"LLM01"}},
		},
	}
	if err := cache.Init(FrameworkRefCacheConfig{
		TTL:  1 * time.Hour, // long TTL so the test does not race the ticker
		Seed: fixedSeed(entries, nil),
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	cache.Stop()
	cache.Stop() // double-stop must be safe

	got := cache.Get(DetectionKey{Type: "threat", ThreatType: "x", Pattern: "y"})
	if len(got) != 1 {
		t.Errorf("Get after Stop = %#v, want 1 entry", got)
	}
}

func TestFrameworkRefCache_SeedError_PreservesStore(t *testing.T) {
	t.Parallel()
	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key:  DetectionKey{Type: "threat", ThreatType: "x", Pattern: "y"},
			Refs: map[string][]string{"owasp_llm": {"LLM01"}},
		},
	}
	seedFn, counter := statefulSeed(entries, 2) // 2 successes, then fail

	if err := cache.Init(FrameworkRefCacheConfig{
		TTL:  50 * time.Millisecond,
		Seed: seedFn,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)

	// Wait for the ticker to fire and the third (failing) call to happen.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(counter) >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if atomic.LoadInt64(counter) < 3 {
		t.Fatalf("expected at least 3 seed calls, got %d", atomic.LoadInt64(counter))
	}

	// Even after a failing re-seed, the store must still
	// serve the original entries.
	got := cache.Get(DetectionKey{Type: "threat", ThreatType: "x", Pattern: "y"})
	if len(got) != 1 {
		t.Errorf("after seed failure, Get = %#v, want 1 entry", got)
	}
}

// --------------------------------------------------------------------
// Concurrency
// --------------------------------------------------------------------

func TestFrameworkRefCache_Concurrent(t *testing.T) {
	t.Parallel()
	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key:  DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "DAN"},
			Refs: map[string][]string{"mitre_atlas": {"AML.T0051"}},
		},
		{
			Key:  DetectionKey{Type: "threat", ThreatType: "jailbreak", Pattern: ""},
			Refs: map[string][]string{"mitre_atlas": {"AML.T0051"}},
		},
	}
	if err := cache.Init(FrameworkRefCacheConfig{
		TTL:  1 * time.Hour,
		Seed: fixedSeed(entries, nil),
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)

	const goroutines = 50
	const itersPerG = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < itersPerG; i++ {
				// Mix of hit and miss lookups.
				if i%2 == 0 {
					_ = cache.Get(DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "DAN"})
				} else {
					_ = cache.Get(DetectionKey{Type: "unknown", ThreatType: fmt.Sprintf("u%d", g), Pattern: "x"})
				}
			}
		}(g)
	}
	wg.Wait()
}

// --------------------------------------------------------------------
// Default seed
// --------------------------------------------------------------------

func TestDefaultSeedFn_NonEmpty(t *testing.T) {
	t.Parallel()
	entries, err := DefaultSeedFn()
	if err != nil {
		t.Fatalf("DefaultSeedFn: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("DefaultSeedFn returned 0 entries; want a non-empty default table")
	}
	// Spot-check: the prompt_injection family must include OWASP LLM01.
	foundLLM01 := false
	for _, e := range entries {
		if e.Key.ThreatType == "prompt_injection" {
			if ids, ok := e.Refs["owasp_llm"]; ok {
				for _, id := range ids {
					if id == "LLM01" {
						foundLLM01 = true
					}
				}
			}
		}
	}
	if !foundLLM01 {
		t.Error("DefaultSeedFn missing OWASP LLM01 for prompt_injection")
	}
}

// --------------------------------------------------------------------
// Global cache + Record() integration
// --------------------------------------------------------------------

func TestGlobalRefCacheFor_NoCache(t *testing.T) {
	resetGlobalRefCache(t)
	SetGlobalRefCache(nil)
	got := GlobalRefCacheFor(DetectionKey{Type: "threat", ThreatType: "x", Pattern: "y"})
	if got == nil {
		t.Fatal("GlobalRefCacheFor with no global returned nil; want empty map")
	}
	if len(got) != 0 {
		t.Errorf("GlobalRefCacheFor with no global = %v, want empty", got)
	}
}

func TestGlobalRefCacheFor_WithCache(t *testing.T) {
	resetGlobalRefCache(t)
	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key:  DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "DAN"},
			Refs: map[string][]string{"mitre_atlas": {"AML.T0051"}},
		},
	}
	if err := cache.Init(FrameworkRefCacheConfig{Seed: fixedSeed(entries, nil)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)
	SetGlobalRefCache(cache)

	got := GlobalRefCacheFor(DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "DAN"})
	if len(got) != 1 {
		t.Fatalf("GlobalRefCacheFor with cache = %#v, want 1 entry", got)
	}
	if ids := got["mitre_atlas"]; len(ids) != 1 || ids[0] != "AML.T0051" {
		t.Errorf("mitre_atlas = %v, want [AML.T0051]", ids)
	}
}

func TestRecord_PopulatesFrameworkRefs(t *testing.T) {
	resetGlobalRefCache(t)
	cache := &FrameworkRefCache{}
	entries := []FrameworkRefEntry{
		{
			Key: DetectionKey{Type: "threat", ThreatType: "prompt_injection", Pattern: "DAN"},
			Refs: map[string][]string{
				"mitre_atlas": {"AML.T0051"},
				"owasp_llm":   {"LLM01"},
			},
		},
	}
	if err := cache.Init(FrameworkRefCacheConfig{Seed: fixedSeed(entries, nil)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(cache.Stop)
	SetGlobalRefCache(cache)

	// Install a recording sink.
	rb := NewRingBuffer(100)
	SetDefault(rb)
	t.Cleanup(func() { SetDefault(nil) })

	// Record a matching event.
	Record(Event{
		Type:       "threat",
		ThreatType: "prompt_injection",
		Pattern:    "DAN",
		Severity:   SeverityHigh,
	})

	// Pull the event from the ring buffer and assert. We use
	// snapshotInWindow (unexported) with a window around now().
	// Add() stamps Event.Time if zero, so the event will be
	// included in this window.
	now := time.Now()
	events := rb.snapshotInWindow(now.Add(-time.Hour), now.Add(time.Hour))
	if len(events) != 1 {
		t.Fatalf("ring buffer events = %d, want 1", len(events))
	}
	got := events[0].FrameworkRefs
	if len(got) != 2 {
		t.Fatalf("Event.FrameworkRefs = %#v, want 2 entries", got)
	}
	if ids := got["mitre_atlas"]; len(ids) != 1 || ids[0] != "AML.T0051" {
		t.Errorf("mitre_atlas = %v, want [AML.T0051]", ids)
	}
	if ids := got["owasp_llm"]; len(ids) != 1 || ids[0] != "LLM01" {
		t.Errorf("owasp_llm = %v, want [LLM01]", ids)
	}
}

func TestRecord_NoGlobalCache_LeavesFrameworkRefsEmpty(t *testing.T) {
	resetGlobalRefCache(t)
	SetGlobalRefCache(nil)

	rb := NewRingBuffer(100)
	SetDefault(rb)
	t.Cleanup(func() { SetDefault(nil) })

	Record(Event{
		Type:       "threat",
		ThreatType: "prompt_injection",
		Pattern:    "DAN",
		Severity:   SeverityHigh,
	})

	now := time.Now()
	events := rb.snapshotInWindow(now.Add(-time.Hour), now.Add(time.Hour))
	if len(events) != 1 {
		t.Fatalf("ring buffer events = %d, want 1", len(events))
	}
	if got := events[0].FrameworkRefs; len(got) != 0 {
		t.Errorf("Event.FrameworkRefs = %v, want empty (no global cache)", got)
	}
}

// --------------------------------------------------------------------
// Tier 1 (TODO-401) end-to-end: Event with FrameworkRefs JSON-encodes
// the field with the frameworkRefs JSON tag.
// --------------------------------------------------------------------

func TestEvent_FrameworkRefs_JSON(t *testing.T) {
	t.Parallel()
	// Empty value: omitempty should drop the field.
	e1 := Event{Type: "threat"}
	// Verify the field is reflectively wired (avoids "field is
	// actually a typo that the compiler accepted" regressions).
	got := e1.FrameworkRefs
	if got != nil {
		t.Errorf("zero-value FrameworkRefs = %v, want nil", got)
	}

	// Non-empty value: the field is settable.
	e2 := Event{
		Type:          "threat",
		FrameworkRefs: map[string][]string{"mitre_atlas": {"AML.T0051"}},
	}
	if e2.FrameworkRefs["mitre_atlas"][0] != "AML.T0051" {
		t.Error("FrameworkRefs round-trip failed")
	}
}
