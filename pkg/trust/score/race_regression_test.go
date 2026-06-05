// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Race regression test for trust/score baseline access
//
// v3.2.0 Phase 8: This test pins the contract that GetBaseline returns a
// snapshot of BaselineMetrics that is safe to read WITHOUT holding the
// baseline engine's mutex. Prior to the Phase 8 fix, GetBaseline returned
// a pointer to the same struct stored in the internal map; concurrent
// RecordEvent calls (which mutate the struct in place) raced with
// Calculate's reads.

package score

import (
	"context"
	"sync"
	"testing"
)

// TestGetBaseline_ReturnsCopyNotPointer is a focused regression test for
// the Phase 8 race fix. It verifies that mutating the returned pointer
// does not affect the engine's internal state — i.e., GetBaseline
// returns a value copy wrapped in a pointer, not a pointer to the
// internal map entry.
func TestGetBaseline_ReturnsCopyNotPointer(t *testing.T) {
	engine := NewBaselineEngine(100)

	// Seed with one event so the baseline exists in the map.
	err := engine.RecordEvent(context.Background(), &BehaviorEvent{
		ID:      "evt-1",
		AgentID: "agent-x",
		Type:    EventCapabilityAllowed,
	})
	if err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	// Get the baseline (caller's copy).
	baseline, err := engine.GetBaseline(context.Background(), "agent-x")
	if err != nil {
		t.Fatalf("GetBaseline: %v", err)
	}
	if baseline == nil {
		t.Fatal("GetBaseline returned nil")
	}
	if baseline.TotalEvents != 1 {
		t.Fatalf("expected TotalEvents=1, got %d", baseline.TotalEvents)
	}

	// Mutate the caller's copy. This MUST NOT affect the engine's
	// internal state. If GetBaseline returned a pointer to the internal
	// map entry, this would corrupt the engine.
	baseline.TotalEvents = 9999
	baseline.SuccessRate = -1.0

	// Record another event. The engine's internal state should still
	// track from 1 (not 9999) because the previous mutation was local.
	err = engine.RecordEvent(context.Background(), &BehaviorEvent{
		ID:      "evt-2",
		AgentID: "agent-x",
		Type:    EventCapabilityAllowed,
	})
	if err != nil {
		t.Fatalf("RecordEvent 2: %v", err)
	}

	// Get the baseline fresh. TotalEvents should be 2 (one initial + one
	// new), proving the engine's internal state was not corrupted by
	// the caller's earlier mutation.
	fresh, err := engine.GetBaseline(context.Background(), "agent-x")
	if err != nil {
		t.Fatalf("GetBaseline (fresh): %v", err)
	}
	if fresh.TotalEvents != 2 {
		t.Errorf("engine state was corrupted by caller mutation: TotalEvents=%d, want 2", fresh.TotalEvents)
	}
	if fresh.SuccessRate != 1.0 {
		t.Errorf("SuccessRate wrong: got %f, want 1.0 (both events allowed)", fresh.SuccessRate)
	}
}

// TestGetBaseline_ConcurrentReadAndWrite exercises the exact race that
// Phase 8 fixes: one goroutine reading baselines in a tight loop while
// another goroutine writes events. Run with `go test -race`. The test
// itself does not assert a specific value; the race detector will fail
// the test if GetBaseline does not return a snapshot copy.
func TestGetBaseline_ConcurrentReadAndWrite(t *testing.T) {
	engine := NewBaselineEngine(1000)

	// Seed the engine so the baseline exists.
	err := engine.RecordEvent(context.Background(), &BehaviorEvent{
		ID:      "evt-seed",
		AgentID: "agent-y",
		Type:    EventCapabilityAllowed,
	})
	if err != nil {
		t.Fatalf("RecordEvent seed: %v", err)
	}

	const writeCount = 500
	var readerWG sync.WaitGroup
	var writerWG sync.WaitGroup

	// Reader goroutine: calls GetBaseline repeatedly for the entire
	// duration of the writer's run.
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for i := 0; i < writeCount*4; i++ {
			baseline, err := engine.GetBaseline(context.Background(), "agent-y")
			if err != nil {
				t.Errorf("GetBaseline: %v", err)
				return
			}
			// Read several fields. With the bug, this would race with
			// the writer's struct mutation.
			_ = baseline.TotalEvents
			_ = baseline.SuccessRate
			_ = baseline.AllowedCount
		}
	}()

	// Writer goroutine: records events.
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for i := 0; i < writeCount; i++ {
			err := engine.RecordEvent(context.Background(), &BehaviorEvent{
				ID:      "evt-" + string(rune('a'+i%26)),
				AgentID: "agent-y",
				Type:    EventCapabilityAllowed,
			})
			if err != nil {
				t.Errorf("RecordEvent: %v", err)
				return
			}
		}
	}()

	// Wait for both to finish.
	writerWG.Wait()
	readerWG.Wait()
}
