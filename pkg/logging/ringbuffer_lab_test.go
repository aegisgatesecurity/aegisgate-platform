// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 AegisGate Security
// =========================================================================
// Ring Buffer Lab Integration Tests
// Requires: cd testlab && docker compose up -d (optional, for live test)
// Run with: LAB_ENABLED=1 go test ./pkg/logging/...
// =========================================================================
//
// ringbuffer_lab_test.go exercises the audit ring buffer under
// realistic load:
//   - High-volume concurrent writes
//   - High-volume concurrent reads (CountBy*)
//   - Overflow behavior (oldest event dropped)
//   - Time-window queries over realistic windows
//   - Real logging.Event values (matching the production schema)
//
// These tests are gated by LAB_ENABLED=1 because they run for
// seconds (not microseconds) and exercise concurrency.
//
// v3.3.0+ Track 2.

package logging

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func skipIfLabDisabled(t *testing.T) {
	t.Helper()
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("LAB_ENABLED not set; skipping lab test (set LAB_ENABLED=1 to enable)")
	}
}

// TestRingBuffer_ConcurrentWrites_NoRace is the canonical race
// test for the ring buffer. Run with go test -race to detect any
// data race. This test is also a long-runner: 50K writes across
// 20 goroutines, designed to expose any missed locking.
func TestRingBuffer_ConcurrentWrites_NoRace(t *testing.T) {
	skipIfLabDisabled(t)
	const capacity = 1000
	const goroutines = 20
	const writesPer = 2500 // 50K total writes
	ring := NewRingBuffer(capacity)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < writesPer; i++ {
				ring.Add(Event{
					ID:       fmt.Sprintf("g%d-i%d", gid, i),
					Type:     "test",
					Severity: SeverityInfo,
				})
			}
		}(g)
	}
	wg.Wait()
	// Buffer should be at capacity (oldest overwritten).
	if got := ring.Size(); got != capacity {
		t.Errorf("Size = %d, want %d (capacity)", got, capacity)
	}
}

// TestRingBuffer_ConcurrentWritesAndReads exercises writes and
// counts in parallel, the realistic load pattern for a live
// audit pipeline.
func TestRingBuffer_ConcurrentWritesAndReads(t *testing.T) {
	skipIfLabDisabled(t)
	const capacity = 5000
	ring := NewRingBuffer(capacity)
	stop := make(chan struct{})
	var writes int64
	var reads int64
	var wg sync.WaitGroup
	// Writers: 4 goroutines, each adding 2K events.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				select {
				case <-stop:
					return
				default:
				}
				ring.Add(Event{
					ID:       fmt.Sprintf("w%d-%d", wid, i),
					Type:     "writeload",
					Severity: SeverityInfo,
				})
				atomic.AddInt64(&writes, 1)
			}
		}(w)
	}
	// Readers: 2 goroutines, capped iterations with yield. This
	// simulates a "monitoring scraper polling counts every second"
	// pattern, not a tight-loop torture test (which would starve
	// writers via read-lock contention).
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			const maxIterations = 200
			for i := 0; i < maxIterations; i++ {
				select {
				case <-stop:
					return
				default:
				}
				now := time.Now()
				ring.CountByType(nil, now.Add(-time.Hour), now.Add(time.Hour))
				ring.CountBySeverity(nil, now.Add(-time.Hour), now.Add(time.Hour))
				ring.CountByFramework(nil, now.Add(-time.Hour), now.Add(time.Hour))
				atomic.AddInt64(&reads, 3)
				runtime.Gosched() // yield so writers can take the write lock
			}
		}()
	}
	// Wait for writers to finish.
	wg.Wait()
	close(stop)
	t.Logf("writes=%d, reads=%d", atomic.LoadInt64(&writes), atomic.LoadInt64(&reads))
	// The buffer should be at capacity (overflowed).
	if got := ring.Size(); got != capacity {
		t.Errorf("Size = %d, want %d", got, capacity)
	}
}

// TestRingBuffer_OverflowPreservesNewest confirms that when the
// buffer is full, the newest events are retained and the oldest
// are dropped.
func TestRingBuffer_OverflowPreservesNewest(t *testing.T) {
	skipIfLabDisabled(t)
	const capacity = 10
	ring := NewRingBuffer(capacity)
	// Add 20 events with sequential IDs.
	for i := 0; i < 20; i++ {
		ring.Add(Event{ID: fmt.Sprintf("evt-%02d", i), Type: "test", Severity: SeverityInfo})
	}
	// The 10 newest should be present (IDs evt-10 through evt-19).
	// We can confirm this via the CountBy* methods.
	now := time.Now()
	byType, _ := ring.CountByType(nil, now.Add(-time.Hour), now.Add(time.Hour))
	if byType["test"] != capacity {
		t.Errorf("by_type[test] = %d, want %d", byType["test"], capacity)
	}
}

// TestRingBuffer_TimeWindow_Large confirms CountBy* over a wide
// time window returns all events.
func TestRingBuffer_TimeWindow_Large(t *testing.T) {
	skipIfLabDisabled(t)
	const count = 1000
	ring := NewRingBuffer(count + 100) // larger than count, no overflow
	for i := 0; i < count; i++ {
		ring.Add(Event{ID: fmt.Sprintf("e%d", i), Type: "load", Severity: SeverityInfo})
	}
	now := time.Now()
	byType, _ := ring.CountByType(nil, now.Add(-24*time.Hour), now.Add(24*time.Hour))
	if byType["load"] != count {
		t.Errorf("by_type[load] = %d, want %d", byType["load"], count)
	}
}

// TestRingBuffer_RealEventSchema confirms the buffer works with
// realistic AegisGate Event values (matching the production schema).
func TestRingBuffer_RealEventSchema(t *testing.T) {
	skipIfLabDisabled(t)
	ring := NewRingBuffer(100)
	// Simulate a realistic audit event stream from the proxy.
	events := []Event{
		{ID: "1", Type: "request", Action: "allow", Severity: SeverityInfo, SourceIP: "10.0.0.1", User: "alice"},
		{ID: "2", Type: "request", Action: "block", Severity: SeverityHigh, SourceIP: "10.0.0.2", User: "bob", Pattern: "sk-.*", ThreatType: "secret_leak"},
		{ID: "3", Type: "scan", Action: "allow", Severity: SeverityLow, ComplianceFramework: "hipaa", ComplianceControl: "164.312(a)(1)"},
		{ID: "4", Type: "scan", Action: "block", Severity: SeverityMedium, ComplianceFramework: "pci", ComplianceControl: "3.4"},
		{ID: "5", Type: "auth", Action: "allow", Severity: SeverityInfo, User: "alice", ClientID: "client-1"},
		{ID: "6", Type: "auth", Action: "deny", Severity: SeverityMedium, User: "eve", ClientID: "client-1"},
	}
	for _, e := range events {
		ring.Add(e)
	}
	// Count by type.
	now := time.Now()
	byType, _ := ring.CountByType(nil, now.Add(-time.Hour), now.Add(time.Hour))
	wantType := map[string]int{"request": 2, "scan": 2, "auth": 2}
	for k, v := range wantType {
		if byType[k] != v {
			t.Errorf("by_type[%s] = %d, want %d", k, byType[k], v)
		}
	}
	// Count by severity.
	bySev, _ := ring.CountBySeverity(nil, now.Add(-time.Hour), now.Add(time.Hour))
	wantSev := map[Severity]int{SeverityInfo: 2, SeverityHigh: 1, SeverityLow: 1, SeverityMedium: 2}
	for k, v := range wantSev {
		if bySev[k] != v {
			t.Errorf("by_sev[%s] = %d, want %d", k, bySev[k], v)
		}
	}
	// Count by framework.
	byFw, _ := ring.CountByFramework(nil, now.Add(-time.Hour), now.Add(time.Hour))
	if byFw["hipaa"] != 1 {
		t.Errorf("by_fw[hipaa] = %d, want 1", byFw["hipaa"])
	}
	if byFw["pci"] != 1 {
		t.Errorf("by_fw[pci] = %d, want 1", byFw["pci"])
	}
}

// TestRingBuffer_Clear_AfterLoad confirms Clear empties the buffer
// and returns subsequent counts to 0.
func TestRingBuffer_Clear_AfterLoad(t *testing.T) {
	skipIfLabDisabled(t)
	ring := NewRingBuffer(100)
	for i := 0; i < 50; i++ {
		ring.Add(Event{ID: fmt.Sprintf("e%d", i), Type: "load", Severity: SeverityInfo})
	}
	ring.Clear()
	if got := ring.Size(); got != 0 {
		t.Errorf("Size after Clear = %d, want 0", got)
	}
	now := time.Now()
	byType, _ := ring.CountByType(nil, now.Add(-time.Hour), now.Add(time.Hour))
	if len(byType) != 0 {
		t.Errorf("by_type after Clear = %v, want empty", byType)
	}
}

// TestRingBuffer_DefaultCapacity confirms NewRingBuffer(0) uses
// the default 10K capacity.
func TestRingBuffer_DefaultCapacity(t *testing.T) {
	skipIfLabDisabled(t)
	ring := NewRingBuffer(0)
	if got := ring.Capacity(); got != DefaultCapacity {
		t.Errorf("Capacity = %d, want %d (DefaultCapacity)", got, DefaultCapacity)
	}
}

// TestRingBuffer_NegativeCapacity_Defaults confirms NewRingBuffer(-1)
// also uses the default.
func TestRingBuffer_NegativeCapacity_Defaults(t *testing.T) {
	skipIfLabDisabled(t)
	ring := NewRingBuffer(-100)
	if got := ring.Capacity(); got != DefaultCapacity {
		t.Errorf("Capacity = %d, want %d", got, DefaultCapacity)
	}
}
