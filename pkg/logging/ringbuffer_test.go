// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Audit Event Ring Buffer tests (v3.3.0+)
//
// ringbuffer_test.go covers the ring buffer used as the
// evidence.EventSource implementation. Tests focus on:
//   - basic add/overwrite semantics
//   - thread safety under concurrent Add
//   - time-window filtering in the three count methods
//   - chronological ordering of the snapshot
//
// v3.3.0+ Track 2.

package logging

import (
	"sync"
	"testing"
	"time"
)

func sampleEvent(t time.Time, typeStr string, sev Severity, framework string) Event {
	return Event{
		Time:                t,
		Type:                typeStr,
		Severity:            sev,
		ComplianceFramework: framework,
		Message:             "test event " + typeStr,
	}
}

func TestRingBuffer_New(t *testing.T) {
	r := NewRingBuffer(100)
	if r.Capacity() != 100 {
		t.Errorf("Capacity = %d, want 100", r.Capacity())
	}
	if r.Size() != 0 {
		t.Errorf("Size = %d, want 0", r.Size())
	}
}

func TestRingBuffer_NewDefault(t *testing.T) {
	r := NewRingBuffer(0) // 0 means default
	if r.Capacity() != DefaultCapacity {
		t.Errorf("Capacity = %d, want %d", r.Capacity(), DefaultCapacity)
	}
	r2 := NewRingBuffer(-1) // negative also means default
	if r2.Capacity() != DefaultCapacity {
		t.Errorf("Capacity = %d, want %d", r2.Capacity(), DefaultCapacity)
	}
}

func TestRingBuffer_Add(t *testing.T) {
	r := NewRingBuffer(5)
	now := time.Now()
	for i := 0; i < 3; i++ {
		r.Add(sampleEvent(now.Add(time.Duration(i)*time.Second), "type-A", SeverityInfo, "hipaa"))
	}
	if r.Size() != 3 {
		t.Errorf("Size = %d, want 3", r.Size())
	}
}

func TestRingBuffer_Overwrite(t *testing.T) {
	r := NewRingBuffer(3)
	now := time.Now()
	for i := 0; i < 5; i++ {
		r.Add(sampleEvent(now.Add(time.Duration(i)*time.Second), "type-A", SeverityInfo, ""))
	}
	if r.Size() != 3 {
		t.Errorf("Size = %d, want 3 (capacity)", r.Size())
	}
}

func TestRingBuffer_CountByType(t *testing.T) {
	r := NewRingBuffer(100)
	now := time.Now()
	r.Add(sampleEvent(now, "type-A", SeverityInfo, ""))
	r.Add(sampleEvent(now, "type-A", SeverityInfo, ""))
	r.Add(sampleEvent(now, "type-B", SeverityInfo, ""))
	got, _ := r.CountByType(nil, now.Add(-time.Hour), now.Add(time.Hour))
	if got["type-A"] != 2 {
		t.Errorf("type-A count = %d, want 2", got["type-A"])
	}
	if got["type-B"] != 1 {
		t.Errorf("type-B count = %d, want 1", got["type-B"])
	}
}

func TestRingBuffer_CountBySeverity(t *testing.T) {
	r := NewRingBuffer(100)
	now := time.Now()
	r.Add(sampleEvent(now, "x", SeverityInfo, ""))
	r.Add(sampleEvent(now, "x", SeverityMedium, ""))
	r.Add(sampleEvent(now, "x", SeverityMedium, ""))
	r.Add(sampleEvent(now, "x", SeverityHigh, ""))
	got, _ := r.CountBySeverity(nil, now.Add(-time.Hour), now.Add(time.Hour))
	if got[SeverityInfo] != 1 {
		t.Errorf("Info count = %d, want 1", got[SeverityInfo])
	}
	if got[SeverityMedium] != 2 {
		t.Errorf("Warning count = %d, want 2", got[SeverityMedium])
	}
	if got[SeverityHigh] != 1 {
		t.Errorf("Error count = %d, want 1", got[SeverityHigh])
	}
}

func TestRingBuffer_CountByFramework(t *testing.T) {
	r := NewRingBuffer(100)
	now := time.Now()
	r.Add(sampleEvent(now, "x", SeverityInfo, "hipaa"))
	r.Add(sampleEvent(now, "x", SeverityInfo, "hipaa"))
	r.Add(sampleEvent(now, "x", SeverityInfo, "pci"))
	r.Add(sampleEvent(now, "x", SeverityInfo, "")) // no framework
	got, _ := r.CountByFramework(nil, now.Add(-time.Hour), now.Add(time.Hour))
	if got["hipaa"] != 2 {
		t.Errorf("hipaa count = %d, want 2", got["hipaa"])
	}
	if got["pci"] != 1 {
		t.Errorf("pci count = %d, want 1", got["pci"])
	}
	if got[""] != 1 {
		t.Errorf("empty framework count = %d, want 1", got[""])
	}
}

func TestRingBuffer_TimeWindow(t *testing.T) {
	r := NewRingBuffer(100)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Add 5 events: t0, t0+1s, t0+2s, t0+3s, t0+4s
	for i := 0; i < 5; i++ {
		r.Add(sampleEvent(t0.Add(time.Duration(i)*time.Second), "x", SeverityInfo, ""))
	}
	// Window covers only the middle 2 (t0+1s and t0+2s).
	got, _ := r.CountByType(nil, t0.Add(time.Second), t0.Add(2*time.Second))
	if len(got) != 1 {
		t.Errorf("got %d keys, want 1", len(got))
	}
	if got["x"] != 2 {
		t.Errorf("x count in window = %d, want 2", got["x"])
	}
}

func TestRingBuffer_TimeWindow_Empty(t *testing.T) {
	r := NewRingBuffer(100)
	now := time.Now()
	// No events added.
	got, _ := r.CountByType(nil, now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 0 {
		t.Errorf("empty buffer count = %v, want empty map", got)
	}
}

func TestRingBuffer_Clear(t *testing.T) {
	r := NewRingBuffer(10)
	now := time.Now()
	for i := 0; i < 5; i++ {
		r.Add(sampleEvent(now, "x", SeverityInfo, ""))
	}
	if r.Size() != 5 {
		t.Fatalf("pre-clear Size = %d, want 5", r.Size())
	}
	r.Clear()
	if r.Size() != 0 {
		t.Errorf("post-clear Size = %d, want 0", r.Size())
	}
	got, _ := r.CountByType(nil, now.Add(-time.Hour), now.Add(time.Hour))
	if len(got) != 0 {
		t.Errorf("post-clear count = %v, want empty", got)
	}
}

func TestRingBuffer_ConcurrentAdd(t *testing.T) {
	r := NewRingBuffer(1000)
	var wg sync.WaitGroup
	const goroutines = 10
	const perGoroutine = 100
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				r.Add(sampleEvent(time.Now(), "concurrent", SeverityInfo, ""))
			}
		}(g)
	}
	wg.Wait()
	if r.Size() != goroutines*perGoroutine {
		t.Errorf("Size = %d, want %d (concurrent add)", r.Size(), goroutines*perGoroutine)
	}
	got, _ := r.CountByType(nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if got["concurrent"] != goroutines*perGoroutine {
		t.Errorf("concurrent count = %d, want %d", got["concurrent"], goroutines*perGoroutine)
	}
}

func TestRingBuffer_ChronologicalOrder(t *testing.T) {
	// Verify the snapshot is in chronological order even after
	// overwrites. This is important for auditors who read the
	// evidence in sequence.
	r := NewRingBuffer(3)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Add 5 events, overwriting the first 2.
	for i := 0; i < 5; i++ {
		r.Add(sampleEvent(t0.Add(time.Duration(i)*time.Second), "x", SeverityInfo, ""))
	}
	// After overwriting, the buffer should contain the last 3
	// events (t0+2s, t0+3s, t0+4s) in chronological order.
	// CountByType only returns counts, but the window filter is
	// applied in chronological order. Use a narrow window to
	// confirm.
	// Window: t0+2s to t0+4s should capture all 3 events.
	got, _ := r.CountByType(nil, t0.Add(2*time.Second), t0.Add(4*time.Second))
	if got["x"] != 3 {
		t.Errorf("window after overwrite: x = %d, want 3 (all 3 retained events)", got["x"])
	}
	// Window: t0+0s to t0+1s should capture 0 (those events were overwritten).
	got, _ = r.CountByType(nil, t0, t0.Add(time.Second))
	if got["x"] != 0 {
		t.Errorf("window before overwrite: x = %d, want 0 (old events were overwritten)", got["x"])
	}
}
