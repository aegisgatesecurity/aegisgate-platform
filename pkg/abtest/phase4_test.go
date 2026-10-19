// SPDX-License-Identifier: Apache-2.0
// Phase 4 coverage tests for A/B testing service.
// Covers ListTests, StopTest, StartTest error paths, AssignVariant edge
// cases, RecordResult error paths, and GetMetrics not-found.

package abtest

import (
	"context"
	"testing"
)

// --- ListTests ---

func TestPhase4_ListTests_Empty(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	tests := s.ListTests(ctx)
	if len(tests) != 0 {
		t.Fatalf("expected 0 tests, got %d", len(tests))
	}
}

func TestPhase4_ListTests_Multiple(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	t1, _ := s.CreateTest(ctx, "test1", "desc1", []Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}})
	t2, _ := s.CreateTest(ctx, "test2", "desc2", []Variant{{Name: "c", Weight: 1}, {Name: "d", Weight: 1}})
	tests := s.ListTests(ctx)
	if len(tests) != 2 {
		t.Fatalf("expected 2 tests, got %d", len(tests))
	}
	// Verify both test IDs are present
	ids := map[string]bool{t1.ID: true, t2.ID: true}
	for _, tt := range tests {
		if !ids[tt.ID] {
			t.Errorf("unexpected test ID: %s", tt.ID)
		}
	}
}

// --- StopTest ---

func TestPhase4_StopTest_Success(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	test, _ := s.CreateTest(ctx, "stop-test", "", []Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}})
	if err := s.StopTest(ctx, test.ID); err != nil {
		t.Fatalf("StopTest: %v", err)
	}
	got, _ := s.GetMetrics(ctx, test.ID) // triggers test lookup
	_ = got
	// Verify status via ListTests
	for _, tt := range s.ListTests(ctx) {
		if tt.ID == test.ID {
			if tt.Status != StatusStopped {
				t.Errorf("status=%s, want stopped", tt.Status)
			}
		}
	}
}

func TestPhase4_StopTest_NotFound(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	if err := s.StopTest(ctx, "nonexistent"); err == nil {
		t.Fatal("expected error for nonexistent test")
	}
}

// --- StartTest error paths ---

func TestPhase4_StartTest_NotFound(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	if err := s.StartTest(ctx, "nonexistent"); err == nil {
		t.Fatal("expected error for nonexistent test")
	}
}

func TestPhase4_StartTest_NotDraft(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	test, _ := s.CreateTest(ctx, "not-draft", "", []Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}})
	if err := s.StartTest(ctx, test.ID); err != nil {
		t.Fatalf("StartTest: %v", err)
	}
	// Second call should fail — test is running, not draft
	if err := s.StartTest(ctx, test.ID); err == nil {
		t.Fatal("expected error when starting already-running test")
	}
}

// --- AssignVariant edge cases ---

func TestPhase4_AssignVariant_NotFound(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	_, err := s.AssignVariant(ctx, "nonexistent", "req-1")
	if err == nil {
		t.Fatal("expected error for nonexistent test")
	}
}

func TestPhase4_AssignVariant_NotRunning(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	test, _ := s.CreateTest(ctx, "not-running", "", []Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}})
	// Test is in draft status — AssignVariant should fail
	_, err := s.AssignVariant(ctx, test.ID, "req-1")
	if err == nil {
		t.Fatal("expected error for non-running test")
	}
}

func TestPhase4_AssignVariant_ZeroTotalWeight(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	test, _ := s.CreateTest(ctx, "zero-weight", "", []Variant{{Name: "a", Weight: 0}, {Name: "b", Weight: 0}})
	_ = s.StartTest(ctx, test.ID)
	// totalWeight == 0 → should return first variant
	v, err := s.AssignVariant(ctx, test.ID, "req-1")
	if err != nil {
		t.Fatalf("AssignVariant: %v", err)
	}
	if v != "a" {
		t.Errorf("expected variant 'a' for zero total weight, got %q", v)
	}
}

func TestPhase4_AssignVariant_WeightedDistribution(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	test, _ := s.CreateTest(ctx, "weighted", "", []Variant{
		{Name: "control", Weight: 90},
		{Name: "treatment", Weight: 10},
	})
	_ = s.StartTest(ctx, test.ID)

	// Run many assignments and check distribution
	controlCount := 0
	treatmentCount := 0
	for i := 0; i < 1000; i++ {
		v, err := s.AssignVariant(ctx, test.ID, "req-"+string(rune(i)))
		if err != nil {
			t.Fatalf("AssignVariant: %v", err)
		}
		switch v {
		case "control":
			controlCount++
		case "treatment":
			treatmentCount++
		default:
			t.Errorf("unexpected variant: %q", v)
		}
	}
	// With 90:10 split over 1000 samples, control should be ~900
	// We just verify both are present (hash-based assignment is deterministic)
	if controlCount == 0 {
		t.Error("expected at least some control assignments")
	}
	if treatmentCount == 0 {
		t.Error("expected at least some treatment assignments")
	}
}

// --- RecordResult error paths ---

func TestPhase4_RecordResult_TestNotFound(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	// Should not panic for nonexistent test
	s.RecordResult(ctx, "nonexistent", "a", true, false, 10.0)
}

func TestPhase4_RecordResult_VariantNotFound(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	test, _ := s.CreateTest(ctx, "bad-variant", "", []Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}})
	_ = s.StartTest(ctx, test.ID)
	// Recording for nonexistent variant should not panic
	s.RecordResult(ctx, test.ID, "nonexistent-variant", true, false, 10.0)
	// Metrics should show no data for the bad variant
	metrics, err := s.GetMetrics(ctx, test.ID)
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	for _, m := range metrics {
		if m.RequestCount != 0 {
			t.Errorf("expected 0 requests for variant %s, got %d", m.VariantName, m.RequestCount)
		}
	}
}

// --- GetMetrics error paths ---

func TestPhase4_GetMetrics_NotFound(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	_, err := s.GetMetrics(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent test")
	}
}

func TestPhase4_GetMetrics_EmptyMetrics(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	test, _ := s.CreateTest(ctx, "empty-metrics", "", []Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}})
	// No results recorded yet — metrics should be zero-valued
	metrics, err := s.GetMetrics(ctx, test.ID)
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 variant metrics, got %d", len(metrics))
	}
	for _, m := range metrics {
		if m.RequestCount != 0 {
			t.Errorf("expected 0 request count for %s, got %d", m.VariantName, m.RequestCount)
		}
		if m.DetectionRate != 0 {
			t.Errorf("expected 0 detection rate for %s, got %f", m.VariantName, m.DetectionRate)
		}
		if m.AvgLatencyMs != 0 {
			t.Errorf("expected 0 avg latency for %s, got %f", m.VariantName, m.AvgLatencyMs)
		}
	}
}

func TestPhase4_GetMetrics_FalsePositiveCount(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	test, _ := s.CreateTest(ctx, "fp-test", "", []Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}})
	_ = s.StartTest(ctx, test.ID)

	s.RecordResult(ctx, test.ID, "a", true, true, 10.0)
	s.RecordResult(ctx, test.ID, "a", true, false, 20.0)
	s.RecordResult(ctx, test.ID, "a", false, false, 30.0)

	metrics, _ := s.GetMetrics(ctx, test.ID)
	for _, m := range metrics {
		if m.VariantName == "a" {
			if m.RequestCount != 3 {
				t.Errorf("RequestCount=%d, want 3", m.RequestCount)
			}
			if m.DetectionCount != 2 {
				t.Errorf("DetectionCount=%d, want 2", m.DetectionCount)
			}
			if m.FalsePositiveCount != 1 {
				t.Errorf("FalsePositiveCount=%d, want 1", m.FalsePositiveCount)
			}
			if m.DetectionRate != 2.0/3.0 {
				t.Errorf("DetectionRate=%f, want %f", m.DetectionRate, 2.0/3.0)
			}
			if m.AvgLatencyMs != 20.0 {
				t.Errorf("AvgLatencyMs=%f, want 20.0", m.AvgLatencyMs)
			}
		}
	}
}

// --- Full lifecycle test ---

func TestPhase4_FullLifecycle(t *testing.T) {
	s := NewService()
	ctx := context.Background()

	// Create
	test, err := s.CreateTest(ctx, "lifecycle", "Full lifecycle test",
		[]Variant{{Name: "control", Weight: 50, ModelRef: "model-v1"}, {Name: "treatment", Weight: 50, ModelRef: "model-v2"}})
	if err != nil {
		t.Fatalf("CreateTest: %v", err)
	}
	if test.Status != StatusDraft {
		t.Fatalf("status=%s, want draft", test.Status)
	}

	// Start
	if err := s.StartTest(ctx, test.ID); err != nil {
		t.Fatalf("StartTest: %v", err)
	}

	// Assign and record
	for i := 0; i < 100; i++ {
		v, err := s.AssignVariant(ctx, test.ID, "req-"+string(rune(i)))
		if err != nil {
			t.Fatalf("AssignVariant: %v", err)
		}
		s.RecordResult(ctx, test.ID, v, i%2 == 0, i%5 == 0, float64(i))
	}

	// Get metrics
	metrics, err := s.GetMetrics(ctx, test.ID)
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(metrics))
	}

	// List
	tests := s.ListTests(ctx)
	if len(tests) != 1 {
		t.Fatalf("expected 1 test, got %d", len(tests))
	}
	if tests[0].Status != StatusRunning {
		t.Errorf("status=%s, want running", tests[0].Status)
	}

	// Stop
	if err := s.StopTest(ctx, test.ID); err != nil {
		t.Fatalf("StopTest: %v", err)
	}
	tests = s.ListTests(ctx)
	if tests[0].Status != StatusStopped {
		t.Errorf("status=%s, want stopped", tests[0].Status)
	}
}

// --- StopTest already stopped ---

func TestPhase4_StopTest_AlreadyStopped(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	test, _ := s.CreateTest(ctx, "double-stop", "", []Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}})
	_ = s.StopTest(ctx, test.ID)
	// Stopping again should not error (no guard against it)
	if err := s.StopTest(ctx, test.ID); err != nil {
		t.Fatalf("second StopTest should not error: %v", err)
	}
}
