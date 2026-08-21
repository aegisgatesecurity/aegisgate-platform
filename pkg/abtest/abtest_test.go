// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — A/B Testing Service Tests

package abtest

import (
	"context"
	"testing"
)

func TestService_CreateTest(t *testing.T) {
	s := NewService()
	test, err := s.CreateTest(context.Background(), "Model A vs B", "Compare detection models",
		[]Variant{{Name: "control", Weight: 50}, {Name: "treatment", Weight: 50}})
	if err != nil {
		t.Fatalf("CreateTest failed: %v", err)
	}
	if test.ID == "" {
		t.Fatal("test ID is empty")
	}
	if test.Status != StatusDraft {
		t.Fatalf("status=%s, want draft", test.Status)
	}
}

func TestService_CreateTest_Validation(t *testing.T) {
	s := NewService()
	ctx := context.Background()

	_, err := s.CreateTest(ctx, "", "", []Variant{{Name: "a", Weight: 1}, {Name: "b", Weight: 1}})
	if err == nil {
		t.Fatal("should error on empty name")
	}

	_, err = s.CreateTest(ctx, "test", "", []Variant{{Name: "a", Weight: 1}})
	if err == nil {
		t.Fatal("should error with < 2 variants")
	}
}

func TestService_AssignVariant(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	_, _ = s.CreateTest(ctx, "test", "", []Variant{{Name: "a", Weight: 50}, {Name: "b", Weight: 50}})
	_ = s.StartTest(ctx, func() string {
		for id, test := range s.tests {
			_ = test
			return id
		}
		return ""
	}())

	// Get the test ID
	var testID string
	for id := range s.tests {
		testID = id
	}

	// Same request ID should always get the same variant (consistent assignment)
	v1, err := s.AssignVariant(ctx, testID, "req-123")
	if err != nil {
		t.Fatalf("AssignVariant failed: %v", err)
	}
	v2, err := s.AssignVariant(ctx, testID, "req-123")
	if err != nil {
		t.Fatalf("AssignVariant failed: %v", err)
	}
	if v1 != v2 {
		t.Fatalf("inconsistent assignment: %s != %s", v1, v2)
	}
}

func TestService_RecordResultAndMetrics(t *testing.T) {
	s := NewService()
	ctx := context.Background()
	_, _ = s.CreateTest(ctx, "test", "", []Variant{{Name: "a", Weight: 50}, {Name: "b", Weight: 50}})
	_ = s.StartTest(ctx, func() string {
		for id := range s.tests {
			return id
		}
		return ""
	}())

	var testID string
	for id := range s.tests {
		testID = id
	}

	s.RecordResult(ctx, testID, "a", true, false, 10.0)
	s.RecordResult(ctx, testID, "a", false, false, 20.0)
	s.RecordResult(ctx, testID, "b", true, true, 15.0)

	metrics, err := s.GetMetrics(ctx, testID)
	if err != nil {
		t.Fatalf("GetMetrics failed: %v", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("expected 2 variant metrics, got %d", len(metrics))
	}

	// Find variant "a"
	var aMetrics *VariantMetrics
	for i := range metrics {
		if metrics[i].VariantName == "a" {
			aMetrics = &metrics[i]
		}
	}
	if aMetrics == nil {
		t.Fatal("variant 'a' metrics not found")
	}
	if aMetrics.RequestCount != 2 {
		t.Fatalf("RequestCount=%d, want 2", aMetrics.RequestCount)
	}
	if aMetrics.DetectionCount != 1 {
		t.Fatalf("DetectionCount=%d, want 1", aMetrics.DetectionCount)
	}
	if aMetrics.DetectionRate != 0.5 {
		t.Fatalf("DetectionRate=%f, want 0.5", aMetrics.DetectionRate)
	}
	if aMetrics.AvgLatencyMs != 15.0 {
		t.Fatalf("AvgLatencyMs=%f, want 15.0", aMetrics.AvgLatencyMs)
	}
}
