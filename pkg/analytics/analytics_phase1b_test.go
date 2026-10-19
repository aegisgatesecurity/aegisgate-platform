// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Analytics Phase 1b Coverage Tests
// =========================================================================
//
// Mechanical unit tests targeting uncovered error paths, edge cases, nil
// handling, and boundary conditions to push package coverage to 90%+.
//
// =========================================================================

package analytics

import (
	"fmt"
	"math"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Mock store that returns configurable errors
// ---------------------------------------------------------------------------

// phase1bErrorStore is a mock Store that returns configurable errors for
// testing error-handling paths in RecordUsage, GetSummary, DetectAnomalies,
// and GetDashboardData.
type phase1bErrorStore struct {
	insertErr     error
	queryByOrgErr error
	closed        bool
}

func (s *phase1bErrorStore) Insert(record *UsageRecord) error {
	if s.insertErr != nil {
		return s.insertErr
	}
	return nil
}

func (s *phase1bErrorStore) QueryByOrg(orgID string, start, end time.Time) ([]*UsageRecord, error) {
	if s.queryByOrgErr != nil {
		return nil, s.queryByOrgErr
	}
	return nil, nil
}

func (s *phase1bErrorStore) QueryByToken(tokenID string, start, end time.Time) ([]*UsageRecord, error) {
	return nil, nil
}

func (s *phase1bErrorStore) Close() error {
	s.closed = true
	return nil
}

// ---------------------------------------------------------------------------
// computeRealTimeMetrics tests (0% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bComputeRealTimeMetrics(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	records := []*UsageRecord{
		// Within 1 min, 5 min, and 1 hour.
		{TokenID: "tok-1", OrganizationID: "org-1", UserID: "u1", Endpoint: "/api", Model: "gpt-4", TokensUsed: 100, CostCents: 10, Timestamp: now.Add(-30 * time.Second), Success: true, LatencyMs: 50},
		// Within 5 min and 1 hour, but NOT within 1 min. Failed request.
		{TokenID: "tok-2", OrganizationID: "org-1", UserID: "u2", Endpoint: "/api", Model: "gpt-4", TokensUsed: 200, CostCents: 20, Timestamp: now.Add(-2 * time.Minute), Success: false, LatencyMs: 100},
		// Within 1 hour only. Different org.
		{TokenID: "tok-1", OrganizationID: "org-2", UserID: "u3", Endpoint: "/api", Model: "gpt-3.5", TokensUsed: 50, CostCents: 5, Timestamp: now.Add(-30 * time.Minute), Success: true, LatencyMs: 200},
		// Outside all windows (2 hours ago).
		{TokenID: "tok-old", OrganizationID: "org-1", UserID: "u-old", Endpoint: "/api", Model: "gpt-4", TokensUsed: 999, CostCents: 999, Timestamp: now.Add(-2 * time.Hour), Success: true, LatencyMs: 50},
	}
	for _, r := range records {
		if err := tr.RecordUsage(r); err != nil {
			t.Fatalf("RecordUsage failed: %v", err)
		}
	}

	tr.computeRealTimeMetrics()

	tr.mu.RLock()
	rt := tr.realTime
	tr.mu.RUnlock()

	// Active tokens within 1 hour: tok-1, tok-2 (tok-1 appears twice but is deduped).
	if rt.ActiveTokens != 2 {
		t.Errorf("expected 2 active tokens, got %d", rt.ActiveTokens)
	}
	// Requests in last minute: only the -30s record.
	if rt.RequestsPerMinute != 1 {
		t.Errorf("expected 1 RPM, got %f", rt.RequestsPerMinute)
	}
	// Cost in last hour: 10 + 20 + 5 = 35 (old record excluded).
	if rt.CurrentCostPerHour != 35 {
		t.Errorf("expected cost per hour 35, got %f", rt.CurrentCostPerHour)
	}
	// Error rate in last 5 min: 1 error / 2 requests = 0.5.
	if rt.ErrorRateLast5Min != 0.5 {
		t.Errorf("expected error rate 0.5, got %f", rt.ErrorRateLast5Min)
	}
	if rt.LastUpdated.IsZero() {
		t.Error("expected LastUpdated to be set")
	}
}

func TestPhase1bComputeRealTimeMetrics_Empty(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	tr.computeRealTimeMetrics()

	tr.mu.RLock()
	rt := tr.realTime
	tr.mu.RUnlock()

	if rt.ActiveTokens != 0 {
		t.Errorf("expected 0 active tokens, got %d", rt.ActiveTokens)
	}
	if rt.RequestsPerMinute != 0 {
		t.Errorf("expected 0 RPM, got %f", rt.RequestsPerMinute)
	}
	if rt.CurrentCostPerHour != 0 {
		t.Errorf("expected 0 cost, got %f", rt.CurrentCostPerHour)
	}
	if rt.ErrorRateLast5Min != 0 {
		t.Errorf("expected 0 error rate, got %f", rt.ErrorRateLast5Min)
	}
	if rt.LastUpdated.IsZero() {
		t.Error("expected LastUpdated to be set")
	}
}

// ---------------------------------------------------------------------------
// severityForThreshold tests (85.7% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bSeverityForThreshold_ZeroThreshold(t *testing.T) {
	// threshold == 0 should return "critical" immediately.
	if severityForThreshold(0.01, 0) != "critical" {
		t.Error("expected critical for zero threshold")
	}
}

func TestPhase1bSeverityForThreshold_AllBranches(t *testing.T) {
	tests := []struct {
		value    float64
		thr      float64
		expected string
	}{
		{0.5, 0.1, "critical"}, // ratio=5 > 3
		{0.25, 0.1, "high"},    // ratio=2.5 > 2
		{0.15, 0.1, "medium"},  // ratio=1.5, default
	}
	for _, tc := range tests {
		result := severityForThreshold(tc.value, tc.thr)
		if result != tc.expected {
			t.Errorf("severityForThreshold(%.2f, %.2f) = %q, want %q", tc.value, tc.thr, result, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// severityOrder tests (83.3% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bSeverityOrder_Unknown(t *testing.T) {
	if severityOrder("unknown") != 4 {
		t.Errorf("expected 4 for unknown severity, got %d", severityOrder("unknown"))
	}
	if severityOrder("") != 4 {
		t.Errorf("expected 4 for empty severity, got %d", severityOrder(""))
	}
	if severityOrder("xyz") != 4 {
		t.Errorf("expected 4 for xyz severity, got %d", severityOrder("xyz"))
	}
}

// ---------------------------------------------------------------------------
// GetCostAttribution error path tests (85.7% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bGetCostAttribution_EmptyOrg(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	_, err := tr.GetCostAttribution("", time.Now(), time.Now().Add(time.Hour))
	if err == nil {
		t.Error("expected error for empty orgID")
	}
}

func TestPhase1bGetCostAttribution_InvalidTimeRange(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	_, err := tr.GetCostAttribution("org-1", now, now.Add(-time.Hour))
	if err == nil {
		t.Error("expected error for invalid time range (end before start)")
	}
}

// ---------------------------------------------------------------------------
// validateROIInput tests (86.7% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bValidateROI_MultiTurnDetectionRate(t *testing.T) {
	// Negative value.
	input := NewDefaultROIInput()
	input.MultiTurnDetectionRate = -0.1
	_, err := CalculateROI(input)
	if err == nil {
		t.Error("expected error for negative MultiTurnDetectionRate")
	}

	// Value > 1.
	input = NewDefaultROIInput()
	input.MultiTurnDetectionRate = 1.5
	_, err = CalculateROI(input)
	if err == nil {
		t.Error("expected error for MultiTurnDetectionRate > 1")
	}
}

func TestPhase1bValidateROI_MultiTurnAttackFraction(t *testing.T) {
	// Negative value.
	input := NewDefaultROIInput()
	input.MultiTurnAttackFraction = -0.1
	_, err := CalculateROI(input)
	if err == nil {
		t.Error("expected error for negative MultiTurnAttackFraction")
	}

	// Value > 1.
	input = NewDefaultROIInput()
	input.MultiTurnAttackFraction = 1.5
	_, err = CalculateROI(input)
	if err == nil {
		t.Error("expected error for MultiTurnAttackFraction > 1")
	}
}

// ---------------------------------------------------------------------------
// RecordUsage store error test (93.8% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bRecordUsage_StoreInsertError(t *testing.T) {
	store := &phase1bErrorStore{insertErr: fmt.Errorf("db connection lost")}
	tr := NewTokenUsageTrackerWithStore(nil, store)
	defer tr.Close()

	err := tr.RecordUsage(&UsageRecord{
		TokenID:        "tok-1",
		OrganizationID: "org-1",
		Timestamp:      time.Now().UTC(),
	})
	if err == nil {
		t.Error("expected error from store insert failure")
	}
}

// ---------------------------------------------------------------------------
// GetSummary store error test (90.9% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bGetSummary_StoreQueryError(t *testing.T) {
	store := &phase1bErrorStore{queryByOrgErr: fmt.Errorf("query timeout")}
	tr := NewTokenUsageTrackerWithStore(nil, store)
	defer tr.Close()

	now := time.Now().UTC()
	_, err := tr.GetSummary("org-1", now.Add(-time.Hour), now)
	if err == nil {
		t.Error("expected error from store query failure")
	}
}

// ---------------------------------------------------------------------------
// DetectAnomalies store error test (89.1% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bDetectAnomalies_StoreError(t *testing.T) {
	store := &phase1bErrorStore{queryByOrgErr: fmt.Errorf("query failed")}
	tr := NewTokenUsageTrackerWithStore(nil, store)
	defer tr.Close()

	_, err := tr.DetectAnomalies("org-1", time.Hour)
	if err == nil {
		t.Error("expected error from store query failure")
	}
}

// ---------------------------------------------------------------------------
// GetDashboardData store error test (94.1% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bGetDashboardData_StoreError(t *testing.T) {
	store := &phase1bErrorStore{queryByOrgErr: fmt.Errorf("query failed")}
	tr := NewTokenUsageTrackerWithStore(nil, store)
	defer tr.Close()

	_, err := tr.GetDashboardData("org-1")
	if err == nil {
		t.Error("expected error from store query failure via GetSummary")
	}
}

// ---------------------------------------------------------------------------
// CalculateROI edge case tests (92.6% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bCalculateROI_NegativeNetBenefit(t *testing.T) {
	input := NewDefaultROIInput()
	// Make FP cost exceed savings: 1M calls * 100% FPR * $1M = $1T FP cost.
	input.FalsePositiveRate = 1.0
	input.AvgFalsePositiveCost = 1_000_000

	result, err := CalculateROI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.MonthlyNetBenefit >= 0 {
		t.Errorf("expected negative net benefit, got %.2f", result.MonthlyNetBenefit)
	}
	if !math.IsInf(result.PaybackPeriodMonths, 1) {
		t.Errorf("expected +Inf payback for negative net benefit, got %.2f", result.PaybackPeriodMonths)
	}
}

func TestPhase1bCalculateROI_ZeroCost(t *testing.T) {
	input := NewDefaultROIInput()
	input.MonthlyLicenseCost = 0
	input.InfrastructureCost = 0

	result, err := CalculateROI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.MonthlyTotalCost != 0 {
		t.Errorf("expected 0 total cost, got %.2f", result.MonthlyTotalCost)
	}
	if result.ROIPercentage != 0 {
		t.Errorf("expected 0 ROI percentage for zero cost, got %.2f", result.ROIPercentage)
	}
}

func TestPhase1bCalculateROI_MinAttacksClamped(t *testing.T) {
	// Very low call count so monthlyAttacks rounds to 0, then clamped to 1.
	// This exercises the "if monthlyAttacks == 0 { monthlyAttacks = 1 }" branch.
	input := NewDefaultROIInput()
	input.MonthlyLLMCalls = 1

	result, err := CalculateROI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// monthlyAttacks = int64(1 * 2.0 / 1000) = 0 → clamped to 1.
	// prevented = int64(1 * 0.7616) = 0, so prevented is 0.
	// The test verifies the clamping branch is exercised without error.
	expectedRate := 0.788*0.7 + 0.70*0.3 // 0.5516 + 0.21 = 0.7616
	if math.Abs(result.EffectiveDetectionRate-expectedRate) > 0.001 {
		t.Errorf("expected effective rate %.4f, got %.4f", expectedRate, result.EffectiveDetectionRate)
	}
}

// ---------------------------------------------------------------------------
// CheckRateLimit remaining clamped test (93.1% → covered)
// ---------------------------------------------------------------------------

func TestPhase1bCheckRateLimit_RemainingClamped(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	// Use limit=1 and call 3 times rapidly in the same second.
	// Call 0: totalInWindow=0, allowed, remaining=0.
	// Call 1: totalInWindow=1, denied, remaining=0.
	// Call 2: totalInWindow=2, remaining=1-2=-1 → clamped to 0.
	for i := 0; i < 3; i++ {
		allowed, remaining, err := tr.CheckRateLimit("tok-clamp", time.Minute, 1)
		if err != nil {
			t.Fatalf("CheckRateLimit call %d failed: %v", i, err)
		}
		if remaining < 0 {
			t.Errorf("call %d: remaining should never be negative, got %d", i, remaining)
		}
		if i > 0 && allowed {
			t.Errorf("call %d: expected denied after limit exceeded", i)
		}
	}
}
