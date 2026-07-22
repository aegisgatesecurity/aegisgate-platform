// SPDX-License-Identifier: Apache-2.0
// CCM (Continuous Control Monitoring) tests.
//
// Tests are organized in two groups:
//  1. CCMDriftDetector tests - pure functions, no I/O
//  2. CCMScheduler tests - exercise the lifecycle and status
//
// Tests use the in-memory state of the scheduler and the
// CCMDriftDetector directly. They do NOT start a real scan loop
// (which would require a Scanner with a Registry); instead they
// verify state transitions and the public status/history APIs.

package compliance

import (
	"context"
	"testing"
	"time"
)

// =====================================================================
// CCMDriftDetector tests
// =====================================================================

func TestCCMDriftDetector_NilInputs(t *testing.T) {
	d := NewCCMDriftDetector()
	if got := d.Compare(nil, nil); got != nil {
		t.Errorf("Compare(nil, nil) = %v, want nil", got)
	}
	r := &ScanReport{}
	if got := d.Compare(nil, r); got != nil {
		t.Errorf("Compare(nil, r) = %v, want nil", got)
	}
	if got := d.Compare(r, nil); got != nil {
		t.Errorf("Compare(r, nil) = %v, want nil", got)
	}
}

func TestCCMDriftDetector_NoRegressions(t *testing.T) {
	d := NewCCMDriftDetector()
	prior := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 80, CompliancePct: 80, Enforced: true},
	}}
	current := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 82, CompliancePct: 82, Enforced: true},
	}}
	if got := d.Compare(prior, current); len(got) != 0 {
		t.Errorf("expected 0 regressions, got %d", len(got))
	}
}

func TestCCMDriftDetector_ScoreRegression(t *testing.T) {
	d := NewCCMDriftDetector()
	prior := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 90, CompliancePct: 90, Enforced: true},
	}}
	current := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 70, CompliancePct: 70, Enforced: true},
	}}
	got := d.Compare(prior, current)
	if len(got) != 1 {
		t.Fatalf("expected 1 regression, got %d", len(got))
	}
	r := got[0]
	if r.Framework != "hipaa" {
		t.Errorf("Framework = %q, want hipaa", r.Framework)
	}
	if r.ScoreDelta != -20 {
		t.Errorf("ScoreDelta = %f, want -20", r.ScoreDelta)
	}
	if r.Severity != CCMSeverityCritical {
		t.Errorf("Severity = %q, want critical (delta -20)", r.Severity)
	}
	if r.Reason != "score_drop" {
		t.Errorf("Reason = %q, want score_drop", r.Reason)
	}
}

func TestCCMDriftDetector_PctRegression(t *testing.T) {
	d := NewCCMDriftDetector()
	// Score stable but compliance pct drops
	prior := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "pci", DisplayName: "PCI", Score: 90, CompliancePct: 95, Enforced: true},
	}}
	current := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "pci", DisplayName: "PCI", Score: 91, CompliancePct: 85, Enforced: true},
	}}
	got := d.Compare(prior, current)
	if len(got) != 1 {
		t.Fatalf("expected 1 regression, got %d", len(got))
	}
	if got[0].Reason != "compliance_pct_drop" {
		t.Errorf("Reason = %q, want compliance_pct_drop", got[0].Reason)
	}
}

func TestCCMDriftDetector_FrameworkDisappeared(t *testing.T) {
	d := NewCCMDriftDetector()
	prior := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 90, CompliancePct: 90, Enforced: true},
		{Framework: "pci", DisplayName: "PCI", Score: 80, CompliancePct: 80, Enforced: true},
	}}
	current := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 92, CompliancePct: 92, Enforced: true},
		// pci disappeared
	}}
	got := d.Compare(prior, current)
	if len(got) != 1 {
		t.Fatalf("expected 1 regression, got %d", len(got))
	}
	if got[0].Severity != CCMSeverityCritical {
		t.Errorf("Severity = %q, want critical", got[0].Severity)
	}
	if got[0].Reason != "framework_disappeared" {
		t.Errorf("Reason = %q, want framework_disappeared", got[0].Reason)
	}
}

func TestCCMDriftDetector_EnforcementLoss(t *testing.T) {
	d := NewCCMDriftDetector()
	prior := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 90, CompliancePct: 90, Enforced: true},
	}}
	current := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 91, CompliancePct: 91, Enforced: false},
	}}
	got := d.Compare(prior, current)
	if len(got) != 1 {
		t.Fatalf("expected 1 regression, got %d", len(got))
	}
	if got[0].Reason != "enforcement_lost" {
		t.Errorf("Reason = %q, want enforcement_lost", got[0].Reason)
	}
}

func TestCCMDriftDetector_BelowThreshold(t *testing.T) {
	d := NewCCMDriftDetector()
	// 3-point drop is below the 5-point threshold - not a regression.
	prior := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 90, CompliancePct: 90, Enforced: true},
	}}
	current := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "hipaa", DisplayName: "HIPAA", Score: 87, CompliancePct: 87, Enforced: true},
	}}
	got := d.Compare(prior, current)
	if len(got) != 0 {
		t.Errorf("3-point drop should not be a regression, got %d", len(got))
	}
}

func TestCCMDriftDetector_SortedBySeverity(t *testing.T) {
	d := NewCCMDriftDetector()
	// Two regressions: one critical (big score drop), one medium (small).
	prior := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "low", DisplayName: "Low", Score: 90, CompliancePct: 90, Enforced: true},
		{Framework: "critical", DisplayName: "Critical", Score: 90, CompliancePct: 90, Enforced: true},
	}}
	current := &ScanReport{Frameworks: []FrameworkScanResult{
		{Framework: "low", DisplayName: "Low", Score: 80, CompliancePct: 80, Enforced: true},
		{Framework: "critical", DisplayName: "Critical", Score: 60, CompliancePct: 60, Enforced: true},
	}}
	got := d.Compare(prior, current)
	if len(got) != 2 {
		t.Fatalf("expected 2 regressions, got %d", len(got))
	}
	// critical (delta -30) should be first
	if got[0].Framework != "critical" {
		t.Errorf("expected critical first, got %s", got[0].Framework)
	}
}

func TestCCMDriftDetector_ClassifySeverity(t *testing.T) {
	d := NewCCMDriftDetector()
	tests := []struct {
		delta float64
		want  CCMRegressionSeverity
	}{
		{-3, CCMSeverityLow},
		{-5, CCMSeverityMedium},
		{-9, CCMSeverityMedium},
		{-10, CCMSeverityHigh},
		{-19, CCMSeverityHigh},
		{-20, CCMSeverityCritical},
		{-50, CCMSeverityCritical},
	}
	for _, tt := range tests {
		got := d.classifySeverity(tt.delta)
		if got != tt.want {
			t.Errorf("classifySeverity(%v) = %q, want %q", tt.delta, got, tt.want)
		}
	}
}

// =====================================================================
// CCMScheduler tests
// =====================================================================

func TestCCMScheduler_Defaults(t *testing.T) {
	s := NewCCMScheduler(nil, CCMSchedule{})
	if s.schedule.Interval != 24*time.Hour {
		t.Errorf("default interval = %v, want 24h", s.schedule.Interval)
	}
	if s.schedule.RunOnStart {
		t.Errorf("default RunOnStart should be false")
	}
	if s.historyMax != 90 {
		t.Errorf("historyMax = %d, want 90", s.historyMax)
	}
	if s.lastReport != nil {
		t.Errorf("lastReport should be nil on new scheduler")
	}
}

func TestCCMScheduler_CustomSchedule(t *testing.T) {
	s := NewCCMScheduler(nil, CCMSchedule{
		Interval:   1 * time.Hour,
		RunOnStart: true,
	})
	if s.schedule.Interval != 1*time.Hour {
		t.Errorf("interval = %v, want 1h", s.schedule.Interval)
	}
	if !s.schedule.RunOnStart {
		t.Errorf("RunOnStart should be true")
	}
}

func TestCCMScheduler_StartStop(t *testing.T) {
	s := NewCCMScheduler(nil, CCMSchedule{Interval: 100 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if s.IsRunning() {
		t.Errorf("scheduler should not be running initially")
	}

	s.Start(ctx)
	if !s.IsRunning() {
		t.Errorf("scheduler should be running after Start")
	}

	// Double-start should be a no-op (still running, not double-counted)
	s.Start(ctx)
	if !s.IsRunning() {
		t.Errorf("scheduler should still be running after double Start")
	}

	s.Stop()
	if s.IsRunning() {
		t.Errorf("scheduler should not be running after Stop")
	}

	// Double-stop should be a no-op
	s.Stop()
}

func TestCCMScheduler_GetStatusBeforeScan(t *testing.T) {
	s := NewCCMScheduler(nil, CCMSchedule{})
	status := s.GetStatus()
	if status.Running {
		t.Errorf("status.Running should be false initially")
	}
	if status.LastReport != nil {
		t.Errorf("status.LastReport should be nil before any scan")
	}
	if status.HistorySize != 0 {
		t.Errorf("status.HistorySize should be 0, got %d", status.HistorySize)
	}
	if status.Regressions != nil {
		t.Errorf("status.Regressions should be nil before any scan")
	}
}

func TestCCMScheduler_GetHistory(t *testing.T) {
	s := NewCCMScheduler(nil, CCMSchedule{})
	history := s.GetHistory()
	if history == nil {
		t.Errorf("GetHistory should return non-nil empty slice")
	}
	if len(history) != 0 {
		t.Errorf("history should be empty, got %d items", len(history))
	}
}

func TestCCMScheduler_SetOnDriftCallback(t *testing.T) {
	s := NewCCMScheduler(nil, CCMSchedule{})
	if s.onDrift != nil {
		t.Errorf("onDrift should be nil before SetOnDriftCallback")
	}
	s.SetOnDriftCallback(func(regressions []CCMRegression) {
		// The callback itself is tested via the drift detector in
		// the other tests; here we just verify assignment.
	})
	if s.onDrift == nil {
		t.Errorf("onDrift callback should be set after SetOnDriftCallback")
	}
}

func TestCCMScheduler_ScanWithNilScanner(t *testing.T) {
	// Verifies that runScan is a no-op when no scanner is configured.
	// This is the common case in unit tests and some production paths.
	s := NewCCMScheduler(nil, CCMSchedule{})
	before := s.GetStatus()
	if before.LastReport != nil {
		t.Fatalf("precondition: lastReport should be nil")
	}
	s.RunNow(context.Background())
	after := s.GetStatus()
	if after.LastReport != nil {
		t.Errorf("RunNow with nil scanner should not produce a report")
	}
	if after.HistorySize != 0 {
		t.Errorf("RunNow with nil scanner should not grow history")
	}
}
