// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Compliance Regression CI Gate Tests
// =========================================================================

package compliance

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// sampleScanReport creates a realistic ScanReport with the given framework
// results. This is a test helper used throughout the regression tests.
func sampleScanReport(frameworks []FrameworkScanResult, generatedAt time.Time) *ScanReport {
	return &ScanReport{
		CustomerTier:         tier.TierProfessional,
		CustomerModules:      []string{"hipaa", "pci", "soc2", "iso42001"},
		Frameworks:           frameworks,
		OverallScore:         85.0,
		OverallCompliancePct: 82.0,
		GeneratedAt:          generatedAt,
		ScanDurationMs:       123,
		HasLicense:           true,
		LicenseValid:         true,
	}
}

// baselineFrameworks returns 4 framework results representing a healthy
// compliance baseline.
func baselineFrameworks() []FrameworkScanResult {
	return []FrameworkScanResult{
		{
			Framework:           "hipaa",
			DisplayName:         "HIPAA",
			Enforced:            true,
			Module:              "hipaa",
			Score:               85.0,
			ControlsTotal:       20,
			ControlsEnforced:    17,
			CompliancePct:       85.0,
			ReasonEnforced:      "module_owned",
			ImplementationReady: true,
			LastScan:            time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			Framework:           "pci",
			DisplayName:         "PCI-DSS",
			Enforced:            true,
			Module:              "pci",
			Score:               78.0,
			ControlsTotal:       25,
			ControlsEnforced:    20,
			CompliancePct:       80.0,
			ReasonEnforced:      "module_owned",
			ImplementationReady: true,
			LastScan:            time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			Framework:           "soc2",
			DisplayName:         "SOC 2",
			Enforced:            true,
			Module:              "soc2",
			Score:               90.0,
			ControlsTotal:       30,
			ControlsEnforced:    27,
			CompliancePct:       90.0,
			ReasonEnforced:      "module_owned",
			ImplementationReady: true,
			LastScan:            time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			Framework:           "iso42001",
			DisplayName:         "ISO 42001",
			Enforced:            true,
			Module:              "iso42001",
			Score:               72.0,
			ControlsTotal:       15,
			ControlsEnforced:    11,
			CompliancePct:       73.33,
			ReasonEnforced:      "module_owned",
			ImplementationReady: true,
			LastScan:            time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		},
	}
}

func TestNewRegressionGate(t *testing.T) {
	t.Run("with nil threshold uses defaults", func(t *testing.T) {
		gate := NewRegressionGate(nil)
		if gate == nil {
			t.Fatal("expected non-nil gate")
		}
		if gate.Threshold == nil {
			t.Fatal("expected non-nil threshold")
		}
		if gate.Threshold.MinScoreDelta != 5.0 {
			t.Errorf("expected MinScoreDelta 5.0, got %f", gate.Threshold.MinScoreDelta)
		}
		if gate.Threshold.MinCompliancePctDelta != 5.0 {
			t.Errorf("expected MinCompliancePctDelta 5.0, got %f", gate.Threshold.MinCompliancePctDelta)
		}
		if !gate.Threshold.FailOnNewUnenforced {
			t.Error("expected FailOnNewUnenforced true")
		}
		if !gate.Threshold.FailOnMissingControls {
			t.Error("expected FailOnMissingControls true")
		}
	})

	t.Run("with custom threshold", func(t *testing.T) {
		custom := &RegressionThreshold{
			MinScoreDelta:         10.0,
			MinCompliancePctDelta: 10.0,
			FailOnNewUnenforced:   false,
			FailOnMissingControls: false,
		}
		gate := NewRegressionGate(custom)
		if gate.Threshold.MinScoreDelta != 10.0 {
			t.Errorf("expected MinScoreDelta 10.0, got %f", gate.Threshold.MinScoreDelta)
		}
		if gate.Threshold.FailOnNewUnenforced {
			t.Error("expected FailOnNewUnenforced false")
		}
	})
}

func TestDefaultRegressionThreshold(t *testing.T) {
	th := DefaultRegressionThreshold()
	if th.MinScoreDelta != 5.0 {
		t.Errorf("expected MinScoreDelta 5.0, got %f", th.MinScoreDelta)
	}
	if th.MinCompliancePctDelta != 5.0 {
		t.Errorf("expected MinCompliancePctDelta 5.0, got %f", th.MinCompliancePctDelta)
	}
	if !th.FailOnNewUnenforced {
		t.Error("expected FailOnNewUnenforced true")
	}
	if !th.FailOnMissingControls {
		t.Error("expected FailOnMissingControls true")
	}
}

func TestSnapshotBaseline(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	ts := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	report := sampleScanReport(bfs, ts)

	snapshot := gate.SnapshotBaseline(report)

	if snapshot.Version != RegressionVersion {
		t.Errorf("expected version %s, got %s", RegressionVersion, snapshot.Version)
	}
	if !snapshot.Timestamp.Equal(ts) {
		t.Errorf("expected timestamp %v, got %v", ts, snapshot.Timestamp)
	}
	if len(snapshot.Frameworks) != 4 {
		t.Fatalf("expected 4 frameworks, got %d", len(snapshot.Frameworks))
	}

	// Check that each framework was captured
	for _, fw := range bfs {
		fb, ok := snapshot.Frameworks[fw.Framework]
		if !ok {
			t.Errorf("framework %q missing from snapshot", fw.Framework)
			continue
		}
		if fb.Framework != fw.Framework {
			t.Errorf("expected framework %q, got %q", fw.Framework, fb.Framework)
		}
		if fb.DisplayName != fw.DisplayName {
			t.Errorf("expected displayName %q, got %q", fw.DisplayName, fb.DisplayName)
		}
		if fb.Score != fw.Score {
			t.Errorf("expected score %f, got %f", fw.Score, fb.Score)
		}
		if fb.CompliancePct != fw.CompliancePct {
			t.Errorf("expected compliancePct %f, got %f", fw.CompliancePct, fb.CompliancePct)
		}
		if fb.ControlsTotal != fw.ControlsTotal {
			t.Errorf("expected controlsTotal %d, got %d", fw.ControlsTotal, fb.ControlsTotal)
		}
		if fb.ControlsEnforced != fw.ControlsEnforced {
			t.Errorf("expected controlsEnforced %d, got %d", fw.ControlsEnforced, fb.ControlsEnforced)
		}
		if fb.Enforced != fw.Enforced {
			t.Errorf("expected enforced %v, got %v", fw.Enforced, fb.Enforced)
		}
		if fb.ReasonEnforced != fw.ReasonEnforced {
			t.Errorf("expected reasonEnforced %q, got %q", fw.ReasonEnforced, fb.ReasonEnforced)
		}
	}
}

func TestCompare_NoRegression(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	currentTime := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Current scan is identical to baseline — no regression expected
	current := sampleScanReport(bfs, currentTime)
	report := gate.Compare(current)

	if !report.Passed {
		t.Errorf("expected report to pass, but it failed; regressions: %+v", report.Regressions)
	}
	if len(report.Regressions) != 0 {
		t.Errorf("expected 0 regressions, got %d: %+v", len(report.Regressions), report.Regressions)
	}
	if !report.BaselineTimestamp.Equal(baselineTime) {
		t.Errorf("expected baseline timestamp %v, got %v", baselineTime, report.BaselineTimestamp)
	}
	if !report.CurrentTimestamp.Equal(currentTime) {
		t.Errorf("expected current timestamp %v, got %v", currentTime, report.CurrentTimestamp)
	}
}

func TestCompare_ScoreDrop(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Drop HIPAA score by 6% (85 → 79): should be a "warning" regression
	dropped := make([]FrameworkScanResult, len(bfs))
	copy(dropped, bfs)
	dropped[0] = FrameworkScanResult{
		Framework:           "hipaa",
		DisplayName:         "HIPAA",
		Enforced:            true,
		Module:              "hipaa",
		Score:               79.0, // was 85
		ControlsTotal:       20,
		ControlsEnforced:    16,   // was 17
		CompliancePct:       80.0, // was 85
		ReasonEnforced:      "module_owned",
		ImplementationReady: true,
		LastScan:            time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}

	current := sampleScanReport(dropped, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	report := gate.Compare(current)

	if report.Passed {
		t.Error("expected report to fail due to regression, but it passed")
	}

	// Should have at least a score regression for HIPAA
	found := false
	for _, r := range report.Regressions {
		if r.Framework == "hipaa" && r.Field == "score" {
			found = true
			if r.Delta < 5.0 {
				t.Errorf("expected delta >= 5.0, got %f", r.Delta)
			}
			if r.Severity != "warning" {
				t.Errorf("expected severity warning for 6%% drop, got %q", r.Severity)
			}
		}
	}
	if !found {
		t.Error("expected HIPAA score regression not found")
	}
}

func TestCompare_ScoreDropCritical(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Drop SOC 2 score by 15% (90 → 75): should be "critical"
	dropped := make([]FrameworkScanResult, len(bfs))
	copy(dropped, bfs)
	dropped[2] = FrameworkScanResult{
		Framework:           "soc2",
		DisplayName:         "SOC 2",
		Enforced:            true,
		Module:              "soc2",
		Score:               75.0, // was 90
		ControlsTotal:       30,
		ControlsEnforced:    23,    // was 27
		CompliancePct:       76.67, // was 90
		ReasonEnforced:      "module_owned",
		ImplementationReady: true,
		LastScan:            time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}

	current := sampleScanReport(dropped, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	report := gate.Compare(current)

	if report.Passed {
		t.Error("expected report to fail, but it passed")
	}

	found := false
	for _, r := range report.Regressions {
		if r.Framework == "soc2" && r.Field == "score" {
			found = true
			if r.Severity != "critical" {
				t.Errorf("expected severity critical for 15%% drop, got %q", r.Severity)
			}
			if r.Delta < 10.0 {
				t.Errorf("expected delta >= 10.0, got %f", r.Delta)
			}
		}
	}
	if !found {
		t.Error("expected SOC2 critical score regression not found")
	}
}

func TestCompare_NewUnenforcedFramework(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Make PCI-DSS no longer enforced
	currentFWs := make([]FrameworkScanResult, len(bfs))
	copy(currentFWs, bfs)
	currentFWs[1] = FrameworkScanResult{
		Framework:           "pci",
		DisplayName:         "PCI-DSS",
		Enforced:            false,
		Module:              "pci",
		Score:               0,
		ControlsTotal:       25,
		ControlsEnforced:    0,
		CompliancePct:       0,
		ReasonNotEnforced:   "module_not_owned",
		MissingModules:      []string{"pci"},
		ImplementationReady: true,
		LastScan:            time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}

	current := sampleScanReport(currentFWs, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	report := gate.Compare(current)

	if report.Passed {
		t.Error("expected report to fail due to unenforced framework, but it passed")
	}

	found := false
	for _, r := range report.Regressions {
		if r.Framework == "pci" && r.Field == "enforced" {
			found = true
			if r.Severity != "critical" {
				t.Errorf("expected severity critical, got %q", r.Severity)
			}
		}
	}
	if !found {
		t.Error("expected PCI enforced regression not found")
	}
}

func TestCompare_ImprovedScores(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Improve all scores — should NOT be a regression
	improved := []FrameworkScanResult{
		{
			Framework: "hipaa", DisplayName: "HIPAA", Enforced: true, Module: "hipaa",
			Score: 92.0, ControlsTotal: 20, ControlsEnforced: 19, CompliancePct: 95.0,
			ReasonEnforced: "module_owned", ImplementationReady: true,
			LastScan: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			Framework: "pci", DisplayName: "PCI-DSS", Enforced: true, Module: "pci",
			Score: 88.0, ControlsTotal: 25, ControlsEnforced: 23, CompliancePct: 92.0,
			ReasonEnforced: "module_owned", ImplementationReady: true,
			LastScan: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			Framework: "soc2", DisplayName: "SOC 2", Enforced: true, Module: "soc2",
			Score: 95.0, ControlsTotal: 30, ControlsEnforced: 29, CompliancePct: 96.67,
			ReasonEnforced: "module_owned", ImplementationReady: true,
			LastScan: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			Framework: "iso42001", DisplayName: "ISO 42001", Enforced: true, Module: "iso42001",
			Score: 80.0, ControlsTotal: 15, ControlsEnforced: 13, CompliancePct: 86.67,
			ReasonEnforced: "module_owned", ImplementationReady: true,
			LastScan: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
		},
	}

	current := sampleScanReport(improved, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	report := gate.Compare(current)

	if !report.Passed {
		t.Errorf("expected report to pass with improved scores, but it failed; regressions: %+v", report.Regressions)
	}
	if len(report.Regressions) != 0 {
		t.Errorf("expected 0 regressions for improved scores, got %d", len(report.Regressions))
	}
}

func TestCompare_EmptyBaseline(t *testing.T) {
	gate := NewRegressionGate(nil)
	// No baseline set — should warn but not fail
	bfs := baselineFrameworks()
	current := sampleScanReport(bfs, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))

	report := gate.Compare(current)

	if !report.Passed {
		t.Error("expected report to pass with empty baseline")
	}
	if len(report.Warnings) == 0 {
		t.Error("expected at least one warning about missing baseline")
	}
	found := false
	for _, w := range report.Warnings {
		if len(w) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected non-empty warning about missing baseline")
	}
}

func TestCheckInCI_Pass(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Same scores — should pass with exit code 0
	current := sampleScanReport(bfs, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	code, report := gate.CheckInCI(current)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !report.Passed {
		t.Error("expected report to pass")
	}
}

func TestCheckInCI_Fail(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Drop HIPAA score significantly
	dropped := make([]FrameworkScanResult, len(bfs))
	copy(dropped, bfs)
	dropped[0] = FrameworkScanResult{
		Framework:           "hipaa",
		DisplayName:         "HIPAA",
		Enforced:            true,
		Module:              "hipaa",
		Score:               70.0, // was 85
		ControlsTotal:       20,
		ControlsEnforced:    14,   // was 17
		CompliancePct:       70.0, // was 85
		ReasonEnforced:      "module_owned",
		ImplementationReady: true,
		LastScan:            time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}

	current := sampleScanReport(dropped, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	code, report := gate.CheckInCI(current)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if report.Passed {
		t.Error("expected report to fail")
	}
}

func TestLoadBaselineJSON(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	snap := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(snap)

	// Export to JSON
	data, err := gate.ExportBaselineJSON()
	if err != nil {
		t.Fatalf("ExportBaselineJSON failed: %v", err)
	}

	// Load back into a new gate
	gate2 := NewRegressionGate(nil)
	if err := gate2.LoadBaselineJSON(data); err != nil {
		t.Fatalf("LoadBaselineJSON failed: %v", err)
	}

	if gate2.Baseline == nil {
		t.Fatal("expected baseline to be set after LoadBaselineJSON")
	}
	if gate2.Baseline.Version != RegressionVersion {
		t.Errorf("expected version %s, got %s", RegressionVersion, gate2.Baseline.Version)
	}
	if len(gate2.Baseline.Frameworks) != 4 {
		t.Errorf("expected 4 frameworks, got %d", len(gate2.Baseline.Frameworks))
	}

	// Verify a specific framework round-tripped correctly
	hipaa, ok := gate2.Baseline.Frameworks["hipaa"]
	if !ok {
		t.Fatal("expected hipaa in loaded baseline")
	}
	if hipaa.Score != 85.0 {
		t.Errorf("expected hipaa score 85.0, got %f", hipaa.Score)
	}
	if hipaa.Enforced != true {
		t.Error("expected hipaa enforced true")
	}
}

func TestExportBaselineJSON(t *testing.T) {
	gate := NewRegressionGate(nil)

	t.Run("no baseline returns error", func(t *testing.T) {
		_, err := gate.ExportBaselineJSON()
		if err == nil {
			t.Error("expected error when no baseline set")
		}
	})

	t.Run("valid baseline round-trips", func(t *testing.T) {
		bfs := baselineFrameworks()
		baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		snap := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
		gate.SetBaseline(snap)

		data, err := gate.ExportBaselineJSON()
		if err != nil {
			t.Fatalf("ExportBaselineJSON failed: %v", err)
		}

		// Verify it's valid JSON
		var parsed BaselineSnapshot
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("failed to parse exported JSON: %v", err)
		}

		if parsed.Version != RegressionVersion {
			t.Errorf("expected version %s, got %s", RegressionVersion, parsed.Version)
		}
		if len(parsed.Frameworks) != 4 {
			t.Errorf("expected 4 frameworks, got %d", len(parsed.Frameworks))
		}
	})
}

func TestThresholdMinScoreDelta(t *testing.T) {
	// Use a threshold with a high MinScoreDelta so small drops are ignored
	threshold := &RegressionThreshold{
		MinScoreDelta:         15.0,
		MinCompliancePctDelta: 15.0,
		FailOnNewUnenforced:   true,
		FailOnMissingControls: true,
	}
	gate := NewRegressionGate(threshold)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Drop HIPAA by 6% — below the 15% threshold, should NOT be a regression
	dropped := make([]FrameworkScanResult, len(bfs))
	copy(dropped, bfs)
	dropped[0] = FrameworkScanResult{
		Framework:           "hipaa",
		DisplayName:         "HIPAA",
		Enforced:            true,
		Module:              "hipaa",
		Score:               79.0, // was 85, drop of 6%
		ControlsTotal:       20,
		ControlsEnforced:    17,
		CompliancePct:       85.0,
		ReasonEnforced:      "module_owned",
		ImplementationReady: true,
		LastScan:            time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}

	current := sampleScanReport(dropped, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	report := gate.Compare(current)

	// With a 15% threshold, a 6% drop should NOT be flagged
	for _, r := range report.Regressions {
		if r.Framework == "hipaa" && r.Field == "score" {
			t.Errorf("6%% drop should not be flagged with 15%% threshold, got: %+v", r)
		}
	}

	// Now drop by 20% — should be flagged
	dropped[0] = FrameworkScanResult{
		Framework:           "hipaa",
		DisplayName:         "HIPAA",
		Enforced:            true,
		Module:              "hipaa",
		Score:               65.0, // was 85, drop of 20%
		ControlsTotal:       20,
		ControlsEnforced:    13,
		CompliancePct:       65.0, // was 85, drop of 20%
		ReasonEnforced:      "module_owned",
		ImplementationReady: true,
		LastScan:            time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}

	current2 := sampleScanReport(dropped, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	report2 := gate.Compare(current2)

	if report2.Passed {
		t.Error("expected report to fail with 20%% drop")
	}
	found := false
	for _, r := range report2.Regressions {
		if r.Framework == "hipaa" && r.Field == "score" {
			found = true
			if r.Delta < 15.0 {
				t.Errorf("expected delta >= 15.0, got %f", r.Delta)
			}
		}
	}
	if !found {
		t.Error("expected HIPAA score regression for 20%% drop")
	}
}

func TestCompare_NewFrameworkInCurrent(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks() // 4 frameworks
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Add a new framework (GDPR) to current — should be a warning, not a regression
	withNew := append(bfs, FrameworkScanResult{
		Framework: "gdpr", DisplayName: "GDPR", Enforced: true, Module: "gdpr",
		Score: 70.0, ControlsTotal: 10, ControlsEnforced: 7, CompliancePct: 70.0,
		ReasonEnforced: "module_owned", ImplementationReady: true,
		LastScan: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	})

	current := sampleScanReport(withNew, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	report := gate.Compare(current)

	// Should still pass (new framework is not a regression)
	if !report.Passed {
		t.Error("expected report to pass with new framework added")
	}

	// Should have a warning about the new framework
	warningFound := false
	for _, w := range report.Warnings {
		if len(w) > 0 {
			warningFound = true
		}
	}
	if !warningFound {
		t.Error("expected warning about new framework not in baseline")
	}
}

func TestCompare_MissingControls(t *testing.T) {
	gate := NewRegressionGate(nil)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Drop controls enforced for ISO 42001 from 11 to 8 (score stays same)
	dropped := make([]FrameworkScanResult, len(bfs))
	copy(dropped, bfs)
	dropped[3] = FrameworkScanResult{
		Framework:           "iso42001",
		DisplayName:         "ISO 42001",
		Enforced:            true,
		Module:              "iso42001",
		Score:               72.0, // same
		ControlsTotal:       15,
		ControlsEnforced:    8,     // was 11
		CompliancePct:       53.33, // was 73.33
		ReasonEnforced:      "module_owned",
		ImplementationReady: true,
		LastScan:            time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}

	current := sampleScanReport(dropped, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	report := gate.Compare(current)

	if report.Passed {
		t.Error("expected report to fail due to missing controls")
	}

	found := false
	for _, r := range report.Regressions {
		if r.Framework == "iso42001" && r.Field == "controlsEnforced" {
			found = true
			if r.Severity != "critical" {
				t.Errorf("expected severity critical for missing controls, got %q", r.Severity)
			}
		}
	}
	if !found {
		t.Error("expected iso42001 controlsEnforced regression not found")
	}
}

func TestCompare_DisabledMissingControlsCheck(t *testing.T) {
	// Disable FailOnMissingControls — control drops should not be regressions
	threshold := &RegressionThreshold{
		MinScoreDelta:         5.0,
		MinCompliancePctDelta: 5.0,
		FailOnNewUnenforced:   true,
		FailOnMissingControls: false,
	}
	gate := NewRegressionGate(threshold)
	bfs := baselineFrameworks()
	baselineTime := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	baseline := gate.SnapshotBaseline(sampleScanReport(bfs, baselineTime))
	gate.SetBaseline(baseline)

	// Drop controls for ISO 42001
	dropped := make([]FrameworkScanResult, len(bfs))
	copy(dropped, bfs)
	dropped[3] = FrameworkScanResult{
		Framework:           "iso42001",
		DisplayName:         "ISO 42001",
		Enforced:            true,
		Module:              "iso42001",
		Score:               72.0,
		ControlsTotal:       15,
		ControlsEnforced:    8,     // was 11, but FailOnMissingControls is false
		CompliancePct:       53.33, // still triggers compliancePct regression
		ReasonEnforced:      "module_owned",
		ImplementationReady: true,
		LastScan:            time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	}

	current := sampleScanReport(dropped, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	report := gate.Compare(current)

	// Should NOT have controlsEnforced regression, but WILL have compliancePct
	for _, r := range report.Regressions {
		if r.Framework == "iso42001" && r.Field == "controlsEnforced" {
			t.Error("expected no controlsEnforced regression when FailOnMissingControls is false")
		}
	}
}

func TestLoadBaselineJSON_InvalidData(t *testing.T) {
	gate := NewRegressionGate(nil)
	err := gate.LoadBaselineJSON([]byte("not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON data")
	}
}
