// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Compliance Regression CI Gate (v3.6.0 P3.1)
// =========================================================================
//
// regression.go implements a compliance regression gate that compares a
// current compliance scan against a stored baseline snapshot. It detects:
//
//   1. Score drops (per-framework and overall)
//   2. New unenforced frameworks (frameworks that were enforced in the
//      baseline but are no longer enforced)
//   3. Missing controls (fewer controls enforced than baseline)
//
// The gate is designed for CI integration: CheckInCI returns an exit code
// (0 = pass, 1 = fail) and a detailed RegressionReport. Baseline snapshots
// are JSON-serializable so they can be stored as CI artifacts.
//
// Usage:
//
//	gate := compliance.NewRegressionGate(nil) // uses defaults
//	baseline := gate.SnapshotBaseline(scanReport)
//	gate.SetBaseline(baseline)
//	code, report := gate.CheckInCI(currentScanReport)
//	os.Exit(code)
//
// =========================================================================

package compliance

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// Version is the regression gate module version.
const RegressionVersion = "3.6.0"

// DefaultRegressionThreshold returns a RegressionThreshold with sensible
// defaults: 5% minimum score delta, 5% minimum compliance delta, and
// fail-on for new unenforced frameworks and missing controls.
func DefaultRegressionThreshold() *RegressionThreshold {
	return &RegressionThreshold{
		MinScoreDelta:         5.0,
		MinCompliancePctDelta: 5.0,
		FailOnNewUnenforced:   true,
		FailOnMissingControls: true,
	}
}

// RegressionThreshold configures how sensitive the regression gate is.
// Only deltas exceeding these thresholds are reported as regressions.
type RegressionThreshold struct {
	// MinScoreDelta is the minimum per-framework score drop (in percentage
	// points) to report as a regression. Default 5.0.
	MinScoreDelta float64 `json:"minScoreDelta"`
	// MinCompliancePctDelta is the minimum per-framework compliance pct
	// drop (in percentage points) to report as a regression. Default 5.0.
	MinCompliancePctDelta float64 `json:"minCompliancePctDelta"`
	// FailOnNewUnenforced, when true, marks any framework that was
	// enforced in the baseline but is no longer enforced as a critical
	// regression. Default true.
	FailOnNewUnenforced bool `json:"failOnNewUnenforced"`
	// FailOnMissingControls, when true, marks any reduction in enforced
	// control count as a regression. Default true.
	FailOnMissingControls bool `json:"failOnMissingControls"`
}

// FrameworkBaseline captures a single framework's compliance posture at
// the time the baseline snapshot was taken.
type FrameworkBaseline struct {
	// Framework is the canonical identifier (e.g., "hipaa", "pci").
	Framework string `json:"framework"`
	// DisplayName is the human-readable name (e.g., "HIPAA").
	DisplayName string `json:"displayName"`
	// Score is the compliance score 0-100 at baseline time.
	Score float64 `json:"score"`
	// CompliancePct is ControlsEnforced / ControlsTotal * 100.
	CompliancePct float64 `json:"compliancePct"`
	// ControlsTotal is the total number of controls in the framework.
	ControlsTotal int `json:"controlsTotal"`
	// ControlsEnforced is the number of passing controls at baseline time.
	ControlsEnforced int `json:"controlsEnforced"`
	// Enforced is true if the framework was enforced at baseline time.
	Enforced bool `json:"enforced"`
	// ReasonEnforced is the enforcement reason (e.g., "module_owned",
	// "framework_free"). Empty if Enforced is false.
	ReasonEnforced string `json:"reasonEnforced,omitempty"`
	// ReasonNotEnforced is the reason the framework was not enforced.
	// Empty if Enforced is true.
	ReasonNotEnforced string `json:"reasonNotEnforced,omitempty"`
}

// BaselineSnapshot captures the complete compliance posture of all
// frameworks at a point in time. It is the baseline against which future
// scans are compared.
type BaselineSnapshot struct {
	// Version is the schema version of the baseline snapshot.
	Version string `json:"version"`
	// Timestamp is when the baseline was captured.
	Timestamp time.Time `json:"timestamp"`
	// Frameworks maps the canonical framework identifier to its baseline.
	Frameworks map[string]FrameworkBaseline `json:"frameworks"`
}

// RegressionDetail describes a single regression detected between the
// current scan and the baseline.
type RegressionDetail struct {
	// Framework is the canonical framework identifier.
	Framework string `json:"framework"`
	// Field is the field that regressed (e.g., "score", "compliancePct",
	// "controlsEnforced", "enforced").
	Field string `json:"field"`
	// OldValue is the baseline value (formatted as string).
	OldValue string `json:"oldValue"`
	// NewValue is the current value (formatted as string).
	NewValue string `json:"newValue"`
	// Delta is the magnitude of the change (always positive for regressions).
	Delta float64 `json:"delta"`
	// Severity is "critical" (score drop >10%), "warning" (>5%), or "info".
	Severity string `json:"severity"`
}

// RegressionReport is the result of comparing a current scan against the
// baseline. Passed is true if no regressions exceed the configured
// thresholds.
type RegressionReport struct {
	// Passed is true if no regressions were detected that exceed thresholds.
	Passed bool `json:"passed"`
	// Regressions lists every detected regression with details.
	Regressions []RegressionDetail `json:"regressions,omitempty"`
	// Warnings lists informational messages (e.g., empty baseline, new
	// frameworks not in baseline).
	Warnings []string `json:"warnings,omitempty"`
	// BaselineTimestamp is when the baseline was captured.
	BaselineTimestamp time.Time `json:"baselineTimestamp"`
	// CurrentTimestamp is the GeneratedAt from the current scan.
	CurrentTimestamp time.Time `json:"currentTimestamp"`
}

// RegressionGate compares a current ScanReport against a stored baseline
// and produces a RegressionReport. It is the primary entry point for
// CI compliance gates.
type RegressionGate struct {
	// Baseline is the stored baseline snapshot. May be nil.
	Baseline *BaselineSnapshot `json:"baseline"`
	// Threshold configures regression detection sensitivity.
	Threshold *RegressionThreshold `json:"threshold"`
}

// NewRegressionGate creates a RegressionGate with the given threshold.
// If threshold is nil, DefaultRegressionThreshold is used.
func NewRegressionGate(threshold *RegressionThreshold) *RegressionGate {
	if threshold == nil {
		threshold = DefaultRegressionThreshold()
	}
	return &RegressionGate{
		Threshold: threshold,
	}
}

// SetBaseline replaces the gate's baseline snapshot.
func (g *RegressionGate) SetBaseline(snapshot *BaselineSnapshot) {
	g.Baseline = snapshot
}

// LoadBaselineJSON deserializes a baseline snapshot from JSON bytes and
// sets it as the gate's baseline. Returns an error if the JSON is invalid.
func (g *RegressionGate) LoadBaselineJSON(data []byte) error {
	var snapshot BaselineSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("regression: load baseline JSON: %w", err)
	}
	g.Baseline = &snapshot
	return nil
}

// ExportBaselineJSON serializes the current baseline to JSON bytes.
// Returns an error if no baseline is set or serialization fails.
func (g *RegressionGate) ExportBaselineJSON() ([]byte, error) {
	if g.Baseline == nil {
		return nil, fmt.Errorf("regression: no baseline set")
	}
	data, err := json.MarshalIndent(g.Baseline, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("regression: export baseline JSON: %w", err)
	}
	return data, nil
}

// SnapshotBaseline creates a BaselineSnapshot from a ScanReport. This is
// used to capture the current compliance posture as a new baseline.
func (g *RegressionGate) SnapshotBaseline(report *ScanReport) *BaselineSnapshot {
	frameworks := make(map[string]FrameworkBaseline, len(report.Frameworks))
	for _, fw := range report.Frameworks {
		frameworks[fw.Framework] = FrameworkBaseline{
			Framework:         fw.Framework,
			DisplayName:       fw.DisplayName,
			Score:             fw.Score,
			CompliancePct:     fw.CompliancePct,
			ControlsTotal:     fw.ControlsTotal,
			ControlsEnforced:  fw.ControlsEnforced,
			Enforced:          fw.Enforced,
			ReasonEnforced:    fw.ReasonEnforced,
			ReasonNotEnforced: fw.ReasonNotEnforced,
		}
	}
	return &BaselineSnapshot{
		Version:    RegressionVersion,
		Timestamp:  report.GeneratedAt,
		Frameworks: frameworks,
	}
}

// severityForScoreDelta returns the severity string for a score drop
// of the given magnitude (in percentage points).
func severityForScoreDelta(delta float64) string {
	if delta > 10.0 {
		return "critical"
	}
	if delta > 5.0 {
		return "warning"
	}
	return "info"
}

// addScoreRegression checks if a score drop exceeds the threshold and
// adds a RegressionDetail if it does.
func (g *RegressionGate) addScoreRegression(regressions *[]RegressionDetail, framework string, oldScore, newScore float64) {
	delta := oldScore - newScore
	if delta <= 0 {
		return // not a regression
	}
	// Round to avoid floating-point noise
	delta = math.Round(delta*100) / 100
	if delta < g.Threshold.MinScoreDelta {
		return
	}
	*regressions = append(*regressions, RegressionDetail{
		Framework: framework,
		Field:     "score",
		OldValue:  fmt.Sprintf("%.2f", oldScore),
		NewValue:  fmt.Sprintf("%.2f", newScore),
		Delta:     delta,
		Severity:  severityForScoreDelta(delta),
	})
}

// addCompliancePctRegression checks if a compliance percentage drop exceeds
// the threshold and adds a RegressionDetail if it does.
func (g *RegressionGate) addCompliancePctRegression(regressions *[]RegressionDetail, framework string, oldPct, newPct float64) {
	delta := oldPct - newPct
	if delta <= 0 {
		return
	}
	delta = math.Round(delta*100) / 100
	if delta < g.Threshold.MinCompliancePctDelta {
		return
	}
	*regressions = append(*regressions, RegressionDetail{
		Framework: framework,
		Field:     "compliancePct",
		OldValue:  fmt.Sprintf("%.2f", oldPct),
		NewValue:  fmt.Sprintf("%.2f", newPct),
		Delta:     delta,
		Severity:  severityForScoreDelta(delta),
	})
}

// addControlsRegression checks if a drop in enforced controls count
// constitutes a regression.
func (g *RegressionGate) addControlsRegression(regressions *[]RegressionDetail, framework string, oldCount, newCount int) {
	if newCount >= oldCount {
		return
	}
	if !g.Threshold.FailOnMissingControls {
		return
	}
	delta := float64(oldCount - newCount)
	*regressions = append(*regressions, RegressionDetail{
		Framework: framework,
		Field:     "controlsEnforced",
		OldValue:  fmt.Sprintf("%d", oldCount),
		NewValue:  fmt.Sprintf("%d", newCount),
		Delta:     delta,
		Severity:  "critical", // any control loss is critical
	})
}

// addUnenforcedRegression records that a previously enforced framework
// is no longer enforced.
func (g *RegressionGate) addUnenforcedRegression(regressions *[]RegressionDetail, framework string, baseline FrameworkBaseline) {
	if !g.Threshold.FailOnNewUnenforced {
		return
	}
	*regressions = append(*regressions, RegressionDetail{
		Framework: framework,
		Field:     "enforced",
		OldValue:  "true",
		NewValue:  "false",
		Delta:     100, // total loss of enforcement
		Severity:  "critical",
	})
}

// Compare produces a RegressionReport by comparing the current ScanReport
// against the stored baseline. If no baseline is set, the report will
// contain a warning but will not fail.
func (g *RegressionGate) Compare(current *ScanReport) *RegressionReport {
	report := &RegressionReport{
		Passed:            true,
		BaselineTimestamp: time.Time{},
		CurrentTimestamp:  current.GeneratedAt,
	}

	if g.Baseline == nil || len(g.Baseline.Frameworks) == 0 {
		report.Warnings = append(report.Warnings,
			"no baseline set; cannot detect regressions, all checks pass by default")
		return report
	}

	report.BaselineTimestamp = g.Baseline.Timestamp

	var regressions []RegressionDetail
	var warnings []string

	// Index current frameworks for lookup
	currentFWs := make(map[string]FrameworkScanResult, len(current.Frameworks))
	for _, fw := range current.Frameworks {
		currentFWs[fw.Framework] = fw
	}

	// Check every baseline framework against current
	for fwID, baselineFW := range g.Baseline.Frameworks {
		currentFW, exists := currentFWs[fwID]

		if !exists {
			// Framework was in baseline but missing from current scan
			warnings = append(warnings,
				fmt.Sprintf("framework %q present in baseline but missing from current scan", baselineFW.DisplayName))
			continue
		}

		// Check if a previously enforced framework is no longer enforced
		if baselineFW.Enforced && !currentFW.Enforced {
			g.addUnenforcedRegression(&regressions, fwID, baselineFW)
		}

		// Only compare scores/compliance if the framework was enforced in baseline
		if baselineFW.Enforced {
			g.addScoreRegression(&regressions, fwID, baselineFW.Score, currentFW.Score)
			g.addCompliancePctRegression(&regressions, fwID, baselineFW.CompliancePct, currentFW.CompliancePct)
			g.addControlsRegression(&regressions, fwID, baselineFW.ControlsEnforced, currentFW.ControlsEnforced)
		}
	}

	// Note new frameworks not in baseline (informational, not a regression)
	for fwID, currentFW := range currentFWs {
		if _, exists := g.Baseline.Frameworks[fwID]; !exists {
			warnings = append(warnings,
				fmt.Sprintf("framework %q found in current scan but not in baseline (new framework)", currentFW.DisplayName))
		}
	}

	report.Regressions = regressions
	report.Warnings = warnings

	if len(regressions) > 0 {
		report.Passed = false
	}

	return report
}

// CheckInCI runs a Compare and returns a CI-friendly exit code along with
// the regression report. Exit code 0 means the scan passed (no regressions),
// exit code 1 means regressions were detected.
func (g *RegressionGate) CheckInCI(current *ScanReport) (int, *RegressionReport) {
	report := g.Compare(current)
	if report.Passed {
		return 0, report
	}
	return 1, report
}
