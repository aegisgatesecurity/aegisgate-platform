// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CCM Drift Detector
// =========================================================================
//
// CCMDriftDetector compares two consecutive ScanReport instances and
// returns the list of regressions - frameworks whose compliance score
// or compliance pct has dropped between scans.
//
// v1 scope:
//   - Framework-level signals only (OverallScore, OverallCompliancePct,
//     Enforced flag)
//   - Threshold: 5 percentage points (configurable per-regression type)
//   - Per-control detection is v2 (would need access to individual
//     control statuses which aren't in the public ScanReport type)
//
// The detector is stateless - all state comes from the two reports
// being compared. This makes it easy to test and to run ad-hoc diffs.
// =========================================================================

package compliance

import (
	"sort"
)

// CCMRegressionSeverity is the severity classification of a regression.
type CCMRegressionSeverity string

const (
	CCMSeverityCritical CCMRegressionSeverity = "critical"
	CCMSeverityHigh     CCMRegressionSeverity = "high"
	CCMSeverityMedium   CCMRegressionSeverity = "medium"
	CCMSeverityLow      CCMRegressionSeverity = "low"
)

// CCMDriftThresholdPct is the minimum drop (in percentage points)
// that constitutes a regression. Smaller drops are considered noise.
// Exposed as a var so tests can override it.
var CCMDriftThresholdPct = 5.0

// CCMRegression is a single detected regression between two scans.
// Fields map directly to the public ScanReport types (ScanReport
// and FrameworkScanResult) for ease of serialization to JSON.
type CCMRegression struct {
	// Framework is the canonical framework ID (e.g., "hipaa", "pci").
	Framework string `json:"framework"`

	// FrameworkName is the human-readable name (e.g., "HIPAA").
	FrameworkName string `json:"frameworkName"`

	// PriorScore is the framework's score before the change.
	PriorScore float64 `json:"priorScore"`

	// CurrentScore is the framework's score after the change.
	CurrentScore float64 `json:"currentScore"`

	// ScoreDelta is CurrentScore - PriorScore. Negative = regression.
	ScoreDelta float64 `json:"scoreDelta"`

	// PriorPct is the framework's compliance pct before.
	PriorPct float64 `json:"priorPct"`

	// CurrentPct is the framework's compliance pct after.
	CurrentPct float64 `json:"currentPct"`

	// PctDelta is CurrentPct - PriorPct. Negative = regression.
	PctDelta float64 `json:"pctDelta"`

	// Severity classifies the regression magnitude.
	Severity CCMRegressionSeverity `json:"severity"`

	// Reason describes why this is a regression (score drop, pct drop,
	// or enforcement loss).
	Reason string `json:"reason"`
}

// CCMDriftDetector is stateless. One instance is shared across all
// schedulers. Zero value is ready to use.
type CCMDriftDetector struct{}

// NewCCMDriftDetector returns a new detector. Equivalent to the zero
// value; exists for API symmetry.
func NewCCMDriftDetector() *CCMDriftDetector {
	return &CCMDriftDetector{}
}

// Compare returns the list of regressions between prior and current.
// A regression is one of:
//   - Score dropped by >= CCMDriftThresholdPct points
//   - CompliancePct dropped by >= CCMDriftThresholdPct points
//   - Framework was Enforced in prior but not in current (enforcement loss)
//
// The returned slice is sorted by severity (critical first) then by
// score delta (most negative first). Improvements (score went UP) are
// NOT returned - they're not regressions.
//
// Nil/empty inputs return nil (no regressions).
func (d *CCMDriftDetector) Compare(prior, current *ScanReport) []CCMRegression {
	if prior == nil || current == nil {
		return nil
	}

	// Index current by framework ID for quick lookup.
	currentByID := make(map[string]*FrameworkScanResult, len(current.Frameworks))
	for i := range current.Frameworks {
		fw := &current.Frameworks[i]
		currentByID[fw.Framework] = fw
	}

	var regressions []CCMRegression

	// Walk prior frameworks; compare to current.
	for i := range prior.Frameworks {
		priorFw := &prior.Frameworks[i]
		currentFw, exists := currentByID[priorFw.Framework]
		if !exists {
			// Framework disappeared - critical regression.
			regressions = append(regressions, CCMRegression{
				Framework:     priorFw.Framework,
				FrameworkName: priorFw.DisplayName,
				PriorScore:    priorFw.Score,
				CurrentScore:  0,
				ScoreDelta:    -priorFw.Score,
				PriorPct:      priorFw.CompliancePct,
				CurrentPct:    0,
				PctDelta:      -priorFw.CompliancePct,
				Severity:      CCMSeverityCritical,
				Reason:        "framework_disappeared",
			})
			continue
		}

		// Score drop.
		scoreDelta := currentFw.Score - priorFw.Score
		if scoreDelta <= -CCMDriftThresholdPct {
			regressions = append(regressions, CCMRegression{
				Framework:     priorFw.Framework,
				FrameworkName: priorFw.DisplayName,
				PriorScore:    priorFw.Score,
				CurrentScore:  currentFw.Score,
				ScoreDelta:    scoreDelta,
				PriorPct:      priorFw.CompliancePct,
				CurrentPct:    currentFw.CompliancePct,
				PctDelta:      currentFw.CompliancePct - priorFw.CompliancePct,
				Severity:      d.classifySeverity(scoreDelta),
				Reason:        "score_drop",
			})
			continue
		}

		// Compliance pct drop.
		pctDelta := currentFw.CompliancePct - priorFw.CompliancePct
		if pctDelta <= -CCMDriftThresholdPct {
			regressions = append(regressions, CCMRegression{
				Framework:     priorFw.Framework,
				FrameworkName: priorFw.DisplayName,
				PriorScore:    priorFw.Score,
				CurrentScore:  currentFw.Score,
				ScoreDelta:    currentFw.Score - priorFw.Score,
				PriorPct:      priorFw.CompliancePct,
				CurrentPct:    currentFw.CompliancePct,
				PctDelta:      pctDelta,
				Severity:      d.classifySeverity(pctDelta),
				Reason:        "compliance_pct_drop",
			})
			continue
		}

		// Enforcement loss: enforced in prior, not in current.
		if priorFw.Enforced && !currentFw.Enforced {
			regressions = append(regressions, CCMRegression{
				Framework:     priorFw.Framework,
				FrameworkName: priorFw.DisplayName,
				PriorScore:    priorFw.Score,
				CurrentScore:  currentFw.Score,
				ScoreDelta:    0,
				PriorPct:      priorFw.CompliancePct,
				CurrentPct:    currentFw.CompliancePct,
				PctDelta:      0,
				Severity:      CCMSeverityHigh,
				Reason:        "enforcement_lost",
			})
		}
	}

	// Sort by severity (critical first) then by score delta (worst first).
	sort.SliceStable(regressions, func(i, j int) bool {
		ri, rj := regressions[i], regressions[j]
		if ri.Severity != rj.Severity {
			return severityOrder(ri.Severity) < severityOrder(rj.Severity)
		}
		return ri.ScoreDelta < rj.ScoreDelta
	})

	return regressions
}

// classifySeverity maps a delta (negative = regression) to a severity.
// Thresholds:
//   - delta <= -20: critical
//   - delta <= -10: high
//   - delta <= -5:  medium
//   - else:         low
func (d *CCMDriftDetector) classifySeverity(delta float64) CCMRegressionSeverity {
	switch {
	case delta <= -20:
		return CCMSeverityCritical
	case delta <= -10:
		return CCMSeverityHigh
	case delta <= -CCMDriftThresholdPct:
		return CCMSeverityMedium
	default:
		return CCMSeverityLow
	}
}

// severityOrder returns a numeric ordering for severity strings.
// Lower = more severe (so sort ASC puts critical first).
func severityOrder(s CCMRegressionSeverity) int {
	switch s {
	case CCMSeverityCritical:
		return 0
	case CCMSeverityHigh:
		return 1
	case CCMSeverityMedium:
		return 2
	case CCMSeverityLow:
		return 3
	default:
		return 4
	}
}
