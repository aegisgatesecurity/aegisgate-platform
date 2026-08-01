// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Shadow Mode Metrics Tests
// =========================================================================
//
// Tests for ComputeMetrics and the running metrics tracker, verifying:
//   - Precision = TP / (TP + FP)
//   - Recall = TP / (TP + FN)
//   - F1 = 2 * Precision * Recall / (Precision + Recall)
//   - AUROC using trapezoidal approximation from TPR/FPR
//   - Edge cases: zero TP, zero FP, all same predictions
//   - Metrics update correctly as shadow log entries are added
//
// =========================================================================

package ml

import (
	"math"
	"testing"
)

// alwaysThreat is a ground-truth function that always returns true.
func alwaysThreat(_ ShadowLogEntry) bool { return true }

// alwaysBenign is a ground-truth function that always returns false.
func alwaysBenign(_ ShadowLogEntry) bool { return false }

// mixedGroundTruth returns true for even-indexed entries and false for odd.
func mixedGroundTruth(i int) func(ShadowLogEntry) bool {
	return func(_ ShadowLogEntry) bool { return i%2 == 0 }
}

func TestComputeMetrics_EmptyEntries(t *testing.T) {
	m := ComputeMetrics(nil, alwaysThreat)
	if m.TruePositives != 0 {
		t.Errorf("expected 0 TP, got %d", m.TruePositives)
	}
	if m.Precision != 0 {
		t.Errorf("expected 0 precision, got %f", m.Precision)
	}
	if m.Recall != 0 {
		t.Errorf("expected 0 recall, got %f", m.Recall)
	}
	if m.F1Score != 0 {
		t.Errorf("expected 0 F1, got %f", m.F1Score)
	}
}

func TestComputeMetrics_AllTruePositives(t *testing.T) {
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5},
		{Score: 0.8, IsThreat: true, Threshold: 0.5},
		{Score: 0.7, IsThreat: true, Threshold: 0.5},
	}
	m := ComputeMetrics(entries, alwaysThreat)
	if m.TruePositives != 3 {
		t.Errorf("expected 3 TP, got %d", m.TruePositives)
	}
	if m.FalsePositives != 0 {
		t.Errorf("expected 0 FP, got %d", m.FalsePositives)
	}
	if m.FalseNegatives != 0 {
		t.Errorf("expected 0 FN, got %d", m.FalseNegatives)
	}
	if m.TrueNegatives != 0 {
		t.Errorf("expected 0 TN, got %d", m.TrueNegatives)
	}
	if math.Abs(m.Precision-1.0) > 1e-9 {
		t.Errorf("expected precision 1.0, got %f", m.Precision)
	}
	if math.Abs(m.Recall-1.0) > 1e-9 {
		t.Errorf("expected recall 1.0, got %f", m.Recall)
	}
	if math.Abs(m.F1Score-1.0) > 1e-9 {
		t.Errorf("expected F1 1.0, got %f", m.F1Score)
	}
}

func TestComputeMetrics_AllFalsePositives(t *testing.T) {
	// All predicted as threats but ground truth is benign.
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5},
		{Score: 0.8, IsThreat: true, Threshold: 0.5},
	}
	m := ComputeMetrics(entries, alwaysBenign)
	if m.TruePositives != 0 {
		t.Errorf("expected 0 TP, got %d", m.TruePositives)
	}
	if m.FalsePositives != 2 {
		t.Errorf("expected 2 FP, got %d", m.FalsePositives)
	}
	if m.Precision != 0 {
		t.Errorf("expected precision 0, got %f", m.Precision)
	}
	// Recall = TP/(TP+FN) = 0/(0+0) = 0 (safe div)
	if m.Recall != 0 {
		t.Errorf("expected recall 0, got %f", m.Recall)
	}
}

func TestComputeMetrics_AllFalseNegatives(t *testing.T) {
	// All predicted as benign but ground truth is threat.
	entries := []ShadowLogEntry{
		{Score: 0.1, IsThreat: false, Threshold: 0.5},
		{Score: 0.2, IsThreat: false, Threshold: 0.5},
	}
	m := ComputeMetrics(entries, alwaysThreat)
	if m.TruePositives != 0 {
		t.Errorf("expected 0 TP, got %d", m.TruePositives)
	}
	if m.FalseNegatives != 2 {
		t.Errorf("expected 2 FN, got %d", m.FalseNegatives)
	}
	// Precision = 0/(0+0) = 0
	if m.Precision != 0 {
		t.Errorf("expected precision 0, got %f", m.Precision)
	}
	// Recall = 0/(0+2) = 0
	if m.Recall != 0 {
		t.Errorf("expected recall 0, got %f", m.Recall)
	}
}

func TestComputeMetrics_MixedPredictions(t *testing.T) {
	// 2 TP, 1 FP, 1 FN, 1 TN
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5},  // TP (predicted threat, actual threat)
		{Score: 0.8, IsThreat: true, Threshold: 0.5},  // TP
		{Score: 0.7, IsThreat: true, Threshold: 0.5},  // FP (predicted threat, actual benign)
		{Score: 0.2, IsThreat: false, Threshold: 0.5}, // FN (predicted benign, actual threat)
		{Score: 0.1, IsThreat: false, Threshold: 0.5}, // TN (predicted benign, actual benign)
	}

	// Ground truth: entries 0,1,3 are threats; entries 2,4 are benign
	isThreat := func(e ShadowLogEntry) bool {
		switch e.Score {
		case 0.9, 0.8, 0.2:
			return true // actual threats
		default:
			return false // actual benign
		}
	}

	m := ComputeMetrics(entries, isThreat)
	if m.TruePositives != 2 {
		t.Errorf("expected 2 TP, got %d", m.TruePositives)
	}
	if m.FalsePositives != 1 {
		t.Errorf("expected 1 FP, got %d", m.FalsePositives)
	}
	if m.FalseNegatives != 1 {
		t.Errorf("expected 1 FN, got %d", m.FalseNegatives)
	}
	if m.TrueNegatives != 1 {
		t.Errorf("expected 1 TN, got %d", m.TrueNegatives)
	}

	// Precision = 2 / (2+1) = 0.6667
	expectedPrecision := 2.0 / 3.0
	if math.Abs(m.Precision-expectedPrecision) > 1e-6 {
		t.Errorf("expected precision %f, got %f", expectedPrecision, m.Precision)
	}

	// Recall = 2 / (2+1) = 0.6667
	expectedRecall := 2.0 / 3.0
	if math.Abs(m.Recall-expectedRecall) > 1e-6 {
		t.Errorf("expected recall %f, got %f", expectedRecall, m.Recall)
	}

	// F1 = 2 * 0.6667 * 0.6667 / (0.6667 + 0.6667) = 0.6667
	expectedF1 := 2.0 * expectedPrecision * expectedRecall / (expectedPrecision + expectedRecall)
	if math.Abs(m.F1Score-expectedF1) > 1e-6 {
		t.Errorf("expected F1 %f, got %f", expectedF1, m.F1Score)
	}
}

func TestComputeMetrics_ZeroTPZeroFP(t *testing.T) {
	// All predictions are negative (IsThreat=false), all actual benign.
	entries := []ShadowLogEntry{
		{Score: 0.1, IsThreat: false, Threshold: 0.5},
		{Score: 0.2, IsThreat: false, Threshold: 0.5},
	}
	m := ComputeMetrics(entries, alwaysBenign)
	if m.TruePositives != 0 {
		t.Errorf("expected 0 TP, got %d", m.TruePositives)
	}
	if m.FalsePositives != 0 {
		t.Errorf("expected 0 FP, got %d", m.FalsePositives)
	}
	if m.Precision != 0 {
		t.Errorf("expected precision 0 (undefined), got %f", m.Precision)
	}
	if m.Recall != 0 {
		t.Errorf("expected recall 0 (undefined), got %f", m.Recall)
	}
	if m.F1Score != 0 {
		t.Errorf("expected F1 0 (undefined), got %f", m.F1Score)
	}
}

func TestComputeMetrics_AUROC_PerfectClassifier(t *testing.T) {
	// Perfect classifier: all threats score above threshold, all benign below.
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5, ModelVersion: "v1"},
		{Score: 0.8, IsThreat: true, Threshold: 0.5, ModelVersion: "v1"},
		{Score: 0.2, IsThreat: false, Threshold: 0.5, ModelVersion: "v1"},
		{Score: 0.1, IsThreat: false, Threshold: 0.5, ModelVersion: "v1"},
	}
	isThreat := func(e ShadowLogEntry) bool {
		return e.Score >= 0.7 // entries with score >= 0.7 are actual threats
	}
	m := ComputeMetrics(entries, isThreat)
	// AUROC should be close to 1.0 for a perfect classifier
	if m.AUROC < 0.9 {
		t.Errorf("expected AUROC close to 1.0 for perfect classifier, got %f", m.AUROC)
	}
}

func TestComputeMetrics_AUROC_RandomClassifier(t *testing.T) {
	// Random classifier: scores don't discriminate.
	entries := []ShadowLogEntry{
		{Score: 0.5, IsThreat: true, Threshold: 0.4, ModelVersion: "v1"},
		{Score: 0.4, IsThreat: false, Threshold: 0.4, ModelVersion: "v1"},
	}
	// Alternate ground truth
	isThreat := func(e ShadowLogEntry) bool {
		return e.Score == 0.5
	}
	m := ComputeMetrics(entries, isThreat)
	// AUROC should be between 0 and 1 for any valid classifier
	if m.AUROC < 0 || m.AUROC > 1 {
		t.Errorf("AUROC should be between 0 and 1, got %f", m.AUROC)
	}
}

func TestComputeMetrics_TotalPredictions(t *testing.T) {
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5},
		{Score: 0.1, IsThreat: false, Threshold: 0.5},
	}
	m := ComputeMetrics(entries, alwaysThreat)
	if m.TotalPredictions != 2 {
		t.Errorf("expected TotalPredictions=2, got %d", m.TotalPredictions)
	}
}

func TestSafeDiv(t *testing.T) {
	tests := []struct {
		a, b, expected float64
	}{
		{1.0, 2.0, 0.5},
		{0.0, 5.0, 0.0},
		{5.0, 0.0, 0.0},
		{3.0, 3.0, 1.0},
	}
	for _, tt := range tests {
		result := safeDiv(tt.a, tt.b)
		if math.Abs(result-tt.expected) > 1e-9 {
			t.Errorf("safeDiv(%f, %f) = %f, want %f", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestSafeF1(t *testing.T) {
	tests := []struct {
		precision, recall, expected float64
	}{
		{1.0, 1.0, 1.0},
		{0.5, 0.5, 0.5},
		{0.0, 0.0, 0.0}, // undefined → 0
		{1.0, 0.0, 0.0}, // F1 = 0 when recall is 0
		{0.0, 1.0, 0.0}, // F1 = 0 when precision is 0
	}
	for _, tt := range tests {
		result := safeF1(tt.precision, tt.recall)
		if math.Abs(result-tt.expected) > 1e-9 {
			t.Errorf("safeF1(%f, %f) = %f, want %f", tt.precision, tt.recall, result, tt.expected)
		}
	}
}

func TestComputeMetrics_PrecisionFormula(t *testing.T) {
	// Precision = TP / (TP + FP)
	// TP=4, FP=1 → Precision = 4/5 = 0.8
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5},   // TP
		{Score: 0.8, IsThreat: true, Threshold: 0.5},   // TP
		{Score: 0.7, IsThreat: true, Threshold: 0.5},   // TP
		{Score: 0.6, IsThreat: true, Threshold: 0.5},   // TP
		{Score: 0.55, IsThreat: true, Threshold: 0.5},  // FP
		{Score: 0.2, IsThreat: false, Threshold: 0.5},  // TN
		{Score: 0.15, IsThreat: false, Threshold: 0.5}, // TN
	}
	isThreat := func(e ShadowLogEntry) bool {
		return e.Score >= 0.6 // 4 actual threats (0.9, 0.8, 0.7, 0.6), 3 benign (0.55, 0.2, 0.15)
	}
	m := ComputeMetrics(entries, isThreat)
	if m.TruePositives != 4 {
		t.Errorf("expected 4 TP, got %d", m.TruePositives)
	}
	if m.FalsePositives != 1 {
		t.Errorf("expected 1 FP, got %d", m.FalsePositives)
	}
	expectedPrecision := 4.0 / 5.0
	if math.Abs(m.Precision-expectedPrecision) > 1e-9 {
		t.Errorf("expected precision %f, got %f", expectedPrecision, m.Precision)
	}
}

func TestComputeMetrics_RecallFormula(t *testing.T) {
	// Recall = TP / (TP + FN)
	// TP=3, FN=2 → Recall = 3/5 = 0.6
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5},  // TP
		{Score: 0.8, IsThreat: true, Threshold: 0.5},  // TP
		{Score: 0.7, IsThreat: true, Threshold: 0.5},  // TP
		{Score: 0.3, IsThreat: false, Threshold: 0.5}, // FN (predicted benign, actual threat)
		{Score: 0.2, IsThreat: false, Threshold: 0.5}, // FN (predicted benign, actual threat)
	}
	isThreat := func(e ShadowLogEntry) bool {
		// All 5 entries are actual threats
		return true
	}
	m := ComputeMetrics(entries, isThreat)
	if m.TruePositives != 3 {
		t.Errorf("expected 3 TP, got %d", m.TruePositives)
	}
	if m.FalseNegatives != 2 {
		t.Errorf("expected 2 FN, got %d", m.FalseNegatives)
	}
	expectedRecall := 3.0 / 5.0
	if math.Abs(m.Recall-expectedRecall) > 1e-9 {
		t.Errorf("expected recall %f, got %f", expectedRecall, m.Recall)
	}
}

func TestComputeMetrics_F1Formula(t *testing.T) {
	// F1 = 2 * P * R / (P + R)
	// With TP=2, FP=1, FN=1: P=2/3≈0.667, R=2/3≈0.667, F1=2/3≈0.667
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5},   // TP: actual threat, predicted threat
		{Score: 0.8, IsThreat: true, Threshold: 0.5},   // TP: actual threat, predicted threat
		{Score: 0.6, IsThreat: true, Threshold: 0.5},   // FP: actual benign (score<0.7), predicted threat
		{Score: 0.75, IsThreat: false, Threshold: 0.5}, // FN: actual threat (score>=0.7), predicted benign
	}
	isThreat := func(e ShadowLogEntry) bool {
		return e.Score >= 0.7 // 3 actual threats: 0.9, 0.8, 0.75
	}
	m := ComputeMetrics(entries, isThreat)
	if m.TruePositives != 2 {
		t.Errorf("expected 2 TP, got %d", m.TruePositives)
	}
	if m.FalsePositives != 1 {
		t.Errorf("expected 1 FP, got %d", m.FalsePositives)
	}
	if m.FalseNegatives != 1 {
		t.Errorf("expected 1 FN, got %d", m.FalseNegatives)
	}
	p := float64(2) / float64(3)
	r := float64(2) / float64(3)
	expectedF1 := 2 * p * r / (p + r)
	if math.Abs(m.F1Score-expectedF1) > 1e-6 {
		t.Errorf("expected F1 %f, got %f", expectedF1, m.F1Score)
	}
}

func TestUpdateRunningMetrics(t *testing.T) {
	cm := NewCalibrationManager(DetectorConfig{
		Enabled:    true,
		ShadowMode: true,
		Threshold:  0.5,
	})

	// Add shadow predictions one by one and verify running metrics.
	entry1 := ShadowLogEntry{Score: 0.9, IsThreat: true, Threshold: 0.5, ModelVersion: "v1"}
	cm.UpdateRunningMetrics(entry1, true) // TP

	m := cm.GetRunningMetrics()
	if m.TruePositives != 1 {
		t.Errorf("expected 1 TP, got %d", m.TruePositives)
	}
	if m.TotalPredictions != 1 {
		t.Errorf("expected TotalPredictions=1, got %d", m.TotalPredictions)
	}

	// Add a false positive.
	entry2 := ShadowLogEntry{Score: 0.6, IsThreat: true, Threshold: 0.5, ModelVersion: "v1"}
	cm.UpdateRunningMetrics(entry2, false) // FP

	m = cm.GetRunningMetrics()
	if m.TruePositives != 1 {
		t.Errorf("expected 1 TP, got %d", m.TruePositives)
	}
	if m.FalsePositives != 1 {
		t.Errorf("expected 1 FP, got %d", m.FalsePositives)
	}
	if m.TotalPredictions != 2 {
		t.Errorf("expected TotalPredictions=2, got %d", m.TotalPredictions)
	}

	// Precision should be 1/(1+1) = 0.5
	if math.Abs(m.Precision-0.5) > 1e-9 {
		t.Errorf("expected precision 0.5, got %f", m.Precision)
	}
}

func TestUpdateRunningMetrics_Reset(t *testing.T) {
	cm := NewCalibrationManager(DetectorConfig{
		Enabled:    true,
		ShadowMode: true,
		Threshold:  0.5,
	})

	entry := ShadowLogEntry{Score: 0.9, IsThreat: true, Threshold: 0.5, ModelVersion: "v1"}
	cm.UpdateRunningMetrics(entry, true)

	m := cm.GetRunningMetrics()
	if m.TruePositives != 1 {
		t.Errorf("expected 1 TP before reset, got %d", m.TruePositives)
	}

	cm.ResetRunningMetrics()

	m = cm.GetRunningMetrics()
	if m.TruePositives != 0 {
		t.Errorf("expected 0 TP after reset, got %d", m.TruePositives)
	}
	if m.TotalPredictions != 0 {
		t.Errorf("expected 0 TotalPredictions after reset, got %d", m.TotalPredictions)
	}
}

func TestComputeMetrics_AUROC_SingleClass(t *testing.T) {
	// All entries are threats (no negatives).
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5, ModelVersion: "v1"},
		{Score: 0.8, IsThreat: true, Threshold: 0.5, ModelVersion: "v1"},
	}
	m := ComputeMetrics(entries, alwaysThreat)
	// When all entries are the same class, AUROC is degenerate but should not panic.
	// It should be between 0 and 1.
	if m.AUROC < 0 || m.AUROC > 1 {
		t.Errorf("AUROC should be between 0 and 1 for single-class data, got %f", m.AUROC)
	}
}

func TestComputeMetrics_AllSamePredictions(t *testing.T) {
	// All predictions are the same (all threat).
	entries := []ShadowLogEntry{
		{Score: 0.9, IsThreat: true, Threshold: 0.5},
		{Score: 0.9, IsThreat: true, Threshold: 0.5},
		{Score: 0.9, IsThreat: true, Threshold: 0.5},
	}
	m := ComputeMetrics(entries, alwaysThreat)
	if m.TruePositives != 3 {
		t.Errorf("expected 3 TP, got %d", m.TruePositives)
	}
	if math.Abs(m.Precision-1.0) > 1e-9 {
		t.Errorf("expected precision 1.0, got %f", m.Precision)
	}
	if math.Abs(m.Recall-1.0) > 1e-9 {
		t.Errorf("expected recall 1.0, got %f", m.Recall)
	}
}
