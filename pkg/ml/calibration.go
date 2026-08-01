// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Calibration Manager
// =========================================================================
//
// The CalibrationManager ensures 0% FPR by:
// 1. Running benign corpus through the model to find max benign score
// 2. Setting threshold = max_benign_score + margin
// 3. Logging all predictions in shadow mode for offline analysis
// 4. Supporting dynamic threshold adjustment without restart
//
// Deployment process:
//   1. Ship model with threshold=0.7, enabled=false, shadow=true
//   2. Run calibration: find zero-FPR threshold
//   3. 7-day shadow validation on production traffic
//   4. Enable blocking (enabled=true, shadow=false)
//
// =========================================================================

package ml

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CalibrationManager manages the ML threshold and shadow-mode logging.
type CalibrationManager struct {
	mu             sync.RWMutex
	config         DetectorConfig
	log            []ShadowLogEntry
	logPath        string
	runningMetrics ShadowMetrics
}

// NewCalibrationManager creates a calibration manager with the given config.
func NewCalibrationManager(cfg DetectorConfig) *CalibrationManager {
	return &CalibrationManager{
		config:  cfg,
		log:     make([]ShadowLogEntry, 0),
		logPath: "shadow_predictions.jsonl",
	}
}

// IsAboveThreshold checks if a score exceeds the calibrated threshold.
// Thread-safe.
func (cm *CalibrationManager) IsAboveThreshold(score float64) bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return score >= cm.config.Threshold
}

// GetThreshold returns the current calibrated threshold.
func (cm *CalibrationManager) GetThreshold() float64 {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config.Threshold
}

// SetThreshold dynamically adjusts the threshold without restart.
// Thread-safe.
func (cm *CalibrationManager) SetThreshold(threshold float64) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.config.Threshold = threshold
}

// IsEnabled returns whether ML detection is enabled.
func (cm *CalibrationManager) IsEnabled() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config.Enabled
}

// SetEnabled enables or disables ML detection.
func (cm *CalibrationManager) SetEnabled(enabled bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.config.Enabled = enabled
}

// IsShadowMode returns whether we're in shadow mode (log only, don't block).
func (cm *CalibrationManager) IsShadowMode() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.config.ShadowMode
}

// SetShadowMode enables or disables shadow mode.
func (cm *CalibrationManager) SetShadowMode(shadow bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.config.ShadowMode = shadow
}

// LogShadowPrediction records a shadow-mode prediction for offline analysis.
// Thread-safe. Does NOT block production traffic.
func (cm *CalibrationManager) LogShadowPrediction(input string, score float64, variant string, modelVersion string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	hash := sha256.Sum256([]byte(input))
	entry := ShadowLogEntry{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		InputHash:    fmt.Sprintf("%x", hash[:16]), // First 16 bytes for privacy
		Score:        score,
		Threshold:    cm.config.Threshold,
		IsThreat:     score >= cm.config.Threshold,
		Variant:      variant,
		ModelVersion: modelVersion,
		InputLength:  len(input),
	}

	cm.log = append(cm.log, entry)
}

// FlushShadowLog writes accumulated shadow predictions to disk as JSONL.
// Thread-safe. Called periodically or on shutdown.
func (cm *CalibrationManager) FlushShadowLog() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if len(cm.log) == 0 {
		return nil
	}

	// Ensure directory exists
	dir := filepath.Dir(cm.logPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create log directory: %w", err)
		}
	}

	f, err := os.OpenFile(cm.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open shadow log: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, entry := range cm.log {
		if err := enc.Encode(entry); err != nil {
			return fmt.Errorf("encode shadow log entry: %w", err)
		}
	}

	cm.log = cm.log[:0] // Clear buffer
	return nil
}

// CalibrateFromBenign runs calibration against a benign corpus.
// Returns the calibrated result with zero-FPR threshold.
func (cm *CalibrationManager) CalibrateFromBenign(benignInputs []string, scoreFn func(string) float64) CalibrationResult {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var maxScore float64
	var falsePositives int

	for _, input := range benignInputs {
		score := scoreFn(input)
		if score > maxScore {
			maxScore = score
		}
		if score >= cm.config.Threshold {
			falsePositives++
		}
	}

	margin := 0.05 // 5% margin above max benign score
	threshold := maxScore + margin

	// Ensure minimum threshold
	if threshold < 0.5 {
		threshold = 0.5
	}

	fpr := float64(falsePositives) / float64(len(benignInputs))

	result := CalibrationResult{
		Threshold:      threshold,
		MaxBenignScore: maxScore,
		Margin:         margin,
		BenignSamples:  len(benignInputs),
		FalsePositives: falsePositives,
		FPR:            fpr,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		ModelVersion:   "calibration-pending",
	}

	// Update config with calibrated threshold
	cm.config.Threshold = threshold

	return result
}

// GetStats returns calibration statistics.
func (cm *CalibrationManager) GetStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return map[string]interface{}{
		"enabled":     cm.config.Enabled,
		"shadow_mode": cm.config.ShadowMode,
		"threshold":   cm.config.Threshold,
		"log_entries": len(cm.log),
	}
}

// ComputeMetrics computes precision, recall, F1, and AUROC from a slice of
// ShadowLogEntry values. Each entry's IsThreat field is the model's prediction;
// the caller must supply a ground-truth label function that returns whether the
// entry is actually a threat.
//
// If entries is empty, ComputeMetrics returns a zero-valued ShadowMetrics.
func ComputeMetrics(entries []ShadowLogEntry, isActualThreat func(ShadowLogEntry) bool) ShadowMetrics {
	if len(entries) == 0 {
		return ShadowMetrics{}
	}

	var tp, tn, fp, fn int
	for _, e := range entries {
		predicted := e.IsThreat
		actual := isActualThreat(e)
		switch {
		case predicted && actual:
			tp++
		case !predicted && !actual:
			tn++
		case predicted && !actual:
			fp++
		case !predicted && actual:
			fn++
		}
	}

	precision := safeDiv(float64(tp), float64(tp+fp))
	recall := safeDiv(float64(tp), float64(tp+fn))
	f1 := safeF1(precision, recall)
	auroc := computeAUROC(entries, isActualThreat)

	return ShadowMetrics{
		TruePositives:    tp,
		TrueNegatives:    tn,
		FalsePositives:   fp,
		FalseNegatives:   fn,
		Precision:        precision,
		Recall:           recall,
		F1Score:          f1,
		AUROC:            auroc,
		TotalPredictions: len(entries),
		Timestamp:        time.Now().UTC(),
		Threshold:        entries[0].Threshold,
		ModelVersion:     entries[0].ModelVersion,
	}
}

// UpdateRunningMetrics accumulates a single shadow prediction into the running
// metrics tracker. The caller provides whether this entry is actually a threat
// (ground truth). Thread-safe.
func (cm *CalibrationManager) UpdateRunningMetrics(entry ShadowLogEntry, isActualThreat bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	predicted := entry.IsThreat
	switch {
	case predicted && isActualThreat:
		cm.runningMetrics.TruePositives++
	case !predicted && !isActualThreat:
		cm.runningMetrics.TrueNegatives++
	case predicted && !isActualThreat:
		cm.runningMetrics.FalsePositives++
	case !predicted && isActualThreat:
		cm.runningMetrics.FalseNegatives++
	}
	cm.runningMetrics.TotalPredictions++
	cm.runningMetrics.Threshold = cm.config.Threshold
	cm.runningMetrics.ModelVersion = entry.ModelVersion
	cm.runningMetrics.Timestamp = time.Now().UTC()

	// Recompute derived metrics from raw counts.
	cm.runningMetrics.Precision = safeDiv(
		float64(cm.runningMetrics.TruePositives),
		float64(cm.runningMetrics.TruePositives+cm.runningMetrics.FalsePositives),
	)
	cm.runningMetrics.Recall = safeDiv(
		float64(cm.runningMetrics.TruePositives),
		float64(cm.runningMetrics.TruePositives+cm.runningMetrics.FalseNegatives),
	)
	cm.runningMetrics.F1Score = safeF1(cm.runningMetrics.Precision, cm.runningMetrics.Recall)
}

// GetRunningMetrics returns a copy of the current running shadow metrics.
// Thread-safe.
func (cm *CalibrationManager) GetRunningMetrics() ShadowMetrics {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.runningMetrics
}

// ResetRunningMetrics resets the running shadow metrics to zero values.
// Thread-safe.
func (cm *CalibrationManager) ResetRunningMetrics() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.runningMetrics = ShadowMetrics{
		Threshold:    cm.config.Threshold,
		Timestamp:    time.Now().UTC(),
		ModelVersion: cm.config.ModelPath,
	}
}

// safeDiv returns a/b, or 0 when b == 0.
func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// safeF1 returns the F1 score from precision and recall, or 0 when both are 0.
func safeF1(precision, recall float64) float64 {
	if precision+recall == 0 {
		return 0
	}
	return 2 * precision * recall / (precision + recall)
}

// computeAUROC computes the area under the ROC curve using the trapezoidal
// rule. It sweeps through multiple score thresholds, computing TPR and FPR
// at each, and integrates.
func computeAUROC(entries []ShadowLogEntry, isActualThreat func(ShadowLogEntry) bool) float64 {
	if len(entries) == 0 {
		return 0
	}

	// Collect all unique scores as candidate thresholds.
	thresholdSet := make(map[float64]struct{})
	for _, e := range entries {
		thresholdSet[e.Score] = struct{}{}
	}
	thresholds := make([]float64, 0, len(thresholdSet))
	for t := range thresholdSet {
		thresholds = append(thresholds, t)
	}
	// Sort thresholds in descending order (highest first).
	// We sweep from the most restrictive threshold (predict nothing)
	// to the least restrictive (predict everything).
	sortFloat64sDesc(thresholds)

	// Compute TPR/FPR at each threshold (predict threat when score >= threshold).
	type point struct{ tpr, fpr float64 }
	points := make([]point, 0, len(thresholds)+2)

	// Add (0,0) as the starting point (threshold above all scores → predict nothing).
	points = append(points, point{0, 0})

	// Count total positives and negatives.
	totalP := 0
	totalN := 0
	for _, e := range entries {
		if isActualThreat(e) {
			totalP++
		} else {
			totalN++
		}
	}

	if totalP == 0 && totalN == 0 {
		return 0
	}

	for _, thresh := range thresholds {
		var tp, fp int
		for _, e := range entries {
			predicted := e.Score >= thresh
			actual := isActualThreat(e)
			if predicted && actual {
				tp++
			}
			if predicted && !actual {
				fp++
			}
		}
		tpr := safeDiv(float64(tp), float64(totalP))
		fpr := safeDiv(float64(fp), float64(totalN))
		points = append(points, point{tpr, fpr})
	}

	// Add (1,1) as the ending point.
	points = append(points, point{1, 1})

	// Trapezoidal integration over FPR (x) and TPR (y).
	auroc := 0.0
	for i := 1; i < len(points); i++ {
		dx := points[i].fpr - points[i-1].fpr
		dy := points[i].tpr + points[i-1].tpr
		auroc += dx * dy / 2
	}

	// Clamp to [0, 1].
	if auroc < 0 {
		auroc = 0
	}
	if auroc > 1 {
		auroc = 1
	}

	return auroc
}

// sortFloat64s sorts a slice of float64 in ascending order.
func sortFloat64s(s []float64) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}

// sortFloat64sDesc sorts a slice of float64 in descending order.
func sortFloat64sDesc(s []float64) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] < key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}
