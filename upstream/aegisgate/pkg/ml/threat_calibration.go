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
	mu      sync.RWMutex
	config  DetectorConfig
	log     []ShadowLogEntry
	logPath string
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
