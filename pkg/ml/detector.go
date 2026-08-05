// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Threat Detector (Core Logic)
// =========================================================================
//
// ThreatDetector performs neural network-based threat detection.
// It uses onnxruntime-go for native Go inference when CGO is enabled,
// and falls back to heuristic-only detection when CGO is disabled.
//
// The detector is designed as a SUPPLEMENTARY layer:
// - It only runs when regex doesn't trigger
// - It catches the ~11.5% gap (transposition, vowel deletion, word reversal)
// - It never overrides regex detections
// - Threshold calibrated for 0% FPR on benign traffic
//
// Cold-start deployment:
//   1. Ship with Enabled=false, ShadowMode=true
//   2. Run calibration to find zero-FPR threshold
//   3. 7-day shadow validation
//   4. Enable blocking after validation
//
// Build tags:
//   - CGO_ENABLED=1: Full ONNX inference (detector_onnx.go)
//   - CGO_ENABLED=0: Heuristic-only fallback (detector_noonnx.go)
//
// =========================================================================

package ml

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ThreatDetector performs neural network-based threat detection.
// ONNX session fields are defined in build-tag-specific files:
//   - detector_onnx.go  (CGO enabled: typed *onnxruntime fields)
//   - detector_noonnx.go (CGO disabled: no ONNX fields)
type ThreatDetector struct {
	mu         sync.RWMutex
	config     DetectorConfig
	normalizer *CharNormalizer
	calibrator *CalibrationManager
	loaded     bool
	modelHash  string
	onnx       *onnxFields // ONNX session (nil when CGO disabled)
}

// NewThreatDetector creates a new threat detector with the given config.
// The detector starts DISABLED (cold-start safety) unless explicitly enabled.
func NewThreatDetector(cfg DetectorConfig) *ThreatDetector {
	if cfg.MaxSequenceLength <= 0 {
		cfg.MaxSequenceLength = MaxSeqLen
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10
	}

	td := &ThreatDetector{
		config:     cfg,
		normalizer: NewCharNormalizer(),
		calibrator: NewCalibrationManager(cfg),
		loaded:     false,
		onnx:       newOnnxFields(),
	}

	return td
}

// Detect analyzes text for threats and returns a ThreatScore.
func (td *ThreatDetector) Detect(text string) ThreatScore {
	td.mu.RLock()
	defer td.mu.RUnlock()

	if !td.config.Enabled && !td.config.ShadowMode {
		return ThreatScore{
			Score:        0,
			IsThreat:     false,
			Threshold:    td.config.Threshold,
			Variant:      "disabled",
			ModelVersion: td.modelHash,
		}
	}

	encoded := td.normalizer.Encode(text)
	score := td.inference(encoded)
	isThreat := score >= td.config.Threshold

	result := ThreatScore{
		Score:        score,
		IsThreat:     isThreat,
		Threshold:    td.config.Threshold,
		Variant:      "original",
		ModelVersion: td.modelHash,
	}

	if td.config.ShadowMode {
		td.calibrator.LogShadowPrediction(text, score, "original", td.modelHash)
		result.IsThreat = false
	}

	return result
}

// DetectAll runs detection on all normalization variants.
func (td *ThreatDetector) DetectAll(variants []string) ThreatScore {
	var bestScore float64
	var bestVariant string

	td.mu.RLock()
	defer td.mu.RUnlock()

	if !td.config.Enabled && !td.config.ShadowMode {
		return ThreatScore{
			Score:        0,
			IsThreat:     false,
			Threshold:    td.config.Threshold,
			Variant:      "disabled",
			ModelVersion: td.modelHash,
		}
	}

	for _, v := range variants {
		encoded := td.normalizer.Encode(v)
		score := td.inference(encoded)
		if score > bestScore {
			bestScore = score
			bestVariant = v
		}
		if score >= td.config.Threshold {
			break
		}
	}

	_ = bestVariant
	isThreat := bestScore >= td.config.Threshold

	result := ThreatScore{
		Score:        bestScore,
		IsThreat:     isThreat,
		Threshold:    td.config.Threshold,
		Variant:      "best_variant",
		ModelVersion: td.modelHash,
	}

	if td.config.ShadowMode {
		td.calibrator.LogShadowPrediction(variants[0], bestScore, "multi_variant", td.modelHash)
		result.IsThreat = false
	}

	return result
}

// inference runs the ONNX model on the encoded input.
// Falls back to heuristic scoring when no model is loaded or CGO is disabled.
func (td *ThreatDetector) inference(encoded []int32) float64 {
	// Try ONNX inference first (only available with CGO)
	if td.loaded {
		if score, ok := td.inferenceONNX(encoded); ok {
			return score
		}
	}
	return td.heuristicScore(encoded)
}

// heuristicScore provides a rule-based fallback when no ONNX model is loaded.
func (td *ThreatDetector) heuristicScore(encoded []int32) float64 {
	text := td.normalizer.Decode(encoded)
	if len(text) == 0 {
		return 0
	}

	score := 0.0
	attackWords := []string{"ignore", "bypass", "override", "inject", "admin",
		"system", "prompt", "hack", "exploit", "reveal", "extract", "steal",
		"disable", "delete", "remove", "access", "forge", "escalate", "poison", "corrupt"}

	textLower := toLower(text)
	for _, word := range attackWords {
		if isTransposition(textLower, word) {
			score += 0.4
		}
	}
	for _, word := range attackWords {
		if isVowelDeleted(textLower, word) {
			score += 0.3
		}
	}
	for _, word := range attackWords {
		if containsReversed(textLower, word) {
			score += 0.3
		}
	}

	if score > 0.9 {
		score = 0.9
	}
	return score
}

// LoadModel loads the ONNX model from disk.
// When CGO is disabled, falls back to heuristic-only mode.
func (td *ThreatDetector) LoadModel(path string) error {
	td.mu.Lock()
	defer td.mu.Unlock()

	cleanPath := filepath.Clean(path) // #nosec G304
	if _, err := os.Stat(cleanPath); err != nil {
		return fmt.Errorf("model file not found: %w", err)
	}

	return td.loadModelONNX(cleanPath)
}

// Close cleans up the ONNX session and tensors.
func (td *ThreatDetector) Close() error {
	td.mu.Lock()
	defer td.mu.Unlock()

	if !td.loaded {
		return nil
	}

	td.loaded = false
	return td.closeONNX()
}

// GetCalibrator returns the calibration manager.
func (td *ThreatDetector) GetCalibrator() *CalibrationManager {
	return td.calibrator
}

// IsEnabled returns whether the neural threat detector is enabled.
func (td *ThreatDetector) IsEnabled() bool {
	td.mu.RLock()
	defer td.mu.RUnlock()
	return td.config.Enabled
}

// GetStats returns detector statistics.
func (td *ThreatDetector) GetStats() map[string]interface{} {
	td.mu.RLock()
	defer td.mu.RUnlock()

	return map[string]interface{}{
		"enabled":      td.config.Enabled,
		"shadow_mode":  td.config.ShadowMode,
		"threshold":    td.config.Threshold,
		"model_loaded": td.loaded,
		"model_hash":   td.modelHash,
		"max_seq_len":  td.config.MaxSequenceLength,
		"timeout_ms":   td.config.Timeout,
	}
}

// =====================================================================
// Helper functions
// =====================================================================

func isTransposition(text, word string) bool {
	if len(word) < 4 {
		return false
	}
	for i := 0; i < len(word)-1; i++ {
		swapped := word[:i] + string(word[i+1]) + string(word[i]) + word[i+2:]
		if contains(text, swapped) {
			return true
		}
	}
	return false
}

func isVowelDeleted(text, word string) bool {
	vowels := "aeiou"
	vowelDeleted := ""
	for i, c := range word {
		if i == 0 || !contains(vowels, string(c)) {
			vowelDeleted += string(c)
		}
	}
	if vowelDeleted != word && contains(text, vowelDeleted) {
		return true
	}
	return false
}

func containsReversed(text, word string) bool {
	reversed := reverse(word)
	if len(reversed) >= 4 && contains(text, reversed) {
		return true
	}
	return false
}

func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	var b []byte
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			b = append(b, byte(c+32))
		} else {
			b = append(b, byte(c)) // #nosec G115
		}
	}
	return string(b)
}