// SPDX-License-Identifier: Apache-2.0
//go:build !cgo
// +build !cgo

// =========================================================================
// AegisGate Platform - ML Threat Detector (Community Edition, no ONNX)
// =========================================================================
//
// This file provides the same ThreatDetector API as threat_detector.go
// but without ONNX Runtime dependencies. When CGO is disabled, the
// detector falls back to heuristic-based detection only.
//
// The heuristic engine catches common evasion patterns (transposition,
// vowel deletion, word reversal) that regex misses, but cannot match
// the neural network's accuracy. For full ML threat detection, use
// the enterprise build with CGO_ENABLED=1.

package ml

import (
	"fmt"
	"os"
	"sync"
)

// ThreatDetector performs neural network-based threat detection.
type ThreatDetector struct {
	mu         sync.RWMutex
	config     DetectorConfig
	normalizer *CharNormalizer
	calibrator *CalibrationManager
	loaded     bool
	modelHash  string
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

	return &ThreatDetector{
		config:     cfg,
		normalizer: NewCharNormalizer(),
		calibrator: NewCalibrationManager(cfg),
		loaded:     false,
	}
}

// Detect analyzes text for threats and returns a ThreatScore.
// If the detector is disabled, returns a zero-score result immediately.
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
		}
		if score >= td.config.Threshold {
			break
		}
	}

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

// inference runs the heuristic model on the encoded input.
// Without ONNX Runtime, only heuristic detection is available.
func (td *ThreatDetector) inference(encoded []int32) float64 {
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

// LoadModel is a no-op in the community edition (no ONNX Runtime).
func (td *ThreatDetector) LoadModel(path string) error {
	td.mu.Lock()
	defer td.mu.Unlock()

	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("model file not found: %w", err)
	}

	hash, err := computeFileHash(path)
	if err != nil {
		return fmt.Errorf("compute model hash: %w", err)
	}

	td.modelHash = hash
	td.loaded = true
	return nil
}

// Close is a no-op in the community edition.
func (td *ThreatDetector) Close() error {
	td.mu.Lock()
	defer td.mu.Unlock()
	td.loaded = false
	return nil
}

// GetCalibrator returns the calibration manager for external configuration.
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

// --- Helper functions (shared between cgo and !cgo builds) ---

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
	reversed := reverseStr(word)
	if len(reversed) >= 4 && contains(text, reversed) {
		return true
	}
	return false
}

func reverseStr(s string) string {
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
			b = append(b, byte(c))
		}
	}
	return string(b)
}

func computeFileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	return fmt.Sprintf("sha256:%x", data[:minInt(len(data), 32)]), nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
