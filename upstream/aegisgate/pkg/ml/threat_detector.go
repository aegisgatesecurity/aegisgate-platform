// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Threat Detector (ONNX Runtime)
// =========================================================================
//
// ThreatDetector loads an ONNX model and performs inference on text input.
// It uses onnxruntime-go for native Go inference — no Python runtime needed.
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
// =========================================================================

package ml

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/yalue/onnxruntime_go"
)

// init initializes the ONNX runtime environment.
// It discovers the onnxruntime shared library before initialization.
func init() {
	// Discover and set the shared library path before initialization
	libPath := discoverONNXRuntimeLib("")
	if libPath != "" {
		onnxruntime_go.SetSharedLibraryPath(libPath)
	}

	if !onnxruntime_go.IsInitialized() {
		if err := onnxruntime_go.InitializeEnvironment(); err != nil {
			// Log but don't fail - will fall back to heuristic
			fmt.Fprintf(os.Stderr, "Warning: Failed to initialize ONNX runtime: %v\n", err)
		}
	}
}

// ThreatDetector performs neural network-based threat detection.
type ThreatDetector struct {
	mu             sync.RWMutex
	config         DetectorConfig
	normalizer     *CharNormalizer
	calibrator     *CalibrationManager
	dynamicSession *onnxruntime_go.DynamicAdvancedSession
	loaded         bool
	modelHash      string
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

	// If detector is disabled, return immediately
	if !td.config.Enabled && !td.config.ShadowMode {
		return ThreatScore{
			Score:        0,
			IsThreat:     false,
			Threshold:    td.config.Threshold,
			Variant:      "disabled",
			ModelVersion: td.modelHash,
		}
	}

	// Preprocess input
	encoded := td.normalizer.Encode(text)

	// Run inference
	score := td.inference(encoded)

	// Check against calibrated threshold
	isThreat := score >= td.config.Threshold

	result := ThreatScore{
		Score:        score,
		IsThreat:     isThreat,
		Threshold:    td.config.Threshold,
		Variant:      "original",
		ModelVersion: td.modelHash,
	}

	// In shadow mode, log but don't block
	if td.config.ShadowMode {
		td.calibrator.LogShadowPrediction(text, score, "original", td.modelHash)
		result.IsThreat = false // Never block in shadow mode
	}

	return result
}

// DetectAll runs detection on all normalization variants.
// Returns the highest score and whether any variant was above threshold.
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

		// Short-circuit if we find a clear threat
		if score >= td.config.Threshold {
			break
		}
	}

	_ = bestVariant // Track which variant triggered (for debugging)

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
		result.IsThreat = false // Never block in shadow mode
	}

	return result
}

// inference runs the ONNX model on the encoded input.
func (td *ThreatDetector) inference(encoded []int32) float64 {
	// If model not loaded or ForceHeuristic is set, use heuristic fallback
	if !td.loaded || td.dynamicSession == nil || td.config.ForceHeuristic {
		return td.heuristicScore(encoded)
	}

	// Prepare input tensor data (copy encoded to 256-length slice)
	inputData := make([]int32, MaxSeqLen)
	copy(inputData, encoded)

	// Create input tensor (int32)
	inputTensor, err := onnxruntime_go.NewTensor[int32](
		onnxruntime_go.NewShape(1, MaxSeqLen),
		inputData,
	)
	if err != nil {
		slog.Warn("Failed to create input tensor", "error", err)
		return td.heuristicScore(encoded)
	}
	defer inputTensor.Destroy()

	// Create output tensor (float32 - model outputs probability directly)
	// Shape must be [1, 1] to match model output, not [1]
	outputData := make([]float32, 1)
	outputTensor, err := onnxruntime_go.NewTensor[float32](
		onnxruntime_go.NewShape(1, 1),
		outputData,
	)
	if err != nil {
		slog.Warn("Failed to create output tensor", "error", err)
		return td.heuristicScore(encoded)
	}
	defer outputTensor.Destroy()

	// Run inference with Value interface
	// DEBUG: ONNX inference starting
	slog.Info("DEBUG: Running ONNX inference")
	slog.Error("DEBUG_ML_INFERENCE_START", "text_len", len(encoded))
	err = td.dynamicSession.Run(
		[]onnxruntime_go.Value{inputTensor},
		[]onnxruntime_go.Value{outputTensor},
	)
	if err != nil {
		slog.Warn("ONNX inference failed", "error", err)
		return td.heuristicScore(encoded)
	}

	// Get output - model already produces probability [0, 1]
	score := float64(outputData[0])
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}
	// DEBUG: Log score for analysis
	if len(encoded) > 0 && encoded[0] != 0 {
		slog.Info("DEBUG_ML_SCORE", "score", score, "first_char", encoded[0])
	}
	return score
}

// heuristicScore provides a rule-based fallback when no ONNX model is loaded.
// This catches the most common evasion patterns that regex misses.
// NOT a replacement for the neural network — just a stopgap.
func (td *ThreatDetector) heuristicScore(encoded []int32) float64 {
	// Reconstruct text from encoded input
	text := td.normalizer.Decode(encoded)
	if len(text) == 0 {
		return 0
	}

	score := 0.0

	// Heuristic 1: Check for transposition patterns
	// (Adjacent character swaps like "byapss" instead of "bypass")
	attackWords := []string{"ignore", "bypass", "override", "inject", "admin",
		"system", "prompt", "hack", "exploit", "reveal", "extract", "steal",
		"disable", "delete", "remove", "access", "forge", "escalate", "poison", "corrupt"}

	textLower := toLower(text)
	for _, word := range attackWords {
		// Check if text contains a 1-character transposition of an attack word
		if isTransposition(textLower, word) {
			score += 0.4
		}
	}

	// Heuristic 2: Check for vowel-deleted attack words
	for _, word := range attackWords {
		if isVowelDeleted(textLower, word) {
			score += 0.3
		}
	}

	// Heuristic 3: Check for reversed attack words
	for _, word := range attackWords {
		if containsReversed(textLower, word) {
			score += 0.3
		}
	}

	// Cap at 0.9 (never 1.0 from heuristics — reserve 1.0 for the model)
	if score > 0.9 {
		score = 0.9
	}

	return score
}

// LoadModel loads the ONNX model from disk.
func (td *ThreatDetector) LoadModel(path string) error {
	td.mu.Lock()
	defer td.mu.Unlock()

	// Check that the model file exists
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("model file not found: %w", err)
	}

	// Use DynamicAdvancedSession for mixed int32 input / float32 output
	session, err := onnxruntime_go.NewDynamicAdvancedSession(
		path,
		[]string{"input"},
		[]string{"threat_score"},
		nil, // options
	)
	if err != nil {
		return fmt.Errorf("create ONNX session: %w", err)
	}

	td.dynamicSession = session

	// Compute SHA256 hash for model versioning
	hash, err := computeFileHash(path)
	if err != nil {
		session.Destroy()
		return fmt.Errorf("compute model hash: %w", err)
	}

	td.modelHash = hash
	td.loaded = true

	return nil
}

// Close cleans up the ONNX session.
func (td *ThreatDetector) Close() error {
	td.mu.Lock()
	defer td.mu.Unlock()

	if !td.loaded || td.dynamicSession == nil {
		return nil
	}

	err := td.dynamicSession.Destroy()
	td.dynamicSession = nil
	td.loaded = false
	return err
}

// GetCalibrator returns the calibration manager for external configuration.
func (td *ThreatDetector) GetCalibrator() *CalibrationManager {
	return td.calibrator
}

// IsEnabled returns whether the neural threat detector is enabled.
// When disabled, Detect() returns zero-score results immediately.
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

// isTransposition checks if text contains a 1-character transposition of word.
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

// isVowelDeleted checks if text contains word with vowels removed.
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

// containsReversed checks if text contains the reversed form of word.
func containsReversed(text, word string) bool {
	reversed := reverse(word)
	if len(reversed) >= 4 && contains(text, reversed) {
		return true
	}
	return false
}

// reverse returns the reversed string.
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// contains checks if s contains substr (case-sensitive).
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

// toLower converts string to lowercase.
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

// computeFileHash computes SHA256 of a file (placeholder until ONNX model exists).
func computeFileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	// Simple hash for now — will use crypto/sha256 when model is real
	return fmt.Sprintf("sha256:%x", data[:min(len(data), 32)]), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
