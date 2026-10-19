// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// ML-Enabled Tests (requires CGO + ONNX model)

//go:build cgo

package assessment

import (
	"os"
	"path/filepath"
	"testing"
)

// findModelPath resolves the ONNX model path, trying multiple candidates.
// Skips the test if the model is not found.
func findModelPath(t testing.TB) string {
	t.Helper()
	candidates := []string{
		filepath.Join("pkg", "ml", "models", "threat_cnn_bilstm.onnx"),
		filepath.Join("..", "..", "pkg", "ml", "models", "threat_cnn_bilstm.onnx"),
	}
	if envPath := os.Getenv("AEGISGATE_ML_MODEL_PATH"); envPath != "" {
		candidates = append([]string{envPath}, candidates...)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	t.Skip("ONNX model file not found — skipping ML test")
	return ""
}

// TestRunnerWithML runs the full assessment with the ML detector enabled.
// This test requires CGO_ENABLED=1 and the ONNX model at pkg/ml/models/threat_cnn_bilstm.onnx.
func TestRunnerWithML(t *testing.T) {
	modelPath := findModelPath(t)
	cfg := &RunnerConfig{
		EnableML:            true,
		ModelPath:           modelPath,
		EnableResponseGuard: true,
	}

	runner, err := NewRunner(cfg)
	if err != nil {
		t.Fatalf("failed to create ML-enabled runner: %v", err)
	}
	defer runner.mlDetector.Close()

	result, err := runner.Run()
	if err != nil {
		t.Fatalf("ML assessment run failed: %v", err)
	}

	t.Logf("=== ML-Enabled Assessment Results ===")
	t.Logf("Total: %d, Blocked: %d, Missed: %d, Score: %.1f%%",
		result.Total, result.Blocked, result.Missed, result.Score*100)
	t.Logf("Duration: %v", result.Duration)

	// Log per-scenario results with detection layer
	regexBlocked := 0
	mlBlocked := 0
	responseBlocked := 0
	notBlocked := 0

	for _, sr := range result.ScenarioResults {
		switch sr.DetectionLayer {
		case "regex":
			regexBlocked++
		case "ml":
			mlBlocked++
		case "response":
			responseBlocked++
		default:
			notBlocked++
			t.Logf("  MISSED [%s] %s — %s (layer: %s, ml_score: %.4f)",
				sr.OWASP, sr.ScenarioID, sr.Name, sr.DetectionLayer, sr.MLScore)
		}
	}

	t.Logf("Detection breakdown: regex=%d, ml=%d, response=%d, missed=%d",
		regexBlocked, mlBlocked, responseBlocked, notBlocked)

	// Log ML-specific catches (scenarios caught by ML that regex would have missed)
	t.Logf("=== ML-Specific Catches (layer=ml) ===")
	for _, sr := range result.ScenarioResults {
		if sr.DetectionLayer == "ml" {
			t.Logf("  ML CAUGHT [%s] %s — %s (score: %.4f)",
				sr.OWASP, sr.ScenarioID, sr.Name, sr.MLScore)
		}
	}

	// Log OWASP coverage
	t.Logf("=== OWASP Coverage ===")
	for owasp, cat := range result.OWASPCoverage {
		t.Logf("  %s: %d/%d blocked (%.0f%%)", owasp, cat.Blocked, cat.Total, cat.Coverage*100)
	}

	// ML should improve the score compared to regex-only
	// Without ML we get ~53.5% (23/43). With ML we expect significantly higher.
	if result.Score < 0.60 {
		t.Errorf("ML-enabled score %.1f%% is too low — expected at least 60%%", result.Score*100)
	}

	// All scenarios should have been processed
	if result.Total != ScenarioCount() {
		t.Errorf("expected %d total, got %d", ScenarioCount(), result.Total)
	}
}

// TestRunnerMLVsRegexComparison runs both regex-only and ML-enabled assessments,
// then compares the results to show the delta.
func TestRunnerMLVsRegexComparison(t *testing.T) {
	// Run 1: Regex-only (default config)
	runnerRegex, err := NewRunner(DefaultRunnerConfig())
	if err != nil {
		t.Fatalf("failed to create regex-only runner: %v", err)
	}

	resultRegex, err := runnerRegex.Run()
	if err != nil {
		t.Fatalf("regex-only assessment failed: %v", err)
	}

	// Run 2: ML-enabled
	modelPath := findModelPath(t)
	cfgML := &RunnerConfig{
		EnableML:            true,
		ModelPath:           modelPath,
		EnableResponseGuard: true,
	}
	runnerML, err := NewRunner(cfgML)
	if err != nil {
		t.Fatalf("failed to create ML runner: %v", err)
	}
	defer runnerML.mlDetector.Close()

	resultML, err := runnerML.Run()
	if err != nil {
		t.Fatalf("ML assessment failed: %v", err)
	}

	t.Logf("=== Regex-Only vs ML-Enabled Comparison ===")
	t.Logf("Regex-only:  %d/%d blocked (%.1f%%)", resultRegex.Blocked, resultRegex.Total, resultRegex.Score*100)
	t.Logf("ML-enabled:  %d/%d blocked (%.1f%%)", resultML.Blocked, resultML.Total, resultML.Score*100)
	t.Logf("Delta:       +%d scenarios blocked by ML", resultML.Blocked-resultRegex.Blocked)

	// Find scenarios that ML caught but regex missed
	regexMissed := make(map[string]bool)
	for _, sr := range resultRegex.ScenarioResults {
		if !sr.Blocked {
			regexMissed[sr.ScenarioID] = true
		}
	}

	t.Logf("=== Scenarios ML Caught That Regex Missed ===")
	mlCatchCount := 0
	for _, sr := range resultML.ScenarioResults {
		if regexMissed[sr.ScenarioID] && sr.Blocked {
			mlCatchCount++
			t.Logf("  + [%s] %s — %s (layer: %s, ml_score: %.4f)",
				sr.OWASP, sr.ScenarioID, sr.Name, sr.DetectionLayer, sr.MLScore)
		}
	}
	t.Logf("ML caught %d additional scenarios", mlCatchCount)

	// Find scenarios BOTH missed
	t.Logf("=== Scenarios Both Regex AND ML Missed ===")
	bothMissed := 0
	for _, sr := range resultML.ScenarioResults {
		if !sr.Blocked && regexMissed[sr.ScenarioID] {
			bothMissed++
			t.Logf("  !! [%s] %s — %s (ml_score: %.4f)",
				sr.OWASP, sr.ScenarioID, sr.Name, sr.MLScore)
		}
	}
	t.Logf("Both missed: %d scenarios", bothMissed)

	// ML should catch at least some scenarios that regex missed
	if mlCatchCount == 0 {
		t.Log("WARNING: ML did not catch any additional scenarios — may indicate model issues or all misses need new patterns")
	}
}
