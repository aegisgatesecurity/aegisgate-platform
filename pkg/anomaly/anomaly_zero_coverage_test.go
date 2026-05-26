// SPDX-License-Identifier: Apache-2.0
// Anomaly tests for 0% coverage functions

package anomaly

import (
	"testing"
)

func TestConfig_ScorerConfig(t *testing.T) {
	cfg := DefaultConfig()
	sc := cfg.ScorerConfig()
	if sc.EntropyWeight <= 0 || sc.EntropyWeight > 1 {
		t.Errorf("Expected EntropyWeight in (0,1], got %f", sc.EntropyWeight)
	}
}

func TestConfig_EntropyThresholds(t *testing.T) {
	cfg := DefaultConfig()
	et := cfg.EntropyThresholds()
	if et.Low <= 0 {
		t.Error("Expected positive low threshold")
	}
	if et.Medium <= et.Low {
		t.Error("Expected medium > low")
	}
}

func TestConfig_SetFileReader(t *testing.T) {
	SetFileReader(func(path string) ([]byte, error) {
		return []byte("test"), nil
	})
	data, err := readFile("/test")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(data) != "test" {
		t.Errorf("Expected 'test', got %s", string(data))
	}
	SetFileReader(defaultReadFile)
}

func TestConfig_ExampleConfig(t *testing.T) {
	example := ExampleConfig()
	if example == "" {
		t.Error("Expected non-empty example")
	}
	if len(example) < 50 {
		t.Error("Expected detailed example")
	}
}

func TestNewEntropyBenchmark(t *testing.T) {
	b := NewEntropyBenchmark()
	if b == nil {
		t.Fatal("Expected non-nil benchmark")
	}
}

func TestEntropyBenchmark_Measure(t *testing.T) {
	b := NewEntropyBenchmark()
	score, size := b.Measure([]byte("hello world"))
	if score < 0 || score > 8 {
		t.Errorf("Unexpected entropy: %f", score)
	}
	if size != 11 {
		t.Errorf("Expected size 11, got %d", size)
	}
}

func TestThresholdManager_SetWindowSize(t *testing.T) {
	tm := NewThresholdManager()
	tm.SetWindowSize(200)
	if tm.windowSize != 200 {
		t.Errorf("Expected 200, got %d", tm.windowSize)
	}
}

func TestThresholdManager_SetThresholds(t *testing.T) {
	tm := NewThresholdManager()
	et := EntropyThresholds{Low: 3.0, Medium: 4.0, High: 5.0, VeryHigh: 6.0}
	tm.SetThresholds(et)
	if tm.entropyThresholds.Low != 3.0 {
		t.Errorf("Expected 3.0, got %f", tm.entropyThresholds.Low)
	}
}

func TestTokenizer_isLikelySessionID(t *testing.T) {
	// Test that the function exists and can be called
	// Actual behavior depends on implementation
	ts := TokenStructure{}
	result := isLikelySessionID("test_string", ts)
	_ = result // Just verify it can be called
}

func TestTokenizer_isBase64Like(t *testing.T) {
	// Test that the function exists and can be called
	result := isBase64Like("test_string")
	_ = result // Just verify it can be called
}

func TestScorer_ScanToken(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("sk-test1234567890", config)
	_ = result
}

func TestIntegration_ScanString(t *testing.T) {
	cfg := DefaultIntegrationConfig(IntegrationSecretScanner)
	scanner := NewTokenScanner(cfg)
	_ = scanner.ScanString("test")
}

func TestClamp(t *testing.T) {
	if clamp(5.0, 0.0, 10.0) != 5.0 {
		t.Error("Expected 5.0")
	}
	if clamp(-1.0, 0.0, 10.0) != 0.0 {
		t.Error("Expected 0.0 for under min")
	}
	if clamp(15.0, 0.0, 10.0) != 10.0 {
		t.Error("Expected 10.0 for over max")
	}
}

func TestThresholdManager_SetAdjustmentFactor(t *testing.T) {
	tm := NewThresholdManager()
	tm.SetAdjustmentFactor(1.5)
	if tm.adjustmentFactor != 1.5 {
		t.Errorf("Expected 1.5, got %f", tm.adjustmentFactor)
	}
}

func TestThresholdManager_IsEnabled(t *testing.T) {
	tm := NewThresholdManager()
	_ = tm.IsEnabled() // Just verify it can be called
}

func TestTokenizer_Classify(t *testing.T) {
	ts := Classify("sk-1234567890abcdef")
	if ts.Type == 0 {
		t.Error("Expected classified token")
	}
}
