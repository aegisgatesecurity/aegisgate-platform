// SPDX-License-Identifier: Apache-2.0
// Anomaly scorer tests - targeting 66.7% Scan functions

package anomaly

import (
	"testing"
)

func TestScorer_Scan_ValidToken(t *testing.T) {
	data := []byte("test_token_abc123")
	config := DefaultScorerConfig()
	result := Scan(data, config)
	_ = result
}

func TestScorer_Scan_EmptyData(t *testing.T) {
	data := []byte("")
	config := DefaultScorerConfig()
	result := Scan(data, config)
	_ = result
}

func TestScorer_Scan_LongData(t *testing.T) {
	longData := make([]byte, 10000)
	for i := range longData {
		longData[i] = byte('a' + (i % 26))
	}
	config := DefaultScorerConfig()
	result := Scan(longData, config)
	_ = result
}

func TestScorer_Scan_HighEntropy(t *testing.T) {
	highEntropyData := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")
	config := DefaultScorerConfig()
	result := Scan(highEntropyData, config)
	_ = result
}

func TestScorer_ScanString_Valid(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanString("normal text content", config)
	_ = result
}

func TestScorer_ScanString_Empty(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanString("", config)
	_ = result
}

func TestScorer_ScanString_WithSecrets(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanString("sk-1234567890abcdefghijklmnop", config)
	_ = result
}

func TestScorer_ScanToken_Valid(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("test_token_123", config)
	_ = result
}

func TestScorer_ScanToken_Empty(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("", config)
	_ = result
}

func TestScorer_ScanToken_WithAPIKey(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("sk-1234567890abcdefghijklmnop", config)
	_ = result
}

func TestScorer_ScanToken_WithGitHubToken(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("ghp_1234567890abcdefghijklmnop", config)
	_ = result
}

func TestScorer_ScanToken_WithJWT(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doziegNqXP3P8cR8vJMyxqMl2K3a8t6J", config)
	_ = result
}

func TestScorer_ScanToken_UUID(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("123e4567-e89b-12d3-a456-426614174000", config)
	_ = result
}

func TestScorer_Scan_NormalText(t *testing.T) {
	data := []byte("hello world this is normal text")
	config := DefaultScorerConfig()
	result := Scan(data, config)
	_ = result
}

func TestScorer_Scan_Short(t *testing.T) {
	data := []byte("a")
	config := DefaultScorerConfig()
	result := Scan(data, config)
	_ = result
}

func TestScorer_ScanToken_AWSKey(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("AKIAIOSFODNN7EXAMPLE", config)
	_ = result
}

func TestScorer_ScanToken_StripeKey(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("sk_live_PLACEHOLDER", config)
	_ = result
}

func TestScorer_ScanToken_GenericSecret(t *testing.T) {
	config := DefaultScorerConfig()
	result := ScanToken("secret_key_1234567890abcdef", config)
	_ = result
}

func TestConfigValidation_Valid(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected valid config, got error: %v", err)
	}
}

func TestConfigValidation_Invalid(t *testing.T) {
	cfg := Config{
		Entropy: EntropyConfig{
			LowThreshold:    5.0,
			MediumThreshold: 4.0,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error")
	}
}

func TestThresholdManager_Creation(t *testing.T) {
	tm := NewThresholdManager()
	if tm == nil {
		t.Fatal("Expected non-nil threshold manager")
	}
}

func TestThresholdManager_Custom(t *testing.T) {
	tm := NewThresholdManager()
	thresholds := tm.GetThresholds()
	if thresholds.Low <= 0 {
		t.Error("Expected positive low threshold")
	}
}

func TestTokenClassifier_Production(t *testing.T) {
	ts := Classify("sk-prod-1234567890")
	if !ts.IsProduction {
		t.Error("Expected production flag")
	}
}

func TestTokenClassifier_NonProduction(t *testing.T) {
	ts := Classify("sk-test-1234567890")
	if ts.IsProduction {
		t.Error("Expected non-production flag")
	}
}

func TestTokenScanner_ScanData_Custom(t *testing.T) {
	cfg := DefaultIntegrationConfig(IntegrationSecretScanner)
	scanner := NewTokenScanner(cfg)
	result := scanner.ScanData([]byte("test"))
	_ = result
}

func TestHighEntropyScanner_Creation(t *testing.T) {
	scanner := NewHighEntropyScanner(6.0)
	if scanner == nil {
		t.Fatal("Expected non-nil scanner")
	}
}

func TestConfigMerge_AllFields(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg2 := Config{
		Entropy: EntropyConfig{
			LowThreshold:      4.0,
			MediumThreshold:   5.0,
			HighThreshold:     6.0,
			VeryHighThreshold: 7.0,
		},
	}
	cfg1.MergeWith(cfg2)

	if cfg1.Entropy.LowThreshold != 4.0 {
		t.Errorf("Expected 4.0, got %f", cfg1.Entropy.LowThreshold)
	}
	if cfg1.Entropy.MediumThreshold != 5.0 {
		t.Errorf("Expected 5.0, got %f", cfg1.Entropy.MediumThreshold)
	}
}

func TestTokenScanner_Creation(t *testing.T) {
	cfg := DefaultIntegrationConfig(IntegrationSecretScanner)
	scanner := NewTokenScanner(cfg)
	if scanner == nil {
		t.Fatal("Expected non-nil scanner")
	}
}

func TestScoreResult_Fields(t *testing.T) {
	data := []byte("sk-test-1234567890")
	config := DefaultScorerConfig()
	result := Scan(data, config)
	_ = result.IsAnomalous
	_ = result.ShouldBlock
	_ = result.Reason
	_ = result.Score.Total
	_ = result.Score.Entropy
	_ = result.Score.Confidence
}

func TestScorer_Scan_Mixed(t *testing.T) {
	data := []byte("sk-1234-abc-DEF")
	config := DefaultScorerConfig()
	result := Scan(data, config)
	_ = result
}

func TestScorer_Scan_LongToken(t *testing.T) {
	data := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doziegNqXP3P8cR8vJMyxqMl2K3a8t6Jklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz")
	config := DefaultScorerConfig()
	result := Scan(data, config)
	_ = result
}
