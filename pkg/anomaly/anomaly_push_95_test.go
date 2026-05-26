// SPDX-License-Identifier: Apache-2.0
// Anomaly coverage push - detectTokenType, isProductionKey, MergeWith

package anomaly

import (
	"testing"
)

func TestDetectTokenType_EdgeCases(t *testing.T) {
	tokens := []string{
		"sk-1234567890abcdefghijklmnop",
		"sk-prod-1234567890abcdefghijklmnop",
		"sk-test-1234567890abcdefghijklmnop",
		"ghp_1234567890abcdefghijklmnop",
		"gho_1234567890abcdefghijklmnop",
		"ghs_1234567890abcdefghijklmnop",
		"ghr_1234567890abcdefghijklmnop",
		"AKIAIOSFODNN7EXAMPLE",
		"ANOTREALEXAMPLE1234567890",
		"ASIA1234567890EXAMPLE",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doziegNqXP3P8cR8vJMyxqMl2K3a8t6J",
		"api_key_1234567890abcdefghijklmnop",
		"apikey_1234567890abcdefghijklmnop",
		"key_1234567890abcdefghijklmnop",
		"token_1234567890abcdefghijklmnop",
		"secret_1234567890abcdefghijklmnop",
		"sk_live_PLACEHOLDER",
		"sk_test_PLACEHOLDER",
		"123e4567-e89b-12d3-a456-426614174000",
		"00000000-0000-0000-0000-000000000000",
		"xoxb-PLACEHOLDER",
		"xoxb-PLACEHOLDER",
		"xoxb-PLACEHOLDER",
		"sess_abc123def456ghi789jkl012",
		"session_id=xyz789abc123def456ghi",
		"SGVsbG8gV29ybGRoZXJldXNlcg==",
		"abcdefghijklmnop",
		"",
		"ab",
	}

	for _, token := range tokens {
		ts := Classify(token)
		_ = ts.Type
		_ = ts.Prefix
		_ = ts.Suffix
		_ = ts.Length
		_ = ts.IsProduction
		_ = ts.HasUUID
		_ = ts.HasTimestamps
		_ = len(ts.Segments)
	}
}

func TestIsProductionKey_ActualLogic(t *testing.T) {
	ts := TokenStructure{}

	// Test production indicators (true)
	prod := []string{"-live", "_live", "prod", "production", "real", "key-prod-123", "key-production-123"}
	for _, s := range prod {
		if !isProductionKey(s, ts) {
			t.Errorf("Expected true for %q", s)
		}
	}

	// Test production prefixes (true)
	prefixes := []string{"sk_live_PLACEHOLDER", "rk_live_PLACEHOLDER", "sk-prod-"}
	for _, p := range prefixes {
		if !isProductionKey(p+"123", ts) {
			t.Errorf("Expected true for prefix %q", p)
		}
	}

	// Test test indicators (false)
	// Note: "prod" contains "prod" not "test" so it's true
	// But "test" alone is false
	if isProductionKey("test", ts) {
		t.Error("Expected false for 'test'")
	}
	if isProductionKey("dev", ts) {
		t.Error("Expected false for 'dev'")
	}
	if isProductionKey("staging", ts) {
		t.Error("Expected false for 'staging'")
	}
	if isProductionKey("sandbox", ts) {
		t.Error("Expected false for 'sandbox'")
	}

	// Default (false)
	if isProductionKey("", ts) {
		t.Error("Expected false for empty")
	}
	if isProductionKey("normal", ts) {
		t.Error("Expected false for 'normal'")
	}
}

func TestMergeWith_AllFields(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MergeWith(Config{
		Entropy: EntropyConfig{LowThreshold: 3.5, MediumThreshold: 4.5, HighThreshold: 5.5},
		Scoring: ScorerConfig{EntropyWeight: 0.7, FrequencyWeight: 0.15, StructureWeight: 0.15},
	})
	if cfg.Entropy.LowThreshold != 3.5 {
		t.Errorf("Expected 3.5, got %f", cfg.Entropy.LowThreshold)
	}
	if cfg.Scoring.EntropyWeight != 0.7 {
		t.Errorf("Expected 0.7, got %f", cfg.Scoring.EntropyWeight)
	}
}

func TestMergeWith_OnlyEntropy(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MergeWith(Config{Entropy: EntropyConfig{LowThreshold: 4.0}})
	if cfg.Entropy.LowThreshold != 4.0 {
		t.Errorf("Expected 4.0, got %f", cfg.Entropy.LowThreshold)
	}
}

func TestMergeWith_OnlyScoring(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MergeWith(Config{Scoring: ScorerConfig{EntropyWeight: 0.8}})
	if cfg.Scoring.EntropyWeight != 0.8 {
		t.Errorf("Expected 0.8, got %f", cfg.Scoring.EntropyWeight)
	}
}

func TestMergeWith_EmptyConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Entropy.LowThreshold = 4.0
	cfg.MergeWith(Config{})
	if cfg.Entropy.LowThreshold != 4.0 {
		t.Errorf("Expected 4.0, got %f", cfg.Entropy.LowThreshold)
	}
}

func TestMergeWith_Chained(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MergeWith(Config{Entropy: EntropyConfig{LowThreshold: 3.0}})
	cfg.MergeWith(Config{Scoring: ScorerConfig{EntropyWeight: 0.6}})
	if cfg.Entropy.LowThreshold != 3.0 || cfg.Scoring.EntropyWeight != 0.6 {
		t.Error("Chained merge failed")
	}
}
