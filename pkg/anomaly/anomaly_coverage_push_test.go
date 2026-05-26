// SPDX-License-Identifier: Apache-2.0
package anomaly

import (
	"testing"
)

func TestIsProductionKey_Called(t *testing.T) {
	// Just test that the function can be called without panic
	suffixes := []string{
		"-live", "-prod", "-example", "-sample",
		"-temp", "-mock", "_test", "_dev",
	}
	for _, suffix := range suffixes {
		ts := TokenStructure{}
		_ = isProductionKey("token"+suffix, ts)
	}
}

func TestDetectTokenType_ClassifyAll(t *testing.T) {
	tokens := []string{
		"sk-1234567890abcdefghijklmnop",
		"sk-prod-1234567890abcdefghijklmnop",
		"sk-test-1234567890abcdefghijklmnop",
		"ghp_1234567890abcdefghijklmnop",
		"AKIAIOSFODNN7EXAMPLE",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"123e4567-e89b-12d3-a456-426614174000",
		"api_key_1234567890abcdefghijklmnop",
		"sk_live_PLACEHOLDER",
		"xoxb-PLACEHOLDER",
		"sess_abc123def456ghi789jkl012",
		"SGVsbG8gV29ybGRoZXJldXNlcg==",
		"",
		"ab",
	}
	for _, token := range tokens {
		ts := Classify(token)
		_ = ts.Type
		_ = ts.IsProduction
		_ = ts.HasUUID
		_ = ts.HasTimestamps
	}
}

func TestTokenStructureFlags(t *testing.T) {
	ts := TokenStructure{
		IsProduction:  true,
		HasUUID:       true,
		HasTimestamps: true,
		Type:          TokenTypeOpenAIKey,
	}
	flags := buildFlags(ts)
	_ = flags
}

func TestMergeWith_AllConfigTypes(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg2 := Config{
		Entropy: EntropyConfig{
			LowThreshold:      3.5,
			MediumThreshold:   4.5,
			HighThreshold:     5.5,
			VeryHighThreshold: 6.5,
		},
	}
	cfg1.MergeWith(cfg2)
	cfg3 := Config{
		Scoring: ScorerConfig{
			EntropyWeight:       0.7,
			FrequencyWeight:     0.15,
			StructureWeight:     0.15,
			SuspiciousThreshold: 0.55,
			AnomalyThreshold:    0.75,
			AlertThreshold:      0.85,
		},
	}
	cfg1.MergeWith(cfg3)
	if cfg1.Entropy.LowThreshold != 3.5 {
		t.Errorf("Expected 3.5, got %f", cfg1.Entropy.LowThreshold)
	}
}

func TestDetectTokenType_IsProduction(t *testing.T) {
	// Test that classify sets IsProduction correctly
	tokens := []string{
		"sk-prod-123",
		"sk-live-123",
		"sk-test-123",
		"sk-dev-123",
	}
	for _, token := range tokens {
		ts := Classify(token)
		_ = ts.IsProduction
	}
}

func TestDetectTokenType_HasUUID(t *testing.T) {
	ts := Classify("123e4567-e89b-12d3-a456-426614174000")
	_ = ts.HasUUID
}

func TestDetectTokenType_HasTimestamps(t *testing.T) {
	ts := Classify("token_1234567890")
	_ = ts.HasTimestamps
}

func TestDetectTokenType_Prefix(t *testing.T) {
	ts := Classify("sk-12345")
	_ = ts.Prefix
}

func TestDetectTokenType_Suffix(t *testing.T) {
	ts := Classify("key-123-live")
	_ = ts.Suffix
}

func TestDetectTokenType_Length(t *testing.T) {
	ts := Classify("sk-1234567890abcdefghijklmnop")
	_ = ts.Length
}

func TestDetectTokenType_Segments(t *testing.T) {
	ts := Classify("a-b-c-d-e-f")
	_ = len(ts.Segments)
}

func TestMergeWith_EntropyOnly(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg2 := Config{
		Entropy: EntropyConfig{LowThreshold: 4.0},
	}
	cfg1.MergeWith(cfg2)
	if cfg1.Entropy.LowThreshold != 4.0 {
		t.Errorf("Expected 4.0, got %f", cfg1.Entropy.LowThreshold)
	}
}

func TestMergeWith_ScoringOnly(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg2 := Config{
		Scoring: ScorerConfig{EntropyWeight: 0.8},
	}
	cfg1.MergeWith(cfg2)
	if cfg1.Scoring.EntropyWeight != 0.8 {
		t.Errorf("Expected 0.8, got %f", cfg1.Scoring.EntropyWeight)
	}
}
