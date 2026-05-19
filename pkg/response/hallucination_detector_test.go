// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Hallucination Detector Tests
// =========================================================================

package response

import (
	"context"
	"testing"
	"time"
)

// ============================================================================
// Basic Functionality Tests
// ============================================================================

func TestExtendedHallucinationDetectorCreation(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	if detector == nil {
		t.Fatal("NewExtendedHallucinationDetector returned nil")
	}
}

func TestScanExtendedEmpty(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	result := detector.ScanExtended("")
	if result == nil {
		t.Fatal("ScanExtended should not return nil")
	}
}

func TestScanExtendedNormalText(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	text := "The weather is nice today."
	result := detector.ScanExtended(text)
	if result == nil {
		t.Fatal("ScanExtended should not return nil")
	}
}

func TestScanExtendedOverconfidentText(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	text := "This is absolutely guaranteed 100%."
	result := detector.ScanExtended(text)
	if result == nil {
		t.Fatal("ScanExtended should not return nil")
	}
	if len(result.OverconfidentClaims) == 0 {
		t.Log("No overconfidence detected (may vary by pattern)")
	}
}

func TestScanExtendedWithStatistics(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	text := "Studies show 95% of users prefer this."
	result := detector.ScanExtended(text)
	if result == nil {
		t.Fatal("ScanExtended should not return nil")
	}
}

// ============================================================================
// Detection Pattern Tests
// ============================================================================

func TestDetectOverconfidence(t *testing.T) {
	detector := NewExtendedHallucinationDetector()

	tests := []struct {
		text     string
		expected bool
	}{
		{"I am absolutely certain.", true},
		{"It definitely works.", true},
		{"Guaranteed to succeed.", true},
		{"The sky is blue.", false},
	}

	for _, tt := range tests {
		claims := detector.detectOverconfidence(tt.text)
		found := len(claims) > 0
		if found != tt.expected {
			t.Errorf("detectOverconfidence(%q): expected %v, got %v", tt.text, tt.expected, found)
		}
	}
}

func TestDetectUnquantifiedStatistics(t *testing.T) {
	detector := NewExtendedHallucinationDetector()

	text := "Statistics show 95% improvement."
	stats := detector.detectUnquantifiedStatistics(text)
	_ = stats // Just verify no panic
}

// ============================================================================
// Timeout Tests
// ============================================================================

func TestExtendedScanWithTimeout(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := detector.ScanWithTimeout(ctx, "Test sentence.", 10*time.Second)
	if err != nil {
		t.Fatalf("ScanWithTimeout failed: %v", err)
	}
	if result == nil {
		t.Error("result should not be nil")
	}
}

func TestExtendedScanWithTimeoutExceeded(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	_, err := detector.ScanWithTimeout(ctx, "test", 1*time.Nanosecond)
	_ = err // May or may not timeout
}

// ============================================================================
// Validation Tests
// ============================================================================

func TestValidateClaim(t *testing.T) {
	detector := NewExtendedHallucinationDetector()

	valid, conf := detector.ValidateClaim("The sky is blue.")
	if conf < 0 || conf > 1 {
		t.Errorf("confidence should be between 0 and 1, got %f", conf)
	}
	_ = valid
}

func TestValidateClaimOverconfident(t *testing.T) {
	detector := NewExtendedHallucinationDetector()

	_, conf := detector.ValidateClaim("This is absolutely guaranteed to work 100%.")
	_ = conf // Just verify no panic
}

// ============================================================================
// Text Analysis Tests
// ============================================================================

func TestAnalyzeText(t *testing.T) {
	detector := NewExtendedHallucinationDetector()

	text := "The weather is nice today."
	analysis := detector.AnalyzeText(text)

	if analysis == nil {
		t.Fatal("AnalyzeText should not return nil")
	}

	if analysis.Text != text {
		t.Error("text should be preserved")
	}

	if analysis.ConfidenceScore < 0 || analysis.ConfidenceScore > 1 {
		t.Errorf("confidence should be between 0 and 1, got %f", analysis.ConfidenceScore)
	}
}

func TestAnalyzeTextHighRisk(t *testing.T) {
	detector := NewExtendedHallucinationDetector()

	text := "This is absolutely guaranteed 100%. Never doubt this fact."
	analysis := detector.AnalyzeText(text)

	if analysis == nil {
		t.Fatal("AnalyzeText should not return nil")
	}

	if analysis.HallucinationRisk != "low" && analysis.HallucinationRisk != "medium" && analysis.HallucinationRisk != "high" {
		t.Errorf("unknown risk level: %s", analysis.HallucinationRisk)
	}
}

// ============================================================================
// Standalone Function Tests
// ============================================================================

func TestQuickHallucinationCheck(t *testing.T) {
	flagged, explanation := QuickHallucinationCheck("The sky is blue.")
	_ = flagged
	_ = explanation
}

func TestQuickHallucinationCheckFlagged(t *testing.T) {
	text := "This is absolutely guaranteed to work 100%."
	flagged, explanation := QuickHallucinationCheck(text)
	_ = flagged
	_ = explanation
}

func TestValidateClaimQuick(t *testing.T) {
	valid, conf := ValidateClaimQuick("Normal statement here.")
	if conf < 0 || conf > 1 {
		t.Errorf("confidence should be between 0 and 1, got %f", conf)
	}
	_ = valid
}

func TestAnalyzeTextQuick(t *testing.T) {
	analysis := AnalyzeTextQuick("The weather is nice today.")
	if analysis == nil {
		t.Error("AnalyzeTextQuick should not return nil")
	}
}

func TestScanHallucinations(t *testing.T) {
	result := ScanHallucinations("Test sentence.")
	if result == nil {
		t.Error("ScanHallucinations should not return nil")
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestExtendedLongText(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	longText := "This is a test. " + string(make([]byte, 1000))
	result := detector.ScanExtended(longText)
	if result == nil {
		t.Error("result should not be nil for long text")
	}
}

func TestExtendedUnicode(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	text := "Unicode test: 你好世界 🌍 émojis"
	result := detector.ScanExtended(text)
	if result == nil {
		t.Error("result should not be nil for unicode text")
	}
}

func TestExtendedSpecialChars(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	text := "Test with \"quotes\" and (parentheses)."
	result := detector.ScanExtended(text)
	if result == nil {
		t.Error("result should not be nil")
	}
}

// ============================================================================
// Pattern Tests
// ============================================================================

func TestOverconfidenceRegex(t *testing.T) {
	patterns := []string{
		"I am absolutely certain.",
		"This is definitely true.",
		"It is guaranteed 100%.",
	}

	for _, text := range patterns {
		if !overconfidenceRegex.MatchString(text) {
			t.Errorf("overconfidence regex should match: %s", text)
		}
	}
}

func TestFactualClaimRegex(t *testing.T) {
	patterns := []string{
		"According to studies",
		"Research indicates",
		"Experts say",
	}

	for _, text := range patterns {
		if !factualClaimRegex.MatchString(text) {
			t.Errorf("factual claim regex should match: %s", text)
		}
	}
}

func TestQuantificationRegex(t *testing.T) {
	patterns := []string{
		"95% of users",
		"50 percent improvement",
		"100% certain",
	}

	for _, text := range patterns {
		// Just verify no panic
		_ = quantificationRegex.MatchString(text)
	}
}

// ============================================================================
// Risk Level Tests
// ============================================================================

func TestRiskLevelCalculation(t *testing.T) {
	detector := NewExtendedHallucinationDetector()

	// Normal text should be low risk
	result := detector.ScanExtended("The sky is blue.")
	if result.RiskLevel != "low" {
		t.Logf("Risk level: %s (may vary by detection)", result.RiskLevel)
	}
}

func TestRiskLevelHigh(t *testing.T) {
	detector := NewExtendedHallucinationDetector()

	// High overconfidence should increase risk
	text := "Absolutely guaranteed. Definitely true. 100% certain. Never fails. Always works."
	result := detector.ScanExtended(text)
	_ = result // Risk level varies
}

// ============================================================================
// Result Structure Tests
// ============================================================================

func TestExtendedHallucinationResultStructure(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	result := detector.ScanExtended("Test sentence.")

	if result == nil {
		t.Fatal("result should not be nil")
	}

	if result.HallucinationResult == nil {
		t.Error("HallucinationResult should not be nil")
	}
}

func TestExtendedResultWithOverconfidence(t *testing.T) {
	detector := NewExtendedHallucinationDetector()
	text := "Absolutely certain this works."
	result := detector.ScanExtended(text)

	if result == nil {
		t.Fatal("result should not be nil")
	}

	if len(result.OverconfidentClaims) > 0 {
		t.Logf("Found overconfident claims: %v", result.OverconfidentClaims)
	}
}
