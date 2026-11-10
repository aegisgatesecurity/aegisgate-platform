// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Detector Adapter Tests
//
// Tests for the DetectorAdapter that wraps the vendored scanner detectors
// for proxy pipeline integration.

package scanner

import (
	"strings"
	"testing"

	scannerdetectors "github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

func TestNewDetectorAdapter(t *testing.T) {
	da := NewDetectorAdapter()
	if da == nil {
		t.Fatal("NewDetectorAdapter returned nil")
	}
	if !da.blockSeverities[scannerdetectors.SeverityHigh] {
		t.Error("High severity should be in blockSeverities")
	}
	if !da.blockSeverities[scannerdetectors.SeverityCritical] {
		t.Error("Critical severity should be in blockSeverities")
	}
	if da.blockSeverities[scannerdetectors.SeverityMedium] {
		t.Error("Medium severity should NOT be in blockSeverities")
	}
	if da.blockSeverities[scannerdetectors.SeverityLow] {
		t.Error("Low severity should NOT be in blockSeverities")
	}
}

func TestTotalDetectorPatterns(t *testing.T) {
	total := TotalDetectorPatterns()
	if total < 500 {
		t.Errorf("TotalDetectorPatterns() = %d, expected >= 500", total)
	}
}

func TestScan(t *testing.T) {
	da := NewDetectorAdapter()

	// Attack content should produce matches
	matches := da.Scan("eval('malicious code')")
	if len(matches) == 0 {
		t.Error("Scan should find matches for dangerous eval() call")
	}

	// Empty content should return nil
	matches = da.Scan("")
	if matches != nil {
		t.Errorf("Scan(\"\") = %v, expected nil", matches)
	}

	// Benign content may or may not have matches, just verify no panic
	_ = da.Scan("Hello, how are you today?")
}

func TestShouldBlock(t *testing.T) {
	da := NewDetectorAdapter()

	// Critical severity should block
	criticalMatches := []scannerdetectors.Match{
		{Category: "test", Severity: scannerdetectors.SeverityCritical, Confidence: 0.9},
	}
	if !da.ShouldBlock(criticalMatches) {
		t.Error("ShouldBlock should return true for Critical severity")
	}

	// High severity should block
	highMatches := []scannerdetectors.Match{
		{Category: "test", Severity: scannerdetectors.SeverityHigh, Confidence: 0.8},
	}
	if !da.ShouldBlock(highMatches) {
		t.Error("ShouldBlock should return true for High severity")
	}

	// Medium severity should NOT block
	mediumMatches := []scannerdetectors.Match{
		{Category: "test", Severity: scannerdetectors.SeverityMedium, Confidence: 0.5},
	}
	if da.ShouldBlock(mediumMatches) {
		t.Error("ShouldBlock should return false for Medium severity")
	}

	// Empty matches should NOT block
	if da.ShouldBlock(nil) {
		t.Error("ShouldBlock should return false for nil matches")
	}
}

func TestScanAndBlock(t *testing.T) {
	da := NewDetectorAdapter()

	// Dangerous content should block
	blocked, names := da.ScanAndBlock("eval('malicious code')")
	if !blocked {
		t.Error("ScanAndBlock should block dangerous eval() content")
	}
	if len(names) == 0 {
		t.Error("ScanAndBlock should return blocking pattern names")
	}

	// Verify names contain expected pattern
	foundEval := false
	for _, name := range names {
		if strings.Contains(name, "eval") {
			foundEval = true
			break
		}
	}
	if !foundEval {
		t.Errorf("ScanAndBlock names %v should contain an eval-related pattern", names)
	}

	// Empty content should not block
	blocked, names = da.ScanAndBlock("")
	if blocked {
		t.Error("ScanAndBlock should not block empty content")
	}
	if names != nil {
		t.Errorf("ScanAndBlock names for empty content should be nil, got %v", names)
	}
}

func TestScanVariants(t *testing.T) {
	da := NewDetectorAdapter()

	// Dangerous content in original should block
	blocked, names := da.ScanVariants("eval('malicious code')", []string{"rot13_variant"})
	if !blocked {
		t.Error("ScanVariants should block when original content has dangerous patterns")
	}
	if len(names) == 0 {
		t.Error("ScanVariants should return blocking pattern names")
	}

	// Benign original with no variants should not block
	blocked, _ = da.ScanVariants("Hello world", nil)
	if blocked {
		t.Error("ScanVariants should not block benign content")
	}

	// Empty content should not block
	blocked, _ = da.ScanVariants("", []string{"variant"})
	if blocked {
		t.Error("ScanVariants should not block empty content")
	}

	// Variant identical to original should be skipped (no double-scan)
	blocked, _ = da.ScanVariants("Hello world", []string{"Hello world"})
	if blocked {
		t.Error("ScanVariants should not block when variant equals original (benign)")
	}

	// Data category patterns should only match on original, not variants
	// AWS key in original should block
	awsKey := "AKIAIOSFODNN7EXAMPLE"
	blocked, _ = da.ScanVariants(awsKey, []string{"benign_variant_text"})
	if !blocked {
		t.Error("ScanVariants should block AWS key in original content")
	}
}

func TestScanVariantsDataCategorySuppression(t *testing.T) {
	da := NewDetectorAdapter()

	// This test verifies that data categories (PII, secrets) are NOT scanned
	// on variants. We can't easily produce a variant that triggers a data FP,
	// but we can verify that a benign variant doesn't cause blocks from
	// data-like patterns that might accidentally match.
	blocked, _ := da.ScanVariants("Hello, I have a question about Python.", []string{"some random text here"})
	// Should not block - neither original nor variant has attack patterns
	if blocked {
		t.Error("ScanVariants should not block benign content + benign variant")
	}
}

func TestIsDataCategoryMatch(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"pii_ssn", true},
		{"pii_us_passport", true},
		{"secret_aws_key", true},
		{"secret_github_token", true},
		{"some_pii_pattern", true},
		{"dangerous_py_eval", false},
		{"injection_sql", false},
		{"evasion_lolbin", false},
		{"socialeng_phishing", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isDataCategoryMatch(tt.name)
			if result != tt.expected {
				t.Errorf("isDataCategoryMatch(%q) = %v, expected %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestLogFindings(t *testing.T) {
	da := NewDetectorAdapter()

	// Should not panic with nil matches
	da.LogFindings("request", "/v1/chat/completions", nil)

	// Should not panic with blocking matches
	blockingMatches := []scannerdetectors.Match{
		{Category: "dangerous_py_eval", Severity: scannerdetectors.SeverityCritical, Confidence: 0.95, Value: "eval("},
	}
	da.LogFindings("request", "/v1/chat/completions", blockingMatches)

	// Should not panic with non-blocking matches
	nonBlockingMatches := []scannerdetectors.Match{
		{Category: "low_severity_pattern", Severity: scannerdetectors.SeverityLow, Confidence: 0.3, Value: "test"},
	}
	da.LogFindings("response", "/v1/chat/completions", nonBlockingMatches)

	// Should not panic with mixed matches
	mixedMatches := []scannerdetectors.Match{
		{Category: "dangerous_py_eval", Severity: scannerdetectors.SeverityCritical, Confidence: 0.95, Value: "eval("},
		{Category: "low_severity_pattern", Severity: scannerdetectors.SeverityLow, Confidence: 0.3, Value: "test"},
	}
	da.LogFindings("request", "/v1/chat/completions", mixedMatches)
}

func TestScanVariantsAttackOnVariant(t *testing.T) {
	da := NewDetectorAdapter()

	// Original is benign, but variant contains attack pattern.
	// Attack categories should be scanned on variants.
	// We use a normalization variant that contains a dangerous function call.
	benignOriginal := "I am learning about web development."
	attackVariant := "eval('payload')"
	blocked, names := da.ScanVariants(benignOriginal, []string{attackVariant})
	if !blocked {
		t.Error("ScanVariants should block when variant contains attack patterns")
	}
	if len(names) == 0 {
		t.Error("ScanVariants should return blocking pattern names from variant")
	}
}
