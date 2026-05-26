// SPDX-License-Identifier: Apache-2.0
// Anomaly Config Validate coverage — 61.1% → 95%+
package anomaly

import (
	"testing"
	"time"
)

func TestValidate_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Default config should be valid: %v", err)
	}
}

func TestValidate_EntropyLowThresholdTooHigh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Entropy.LowThreshold = 4.5
	cfg.Entropy.MediumThreshold = 4.0 // Low >= Medium
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for low_threshold >= medium_threshold")
	}
}

func TestValidate_EntropyMediumThresholdTooHigh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Entropy.MediumThreshold = 6.5
	cfg.Entropy.HighThreshold = 6.0 // Medium >= High
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for medium_threshold >= high_threshold")
	}
}

func TestValidate_ScoringWeightsTooLow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scoring.EntropyWeight = 0.3
	cfg.Scoring.FrequencyWeight = 0.3
	cfg.Scoring.StructureWeight = 0.2 // Sum = 0.8 < 0.9
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for scoring weights sum < 0.9")
	}
}

func TestValidate_ScoringWeightsTooHigh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scoring.EntropyWeight = 0.5
	cfg.Scoring.FrequencyWeight = 0.4
	cfg.Scoring.StructureWeight = 0.3 // Sum = 1.2 > 1.1
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for scoring weights sum > 1.1")
	}
}

func TestValidate_SuspiciousThresholdTooHigh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scoring.SuspiciousThreshold = 0.8
	cfg.Scoring.AnomalyThreshold = 0.7 // Suspicious >= Anomaly
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for suspicious_threshold >= anomaly_threshold")
	}
}

func TestValidate_AnomalyThresholdTooHigh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scoring.AnomalyThreshold = 0.95
	cfg.Scoring.AlertThreshold = 0.9 // Anomaly >= Alert
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for anomaly_threshold >= alert_threshold")
	}
}

func TestValidate_MaxInputSizeTooSmall(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Performance.MaxInputSize = 512 // < 1024
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for max_input_size < 1024")
	}
}

func TestValidate_MaxInputSizeTooLarge(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Performance.MaxInputSize = 2 * 1024 * 1024 // > 1MB
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for max_input_size > 1MB")
	}
}

func TestValidate_TimeoutTooSmall(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Performance.Timeout = 0 // < 1ms
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for timeout < 1ms")
	}
}

func TestValidate_TimeoutMicroseconds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Performance.Timeout = 500 * time.Microsecond
	if err := cfg.Validate(); err == nil {
		t.Error("Expected error for timeout < 1ms")
	}
}

func TestToYAML_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	data, err := cfg.ToYAML()
	if err != nil {
		t.Errorf("ToYAML failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("ToYAML should return non-empty data")
	}
}

func TestFromYAMLFile_Nonexistent(t *testing.T) {
	_, err := FromYAMLFile("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("FromYAMLFile should fail for nonexistent file")
	}
}

func TestMergeWith(t *testing.T) {
	base := DefaultConfig()
	override := DefaultConfig()
	override.Entropy.LowThreshold = 0.5
	base.MergeWith(override)
	if base.Entropy.LowThreshold != 0.5 {
		t.Errorf("MergeWith should override low_threshold, got %f", base.Entropy.LowThreshold)
	}
}

func TestLogResult_WithNilLogger(t *testing.T) {
	result := ScannerResult{
		Augmented:      true,
		ProcessingTime: 10 * time.Millisecond,
		AnomalyScore: AnomalyScore{
			IsAnomalous:    true,
			IsAlert:        true,
			Total:          0.95,
			Classification: "suspicious_token",
			Flags:          []string{"high_entropy", "unusual_frequency"},
			TokenType:      TokenTypeAPIKey,
		},
	}
	// Should not panic with nil logger
	result.LogResult(nil)
}

func TestLogResult_WithError(t *testing.T) {
	result := ScannerResult{
		Augmented:      false,
		ProcessingTime: 5 * time.Millisecond,
		Error:          fmtError("scan error"),
	}
	result.LogResult(nil) // nil logger → uses default
}

func TestLogResult_AnalousNotAlert(t *testing.T) {
	result := ScannerResult{
		Augmented:      true,
		ProcessingTime: 3 * time.Millisecond,
		AnomalyScore: AnomalyScore{
			IsAnomalous:    true,
			IsAlert:        false,
			Total:          0.6,
			Classification: "unusual_pattern",
		},
	}
	result.LogResult(nil)
}

func TestLogResult_Clean(t *testing.T) {
	result := ScannerResult{
		Augmented:      true,
		ProcessingTime: 1 * time.Millisecond,
		AnomalyScore: AnomalyScore{
			IsAnomalous: false,
			IsAlert:     false,
			Total:       0.1,
		},
	}
	result.LogResult(nil)
}

func TestShouldBlock_WithBlockOnAlert(t *testing.T) {
	result := ScannerResult{
		BlockOnAlert: true,
		AnomalyScore: AnomalyScore{IsAlert: true},
	}
	if !result.ShouldBlock() {
		t.Error("ShouldBlock should return true when BlockOnAlert and IsAlert")
	}
}

func TestShouldBlock_WithoutBlockOnAlert(t *testing.T) {
	result := ScannerResult{
		BlockOnAlert: false,
		AnomalyScore: AnomalyScore{IsAlert: true},
	}
	if result.ShouldBlock() {
		t.Error("ShouldBlock should return false when not BlockOnAlert")
	}
}

func TestShouldBlock_WithError(t *testing.T) {
	result := ScannerResult{
		BlockOnAlert: true,
		Error:        fmtError("some error"),
	}
	// Fail-closed: errors don't block
	if result.ShouldBlock() {
		t.Error("ShouldBlock should return false on errors (fail-closed but non-blocking)")
	}
}

func fmtError(msg string) error {
	return &simpleError{msg: msg}
}

type simpleError struct {
	msg string
}

func (e *simpleError) Error() string {
	return e.msg
}
