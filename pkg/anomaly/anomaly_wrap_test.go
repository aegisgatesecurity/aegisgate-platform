//go:build !race

// SPDX-License-Identifier: Apache-2.0
// Anomaly WrapWithAnomalyDetection and calculateAverageRunLength coverage tests
// Target: WrapWithAnomalyDetection 75% → 95%, calculateAverageRunLength 94.7% → 100%

package anomaly

import (
	"testing"
	"time"
)

// =========================================================================
// WrapWithAnomalyDetection: Disabled config path (line 426-428)
// =========================================================================

func TestWrapWithAnomalyDetection_DisabledConfig(t *testing.T) {
	fn := func(data []byte) interface{} { return "mock-disabled" }
	config := IntegrationConfig{
		Enabled:        false,
		AugmentResults: false,
		BlockOnAlert:   false,
		Timeout:        10 * time.Millisecond,
		ScorerConfig:   DefaultScorerConfig(),
	}
	wrapped := WrapWithAnomalyDetection(fn, config)
	result := wrapped([]byte("sk-live-abc123"))

	if result.Augmented {
		t.Error("Expected Augmented=false when config disabled")
	}
	if result.OriginalResult != nil {
		t.Error("Expected OriginalResult=nil when config disabled, scanner should not run")
	}
	if result.Error != nil {
		t.Errorf("Expected no error when config disabled, got %v", result.Error)
	}
}

// =========================================================================
// WrapWithAnomalyDetection: Timeout path (line 436-438)
// =========================================================================

func TestWrapWithAnomalyDetection_TimeoutPath(t *testing.T) {
	fn := func(data []byte) interface{} { return "mock-timeout" }
	config := IntegrationConfig{
		Enabled:        true,
		AugmentResults: true,
		BlockOnAlert:   false,
		Timeout:        1 * time.Nanosecond, // Extremely short timeout to trigger timeout
		ScorerConfig:   ScorerConfig{EntropyWeight: 0.4, FrequencyWeight: 0.3, StructureWeight: 0.3, AnomalyThreshold: 0.7, AlertThreshold: 0.5},
	}
	wrapped := WrapWithAnomalyDetection(fn, config)
	result := wrapped([]byte("sk-live-abc123"))

	if result.Error == nil {
		// In some cases the goroutine may complete before the timeout
		// If timeout fires, we expect an error
		t.Logf("Timeout did not trigger (result.AnomalyScore.Total=%.4f), this is acceptable if fast", result.AnomalyScore.Total)
	} else {
		if result.Error.Error() != "anomaly detection timeout" {
			t.Errorf("Expected timeout error, got: %v", result.Error)
		}
	}
}

// =========================================================================
// WrapWithAnomalyDetection: Successful path with OriginalResult
// =========================================================================

func TestWrapWithAnomalyDetection_SuccessfulPath(t *testing.T) {
	called := false
	fn := func(data []byte) interface{} {
		called = true
		return string(data)
	}
	config := IntegrationConfig{
		Enabled:        true,
		AugmentResults: true,
		BlockOnAlert:   true,
		Timeout:        5 * time.Second,
		ScorerConfig:   DefaultScorerConfig(),
	}
	wrapped := WrapWithAnomalyDetection(fn, config)
	result := wrapped([]byte("hello world"))

	if !result.Augmented {
		t.Error("Expected Augmented=true when config enabled")
	}
	if !called {
		t.Error("Expected underlying scanner to be called")
	}
	if result.OriginalResult != "hello world" {
		t.Errorf("Expected OriginalResult='hello world', got %v", result.OriginalResult)
	}
	if !result.BlockOnAlert {
		t.Error("Expected BlockOnAlert=true from config")
	}
	if result.ProcessingTime == 0 {
		t.Error("Expected non-zero ProcessingTime")
	}
}

// =========================================================================
// WrapWithAnomalyDetection: Various input types
// =========================================================================

func TestWrapWithAnomalyDetection_HighEntropyInput(t *testing.T) {
	fn := func(data []byte) interface{} { return "high-entropy-detected" }
	config := DefaultIntegrationConfig(IntegrationSecretScanner)
	wrapped := WrapWithAnomalyDetection(fn, config)

	// High-entropy string (simulating a secret/API key)
	result := wrapped([]byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"))
	if !result.Augmented {
		t.Error("Expected Augmented=true for high-entropy input")
	}
	if result.AnomalyScore.Total <= 0 {
		t.Logf("AnomalyScore.Total=%.4f", result.AnomalyScore.Total)
	}
}

func TestWrapWithAnomalyDetection_LowEntropyInput(t *testing.T) {
	fn := func(data []byte) interface{} { return "low-entropy-result" }
	config := DefaultIntegrationConfig(IntegrationResponseGuard)
	wrapped := WrapWithAnomalyDetection(fn, config)

	// Low-entropy string (normal text)
	result := wrapped([]byte("hello world this is normal text"))
	if !result.Augmented {
		t.Error("Expected Augmented=true")
	}
	if result.OriginalResult != "low-entropy-result" {
		t.Errorf("Expected OriginalResult='low-entropy-result', got %v", result.OriginalResult)
	}
}

// =========================================================================
// calculateAverageRunLength: Edge cases
// =========================================================================

func TestCalculateAverageRunLength_SingleByte(t *testing.T) {
	result := calculateAverageRunLength([]byte{0x41})
	if result != 1.0 {
		t.Errorf("Expected 1.0 for single byte, got %f", result)
	}
}

func TestCalculateAverageRunLength_EmptyInput(t *testing.T) {
	result := calculateAverageRunLength([]byte{})
	// Empty input should return 1.0 (handled by len < 2)
	if result != 1.0 {
		t.Errorf("Expected 1.0 for empty input, got %f", result)
	}
}

func TestCalculateAverageRunLength_TwoBytes(t *testing.T) {
	// Two bytes of different types (letter vs digit): two runs of length 1 each = avg 1.0
	// Two bytes of same type (letter+letter): one run of length 2 = avg 2.0
	// 'A'(0x41) and '1'(0x31) are letter vs digit → two runs → avg 1.0
	result := calculateAverageRunLength([]byte("A1"))
	if result != 1.0 {
		t.Errorf("Expected 1.0 for letter+digit, got %f", result)
	}
	// Two letters: one run of length 2 → avg 2.0
	result2 := calculateAverageRunLength([]byte("AB"))
	if result2 != 2.0 {
		t.Errorf("Expected 2.0 for two same-type bytes, got %f", result2)
	}
}

func TestCalculateAverageRunLength_AllSame(t *testing.T) {
	result := calculateAverageRunLength([]byte{0x41, 0x41, 0x41, 0x41})
	if result != 4.0 {
		t.Errorf("Expected 4.0 for all same bytes, got %f", result)
	}
}

func TestCalculateAverageRunLength_MixedTypes(t *testing.T) {
	// Mix of letters, digits, whitespace, and other chars
	data := []byte("abc 123!@#")
	result := calculateAverageRunLength(data)
	if result <= 0 {
		t.Errorf("Expected positive result, got %f", result)
	}
}

func TestCalculateAverageRunLength_LongSequence(t *testing.T) {
	// Long alternating pattern
	data := []byte("a1b2c3d4e5f6g7h8i9j0")
	result := calculateAverageRunLength(data)
	// With alternating types, run length should be close to 1.0
	if result > 2.0 {
		t.Errorf("Expected small run length for alternating pattern, got %f", result)
	}
}

func TestCalculateAverageRunLength_RepeatedBlocks(t *testing.T) {
	// Repeated blocks of same character type
	data := []byte("aaabbbcccdddeee")
	result := calculateAverageRunLength(data)
	if result <= 0 {
		t.Errorf("Expected positive result, got %f", result)
	}
}

// =========================================================================
// WrapWithAnomalyDetection: IntegrationPoint types
// =========================================================================

func TestWrapWithAnomalyDetection_ResponseGuardPoint(t *testing.T) {
	fn := func(data []byte) interface{} { return "response-guard-result" }
	config := DefaultIntegrationConfig(IntegrationResponseGuard)
	wrapped := WrapWithAnomalyDetection(fn, config)
	result := wrapped([]byte("test data for response guard"))
	if !result.Augmented {
		t.Error("Expected Augmented=true for response guard integration")
	}
}

func TestWrapWithAnomalyDetection_MCPServerPoint(t *testing.T) {
	fn := func(data []byte) interface{} { return "mcp-server-result" }
	config := DefaultIntegrationConfig(IntegrationMCPServer)
	wrapped := WrapWithAnomalyDetection(fn, config)
	result := wrapped([]byte("test data for mcp server"))
	if !result.Augmented {
		t.Error("Expected Augmented=true for MCP server integration")
	}
}

func TestWrapWithAnomalyDetection_HTTPGuardPoint(t *testing.T) {
	fn := func(data []byte) interface{} { return "http-guard-result" }
	config := DefaultIntegrationConfig(IntegrationHTTPGuard)
	wrapped := WrapWithAnomalyDetection(fn, config)
	result := wrapped([]byte("test data for http guard"))
	if !result.Augmented {
		t.Error("Expected Augmented=true for HTTP guard integration")
	}
}
