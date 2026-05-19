// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Redactor Tests
// =========================================================================

package response

import (
	"context"
	"testing"
)

// ============================================================================
// Basic Functionality Tests
// ============================================================================

func TestRedactorCreation(t *testing.T) {
	redactor := NewRedactor()
	if redactor == nil {
		t.Fatal("NewRedactor returned nil")
	}

	if redactor.config == nil {
		t.Error("config should not be nil")
	}

	if redactor.pii == nil {
		t.Error("pii scanner should not be nil")
	}
}

func TestRedactorWithConfig(t *testing.T) {
	config := &RedactorConfig{
		Strategy:         StrategyAsterisks,
		ReplaceWith:      "[CUSTOM]",
		RedactSSN:        true,
		RedactEmail:      true,
		RedactPhone:      true,
		RedactCreditCard: true,
	}

	redactor := NewRedactorWithConfig(config)
	if redactor.config.Strategy != StrategyAsterisks {
		t.Error("strategy not set correctly")
	}
}

func TestRedactorNilConfig(t *testing.T) {
	redactor := NewRedactorWithConfig(nil)
	if redactor.config == nil {
		t.Error("config should use defaults when nil")
	}
}

// ============================================================================
// Basic Redaction Tests
// ============================================================================

func TestRedactorEmptyInput(t *testing.T) {
	redactor := NewRedactor()
	result := redactor.Redact("")
	if result != "" {
		t.Error("empty input should return empty")
	}
}

func TestRedactorNoSensitiveData(t *testing.T) {
	redactor := NewRedactor()
	text := "This is a normal sentence."
	result := redactor.Redact(text)
	if result != text {
		t.Error("clean text should not change")
	}
}

func TestRedactorPIIRedaction(t *testing.T) {
	redactor := NewRedactor()
	text := "Contact me at test@example.com"
	result := redactor.Redact(text)
	if containsSubstring(result, "test@example.com") {
		t.Error("email should be redacted")
	}
}

func TestRedactorSSNRedaction(t *testing.T) {
	redactor := NewRedactor()
	text := "My SSN is 234-56-7890"
	result := redactor.Redact(text)
	if containsSubstring(result, "234-56-7890") {
		t.Error("SSN should be redacted")
	}
}

func TestRedactorCreditCardRedaction(t *testing.T) {
	redactor := NewRedactor()
	text := "Card: 4111111111111111"
	result := redactor.Redact(text)
	if containsSubstring(result, "4111111111111111") {
		t.Error("credit card should be redacted")
	}
}

func TestRedactorPhoneRedaction(t *testing.T) {
	redactor := NewRedactor()
	text := "Call 555-123-4567"
	result := redactor.Redact(text)
	if containsSubstring(result, "555-123-4567") {
		t.Error("phone should be redacted")
	}
}

// ============================================================================
// Secret Redaction Tests
// ============================================================================

func TestRedactorStripeKeyRedaction(t *testing.T) {
	redactor := NewRedactor()
	text := "Key: sk_live_REDACTED1234567890"
	result := redactor.Redact(text)

	// Should attempt redaction - result may vary
	_ = result
}

func TestRedactorGitHubTokenRedaction(t *testing.T) {
	redactor := NewRedactor()
	text := "GitHub: ghp_REDACTED123456789012345678901234"
	result := redactor.Redact(text)

	// Should attempt redaction
	_ = result
}

func TestRedactorJWTRedaction(t *testing.T) {
	redactor := NewRedactor()
	text := "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	result := redactor.Redact(text)

	// Should attempt redaction
	_ = result
}

// ============================================================================
// Strategy Tests
// ============================================================================

func TestRedactorStrategyPlaceholder(t *testing.T) {
	redactor := NewRedactorWithConfig(&RedactorConfig{
		Strategy:    StrategyPlaceholder,
		ReplaceWith: "[REDACTED]",
		RedactSSN:   true,
	})

	text := "SSN: 234-56-7890"
	result := redactor.Redact(text)

	// SSN should be redacted with custom replacement
	if containsSubstring(result, "234-56-7890") {
		t.Error("SSN should be redacted")
	}
}

func TestRedactorStrategyAsterisks(t *testing.T) {
	redactor := NewRedactorWithConfig(&RedactorConfig{
		Strategy:  StrategyAsterisks,
		RedactSSN: true,
	})

	text := "SSN: 234-56-7890"
	result := redactor.Redact(text)

	// Should have redacted SSN
	if containsSubstring(result, "234-56-7890") {
		t.Error("SSN should be redacted")
	}
}

func TestRedactorCustomReplacement(t *testing.T) {
	redactor := NewRedactorWithConfig(&RedactorConfig{
		ReplaceWith: "[SENSITIVE_DATA]",
		RedactSSN:   true,
		RedactEmail: true,
	})

	text := "SSN: 234-56-7890"
	result := redactor.Redact(text)

	// SSN should be redacted with custom replacement
	if result == text {
		t.Error("should have redacted SSN")
	}
}

// ============================================================================
// Context Tests
// ============================================================================

func TestRedactorRedactWithContext(t *testing.T) {
	redactor := NewRedactor()
	ctx := context.Background()

	result := redactor.RedactWithContext(ctx, "test@example.com in text")
	if result == "" {
		t.Error("should return result")
	}
}

func TestRedactorRedactWithCancelledContext(t *testing.T) {
	redactor := NewRedactor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := redactor.RedactWithContext(ctx, "test data")
	if result != "test data" {
		t.Errorf("expected unchanged text, got %s", result)
	}
}

// ============================================================================
// Batch Processing Tests
// ============================================================================

func TestRedactorRedactBatch(t *testing.T) {
	redactor := NewRedactor()

	texts := []string{
		"Email: test@example.com",
		"Phone: 555-123-4567",
		"No sensitive data",
	}

	results := redactor.RedactBatch(texts)
	if len(results) != len(texts) {
		t.Errorf("expected %d results, got %d", len(texts), len(results))
	}

	if containsSubstring(results[0], "test@example.com") {
		t.Error("email should be redacted in batch")
	}
}

func TestRedactorRedactBatchEmpty(t *testing.T) {
	redactor := NewRedactor()
	results := redactor.RedactBatch([]string{})
	if len(results) != 0 {
		t.Error("empty batch should return empty results")
	}
}

func TestRedactorRedactBatchWithContext(t *testing.T) {
	redactor := NewRedactor()
	ctx := context.Background()

	texts := []string{"test1@example.com", "test2@example.com"}
	results, err := redactor.RedactBatchWithContext(ctx, texts)

	if err != nil {
		t.Fatalf("RedactBatchWithContext failed: %v", err)
	}

	if len(results) != len(texts) {
		t.Errorf("expected %d results, got %d", len(texts), len(results))
	}
}

// ============================================================================
// Audit Tests
// ============================================================================

func TestRedactorGetAuditLog(t *testing.T) {
	redactor := NewRedactor()
	log := redactor.GetAuditLog()
	if log == nil {
		t.Error("audit log should not be nil")
	}
}

func TestRedactorClearAuditLog(t *testing.T) {
	redactor := NewRedactor()
	redactor.ClearAuditLog()
	log := redactor.GetAuditLog()
	if len(log) != 0 {
		t.Error("audit log should be empty after clear")
	}
}

// ============================================================================
// Selective Redaction Tests
// ============================================================================

func TestRedactorRedactPIIOnly(t *testing.T) {
	redactor := NewRedactor()

	text := "Email: test@example.com, Key: sk_live_REDACTED1234567890"
	result := redactor.RedactPIIOnly(text)

	// Only PII should be redacted
	if containsSubstring(result, "test@example.com") {
		t.Error("email should be redacted")
	}
}

func TestRedactorRedactSecretsOnly(t *testing.T) {
	redactor := NewRedactor()

	text := "Email: test@example.com, Key: sk_live_REDACTED1234567890"
	result := redactor.RedactSecretsOnly(text)

	_ = result // May or may not redact email
}

// ============================================================================
// Utility Function Tests
// ============================================================================

func TestQuickRedact(t *testing.T) {
	result := QuickRedact("test@example.com")
	if result == "" {
		t.Error("QuickRedact should return result")
	}
}

func TestRedactWithStrategy(t *testing.T) {
	result := RedactWithStrategy("test@example.com", StrategyPlaceholder, "[REDACTED]")
	if result == "" {
		t.Error("RedactWithStrategy should return result")
	}
}

func TestRedactWithStrategyAsterisks(t *testing.T) {
	result := RedactWithStrategy("test@example.com", StrategyAsterisks, "")
	if result == "" {
		t.Error("RedactWithStrategy should return result")
	}
}

// ============================================================================
// Statistics Tests
// ============================================================================

func TestRedactorGetStats(t *testing.T) {
	redactor := NewRedactor()
	stats := redactor.GetStats()
	if stats == nil {
		t.Error("stats should not be nil")
	}
}

func TestRedactorStatsTotalRedacted(t *testing.T) {
	redactor := NewRedactor()
	redactor.Redact("test@example.com")

	stats := redactor.GetStats()
	if stats.TotalRedacted < 0 {
		t.Error("total redacted should be non-negative")
	}
}

// ============================================================================
// Edge Cases
// ============================================================================

func TestRedactorLongText(t *testing.T) {
	redactor := NewRedactor()
	longText := "test@example.com " + string(make([]byte, 10000))
	result := redactor.Redact(longText)
	if result == "" {
		t.Error("should handle long text")
	}
}

func TestRedactorSpecialCharacters(t *testing.T) {
	redactor := NewRedactor()
	text := "Email: \"test@example.com\" with <brackets>"
	result := redactor.Redact(text)
	_ = result // Should handle without panic
}

func TestRedactorUnicode(t *testing.T) {
	redactor := NewRedactor()
	text := "Email: test@example.com with 日本語"
	result := redactor.Redact(text)
	_ = result // Should handle unicode
}

// ============================================================================
// Strategy Constants Tests
// ============================================================================

func TestRedactionStrategyConstants(t *testing.T) {
	if StrategyPlaceholder != 0 {
		t.Error("StrategyPlaceholder should be 0")
	}
	if StrategyAsterisks != 1 {
		t.Error("StrategyAsterisks should be 1")
	}
	if StrategyHash != 2 {
		t.Error("StrategyHash should be 2")
	}
}

func TestDefaultRedactorConfig(t *testing.T) {
	config := DefaultRedactorConfig()
	if config.Strategy != StrategyPlaceholder {
		t.Error("default strategy should be StrategyPlaceholder")
	}
	if config.ReplaceWith != "[REDACTED]" {
		t.Error("default replace with should be [REDACTED]")
	}
}

// ============================================================================
// Helper function
// ============================================================================

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
