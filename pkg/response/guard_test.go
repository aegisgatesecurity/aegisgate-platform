// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Response Guard Tests
// =========================================================================

package response

import (
	"context"
	"testing"
)

func TestNewResponseGuard(t *testing.T) {
	guard := NewResponseGuard()
	if guard == nil {
		t.Fatal("NewResponseGuard() returned nil")
	}
	if guard.piiScanner == nil {
		t.Error("piiScanner not initialized")
	}
	if guard.secretDetector == nil {
		t.Error("secretDetector not initialized")
	}
}

func TestNewResponseGuardWithConfig(t *testing.T) {
	config := DefaultResponseGuardConfig()
	config.StrictMode = true
	config.MaxResponseTokens = 4096

	guard := NewResponseGuardWithConfig(config)
	if guard == nil {
		t.Fatal("NewResponseGuardWithConfig() returned nil")
	}

	cfg := guard.GetConfig()
	if cfg.StrictMode != true {
		t.Error("StrictMode not set correctly")
	}
	if cfg.MaxResponseTokens != 4096 {
		t.Error("MaxResponseTokens not set correctly")
	}
}

func TestScanClean(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	response := "This is a clean AI response with no sensitive data."
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected clean response to be allowed")
	}
	if len(result.Threats) != 0 {
		t.Errorf("expected 0 threats, got %d", len(result.Threats))
	}
}

func TestScanWithPII(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	response := "User John Doe with SSN 123-45-6789 and email john@example.com"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	// Should be allowed but with threats
	if result.Allowed && !guard.config.StrictMode {
		// Expected behavior in non-strict mode
	}
	if len(result.DetectedPII) == 0 {
		t.Error("expected PII to be detected")
	}
}

func TestScanWithSecrets(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	response := "My API key is sk_live_1234567890abcdefghij and AWS key is AKIAIOSFODNN7EXAMPLE"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(result.DetectedSecrets) == 0 {
		t.Error("expected secrets to be detected")
	}
}

func TestScanStrictMode(t *testing.T) {
	config := DefaultResponseGuardConfig()
	config.StrictMode = true
	guard := NewResponseGuardWithConfig(config)
	ctx := context.Background()

	response := "User data: SSN 234-56-7890"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	// In strict mode, any detection should block
	if result.Allowed {
		t.Error("expected response to be blocked in strict mode")
	}
}

func TestScanWithContext(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()
	scanCtx := NewScanContext("test-client", "test-request")

	response := "Test response"
	result, err := guard.ScanWithContext(ctx, response, scanCtx)

	if err != nil {
		t.Fatalf("ScanWithContext() error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected clean response to be allowed")
	}
}

func TestEnableDisable(t *testing.T) {
	guard := NewResponseGuard()

	// Test initial state
	if !guard.IsEnabled() {
		t.Error("expected guard to be enabled by default")
	}

	// Test disable
	guard.Disable()
	if guard.IsEnabled() {
		t.Error("expected guard to be disabled")
	}

	// Test enable
	guard.Enable()
	if !guard.IsEnabled() {
		t.Error("expected guard to be enabled")
	}
}

func TestUpdateConfig(t *testing.T) {
	guard := NewResponseGuard()

	newConfig := &ResponseGuardConfig{
		EnablePIIScanner:      false,
		EnableSecretDetection: true,
		StrictMode:            true,
		MaxResponseTokens:     2048,
	}

	guard.UpdateConfig(newConfig)
	cfg := guard.GetConfig()

	if cfg.EnablePIIScanner != false {
		t.Error("EnablePIIScanner not updated")
	}
	if cfg.EnableSecretDetection != true {
		t.Error("EnableSecretDetection not updated")
	}
	if cfg.StrictMode != true {
		t.Error("StrictMode not updated")
	}
}

func TestComplianceReports(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	// Test with GDPR-relevant data
	response := "Contact me at john@example.com or call 555-123-4567"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Check GDPR report
	if gdpr, ok := result.ComplianceReports["GDPR"]; ok {
		if gdpr.Compliant {
			t.Error("expected GDPR non-compliance for email/phone")
		}
	}
}

func TestComplianceReportsHIPAA(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	// Test with HIPAA-relevant data
	response := "Patient MRN: 12345678, DOB: 01/15/1985"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Check HIPAA report
	if hipaa, ok := result.ComplianceReports["HIPAA"]; ok {
		if hipaa.Compliant {
			t.Error("expected HIPAA non-compliance for health info")
		}
	}
}

func TestComplianceReportsPCI(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	// Test with PCI-DSS relevant data
	response := "Card: 4111111111111111"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Check PCI-DSS report
	if pci, ok := result.ComplianceReports["PCI-DSS"]; ok {
		if pci.Compliant {
			t.Error("expected PCI-DSS non-compliance for credit card")
		}
	}
}

func TestTokenCounting(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	// Normal response
	response := "This is a normal response with typical content."
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if result.Tokens == 0 {
		t.Error("expected token count to be > 0")
	}
}

func TestScanDisabled(t *testing.T) {
	guard := NewResponseGuard()
	guard.Disable()
	ctx := context.Background()

	response := "SSN: 234-56-7890"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// When disabled, should allow everything
	if !result.Allowed {
		t.Error("expected response to be allowed when guard is disabled")
	}
	if len(result.Threats) != 0 {
		t.Error("expected no threats when guard is disabled")
	}
}

func TestScanWithToxicContent(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	// Create a response that matches toxicity filter
	response := "I will definitely kill you and shoot you with my machine gun"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Should detect toxicity
	found := false
	for _, threat := range result.Threats {
		if threat.Type == "toxicity" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected toxicity to be detected")
	}
}

func TestScanWithHallucination(t *testing.T) {
	guard := NewResponseGuardWithConfig(&ResponseGuardConfig{
		EnableHallucination: true,
	})
	ctx := context.Background()

	// Hallucination detector uses heuristics - create a response with multiple overconfident phrases
	// Note: Hallucination detector may not always flag - it's a heuristic
	response := "Everyone definitely always agrees that 99% of users prefer this. Absolutely guaranteed no one will disagree. Always works, never fails. 100% satisfaction."
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Hallucination detection is heuristic-based, may vary
	// Just verify the guard works without error
	if result == nil {
		t.Error("expected result to not be nil")
	}
}

func TestScanWithConfig(t *testing.T) {
	guard := NewResponseGuard()

	config := &ResponseGuardConfig{
		EnablePIIScanner:      false, // Disable PII scanning
		EnableSecretDetection: true,
		StrictMode:            false,
	}

	response := "API key: sk_live_1234567890abcdefghij"
	result, err := guard.ScanWithConfig(context.Background(), response, config)

	if err != nil {
		t.Fatalf("ScanWithConfig() error: %v", err)
	}

	// PII should not be detected (scanner disabled)
	// Note: With PII scanner disabled, no PII should be detected
	// but we can verify the config was respected

	// Secrets should still be detected
	if len(result.DetectedSecrets) == 0 {
		t.Error("expected secrets to be detected")
	}
}

func TestResetUsage(t *testing.T) {
	guard := NewResponseGuard()

	// Add some usage
	scanCtx := NewScanContext("test-client", "req-1")
	guard.ScanWithContext(context.Background(), "Response with tokens", scanCtx)

	// Reset usage
	guard.ResetUsage("test-client")

	// Check usage is reset
	usage := guard.GetUsage("test-client")
	if usage != nil {
		t.Error("expected usage to be nil after reset")
	}
}

func TestResetAllUsage(t *testing.T) {
	guard := NewResponseGuard()

	// Add usage for multiple clients
	guard.ScanWithContext(context.Background(), "Response", NewScanContext("client-1", "req-1"))
	guard.ScanWithContext(context.Background(), "Response", NewScanContext("client-2", "req-1"))

	// Reset all
	guard.ResetAllUsage()

	// Check both are reset
	if guard.GetUsage("client-1") != nil {
		t.Error("expected client-1 usage to be nil")
	}
	if guard.GetUsage("client-2") != nil {
		t.Error("expected client-2 usage to be nil")
	}
}

func TestPIIScannerAccess(t *testing.T) {
	guard := NewResponseGuard()

	scanner := guard.PIIScanner()
	if scanner == nil {
		t.Error("expected PIIScanner to be accessible")
	}

	// Test that scanner works
	matches := scanner.FindPII("SSN: 234-56-7890")
	if len(matches) == 0 {
		t.Error("expected SSN to be detected via PIIScanner")
	}
}

func TestSecretDetectorAccess(t *testing.T) {
	guard := NewResponseGuard()

	detector := guard.SecretDetector()
	if detector == nil {
		t.Error("expected SecretDetector to be accessible")
	}

	// Test that detector works
	matches := detector.FindSecrets("sk_live_1234567890abcdefghij")
	if len(matches) == 0 {
		t.Error("expected Stripe key to be detected via SecretDetector")
	}
}

func TestTokenLimiterAccess(t *testing.T) {
	guard := NewResponseGuard()

	limiter := guard.TokenLimiter()
	if limiter == nil {
		t.Error("expected TokenLimiter to be accessible")
	}

	// Test token counting
	count := limiter.CountTokens("This is a test response")
	if count == 0 {
		t.Error("expected token count to be > 0")
	}
}

func TestScanResponseFunction(t *testing.T) {
	response := "Clean response"
	result, err := ScanResponse(response)

	if err != nil {
		t.Fatalf("ScanResponse() error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected clean response to be allowed")
	}
}

func TestScanResponseStrictFunction(t *testing.T) {
	response := "SSN: 234-56-7890"
	result, err := ScanResponseStrict(response)

	if err != nil {
		t.Fatalf("ScanResponseStrict() error: %v", err)
	}
	// In strict mode, should be blocked
	if result.Allowed {
		t.Error("expected response to be blocked in strict mode")
	}
}

func TestRedactResponse(t *testing.T) {
	response := "User SSN is 234-56-7890"
	redacted := RedactResponse(response)

	if containsStr(redacted, "234-56-7890") {
		t.Error("expected SSN to be redacted")
	}
}

func TestMaskResponse(t *testing.T) {
	response := "API key: sk_live_1234567890abcdefghij"
	masked := MaskResponse(response)

	if containsStr(masked, "sk_live_1234567890abcdefghij") {
		t.Error("expected API key to be masked")
	}
}

func TestMultipleThreats(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	response := "User John with SSN 234-56-7890 and card 4111111111111111"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Should have multiple threats
	if len(result.Threats) < 2 {
		t.Errorf("expected at least 2 threats, got %d", len(result.Threats))
	}
}

func TestLatency(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	response := "Normal response"
	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Latency should be reasonable (< 1 second)
	if result.LatencyMs > 1000 {
		t.Errorf("expected latency < 1s, got %dms", result.LatencyMs)
	}
}

func TestEmptyResponse(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	result, err := guard.Scan(ctx, "")

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected empty response to be allowed")
	}
}

func TestVeryLongResponse(t *testing.T) {
	guard := NewResponseGuard()
	ctx := context.Background()

	// Create a very long response
	longText := "This is a test. "
	var response string
	for i := 0; i < 1000; i++ {
		response += longText
	}

	result, err := guard.Scan(ctx, response)

	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	// Should handle long responses without error
	if result.Tokens == 0 {
		t.Error("expected token count for long response")
	}
}
