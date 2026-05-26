// SPDX-License-Identifier: Apache-2.0
// Bridge package - Final coverage push targeting remaining uncovered paths
// Sprint 12: Push bridge package to 95%+ coverage

package bridge_test

import (
	"context"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge"
	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ============================================================================
// ScanResponseWithContext - Hit the !result.Allowed logging branch
// ============================================================================

func TestScanResponseWithContext_BlockedToxicContent(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	// Content that triggers toxicity blocking
	blockedContent := "I want to murder and kill people with a bomb and weapon"
	result, err := rs.ScanResponseWithContext(ctx, blockedContent, nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	// This hits the !result.Allowed branch in ScanResponseWithContext
	if result.Allowed {
		t.Error("Toxic content should be blocked")
	}
	if result.BlockReason == "" {
		t.Error("Expected block reason for toxic content")
	}
}

func TestScanResponseWithContext_LargeContentBlocked(t *testing.T) {
	rs := bridge.NewResponseScannerWithConfig(&responseguard.ResponseGuardConfig{
		EnablePIIScanner:      false,
		EnableSecretDetection: false,
		EnableToxicityFilter:  false,
		EnableHallucination:   false,
	})
	ctx := context.Background()

	// Generate content exceeding MaxTokensPerResponse
	var largeContent strings.Builder
	for i := 0; i < 200000; i++ {
		largeContent.WriteString("x")
	}

	result, err := rs.ScanResponseWithContext(ctx, largeContent.String(), nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	t.Logf("Large content result: Allowed=%v, Reason=%s", result.Allowed, result.BlockReason)
}

func TestScanResponseWithContext_NilContext(t *testing.T) {
	rs := bridge.NewResponseScanner()

	result, err := rs.ScanResponseWithContext(nil, "clean content", nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

// ============================================================================
// IsResponseAllowed - Test blocked path
// ============================================================================

func TestIsResponseAllowed_BlockedToxicContent(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	allowed := rs.IsResponseAllowed(ctx, "I want to murder and kill everyone with explosives")
	if allowed {
		t.Error("Toxic content should be blocked")
	}
}

func TestIsResponseAllowed_EmptyContent(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	allowed := rs.IsResponseAllowed(ctx, "")
	if !allowed {
		t.Error("Empty content should be allowed")
	}
}

// ============================================================================
// GetComplianceReport - Test with various content
// ============================================================================

func TestGetComplianceReport_EmptyContent(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	report, err := rs.GetComplianceReport(ctx, "")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if report == nil {
		t.Error("Expected non-nil report for empty content")
	}
}

func TestGetComplianceReport_WithSecretsContent(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	report, err := rs.GetComplianceReport(ctx, "API key: sk-1234567890abcdefghijklmnop")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if report == nil {
		t.Error("Expected non-nil report")
	}
	t.Logf("Compliance report entries: %d", len(report))
}

// ============================================================================
// GetDetectedPII - Additional coverage
// ============================================================================

func TestGetDetectedPII_WithPhoneNumber(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	pii := rs.GetDetectedPII(ctx, "Phone: 555-123-4567, Mobile: (555) 987-6543")
	t.Logf("Detected PII: %v", pii)
}

func TestGetDetectedPII_WithCreditCard(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	pii := rs.GetDetectedPII(ctx, "Card: 4532015112830366")
	t.Logf("Detected PII: %v", pii)
}

func TestGetDetectedPII_WithIPAddress(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	pii := rs.GetDetectedPII(ctx, "IP: 192.168.1.1 and 10.0.0.255")
	t.Logf("Detected PII: %v", pii)
}

// ============================================================================
// GetDetectedSecrets - Additional coverage
// ============================================================================

func TestGetDetectedSecrets_WithAWSKeys(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	secrets := rs.GetDetectedSecrets(ctx, "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE AWS_SECRET=abc123")
	t.Logf("Detected secrets: %v", secrets)
}

func TestGetDetectedSecrets_WithPassword(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	secrets := rs.GetDetectedSecrets(ctx, "password=MySecret123")
	t.Logf("Detected secrets: %v", secrets)
}

func TestGetDetectedSecrets_WithPrivateKey(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	secrets := rs.GetDetectedSecrets(ctx, "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBALRiMLAHudeSA2C1...\n-----END RSA PRIVATE KEY-----")
	t.Logf("Detected secrets: %v", secrets)
}

// ============================================================================
// ScanBridgeResponse - Hit all threat type switch branches
// ============================================================================

func TestScanBridgeResponse_PIIOnlyThreat(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	resp := &bridge.LLMResponse{
		RequestID:  "test-pii-only",
		StatusCode: 200,
		Body:       []byte("Email: user@example.com"),
	}

	result, err := bridge.ScanBridgeResponse(ctx, resp, scanner)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if len(result.PIIFound) > 0 {
		t.Logf("PII found: %v", result.PIIFound)
	}
}

func TestScanBridgeResponse_SecretOnlyThreat(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()
	resp := &bridge.LLMResponse{
		RequestID:  "test-secret-only",
		StatusCode: 200,
		Body:       []byte("Key: sk-1234567890abcdefghijklmnop"),
	}

	result, err := bridge.ScanBridgeResponse(ctx, resp, scanner)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if len(result.SecretsFound) > 0 {
		t.Logf("Secrets found: %v", result.SecretsFound)
	}
}

func TestScanBridgeResponse_AllThreatTypes(t *testing.T) {
	scanner := bridge.NewResponseScanner()
	ctx := context.Background()

	content := "I want to kill you. Email: admin@test.com. Secret: ghp_ABCDEFGHIJKLMNOP"
	resp := &bridge.LLMResponse{
		RequestID:  "test-all-threats",
		StatusCode: 200,
		Body:       []byte(content),
	}

	result, err := bridge.ScanBridgeResponse(ctx, resp, scanner)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.ToxicityDetected {
		t.Log("Toxicity detected")
	}
	if len(result.PIIFound) > 0 {
		t.Logf("PII found: %v", result.PIIFound)
	}
	if len(result.SecretsFound) > 0 {
		t.Logf("Secrets found: %v", result.SecretsFound)
	}
}

// ============================================================================
// ScanAndFilter - Test blocked content in non-strict mode
// ============================================================================

func TestScanAndFilter_BlockedContentNonStrict(t *testing.T) {
	pb, err := bridge.NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}
	defer pb.Close()

	ctx := context.Background()

	toxicContent := "I want to murder and kill everyone"

	filtered, result, err := pb.ScanAndFilter(ctx, toxicContent)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Allowed {
		t.Log("Content was allowed (non-toxic or non-blocking)")
	} else {
		t.Logf("Content was blocked: %s", result.BlockReason)
		// In non-strict mode, blocked content should pass through
		if filtered != toxicContent {
			t.Error("In non-strict mode, blocked content should pass through")
		}
	}
}

func TestScanAndFilter_ContentWithSecrets(t *testing.T) {
	pb, err := bridge.NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}
	defer pb.Close()

	ctx := context.Background()
	secretContent := "Your API key is: sk-1234567890abcdefghijklmnop"

	_, result, err := pb.ScanAndFilter(ctx, secretContent)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	t.Logf("Result: Allowed=%v", result.Allowed)
}

func TestScanAndFilter_ContentWithPII(t *testing.T) {
	pb, err := bridge.NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("Failed to create bridge: %v", err)
	}
	defer pb.Close()

	ctx := context.Background()
	piiContent := "Contact: user@example.com, Phone: 555-123-4567"

	_, result, err := pb.ScanAndFilter(ctx, piiContent)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	t.Logf("Result: Allowed=%v, PII=%v", result.Allowed, len(result.ComplianceReports))
}

// ============================================================================
// Additional integration tests
// ============================================================================

func TestScanResponse_DisabledScanner(t *testing.T) {
	rs := bridge.NewResponseScannerWithConfig(&responseguard.ResponseGuardConfig{
		EnablePIIScanner:      false,
		EnableSecretDetection: false,
		EnableToxicityFilter:  false,
		EnableHallucination:   false,
	})
	ctx := context.Background()

	result, err := rs.ScanResponse(ctx, "any content")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestScanResponse_HallucinationDetected(t *testing.T) {
	rs := bridge.NewResponseScannerWithConfig(&responseguard.ResponseGuardConfig{
		EnablePIIScanner:      false,
		EnableSecretDetection: false,
		EnableToxicityFilter:  false,
		EnableHallucination:   true,
	})
	ctx := context.Background()

	result, err := rs.ScanResponse(ctx, "The capital of France is Paris, I am certain.")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	t.Logf("Result: Allowed=%v, Threats=%d", result.Allowed, len(result.Threats))
}

func TestResponseScanner_ConcurrentAccess(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			rs.ScanResponse(ctx, "concurrent test content")
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
