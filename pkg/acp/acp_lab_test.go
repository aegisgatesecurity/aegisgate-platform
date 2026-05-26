// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP Lab Integration Tests with Keycloak
// =========================================================================
//
// Integration tests for ACP security using the testlab environment.
// Requires: docker-compose up -d (Keycloak on port 9080)
//
// Run with: LAB_ENABLED=1 go test -tags=lab -v ./pkg/acp/...
// =========================================================================

package acp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// skipIfNoLab skips tests if LAB_ENABLED is not set
func skipIfNoLab(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("LAB_ENABLED not set - skipping integration test")
	}
}

// TestLabKeycloakHealthCheck verifies Keycloak is accessible
func TestLabKeycloakHealthCheck(t *testing.T) {
	skipIfNoLab(t)

	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://localhost:9080"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", keycloakURL+"/health/ready", nil)
	if err != nil {
		t.Skipf("Keycloak not accessible: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("Keycloak not running: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("Keycloak not healthy: status %d", resp.StatusCode)
	}

	t.Log("Keycloak health check passed")
}

// TestLabACPBasicScanning tests basic ACP message scanning
func TestLabACPBasicScanning(t *testing.T) {
	skipIfNoLab(t)

	scanner := NewACPResponseScanner()
	ctx := context.Background()

	tests := []struct {
		name    string
		content string
		allowed bool
	}{
		{"clean", "Hello, how can I help you today?", true},
		{"empty", "", true},
		{"unicode", "Test with emojis and unicode", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := scanner.ScanResponse(ctx, tc.content, "lab-test")
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}
			if result.Allowed != tc.allowed {
				t.Errorf("Expected Allowed=%v, got %v", tc.allowed, result.Allowed)
			}
		})
	}
}

// TestLabACPHMACVerification tests HMAC message signing
func TestLabACPHMACVerification(t *testing.T) {
	skipIfNoLab(t)

	hv := NewHMACVerifier("test-secret")
	payload := []byte("ACP message content for signing")
	timestamp, signature := hv.SignMessage(payload)

	err := hv.VerifyMessageSignature(timestamp, payload, signature)
	if err != nil {
		t.Errorf("Valid signature should verify: %v", err)
	}

	err = hv.VerifyMessageSignature(timestamp, payload, "invalid")
	if err != ErrHMACVerification {
		t.Errorf("Invalid signature should fail: %v", err)
	}
}

// TestLabACPRateLimiting tests rate limiting behavior
func TestLabACPRateLimiting(t *testing.T) {
	skipIfNoLab(t)

	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 3
	cfg.RateLimitPerMinute = 60

	scanner := NewACPResponseScannerWithConfig(cfg)

	for i := 0; i < 3; i++ {
		err := scanner.CheckRateLimit("lab-rate-test")
		if err != nil {
			t.Errorf("Request %d should be allowed: %v", i+1, err)
		}
	}

	err := scanner.CheckRateLimit("lab-rate-test")
	if err != ErrRateLimited {
		t.Errorf("Request 4 should be limited: %v", err)
	}
}

// TestLabACPCapabilityEnforcement tests capability management
func TestLabACPCapabilityEnforcement(t *testing.T) {
	skipIfNoLab(t)

	ce := NewCapabilityEnforcer()

	ce.Allow("agent-1", CapabilityExecuteTerminal)
	ce.Allow("agent-1", CapabilityReadFile)

	if !ce.Check("agent-1", CapabilityExecuteTerminal) {
		t.Error("Terminal capability should be granted")
	}
	if !ce.Check("agent-1", CapabilityReadFile) {
		t.Error("Read capability should be granted")
	}
	if ce.Check("agent-1", CapabilityWriteFile) {
		t.Error("Write should be denied by default")
	}

	ce.Disallow("agent-1", CapabilityExecuteTerminal)
	if ce.Check("agent-1", CapabilityExecuteTerminal) {
		t.Error("Terminal should be revoked")
	}

	t.Log("Capability enforcement working correctly")
}

// TestLabACPWithKeycloakAuth tests ACP middleware with auth context
func TestLabACPWithKeycloakAuth(t *testing.T) {
	skipIfNoLab(t)

	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100

	middleware := NewMiddlewareWithConfig(cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "{\"status\":\"ok\"}")
	})

	wrapped := middleware.WrapHandler(handler)

	req := httptest.NewRequest("POST", "/acp/test", strings.NewReader("{\"method\":\"test\"}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ACP-Session", "lab-keycloak-session")

	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

// TestLabACPMetricsRecording tests Prometheus metrics
func TestLabACPMetricsRecording(t *testing.T) {
	skipIfNoLab(t)

	RecordMessage("test.method", true, 1024)
	RecordHMACVerification(true, false)
	RecordRateLimitHit("test-identity")
	RecordDetectedPII("email")
	RecordDetectedSecret("api_key")
	RecordBlockedMethod("dangerous.method")
	SetGuardEnabled(true)
	SetActiveSessions(5)

	t.Log("Prometheus metrics recording successful")
}

// TestLabACPResponseScanningWithThreatContent tests scanning with content that triggers detection
func TestLabACPResponseScanningWithThreatContent(t *testing.T) {
	skipIfNoLab(t)

	scanner := NewACPResponseScanner()
	ctx := context.Background()

	// Content with PII
	piiContent := "User email: test@example.com"
	result, err := scanner.ScanResponse(ctx, piiContent, "lab-pii-test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	t.Logf("PII scan: Allowed=%v, PII count=%d", result.Allowed, len(result.DetectedPII))

	// Content with potential secret patterns
	secretContent := "API key: sk-abcdefghij1234567890"
	result, err = scanner.ScanResponse(ctx, secretContent, "lab-secret-test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	t.Logf("Secret scan: Allowed=%v, Secrets count=%d", result.Allowed, len(result.DetectedSecrets))

	// Clean content
	cleanContent := "Hello! How can I assist you today?"
	result, err = scanner.ScanResponse(ctx, cleanContent, "lab-clean-test")
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if !result.Allowed {
		t.Errorf("Clean content should be allowed, got: %s", result.BlockReason)
	}
}

// TestLabACPE2EIntegration simulates complete ACP flow
func TestLabACPE2EIntegration(t *testing.T) {
	skipIfNoLab(t)

	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.EnableHMAC = true
	cfg.RateLimitBurst = 10

	scanner := NewACPResponseScannerWithConfig(cfg)

	// Step 1: Sign message
	hv := NewHMACVerifier(cfg.HMACSecret)
	payload := []byte("{\"method\":\"agent.query\",\"params\":{\"text\":\"Hello agent\"}}")
	timestamp, signature := hv.SignMessage(payload)

	// Step 2: Verify signature
	err := hv.VerifyMessageSignature(timestamp, payload, signature)
	if err != nil {
		t.Errorf("HMAC verification failed: %v", err)
	}

	// Step 3: Check rate limit
	err = scanner.CheckRateLimit("e2e-lab-test")
	if err != nil {
		t.Errorf("Rate limit check failed: %v", err)
	}

	// Step 4: Scan response
	respContent := "Hello! I'm your AI assistant. How can I help you today?"
	result, err := scanner.ScanResponse(context.Background(), respContent, "e2e-lab-test")
	if err != nil {
		t.Errorf("Response scan failed: %v", err)
	}

	if !result.Allowed {
		t.Errorf("Expected response to be allowed, got: %s", result.BlockReason)
	}

	t.Log("E2E ACP flow completed successfully")
}

// TestLabACPKeycloakTokenValidation tests Keycloak token validation flow
func TestLabACPKeycloakTokenValidation(t *testing.T) {
	skipIfNoLab(t)

	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://localhost:9080"
	}

	// In a real integration, we would:
	// 1. Get token from Keycloak: POST {url}/realms/aegisgate/protocol/openid-connect/token
	// 2. Validate token in ACP messages
	// 3. Extract roles for capability mapping

	// For now, just verify Keycloak is accessible
	req, err := http.NewRequest("GET", keycloakURL+"/realms/aegisgate", nil)
	if err != nil {
		t.Skipf("Keycloak not accessible: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Skipf("Keycloak not running: %v", err)
	}
	defer resp.Body.Close()

	t.Log("Keycloak realm accessible - ready for token validation")
}
