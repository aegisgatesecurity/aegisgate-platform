// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Webhook Server Tests
// =========================================================================

package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ============================================================================
// Basic Server Tests
// ============================================================================

func TestNewWebhookServer(t *testing.T) {
	server := NewWebhookServer("8080")
	if server == nil {
		t.Fatal("NewWebhookServer returned nil")
	}
	if server.port != "8080" {
		t.Errorf("port = %s, want 8080", server.port)
	}
}

func TestWebhookServerWithLicenseGenerator(t *testing.T) {
	server := NewWebhookServer("8080")
	gen := NewMockLicenseGenerator()

	server.WithLicenseGenerator(gen)

	if server.licenseGen == nil {
		t.Error("license generator not set")
	}
}

func TestWebhookServerWithEmailService(t *testing.T) {
	server := NewWebhookServer("8080")
	svc := NewMockEmailService()

	server.WithEmailService(svc)

	if server.emailService == nil {
		t.Error("email service not set")
	}
}

// ============================================================================
// Health Endpoint Tests
// ============================================================================

func TestHealthEndpoint(t *testing.T) {
	server := NewWebhookServer("8080")

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "healthy" {
		t.Errorf("health status = %s, want healthy", resp["status"])
	}
}

func TestHealthEndpointNoSecret(t *testing.T) {
	// Ensure no secret is set
	os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	server := NewWebhookServer("8080")

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["webhook_secret"] != "not configured" {
		t.Errorf("webhook_secret = %s, want not configured", resp["webhook_secret"])
	}
}

func TestHealthEndpointWithSecret(t *testing.T) {
	os.Setenv("STRIPE_WEBHOOK_SECRET", "test_secret")
	defer os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	server := NewWebhookServer("8080")

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["webhook_secret"] != "configured" {
		t.Errorf("webhook_secret = %s, want configured", resp["webhook_secret"])
	}
}

// ============================================================================
// Webhook Handler Tests
// ============================================================================

func TestWebhookMissingSignature(t *testing.T) {
	server := NewWebhookServer("8080")
	server.secret = "test_secret"

	body := `{"id": "evt_123", "type": "checkout.session.completed"}`
	req := httptest.NewRequest("POST", "/webhook/stripe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestWebhookInvalidJSON(t *testing.T) {
	server := NewWebhookServer("8080")
	server.secret = "test_secret"

	body := `invalid json {`
	sig := createTestSignature([]byte(body), "test_secret")

	req := httptest.NewRequest("POST", "/webhook/stripe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", sig)
	w := httptest.NewRecorder()

	server.handleWebhook(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestWebhookCheckoutCompleted(t *testing.T) {
	server := NewWebhookServer("8080")
	server.licenseGen = NewMockLicenseGenerator()
	server.emailService = NewMockEmailService()

	session := CheckoutSession{
		ID:            "cs_test_123",
		CustomerEmail: "test@example.com",
		Customer:      "cus_test_123",
		PaymentStatus: "paid",
		Status:        "complete",
		AmountTotal:   7900,
		Metadata:      map[string]string{},
	}

	data, _ := json.Marshal(session)
	event := WebhookPayload{
		ID:      "evt_123",
		Type:    "checkout.session.completed",
		Created: 1234567890,
	}
	event.Data.Object = data

	eventData, _ := json.Marshal(event)
	body := string(eventData)
	sig := createTestSignature([]byte(body), "")

	req := httptest.NewRequest("POST", "/webhook/stripe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", sig)
	w := httptest.NewRecorder()

	server.handleWebhook(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestWebhookUnpaidCheckout(t *testing.T) {
	server := NewWebhookServer("8080")
	server.licenseGen = NewMockLicenseGenerator()

	session := CheckoutSession{
		ID:            "cs_test_456",
		CustomerEmail: "test@example.com",
		PaymentStatus: "unpaid",
		AmountTotal:   7900,
	}

	data, _ := json.Marshal(session)
	event := WebhookPayload{
		ID:   "evt_456",
		Type: "checkout.session.completed",
	}
	event.Data.Object = data

	eventData, _ := json.Marshal(event)
	body := string(eventData)

	req := httptest.NewRequest("POST", "/webhook/stripe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleWebhook(w, req)

	// Should still return OK (just skip processing)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestWebhookSubscriptionUpdated(t *testing.T) {
	server := NewWebhookServer("8080")

	sub := Subscription{
		ID:                 "sub_test_123",
		Customer:           "cus_test_123",
		Status:             "past_due",
		CurrentPeriodStart: 1234567890,
		CurrentPeriodEnd:   1234567890 + 86400*30,
	}

	data, _ := json.Marshal(sub)
	event := WebhookPayload{
		ID:   "evt_789",
		Type: "customer.subscription.updated",
	}
	event.Data.Object = data

	eventData, _ := json.Marshal(event)
	body := string(eventData)

	req := httptest.NewRequest("POST", "/webhook/stripe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleWebhook(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestWebhookUnhandledType(t *testing.T) {
	server := NewWebhookServer("8080")

	event := WebhookPayload{
		ID:   "evt_unknown",
		Type: "customer.created", // Not handled
	}

	eventData, _ := json.Marshal(event)
	body := string(eventData)

	req := httptest.NewRequest("POST", "/webhook/stripe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleWebhook(w, req)

	// Unhandled types should still return OK
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// ============================================================================
// Signature Verification Tests
// ============================================================================

func TestVerifySignature(t *testing.T) {
	secret := "whsec_test_secret"
	payload := []byte(`{"id": "evt_123", "type": "test"}`)
	sig := createTestSignature(payload, secret)

	server := NewWebhookServer("8080")
	server.secret = secret

	err := server.verifySignature(payload, sig)
	if err != nil {
		t.Errorf("verifySignature failed: %v", err)
	}
}

func TestVerifySignatureInvalid(t *testing.T) {
	server := NewWebhookServer("8080")
	server.secret = "whsec_test_secret"

	payload := []byte(`{"id": "evt_123", "type": "test"}`)
	sig := "t=1234567890,v1=invalid_signature"

	err := server.verifySignature(payload, sig)
	if err == nil {
		t.Error("expected signature mismatch error")
	}
}

func TestVerifySignatureNoSecret(t *testing.T) {
	server := NewWebhookServer("8080")
	server.secret = ""

	payload := []byte(`{"id": "evt_123", "type": "test"}`)
	sig := "t=1234567890,v1=test_signature"

	// Should error when no secret but signature provided (invalid format)
	err := server.verifySignature(payload, sig)
	if err == nil {
		t.Error("expected error when no secret configured")
	}
}

// =============================================================================
// Tier Inference Tests (Server)
// =============================================================================

func TestServerInferTierFromAmount(t *testing.T) {
	server := NewWebhookServer("8080")

	// Thresholds: professional >= 24900, developer >= 7900, starter >= 2900

	// Professional tier (>= 24900)
	professionalAmounts := []int64{29000, 249000, 24900, 50000}
	for _, amt := range professionalAmounts {
		if got := server.inferTierFromAmount(amt); got != "professional" {
			t.Errorf("inferTierFromAmount(%d) = %s, want professional", amt, got)
		}
	}

	// Developer tier (>= 7900, < 24900)
	developerAmounts := []int64{7900, 15000, 10000, 24899}
	for _, amt := range developerAmounts {
		if got := server.inferTierFromAmount(amt); got != "developer" {
			t.Errorf("inferTierFromAmount(%d) = %s, want developer", amt, got)
		}
	}

	// Starter tier (>= 2900, < 7900)
	starterAmounts := []int64{2900, 5000, 7899}
	for _, amt := range starterAmounts {
		if got := server.inferTierFromAmount(amt); got != "starter" {
			t.Errorf("inferTierFromAmount(%d) = %s, want starter", amt, got)
		}
	}

	// Default (developer) for amounts below starter
	lowAmounts := []int64{1000, 100, 0, 2899}
	for _, amt := range lowAmounts {
		if got := server.inferTierFromAmount(amt); got != "developer" {
			t.Errorf("inferTierFromAmount(%d) = %s, want developer (default)", amt, got)
		}
	}
}

// =============================================================================
// Utility Tests
// =============================================================================

func TestCreateWebhookEndpoint(t *testing.T) {
	tests := []struct {
		baseURL string
		want    string
	}{
		{"https://api.example.com", "https://api.example.com/webhook/stripe"},
		{"https://api.example.com/", "https://api.example.com/webhook/stripe"},
		{"", "/webhook/stripe"},
	}

	for _, tt := range tests {
		got := CreateWebhookEndpoint(tt.baseURL)
		if got != tt.want {
			t.Errorf("CreateWebhookEndpoint(%s) = %s, want %s", tt.baseURL, got, tt.want)
		}
	}
}

func TestGetWebhookSigningSecret(t *testing.T) {
	os.Setenv("STRIPE_WEBHOOK_SECRET", "test_secret")
	defer os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	secret := GetWebhookSigningSecret()
	if secret != "test_secret" {
		t.Errorf("GetWebhookSigningSecret() = %s, want test_secret", secret)
	}
}

func TestSetWebhookSigningSecret(t *testing.T) {
	SetWebhookSigningSecret("new_secret")
	defer os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	secret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if secret != "new_secret" {
		t.Errorf("STRIPE_WEBHOOK_SECRET = %s, want new_secret", secret)
	}
}

// ============================================================================
// Mock License Generator Tests
// ============================================================================

func TestMockLicenseGeneratorGenerate(t *testing.T) {
	gen := NewMockLicenseGenerator()

	key, err := gen.GenerateLicense("cus_123", "developer", 365)
	if err != nil {
		t.Fatalf("GenerateLicense failed: %v", err)
	}

	if key == "" {
		t.Error("generated key is empty")
	}

	if !strings.HasPrefix(key, "AG-DEVELOPER-") {
		t.Errorf("key doesn't match expected format: %s", key)
	}
}

func TestMockLicenseGeneratorActivate(t *testing.T) {
	gen := NewMockLicenseGenerator()

	key, _ := gen.GenerateLicense("cus_123", "developer", 365)
	err := gen.ActivateLicense(key, "test@example.com")
	if err != nil {
		t.Errorf("ActivateLicense failed: %v", err)
	}
}

func TestMockLicenseGeneratorActivateInvalid(t *testing.T) {
	gen := NewMockLicenseGenerator()

	err := gen.ActivateLicense("invalid_key", "test@example.com")
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

// ============================================================================
// Mock Email Service Tests
// ============================================================================

func TestMockEmailService(t *testing.T) {
	svc := NewMockEmailService()

	err := svc.SendLicenseKey("test@example.com", "AG-KEY-123", "developer", "2027-01-01")
	if err != nil {
		t.Errorf("SendLicenseKey failed: %v", err)
	}

	if len(svc.sent) != 1 {
		t.Errorf("expected 1 email sent, got %d", len(svc.sent))
	}

	if svc.sent[0].to != "test@example.com" {
		t.Errorf("email to = %s, want test@example.com", svc.sent[0].to)
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func createTestSignature(payload []byte, secret string) string {
	if secret == "" {
		return "t=1234567890,v1=test_signature"
	}

	timestamp := "1234567890"
	signedPayload := timestamp + "." + string(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	signature := hex.EncodeToString(mac.Sum(nil))

	return "t=" + timestamp + ",v1=" + signature
}

// ============================================================================
// Test Helpers
// ============================================================================

func makeWebhookRequest(body string, secret string) (*http.Request, *httptest.ResponseRecorder) {
	req := httptest.NewRequest("POST", "/webhook/stripe", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	if secret != "" {
		sig := createTestSignature([]byte(body), secret)
		req.Header.Set("Stripe-Signature", sig)
	}

	w := httptest.NewRecorder()
	return req, w
}
