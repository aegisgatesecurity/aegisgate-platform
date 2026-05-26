// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Billing/Webhook 95%+ Coverage Push
// Sprint 12: Targeted tests for remaining uncovered paths
// =========================================================================

package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ============================================================================
// Test: SetWebhookSigningSecret - Error Path Coverage
// ============================================================================

func TestSetWebhookSigningSecret_BillingBasic(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)

	SetWebhookSigningSecret("test-secret-key-12345")

	got := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if got != "test-secret-key-12345" {
		t.Errorf("Expected secret 'test-secret-key-12345', got '%s'", got)
	}
}

func TestSetWebhookSigningSecret_BillingEmpty(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)

	SetWebhookSigningSecret("")

	got := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if got != "" {
		t.Errorf("Expected empty secret, got '%s'", got)
	}
}

// ============================================================================
// Test: GetWebhookSigningSecret
// ============================================================================

func TestGetWebhookSigningSecret_BillingNotSet(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	got := GetWebhookSigningSecret()
	if got != "" {
		t.Errorf("Expected empty string when not set, got '%s'", got)
	}
}

func TestGetWebhookSigningSecret_BillingSet(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test123")

	got := GetWebhookSigningSecret()
	if got != "whsec_test123" {
		t.Errorf("Expected 'whsec_test123', got '%s'", got)
	}
}

// ============================================================================
// Test: CreateWebhookEndpoint
// ============================================================================

func TestCreateWebhookEndpoint_BillingBasic(t *testing.T) {
	tests := []struct {
		baseURL     string
		expectedURL string
	}{
		{"https://api.example.com", "https://api.example.com/webhook/stripe"},
		{"https://api.example.com/", "https://api.example.com/webhook/stripe"},
		{"https://api.example.com/v1", "https://api.example.com/v1/webhook/stripe"},
		{"http://localhost:8080", "http://localhost:8080/webhook/stripe"},
	}

	for _, tc := range tests {
		t.Run(tc.baseURL, func(t *testing.T) {
			got := CreateWebhookEndpoint(tc.baseURL)
			if got != tc.expectedURL {
				t.Errorf("CreateWebhookEndpoint(%s) = %s; want %s", tc.baseURL, got, tc.expectedURL)
			}
		})
	}
}

// ============================================================================
// Test: verifySignature - Complete Coverage
// ============================================================================

func TestVerifySignature_BillingValid(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_secret_key")

	s := &Server{
		logger: log.Default(), secret: "whsec_test_secret_key"}

	payload := []byte(`{"type": "checkout.session.completed", "id": "evt_test"}`)
	timestamp := "1234567890"
	signedPayload := timestamp + "." + string(payload)

	mac := hmac.New(sha256.New, []byte("whsec_test_secret_key"))
	mac.Write([]byte(signedPayload))
	sig := hex.EncodeToString(mac.Sum(nil))

	sigHeader := fmt.Sprintf("t=%s,v1=%s", timestamp, sig)

	err := s.verifySignature(payload, sigHeader)
	if err != nil {
		t.Errorf("Expected valid signature to pass, got error: %v", err)
	}
}

func TestVerifySignature_BillingInvalidFormat(t *testing.T) {
	s := &Server{
		logger: log.Default(), secret: "test-secret"}

	err := s.verifySignature([]byte("test"), "")
	if err == nil {
		t.Error("Expected error for empty signature")
	}
	if err.Error() != "invalid signature format" {
		t.Errorf("Expected 'invalid signature format', got '%s'", err.Error())
	}
}

func TestVerifySignature_BillingTimestampOnly(t *testing.T) {
	s := &Server{
		logger: log.Default(), secret: "test-secret"}

	err := s.verifySignature([]byte("test"), "t=1234567890")
	if err == nil {
		t.Error("Expected error for timestamp-only signature")
	}
	if err.Error() != "invalid signature format" {
		t.Errorf("Expected 'invalid signature format', got '%s'", err.Error())
	}
}

func TestVerifySignature_BillingV1Only(t *testing.T) {
	s := &Server{
		logger: log.Default(), secret: "test-secret"}

	err := s.verifySignature([]byte("test"), "v1=somesignature")
	if err == nil {
		t.Error("Expected error for v1-only signature")
	}
	if err.Error() != "invalid signature format" {
		t.Errorf("Expected 'invalid signature format', got '%s'", err.Error())
	}
}

func TestVerifySignature_BillingWrongSecret(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "correct-secret")

	s := &Server{
		logger: log.Default(), secret: "correct-secret"}

	payload := []byte(`{"type": "test"}`)
	timestamp := "1234567890"
	signedPayload := timestamp + "." + string(payload)

	mac := hmac.New(sha256.New, []byte("wrong-secret"))
	mac.Write([]byte(signedPayload))
	sig := hex.EncodeToString(mac.Sum(nil))

	sigHeader := fmt.Sprintf("t=%s,v1=%s", timestamp, sig)

	err := s.verifySignature(payload, sigHeader)
	if err == nil {
		t.Error("Expected error for wrong secret")
	}
	if err.Error() != "signature mismatch" {
		t.Errorf("Expected 'signature mismatch', got '%s'", err.Error())
	}
}

func TestVerifySignature_BillingMultipleV1(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "test-secret")

	s := &Server{
		logger: log.Default(), secret: "test-secret"}

	payload := []byte("test")
	timestamp := "1234567890"
	signedPayload := timestamp + "." + string(payload)

	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write([]byte(signedPayload))
	correctSig := hex.EncodeToString(mac.Sum(nil))

	wrongMac := hmac.New(sha256.New, []byte("wrong"))
	wrongMac.Write([]byte(signedPayload))
	wrongSig := hex.EncodeToString(wrongMac.Sum(nil))

	sigHeader := fmt.Sprintf("t=%s,v1=%s,v1=%s", timestamp, wrongSig, correctSig)

	err := s.verifySignature(payload, sigHeader)
	if err != nil {
		t.Errorf("Expected signature to pass (one matches), got: %v", err)
	}
}

func TestVerifySignature_BillingWhitespace(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "test-secret")

	s := &Server{
		logger: log.Default(), secret: "test-secret"}

	payload := []byte("test")
	timestamp := "1234567890"
	signedPayload := timestamp + "." + string(payload)

	mac := hmac.New(sha256.New, []byte("test-secret"))
	mac.Write([]byte(signedPayload))
	sig := hex.EncodeToString(mac.Sum(nil))

	sigHeader := fmt.Sprintf("  t=%s , v1=%s  ", timestamp, sig)

	err := s.verifySignature(payload, sigHeader)
	if err != nil {
		t.Errorf("Expected signature to pass with whitespace, got: %v", err)
	}
}

// ============================================================================
// Test: handleHealth
// ============================================================================

func TestHandleHealth_BillingWithSecret(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test123")

	s := &Server{
		logger: log.Default(), secret: "whsec_test123"}
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	s.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var status map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if status["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", status["status"])
	}
	if status["webhook_secret"] != "configured" {
		t.Errorf("Expected webhook_secret 'configured', got '%s'", status["webhook_secret"])
	}
}

func TestHandleHealth_BillingNoSecret(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	s := &Server{
		logger: log.Default(), secret: ""}
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	s.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var status map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if status["webhook_secret"] != "not configured" {
		t.Errorf("Expected webhook_secret 'not configured', got '%s'", status["webhook_secret"])
	}
}

// ============================================================================
// Test: handleWebhook
// ============================================================================

func TestHandleWebhook_BillingWithLicenseGen(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	s := &Server{
		logger:       log.Default(),
		secret:       "",
		licenseGen:   NewMockLicenseGenerator(),
		emailService: NewMockEmailService(),
	}

	payload := []byte(`{
		"id": "evt_test",
		"type": "checkout.session.completed",
		"data": {
			"object": {
				"id": "cs_test",
				"customer_email": "test@example.com",
				"customer": "cus_test",
				"payment_status": "paid",
				"subscription": "sub_test",
				"amount_total": 9900,
				"currency": "usd",
				"metadata": {"tier": "developer"}
			}
		}
	}`)

	req := httptest.NewRequest("POST", "/webhook/stripe", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleWebhook(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestHandleWebhook_BillingInvalidJSON(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	s := &Server{
		logger: log.Default(), secret: ""}

	payload := []byte("not valid json{{{")

	req := httptest.NewRequest("POST", "/webhook/stripe", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleWebhook(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleWebhook_BillingMissingSignature(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")

	s := &Server{
		logger: log.Default(), secret: "whsec_test"}

	payload := []byte(`{"id": "evt_test", "type": "test"}`)

	req := httptest.NewRequest("POST", "/webhook/stripe", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleWebhook(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for missing signature, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleWebhook_BillingInvalidSignature(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")

	s := &Server{
		logger: log.Default(), secret: "whsec_test"}

	payload := []byte(`{"id": "evt_test", "type": "test"}`)

	req := httptest.NewRequest("POST", "/webhook/stripe", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", "t=1234567890,v1=invalidsignature")
	rr := httptest.NewRecorder()

	s.handleWebhook(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for invalid signature, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleWebhook_BillingUnhandledEvent(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	s := &Server{
		logger: log.Default(), secret: ""}

	payload := []byte(`{"id": "evt_test", "type": "unknown.event"}`)

	req := httptest.NewRequest("POST", "/webhook/stripe", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleWebhook(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d for unhandled event, got %d", http.StatusOK, rr.Code)
	}
}

// ============================================================================
// Test: handleCheckoutCompleted
// ============================================================================

func TestHandleCheckoutCompleted_BillingAllServices(t *testing.T) {
	s := &Server{
		logger:       log.Default(),
		licenseGen:   NewMockLicenseGenerator(),
		emailService: NewMockEmailService(),
	}

	data := []byte(`{
		"id": "cs_test",
		"customer_email": "customer@example.com",
		"customer": "cus_123",
		"payment_status": "paid",
		"amount_total": 9900,
		"metadata": {"tier": "developer"}
	}`)

	err := s.handleCheckoutCompleted(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestHandleCheckoutCompleted_BillingUnpaid(t *testing.T) {
	s := &Server{
		logger:       log.Default(),
		licenseGen:   NewMockLicenseGenerator(),
		emailService: NewMockEmailService(),
	}

	data := []byte(`{
		"id": "cs_test",
		"customer_email": "customer@example.com",
		"customer": "cus_123",
		"payment_status": "unpaid",
		"amount_total": 9900
	}`)

	err := s.handleCheckoutCompleted(data)
	if err != nil {
		t.Errorf("Unexpected error for unpaid session: %v", err)
	}
}

func TestHandleCheckoutCompleted_BillingInferTier(t *testing.T) {
	s := &Server{
		logger:       log.Default(),
		licenseGen:   NewMockLicenseGenerator(),
		emailService: NewMockEmailService(),
	}

	data := []byte(`{
		"id": "cs_test",
		"customer_email": "customer@example.com",
		"customer": "cus_123",
		"payment_status": "paid",
		"amount_total": 30000
	}`)

	err := s.handleCheckoutCompleted(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestHandleCheckoutCompleted_BillingNoLicenseGen(t *testing.T) {
	s := &Server{
		logger: log.Default(), emailService: NewMockEmailService()}

	data := []byte(`{
		"id": "cs_test",
		"customer_email": "customer@example.com",
		"customer": "cus_123",
		"payment_status": "paid",
		"amount_total": 9900,
		"metadata": {"tier": "developer"}
	}`)

	err := s.handleCheckoutCompleted(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

// Mock license generator that fails
type billingFailingLicenseGen struct{}

func (f *billingFailingLicenseGen) GenerateLicense(customerID string, tier string, days int) (string, error) {
	return "", errors.New("generation failed")
}

func (f *billingFailingLicenseGen) ActivateLicense(key string, email string) error {
	return nil
}

func TestHandleCheckoutCompleted_BillingGenFails(t *testing.T) {
	s := &Server{
		logger:       log.Default(),
		licenseGen:   &billingFailingLicenseGen{},
		emailService: NewMockEmailService(),
	}

	data := []byte(`{
		"id": "cs_test",
		"customer_email": "customer@example.com",
		"customer": "cus_123",
		"payment_status": "paid",
		"amount_total": 9900,
		"metadata": {"tier": "developer"}
	}`)

	err := s.handleCheckoutCompleted(data)
	if err == nil {
		t.Error("Expected error when license generation fails")
	}
}

// Mock email service that fails
type failingEmailSvc struct{}

func (f *failingEmailSvc) SendLicenseKey(to string, key string, tier string, expiresAt string) error {
	return errors.New("email send failed")
}

func TestHandleCheckoutCompleted_BillingEmailFails(t *testing.T) {
	s := &Server{
		logger:       log.Default(),
		licenseGen:   NewMockLicenseGenerator(),
		emailService: &failingEmailSvc{},
	}

	data := []byte(`{
		"id": "cs_test",
		"customer_email": "customer@example.com",
		"customer": "cus_123",
		"payment_status": "paid",
		"amount_total": 9900,
		"metadata": {"tier": "developer"}
	}`)

	// Should succeed even if email fails (logged but not fatal)
	err := s.handleCheckoutCompleted(data)
	if err != nil {
		t.Errorf("Unexpected error (email failure should be non-fatal): %v", err)
	}
}

// ============================================================================
// Test: handleSubscriptionUpdated
// ============================================================================

func TestHandleSubscriptionUpdated_BillingPastDue(t *testing.T) {
	s := &Server{
		logger: log.Default()}

	data := []byte(`{
		"id": "sub_test",
		"customer": "cus_test",
		"status": "past_due"
	}`)

	err := s.handleSubscriptionUpdated(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestHandleSubscriptionUpdated_BillingActive(t *testing.T) {
	s := &Server{
		logger: log.Default()}

	data := []byte(`{
		"id": "sub_test",
		"customer": "cus_test",
		"status": "active"
	}`)

	err := s.handleSubscriptionUpdated(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestHandleSubscriptionUpdated_BillingCanceled(t *testing.T) {
	s := &Server{
		logger: log.Default()}

	data := []byte(`{
		"id": "sub_test",
		"customer": "cus_test",
		"status": "canceled"
	}`)

	err := s.handleSubscriptionUpdated(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

// ============================================================================
// Test: inferTierFromAmount
// ============================================================================

func TestInferTierFromAmount_BillingEdgeCases(t *testing.T) {
	s := &Server{
		logger: log.Default()}

	tests := []struct {
		amount   int64
		expected string
	}{
		{0, "developer"},
		{2899, "developer"},
		{2900, "starter"},
		{5000, "starter"},
		{7899, "starter"},
		{7900, "developer"},
		{10000, "developer"},
		{24899, "developer"},
		{24900, "professional"},
		{50000, "professional"},
		{100000, "professional"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("amount_%d", tc.amount), func(t *testing.T) {
			got := s.inferTierFromAmount(tc.amount)
			if got != tc.expected {
				t.Errorf("inferTierFromAmount(%d) = %s; want %s", tc.amount, got, tc.expected)
			}
		})
	}
}

// ============================================================================
// Test: TierPrices
// ============================================================================

func TestTierPrices_BillingValues(t *testing.T) {
	if TierPrices["starter"] != 2900 {
		t.Errorf("Expected starter price 2900, got %d", TierPrices["starter"])
	}
	if TierPrices["developer"] != 7900 {
		t.Errorf("Expected developer price 7900, got %d", TierPrices["developer"])
	}
	if TierPrices["professional"] != 24900 {
		t.Errorf("Expected professional price 24900, got %d", TierPrices["professional"])
	}
}

// ============================================================================
// Test: MockLicenseGenerator
// ============================================================================

func TestMockLicenseGenerator_BillingGen(t *testing.T) {
	m := NewMockLicenseGenerator()

	key, err := m.GenerateLicense("cus_123", "developer", 365)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if key == "" {
		t.Error("Expected non-empty license key")
	}
	if len(key) < 3 || key[:3] != "AG-" {
		t.Errorf("Expected key to start with 'AG-', got %s", key)
	}
}

func TestMockLicenseGenerator_BillingActivate(t *testing.T) {
	m := NewMockLicenseGenerator()

	key, _ := m.GenerateLicense("cus_123", "developer", 365)
	err := m.ActivateLicense(key, "test@example.com")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestMockLicenseGenerator_BillingNotFound(t *testing.T) {
	m := NewMockLicenseGenerator()

	err := m.ActivateLicense("invalid-key", "test@example.com")
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
}

func TestMockLicenseGenerator_BillingMultiple(t *testing.T) {
	m := NewMockLicenseGenerator()

	key1, _ := m.GenerateLicense("cus_1", "starter", 30)
	key2, _ := m.GenerateLicense("cus_2", "developer", 365)
	key3, _ := m.GenerateLicense("cus_3", "professional", 730)

	if key1 == key2 || key2 == key3 || key1 == key3 {
		t.Error("Expected unique license keys")
	}
}

// ============================================================================
// Test: MockEmailService
// ============================================================================

func TestMockEmailService_BillingSend(t *testing.T) {
	m := NewMockEmailService()

	err := m.SendLicenseKey("test@example.com", "AG-KEY-123", "developer", "January 1, 2026")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(m.sent) != 1 {
		t.Errorf("Expected 1 sent email, got %d", len(m.sent))
	}

	if m.sent[0].to != "test@example.com" {
		t.Errorf("Expected to 'test@example.com', got '%s'", m.sent[0].to)
	}
}

// ============================================================================
// Test: NewWebhookServer
// ============================================================================

func TestNewWebhookServer_Billing(t *testing.T) {
	origVal := os.Getenv("STRIPE_WEBHOOK_SECRET")
	defer os.Setenv("STRIPE_WEBHOOK_SECRET", origVal)
	os.Unsetenv("STRIPE_WEBHOOK_SECRET")

	s := NewWebhookServer("8080")

	if s.port != "8080" {
		t.Errorf("Expected port '8080', got '%s'", s.port)
	}
	if s.secret != "" {
		t.Errorf("Expected empty secret, got '%s'", s.secret)
	}
	if s.logger == nil {
		t.Error("Expected non-nil logger")
	}
}

// Unused helper to avoid compiler warnings
var _ = strings.TrimSpace
