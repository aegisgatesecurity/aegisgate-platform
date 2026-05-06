// SPDX-License-Identifier: Apache-2.0
//go:build !race

package billing

// ---------------------------------------------------------------------------
// stripe_test.go — Full coverage for billing/stripe.go
// Tests mock-mode operations for all exported functions.
// No real Stripe credentials required — all tests use mock mode.
// ---------------------------------------------------------------------------

import (
	"context"
	"os"
	"testing"
	"time"
)

// helper: make a test client in explicit mock mode.
func newMockClient() *StripeClient {
	c := &StripeClient{mockMode: true, secretKey: "", webhookSecret: "", publishableKey: ""}
	return c
}

func TestNewStripeClient_MockMode(t *testing.T) {
	// Ensure STRIPE_SECRET_KEY is not set so we're in mock mode
	old := os.Getenv("STRIPE_SECRET_KEY")
	os.Unsetenv("STRIPE_SECRET_KEY")
	defer func() {
		if old != "" {
			os.Setenv("STRIPE_SECRET_KEY", old)
		}
	}()

	c := NewStripeClient()
	if !c.mockMode {
		t.Fatal("expected mock mode when STRIPE_SECRET_KEY is not set")
	}
}

func TestNewStripeClient_PlaceholderKey(t *testing.T) {
	old := os.Getenv("STRIPE_SECRET_KEY")
	os.Setenv("STRIPE_SECRET_KEY", "sk_test_placeholder")
	defer func() {
		if old != "" {
			os.Setenv("STRIPE_SECRET_KEY", old)
		} else {
			os.Unsetenv("STRIPE_SECRET_KEY")
		}
	}()

	c := NewStripeClient()
	if !c.mockMode {
		t.Fatal("expected mock mode when STRIPE_SECRET_KEY is placeholder")
	}
}

func TestIsMockMode(t *testing.T) {
	c := newMockClient()
	if !c.IsMockMode() {
		t.Error("IsMockMode() should return true for mock client")
	}
}

func TestGetPublishableKey(t *testing.T) {
	c := newMockClient()
	if got := c.GetPublishableKey(); got != "" {
		t.Errorf("GetPublishableKey() = %q, want empty", got)
	}

	c.publishableKey = "pk_test_abc123"
	if got := c.GetPublishableKey(); got != "pk_test_abc123" {
		t.Errorf("GetPublishableKey() = %q, want pk_test_abc123", got)
	}
}

func TestValidateConfig_EmptyKey(t *testing.T) {
	c := newMockClient()
	if err := c.ValidateConfig(); err == nil {
		t.Fatal("expected error for empty secret key")
	}
}

func TestValidateConfig_PlaceholderKey(t *testing.T) {
	c := newMockClient()
	c.secretKey = "sk_test_placeholder"
	if err := c.ValidateConfig(); err == nil {
		t.Fatal("expected error for placeholder key")
	}
}

func TestValidateConfig_ValidKey(t *testing.T) {
	c := newMockClient()
	c.secretKey = "sk_test_realkey123"
	if err := c.ValidateConfig(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateCheckoutSession_MockMode(t *testing.T) {
	c := newMockClient()
	session, err := c.CreateCheckoutSession(context.Background(), "developer", "user@example.com", "https://success", "https://cancel")
	if err != nil {
		t.Fatalf("CreateCheckoutSession() error: %v", err)
	}
	if session.Tier != "developer" {
		t.Errorf("Tier=%q, want developer", session.Tier)
	}
	if session.CustomerEmail != "user@example.com" {
		t.Errorf("CustomerEmail=%q, want user@example.com", session.CustomerEmail)
	}
	if session.URL == "" {
		t.Error("URL should be non-empty")
	}
	if session.Status != "complete" {
		t.Errorf("Status=%q, want complete", session.Status)
	}
}

func TestGetCustomer_MockMode(t *testing.T) {
	c := newMockClient()
	cust, err := c.GetCustomer(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("GetCustomer() error: %v", err)
	}
	if cust.Email != "alice@example.com" {
		t.Errorf("Email=%q, want alice@example.com", cust.Email)
	}
	if cust.ID == "" {
		t.Error("ID should be non-empty")
	}
}

func TestGetSubscription_MockMode(t *testing.T) {
	c := newMockClient()
	sub, err := c.GetSubscription(context.Background(), "sub_test_123")
	if err != nil {
		t.Fatalf("GetSubscription() error: %v", err)
	}
	if sub.ID != "sub_test_123" {
		t.Errorf("ID=%q, want sub_test_123", sub.ID)
	}
	if sub.Status != "active" {
		t.Errorf("Status=%q, want active", sub.Status)
	}
	// Verify period end is in the future
	if !sub.CurrentPeriodEnd.After(time.Now()) {
		t.Error("CurrentPeriodEnd should be in the future")
	}
}

func TestCreateBillingPortalSession_MockMode(t *testing.T) {
	c := newMockClient()
	portal, err := c.CreateBillingPortalSession(context.Background(), "cus_test_abc", "https://return")
	if err != nil {
		t.Fatalf("CreateBillingPortalSession() error: %v", err)
	}
	if portal.ID == "" {
		t.Error("ID should be non-empty")
	}
	if portal.ReturnURL != "https://return" {
		t.Errorf("ReturnURL=%q, want https://return", portal.ReturnURL)
	}
}

func TestCancelSubscription_MockMode(t *testing.T) {
	c := newMockClient()
	if err := c.CancelSubscription(context.Background(), "sub_test_123"); err != nil {
		t.Fatalf("CancelSubscription() error: %v", err)
	}
}

func TestUpdateSubscription_MockMode(t *testing.T) {
	c := newMockClient()
	if err := c.UpdateSubscription(context.Background(), "sub_test_123", "professional"); err != nil {
		t.Fatalf("UpdateSubscription() error: %v", err)
	}
}

func TestGetInvoices_MockMode(t *testing.T) {
	c := newMockClient()
	invoices, err := c.GetInvoices(context.Background(), "cus_test_abc")
	if err != nil {
		t.Fatalf("GetInvoices() error: %v", err)
	}
	if len(invoices) == 0 {
		t.Fatal("expected at least one invoice in mock mode")
	}
	inv := invoices[0]
	if inv.CustomerID != "cus_test_abc" {
		t.Errorf("CustomerID=%q, want cus_test_abc", inv.CustomerID)
	}
	if inv.Currency != "usd" {
		t.Errorf("Currency=%q, want usd", inv.Currency)
	}
	if inv.Status != "paid" {
		t.Errorf("Status=%q, want paid", inv.Status)
	}
}

func TestVerifyWebhookSignature_NoSecret(t *testing.T) {
	c := newMockClient()
	payload := []byte(`{"type":"checkout.session.completed"}`)
	result, err := c.VerifyWebhookSignature(payload, "sig123")
	if err != nil {
		t.Fatalf("VerifyWebhookSignature() error: %v", err)
	}
	if string(result) != string(payload) {
		t.Errorf("result=%s, want %s", result, payload)
	}
}

func TestVerifyWebhookSignature_WithSecret(t *testing.T) {
	c := newMockClient()
	c.webhookSecret = "whsec_test_secret"
	payload := []byte(`{"type":"invoice.paid"}`)
	result, err := c.VerifyWebhookSignature(payload, "sig123")
	if err != nil {
		t.Fatalf("VerifyWebhookSignature() error: %v", err)
	}
	if string(result) != string(payload) {
		t.Errorf("result=%s, want %s", result, payload)
	}
}

func TestConfigureProducts(t *testing.T) {
	// Save original
	orig := make(map[string]string)
	for k, v := range TierProducts {
		orig[k] = v
	}
	defer func() {
		for k, v := range orig {
			TierProducts[k] = v
		}
	}()

	products := map[string]string{
		"developer":    "price_dev_123",
		"professional": "price_pro_456",
	}
	ConfigureProducts(products)

	if TierProducts["developer"] != "price_dev_123" {
		t.Errorf("TierProducts[developer]=%q, want price_dev_123", TierProducts["developer"])
	}
	if TierProducts["professional"] != "price_pro_456" {
		t.Errorf("TierProducts[professional]=%q, want price_pro_456", TierProducts["professional"])
	}
	// starter/enterprise unchanged
	if TierProducts["starter"] != "" {
		t.Errorf("TierProducts[starter]=%q, want empty", TierProducts["starter"])
	}
}

func TestTierToUpper(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"starter", "STARTER"},
		{"developer", "DEVELOPER"},
		{"professional", "PROFESSIONAL"},
		{"enterprise", ""},
		{"unknown", ""},
	}
	for _, tc := range tests {
		if got := tierToUpper(tc.input); got != tc.want {
			t.Errorf("tierToUpper(%q)=%q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestCreateCheckoutSession_NonMockMode(t *testing.T) {
	c := newMockClient()
	c.mockMode = false
	c.secretKey = "sk_test_real"
	_, err := c.CreateCheckoutSession(context.Background(), "developer", "x@y.com", "http://ok", "http://cancel")
	if err == nil {
		t.Fatal("expected error in non-mock mode without real Stripe")
	}
}

func TestGetCustomer_NonMockMode(t *testing.T) {
	c := newMockClient()
	c.mockMode = false
	c.secretKey = "sk_test_real"
	_, err := c.GetCustomer(context.Background(), "x@y.com")
	if err == nil {
		t.Fatal("expected error in non-mock mode without real Stripe")
	}
}

func TestGetSubscription_NonMockMode(t *testing.T) {
	c := newMockClient()
	c.mockMode = false
	c.secretKey = "sk_test_real"
	_, err := c.GetSubscription(context.Background(), "sub_123")
	if err == nil {
		t.Fatal("expected error in non-mock mode without real Stripe")
	}
}

func TestCreateBillingPortalSession_NonMockMode(t *testing.T) {
	c := newMockClient()
	c.mockMode = false
	c.secretKey = "sk_test_real"
	_, err := c.CreateBillingPortalSession(context.Background(), "cus_123", "http://return")
	if err == nil {
		t.Fatal("expected error in non-mock mode without real Stripe")
	}
}

func TestCancelSubscription_NonMockMode(t *testing.T) {
	c := newMockClient()
	c.mockMode = false
	c.secretKey = "sk_test_real"
	err := c.CancelSubscription(context.Background(), "sub_123")
	if err == nil {
		t.Fatal("expected error in non-mock mode without real Stripe")
	}
}

func TestUpdateSubscription_NonMockMode(t *testing.T) {
	c := newMockClient()
	c.mockMode = false
	c.secretKey = "sk_test_real"
	err := c.UpdateSubscription(context.Background(), "sub_123", "enterprise")
	if err == nil {
		t.Fatal("expected error in non-mock mode without real Stripe")
	}
}

func TestGetInvoices_NonMockMode(t *testing.T) {
	c := newMockClient()
	c.mockMode = false
	c.secretKey = "sk_test_real"
	_, err := c.GetInvoices(context.Background(), "cus_123")
	if err == nil {
		t.Fatal("expected error in non-mock mode without real Stripe")
	}
}
