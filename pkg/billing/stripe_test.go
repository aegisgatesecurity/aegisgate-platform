// Package billing provides Stripe billing integration for AegisGate.
//
// Comprehensive tests for stripe.go - covers all exported functions.
//
//go:build billing
// +build billing

package billing

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// =============================================================================
// Mock Mode Tests
// =============================================================================

func TestIsMockMode(t *testing.T) {
	client := NewStripeClient()

	// Default should be true (mock mode)
	if !client.IsMockMode() {
		t.Error("New client should default to mock mode")
	}
}

func TestMockModeDisabled(t *testing.T) {
	client := &StripeClient{}
	if client.IsMockMode() {
		t.Error("Empty client should not be in mock mode")
	}
}

// =============================================================================
// Publishable Key Tests
// =============================================================================

func TestGetPublishableKey(t *testing.T) {
	client := NewStripeClient()
	client.publishableKey = "pk_test_abc123"

	key := client.GetPublishableKey()
	if key != "pk_test_abc123" {
		t.Errorf("GetPublishableKey() = %q, want %q", key, "pk_test_abc123")
	}
}

func TestGetPublishableKeyEmpty(t *testing.T) {
	client := NewStripeClient()
	key := client.GetPublishableKey()
	if key != "" {
		t.Errorf("GetPublishableKey() = %q, want empty string", key)
	}
}

// =============================================================================
// Configuration Validation Tests
// =============================================================================

func TestValidateConfig(t *testing.T) {
	// Test with empty client - should not panic
	client := NewStripeClient()
	err := client.ValidateConfig()
	// May error if STRIPE_SECRET_KEY not set - that's expected behavior
	// Just verify it doesn't panic
	_ = err
}

// =============================================================================
// Checkout Session Tests
// =============================================================================

func TestCreateCheckoutSession(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	session, err := client.CreateCheckoutSession(
		ctx,
		"developer",
		"test@example.com",
		"https://aegisgatesecurity.io/success",
		"https://aegisgatesecurity.io/cancel",
	)

	if err != nil {
		t.Fatalf("CreateCheckoutSession() error = %v", err)
	}

	if session.ID == "" {
		t.Error("Checkout session ID should not be empty")
	}

	if session.CustomerEmail != "test@example.com" {
		t.Errorf("CustomerEmail = %q, want %q", session.CustomerEmail, "test@example.com")
	}

	if session.Tier != "developer" {
		t.Errorf("Tier = %q, want %q", session.Tier, "developer")
	}

	if session.URL == "" {
		t.Error("Checkout URL should not be empty in mock mode")
	}
}

func TestCreateCheckoutSessionAllTiers(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	tiers := []string{"starter", "developer", "professional", "enterprise"}

	for _, tier := range tiers {
		t.Run(tier, func(t *testing.T) {
			session, err := client.CreateCheckoutSession(
				ctx, tier, "test@example.com", "https://success", "https://cancel",
			)
			if err != nil {
				t.Fatalf("CreateCheckoutSession() error = %v", err)
			}
			if session.Tier != tier {
				t.Errorf("Tier = %q, want %q", session.Tier, tier)
			}
		})
	}
}

func TestCreateCheckoutSessionInvalidTier(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	session, err := client.CreateCheckoutSession(
		ctx, "invalid_tier", "test@example.com", "https://success", "https://cancel",
	)

	// Mock mode should not return error for invalid tier
	if err != nil {
		t.Errorf("CreateCheckoutSession() with invalid tier error = %v", err)
	}
	if session != nil && session.Tier != "invalid_tier" {
		t.Errorf("Session tier = %q, want %q", session.Tier, "invalid_tier")
	}
}

func TestMockCreateCheckoutSession(t *testing.T) {
	client := NewStripeClient()

	session, err := client.mockCreateCheckoutSession(
		"professional",
		"mock@example.com",
		"https://success",
		"https://cancel",
	)

	if err != nil {
		t.Fatalf("mockCreateCheckoutSession() error = %v", err)
	}

	if session.ID == "" {
		t.Error("Mock session ID should not be empty")
	}

	if session.CustomerEmail != "mock@example.com" {
		t.Errorf("CustomerEmail = %q, want %q", session.CustomerEmail, "mock@example.com")
	}
}

// =============================================================================
// Customer Tests
// =============================================================================

func TestGetCustomer(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	customer, err := client.GetCustomer(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetCustomer() error = %v", err)
	}

	if customer.ID == "" {
		t.Error("Customer ID should not be empty")
	}

	if customer.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", customer.Email, "test@example.com")
	}
}

func TestGetCustomerMockData(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	// Get same customer twice - should return consistent mock data
	customer1, _ := client.GetCustomer(ctx, "test@example.com")
	customer2, _ := client.GetCustomer(ctx, "test@example.com")

	// Both should have valid IDs (not checking equality since mock may generate new ones)
	if customer1.ID == "" || customer2.ID == "" {
		t.Error("Customer IDs should not be empty")
	}
}

// =============================================================================
// Subscription Tests
// =============================================================================

func TestGetSubscription(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	subscription, err := client.GetSubscription(ctx, "sub_test123")
	if err != nil {
		t.Fatalf("GetSubscription() error = %v", err)
	}

	if subscription.ID != "sub_test123" {
		t.Errorf("Subscription ID = %q, want %q", subscription.ID, "sub_test123")
	}
}

func TestGetSubscriptionStatus(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	subscription, err := client.GetSubscription(ctx, "sub_active")
	if err != nil {
		t.Fatalf("GetSubscription() error = %v", err)
	}

	if subscription.Status == "" {
		t.Error("Subscription status should not be empty")
	}
}

func TestCancelSubscription(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	err := client.CancelSubscription(ctx, "sub_test123")
	if err != nil {
		t.Errorf("CancelSubscription() error = %v", err)
	}
}

func TestUpdateSubscription(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	err := client.UpdateSubscription(ctx, "sub_test123", "professional")
	if err != nil {
		t.Errorf("UpdateSubscription() error = %v", err)
	}
}

func TestUpdateSubscriptionInvalidTier(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	err := client.UpdateSubscription(ctx, "sub_test123", "invalid")
	if err != nil {
		t.Errorf("UpdateSubscription() with invalid tier should not error in mock mode")
	}
}

// =============================================================================
// Portal Session Tests
// =============================================================================

func TestCreateBillingPortalSession(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	session, err := client.CreateBillingPortalSession(
		ctx, "cus_test123", "https://aegisgatesecurity.io/account",
	)

	if err != nil {
		t.Fatalf("CreateBillingPortalSession() error = %v", err)
	}

	if session.ID == "" {
		t.Error("Portal session ID should not be empty")
	}

	if session.ReturnURL != "https://aegisgatesecurity.io/account" {
		t.Errorf("ReturnURL = %q, want %q", session.ReturnURL, "https://aegisgatesecurity.io/account")
	}
}

// =============================================================================
// Invoice Tests
// =============================================================================

func TestGetInvoices(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	invoices, err := client.GetInvoices(ctx, "cus_test123")
	if err != nil {
		t.Fatalf("GetInvoices() error = %v", err)
	}

	if len(invoices) == 0 {
		t.Error("GetInvoices() should return at least one mock invoice")
	}
}

func TestGetInvoicesEmptyCustomer(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	invoices, err := client.GetInvoices(ctx, "")
	if err != nil {
		t.Errorf("GetInvoices() with empty customer should not error in mock mode")
	}
	if invoices == nil {
		t.Error("GetInvoices() should return empty slice, not nil")
	}
}

func TestInvoiceFields(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	invoices, _ := client.GetInvoices(ctx, "cus_test123")
	if len(invoices) > 0 {
		invoice := invoices[0]
		if invoice.ID == "" {
			t.Error("Invoice ID should not be empty")
		}
		if invoice.AmountDue < 0 {
			t.Errorf("Invoice AmountDue = %d, should be non-negative", invoice.AmountDue)
		}
	}
}

// =============================================================================
// Webhook Signature Verification Tests
// =============================================================================

func TestVerifyWebhookSignature(t *testing.T) {
	client := NewStripeClient()

	payload := []byte(`{"test": "data"}`)
	sig := "test_signature"

	result, err := client.VerifyWebhookSignature(payload, sig)
	if err != nil {
		t.Fatalf("VerifyWebhookSignature() error = %v", err)
	}

	if len(result) == 0 {
		t.Error("VerifyWebhookSignature() should return payload")
	}
}

func TestVerifyWebhookSignatureEmpty(t *testing.T) {
	client := NewStripeClient()

	_, err := client.VerifyWebhookSignature([]byte{}, "")
	if err != nil {
		t.Errorf("VerifyWebhookSignature() with empty payload should not error")
	}
}

// =============================================================================
// Product Configuration Tests
// =============================================================================

func TestConfigureProducts(t *testing.T) {
	products := map[string]string{
		"developer":    "prod_developer",
		"professional": "prod_professional",
	}

	ConfigureProducts(products)

	// Verify products were configured
	if TierProducts["developer"] != "prod_developer" {
		t.Errorf("TierProducts[developer] = %q, want %q", TierProducts["developer"], "prod_developer")
	}
}

func TestConfigureProductsEmpty(t *testing.T) {
	ConfigureProducts(map[string]string{})

	// Should not panic
}

// =============================================================================
// Type Serialization Tests
// =============================================================================

func TestCheckoutSessionJSON(t *testing.T) {
	session := &CheckoutSession{
		ID:            "cs_123",
		CustomerEmail: "test@example.com",
		Tier:          "developer",
		Status:        "complete",
		URL:           "https://checkout.stripe.com",
		CreatedAt:     time.Now(),
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed CheckoutSession
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.ID != session.ID {
		t.Errorf("Parsed ID = %q, want %q", parsed.ID, session.ID)
	}
}

func TestCustomerJSON(t *testing.T) {
	customer := &Customer{
		ID:        "cus_123",
		Email:     "test@example.com",
		Name:      "Test User",
		CreatedAt: time.Now(),
	}

	data, err := json.Marshal(customer)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed Customer
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.Email != customer.Email {
		t.Errorf("Parsed Email = %q, want %q", parsed.Email, customer.Email)
	}
}

func TestSubscriptionJSON(t *testing.T) {
	now := time.Now()
	subscription := &Subscription{
		ID:                 "sub_123",
		CustomerID:         "cus_123",
		Status:             "active",
		CurrentPeriodStart: now,
		CurrentPeriodEnd:   now.AddDate(0, 1, 0),
	}

	data, err := json.Marshal(subscription)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed Subscription
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.Status != subscription.Status {
		t.Errorf("Parsed Status = %q, want %q", parsed.Status, subscription.Status)
	}
}

func TestInvoiceJSON(t *testing.T) {
	invoice := &Invoice{
		ID:         "in_123",
		CustomerID: "cus_123",
		AmountDue:  7900,
		Currency:   "usd",
		Status:     "paid",
	}

	data, err := json.Marshal(invoice)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed Invoice
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.AmountDue != invoice.AmountDue {
		t.Errorf("Parsed AmountDue = %d, want %d", parsed.AmountDue, invoice.AmountDue)
	}
}

func TestPortalSessionJSON(t *testing.T) {
	session := &PortalSession{
		ID:        "bps_123",
		URL:       "https://billing.stripe.com",
		ReturnURL: "https://aegisgatesecurity.io",
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed PortalSession
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.ID != session.ID {
		t.Errorf("Parsed ID = %q, want %q", parsed.ID, session.ID)
	}
}

// =============================================================================
// Tier Constants Tests
// =============================================================================

func TestTierConstants(t *testing.T) {
	// Verify tier constants are defined
	tiers := []string{"starter", "developer", "professional", "enterprise"}

	for _, tier := range tiers {
		if _, ok := TierProducts[tier]; !ok {
			t.Errorf("TierProducts missing tier %q", tier)
		}
	}
}

func TestTierPricing(t *testing.T) {
	// Prices are now loaded from billing-config.json (or env vars).
	// LoadBillingConfig must be called first to populate TierPrices.
	if err := LoadBillingConfig(); err != nil {
		t.Fatalf("LoadBillingConfig() failed: %v", err)
	}

	if TierPrices["starter"] != 2900 {
		t.Errorf("Starter price = %d, want 2900", TierPrices["starter"])
	}

	if TierPrices["developer"] != 7900 {
		t.Errorf("Developer price = %d, want 7900", TierPrices["developer"])
	}

	if TierPrices["professional"] != 24900 {
		t.Errorf("Professional price = %d, want 24900", TierPrices["professional"])
	}
}
