// Package billing provides Stripe billing integration for AegisGate.
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
// Additional Coverage Tests - To reach 80%
// =============================================================================

func TestCreateCheckoutSessionWithMockClient(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	session, err := client.CreateCheckoutSession(ctx, "starter", "starter@test.com", "https://example.com/success", "https://example.com/cancel")
	if err != nil {
		t.Errorf("CreateCheckoutSession() starter error = %v", err)
	}
	if session == nil {
		t.Fatal("CreateCheckoutSession() returned nil session")
	}
	if session.ID == "" {
		t.Error("Session ID should be set")
	}
}

func TestCreateCheckoutSessionProfessional(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	session, err := client.CreateCheckoutSession(ctx, "professional", "pro@test.com", "https://example.com/success", "https://example.com/cancel")
	if err != nil {
		t.Errorf("CreateCheckoutSession() professional error = %v", err)
	}
	if session.URL == "" {
		t.Error("Session URL should be set")
	}
}

func TestCreateCheckoutSessionEnterprise(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	session, err := client.CreateCheckoutSession(ctx, "enterprise", "enterprise@test.com", "https://example.com/success", "https://example.com/cancel")
	if err != nil {
		t.Errorf("CreateCheckoutSession() enterprise error = %v", err)
	}
	if session.Status == "" {
		t.Error("Session status should be set")
	}
}

func TestCreateCheckoutSessionDeveloper(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	session, err := client.CreateCheckoutSession(ctx, "developer", "dev@test.com", "https://example.com/success", "https://example.com/cancel")
	if err != nil {
		t.Errorf("CreateCheckoutSession() developer error = %v", err)
	}
	if session == nil {
		t.Fatal("CreateCheckoutSession() returned nil session")
	}
}

func TestGetCustomerWithMockClient(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	customer, err := client.GetCustomer(ctx, "cus_mock123")
	if err != nil {
		t.Errorf("GetCustomer() error = %v", err)
	}
	if customer == nil {
		t.Fatal("GetCustomer() returned nil customer")
	}
	if customer.ID == "" {
		t.Error("Customer ID should be set")
	}
}

func TestGetSubscriptionWithMockClient(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	sub, err := client.GetSubscription(ctx, "sub_mock123")
	if err != nil {
		t.Errorf("GetSubscription() error = %v", err)
	}
	if sub == nil {
		t.Fatal("GetSubscription() returned nil subscription")
	}
	if sub.ID == "" {
		t.Error("Subscription ID should be set")
	}
}

func TestCreateBillingPortalSessionMock(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	session, err := client.CreateBillingPortalSession(ctx, "cus_mock123", "https://example.com/return")
	if err != nil {
		t.Errorf("CreateBillingPortalSession() error = %v", err)
	}
	if session == nil {
		t.Fatal("CreateBillingPortalSession() returned nil session")
	}
	if session.URL == "" {
		t.Error("Portal session URL should be set")
	}
}

func TestCancelSubscriptionMock(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	err := client.CancelSubscription(ctx, "sub_mock123")
	if err != nil {
		t.Errorf("CancelSubscription() error = %v", err)
	}
}

func TestUpdateSubscriptionMock(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	err := client.UpdateSubscription(ctx, "sub_mock123", "professional")
	if err != nil {
		t.Errorf("UpdateSubscription() error = %v", err)
	}
}

func TestGetInvoicesWithMockClient(t *testing.T) {
	client := NewStripeClient()
	ctx := context.Background()

	invoices, err := client.GetInvoices(ctx, "cus_mock123")
	if err != nil {
		t.Errorf("GetInvoices() error = %v", err)
	}
	if invoices == nil {
		t.Fatal("GetInvoices() returned nil")
	}
}

func TestVerifyWebhookSignatureMock(t *testing.T) {
	client := NewStripeClient()

	payload := []byte(`{"id": "evt_test"}`)
	verified, err := client.VerifyWebhookSignature(payload, "sig_test")
	if err != nil {
		t.Errorf("VerifyWebhookSignature() error = %v", err)
	}
	if verified == nil {
		t.Error("VerifyWebhookSignature() should return payload")
	}
}

// =============================================================================
// Test Error Paths (Non-Mock Mode)
// =============================================================================

func TestCreateCheckoutSessionRealMode(t *testing.T) {
	// Create a client that thinks it's in real mode
	// by using a key format that doesn't match mock patterns
	client := &StripeClient{
		secretKey: "sk_live_real_key_format",
		mockMode:  false,
	}

	session, err := client.CreateCheckoutSession(context.Background(), "starter", "test@test.com", "https://success", "https://cancel")
	if err == nil {
		t.Error("CreateCheckoutSession() real mode should return error")
	}
	if session != nil {
		t.Error("CreateCheckoutSession() real mode should return nil session")
	}
}

func TestGetCustomerRealMode(t *testing.T) {
	client := &StripeClient{
		secretKey: "sk_live_real_key",
		mockMode:  false,
	}

	customer, err := client.GetCustomer(context.Background(), "test@test.com")
	if err == nil {
		t.Error("GetCustomer() real mode should return error")
	}
	if customer != nil {
		t.Error("GetCustomer() real mode should return nil")
	}
}

func TestGetSubscriptionRealMode(t *testing.T) {
	client := &StripeClient{
		secretKey: "sk_live_real_key",
		mockMode:  false,
	}

	sub, err := client.GetSubscription(context.Background(), "sub_123")
	if err == nil {
		t.Error("GetSubscription() real mode should return error")
	}
	if sub != nil {
		t.Error("GetSubscription() real mode should return nil")
	}
}

func TestCreateBillingPortalSessionRealMode(t *testing.T) {
	client := &StripeClient{
		secretKey: "sk_live_real_key",
		mockMode:  false,
	}

	session, err := client.CreateBillingPortalSession(context.Background(), "cus_123", "https://return")
	if err == nil {
		t.Error("CreateBillingPortalSession() real mode should return error")
	}
	if session != nil {
		t.Error("CreateBillingPortalSession() real mode should return nil")
	}
}

func TestCancelSubscriptionRealMode(t *testing.T) {
	client := &StripeClient{
		secretKey: "sk_live_real_key",
		mockMode:  false,
	}

	err := client.CancelSubscription(context.Background(), "sub_123")
	if err == nil {
		t.Error("CancelSubscription() real mode should return error")
	}
}

func TestUpdateSubscriptionRealMode(t *testing.T) {
	client := &StripeClient{
		secretKey: "sk_live_real_key",
		mockMode:  false,
	}

	err := client.UpdateSubscription(context.Background(), "sub_123", "professional")
	if err == nil {
		t.Error("UpdateSubscription() real mode should return error")
	}
}

func TestGetInvoicesRealMode(t *testing.T) {
	client := &StripeClient{
		secretKey: "sk_live_real_key",
		mockMode:  false,
	}

	invoices, err := client.GetInvoices(context.Background(), "cus_123")
	if err == nil {
		t.Error("GetInvoices() real mode should return error")
	}
	if invoices != nil {
		t.Error("GetInvoices() real mode should return nil")
	}
}

func TestVerifyWebhookSignatureWithSecret(t *testing.T) {
	client := &StripeClient{
		secretKey:     "sk_live_real_key",
		webhookSecret: "whsec_test_secret",
		mockMode:      false,
	}

	payload := []byte(`{"id": "evt_test"}`)
	verified, err := client.VerifyWebhookSignature(payload, "sig_test")
	if err != nil {
		t.Errorf("VerifyWebhookSignature() error = %v", err)
	}
	if verified == nil {
		t.Error("VerifyWebhookSignature() should return payload")
	}
}

func TestValidateConfigEmptyKey(t *testing.T) {
	client := &StripeClient{
		secretKey: "",
		mockMode:  false,
	}

	err := client.ValidateConfig()
	if err == nil {
		t.Error("ValidateConfig() with empty key should return error")
	}
}

func TestValidateConfigPlaceholder(t *testing.T) {
	client := &StripeClient{
		secretKey: "sk_test_placeholder",
		mockMode:  true,
	}

	err := client.ValidateConfig()
	if err == nil {
		t.Error("ValidateConfig() with placeholder should return error")
	}
}

// =============================================================================
// JSON Serialization Tests
// =============================================================================

func TestTierProductsAndPrices(t *testing.T) {
	// Prices are loaded from billing-config.json via LoadBillingConfig
	if err := LoadBillingConfig(); err != nil {
		t.Fatalf("LoadBillingConfig() failed: %v", err)
	}

	expectedTiers := []string{"starter", "developer", "professional", "enterprise"}

	for _, tier := range expectedTiers {
		if _, exists := TierProducts[tier]; !exists {
			t.Errorf("TierProducts missing entry for %s", tier)
		}
	}

	if TierPrices["starter"] != 2900 {
		t.Errorf("TierPrices[starter] = %d, want 2900", TierPrices["starter"])
	}
	if TierPrices["developer"] != 7900 {
		t.Errorf("TierPrices[developer] = %d, want 7900", TierPrices["developer"])
	}
	if TierPrices["professional"] != 24900 {
		t.Errorf("TierPrices[professional] = %d, want 24900", TierPrices["professional"])
	}
}

func TestMockCheckoutSessionData(t *testing.T) {
	session := &CheckoutSession{
		ID:     "cs_test_mock",
		URL:    "https://checkout.stripe.com/mock",
		Status: "complete",
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

func TestMockCustomerData(t *testing.T) {
	customer := &Customer{
		ID:        "cus_test_mock",
		Email:     "customer@test.com",
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

func TestMockSubscriptionData(t *testing.T) {
	subscription := &Subscription{
		ID:         "sub_test_mock",
		CustomerID: "cus_mock",
		Status:     "active",
	}

	data, err := json.Marshal(subscription)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed Subscription
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.Status != "active" {
		t.Errorf("Parsed Status = %q, want %q", parsed.Status, "active")
	}
}

func TestMockInvoiceData(t *testing.T) {
	invoice := &Invoice{
		ID:         "in_test_mock",
		CustomerID: "cus_mock",
		AmountDue:  7900,
		AmountPaid: 7900,
		Currency:   "usd",
		Status:     "paid",
		Created:    time.Now(),
	}

	data, err := json.Marshal(invoice)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed Invoice
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.AmountPaid != invoice.AmountPaid {
		t.Errorf("Parsed AmountPaid = %d, want %d", parsed.AmountPaid, invoice.AmountPaid)
	}
}

func TestMockPortalSessionData(t *testing.T) {
	session := &PortalSession{
		URL: "https://billing.stripe.com/mock",
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed PortalSession
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.URL != session.URL {
		t.Errorf("Parsed URL = %q, want %q", parsed.URL, session.URL)
	}
}

func TestNewStripeClientMultipleTimes(t *testing.T) {
	client1 := NewStripeClient()
	client2 := NewStripeClient()

	if client1 == nil || client2 == nil {
		t.Fatal("NewStripeClient() should return non-nil client")
	}
}

func TestMockCreateCheckoutSessionAllTiers(t *testing.T) {
	client := NewStripeClient()

	tiers := []string{"starter", "developer", "professional", "enterprise"}

	for _, tier := range tiers {
		t.Run(tier, func(t *testing.T) {
			session, err := client.CreateCheckoutSession(context.Background(), tier, "test@test.com", "https://success", "https://cancel")
			if err != nil {
				t.Errorf("CreateCheckoutSession(%s) error = %v", tier, err)
			}
			if session == nil {
				t.Errorf("CreateCheckoutSession(%s) returned nil", tier)
			}
		})
	}
}

func TestMockGetCustomerMultiple(t *testing.T) {
	client := NewStripeClient()

	customers := []string{"cus_1", "cus_2", "cus_3"}

	for _, id := range customers {
		t.Run(id, func(t *testing.T) {
			customer, err := client.GetCustomer(context.Background(), id)
			if err != nil {
				t.Errorf("GetCustomer(%s) error = %v", id, err)
			}
			if customer == nil {
				t.Errorf("GetCustomer(%s) returned nil", id)
			}
		})
	}
}

func TestMockGetSubscriptionMultiple(t *testing.T) {
	client := NewStripeClient()

	subs := []string{"sub_1", "sub_2", "sub_3"}

	for _, id := range subs {
		t.Run(id, func(t *testing.T) {
			sub, err := client.GetSubscription(context.Background(), id)
			if err != nil {
				t.Errorf("GetSubscription(%s) error = %v", id, err)
			}
			if sub == nil {
				t.Errorf("GetSubscription(%s) returned nil", id)
			}
		})
	}
}

func TestMockVerifyWebhookSignatureEmpty(t *testing.T) {
	client := NewStripeClient()

	payload := []byte(``)
	verified, err := client.VerifyWebhookSignature(payload, "")
	if err != nil {
		t.Errorf("VerifyWebhookSignature(empty) error = %v", err)
	}
	if len(verified) != 0 {
		t.Errorf("VerifyWebhookSignature(empty) should return empty payload")
	}
}
