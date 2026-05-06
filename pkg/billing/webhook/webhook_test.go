// SPDX-License-Identifier: Apache-2.0
//go:build !race

package webhook

// ---------------------------------------------------------------------------
// webhook_test.go — Full coverage for billing/webhook/webhook.go
// ---------------------------------------------------------------------------

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"testing"
	"time"
)

// testLicenseService implements LicenseServicer for testing.
type testLicenseService struct {
	generateError  error
	activateError  error
	deactivateError error
	updateError    error
	generatedKey   string
	calls          []string
}

func (m *testLicenseService) GenerateLicense(ctx context.Context, customerID string, tier string, durationDays int) (string, error) {
	m.calls = append(m.calls, "GenerateLicense")
	if m.generateError != nil {
		return "", m.generateError
	}
	m.generatedKey = "test-license-" + customerID
	return m.generatedKey, nil
}

func (m *testLicenseService) ActivateLicense(ctx context.Context, licenseKey string, customerEmail string) error {
	m.calls = append(m.calls, "ActivateLicense")
	return m.activateError
}

func (m *testLicenseService) DeactivateLicense(ctx context.Context, licenseKey string) error {
	m.calls = append(m.calls, "DeactivateLicense")
	return m.deactivateError
}

func (m *testLicenseService) UpdateLicenseTier(ctx context.Context, licenseKey string, newTier string) error {
	m.calls = append(m.calls, "UpdateLicenseTier")
	return m.updateError
}

// testEmailService implements EmailServicer for testing.
type testEmailService struct {
	sendError error
	sentTo   string
	sentData  EmailData
}

func (m *testEmailService) SendLicenseEmail(ctx context.Context, to string, data EmailData) error {
	m.sentTo = to
	m.sentData = data
	return m.sendError
}

func TestDefaultHandler(t *testing.T) {
	h := DefaultHandler("whsec_test_secret")
	if h.webhookSecret != "whsec_test_secret" {
		t.Errorf("webhookSecret=%q, want whsec_test_secret", h.webhookSecret)
	}
	if h.logger == nil {
		t.Error("logger should not be nil")
	}
}

func TestHandler_WithLicenseService(t *testing.T) {
	h := &Handler{}
	mock := &testLicenseService{}
	result := h.WithLicenseService(mock)
	if result != h {
		t.Error("WithLicenseService should return the same handler")
	}
	if h.licenseService != mock {
		t.Error("licenseService not set correctly")
	}
}

func TestHandler_WithEmailService(t *testing.T) {
	h := &Handler{}
	mock := &testEmailService{}
	result := h.WithEmailService(mock)
	if result != h {
		t.Error("WithEmailService should return the same handler")
	}
	if h.emailService != mock {
		t.Error("emailService not set correctly")
	}
}

func TestProcessEvent_UnknownType(t *testing.T) {
	h := &Handler{logger: testLogger()}
	event := StripeEvent{
		ID:   "evt_test_123",
		Type: "unknown.event.type",
		Data: json.RawMessage(`{}`),
	}
	payload, _ := json.Marshal(event)

	// Should not error — unknown events are logged and skipped
	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}
}

func TestProcessEvent_CheckoutSessionCompleted(t *testing.T) {
	mockLic := &testLicenseService{}
	mockEmail := &testEmailService{}
	h := &Handler{
		logger:         testLogger(),
		licenseService: mockLic,
		emailService:   mockEmail,
	}

	sessionData := CheckoutSessionData{
		ID:            "cs_test_123",
		CustomerEmail: "alice@example.com",
		CustomerID:    "cus_test_abc",
		PaymentStatus: "paid",
		Metadata:      map[string]string{"tier": "developer"},
	}
	data, _ := json.Marshal(sessionData)
	event := StripeEvent{
		ID:   "evt_checkout",
		Type: "checkout.session.completed",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}

	if len(mockLic.calls) == 0 {
		t.Error("license service should have been called")
	}
}

func TestProcessEvent_CheckoutNotPaid(t *testing.T) {
	mockLic := &testLicenseService{}
	h := &Handler{
		logger:         testLogger(),
		licenseService: mockLic,
	}

	sessionData := CheckoutSessionData{
		ID:            "cs_test_123",
		CustomerEmail: "bob@example.com",
		PaymentStatus: "unpaid", // NOT paid
	}
	data, _ := json.Marshal(sessionData)
	event := StripeEvent{
		ID:   "evt_checkout_unpaid",
		Type: "checkout.session.completed",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}

	// Should NOT generate license for unpaid checkout
	if len(mockLic.calls) > 0 {
		t.Error("license service should not have been called for unpaid checkout")
	}
}

func TestProcessEvent_CheckoutSessionCompleted_TierInferFromAmount(t *testing.T) {
	mockLic := &testLicenseService{}
	h := &Handler{
		logger:         testLogger(),
		licenseService: mockLic,
	}

	// Amount corresponds to "professional" tier (>= 24900 cents)
	sessionData := CheckoutSessionData{
		ID:            "cs_test_pro",
		CustomerEmail: "pro@example.com",
		PaymentStatus: "paid",
		AmountTotal:   29900,
		Metadata:      map[string]string{}, // no tier in metadata
	}
	data, _ := json.Marshal(sessionData)
	event := StripeEvent{
		ID:   "evt_pro",
		Type: "checkout.session.completed",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}
}

func TestProcessEvent_CheckoutSessionCompleted_LicenseServiceError(t *testing.T) {
	mockLic := &testLicenseService{generateError: context.DeadlineExceeded}
	h := &Handler{
		logger:         testLogger(),
		licenseService: mockLic,
	}

	sessionData := CheckoutSessionData{
		ID:            "cs_test_err",
		CustomerEmail: "err@example.com",
		CustomerID:    "cus_err",
		PaymentStatus: "paid",
		Metadata:      map[string]string{"tier": "developer"},
	}
	data, _ := json.Marshal(sessionData)
	event := StripeEvent{
		ID:   "evt_err",
		Type: "checkout.session.completed",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err == nil {
		t.Fatal("expected error when license service fails")
	}
}

func TestProcessEvent_CheckoutSessionCompleted_EmailError(t *testing.T) {
	mockLic := &testLicenseService{}
	mockEmail := &testEmailService{sendError: context.DeadlineExceeded}
	h := &Handler{
		logger:         testLogger(),
		licenseService: mockLic,
		emailService:   mockEmail,
	}

	sessionData := CheckoutSessionData{
		ID:            "cs_test_email_err",
		CustomerEmail: "emailerr@example.com",
		CustomerID:    "cus_email_err",
		PaymentStatus: "paid",
		Metadata:      map[string]string{"tier": "developer"},
	}
	data, _ := json.Marshal(sessionData)
	event := StripeEvent{
		ID:   "evt_email_err",
		Type: "checkout.session.completed",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	// Email errors should NOT cause ProcessEvent to fail
	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() should not fail on email error: %v", err)
	}
}

func TestProcessEvent_SubscriptionUpdated(t *testing.T) {
	h := &Handler{logger: testLogger()}

	subData := SubscriptionData{
		ID:     "sub_test_123",
		Status: "active",
	}
	data, _ := json.Marshal(subData)
	event := StripeEvent{
		ID:   "evt_sub_active",
		Type: "customer.subscription.updated",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}
}

func TestProcessEvent_SubscriptionUpdated_PastDue(t *testing.T) {
	h := &Handler{logger: testLogger()}

	subData := SubscriptionData{
		ID:     "sub_past_due",
		Status: "past_due",
	}
	data, _ := json.Marshal(subData)
	event := StripeEvent{
		ID:   "evt_past_due",
		Type: "customer.subscription.updated",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}
}

func TestProcessEvent_SubscriptionUpdated_Canceled(t *testing.T) {
	h := &Handler{logger: testLogger()}

	subData := SubscriptionData{
		ID:     "sub_canceled",
		Status: "canceled",
	}
	data, _ := json.Marshal(subData)
	event := StripeEvent{
		ID:   "evt_sub_canceled",
		Type: "customer.subscription.updated",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}
}

func TestProcessEvent_SubscriptionDeleted(t *testing.T) {
	mockLic := &testLicenseService{}
	h := &Handler{
		logger:         testLogger(),
		licenseService: mockLic,
	}

	subData := SubscriptionData{
		ID:         "sub_deleted",
		CustomerID: "cus_deleted",
	}
	data, _ := json.Marshal(subData)
	event := StripeEvent{
		ID:   "evt_sub_deleted",
		Type: "customer.subscription.deleted",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}
}

func TestProcessEvent_InvoicePaymentSucceeded(t *testing.T) {
	h := &Handler{logger: testLogger()}

	invData := InvoiceData{
		ID:        "in_test_123",
		AmountPaid: 9900,
		Currency:  "usd",
		Status:    "paid",
	}
	data, _ := json.Marshal(invData)
	event := StripeEvent{
		ID:   "evt_inv_paid",
		Type: "invoice.payment_succeeded",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}
}

func TestProcessEvent_InvoicePaymentFailed(t *testing.T) {
	h := &Handler{logger: testLogger()}

	invData := InvoiceData{
		ID:       "in_test_failed",
		AmountDue: 9900,
		Currency: "usd",
		Status:   "open",
	}
	data, _ := json.Marshal(invData)
	event := StripeEvent{
		ID:   "evt_inv_failed",
		Type: "invoice.payment_failed",
		Data: data,
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err != nil {
		t.Fatalf("ProcessEvent() error: %v", err)
	}
}

func TestProcessEvent_InvalidPayload(t *testing.T) {
	h := &Handler{logger: testLogger()}
	if err := h.ProcessEvent(context.Background(), []byte(`not valid json`), "sig"); err == nil {
		t.Fatal("expected error for invalid JSON payload")
	}
}

func TestProcessEvent_InvalidEventData(t *testing.T) {
	h := &Handler{logger: testLogger()}

	event := StripeEvent{
		ID:   "evt_bad_data",
		Type: "checkout.session.completed",
		Data: json.RawMessage(`not valid json here`),
	}
	payload, _ := json.Marshal(event)

	if err := h.ProcessEvent(context.Background(), payload, "sig"); err == nil {
		t.Fatal("expected error for invalid event data")
	}
}

func TestInferTierFromAmount(t *testing.T) {
	h := &Handler{}
	tests := []struct {
		amount int64
		want   string
	}{
		{29900, "professional"}, // >= 24900
		{24900, "professional"}, // >= 24900
		{24899, "developer"},    // >= 7900
		{7900, "developer"},     // >= 7900
		{7899, "starter"},       // >= 2900
		{2900, "starter"},       // >= 2900
		{2899, "developer"},     // default fallback
		{0, "developer"},        // default fallback
	}
	for _, tc := range tests {
		if got := h.inferTierFromAmount(tc.amount); got != tc.want {
			t.Errorf("inferTierFromAmount(%d)=%q, want %q", tc.amount, got, tc.want)
		}
	}
}

func TestHealthCheck_NoSecret(t *testing.T) {
	h := &Handler{webhookSecret: ""}
	if err := h.HealthCheck(); err == nil {
		t.Fatal("expected error when webhook secret is empty")
	}
}

func TestHealthCheck_WithSecret(t *testing.T) {
	h := &Handler{webhookSecret: "whsec_test"}
	if err := h.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck() error: %v", err)
	}
}

func TestCheckoutSessionData_Fields(t *testing.T) {
	data := CheckoutSessionData{
		ID:            "cs_123",
		CustomerEmail: "test@example.com",
		CustomerID:    "cus_123",
		PaymentStatus: "paid",
		Status:        "complete",
		AmountTotal:   9900,
		Currency:      "usd",
		Metadata:      map[string]string{"tier": "developer"},
	}
	if data.ID != "cs_123" {
		t.Errorf("ID=%q, want cs_123", data.ID)
	}
	if data.PaymentStatus != "paid" {
		t.Errorf("PaymentStatus=%q, want paid", data.PaymentStatus)
	}
}

func TestSubscriptionData_Fields(t *testing.T) {
	data := SubscriptionData{
		ID:                 "sub_123",
		CustomerID:         "cus_123",
		Status:             "active",
		Tier:               "developer",
		CurrentPeriodStart: time.Now().AddDate(0, -1, 0),
		CurrentPeriodEnd:    time.Now().AddDate(0, 1, 0),
		CancelAtPeriodEnd:   false,
	}
	if data.Status != "active" {
		t.Errorf("Status=%q, want active", data.Status)
	}
}

func TestInvoiceData_Fields(t *testing.T) {
	data := InvoiceData{
		ID:             "in_123",
		CustomerID:     "cus_123",
		SubscriptionID: "sub_123",
		AmountDue:      9900,
		AmountPaid:     9900,
		Currency:       "usd",
		Status:         "paid",
		Paid:           true,
		Number:         "INV-0001",
		Description:    "AegisGate Developer License",
	}
	if data.Status != "paid" {
		t.Errorf("Status=%q, want paid", data.Status)
	}
	if !data.Paid {
		t.Error("Paid should be true")
	}
}

// testLogger returns a logger that writes to stderr (safe for tests).
func testLogger() *log.Logger {
	return log.New(os.Stderr, "", 0)
}
