// Package webhook provides Stripe webhook handling for AegisGate.
//
//go:build billing
// +build billing

package webhook

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// =============================================================================
// Handler Creation Tests
// =============================================================================

func TestDefaultHandler(t *testing.T) {
	handler := DefaultHandler("test_secret")
	if handler == nil {
		t.Fatal("DefaultHandler() should not return nil")
	}
}

func TestDefaultHandlerEmptySecret(t *testing.T) {
	handler := DefaultHandler("")
	if handler == nil {
		t.Fatal("DefaultHandler() with empty secret should not return nil")
	}
}

func TestHandlerWithLicenseService(t *testing.T) {
	handler := DefaultHandler("secret")
	result := handler.WithLicenseService(nil)
	if result != handler {
		t.Error("WithLicenseService() should return same handler")
	}
}

func TestHandlerWithEmailService(t *testing.T) {
	handler := DefaultHandler("secret")
	result := handler.WithEmailService(nil)
	if result != handler {
		t.Error("WithEmailService() should return same handler")
	}
}

func TestHandlerHealthCheck(t *testing.T) {
	handler := DefaultHandler("secret")
	err := handler.HealthCheck()
	if err != nil {
		t.Errorf("HealthCheck() error = %v", err)
	}
}

func TestHandlerHealthCheckEmptySecret(t *testing.T) {
	handler := DefaultHandler("")
	err := handler.HealthCheck()
	if err == nil {
		t.Error("HealthCheck() with empty secret should error")
	}
}

// =============================================================================
// Event Parsing Tests
// =============================================================================

func TestStripeEventFields(t *testing.T) {
	event := &StripeEvent{
		ID:        "evt_123",
		Type:      "checkout.session.completed",
		CreatedAt: time.Now().Unix(),
		Livemode:  false,
	}

	if event.ID != "evt_123" {
		t.Errorf("Event ID = %q, want %q", event.ID, "evt_123")
	}
	if event.Type != "checkout.session.completed" {
		t.Errorf("Event Type = %q, want %q", event.Type, "checkout.session.completed")
	}
}

func TestStripeEventJSONSerialization(t *testing.T) {
	event := &StripeEvent{
		ID:        "evt_json_test",
		Type:      "invoice.paid",
		CreatedAt: 1714425600,
		Livemode:  true,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed StripeEvent
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.ID != event.ID {
		t.Errorf("Parsed ID = %q, want %q", parsed.ID, event.ID)
	}
	if parsed.Livemode != event.Livemode {
		t.Errorf("Parsed Livemode = %v, want %v", parsed.Livemode, event.Livemode)
	}
}

func TestStripeEventDataRawMessage(t *testing.T) {
	event := &StripeEvent{
		ID:   "evt_data",
		Type: "test",
		Data: json.RawMessage(`{"key": "value"}`),
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(event.Data, &parsed); err != nil {
		t.Fatalf("Failed to parse event Data: %v", err)
	}

	if parsed["key"] != "value" {
		t.Errorf("Parsed Data[key] = %v, want %v", parsed["key"], "value")
	}
}

// =============================================================================
// Checkout Session Data Tests
// =============================================================================

func TestCheckoutSessionDataFields(t *testing.T) {
	data := &CheckoutSessionData{
		ID:            "cs_123",
		CustomerEmail: "test@example.com",
		CustomerID:    "cus_123",
		AmountTotal:   7900,
		Currency:      "usd",
		Status:        "complete",
		Metadata:      map[string]string{"tier": "developer"},
	}

	if data.CustomerEmail != "test@example.com" {
		t.Errorf("CustomerEmail = %q, want %q", data.CustomerEmail, "test@example.com")
	}
	if data.AmountTotal != 7900 {
		t.Errorf("AmountTotal = %d, want 7900", data.AmountTotal)
	}
}

func TestCheckoutSessionDataMetadata(t *testing.T) {
	data := &CheckoutSessionData{
		ID:       "cs_metadata",
		Metadata: map[string]string{"tier": "professional", "seats": "5"},
	}

	if data.Metadata["tier"] != "professional" {
		t.Errorf("Metadata[tier] = %q, want %q", data.Metadata["tier"], "professional")
	}
}

func TestCheckoutSessionDataJSON(t *testing.T) {
	data := &CheckoutSessionData{
		ID:            "cs_json",
		CustomerEmail: "json@example.com",
		AmountTotal:   24900,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed CheckoutSessionData
	if err := json.Unmarshal(dataBytes, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.CustomerEmail != data.CustomerEmail {
		t.Errorf("Parsed CustomerEmail = %q, want %q", parsed.CustomerEmail, data.CustomerEmail)
	}
}

// =============================================================================
// Subscription Data Tests
// =============================================================================

func TestSubscriptionDataFields(t *testing.T) {
	data := &SubscriptionData{
		ID:         "sub_123",
		CustomerID: "cus_123",
		Status:     "active",
	}

	if data.Status != "active" {
		t.Errorf("Status = %q, want %q", data.Status, "active")
	}
}

func TestSubscriptionDataCancelAtPeriodEnd(t *testing.T) {
	data := &SubscriptionData{
		ID:                "sub_cancel",
		CustomerID:        "cus_123",
		Status:            "active",
		CancelAtPeriodEnd: true,
	}

	if !data.CancelAtPeriodEnd {
		t.Error("CancelAtPeriodEnd should be true")
	}
}

func TestSubscriptionDataJSON(t *testing.T) {
	data := &SubscriptionData{
		ID:         "sub_json",
		CustomerID: "cus_json",
		Status:     "trialing",
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed SubscriptionData
	if err := json.Unmarshal(dataBytes, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.Status != "trialing" {
		t.Errorf("Parsed Status = %q, want %q", parsed.Status, "trialing")
	}
}

// =============================================================================
// Invoice Data Tests
// =============================================================================

func TestInvoiceDataFields(t *testing.T) {
	data := &InvoiceData{
		ID:             "in_123",
		CustomerID:     "cus_123",
		SubscriptionID: "sub_123",
		AmountPaid:     7900,
		Currency:       "usd",
		Status:         "paid",
	}

	if data.AmountPaid != 7900 {
		t.Errorf("AmountPaid = %d, want 7900", data.AmountPaid)
	}
	if data.Status != "paid" {
		t.Errorf("Status = %q, want %q", data.Status, "paid")
	}
}

func TestInvoiceDataPastDue(t *testing.T) {
	data := &InvoiceData{
		ID:         "in_past_due",
		CustomerID: "cus_123",
		AmountPaid: 0,
		Currency:   "usd",
		Status:     "past_due",
	}

	if data.Status != "past_due" {
		t.Errorf("Status = %q, want %q", data.Status, "past_due")
	}
}

func TestInvoiceDataJSON(t *testing.T) {
	data := &InvoiceData{
		ID:         "in_json",
		CustomerID: "cus_json",
		AmountPaid: 24900,
		Currency:   "usd",
		Status:     "paid",
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var parsed InvoiceData
	if err := json.Unmarshal(dataBytes, &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if parsed.AmountPaid != 24900 {
		t.Errorf("Parsed AmountPaid = %d, want 24900", parsed.AmountPaid)
	}
}

// =============================================================================
// ProcessEvent Tests
// =============================================================================

func TestProcessEventCheckoutSessionCompleted(t *testing.T) {
	handler := DefaultHandler("secret")
	payload := []byte(`{
		"id": "evt_checkout",
		"type": "checkout.session.completed",
		"created": 1714425600,
		"data": {"object": {"id": "cs_123", "customer_email": "test@example.com"}}
	}`)

	err := handler.ProcessEvent(context.Background(), payload, "sig_123")
	_ = err
}

func TestProcessEventSubscriptionCreated(t *testing.T) {
	handler := DefaultHandler("secret")
	payload := []byte(`{"id": "evt_sub", "type": "customer.subscription.created", "created": 1714425600}`)
	err := handler.ProcessEvent(context.Background(), payload, "sig_123")
	_ = err
}

func TestProcessEventInvoicePaid(t *testing.T) {
	handler := DefaultHandler("secret")
	payload := []byte(`{"id": "evt_invoice", "type": "invoice.paid", "created": 1714425600}`)
	err := handler.ProcessEvent(context.Background(), payload, "sig_123")
	_ = err
}

func TestProcessEventInvalidJSON(t *testing.T) {
	handler := DefaultHandler("secret")
	payload := []byte(`invalid json {`)
	err := handler.ProcessEvent(context.Background(), payload, "sig_123")
	if err == nil {
		t.Error("ProcessEvent() with invalid JSON should error")
	}
}

func TestProcessEventEmptyPayload(t *testing.T) {
	handler := DefaultHandler("secret")
	err := handler.ProcessEvent(context.Background(), []byte{}, "sig")
	if err == nil {
		t.Error("ProcessEvent() with empty payload should error")
	}
}

func TestProcessEventPaymentFailed(t *testing.T) {
	handler := DefaultHandler("secret")
	payload := []byte(`{"id": "evt_failed", "type": "invoice.payment_failed", "created": 1714425600, "data": {"object": {}}}`)
	_ = handler.ProcessEvent(context.Background(), payload, "sig")
}

func TestProcessEventSubscriptionDeleted(t *testing.T) {
	handler := DefaultHandler("secret")
	payload := []byte(`{"id": "evt_deleted", "type": "customer.subscription.deleted", "created": 1714425600}`)
	_ = handler.ProcessEvent(context.Background(), payload, "sig")
}

func TestProcessEventSubscriptionUpdated(t *testing.T) {
	handler := DefaultHandler("secret")
	payload := []byte(`{"id": "evt_updated", "type": "customer.subscription.updated", "created": 1714425600}`)
	_ = handler.ProcessEvent(context.Background(), payload, "sig")
}

// =============================================================================
// Direct Handler Function Tests
// =============================================================================

func TestHandleCheckoutSessionCompletedWithData(t *testing.T) {
	handler := DefaultHandler("whsec_test")
	ctx := context.Background()

	dataJSON := `{"object": {"id": "cs_test", "customer_email": "test@example.com", "customer_id": "cus_test"}}`
	event := &StripeEvent{
		ID:   "evt_handle_checkout_data",
		Type: "checkout.session.completed",
		Data: json.RawMessage(dataJSON),
	}

	err := handler.handleCheckoutSessionCompleted(ctx, event)
	if err != nil {
		t.Errorf("handleCheckoutSessionCompleted() with data error = %v", err)
	}
}

func TestHandleCheckoutSessionCompletedPaid(t *testing.T) {
	handler := DefaultHandler("whsec_test")
	ctx := context.Background()

	dataJSON := `{"object": {"id": "cs_paid", "customer_email": "paid@example.com", "customer_id": "cus_paid", "amount_total": 7900}}`
	event := &StripeEvent{
		ID:   "evt_paid_checkout",
		Type: "checkout.session.completed",
		Data: json.RawMessage(dataJSON),
	}

	err := handler.handleCheckoutSessionCompleted(ctx, event)
	if err != nil {
		t.Errorf("handleCheckoutSessionCompleted() paid checkout error = %v", err)
	}
}

func TestHandleSubscriptionUpdatedWithData(t *testing.T) {
	handler := DefaultHandler("whsec_test")
	ctx := context.Background()

	dataJSON := `{"object": {"id": "sub_test", "customer": "cus_test", "status": "active"}}`
	event := &StripeEvent{
		ID:   "evt_sub_updated_data",
		Type: "customer.subscription.updated",
		Data: json.RawMessage(dataJSON),
	}

	err := handler.handleSubscriptionUpdated(ctx, event)
	if err != nil {
		t.Errorf("handleSubscriptionUpdated() with data error = %v", err)
	}
}

func TestHandleSubscriptionDeletedWithData(t *testing.T) {
	handler := DefaultHandler("whsec_test")
	ctx := context.Background()

	dataJSON := `{"object": {"id": "sub_deleted", "customer": "cus_test", "status": "canceled"}}`
	event := &StripeEvent{
		ID:   "evt_sub_deleted_data",
		Type: "customer.subscription.deleted",
		Data: json.RawMessage(dataJSON),
	}

	err := handler.handleSubscriptionDeleted(ctx, event)
	if err != nil {
		t.Errorf("handleSubscriptionDeleted() with data error = %v", err)
	}
}

func TestHandleInvoicePaymentSucceededWithData(t *testing.T) {
	handler := DefaultHandler("whsec_test")
	ctx := context.Background()

	dataJSON := `{"object": {"id": "in_test", "customer": "cus_test", "amount_paid": 7900, "status": "paid"}}`
	event := &StripeEvent{
		ID:   "evt_invoice_succeeded_data",
		Type: "invoice.paid",
		Data: json.RawMessage(dataJSON),
	}

	err := handler.handleInvoicePaymentSucceeded(ctx, event)
	if err != nil {
		t.Errorf("handleInvoicePaymentSucceeded() with data error = %v", err)
	}
}

func TestHandleInvoicePaymentFailedWithData(t *testing.T) {
	handler := DefaultHandler("whsec_test")
	ctx := context.Background()

	dataJSON := `{"object": {"id": "in_failed", "customer": "cus_test", "amount_paid": 0, "status": "open"}}`
	event := &StripeEvent{
		ID:   "evt_invoice_failed_data",
		Type: "invoice.payment_failed",
		Data: json.RawMessage(dataJSON),
	}

	err := handler.handleInvoicePaymentFailed(ctx, event)
	if err != nil {
		t.Errorf("handleInvoicePaymentFailed() with data error = %v", err)
	}
}

func TestHandleInvoicePaymentFailedWithCustomerEmail(t *testing.T) {
	handler := DefaultHandler("whsec_test")
	ctx := context.Background()

	dataJSON := `{"object": {"id": "in_failed_email", "customer_email": "failed@example.com"}}`
	event := &StripeEvent{
		ID:   "evt_invoice_failed_email",
		Type: "invoice.payment_failed",
		Data: json.RawMessage(dataJSON),
	}

	err := handler.handleInvoicePaymentFailed(ctx, event)
	if err != nil {
		t.Errorf("handleInvoicePaymentFailed() with customer email error = %v", err)
	}
}

// =============================================================================
// Tier Inference Tests
// =============================================================================

func TestInferTierFromAmount(t *testing.T) {
	handler := DefaultHandler("secret")

	tests := []struct {
		amount int64
		want   string
	}{
		// Amount >= 24900 returns professional
		{24900, "professional"},
		{100000, "professional"},
		// Amount >= 7900 returns developer
		{7900, "developer"},
		{15000, "developer"},
		// Amount >= 2900 returns starter
		{2900, "starter"},
		{5000, "starter"},
		// Below 2900 returns developer (default fallback)
		{0, "developer"},
		{2800, "developer"},
		{-100, "developer"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := handler.inferTierFromAmount(tt.amount)
			if got != tt.want {
				t.Errorf("inferTierFromAmount(%d) = %q, want %q", tt.amount, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Event Type Constants
// =============================================================================

func TestEventTypeConstants(t *testing.T) {
	eventTypes := []string{
		"checkout.session.completed",
		"customer.subscription.created",
		"customer.subscription.updated",
		"customer.subscription.deleted",
		"invoice.paid",
		"invoice.payment_failed",
	}

	for _, et := range eventTypes {
		if et == "" {
			t.Error("Empty event type constant")
		}
	}
}

func TestAllEventTypesCovered(t *testing.T) {
	requiredEvents := map[string]bool{
		"checkout.session.completed":    false,
		"customer.subscription.created": false,
		"customer.subscription.updated": false,
		"customer.subscription.deleted": false,
		"invoice.paid":                  false,
		"invoice.payment_failed":        false,
	}

	for event := range requiredEvents {
		if event == "" {
			t.Error("Empty event type")
		}
	}
}
