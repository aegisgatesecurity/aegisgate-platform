// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026 AegisGate Security
// =========================================================================
// AegisGate Platform - Stripe Webhook Coverage Tests
// =========================================================================

package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"testing"
)

// handleSubscriptionDeleted Tests

func TestHandleSubscriptionDeleted(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	subData, _ := json.Marshal(map[string]interface{}{
		"id":       "sub_123",
		"customer": "cus_456",
		"status":   "canceled",
	})
	err := srv.handleSubscriptionDeleted(subData)
	if err != nil {
		t.Errorf("handleSubscriptionDeleted failed: %v", err)
	}
}

func TestHandleSubscriptionDeleted_InvalidJSON(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	err := srv.handleSubscriptionDeleted([]byte("invalid json"))
	if err == nil {
		t.Error("handleSubscriptionDeleted should fail on invalid JSON")
	}
}

func TestHandleSubscriptionDeleted_PartialData(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	subData, _ := json.Marshal(map[string]interface{}{"id": "sub_minimal"})
	err := srv.handleSubscriptionDeleted(subData)
	if err != nil {
		t.Errorf("handleSubscriptionDeleted failed on partial data: %v", err)
	}
}

// handleInvoicePaid Tests

func TestHandleInvoicePaid(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	invoiceData, _ := json.Marshal(map[string]interface{}{
		"id":           "in_123",
		"customer":     "cus_456",
		"amount_paid":  7900,
		"currency":     "usd",
		"status":       "paid",
		"subscription": "sub_789",
	})
	err := srv.handleInvoicePaid(invoiceData)
	if err != nil {
		t.Errorf("handleInvoicePaid failed: %v", err)
	}
}

func TestHandleInvoicePaid_InvalidJSON(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	err := srv.handleInvoicePaid([]byte("invalid json"))
	if err == nil {
		t.Error("handleInvoicePaid should fail on invalid JSON")
	}
}

func TestHandleInvoicePaid_LargeAmount(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	invoiceData, _ := json.Marshal(map[string]interface{}{
		"id":          "in_large",
		"customer":    "cus_large",
		"amount_paid": 2490000,
		"currency":    "usd",
	})
	err := srv.handleInvoicePaid(invoiceData)
	if err != nil {
		t.Errorf("handleInvoicePaid failed on large amount: %v", err)
	}
}

func TestHandleInvoicePaid_CurrencyTypes(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	currencies := []string{"usd", "eur", "gbp", "jpy"}
	for _, curr := range currencies {
		invoiceData, _ := json.Marshal(map[string]interface{}{
			"id":          "in_" + curr,
			"customer":    "cus_" + curr,
			"amount_paid": 7900,
			"currency":    curr,
		})
		err := srv.handleInvoicePaid(invoiceData)
		if err != nil {
			t.Errorf("handleInvoicePaid failed for currency %s: %v", curr, err)
		}
	}
}

// handleInvoiceFailed Tests

func TestHandleInvoiceFailed(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	invoiceData, _ := json.Marshal(map[string]interface{}{
		"id":         "in_failed_123",
		"customer":   "cus_failed_456",
		"amount_due": 7900,
		"currency":   "usd",
	})
	err := srv.handleInvoiceFailed(invoiceData)
	if err != nil {
		t.Errorf("handleInvoiceFailed failed: %v", err)
	}
}

func TestHandleInvoiceFailed_InvalidJSON(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	err := srv.handleInvoiceFailed([]byte("invalid json"))
	if err == nil {
		t.Error("handleInvoiceFailed should fail on invalid JSON")
	}
}

func TestHandleInvoiceFailed_PartialData(t *testing.T) {
	srv := &Server{port: "8080", secret: "test-secret", logger: log.Default()}
	invoiceData, _ := json.Marshal(map[string]interface{}{"id": "in_minimal"})
	err := srv.handleInvoiceFailed(invoiceData)
	if err != nil {
		t.Errorf("handleInvoiceFailed failed on partial data: %v", err)
	}
}

// verifySignature Tests

func computeHMAC(payload []byte, secret string) string {
	timestamp := "1234567890"
	signedPayload := timestamp + "." + string(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	return "t=" + timestamp + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifySignature_Valid(t *testing.T) {
	srv := &Server{port: "8080", secret: "whsec_test_secret_12345", logger: log.Default()}
	payload := []byte("{\"type\": \"checkout.session.completed\"}")
	sig := computeHMAC(payload, srv.secret)
	err := srv.verifySignature(payload, sig)
	if err != nil {
		t.Errorf("verifySignature should succeed: %v", err)
	}
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
	srv := &Server{port: "8080", secret: "whsec_test_secret", logger: log.Default()}
	payload := []byte("{\"type\": \"checkout.session.completed\"}")
	sig := "t=1234567890,v1=invalid_signature_here"
	err := srv.verifySignature(payload, sig)
	if err == nil {
		t.Error("verifySignature should fail for invalid signature")
	}
}

func TestVerifySignature_MissingTimestamp(t *testing.T) {
	srv := &Server{port: "8080", secret: "whsec_test_secret", logger: log.Default()}
	payload := []byte("{\"type\": \"checkout.session.completed\"}")
	sig := "v1=some_signature"
	err := srv.verifySignature(payload, sig)
	if err == nil {
		t.Error("verifySignature should fail for missing timestamp")
	}
}

func TestVerifySignature_MissingSignature(t *testing.T) {
	srv := &Server{port: "8080", secret: "whsec_test_secret", logger: log.Default()}
	payload := []byte("{\"type\": \"checkout.session.completed\"}")
	sig := "t=1234567890"
	err := srv.verifySignature(payload, sig)
	if err == nil {
		t.Error("verifySignature should fail for missing v1 signature")
	}
}

func TestVerifySignature_MalformedFormat(t *testing.T) {
	srv := &Server{port: "8080", secret: "whsec_test_secret", logger: log.Default()}
	payload := []byte("{\"type\": \"checkout.session.completed\"}")
	sig := "malformed=signature=format"
	err := srv.verifySignature(payload, sig)
	if err == nil {
		t.Error("verifySignature should fail for malformed format")
	}
}

func TestVerifySignature_MultipleSignatures(t *testing.T) {
	srv := &Server{port: "8080", secret: "whsec_test_secret", logger: log.Default()}
	payload := []byte("{\"type\": \"checkout.session.completed\"}")
	sig := computeHMAC(payload, srv.secret) + ",v1=invalid_other"
	err := srv.verifySignature(payload, sig)
	if err != nil {
		t.Errorf("verifySignature should succeed with multiple sigs: %v", err)
	}
}

// inferTierFromAmount Tests

func TestInferTierFromAmount_Professional(t *testing.T) {
	srv := &Server{}
	for _, amt := range []int64{30000, 24900, 25000, 50000} {
		if tier := srv.inferTierFromAmount(amt); tier != "professional" {
			t.Errorf("inferTierFromAmount(%d) = %s, want professional", amt, tier)
		}
	}
}

func TestInferTierFromAmount_Developer(t *testing.T) {
	srv := &Server{}
	for _, amt := range []int64{7900, 8000, 15000, 24800} {
		if tier := srv.inferTierFromAmount(amt); tier != "developer" {
			t.Errorf("inferTierFromAmount(%d) = %s, want developer", amt, tier)
		}
	}
}

func TestInferTierFromAmount_Starter(t *testing.T) {
	srv := &Server{}
	for _, amt := range []int64{2900, 3000, 5000, 7800} {
		if tier := srv.inferTierFromAmount(amt); tier != "starter" {
			t.Errorf("inferTierFromAmount(%d) = %s, want starter", amt, tier)
		}
	}
}

func TestInferTierFromAmount_Default(t *testing.T) {
	srv := &Server{}
	for _, amt := range []int64{0, 100, 2000, 2899} {
		if tier := srv.inferTierFromAmount(amt); tier != "developer" {
			t.Errorf("inferTierFromAmount(%d) = %s, want developer", amt, tier)
		}
	}
}
