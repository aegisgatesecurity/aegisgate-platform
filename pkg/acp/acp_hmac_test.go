// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - ACP HMAC Tests

package acp

import (
	"strconv"
	"testing"
)

func TestNewHMACVerifier(t *testing.T) {
	verifier := NewHMACVerifier("test-secret-key")
	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestSignMessage(t *testing.T) {
	verifier := NewHMACVerifier("test-secret")
	payload := []byte("test message content")

	timestamp, signature := verifier.SignMessage(payload)
	if timestamp == 0 {
		t.Error("Expected non-zero timestamp")
	}
	if signature == "" {
		t.Error("Expected non-empty signature")
	}
	t.Logf("Signed: ts=%d, sig=%s...", timestamp, signature[:15])
}

func TestSignMessageEmpty(t *testing.T) {
	verifier := NewHMACVerifier("test-secret")
	timestamp, signature := verifier.SignMessage([]byte{})
	if timestamp == 0 {
		t.Error("Expected non-zero timestamp for empty payload")
	}
	if signature == "" {
		t.Error("Expected non-empty signature")
	}
}

func TestVerifyMessageSignature(t *testing.T) {
	verifier := NewHMACVerifier("test-secret")
	payload := []byte("test message content")

	timestamp, signature := verifier.SignMessage(payload)
	err := verifier.VerifyMessageSignature(timestamp, payload, signature)
	if err != nil {
		t.Error("Expected signature to be valid")
	}
}

func TestVerifyMessageSignatureInvalid(t *testing.T) {
	verifier := NewHMACVerifier("test-secret")
	payload := []byte("test message content")

	err := verifier.VerifyMessageSignature(1234567890, payload, "invalid-signature")
	if err == nil {
		t.Error("Expected error for invalid signature")
	}
}

func TestParseHMACHeader(t *testing.T) {
	ts, sig, err := ParseHMACHeader("t=1234567890,v1=abc123def456")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if ts != 1234567890 {
		t.Errorf("Expected timestamp 1234567890, got %d", ts)
	}
	if sig != "abc123def456" {
		t.Errorf("Expected signature abc123def456, got %s", sig)
	}
}

func TestParseHMACHeaderInvalidFormat(t *testing.T) {
	_, _, err := ParseHMACHeader("invalid-header")
	if err == nil {
		t.Error("Expected error for invalid format")
	}
}

func TestParseHMACHeaderEmpty(t *testing.T) {
	_, _, err := ParseHMACHeader("")
	if err == nil {
		t.Error("Expected error for empty header")
	}
}

func TestVerifyHeader(t *testing.T) {
	verifier := NewHMACVerifier("test-secret")
	payload := []byte("test content")

	timestamp, signature := verifier.SignMessage(payload)
	header := "t=" + strconv.FormatInt(timestamp, 10) + ",v1=" + signature

	err := verifier.VerifyHeader(header, payload)
	if err != nil {
		t.Error("Expected header verification to succeed")
	}
}

func TestVerifyHeaderInvalid(t *testing.T) {
	verifier := NewHMACVerifier("test-secret")
	payload := []byte("test content")

	err := verifier.VerifyHeader("t=1234567890,v1=invalid-signature", payload)
	if err == nil {
		t.Error("Expected error for invalid header")
	}
}
