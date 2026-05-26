// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - ACP HMAC Tests

package acp

import (
	"strconv"
	"testing"
	"time"
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
}

func TestVerifyMessageSignatureInvalid(t *testing.T) {
	verifier := NewHMACVerifier("test-secret")
	payload := []byte("test message")
	_, signature := verifier.SignMessage(payload)
	tamperedSig := signature + "x"
	err := verifier.VerifyMessageSignature(time.Now().Unix(), payload, tamperedSig)
	if err != ErrHMACVerification {
		t.Errorf("Expected ErrHMACVerification, got %v", err)
	}
}

func TestParseHMACHeader(t *testing.T) {
	// Test existing format
	_, _, err := ParseHMACHeader("t=1234567890,v1=somesig")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestParseHMACHeaderInvalidFormat(t *testing.T) {
	_, _, err := ParseHMACHeader("invalid-format")
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
	payload := []byte("test message")
	timestamp, sig := verifier.SignMessage(payload)
	header := "t=" + strconv.FormatInt(timestamp, 10) + ",v1=" + sig
	err := verifier.VerifyHeader(header, payload)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestVerifyHeaderInvalid(t *testing.T) {
	verifier := NewHMACVerifier("test-secret")
	err := verifier.VerifyHeader("invalid", []byte("payload"))
	if err == nil {
		t.Error("Expected error for invalid header")
	}
}

// New tests for uncovered lines

func TestParseHMACHeaderSscanf(t *testing.T) {
	timestamp, signature, err := ParseHMACHeader("t=1234567890,v1=abc123")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if timestamp != 1234567890 {
		t.Errorf("Expected timestamp 1234567890, got %d", timestamp)
	}
	if signature != "abc123" {
		t.Errorf("Expected signature 'abc123', got '%s'", signature)
	}
}

func TestParseHMACHeaderManualParse(t *testing.T) {
	timestamp, signature, err := ParseHMACHeader("t=9876543210,v1=xyz789")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if timestamp != 9876543210 {
		t.Errorf("Expected timestamp 9876543210, got %d", timestamp)
	}
	if signature != "xyz789" {
		t.Errorf("Expected signature 'xyz789', got '%s'", signature)
	}
}

func TestParseHMACHeaderMissingTimestamp(t *testing.T) {
	_, _, err := ParseHMACHeader("v1=abc123")
	if err == nil {
		t.Error("Expected error for missing timestamp")
	}
}

func TestParseHMACHeaderMissingSignature(t *testing.T) {
	_, _, err := ParseHMACHeader("t=1234567890")
	if err == nil {
		t.Error("Expected error for missing signature")
	}
}

func TestVerifyHeaderError(t *testing.T) {
	hv := NewHMACVerifier("test-secret-key-32-bytes-long!!!!")
	err := hv.VerifyHeader("invalid-header", []byte("payload"))
	if err == nil {
		t.Error("Expected error for invalid header")
	}
}

func TestVerifyMessageSignatureExpired(t *testing.T) {
	hv := NewHMACVerifier("test-secret-key-32-bytes-long!!!!")
	oldTimestamp := time.Now().Add(-10 * time.Minute).Unix()
	err := hv.VerifyMessageSignature(oldTimestamp, []byte("payload"), "invalid-sig")
	if err != ErrTokenExpired {
		t.Errorf("Expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyMessageSignatureValid(t *testing.T) {
	hv := NewHMACVerifier("test-secret-key-32-bytes-long!!!!")
	payload := []byte("test message")
	timestamp, signature := hv.SignMessage(payload)
	err := hv.VerifyMessageSignature(timestamp, payload, signature)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}
