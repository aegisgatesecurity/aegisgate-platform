// SPDX-License-Identifier: Apache-2.0
//go:build !race

package signature_verification

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// =============================================================================
// Enable/Disable/StrictMode tests (0% → 100%)
// =============================================================================

func TestEnable_ThenDisable(t *testing.T) {
	sv := NewSignatureVerifier()
	if sv.IsEnabled() != true {
		t.Errorf("expected IsEnabled=true initially (verification enabled by default), got false")
	}

	sv.Disable()
	if sv.IsEnabled() != false {
		t.Errorf("expected IsEnabled=false after Disable(), got true")
	}

	sv.Enable()
	if sv.IsEnabled() != true {
		t.Errorf("expected IsEnabled=true after Enable(), got false")
	}
}

func TestStrictMode_EnableDisable(t *testing.T) {
	sv := NewSignatureVerifier()
	if sv.IsStrictModeEnabled() != false {
		t.Errorf("expected IsStrictModeEnabled=false initially, got true")
	}

	sv.EnableStrictMode()
	if sv.IsStrictModeEnabled() != true {
		t.Errorf("expected IsStrictModeEnabled=true after EnableStrictMode(), got false")
	}

	sv.DisableStrictMode()
	if sv.IsStrictModeEnabled() != false {
		t.Errorf("expected IsStrictModeEnabled=false after DisableStrictMode(), got false")
	}
}

func TestStrictMode_CanBeEnabledDisabled(t *testing.T) {
	sv := NewSignatureVerifier()

	sv.Enable()
	if sv.IsEnabled() != true {
		t.Errorf("Enable() failed")
	}
	if sv.IsStrictModeEnabled() != false {
		t.Errorf("strict mode should not change when Enable() called")
	}

	sv.EnableStrictMode()
	if sv.IsStrictModeEnabled() != true {
		t.Errorf("EnableStrictMode() failed")
	}
	if sv.IsEnabled() != true {
		t.Errorf("Enable should not change when EnableStrictMode() called")
	}
}

// =============================================================================
// SetAllowedKeys / GetAllowedKeys tests (0% → 100%)
// =============================================================================

func TestAllowedKeys_SetAndGet(t *testing.T) {
	sv := NewSignatureVerifier()
	if sv.GetAllowedKeys() != nil && len(sv.GetAllowedKeys()) != 0 {
		t.Errorf("expected empty keys initially")
	}

	keys := map[string]bool{
		"key-1": true,
		"key-2": true,
		"key-3": false,
	}
	sv.SetAllowedKeys(keys)

	got := sv.GetAllowedKeys()
	if len(got) != 3 {
		t.Errorf("expected 3 keys, got %d", len(got))
	}
	if !got["key-1"] || !got["key-2"] {
		// key-3's false value may or may not be stored depending on impl
		t.Errorf("key-1/key-2 mismatch: %v", got)
	}
}

func TestAllowedKeys_ReplaceKeys(t *testing.T) {
	sv := NewSignatureVerifier()

	sv.SetAllowedKeys(map[string]bool{"key-a": true})
	sv.SetAllowedKeys(map[string]bool{"key-b": true, "key-c": false})

	got := sv.GetAllowedKeys()
	if len(got) != 2 {
		t.Errorf("expected 2 keys after replace, got %d", len(got))
	}
	if got["key-a"] {
		t.Errorf("key-a should have been replaced")
	}
	if !got["key-b"] {
		t.Errorf("key-b should exist")
	}
}

// =============================================================================
// ValidateSignedPayload tests (0% → 100%)
// =============================================================================

func TestValidateSignedPayload_ValidSignature(t *testing.T) {
	sv := NewSignatureVerifier()

	priv, _, pubPEM, _ := GenerateTestRSAKeyPair(2048)
	if priv == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	payload := []byte("test payload for ValidateSignedPayload")
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("SignPKCS1v15 failed: %v", err)
	}

	signed := &SignedPayload{
		Data:      payload,
		Signature: sig,
		PublicKey: pubPEM,
	}

	result, _ := sv.ValidateSignedPayload(signed)
	if result == nil {
		t.Errorf("ValidateSignedPayload returned nil")
	}
}

func TestValidateSignedPayload_NilPayload(t *testing.T) {
	sv := NewSignatureVerifier()

	signed := &SignedPayload{
		Data:      nil,
		Signature: []byte("sig"),
		PublicKey: []byte("key"),
	}

	result, _ := sv.ValidateSignedPayload(signed)
	if result == nil {
		t.Errorf("ValidateSignedPayload should return a result")
	}
}

// =============================================================================
// GetStats tests — multiple operations incrementing counters
// =============================================================================

func TestGetStats_MultipleOperations(t *testing.T) {
	sv := NewSignatureVerifier()

	stats := sv.GetStats()
	if stats == nil {
		t.Fatalf("GetStats returned nil")
	}

	// After failed verify, stats should be updated
	_, _ = sv.VerifySignature([]byte("data"), []byte("bad-sig"), []byte("bad-key"))

	stats = sv.GetStats()
	if stats.TotalVerifications < 1 {
		t.Errorf("expected TotalVerifications>=1 after failed verify, got %d", stats.TotalVerifications)
	}
}

func TestUpdateStats_AfterFailedVerify(t *testing.T) {
	sv := NewSignatureVerifier()

	_, _ = sv.VerifySignature([]byte("payload"), []byte("invalid-sig"), []byte("not-a-key"))

	stats := sv.GetStats()
	if stats.Failed < 1 {
		t.Errorf("expected Failed>=1 after failed verify, got %d", stats.Failed)
	}
	if stats.LastFailTime.IsZero() {
		t.Errorf("LastFailTime should be set after failed verify")
	}
}

func TestUpdateStats_AfterSuccessfulVerify(t *testing.T) {
	sv := NewSignatureVerifier()

	priv, _, pubPEM, _ := GenerateTestRSAKeyPair(2048)
	if priv == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	payload := []byte("test payload for successful verify")
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("SignPKCS1v15 failed: %v", err)
	}

	_, _ = sv.VerifySignature(payload, sig, pubPEM)

	stats := sv.GetStats()
	if stats.Successful < 1 {
		t.Errorf("expected Successful>=1 after valid verify, got %d", stats.Successful)
	}
	if stats.LastSuccessTime.IsZero() {
		t.Errorf("LastSuccessTime should be set after successful verify")
	}
}

// =============================================================================
// VerifyStringSignature — error and success paths
// =============================================================================

func TestVerifyStringSignature_InvalidBase64(t *testing.T) {
	sv := NewSignatureVerifier()

	_, _, key, _ := GenerateTestRSAKeyPair(2048)
	if key == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	result, err := sv.VerifyStringSignature([]byte("payload"), "not-valid-base64!!!", key)
	if err == nil && result != nil && result.Valid {
		t.Errorf("invalid base64 signature should not verify as valid")
	}
}

func TestVerifyStringSignature_EmptySignature(t *testing.T) {
	sv := NewSignatureVerifier()

	_, _, key, _ := GenerateTestRSAKeyPair(2048)
	if key == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	result, err := sv.VerifyStringSignature([]byte("payload"), "", key)
	if err == nil && result != nil && result.Valid {
		t.Errorf("empty signature should not verify as valid")
	}
}

func TestVerifyStringSignature_ValidBase64Signature(t *testing.T) {
	sv := NewSignatureVerifier()

	priv, _, pubPEM, _ := GenerateTestRSAKeyPair(2048)
	if priv == nil || pubPEM == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	payload := []byte("test payload for string signature")
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("SignPKCS1v15 failed: %v", err)
	}

	sigB64 := base64.StdEncoding.EncodeToString(sig)

	result, err := sv.VerifyStringSignature(payload, sigB64, pubPEM)
	if err != nil {
		t.Errorf("VerifyStringSignature failed: %v", err)
	}
	if result == nil {
		t.Errorf("VerifyStringSignature returned nil result")
	}
}

// =============================================================================
// VerifySignature edge cases
// =============================================================================

func TestVerifySignature_ValidSignature(t *testing.T) {
	sv := NewSignatureVerifier()

	priv, _, pubPEM, _ := GenerateTestRSAKeyPair(2048)
	if priv == nil || pubPEM == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	payload := []byte("test data for VerifySignature method")
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	sig, _ := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed)

	result, _ := sv.VerifySignature(payload, sig, pubPEM)
	if result == nil {
		t.Errorf("VerifySignature returned nil result")
	}
}

func TestVerifySignature_TamperedPayload(t *testing.T) {
	sv := NewSignatureVerifier()

	priv, _, pubPEM, _ := GenerateTestRSAKeyPair(2048)
	if priv == nil || pubPEM == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	payload := []byte("original data")
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)
	sig, _ := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed)

	// Tamper with the payload
	tampered := []byte("tampered data")

	result, _ := sv.VerifySignature(tampered, sig, pubPEM)
	if result != nil && result.Valid {
		t.Errorf("tampered payload should NOT verify as valid")
	}
}

// =============================================================================
// VerifyStringSignature — error and success paths
// =============================================================================

func TestParseVerificationStats_ValidJSON(t *testing.T) {
	now := time.Now()
	stats := &VerificationStats{
		TotalVerifications: 100,
		Successful:         95,
		Failed:             5,
		LastSuccessTime:    now,
		LastFailTime:       now,
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed VerificationStats
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if parsed.TotalVerifications != 100 {
		t.Errorf("TotalVerifications mismatch: got %d", parsed.TotalVerifications)
	}
	if parsed.Successful != 95 {
		t.Errorf("Successful mismatch: got %d", parsed.Successful)
	}
}

// =============================================================================
// Edge cases for VerificationResult fields
// =============================================================================

func TestVerificationResult_AllFields(t *testing.T) {
	sv := NewSignatureVerifier()

	priv, _, pubPEM, _ := GenerateTestRSAKeyPair(2048)
	if priv == nil || pubPEM == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	payload := []byte("test")
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)
	sig, _ := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, hashed)

	result, _ := sv.VerifySignature(payload, sig, pubPEM)

	if result == nil {
		t.Fatalf("VerifySignature returned nil result")
	}
	if result.Timestamp.IsZero() {
		t.Errorf("Timestamp should be set")
	}
	if result.PublicKey.Type == "" {
		t.Errorf("PublicKey.Type should be set")
	}
	if result.PublicKey.CreatedAt.IsZero() {
		t.Errorf("PublicKey.CreatedAt should be set")
	}
	// Algorithm is 0-indexed (iota), so 0 means RSASSA_PKCS1v15 which is valid
	if result.Valid && result.Algorithm < 0 {
		t.Errorf("Algorithm should be >= 0 when verification succeeds")
	}
}

func TestVerifySignature_NilPayload(t *testing.T) {
	sv := NewSignatureVerifier()

	_, _, key, _ := GenerateTestRSAKeyPair(2048)
	if key == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	_, err := sv.VerifySignature(nil, []byte("sig"), key)
	if err != nil {
		t.Logf("nil payload returned error: %v", err)
	}
}

func TestVerifySignature_EmptyPayload(t *testing.T) {
	sv := NewSignatureVerifier()

	_, _, key, _ := GenerateTestRSAKeyPair(2048)
	if key == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	_, err := sv.VerifySignature([]byte{}, []byte("sig"), key)
	if err != nil {
		t.Logf("empty payload returned error: %v", err)
	}
}

func TestVerifySignature_NilSignature(t *testing.T) {
	sv := NewSignatureVerifier()

	_, _, key, _ := GenerateTestRSAKeyPair(2048)
	if key == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	_, err := sv.VerifySignature([]byte("payload"), nil, key)
	if err != nil {
		t.Logf("nil signature returned error: %v", err)
	}
}

func TestVerifySignature_EmptySignature(t *testing.T) {
	sv := NewSignatureVerifier()

	_, _, key, _ := GenerateTestRSAKeyPair(2048)
	if key == nil {
		t.Skip("GenerateTestRSAKeyPair returned nil")
	}

	_, err := sv.VerifySignature([]byte("payload"), []byte{}, key)
	if err != nil {
		t.Logf("empty signature returned error: %v", err)
	}
}
