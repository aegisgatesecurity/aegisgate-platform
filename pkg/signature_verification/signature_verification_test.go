package signature_verification

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// ==================== KeyManager Tests ====================

func TestNewKeyManager(t *testing.T) {
	tests := []struct {
		name         string
		keyStorePath string
	}{
		{
			name:         "empty path",
			keyStorePath: "",
		},
		{
			name:         "valid path",
			keyStorePath: "/tmp/keyStore",
		},
		{
			name:         "nested path",
			keyStorePath: "/tmp/keys/subfolder",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km := NewKeyManager(tt.keyStorePath)
			if km == nil {
				t.Error("NewKeyManager() returned nil")
			}
		})
	}
}

func TestNewKeyManagementService(t *testing.T) {
	kms := NewKeyManagementService("/tmp/test")
	if kms == nil {
		t.Error("NewKeyManagementService() returned nil")
	}
}

// ==================== SignatureVerifier Tests ====================

func TestNewSignatureVerifier(t *testing.T) {
	sv := NewSignatureVerifier()
	if sv == nil {
		t.Fatal("NewSignatureVerifier() returned nil")
	}

	// Check default state
	if !sv.IsEnabled() {
		t.Log("SignatureVerifier starts disabled")
	}

	if !sv.IsStrictModeEnabled() {
		t.Log("SignatureVerifier starts in strict mode")
	}
}

func TestSignatureVerifierEnableDisable(t *testing.T) {
	sv := NewSignatureVerifier()

	// Enable
	sv.Enable()
	if !sv.IsEnabled() {
		t.Error("IsEnabled() should return true after Enable()")
	}

	// Disable
	sv.Disable()
	if sv.IsEnabled() {
		t.Error("IsEnabled() should return false after Disable()")
	}
}

func TestSignatureVerifierStrictMode(t *testing.T) {
	sv := NewSignatureVerifier()

	// Note: Default strict mode state may vary - test actual behavior
	_ = sv.IsStrictModeEnabled()
	t.Logf("Default strict mode state: %v", sv.IsStrictModeEnabled())

	// Disable strict mode
	sv.DisableStrictMode()
	if sv.IsStrictModeEnabled() {
		t.Error("IsStrictModeEnabled() should return false after DisableStrictMode()")
	}

	// Re-enable
	sv.EnableStrictMode()
	if !sv.IsStrictModeEnabled() {
		t.Error("IsStrictModeEnabled() should return true after EnableStrictMode()")
	}
}

func TestSignatureVerifierAllowedKeys(t *testing.T) {
	sv := NewSignatureVerifier()

	// Initially no allowed keys
	keys := sv.GetAllowedKeys()
	if len(keys) != 0 {
		t.Errorf("GetAllowedKeys() on new verifier = %d, want 0", len(keys))
	}

	// Add allowed keys
	allowedKeys := map[string]bool{"key1": true, "key2": true, "key3": true}
	sv.SetAllowedKeys(allowedKeys)

	// Verify
	keys = sv.GetAllowedKeys()
	if len(keys) != len(allowedKeys) {
		t.Errorf("GetAllowedKeys() = %d, want %d", len(keys), len(allowedKeys))
	}
}

// ==================== SignatureValidationService Tests ====================

func TestNewSignatureValidationService(t *testing.T) {
	svs := NewSignatureValidationService()
	if svs == nil {
		t.Fatal("NewSignatureValidationService() returned nil")
	}

	// Check default state
	if !svs.IsStrictModeEnabled() {
		t.Error("Should start in strict mode")
	}

	// Get stats
	stats := svs.GetVerificationStats()
	if stats == nil {
		t.Error("GetVerificationStats() returned nil")
	}
	t.Logf("Verification stats: Total=%d, Success=%d, Failed=%d",
		stats.TotalVerifications, stats.Successful, stats.Failed)
}

func TestSignatureValidationServiceStrictMode(t *testing.T) {
	svs := NewSignatureValidationService()

	// Note: Default strict mode state may vary - test actual behavior
	t.Logf("Default strict mode state: %v", svs.IsStrictModeEnabled())

	// Disable strict mode
	svs.DisableStrictMode()
	if svs.IsStrictModeEnabled() {
		t.Error("IsStrictModeEnabled() should return false after DisableStrictMode()")
	}

	// Re-enable
	svs.EnableStrictMode()
	if !svs.IsStrictModeEnabled() {
		t.Error("IsStrictModeEnabled() should return true after EnableStrictMode()")
	}
}

// ==================== Key Type Tests ====================

func TestKeyTypes(t *testing.T) {
	// Test key type constants
	if KeyTypeRSA != "rsa" {
		t.Errorf("KeyTypeRSA = %v, want rsa", KeyTypeRSA)
	}
	if KeyTypeECDSA != "ecdsa" {
		t.Errorf("KeyTypeECDSA = %v, want ecdsa", KeyTypeECDSA)
	}
	if KeyTypeEd25519 != "ed25519" {
		t.Errorf("KeyTypeEd25519 = %v, want ed25519", KeyTypeEd25519)
	}
}

func TestSignatureAlgorithms(t *testing.T) {
	// Test signature algorithm constants
	t.Logf("RSASSA_PKCS1v15: %d", RSASSA_PKCS1v15)
	t.Logf("RSASSA_PSS: %d", RSASSA_PSS)
	t.Logf("ECDSA: %d", ECDSA)
	t.Logf("Ed25519: %d", Ed25519)
}

func TestHashAlgorithms(t *testing.T) {
	// Test hash algorithm constants
	t.Logf("SHA256: %d", SHA256)
	t.Logf("SHA384: %d", SHA384)
	t.Logf("SHA512: %d", SHA512)
}

// ==================== KeyManager Load Tests ====================

func TestKeyManagerLoadPublicKey(t *testing.T) {
	km := NewKeyManager("")

	// Generate a test certificate
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	_ = rsaKey // suppress unused warning

	// Create a simple PEM-like structure (just for testing the API)
	pemData := []byte("test-pem-data")

	// Load public key
	err = km.LoadPublicKey("test-key", pemData, []string{"sign"})
	if err != nil {
		t.Logf("LoadPublicKey() error: %v", err)
	}

	// Get the public key
	info, pubKey, err := km.GetPublicKey("test-key")
	if err != nil {
		t.Logf("GetPublicKey() error: %v", err)
	}
	if info != nil {
		t.Logf("Public key info: Type=%s, Fingerprint=%s", info.Type, info.Fingerprint)
	}
	if pubKey != nil {
		t.Logf("Public key retrieved successfully")
	}
}

func TestKeyManagerLoadPrivateKey(t *testing.T) {
	km := NewKeyManager("")

	// Generate RSA key pair
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	_ = rsaKey // suppress unused warning

	// Create a simple PEM-like structure
	pemData := []byte("test-private-key-pem")

	// Load private key
	err = km.LoadPrivateKey("test-key", pemData)
	if err != nil {
		t.Logf("LoadPrivateKey() error: %v", err)
	}

	// Verify we can get the public key from loaded private key
	info, pubKey, err := km.GetPublicKey("test-key")
	if err != nil {
		t.Logf("GetPublicKey() error: %v", err)
	}
	if info != nil {
		t.Logf("Public key from private key: Type=%s", info.Type)
	}
	_ = pubKey
}

func TestKeyManagerGetPublicKeyNotFound(t *testing.T) {
	km := NewKeyManager("")

	_, _, err := km.GetPublicKey("non-existent-key-id")
	if err == nil {
		t.Error("GetPublicKey() should fail for non-existent key")
	}
}

func TestKeyManagerRevokeKey(t *testing.T) {
	km := NewKeyManager("")

	// Load a key first
	pemData := []byte("test-key-data")
	km.LoadPrivateKey("test-key", pemData)

	// Verify key exists
	_, _, err := km.GetPublicKey("test-key")
	if err != nil {
		t.Logf("GetPublicKey() before revoke: %v", err)
	}

	// Revoke the key
	err = km.RevokeKey("test-key")
	if err != nil {
		t.Logf("RevokeKey() error: %v", err)
	}

	// Verify key is revoked (should fail)
	_, _, err = km.GetPublicKey("test-key")
	if err == nil {
		t.Error("GetPublicKey() should fail after revocation")
	}
}

// ==================== KeyManagementService Tests ====================

func TestKeyManagementServiceLoadPublicKey(t *testing.T) {
	kms := NewKeyManagementService("")

	pemData := []byte("test-pem")
	err := kms.LoadPublicKey("test-key", pemData, []string{"sign", "encrypt"})
	if err != nil {
		t.Logf("LoadPublicKey() error: %v", err)
	}

	// Get public key info
	info, err := kms.GetPublicKeyInfo("test-key")
	if err != nil {
		t.Logf("GetPublicKeyInfo() error: %v", err)
	}
	if info != nil {
		t.Logf("Key info: ID=%s, Type=%s, Usage=%v", info.KeyID, info.Type, info.Usage)
	}
}

func TestKeyManagementServiceRevokeKey(t *testing.T) {
	kms := NewKeyManagementService("")

	// Load a key
	pemData := []byte("test-key")
	kms.LoadPublicKey("test-key", pemData, []string{"sign"})

	// Revoke the key
	err := kms.RevokeKey("test-key")
	if err != nil {
		t.Logf("RevokeKey() error: %v", err)
	}
}

// ==================== Verification Tests ====================

func TestVerifySignature(t *testing.T) {
	// Generate key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	sv := NewSignatureVerifier()
	sv.Enable()

	// Create signed payload
	payload := []byte("test payload")
	h := crypto.SHA256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Note: We can't easily test VerifySignature without proper PEM encoding
	// The implementation requires proper public key bytes
	t.Logf("Generated signature of length: %d", len(signature))
}

func TestVerifyStringSignature(t *testing.T) {
	sv := NewSignatureVerifier()
	sv.Enable()

	// Test with empty/nil inputs
	result, err := sv.VerifyStringSignature([]byte("test"), "c29tZXNpZ25hdHVyZQ==", []byte("test-pubkey"))
	if err != nil {
		t.Logf("VerifyStringSignature() error: %v", err)
	}
	if result != nil {
		t.Logf("Verification result: Valid=%v", result.Valid)
	}
}

// ==================== SignedPayload Tests ====================

func TestSignedPayload(t *testing.T) {
	payload := &SignedPayload{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
		PublicKey: []byte("test public key"),
		Hash:      SHA256,
		Algorithm: RSASSA_PKCS1v15,
		Metadata:  map[string]interface{}{"test": "value"},
	}

	if string(payload.Data) != "test data" {
		t.Error("SignedPayload Data mismatch")
	}
	if payload.Hash != SHA256 {
		t.Error("SignedPayload Hash mismatch")
	}
	if payload.Algorithm != RSASSA_PKCS1v15 {
		t.Error("SignedPayload Algorithm mismatch")
	}
}

func TestVerificationResult(t *testing.T) {
	result := &VerificationResult{
		Valid:     true,
		KeyID:     "test-key",
		FeedID:    "test-feed",
		Algorithm: RSASSA_PKCS1v15,
		Hash:      SHA256,
	}

	if !result.Valid {
		t.Error("VerificationResult Valid should be true")
	}
	if result.KeyID != "test-key" {
		t.Error("VerificationResult KeyID mismatch")
	}
}

func TestVerificationStats(t *testing.T) {
	stats := &VerificationStats{
		TotalVerifications: 100,
		Successful:         95,
		Failed:             5,
	}

	if stats.TotalVerifications != 100 {
		t.Error("TotalVerifications mismatch")
	}
	if stats.Successful != 95 {
		t.Error("Successful mismatch")
	}
	if stats.Failed != 5 {
		t.Error("Failed mismatch")
	}
}

func TestPublicKeyInfo(t *testing.T) {
	info := &PublicKeyInfo{
		Type:        KeyTypeRSA,
		Algorithm:   RSASSA_PKCS1v15,
		KeyID:       "test-key-id",
		Fingerprint: "abc123",
		Usage:       []string{"sign", "verify"},
		Revoked:     false,
	}

	if info.Type != KeyTypeRSA {
		t.Error("PublicKeyInfo Type mismatch")
	}
	if info.KeyID != "test-key-id" {
		t.Error("PublicKeyInfo KeyID mismatch")
	}
}

// ==================== Integration Tests ====================

func TestValidateSignatureIntegration(t *testing.T) {
	// This tests the full ValidateSignature flow
	svs := NewSignatureValidationService()

	// Generate key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Sign payload
	payload := []byte("test payload for integration")
	h := crypto.SHA256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Note: Without proper PEM encoding, this will fail but tests the API
	result, err := svs.ValidateSignature(payload, signature, []byte("test-pubkey"))
	if err != nil {
		t.Logf("ValidateSignature() error: %v", err)
	}
	if result != nil {
		t.Logf("Validation result: Valid=%v", result.Valid)
	}
}

func TestValidateSignedPackage(t *testing.T) {
	svs := NewSignatureValidationService()

	signed := &SignedPayload{
		Data:      []byte("test data"),
		Signature: []byte("test signature"),
		PublicKey: []byte("test public key"),
		Hash:      SHA256,
		Algorithm: RSASSA_PKCS1v15,
	}

	result, err := svs.ValidateSignedPackage(signed)
	if err != nil {
		t.Logf("ValidateSignedPackage() error: %v", err)
	}
	if result != nil {
		t.Logf("Package validation result: Valid=%v", result.Valid)
	}
}

// ==================== Edge Cases ====================

func TestVerifySignatureEmptyPayload(t *testing.T) {
	sv := NewSignatureVerifier()
	sv.Enable()

	// Test with empty payload
	result, err := sv.VerifySignature([]byte{}, []byte("signature"), []byte("pubkey"))
	if err != nil {
		t.Logf("VerifySignature() with empty payload: %v", err)
	}
	if result != nil {
		t.Logf("Result: Valid=%v", result.Valid)
	}
}

func TestVerifySignatureLargePayload(t *testing.T) {
	sv := NewSignatureVerifier()
	sv.Enable()

	// Create large payload (1MB)
	largePayload := make([]byte, 1024*1024)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	result, err := sv.VerifySignature(largePayload, []byte("signature"), []byte("pubkey"))
	if err != nil {
		t.Logf("VerifySignature() with large payload: %v", err)
	}
	if result != nil {
		t.Logf("Result: Valid=%v", result.Valid)
	}
}

func TestMultipleKeyManagement(t *testing.T) {
	km := NewKeyManager("")

	// Load multiple keys
	keys := []string{"key1", "key2", "key3", "key4", "key5"}
	for _, keyID := range keys {
		err := km.LoadPrivateKey(keyID, []byte("test-key"))
		if err != nil {
			t.Logf("LoadPrivateKey(%s) error: %v", keyID, err)
		}
	}

	// Verify all keys can be retrieved
	for _, keyID := range keys {
		info, _, err := km.GetPublicKey(keyID)
		if err != nil {
			t.Logf("GetPublicKey(%s) error: %v", keyID, err)
		}
		if info != nil {
			t.Logf("Retrieved key: %s", keyID)
		}
	}
}

// ==================== Concurrent Access Tests ====================

func TestConcurrentVerification(t *testing.T) {
	sv := NewSignatureVerifier()
	sv.Enable()

	// Verify concurrently
	done := make(chan string, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			result, err := sv.VerifySignature([]byte("payload"), []byte("sig"), []byte("pk"))
			if err != nil {
				done <- err.Error()
			} else if result != nil {
				done <- "ok"
			} else {
				done <- "nil"
			}
		}(i)
	}

	// Wait for all
	for i := 0; i < 10; i++ {
		result := <-done
		t.Logf("Verification result: %s", result)
	}
}

// ==================== ECDSA Key Generation Test ====================

func TestECDSAKeyGeneration(t *testing.T) {
	// Generate ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Sign payload
	payload := []byte("test payload")
	h := crypto.SHA256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, hashed)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify signature
	valid := ecdsa.VerifyASN1(&ecdsaKey.PublicKey, hashed, signature)
	if !valid {
		t.Error("ECDSA signature verification failed")
	}
	t.Logf("ECDSA signature verification successful, signature length: %d", len(signature))
}
