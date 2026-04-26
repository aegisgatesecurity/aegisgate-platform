// SPDX-License-Identifier: Apache-2.0

package signature_verification

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestSignatureValidationService tests the SignatureValidationService
func TestSignatureValidationService(t *testing.T) {
	svc := NewSignatureValidationService()

	t.Run("EnableStrictMode", func(t *testing.T) {
		svc.EnableStrictMode()
		if !svc.IsStrictModeEnabled() {
			t.Error("IsStrictModeEnabled should return true after EnableStrictMode")
		}
	})

	t.Run("DisableStrictMode", func(t *testing.T) {
		svc.DisableStrictMode()
		if svc.IsStrictModeEnabled() {
			t.Error("IsStrictModeEnabled should return false after DisableStrictMode")
		}
	})

	t.Run("GetVerificationStats", func(t *testing.T) {
		stats := svc.GetVerificationStats()
		if stats == nil {
			t.Error("GetVerificationStats should not return nil")
		}
	})
}

// TestKeyManagementService tests the KeyManagementService
func TestKeyManagementService(t *testing.T) {
	// Create a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert to PEM format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	t.Run("LoadPublicKey", func(t *testing.T) {
		svc := NewKeyManagementService("/tmp/test-keystore")
		err := svc.LoadPublicKey("test-key-1", pubKeyPEM, []string{"verify"})
		if err != nil {
			t.Errorf("LoadPublicKey failed: %v", err)
		}
	})

	t.Run("GetPublicKeyInfo", func(t *testing.T) {
		svc := NewKeyManagementService("/tmp/test-keystore")
		_ = svc.LoadPublicKey("test-key-2", pubKeyPEM, []string{"verify"})
		info, err := svc.GetPublicKeyInfo("test-key-2")
		if err != nil {
			t.Errorf("GetPublicKeyInfo failed: %v", err)
		}
		if info.Type != "rsa" {
			t.Errorf("Expected RSA type, got %s", info.Type)
		}
	})

	t.Run("RevokeKey", func(t *testing.T) {
		svc := NewKeyManagementService("/tmp/test-keystore")
		_ = svc.LoadPublicKey("test-key-3", pubKeyPEM, []string{"verify"})
		err := svc.RevokeKey("test-key-3")
		if err != nil {
			t.Errorf("RevokeKey failed: %v", err)
		}
	})
}

// TestValidateSignature tests signature validation
func TestValidateSignature(t *testing.T) {
	svc := NewSignatureValidationService()

	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Marshal and load public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Load key into verifier
	err = svc.verifier.keyManager.LoadPublicKey("test-key", pubKeyPEM, []string{"verify"})
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	t.Run("Invalid Signature", func(t *testing.T) {
		_, err := svc.ValidateSignature([]byte("test"), []byte("invalid"), pubKeyPEM)
		if err == nil {
			t.Error("Expected error for invalid signature")
		}
	})

	t.Run("Empty Payload", func(t *testing.T) {
		_, err := svc.ValidateSignature([]byte(""), []byte("sig"), pubKeyPEM)
		if err == nil {
			t.Error("Expected error for empty payload")
		}
	})
}

// TestValidateSignatureWithEd25519 tests signature validation with Ed25519 keys
func TestValidateSignatureWithEd25519(t *testing.T) {
	svc := NewSignatureValidationService()

	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Skip("Ed25519 not available: ", err)
	}

	// Marshal and load public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Load key into verifier
	err = svc.verifier.keyManager.LoadPublicKey("ed25519-test", pubKeyPEM, []string{"verify"})
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	// Sign with Ed25519
	message := []byte("test message for ed25519")
	signature := ed25519.Sign(privKey, message)

	// Verify via exported method - this exercises verifyEd25519Signature internally
	result, err := svc.ValidateSignature(message, signature, pubKeyPEM)
	if err != nil {
		t.Errorf("Ed25519 signature verification failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result is nil")
	}
	if !result.Valid {
		t.Error("Ed25519 signature should be valid")
	}

	// Test with wrong message
	wrongResult, _ := svc.ValidateSignature([]byte("wrong message"), signature, pubKeyPEM)
	if wrongResult == nil {
		t.Fatal("Wrong result is nil")
	}
	if wrongResult.Valid {
		t.Error("Signature with wrong message should be invalid")
	}
}

// TestKeyManager tests the KeyManager
func TestKeyManager(t *testing.T) {
	km := NewKeyManager("/tmp/test-keys")

	// Generate and load a key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	t.Run("LoadPrivateKey", func(t *testing.T) {
		privPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
		err := km.LoadPrivateKey("priv-key", privPEM)
		if err != nil {
			t.Errorf("LoadPrivateKey failed: %v", err)
		}
	})

	t.Run("LoadPublicKey and GetPublicKey", func(t *testing.T) {
		err := km.LoadPublicKey("pub-key", pubKeyPEM, []string{"verify"})
		if err != nil {
			t.Errorf("LoadPublicKey failed: %v", err)
		}

		info, _, err := km.GetPublicKey("pub-key")
		if err != nil {
			t.Errorf("GetPublicKey failed: %v", err)
		}
		if info.Type != "rsa" {
			t.Errorf("Expected RSA type, got %s", info.Type)
		}
	})
}

// TestDetectKeyType tests the detectKeyType helper
func TestDetectKeyType(t *testing.T) {
	// Generate RSA key
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPubBytes, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPubBytes})

	km := NewKeyManager("/tmp/test")
	_ = km.LoadPublicKey("rsa", rsaPEM, []string{"verify"})
	info, _, _ := km.GetPublicKey("rsa")
	if info.Type != "rsa" {
		t.Errorf("Expected RSA, got %s", info.Type)
	}

	// Generate ECDSA key
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaPubBytes, _ := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecdsaPubBytes})

	_ = km.LoadPublicKey("ecdsa", ecdsaPEM, []string{"verify"})
	ecdsaInfo, _, _ := km.GetPublicKey("ecdsa")
	if ecdsaInfo.Type != "ecdsa" {
		t.Errorf("Expected ECDSA, got %s", ecdsaInfo.Type)
	}
}

// TestLoadPublicKeyErrors tests error paths for LoadPublicKey
func TestLoadPublicKeyErrors(t *testing.T) {
	svc := NewSignatureValidationService()
	km := svc.verifier.keyManager

	tests := []struct {
		name      string
		keyPEM    []byte
		expectErr bool
	}{
		{
			name:      "invalid PEM data",
			keyPEM:    []byte("not valid pem"),
			expectErr: true,
		},
		{
			name:      "unsupported key type",
			keyPEM:    pem.EncodeToMemory(&pem.Block{Type: "UNSUPPORTED KEY", Bytes: []byte("data")}),
			expectErr: true,
		},
		{
			name:      "corrupted PKIX public key",
			keyPEM:    pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("corrupted")}),
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := km.LoadPublicKey(tc.name, tc.keyPEM, []string{"verify"})
			if tc.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestLoadPrivateKeyErrors tests error paths for LoadPrivateKey
func TestLoadPrivateKeyErrors(t *testing.T) {
	svc := NewSignatureValidationService()
	km := svc.verifier.keyManager

	tests := []struct {
		name      string
		keyPEM    []byte
		expectErr bool
	}{
		{
			name:      "invalid PEM data",
			keyPEM:    []byte("not valid pem"),
			expectErr: true,
		},
		{
			name:      "unsupported key type",
			keyPEM:    pem.EncodeToMemory(&pem.Block{Type: "UNSUPPORTED KEY", Bytes: []byte("data")}),
			expectErr: true,
		},
		{
			name:      "corrupted PKCS8 private key",
			keyPEM:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("corrupted")}),
			expectErr: true,
		},
		{
			name:      "corrupted RSA private key",
			keyPEM:    pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("corrupted")}),
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := km.LoadPrivateKey(tc.name, tc.keyPEM)
			if tc.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestVerifySignatureWithValidRSA tests RSA signature verification with valid signatures
func TestVerifySignatureWithValidRSA(t *testing.T) {
	svc := NewSignatureValidationService()
	verifier := svc.verifier

	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Marshal and load public key
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	err = verifier.keyManager.LoadPublicKey("rsa-valid", pubKeyPEM, []string{"verify"})
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	// Create and sign a message
	message := []byte("test message for RSA verification")
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify signature
	result, err := verifier.VerifySignature(message, signature, pubKeyPEM)
	if err != nil {
		t.Errorf("VerifySignature failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result is nil")
	}
	if !result.Valid {
		t.Error("Valid RSA signature should verify")
	}
}

// TestVerifySignatureWithValidECDSA tests ECDSA signature verification
func TestVerifySignatureWithValidECDSA(t *testing.T) {
	svc := NewSignatureValidationService()
	verifier := svc.verifier

	// Generate ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Marshal and load public key
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	err = verifier.keyManager.LoadPublicKey("ecdsa-valid", pubKeyPEM, []string{"verify"})
	if err != nil {
		t.Fatalf("Failed to load key: %v", err)
	}

	// Create and sign a message
	message := []byte("test message for ECDSA verification")
	hashed := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, hashed[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify signature
	result, err := verifier.VerifySignature(message, signature, pubKeyPEM)
	if err != nil {
		t.Errorf("VerifySignature failed: %v", err)
	}
	if result == nil {
		t.Fatal("Result is nil")
	}
	if !result.Valid {
		t.Error("Valid ECDSA signature should verify")
	}
}

// TestVerifySignatureWithInvalidKeys tests error paths
func TestVerifySignatureWithInvalidKeys(t *testing.T) {
	svc := NewSignatureValidationService()
	verifier := svc.verifier

	tests := []struct {
		name    string
		pubKey  []byte
		message []byte
		sig     []byte
	}{
		{
			name:    "corrupted public key",
			pubKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("corrupted")}),
			message: []byte("test"),
			sig:     []byte("sig"),
		},
		{
			name:    "nil public key",
			pubKey:  nil,
			message: []byte("test"),
			sig:     []byte("sig"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := verifier.VerifySignature(tc.message, tc.sig, tc.pubKey)
			if err == nil && result != nil && result.Valid {
				t.Error("Should fail for invalid keys")
			}
		})
	}
}

func mustMarshalPKIX(key interface{}) []byte {
	bytes, _ := x509.MarshalPKIXPublicKey(key)
	return bytes
}
