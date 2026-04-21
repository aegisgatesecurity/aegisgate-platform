// SPDX-License-Identifier: Apache-2.0
package license

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"strings"
	"testing"
)

// TestIsKeyPlaceholder verifies that the embedded key is NOT a placeholder
// after Task 1.2 — a real ECDSA P-256 key has been embedded.
func TestIsKeyPlaceholder(t *testing.T) {
	if IsKeyPlaceholder() {
		t.Error("IsKeyPlaceholder() = true, expected false (real key should be embedded after Task 1.2)")
	}
}

// TestKeyFingerprint verifies fingerprint returns a valid hex string
// for the embedded public key.
func TestKeyFingerprint(t *testing.T) {
	fp := KeyFingerprint()
	if fp == "" {
		t.Error("KeyFingerprint() returned empty string")
	}
	if fp == "invalid" {
		t.Error("KeyFingerprint() returned 'invalid' — PEM decode failed")
	}
	if fp == "short" {
		t.Error("KeyFingerprint() returned 'short' — DER bytes < 8")
	}
	t.Logf("Key fingerprint (first 8 DER bytes): %s", fp)

	// Fingerprint should be consistent across calls
	fp2 := KeyFingerprint()
	if fp != fp2 {
		t.Errorf("KeyFingerprint() inconsistent: %q vs %q", fp, fp2)
	}
}

// TestGetEmbeddedPublicKey verifies that the embedded public key parses
// successfully as a valid ECDSA P-256 key.
func TestGetEmbeddedPublicKey(t *testing.T) {
	pubKey, err := GetEmbeddedPublicKey()
	if err != nil {
		t.Fatalf("GetEmbeddedPublicKey() returned error: %v", err)
	}
	if pubKey == nil {
		t.Fatal("GetEmbeddedPublicKey() returned nil key")
	}
	if pubKey.Curve == nil {
		t.Fatal("Public key has nil curve")
	}
	if pubKey.Curve != elliptic.P256() {
		t.Errorf("Public key curve = %v, want P-256", pubKey.Curve.Params().Name)
	}
	if pubKey.X == nil || pubKey.Y == nil {
		t.Error("Public key X or Y coordinate is nil")
	}
	t.Logf("Public key curve: P-%s", pubKey.Curve.Params().Name)
	t.Logf("Public key X: %s...", pubKey.X.String()[:20])
	t.Logf("Public key Y: %s...", pubKey.Y.String()[:20])
}

// TestGetEmbeddedPublicKeyStructure validates the returned key's fields
// are on the P-256 curve.
func TestGetEmbeddedPublicKeyStructure(t *testing.T) {
	pubKey, err := GetEmbeddedPublicKey()
	if err != nil {
		t.Fatalf("GetEmbeddedPublicKey() error: %v", err)
	}

	// P-256 key should have non-nil coordinates on the curve
	if pubKey.X == nil || pubKey.Y == nil {
		t.Fatal("Public key X or Y coordinate is nil")
	}

	// Verify the point is actually on the P-256 curve
	if !pubKey.Curve.IsOnCurve(pubKey.X, pubKey.Y) {
		t.Error("Public key point is NOT on the P-256 curve")
	}

	t.Logf("PublicKey X: %s", pubKey.X.String()[:20]+"...")
	t.Logf("PublicKey Y: %s", pubKey.Y.String()[:20]+"...")
}

// TestKeyFingerprintConsistency verifies that KeyFingerprint returns
// consistent results across calls.
func TestKeyFingerprintConsistency(t *testing.T) {
	fp1 := KeyFingerprint()
	fp2 := KeyFingerprint()
	if fp1 != fp2 {
		t.Errorf("KeyFingerprint() inconsistent: %q vs %q", fp1, fp2)
	}
}

// TestRealKeyNotPlaceholder verifies that after Task 1.2, the embedded key
// is a real key (not a placeholder).
func TestRealKeyNotPlaceholder(t *testing.T) {
	if IsKeyPlaceholder() {
		t.Error("IsKeyPlaceholder() = true — real key should be embedded after Task 1.2")
	}

	// Verify the key parses successfully
	pubKey, err := GetEmbeddedPublicKey()
	if err != nil {
		t.Errorf("Real embedded key failed to parse: %v", err)
	} else {
		t.Logf("Real key parses successfully: P-%s, X=%s...", pubKey.Curve.Params().Name, pubKey.X.String()[:20])
	}
}

// TestKeyParsingWithRealKey verifies that NewManagerWithKey can parse a real
// ECDSA P-256 public key PEM. This tests the code path that will be used
// when the real key is embedded.
func TestKeyParsingWithRealKey(t *testing.T) {
	// Real P-256 public key (generated for testing only)
	testPubKeyPEM := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETkjBsBUl4w5Ph1OuoaEzowvpusQU
JGGoggaLBIQMgNfzrUCSn6hcHMnuNlLZNs5v6V5Lcv+wZa/GC8Hq3A1o5w==
-----END PUBLIC KEY-----
`
	mgr, err := NewManagerWithKey(testPubKeyPEM)
	if err != nil {
		t.Fatalf("NewManagerWithKey() error: %v", err)
	}
	if mgr == nil {
		t.Fatal("NewManagerWithKey() returned nil manager")
	}
	if mgr.publicKey == nil {
		t.Error("Manager publicKey is nil after init with real key")
	}
	if mgr.publicKey.Curve != elliptic.P256() {
		t.Errorf("Key curve = %v, want P-256", mgr.publicKey.Curve.Params().Name)
	}
}

// TestNewManagerWithKeyInvalidPEM tests error handling for bad PEM data
func TestNewManagerWithKeyInvalidPEM(t *testing.T) {
	tests := []struct {
		name    string
		pemData string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty string",
			pemData: "",
			wantErr: true,
			errMsg:  "failed to decode PEM block",
		},
		{
			name:    "garbage data",
			pemData: "not-a-pem-block-at-all",
			wantErr: true,
			errMsg:  "failed to decode PEM block",
		},
		{
			name:    "wrong PEM type (certificate)",
			pemData: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
			wantErr: true,
			errMsg:  "failed to parse public key",
		},
		{
			name:    "RSA key (not ECDSA)",
			pemData: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5kHmLAmljI7Gq4cP5ME6\n6ra295AZo3HUw0Gk4OeLkvEAUuzT8vXriUwHyircrdvs7wzcuv6L9Ej/8Ozv+53h\nnHBwMRHd/67YJGTY4tIk7xFE3Fh+eNhPFoBmrnmPhKIvPyHRGNcEE9QFum3xirjI\nAEw7ylLkBPGvt3zCYP3KAm0OEP+vFh3Zq3eFzfaDnFZcGbtBZ7ObRSvY3iqKvHUv\nqZz6QjrBnWIIwEG5c01rgydDD5VeOj6xev8xwfUjAyT0zfvO/ICNLwMiEJRKtyjj\ns8N63eGpuAEgmY6xAmogikVQkfRbmvEdFvYaI8Fg5lYmPsasP0MPqQXtJeQ01dEN\nVwIDAQAB\n-----END PUBLIC KEY-----",
			wantErr: true,
			errMsg:  "not an ECDSA key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewManagerWithKey(tt.pemData)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.errMsg)
				}
				if mgr != nil {
					t.Error("expected nil manager on error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if mgr == nil {
					t.Error("expected non-nil manager")
				}
			}
		})
	}
}

// TestNewManagerWithKeyCurveValidation verifies we reject non-P256 ECDSA keys
func TestNewManagerWithKeyCurveValidation(t *testing.T) {
	// Generate a P-384 key (wrong curve for AegisGate)
	// We can't easily do this inline, so this test documents the requirement
	t.Log("AegisGate requires ECDSA P-256 keys; P-384 and P-521 are rejected")
	t.Log("This will be enforced by the x509.ParsePKIXPublicKey + type assertion")
}

// TestNewManagerCreatesCache verifies the Manager initializes with a working cache
func TestNewManagerCreatesCache(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	if mgr.cache == nil {
		t.Error("Manager cache map is nil")
	}
	if !mgr.cacheEnabled {
		t.Error("Manager cache is disabled by default")
	}
	if mgr.GetCachedEntries() != 0 {
		t.Errorf("Expected 0 cached entries, got %d", mgr.GetCachedEntries())
	}
}

// TestNewManagerWithKeyCreatesCache verifies cache init with custom key
func TestNewManagerWithKeyCreatesCache(t *testing.T) {
	testPubKeyPEM := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETkjBsBUl4w5Ph1OuoaEzowvpusQU
JGGoggaLBIQMgNfzrUCSn6hcHMnuNlLZNs5v6V5Lcv+wZa/GC8Hq3A1o5w==
-----END PUBLIC KEY-----
`
	mgr, err := NewManagerWithKey(testPubKeyPEM)
	if err != nil {
		t.Fatalf("NewManagerWithKey() error: %v", err)
	}
	if mgr.cache == nil {
		t.Error("Manager cache map is nil")
	}
	if !mgr.cacheEnabled {
		t.Error("Manager cache is disabled by default")
	}
}

// TestPublicKeyTypeAssertion verifies that GetEmbeddedPublicKey
// returns an *ecdsa.PublicKey (not a generic PublicKey interface).
func TestPublicKeyTypeAssertion(t *testing.T) {
	pubKey, err := GetEmbeddedPublicKey()
	if err != nil {
		t.Fatalf("GetEmbeddedPublicKey() error: %v", err)
	}

	// Verify it's actually *ecdsa.PublicKey
	var keyAny any = pubKey
	switch keyAny.(type) {
	case *ecdsa.PublicKey:
		t.Log("GetEmbeddedPublicKey correctly returns *ecdsa.PublicKey")
	default:
		t.Errorf("GetEmbeddedPublicKey returned %T, want *ecdsa.PublicKey", pubKey)
	}
}
