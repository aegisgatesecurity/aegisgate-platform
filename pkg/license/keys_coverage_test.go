// SPDX-License-Identifier: Apache-2.0
//go:build !race

package license

import (
	"strings"
	"testing"
)

// ---------- parsePublicKeyFromPEM error paths ----------

func TestParsePublicKeyFromPEM_EmptyString(t *testing.T) {
	key, err := parsePublicKeyFromPEM("")
	if err == nil {
		t.Error("expected error for empty PEM string")
	}
	if key != nil {
		t.Error("expected nil key for empty PEM string")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Errorf("error = %q, want containing 'failed to decode PEM block'", err.Error())
	}
}

func TestParsePublicKeyFromPEM_GarbageData(t *testing.T) {
	key, err := parsePublicKeyFromPEM("not-a-pem-block-at-all")
	if err == nil {
		t.Error("expected error for garbage PEM data")
	}
	if key != nil {
		t.Error("expected nil key for garbage PEM data")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Errorf("error = %q, want containing 'failed to decode PEM block'", err.Error())
	}
}

func TestParsePublicKeyFromPEM_InvalidDER(t *testing.T) {
	// Valid PEM block with garbage DER bytes
	pemData := `-----BEGIN PUBLIC KEY-----
AAAA
-----END PUBLIC KEY-----`
	key, err := parsePublicKeyFromPEM(pemData)
	if err == nil {
		t.Error("expected error for invalid DER data")
	}
	if key != nil {
		t.Error("expected nil key for invalid DER data")
	}
	if !strings.Contains(err.Error(), "failed to parse public key") {
		t.Errorf("error = %q, want containing 'failed to parse public key'", err.Error())
	}
}

func TestParsePublicKeyFromPEM_RSAPublicKey(t *testing.T) {
	// RSA public key — not ECDSA
	rsaPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5kHmLAmljI7Gq4cP5ME6
6ra295AZo3HUw0Gk4OeLkvEAUuzT8vXriUwHyircrdvs7wzcuv6L9Ej/8Ozv+53h
nHBwMRHd/67YJGTY4tIk7xFE3Fh+eNhPFoBmrnmPhKIvPyHRGNcEE9QFum3xirjI
AEw7ylLkBPGvt3zCYP3KAm0OEP+vFh3Zq3eFzfaDnFZcGbtBZ7ObRSvY3iqKvHUv
qZz6QjrBnWIIwEG5c01rgydDD5VeOj6xev8xwfUjAyT0zfvO/ICNLwMiEJRKtyjj
s8N63eGpuAEgmY6xAmogikVQkfRbmvEdFvYaI8Fg5lYmPsasP0MPqQXtJeQ01dEN
VwIDAQAB
-----END PUBLIC KEY-----`
	key, err := parsePublicKeyFromPEM(rsaPEM)
	if err == nil {
		t.Error("expected error for RSA key (not ECDSA)")
	}
	if key != nil {
		t.Error("expected nil key for RSA key")
	}
	if !strings.Contains(err.Error(), "not ECDSA") {
		t.Errorf("error = %q, want containing 'not ECDSA'", err.Error())
	}
}

func TestParsePublicKeyFromPEM_ValidP256Key(t *testing.T) {
	// The embedded P-256 key should parse successfully
	key, err := parsePublicKeyFromPEM(embeddedPublicKeyPEM)
	if err != nil {
		t.Fatalf("parsePublicKeyFromPEM with embedded key: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key for valid P-256 PEM")
	}
	if key.Curve == nil {
		t.Fatal("key has nil curve")
	}
	if key.Curve.Params().Name != "P-256" {
		t.Errorf("curve = %q, want P-256", key.Curve.Params().Name)
	}
}

// ---------- fingerprintFromPEM error paths ----------

func TestFingerprintFromPEM_InvalidPEM(t *testing.T) {
	fp := fingerprintFromPEM("not-a-pem-string")
	if fp != "invalid" {
		t.Errorf("fingerprintFromPEM(garbage) = %q, want 'invalid'", fp)
	}
}

func TestFingerprintFromPEM_EmptyPEM(t *testing.T) {
	fp := fingerprintFromPEM("")
	if fp != "invalid" {
		t.Errorf("fingerprintFromPEM(empty) = %q, want 'invalid'", fp)
	}
}

func TestFingerprintFromPEM_ShortDER(t *testing.T) {
	// Create a PEM block with very short DER bytes (< 8 bytes)
	// This exercises the "short" return path
	shortPEM := `-----BEGIN PUBLIC KEY-----
AA==
-----END PUBLIC KEY-----`
	fp := fingerprintFromPEM(shortPEM)
	// The DER bytes of "AA==" decode to a single byte (0x00), which is < 8
	// but pem.Decode might fail or return very short bytes
	// If PEM parses successfully but DER is < 8 bytes, we get "short"
	t.Logf("fingerprintFromPEM(short DER) = %q", fp)
	// We just verify it doesn't crash. The value depends on whether pem.Decode succeeds.
	if fp == "" {
		t.Error("fingerprintFromPEM should return non-empty string")
	}
}

func TestFingerprintFromPEM_ValidPEM(t *testing.T) {
	fp := fingerprintFromPEM(embeddedPublicKeyPEM)
	if fp == "" || fp == "invalid" || fp == "short" {
		t.Errorf("fingerprintFromPEM(embedded) = %q, want hex fingerprint", fp)
	}
	// Verify it matches what KeyFingerprint returns
	fpDirect := KeyFingerprint()
	if fp != fpDirect {
		t.Errorf("fingerprintFromPEM mismatch: got %q, KeyFingerprint returns %q", fp, fpDirect)
	}
}
