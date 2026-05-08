// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// signature_verification internal test coverage
// Tests unexported functions verifyRSASignature, verifyECDSASignature
// =========================================================================

//go:build !race

package signature_verification

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// =========================================================================
// verifyRSASignature edge case tests (73.7% → 95%+)
// =========================================================================

func TestVerifyRSASignature_RSASSA_PSS_ErrorPath(t *testing.T) {
	// Test RSASSA_PSS path where VerifyPSS returns error
	// RSASSA_PSS algorithm is defined (iota=1) but needs testing through internal API
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("test-payload-pss-error")

	// Create an invalid signature (padding bytes, not a real signature)
	invalidSig := make([]byte, 50)
	valid, err := verifyRSASignature(&priv.PublicKey, payload, invalidSig, RSASSA_PSS)
	if err == nil && valid {
		t.Error("invalid PSS signature should return error or false")
	}
}

func TestVerifyRSASignature_UnsupportedAlgorithm(t *testing.T) {
	// Test the default case in the algorithm switch
	// This requires an algorithm value not in {RSASSA_PKCS1v15, RSASSA_PSS}
	// We can use a type assertion or create test that forces this path
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("test-payload")
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	// Sign with valid signature
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatal(err)
	}

	// Use algorithm value 99 (not defined, triggers default case)
	valid, err := verifyRSASignature(&priv.PublicKey, payload, sig, SignatureAlgorithm(99))
	if err == nil {
		t.Error("unsupported algorithm should return error")
	}
	if valid {
		t.Error("unsupported algorithm should return valid=false")
	}
}

// =========================================================================
// verifyECDSASignature edge case tests
// =========================================================================

func TestVerifyECDSASignature_InvalidSigBytes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create invalid signature (wrong length)
	invalidSig := []byte{0x00, 0x01, 0x02}
	valid, err := verifyECDSASignature(&priv.PublicKey, nil, invalidSig)
	if err == nil && valid {
		t.Error("invalid ECDSA signature should return error or false")
	}
}

func TestVerifyECDSASignature_WrongKey(t *testing.T) {
	priv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	priv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	h := sha256.New()
	h.Write([]byte("test-payload"))
	hashed := h.Sum(nil)

	// Sign with priv2
	sig, err := ecdsa.SignASN1(rand.Reader, priv2, hashed)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with priv1's public key - should fail
	valid, err := verifyECDSASignature(&priv1.PublicKey, nil, sig)
	if err == nil && valid {
		t.Error("signature with wrong key should fail verification")
	}
}

// =========================================================================
// LoadPublicKey PEM parsing error paths (72.7% → 95%+)
// =========================================================================

func TestLoadPublicKey_RSAPKCS1ParsingError(t *testing.T) {
	// "RSA PUBLIC KEY" type uses x509.ParsePKCS1PublicKey
	// Invalid DER bytes should cause parsing error
	km := NewKeyManager("")

	// Create PEM with "RSA PUBLIC KEY" type but invalid bytes
	invalidPEM := []byte("-----BEGIN RSA PUBLIC KEY-----\ninvalid_base64_data!!!\n-----END RSA PUBLIC KEY-----")

	err := km.LoadPublicKey("test-key", invalidPEM, []string{"test"})
	if err == nil {
		t.Error("invalid PKCS1 data should return parsing error")
	}
}

func TestLoadPublicKey_ECPKIXParsingError(t *testing.T) {
	// "EC PUBLIC KEY" type uses x509.ParsePKIXPublicKey
	// Invalid DER bytes should cause parsing error
	km := NewKeyManager("")

	// Create PEM with "EC PUBLIC KEY" type but invalid bytes
	invalidPEM := []byte("-----BEGIN EC PUBLIC KEY-----\ninvalid_base64_data!!!\n-----END EC PUBLIC KEY-----")

	err := km.LoadPublicKey("test-key", invalidPEM, []string{"test"})
	if err == nil {
		t.Error("invalid EC PKIX data should return parsing error")
	}
}

// =========================================================================
// LoadPrivateKey PEM parsing error paths
// =========================================================================

func TestLoadPrivateKey_ECPrivateKeyParsingError(t *testing.T) {
	// "EC PRIVATE KEY" uses x509.ParsePKCS8PrivateKey
	// Invalid DER bytes should cause parsing error
	km := NewKeyManager("")

	// Create PEM with "EC PRIVATE KEY" type but invalid bytes
	invalidPEM := []byte("-----BEGIN EC PRIVATE KEY-----\ninvalid_base64_data!!!\n-----END EC PRIVATE KEY-----")

	err := km.LoadPrivateKey("test-key", invalidPEM)
	if err == nil {
		t.Error("invalid EC private key data should return parsing error")
	}
}
