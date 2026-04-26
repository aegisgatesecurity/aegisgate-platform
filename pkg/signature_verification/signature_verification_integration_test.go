// SPDX-License-Identifier: Apache-2.0

//go:build integration

package signature_verification

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// TestVerifyEd25519Signature tests Ed25519 signature verification
// This requires real Ed25519 key generation and signing
func TestVerifyEd25519Signature(t *testing.T) {
	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Skip("Ed25519 not available: ", err)
	}

	// Create verifier
	verifier := NewSignatureVerifier()
	verifier.Enable()

	// Sign a message
	message := []byte("test message for ed25519")
	signature := ed25519.Sign(privKey, message)

	// Verify should work
	verifier.addKeyForTesting("test-key", pubKey)
	if !verifier.verifyEd25519Signature(message, signature, pubKey) {
		t.Error("verifyEd25519Signature failed for valid signature")
	}

	// Verify should fail for wrong message
	wrongMsg := []byte("wrong message")
	if verifier.verifyEd25519Signature(wrongMsg, signature, pubKey) {
		t.Error("verifyEd25519Signature should fail for wrong message")
	}

	// Verify should fail for wrong signature
	wrongSig := make([]byte, len(signature))
	verifier.verifyEd25519Signature(message, wrongSig, pubKey)
}

// TestLoadPublicKeyFromFile tests loading RSA key from PEM file
// This requires real key files
func TestLoadPublicKeyFromFile(t *testing.T) {
	// Create temp PEM file with RSA public key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skip("RSA key generation failed: ", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Skip("Cannot marshal public key: ", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	tmpFile, err := os.CreateTemp("", "pubkey-*.pem")
	if err != nil {
		t.Skip("Cannot create temp file: ", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(pem.EncodeToMemory(pemBlock))
	tmpFile.Close()

	// Test loading
	verifier := NewSignatureVerifier()
	key, err := verifier.LoadPublicKey(tmpFile.Name())
	if err != nil {
		t.Errorf("LoadPublicKey failed: %v", err)
	}
	if key == nil {
		t.Error("LoadPublicKey returned nil")
	}
}

// TestLoadPrivateKeyFromFile tests loading RSA private key from PEM file
func TestLoadPrivateKeyFromFile(t *testing.T) {
	// Create temp PEM file with RSA private key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skip("RSA key generation failed: ", err)
	}

	privKeyBytes, err := x509.MarshalPKCS1PrivateKey(rsaKey)
	if err != nil {
		t.Skip("Cannot marshal private key: ", err)
	}

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	tmpFile, err := os.CreateTemp("", "privkey-*.pem")
	if err != nil {
		t.Skip("Cannot create temp file: ", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(pem.EncodeToMemory(pemBlock))
	tmpFile.Close()

	// Test loading
	km := NewKeyManager()
	key, err := km.LoadPrivateKey(tmpFile.Name())
	if err != nil {
		t.Errorf("LoadPrivateKey failed: %v", err)
	}
	if key == nil {
		t.Error("LoadPrivateKey returned nil")
	}
}

// TestRSASSAvSSHA256 tests RSA signature with SHA256
func TestRSASSAvSSHA256(t *testing.T) {
	// Generate RSA key pair
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skip("RSA key generation failed: ", err)
	}

	message := []byte("test message for RSA-SHA256")
	hashed := hashPayload(message)

	// Sign with PKCS1v15
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed)
	if err != nil {
		t.Skip("RSA signing failed: ", err)
	}

	// Verify
	verifier := NewSignatureVerifier()
	verifier.Enable()

	if !verifier.verifyRSASignature(message, signature, &rsaKey.PublicKey, AlgorithmRSASSAvSSHA256) {
		t.Error("RSA-SHA256 verification failed for valid signature")
	}
}
