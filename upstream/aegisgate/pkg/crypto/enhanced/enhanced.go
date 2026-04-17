// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Copyright 2024 AegisGate
// Enhanced Cryptographic Operations using golang.org/x/crypto
//
// This module provides enhanced cryptographic operations using the
// golang.org/x/crypto package for FIPS-compatible cryptography.

package enhanced

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
)

// ============================================================================
// Hash Functions
// ============================================================================

// NewSHA256 creates a SHA-256 hash (FIPS approved)
func NewSHA256() hash.Hash {
	return sha256.New()
}

// NewSHA3256 creates a SHA3-256 hash (FIPS approved)
func NewSHA3256() hash.Hash {
	return sha3.New256()
}

// NewSHA3512 creates a SHA3-512 hash (FIPS approved)
func NewSHA3512() hash.Hash {
	return sha3.New512()
}

// NewBLAKE2b creates a BLAKE2b hash (NIST approved)
func NewBLAKE2b(size int) (hash.Hash, error) {
	return blake2b.New(size, nil)
}

// ============================================================================
// Key Derivation Functions
// ============================================================================

// DeriveKeyPBKDF2 derives a key using PBKDF2 (FIPS approved)
func DeriveKeyPBKDF2(password []byte, salt []byte, iterations int, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

// ============================================================================
// Encryption Functions
// ============================================================================

// ChaCha20Poly1305Encrypt encrypts data using ChaCha20-Poly1305
func ChaCha20Poly1305Encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// ChaCha20Poly1305Decrypt decrypts data using ChaCha20-Poly1305
func ChaCha20Poly1305Decrypt(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// ============================================================================
// Digital Signatures
// ============================================================================

// GenerateED25519Key generates an ED25519 key pair
func GenerateED25519Key() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// SignED25519 signs data using ED25519
func SignED25519(privKey ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(privKey, data)
}

// VerifyED25519 verifies an ED25519 signature
func VerifyED25519(pubKey ed25519.PublicKey, data []byte, sig []byte) bool {
	return ed25519.Verify(pubKey, data, sig)
}

// ============================================================================
// RSA Operations
// ============================================================================

// GenerateRSAKey generates an RSA key pair with FIPS-compliant minimum size
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("key size must be at least 2048 bits for FIPS compliance")
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// RSASign signs data using RSA-SHA256
func RSASign(privKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
}

// RSAVerify verifies an RSA signature
func RSAVerify(pubKey *rsa.PublicKey, data []byte, sig []byte) error {
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig)
}

// ============================================================================
// SSH Key Operations
// ============================================================================

// GenerateSSHKey generates an SSH key pair
func GenerateSSHKey(bits int) (ssh.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(&priv.PublicKey)
}

// ============================================================================
// TLS Configuration Helpers
// ============================================================================

// GetFIPSCipherSuites returns FIPS-approved TLS cipher suites
func GetFIPSCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}
}

// GetSecureTLSConfig returns a secure TLS configuration
func GetSecureTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CipherSuites:             GetFIPSCipherSuites(),
	}
}

// ============================================================================
// Utility Functions
// ============================================================================

// ConstantTimeCompare performs constant-time comparison
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
