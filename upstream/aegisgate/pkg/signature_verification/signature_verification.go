// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package signature_verification

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// HashAlgorithm defines the hashing algorithm to use
type HashAlgorithm int

const (
	SHA256 HashAlgorithm = iota
	SHA384
	SHA512
)

// SignatureAlgorithm defines the signature algorithm
type SignatureAlgorithm int

const (
	RSASSA_PKCS1v15 SignatureAlgorithm = iota
	RSASSA_PSS
	ECDSA
	Ed25519
)

// KeyType defines the type of cryptographic key
type KeyType string

const (
	KeyTypeRSA     KeyType = "rsa"
	KeyTypeECDSA   KeyType = "ecdsa"
	KeyTypeEd25519 KeyType = "ed25519"
)

// VerificationResult represents the result of signature verification
type VerificationResult struct {
	Valid     bool
	KeyID     string
	FeedID    string
	Timestamp time.Time
	Algorithm SignatureAlgorithm
	Hash      HashAlgorithm
	PublicKey PublicKeyInfo
	Error     error
}

// PublicKeyInfo contains information about a public key
type PublicKeyInfo struct {
	Type        KeyType
	Algorithm   SignatureAlgorithm
	KeyID       string
	Fingerprint string
	Usage       []string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Revoked     bool
}

// SignedPayload represents a signed data payload
type SignedPayload struct {
	Data      []byte
	Signature []byte
	PublicKey []byte
	Hash      HashAlgorithm
	Algorithm SignatureAlgorithm
	Metadata  map[string]interface{}
}

// VerificationStats holds verification statistics
type VerificationStats struct {
	TotalVerifications int64
	Successful         int64
	Failed             int64
	LastSuccessTime    time.Time
	LastFailTime       time.Time
	LastAlgorithm      SignatureAlgorithm
	LastHash           HashAlgorithm
}

// KeyManager manages cryptographic keys for signature verification
type KeyManager struct {
	publicKeys   map[string]*PublicKeyInfo
	privateKeys  map[string]crypto.PrivateKey
	lock         sync.RWMutex
	keyStorePath string
}

// SignatureVerifier provides signature verification services
type SignatureVerifier struct {
	keyManager  *KeyManager
	enabled     bool
	strictMode  bool
	allowedKeys map[string]bool
	stats       *VerificationStats
	statsLock   sync.Mutex
}

// NewKeyManager creates a new key manager
func NewKeyManager(keyStorePath string) *KeyManager {
	return &KeyManager{
		publicKeys:   make(map[string]*PublicKeyInfo),
		privateKeys:  make(map[string]crypto.PrivateKey),
		keyStorePath: keyStorePath,
	}
}

// NewSignatureVerifier creates a new signature verifier
func NewSignatureVerifier() *SignatureVerifier {
	return &SignatureVerifier{
		keyManager:  NewKeyManager(""),
		enabled:     true,
		strictMode:  false,
		allowedKeys: make(map[string]bool),
		stats:       &VerificationStats{},
	}
}

// LoadPublicKey loads a public key from PEM format
func (km *KeyManager) LoadPublicKey(keyID string, pemData []byte, usage []string) error {
	km.lock.Lock()
	defer km.lock.Unlock()

	block, _ := pem.Decode(pemData)
	if block == nil {
		return errors.New("failed to decode PEM data")
	}

	var publicKey crypto.PublicKey
	var err error

	switch block.Type {
	case "PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
	case "RSA PUBLIC KEY":
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA public key: %w", err)
		}
	case "EC PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse EC public key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported key type: %s", block.Type)
	}

	fingerprint := generateFingerprint(publicKey)

	keyInfo := &PublicKeyInfo{
		Type:        detectKeyType(publicKey),
		Algorithm:   detectSignatureAlgorithm(publicKey),
		KeyID:       keyID,
		Fingerprint: fingerprint,
		Usage:       usage,
		CreatedAt:   time.Now(),
		Revoked:     false,
	}

	km.publicKeys[keyID] = keyInfo

	return nil
}

// LoadPrivateKey loads a private key from PEM format
func (km *KeyManager) LoadPrivateKey(keyID string, pemData []byte) error {
	km.lock.Lock()
	defer km.lock.Unlock()

	block, _ := pem.Decode(pemData)
	if block == nil {
		return errors.New("failed to decode PEM data")
	}

	var privateKey crypto.PrivateKey
	var err error

	if block.Type == "PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	} else if block.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
	} else if block.Type == "EC PRIVATE KEY" {
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse EC private key: %w", err)
		}
	} else {
		return fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	km.privateKeys[keyID] = privateKey

	return nil
}

// GetPublicKey retrieves a public key by ID
func (km *KeyManager) GetPublicKey(keyID string) (*PublicKeyInfo, crypto.PublicKey, error) {
	km.lock.RLock()
	defer km.lock.RUnlock()

	keyInfo, exists := km.publicKeys[keyID]
	if !exists {
		return nil, nil, errors.New("key not found")
	}

	if keyInfo.Revoked {
		return nil, nil, errors.New("key has been revoked")
	}

	return keyInfo, nil, nil
}

// RevokeKey revokes a key by ID
func (km *KeyManager) RevokeKey(keyID string) error {
	km.lock.Lock()
	defer km.lock.Unlock()

	keyInfo, exists := km.publicKeys[keyID]
	if !exists {
		return errors.New("key not found")
	}

	keyInfo.Revoked = true
	return nil
}

// detectKeyType detects the key type
func detectKeyType(publicKey crypto.PublicKey) KeyType {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return KeyTypeRSA
	case *ecdsa.PublicKey:
		return KeyTypeECDSA
	case ed25519.PublicKey:
		return KeyTypeEd25519
	default:
		return ""
	}
}

// detectSignatureAlgorithm detects the signature algorithm
func detectSignatureAlgorithm(publicKey crypto.PublicKey) SignatureAlgorithm {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return RSASSA_PKCS1v15
	case *ecdsa.PublicKey:
		return ECDSA
	case ed25519.PublicKey:
		return Ed25519
	default:
		return RSASSA_PKCS1v15
	}
}

// generateFingerprint generates a fingerprint for the public key
func generateFingerprint(publicKey crypto.PublicKey) string {
	derEncode, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}

	h := sha256.Sum256(derEncode)
	return fmt.Sprintf("%x", h[:])[:16]
}

// VerifySignature verifies a signature
func (sv *SignatureVerifier) VerifySignature(payload []byte, signature []byte, publicKeyBytes []byte) (*VerificationResult, error) {
	sv.statsLock.Lock()
	sv.stats.TotalVerifications++
	sv.statsLock.Unlock()

	if !sv.enabled {
		return &VerificationResult{
			Valid:     true,
			Timestamp: time.Now(),
			Error:     errors.New("signature verification is disabled"),
		}, nil
	}

	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		result := &VerificationResult{
			Valid:     false,
			Timestamp: time.Now(),
			Error:     errors.New("failed to decode PEM data"),
		}
		sv.updateStats(false, result.Error)
		return result, result.Error
	}

	var publicKey crypto.PublicKey
	var err error

	switch block.Type {
	case "PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			result := &VerificationResult{
				Valid:     false,
				Timestamp: time.Now(),
				Error:     fmt.Errorf("failed to parse public key: %w", err),
			}
			sv.updateStats(false, result.Error)
			return result, result.Error
		}
	case "RSA PUBLIC KEY":
		publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			result := &VerificationResult{
				Valid:     false,
				Timestamp: time.Now(),
				Error:     fmt.Errorf("failed to parse RSA public key: %w", err),
			}
			sv.updateStats(false, result.Error)
			return result, result.Error
		}
	case "EC PUBLIC KEY":
		publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			result := &VerificationResult{
				Valid:     false,
				Timestamp: time.Now(),
				Error:     fmt.Errorf("failed to parse EC public key: %w", err),
			}
			sv.updateStats(false, result.Error)
			return result, result.Error
		}
	default:
		result := &VerificationResult{
			Valid:     false,
			Timestamp: time.Now(),
			Error:     fmt.Errorf("unsupported key type: %s", block.Type),
		}
		sv.updateStats(false, result.Error)
		return result, result.Error
	}

	algorithm := detectSignatureAlgorithm(publicKey)

	var valid bool

	switch algorithm {
	case RSASSA_PKCS1v15, RSASSA_PSS:
		valid, err = verifyRSASignature(publicKey.(*rsa.PublicKey), payload, signature, algorithm)
	case ECDSA:
		valid, err = verifyECDSASignature(publicKey.(*ecdsa.PublicKey), payload, signature)
	case Ed25519:
		valid, err = verifyEd25519Signature(publicKey.(ed25519.PublicKey), payload, signature)
	default:
		err = errors.New("unsupported signature algorithm")
	}

	result := &VerificationResult{
		Valid:     valid,
		KeyID:     "",
		FeedID:    "",
		Timestamp: time.Now(),
		Algorithm: algorithm,
		PublicKey: PublicKeyInfo{
			Type:      detectKeyType(publicKey),
			Algorithm: algorithm,
			KeyID:     "",
			CreatedAt: time.Now(),
		},
		Error: err,
	}

	sv.updateStats(valid, err)
	return result, err
}

// verifyRSASignature verifies an RSA signature
func verifyRSASignature(publicKey *rsa.PublicKey, payload, signature []byte, algorithm SignatureAlgorithm) (bool, error) {
	var hashFunc crypto.Hash

	switch publicKey.N.BitLen() {
	case 2048:
		hashFunc = crypto.SHA256
	case 3072:
		hashFunc = crypto.SHA384
	case 4096:
		hashFunc = crypto.SHA512
	default:
		return false, errors.New("unsupported RSA key size")
	}

	h := hashFunc.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	switch algorithm {
	case RSASSA_PKCS1v15:
		err := rsa.VerifyPKCS1v15(publicKey, hashFunc, hashed, signature)
		if err != nil {
			return false, err
		}
		return true, nil
	case RSASSA_PSS:
		err := rsa.VerifyPSS(publicKey, hashFunc, hashed, signature, nil)
		if err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, errors.New("unsupported RSA algorithm")
	}
}

// verifyECDSASignature verifies an ECDSA signature
func verifyECDSASignature(publicKey *ecdsa.PublicKey, payload, signature []byte) (bool, error) {
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	var sig struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return false, err
	}

	valid := ecdsa.Verify(publicKey, hashed, sig.R, sig.S)
	return valid, nil
}

// verifyEd25519Signature verifies an Ed25519 signature
func verifyEd25519Signature(publicKey ed25519.PublicKey, payload, signature []byte) (bool, error) {
	valid := ed25519.Verify(publicKey, payload, signature)
	return valid, nil
}

// updateStats updates verification statistics
func (sv *SignatureVerifier) updateStats(success bool, err error) {
	sv.statsLock.Lock()
	defer sv.statsLock.Unlock()

	sv.stats.TotalVerifications++

	if success {
		sv.stats.Successful++
		sv.stats.LastSuccessTime = time.Now()
	} else {
		sv.stats.Failed++
		sv.stats.LastFailTime = time.Now()
	}
}

// GetStats returns verification statistics
func (sv *SignatureVerifier) GetStats() *VerificationStats {
	sv.statsLock.Lock()
	defer sv.statsLock.Unlock()

	stats := *sv.stats
	return &stats
}

// ValidateSignedPayload validates a signed payload
func (sv *SignatureVerifier) ValidateSignedPayload(signed *SignedPayload) (*VerificationResult, error) {
	return sv.VerifySignature(signed.Data, signed.Signature, signed.PublicKey)
}

// VerifyStringSignature verifies a base64-encoded signature
func (sv *SignatureVerifier) VerifyStringSignature(payload []byte, signature string, publicKeyBytes []byte) (*VerificationResult, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return &VerificationResult{
			Valid:     false,
			Timestamp: time.Now(),
			Error:     fmt.Errorf("failed to decode signature: %w", err),
		}, err
	}

	return sv.VerifySignature(payload, sigBytes, publicKeyBytes)
}

// Enable enables signature verification
func (sv *SignatureVerifier) Enable() {
	sv.enabled = true
}

// Disable disables signature verification
func (sv *SignatureVerifier) Disable() {
	sv.enabled = false
}

// IsEnabled returns whether verification is enabled
func (sv *SignatureVerifier) IsEnabled() bool {
	return sv.enabled
}

// EnableStrictMode enables strict mode
func (sv *SignatureVerifier) EnableStrictMode() {
	sv.strictMode = true
}

// DisableStrictMode disables strict mode
func (sv *SignatureVerifier) DisableStrictMode() {
	sv.strictMode = false
}

// IsStrictModeEnabled returns whether strict mode is enabled
func (sv *SignatureVerifier) IsStrictModeEnabled() bool {
	return sv.strictMode
}

// SetAllowedKeys sets the allowed keys
func (sv *SignatureVerifier) SetAllowedKeys(keys map[string]bool) {
	sv.allowedKeys = keys
}

// GetAllowedKeys returns the allowed keys
func (sv *SignatureVerifier) GetAllowedKeys() map[string]bool {
	return sv.allowedKeys
}
