// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - MCP Signature Verification Adapter
// =========================================================================
//
// Adapts signature_verification package for integration with MCP server.
// This enables verification of MCP server registrations and initialization
// handshakes.
// =========================================================================

package signature_verification

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MCPVerifier provides signature verification for MCP server connections
type MCPVerifier struct {
	verifier        *SignatureVerifier
	enabled         bool
	strictMode      bool
	trustedKeys     map[string]*PublicKeyInfo
	pendingSessions map[string]*PendingSession
	mu              sync.RWMutex
}

// PendingSession represents a session awaiting signature verification
type PendingSession struct {
	SessionID  string
	ClientAddr string
	ServerID   string
	Timestamp  time.Time
	PublicKey  []byte
	Signature  []byte
	Verified   bool
}

// Config holds MCP verification configuration
type Config struct {
	// Enable verification for MCP registrations
	Enabled bool

	// Require all connections to have valid signatures
	Required bool

	// Trusted key fingerprints (hex-encoded, first 16 chars)
	TrustedKeyFingerprints []string

	// Maximum age for pending sessions before timeout
	SessionTimeout time.Duration

	// Strict mode: reject even if verification is disabled
	StrictMode bool
}

// DefaultConfig returns the default MCP verification configuration
func DefaultMCPConfig() *Config {
	return &Config{
		Enabled:                true,
		Required:               false,
		TrustedKeyFingerprints: []string{},
		SessionTimeout:         5 * time.Minute,
		StrictMode:             false,
	}
}

// NewMCPVerifier creates a new MCP signature verifier
func NewMCPVerifier(cfg *Config) *MCPVerifier {
	if cfg == nil {
		cfg = DefaultMCPConfig()
	}

	return &MCPVerifier{
		verifier:        NewSignatureVerifier(),
		enabled:         cfg.Enabled,
		strictMode:      cfg.StrictMode,
		trustedKeys:     make(map[string]*PublicKeyInfo),
		pendingSessions: make(map[string]*PendingSession),
	}
}

// Enable enables MCP signature verification
func (mv *MCPVerifier) Enable() {
	mv.enabled = true
}

// Disable disables MCP signature verification
func (mv *MCPVerifier) Disable() {
	mv.enabled = false
}

// IsEnabled returns whether verification is enabled
func (mv *MCPVerifier) IsEnabled() bool {
	return mv.enabled
}

// RegisterPendingSession registers a session awaiting signature verification
// Returns a session token to be included in the initialization response
func (mv *MCPVerifier) RegisterPendingSession(sessionID, clientAddr, serverID string, publicKey []byte) (string, error) {
	mv.mu.Lock()
	defer mv.mu.Unlock()

	if !mv.enabled {
		// When verification is disabled, return empty token.
		// The VerifyMCPInitialize and IsVerified methods will deny requests,
		// so sessions won't be treated as verified without proper verification.
		return "", nil
	}

	token := generateSessionToken(sessionID, serverID)
	mv.pendingSessions[token] = &PendingSession{
		SessionID:  sessionID,
		ClientAddr: clientAddr,
		ServerID:   serverID,
		Timestamp:  time.Now(),
		PublicKey:  publicKey,
		Verified:   false,
	}

	return token, nil
}

// VerifyPendingSession verifies a session's signature
func (mv *MCPVerifier) VerifyPendingSession(token string, signature []byte) (*VerificationResult, error) {
	mv.mu.Lock()
	defer mv.mu.Unlock()

	if !mv.enabled {
		// FAIL-CLOSED: When verification is disabled, sessions are NOT auto-verified.
		// Returns Valid=false so callers checking result.Valid will deny the request.
		return &VerificationResult{
			Valid:     false,
			Timestamp: time.Now(),
			Error:     errors.New("signature verification is disabled — session verification denied by default"),
		}, errors.New("signature verification is disabled")
	}

	pending, exists := mv.pendingSessions[token]
	if !exists {
		return &VerificationResult{
			Valid:     false,
			Timestamp: time.Now(),
			Error:     errors.New("session token not found or expired"),
		}, errors.New("session token not found or expired")
	}

	// Build payload from session data
	payload := []byte(fmt.Sprintf("%s:%s:%s:%d", pending.SessionID, pending.ServerID, pending.ClientAddr, pending.Timestamp.Unix()))

	// Verify signature using embedded public key
	result, err := mv.verifier.VerifySignature(payload, signature, pending.PublicKey)
	if err != nil {
		return result, err
	}

	// Mark session as verified
	pending.Verified = result.Valid

	if result.Valid {
		delete(mv.pendingSessions, token)
	}

	return result, nil
}

// VerifyMCPInitialize verifies an MCP initialization handshake
// This can be called during the initialize handler to verify the client
func (mv *MCPVerifier) VerifyMCPInitialize(ctx context.Context, init *MCPInitializeRequest) (*VerificationResult, error) {
	if !mv.enabled {
		// FAIL-CLOSED: When verification is disabled, ALL initializations are denied.
		// Returns Valid=false so callers checking result.Valid will reject the connection.
		return &VerificationResult{
			Valid:     false,
			Timestamp: time.Now(),
			Error:     errors.New("signature verification is disabled — MCP initialization denied by default"),
		}, errors.New("signature verification is disabled")
	}

	// Build payload for verification
	payload := buildInitializePayload(init)

	// Verify signature if provided
	if len(init.Signature) > 0 {
		result, err := mv.verifier.VerifySignature(payload, init.Signature, init.PublicKey)
		if err != nil {
			return result, err
		}

		// Check if key is trusted
		if result.Valid {
			result.Valid = mv.isKeyTrusted(result.PublicKey.Fingerprint)
		}

		return result, nil
	}

	// No signature provided — FAIL-CLOSED: deny by default.
	// In a security product, unsigned connections must NOT be allowed through.
	// Use strictMode=true in production to enforce this at the config level.
	// When strictMode=false (development/testing only), we still deny unsigned
	// requests here to prevent accidental misconfiguration.
	return &VerificationResult{
		Valid:     false,
		Timestamp: time.Now(),
		Error:     errors.New("signature required for MCP initialization — unsigned connections are denied by default"),
	}, errors.New("signature required for MCP initialization")
}

// MCPInitializeRequest represents an MCP initialization request
type MCPInitializeRequest struct {
	SessionID  string
	ClientAddr string
	ServerID   string
	Protocol   string
	Version    string
	PublicKey  []byte
	Signature  []byte
}

// IsVerified returns whether a pending session is verified
func (mv *MCPVerifier) IsVerified(token string) bool {
	mv.mu.RLock()
	defer mv.mu.RUnlock()

	pending, exists := mv.pendingSessions[token]
	// FAIL-CLOSED: Unknown tokens are NOT verified. If a session token doesn't exist
	// in the pending map, it was either never created (bogus token) or already consumed.
	// Neither case should result in verified=true.
	if !exists {
		return false
	}

	return pending.Verified
}

// GetPendingSession returns a pending session by token
func (mv *MCPVerifier) GetPendingSession(token string) (*PendingSession, error) {
	mv.mu.RLock()
	defer mv.mu.RUnlock()

	pending, exists := mv.pendingSessions[token]
	if !exists {
		return nil, errors.New("session not found")
	}

	return pending, nil
}

// CleanupExpiredSessions removes sessions older than SessionTimeout
func (mv *MCPVerifier) CleanupExpiredSessions() int {
	mv.mu.Lock()
	defer mv.mu.Unlock()

	cfg := DefaultMCPConfig()
	count := 0
	now := time.Now()

	for token, pending := range mv.pendingSessions {
		if now.Sub(pending.Timestamp) > cfg.SessionTimeout {
			delete(mv.pendingSessions, token)
			count++
		}
	}

	return count
}

// AddTrustedKey adds a key to the trusted keys list
func (mv *MCPVerifier) AddTrustedKey(keyInfo *PublicKeyInfo) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	mv.trustedKeys[keyInfo.Fingerprint] = keyInfo
}

// RemoveTrustedKey removes a key from the trusted keys list
func (mv *MCPVerifier) RemoveTrustedKey(fingerprint string) {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	delete(mv.trustedKeys, fingerprint)
}

// isKeyTrusted checks if a key fingerprint is in the trusted list
func (mv *MCPVerifier) isKeyTrusted(fingerprint string) bool {
	mv.mu.RLock()
	defer mv.mu.RUnlock()

	_, trusted := mv.trustedKeys[fingerprint]
	return trusted
}

// generateSessionToken generates a unique token for a pending session
func generateSessionToken(sessionID, serverID string) string {
	payload := fmt.Sprintf("%s:%s:%d", sessionID, serverID, time.Now().UnixNano())

	h := crypto.SHA256.New()
	h.Write([]byte(payload))
	hash := h.Sum(nil)

	return base64.URLEncoding.EncodeToString(hash[:16])
}

// buildInitializePayload builds the payload to be signed
func buildInitializePayload(init *MCPInitializeRequest) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%s",
		init.SessionID,
		init.ClientAddr,
		init.ServerID,
		init.Protocol,
		init.Version,
	))
}

// ============================================================================
// Test Utilities
// ============================================================================

// GenerateTestRSAKeyPair generates an RSA key pair for testing
func GenerateTestRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	// Encode public key to PEM
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return privateKey, publicKey, pubPEM, nil
}

// GenerateTestECDSAKeyPair generates an ECDSA key pair for testing
func GenerateTestECDSAKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	publicKey := &privateKey.PublicKey

	// Encode public key to PEM
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return privateKey, publicKey, pubPEM, nil
}
