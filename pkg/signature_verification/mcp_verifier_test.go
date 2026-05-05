// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - MCP Signature Verification Tests
// =========================================================================

package signature_verification

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"
)

// ============================================================================
// TestMCPVerifier_Basic
// ============================================================================

func TestNewMCPVerifier(t *testing.T) {
	mv := NewMCPVerifier(nil)
	if mv == nil {
		t.Fatal("NewMCPVerifier() returned nil")
	}
	if !mv.IsEnabled() {
		t.Error("MCPVerifier should be enabled by default")
	}
}

func TestMCPVerifier_EnableDisable(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())

	// Disable
	mv.Disable()
	if mv.IsEnabled() {
		t.Error("IsEnabled() should return false after Disable()")
	}

	// Re-enable
	mv.Enable()
	if !mv.IsEnabled() {
		t.Error("IsEnabled() should return true after Enable()")
	}
}

func TestMCPVerifier_DefaultConfig(t *testing.T) {
	cfg := DefaultMCPConfig()

	if !cfg.Enabled {
		t.Error("default config should be enabled")
	}
	if cfg.SessionTimeout != 5*time.Minute {
		t.Errorf("default session timeout should be 5 minutes, got %v", cfg.SessionTimeout)
	}
}

// ============================================================================
// TestMCPVerifier_PendingSessions
// ============================================================================

func TestMCPVerifier_RegisterPendingSession(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())
	mv.Enable()

	token, err := mv.RegisterPendingSession("session-1", "192.168.1.1:1234", "server-1", generateTestPublicKeyPEM(t))
	if err != nil {
		t.Fatalf("RegisterPendingSession() error: %v", err)
	}
	if token == "" {
		t.Error("token should not be empty")
	}

	// Verify token exists
	pending, err := mv.GetPendingSession(token)
	if err != nil {
		t.Fatalf("GetPendingSession() error: %v", err)
	}
	if pending.SessionID != "session-1" {
		t.Errorf("SessionID mismatch: got %s, want session-1", pending.SessionID)
	}
	if pending.ClientAddr != "192.168.1.1:1234" {
		t.Errorf("ClientAddr mismatch: got %s, want 192.168.1.1:1234", pending.ClientAddr)
	}
}

func TestMCPVerifier_RegisterPendingSession_Disabled(t *testing.T) {
	cfg := DefaultMCPConfig()
	cfg.Enabled = false
	mv := NewMCPVerifier(cfg)

	// When disabled, should return empty token (no verification needed)
	token, err := mv.RegisterPendingSession("session-1", "192.168.1.1:1234", "server-1", nil)
	if err != nil {
		t.Fatalf("RegisterPendingSession() error: %v", err)
	}
	if token != "" {
		t.Error("disabled verifier should return empty token")
	}
}

func TestMCPVerifier_GetPendingSession_NotFound(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())

	_, err := mv.GetPendingSession("non-existent-token")
	if err == nil {
		t.Error("GetPendingSession() should fail for non-existent token")
	}
}

// ============================================================================
// TestMCPVerifier_Verification
// ============================================================================

func TestMCPVerifier_VerifyPendingSession(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())
	mv.Enable()

	// Register a session
	pubPEM := generateTestPublicKeyPEM(t)
	token, err := mv.RegisterPendingSession("session-verify", "127.0.0.1:8080", "test-server", pubPEM)
	if err != nil {
		t.Fatalf("RegisterPendingSession() error: %v", err)
	}

	// Create a fake signature for testing
	signature := []byte("fake-signature")

	// Verify - should fail because signature is fake
	result, err := mv.VerifyPendingSession(token, signature)
	if err != nil {
		t.Logf("VerifyPendingSession() error (expected): %v", err)
	}
	if result != nil && result.Valid {
		t.Error("fake signature should not be valid")
	}
}

func TestMCPVerifier_VerifyPendingSession_NotFound(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())
	mv.Enable()

	result, err := mv.VerifyPendingSession("non-existent-token", []byte("sig"))
	if err == nil {
		t.Error("should fail for non-existent token")
	}
	if result != nil && result.Valid {
		t.Error("result should not be valid for non-existent token")
	}
}

// ============================================================================
// TestMCPVerifier_MCPInitialize
// ============================================================================

func TestMCPVerifier_VerifyMCPInitialize_NoSignature(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())
	mv.Enable()

	init := &MCPInitializeRequest{
		SessionID:  "init-session",
		ClientAddr: "localhost:1234",
		ServerID:   "test-server",
		Protocol:   "2024-11-05",
		Version:    "1.0",
	}

	// FAIL-CLOSED: Unsigned initialization requests are denied by default,
	// regardless of strict mode. Unsigned requests are a security risk.
	result, err := mv.VerifyMCPInitialize(nil, init)
	if err == nil {
		t.Error("unsigned initialization should fail (fail-closed)")
	}
	if result != nil && result.Valid {
		t.Error("unsigned initialization should NOT be valid (fail-closed)")
	}
}

func TestMCPVerifier_VerifyMCPInitialize_StrictMode(t *testing.T) {
	cfg := DefaultMCPConfig()
	cfg.StrictMode = true
	mv := NewMCPVerifier(cfg)
	mv.Enable()

	init := &MCPInitializeRequest{
		SessionID:  "init-session",
		ClientAddr: "localhost:1234",
		ServerID:   "test-server",
		Protocol:   "2024-11-05",
		Version:    "1.0",
	}

	// Strict mode: should fail without signature
	result, err := mv.VerifyMCPInitialize(nil, init)
	if err == nil {
		t.Error("should fail in strict mode without signature")
	}
	if result != nil && result.Valid {
		t.Error("should not be valid in strict mode without signature")
	}
}

func TestMCPVerifier_VerifyMCPInitialize_Disabled(t *testing.T) {
	cfg := DefaultMCPConfig()
	cfg.Enabled = false
	mv := NewMCPVerifier(cfg)

	init := &MCPInitializeRequest{
		SessionID:  "init-session",
		ClientAddr: "localhost:1234",
		ServerID:   "test-server",
	}

	result, err := mv.VerifyMCPInitialize(nil, init)
	// FAIL-CLOSED: When verification is disabled, all requests are denied by default.
	// Disabled verification means we CANNOT verify the request, so it must be denied.
	if err == nil {
		t.Error("disabled verifier should deny all requests (fail-closed)")
	}
	if result != nil && result.Valid {
		t.Error("disabled verifier should return Valid=false (fail-closed)")
	}
}

// ============================================================================
// TestMCPVerifier_IsVerified
// ============================================================================

func TestMCPVerifier_IsVerified(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())
	mv.Enable()

	// FAIL-CLOSED: Unknown tokens are NOT verified.
	// If a session token doesn't exist in the pending map, it was either
	// never created (bogus token) or already consumed — neither should be verified.
	if mv.IsVerified("non-existent-token") {
		t.Error("non-existent token should NOT be verified (fail-closed)")
	}

	// Register a session
	token, _ := mv.RegisterPendingSession("session-check", "127.0.0.1", "server", nil)

	// Pending session should not be verified
	if mv.IsVerified(token) {
		t.Error("pending session should not be verified initially")
	}
}

// ============================================================================
// TestMCPVerifier_Cleanup
// ============================================================================

func TestMCPVerifier_CleanupExpiredSessions(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())
	mv.Enable()

	// Register some sessions
	mv.RegisterPendingSession("session-1", "addr1", "server1", nil)
	mv.RegisterPendingSession("session-2", "addr2", "server2", nil)

	// Cleanup should find 0 expired (sessions are fresh)
	count := mv.CleanupExpiredSessions()
	t.Logf("Cleaned up %d expired sessions", count)
}

// ============================================================================
// TestMCPVerifier_TrustedKeys
// ============================================================================

func TestMCPVerifier_AddTrustedKey(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())

	keyInfo := &PublicKeyInfo{
		Type:        KeyTypeRSA,
		Algorithm:   RSASSA_PKCS1v15,
		KeyID:       "trusted-key-1",
		Fingerprint: "abc123def456",
		Usage:       []string{"sign"},
	}

	mv.AddTrustedKey(keyInfo)

	// Key should be trusted now (checked internally)
	trusted := mv.isKeyTrusted("abc123def456")
	if !trusted {
		t.Error("key should be trusted after AddTrustedKey()")
	}
}

func TestMCPVerifier_RemoveTrustedKey(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())

	keyInfo := &PublicKeyInfo{
		Type:        KeyTypeRSA,
		KeyID:       "trusted-key-1",
		Fingerprint: "abc123def456",
	}

	mv.AddTrustedKey(keyInfo)
	mv.RemoveTrustedKey("abc123def456")

	trusted := mv.isKeyTrusted("abc123def456")
	if trusted {
		t.Error("key should not be trusted after RemoveTrustedKey()")
	}
}

// ============================================================================
// TestMCPVerifier_GenerateTestKeys
// ============================================================================

func TestGenerateTestRSAKeyPair(t *testing.T) {
	priv, pub, pubPEM, err := GenerateTestRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateTestRSAKeyPair() error: %v", err)
	}
	if priv == nil || pub == nil {
		t.Fatal("key pair should not be nil")
	}
	if len(pubPEM) == 0 {
		t.Error("PEM encoded public key should not be empty")
	}
	if pub.N.BitLen() != 2048 {
		t.Errorf("RSA key should be 2048 bits, got %d", pub.N.BitLen())
	}
}

func TestGenerateTestECDSAKeyPair(t *testing.T) {
	priv, pub, pubPEM, err := GenerateTestECDSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateTestECDSAKeyPair() error: %v", err)
	}
	if priv == nil || pub == nil {
		t.Fatal("key pair should not be nil")
	}
	if len(pubPEM) == 0 {
		t.Error("PEM encoded public key should not be empty")
	}
}

// ============================================================================
// TestMCPVerifier_RealSignatureFlow
// ============================================================================

func TestMCPVerifier_RealSignatureFlow(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())
	mv.Enable()

	// Generate a real key pair
	priv, _, pubPEM, err := GenerateTestRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateTestRSAKeyPair() error: %v", err)
	}

	// Register a session
	token, err := mv.RegisterPendingSession("real-signature-test", "192.168.1.100:9000", "mcp-server-1", pubPEM)
	if err != nil {
		t.Fatalf("RegisterPendingSession() error: %v", err)
	}

	// Get the pending session to build the payload
	pending, err := mv.GetPendingSession(token)
	if err != nil {
		t.Fatalf("GetPendingSession() error: %v", err)
	}

	// Build the payload (same way the verifier does)
	payload := []byte(fmt.Sprintf("%s:%s:%s:%d", pending.SessionID, pending.ServerID, pending.ClientAddr, pending.Timestamp.Unix()))

	// Sign the payload
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Now verify with the real public key
	result, err := mv.VerifyPendingSession(token, signature)
	if err != nil {
		t.Fatalf("VerifyPendingSession() error: %v", err)
	}
	if !result.Valid {
		t.Error("real signature should be valid")
	}
	t.Logf("Real signature verified successfully: key type=%s, fingerprint=%s", result.PublicKey.Type, result.PublicKey.Fingerprint)

	// Verify key type detection
	if result.PublicKey.Type != KeyTypeRSA {
		t.Errorf("expected KeyTypeRSA, got %s", result.PublicKey.Type)
	}
}

func TestMCPVerifier_ECDSA_RealSignatureFlow(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())
	mv.Enable()

	// Generate an ECDSA key pair
	priv, _, pubPEM, err := GenerateTestECDSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateTestECDSAKeyPair() error: %v", err)
	}

	// Register a session
	token, err := mv.RegisterPendingSession("ecdsa-signature-test", "10.0.0.1:5000", "ecdsa-server", pubPEM)
	if err != nil {
		t.Fatalf("RegisterPendingSession() error: %v", err)
	}

	pending, err := mv.GetPendingSession(token)
	if err != nil {
		t.Fatalf("GetPendingSession() error: %v", err)
	}

	// Build payload
	payload := []byte(fmt.Sprintf("%s:%s:%s:%d", pending.SessionID, pending.ServerID, pending.ClientAddr, pending.Timestamp.Unix()))

	// Sign with ECDSA
	h := sha256.New()
	h.Write(payload)
	hashed := h.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, priv, hashed)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify
	result, err := mv.VerifyPendingSession(token, sig)
	if err != nil {
		t.Fatalf("VerifyPendingSession() error: %v", err)
	}
	if !result.Valid {
		t.Error("ECDSA signature should be valid")
	}

	if result.PublicKey.Type != KeyTypeECDSA {
		t.Errorf("expected KeyTypeECDSA, got %s", result.PublicKey.Type)
	}
}

// ============================================================================
// TestMCPVerifier_ConcurrentAccess
// ============================================================================

func TestMCPVerifier_ConcurrentAccess(t *testing.T) {
	mv := NewMCPVerifier(DefaultMCPConfig())
	mv.Enable()

	done := make(chan bool, 50)
	for i := 0; i < 50; i++ {
		go func(n int) {
			token, _ := mv.RegisterPendingSession(
				"concurrent-session",
				"127.0.0.1:8080",
				"server",
				nil,
			)
			_ = mv.IsVerified(token)
			done <- true
		}(i)
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}

// ============================================================================
// Helper function
// ============================================================================

func generateTestPublicKeyPEM(t *testing.T) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
}
