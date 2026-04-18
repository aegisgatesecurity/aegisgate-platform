package core

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"
)

// generateTestKeyPair creates RSA key pair for testing
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// licenseToSign creates the string that gets signed
func licenseToSign(l *License) string {
	return l.ID + l.Email + l.ExpiresAt.Format(time.RFC3339)
}

// TestRSASignature verifies RSA signing and verification
func TestRSASignature(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	license := &License{
		ID:        "test-license-001",
		Email:     "admin@test.com",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Features:  []string{"ai_proxy", "openai"},
	}

	// Sign it
	data := licenseToSign(license)
	h := sha256.Sum256([]byte(data))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify with correct key
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	license.Signature = encodedSig

	sigBytes, _ := base64.StdEncoding.DecodeString(license.Signature)
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, h[:], sigBytes)
	if err != nil {
		t.Errorf("Verification with correct key failed: %v", err)
	}

	// Verify with wrong key should fail
	wrongKey, _ := generateTestKeyPair(t)
	wrongPub := wrongKey.PublicKey
	err = rsa.VerifyPKCS1v15(&wrongPub, crypto.SHA256, h[:], sigBytes)
	if err == nil {
		t.Error("Verification with wrong key should have failed")
	}
}

// TestRSASignatureTampered verifies tampered data fails verification
func TestRSASignatureTampered(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)

	license := &License{
		ID:        "test-license-002",
		Email:     "admin@test.com",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Features:  []string{"ai_proxy"},
	}

	data := licenseToSign(license)
	h := sha256.Sum256([]byte(data))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
	license.Signature = base64.StdEncoding.EncodeToString(signature)

	// Tamper with data
	oldID := license.ID
	license.ID = "tampered-id"

	// Verification should fail
	dataTampered := licenseToSign(license)
	hTampered := sha256.Sum256([]byte(dataTampered))
	sigBytes, _ := base64.StdEncoding.DecodeString(license.Signature)
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hTampered[:], sigBytes)
	if err == nil {
		t.Error("Verification of tampered license should have failed")
	}

	// Restore
	license.ID = oldID
}

// TestLicenseStructFields verifies the License struct fields
func TestLicenseStructFields(t *testing.T) {
	expires := time.Now().Add(24 * time.Hour)
	license := &License{
		ID:           "test-001",
		Type:         LicenseTypeCommunity,
		Email:        "test@example.com",
		Organization: "Test Org",
		Tiers:        []Tier{TierCommunity, TierDeveloper},
		IssuedAt:     time.Now(),
		ExpiresAt:    expires,
		MaxServers:   10,
		Features:     []string{"ai_proxy"},
		Signature:    "dGVzdA==",
	}

	if license.ID != "test-001" {
		t.Errorf("Expected ID test-001, got %s", license.ID)
	}
	if license.Type != LicenseTypeCommunity {
		t.Errorf("Expected Type Community, got %v", license.Type)
	}
	if len(license.Tiers) != 2 {
		t.Errorf("Expected 2 tiers, got %d", len(license.Tiers))
	}
	if license.MaxServers != 10 {
		t.Errorf("Expected MaxServers 10, got %d", license.MaxServers)
	}
}

// TestLicenseExpiration tests license expiration logic
func TestLicenseExpiration(t *testing.T) {
	now := time.Now()

	// Not expired
	notExpired := &License{
		ID:        "not-expired",
		ExpiresAt: now.Add(24 * time.Hour),
	}

	if now.After(notExpired.ExpiresAt) {
		t.Error("License should not be expired")
	}

	// Already expired
	expired := &License{
		ID:        "expired",
		ExpiresAt: now.Add(-24 * time.Hour),
	}

	if !now.After(expired.ExpiresAt) {
		t.Error("License should be expired")
	}
}
