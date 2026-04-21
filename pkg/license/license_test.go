package license

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// helper to generate a signed license string for a given payload and private key
func signLicense(t *testing.T, payload LicensePayload, priv *ecdsa.PrivateKey) string {
	// Marshal payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	// Compute hash
	hash := sha256.Sum256(payloadBytes)
	// Sign
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Build 64‑byte signature (r||s)
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	// Assemble full license structure
	lk := LicenseKeyFormat{Payload: payload, Signature: sigB64}
	lkBytes, err := json.Marshal(lk)
	if err != nil {
		t.Fatalf("marshal license: %v", err)
	}
	return base64.StdEncoding.EncodeToString(lkBytes)
}

func TestValidateEmptyKey(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	res := mgr.Validate("")
	if !res.Valid || res.Tier != tier.TierCommunity {
		t.Fatalf("expected community tier for empty key, got %+v", res)
	}
}

func TestValidateMalformedKey(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	// random string not base64
	res := mgr.Validate("not-base64!!!")
	if res.Valid {
		t.Fatalf("expected invalid result for malformed key")
	}
}

func TestValidateSignedLicense(t *testing.T) {
	// generate test ECDSA P‑256 key pair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// export public key PEM for manager
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))

	mgr, err := NewManagerWithKey(pubPEM)
	if err != nil {
		t.Fatalf("new manager with key: %v", err)
	}

	// build a payload for a Developer tier, valid for 30 days
	now := time.Now().UTC()
	payload := LicensePayload{
		LicenseID:  "test-license-123",
		Tier:       "developer",
		Customer:   "test-customer",
		IssuedAt:   now,
		ExpiresAt:  now.Add(30 * 24 * time.Hour),
		Features:   []string{"featureA", "featureB"},
		MaxServers: 5,
		MaxUsers:   10,
	}
	licenseStr := signLicense(t, payload, priv)

	res := mgr.Validate(licenseStr)
	if !res.Valid {
		t.Fatalf("expected valid license, got error: %v", res.Error)
	}
	if res.Tier != tier.TierDeveloper {
		t.Fatalf("expected developer tier, got %s", res.Tier.DisplayName())
	}
	if res.GracePeriod {
		t.Fatalf("should not be in grace period")
	}
}

func TestGracePeriod(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))
	mgr, _ := NewManagerWithKey(pubPEM)
	now := time.Now().UTC()
	payload := LicensePayload{
		LicenseID:  "expired-license",
		Tier:       "professional",
		Customer:   "cust",
		IssuedAt:   now.Add(-40 * 24 * time.Hour),
		ExpiresAt:  now.Add(-1 * time.Hour), // expired 1 hour ago
		Features:   []string{},
		MaxServers: 0,
		MaxUsers:   0,
	}
	// sign payload
	payloadBytes, _ := json.Marshal(payload)
	hash := sha256.Sum256(payloadBytes)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	lk := LicenseKeyFormat{Payload: payload, Signature: sigB64}
	lkBytes, _ := json.Marshal(lk)
	licenseStr := base64.StdEncoding.EncodeToString(lkBytes)

	res := mgr.Validate(licenseStr)
	if !res.Valid {
		t.Fatalf("license should be considered valid during grace period")
	}
	if !res.GracePeriod {
		t.Fatalf("expected grace period flag")
	}
	if res.Tier != tier.TierProfessional {
		t.Fatalf("expected professional tier, got %s", res.Tier.DisplayName())
	}
}
