package pkiattest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestBasicIntegration(t *testing.T) {
	config := &AttestationConfig{
		TrustAnchors: []*TrustAnchor{},
		VerifyChain:  true,
	}

	attestation, err := NewAttestation(config)
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	if attestation == nil {
		t.Fatal("Attestation should not be nil")
	}
}

func TestCRLManagerIntegration(t *testing.T) {
	manager := NewCRLManager(5*time.Minute, 5*time.Minute)
	if manager == nil {
		t.Fatal("CRLManager should not be nil")
	}
}

func TestOCSPManagerIntegration(t *testing.T) {
	manager := NewOCSPManager(5*time.Minute, 5*time.Minute)
	if manager == nil {
		t.Fatal("OCSPManager should not be nil")
	}
}

func TestSignatureVerificationIntegration(t *testing.T) {
	verification := NewSignatureVerification([]*TrustAnchor{})
	if verification == nil {
		t.Fatal("SignatureVerification should not be nil")
	}
}

func TestTrustAnchorIntegration(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Integration Test CA"},
		SerialNumber:          big.NewInt(100),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse cert: %v", err)
	}

	anchor, err := NewTrustAnchor(cert, "test")
	if err != nil {
		t.Fatalf("Failed to create anchor: %v", err)
	}

	if anchor.Certificate == nil {
		t.Fatal("Anchor certificate should not be nil")
	}
}

func TestBackdoorPrevention(t *testing.T) {
	prevention := NewBackdoorPrevention()
	if prevention == nil {
		t.Fatal("BackdoorPrevention should not be nil")
	}
}
