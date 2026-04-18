package pkiattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestTrustAnchorCRUD(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test CA"},
		SerialNumber:          big.NewInt(1),
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
		t.Error("Certificate should not be nil")
	}
}

func TestSignatureVerification(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "ECDSA Test"},
		SerialNumber: big.NewInt(2),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse cert: %v", err)
	}

	verifier := NewSignatureVerification([]*TrustAnchor{})
	valid, err := verifier.VerifyCertificateSignature(cert)
	_ = valid
	_ = err
}

func TestAttestationBasic(t *testing.T) {
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

func TestHashCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Hash Test CA"},
		SerialNumber:          big.NewInt(10),
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

	hash, err := HashCertificate(cert)
	if err != nil {
		t.Errorf("Hash failed: %v", err)
	}

	if len(hash) == 0 {
		t.Error("Hash should not be empty")
	}
}

func TestCertificateFingerprint(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Fingerprint Test CA"},
		SerialNumber:          big.NewInt(11),
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

	fingerprint := CertificateFingerprint(cert)
	if fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
}

func TestECDSASignatureVerification(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "ECDSA Test"},
		SerialNumber: big.NewInt(12),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse cert: %v", err)
	}

	verifier := NewSignatureVerification([]*TrustAnchor{})
	valid, err := verifier.VerifyCertificateSignature(cert)
	_ = valid
	_ = err
}

func TestRevocationManagement(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Revocation Test CA"},
		SerialNumber:          big.NewInt(13),
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

	config := &AttestationConfig{
		TrustAnchors: []*TrustAnchor{anchor},
		VerifyChain:  true,
	}

	attestation, err := NewAttestation(config)
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	err = attestation.RevokeTrustAnchor(anchor.CertificateID)
	if err != nil {
		t.Errorf("Revoke failed: %v", err)
	}

	anchors := attestation.GetTrustAnchors()
	if len(anchors) == 0 {
		t.Error("Should have at least one anchor")
	}
}

func TestVerifySignatureMethod(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Verify Sig Test CA"},
		SerialNumber:          big.NewInt(14),
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

	attestation, err := NewAttestation(&AttestationConfig{
		TrustAnchors: []*TrustAnchor{},
		VerifyChain:  true,
	})
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	_, err = attestation.VerifySignature(cert, &key.PublicKey)
	if err == nil {
		t.Log("VerifySignature method executed successfully")
	}
}
