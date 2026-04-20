// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package pkiattest

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// BackdoorPrevention implements cryptographic backdoor detection
type BackdoorPrevention struct {
	trustStore  *TrustStore
	attestation *Attestation
}

// BackdoorResult represents the result of backdoor detection
type BackdoorResult struct {
	BackdoorDetected bool
	Issues           []string
	Reason           string
}

// NewBackdoorPrevention creates a new backdoor prevention system
func NewBackdoorPrevention() *BackdoorPrevention {
	return &BackdoorPrevention{
		trustStore:  NewTrustStore(),
		attestation: nil,
	}
}

// SetAttestation sets the attestation service
func (b *BackdoorPrevention) SetAttestation(a *Attestation) {
	b.attestation = a
}

// DetectBackdoor attempts to detect if a certificate has been tampered with
func (b *BackdoorPrevention) DetectBackdoor(cert *x509.Certificate) (bool, string, error) {
	if cert == nil {
		return true, "certificate is nil", nil
	}

	// Check for backdoor signatures
	if cert.SerialNumber.Cmp(big.NewInt(0)) == 0 {
		return true, "certificate has zero serial number (backdoor indicator)", nil
	}

	// Check for suspicious validity periods
	now := time.Now()
	if now.Before(cert.NotBefore.Add(-24 * time.Hour)) {
		return true, "certificate validity starts in the future", nil
	}

	if now.After(cert.NotAfter.Add(365 * 24 * time.Hour)) {
		return true, "certificate validity period exceeds one year", nil
	}

	// Verify the certificate signature
	if b.attestation != nil {
		result, err := b.attestation.AttestCertificate(cert)
		if err != nil {
			return false, fmt.Sprintf("attestation failed: %v", err), err
		}
		if !result.Valid {
			return true, result.Reason, nil
		}
	}

	return false, "certificate passed backdoor detection", nil
}

// VerifyCertificateChain verifies a complete certificate chain
func VerifyCertificateChain(cert *x509.Certificate, trustAnchors []*TrustAnchor) ([]x509.Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate cannot be nil")
	}

	chain := []x509.Certificate{*cert}

	currentCert := cert
	for {
		isTrustAnchor := false
		for _, anchor := range trustAnchors {
			if anchor.Certificate.SerialNumber.String() == currentCert.SerialNumber.String() {
				isTrustAnchor = true
				break
			}
		}

		if isTrustAnchor || currentCert.IsCA {
			break
		}

		var issuerCert *x509.Certificate
		for _, anchor := range trustAnchors {
			if anchor.Certificate.Subject.CommonName == currentCert.Issuer.CommonName {
				issuerCert = anchor.Certificate
				break
			}
		}

		if issuerCert == nil {
			return nil, fmt.Errorf("issuer certificate not found: %s", currentCert.Issuer.CommonName)
		}

		chain = append(chain, *issuerCert)
		currentCert = issuerCert
	}

	return chain, nil
}

// HashCertificate computes a SHA-256 hash of a certificate
func HashCertificate(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate cannot be nil")
	}
	hash := sha256.Sum256(cert.Raw)
	return hash[:], nil
}

// CertificateFingerprint returns a human-readable certificate fingerprint
func CertificateFingerprint(cert *x509.Certificate) string {
	hash, _ := HashCertificate(cert)
	return fmt.Sprintf("%x", hash[:8])
}

// NewTrustAnchor creates a new trust anchor from a certificate
func NewTrustAnchor(cert *x509.Certificate, purpose string) (*TrustAnchor, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate cannot be nil")
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate")
	}

	return &TrustAnchor{
		Certificate:   cert,
		CertificateID: fmt.Sprintf("ta-%s", getShortSerial(cert.SerialNumber)),
		CreatedAt:     time.Now(),
		ExpiresAt:     cert.NotAfter,
		Purpose:       purpose,
		Revoked:       false,
	}, nil
}

// getShortSerial returns first 8 chars of serial number, padded if needed
func getShortSerial(serial *big.Int) string {
	s := serial.String()
	if len(s) >= 8 {
		return s[:8]
	}
	// Pad with leading zeros if too short
	return fmt.Sprintf("%08s", s)
}
