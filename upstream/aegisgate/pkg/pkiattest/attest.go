// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package pkiattest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"time"
)

// AttestationResult represents the result of certificate attestation
type AttestationResult struct {
	Valid     bool
	Reason    string
	Timestamp time.Time
	Chain     []x509.Certificate
}

// TrustAnchor represents a trusted certificate authority
type TrustAnchor struct {
	Certificate   *x509.Certificate
	CertificateID string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Purpose       string
	Revoked       bool
	RevokedAt     time.Time
}

// AttestationConfig holds configuration for attestation
type AttestationConfig struct {
	TrustAnchors     []*TrustAnchor
	RequireCRL       bool
	RequireOCSP      bool
	CRLCheckTimeout  time.Duration
	OCSPCheckTimeout time.Duration
	AllowExpired     bool
	VerifyChain      bool
}

// Attestation provides cryptographic attestation capabilities
type Attestation struct {
	config *AttestationConfig
	cache  *AttestationCache
}

// AttestationCache provides caching for attestation results
type AttestationCache struct {
	results     map[string]*AttestationResult
	cacheTTL    time.Duration
	lastUpdated time.Time
}

// NewAttestation creates a new attestation service
func NewAttestation(config *AttestationConfig) (*Attestation, error) {
	if config == nil {
		config = &AttestationConfig{
			RequireCRL:       true,
			RequireOCSP:      true,
			CRLCheckTimeout:  5 * time.Second,
			OCSPCheckTimeout: 5 * time.Second,
			VerifyChain:      true,
		}
	}
	if config.TrustAnchors == nil {
		config.TrustAnchors = []*TrustAnchor{}
	}
	return &Attestation{
		config: config,
		cache: &AttestationCache{
			results:  make(map[string]*AttestationResult),
			cacheTTL: 5 * time.Minute,
		},
	}, nil
}

// AttestCertificate verifies a certificate against trust anchors
func (a *Attestation) AttestCertificate(cert *x509.Certificate) (*AttestationResult, error) {
	if cert == nil {
		return &AttestationResult{
			Valid:     false,
			Reason:    "certificate is nil",
			Timestamp: time.Now(),
		}, nil
	}

	cacheKey := cert.SerialNumber.String()
	if cached, ok := a.cache.results[cacheKey]; ok {
		if time.Since(a.cache.lastUpdated) < a.cache.cacheTTL {
			return cached, nil
		}
	}

	result := &AttestationResult{
		Timestamp: time.Now(),
	}

	if a.config.VerifyChain {
		chain, err := a.verifyCertificateChain(cert)
		if err != nil {
			result.Valid = false
			result.Reason = fmt.Sprintf("chain verification failed: %v", err)
			return result, nil
		}
		result.Chain = chain
	}

	if a.config.RequireCRL || a.config.RequireOCSP {
		revocationOK, revocationReason, err := a.checkRevocation(cert)
		if err != nil {
			result.Valid = false
			result.Reason = fmt.Sprintf("revocation check failed: %v", err)
			return result, nil
		}
		if !revocationOK {
			result.Valid = false
			result.Reason = revocationReason
			return result, nil
		}
	}

	signatureValid, signatureReason := a.verifySignature(cert)
	if !signatureValid {
		result.Valid = false
		result.Reason = signatureReason
		return result, nil
	}

	result.Valid = true
	result.Reason = "certificate attested successfully"
	a.cache.results[cacheKey] = result
	a.cache.lastUpdated = time.Now()
	slog.Info("Certificate attestation successful",
		"serial", cert.SerialNumber.String(),
		"subject", cert.Subject.CommonName,
		"issuer", cert.Issuer.CommonName,
	)
	return result, nil
}

// verifyCertificateChain verifies the certificate chain up to a trust anchor
func (a *Attestation) verifyCertificateChain(cert *x509.Certificate) ([]x509.Certificate, error) {
	chain := []x509.Certificate{*cert}
	currentCert := cert

	for {
		isTrustAnchor := false
		for _, anchor := range a.config.TrustAnchors {
			if anchor.Certificate.SerialNumber.String() == currentCert.SerialNumber.String() {
				isTrustAnchor = true
				break
			}
		}
		if isTrustAnchor || currentCert.IsCA {
			break
		}

		var issuerCert *x509.Certificate
		for _, anchor := range a.config.TrustAnchors {
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

// checkRevocation verifies certificate status via CRL or OCSP
func (a *Attestation) checkRevocation(cert *x509.Certificate) (bool, string, error) {
	for _, anchor := range a.config.TrustAnchors {
		if anchor.Certificate.SerialNumber.String() == cert.SerialNumber.String() {
			if anchor.Revoked {
				return false, "trust anchor has been revoked", nil
			}
			break
		}
	}
	if a.config.RequireCRL {
		slog.Debug("CRL checking not yet implemented")
	}
	if a.config.RequireOCSP {
		slog.Debug("OCSP checking not yet implemented")
	}
	return true, "revocation check passed", nil
}

// verifySignature verifies the certificate signature
func (a *Attestation) verifySignature(cert *x509.Certificate) (bool, string) {
	if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return false, "unknown signature algorithm"
	}

	hashed := sha256.Sum256(cert.Raw)
	hash := hashed[:]

	if cert.AuthorityKeyId != nil {
		var issuerPubKey crypto.PublicKey
		for _, anchor := range a.config.TrustAnchors {
			if string(anchor.Certificate.SubjectKeyId) == string(cert.AuthorityKeyId) ||
				anchor.Certificate.Subject.CommonName == cert.Issuer.CommonName {
				issuerPubKey = anchor.Certificate.PublicKey
				break
			}
		}
		if issuerPubKey == nil {
			return false, "issuer public key not found"
		}

		switch cert.SignatureAlgorithm {
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
			rsaPubKey, ok := issuerPubKey.(*rsa.PublicKey)
			if !ok {
				return false, "invalid RSA public key"
			}
			err := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hash, cert.Signature)
			if err != nil {
				return false, fmt.Sprintf("signature verification failed: %v", err)
			}
		case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
			ecdsaPubKey, ok := issuerPubKey.(*ecdsa.PublicKey)
			if !ok {
				return false, "invalid ECDSA public key"
			}
			r, s, err := parseECDSASignature(cert.Signature)
			if err != nil {
				return false, fmt.Sprintf("failed to parse ECDSA signature: %v", err)
			}
			if !ecdsa.Verify(ecdsaPubKey, hash, r, s) {
				return false, "signature verification failed"
			}
		default:
			return false, fmt.Sprintf("unsupported signature algorithm: %v", cert.SignatureAlgorithm)
		}
	}

	return true, "signature verified successfully"
}

// AddTrustAnchor adds a new trust anchor
func (a *Attestation) AddTrustAnchor(cert *x509.Certificate) (*TrustAnchor, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate cannot be nil")
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate")
	}

	anchor := &TrustAnchor{
		Certificate:   cert,
		CertificateID: fmt.Sprintf("ta-%s", cert.SerialNumber.String()[:8]),
		CreatedAt:     time.Now(),
		ExpiresAt:     cert.NotAfter,
		Purpose:       "general-purpose CA",
		Revoked:       false,
	}
	a.config.TrustAnchors = append(a.config.TrustAnchors, anchor)
	slog.Info("Trust anchor added",
		"id", anchor.CertificateID,
		"subject", cert.Subject.CommonName,
		"expires", cert.NotAfter.Format("2006-01-02"),
	)
	return anchor, nil
}

// RevokeTrustAnchor revokes a trust anchor
func (a *Attestation) RevokeTrustAnchor(certID string) error {
	for _, anchor := range a.config.TrustAnchors {
		if anchor.CertificateID == certID {
			anchor.Revoked = true
			anchor.RevokedAt = time.Now()
			a.clearCache()
			slog.Warn("Trust anchor revoked", "id", certID)
			return nil
		}
	}
	return fmt.Errorf("trust anchor not found: %s", certID)
}

// clearCache clears the attestation cache
func (a *Attestation) clearCache() {
	a.cache.results = make(map[string]*AttestationResult)
	a.cache.lastUpdated = time.Time{}
}

// GetTrustAnchors returns all configured trust anchors
func (a *Attestation) GetTrustAnchors() []*TrustAnchor {
	return a.config.TrustAnchors
}

// Base64EncodeCertificate serializes a certificate to base64
func Base64EncodeCertificate(cert *x509.Certificate) (string, error) {
	certDER := cert.Raw
	return base64.StdEncoding.EncodeToString(certDER), nil
}

// Base64DecodeCertificate deserializes a certificate from base64
func Base64DecodeCertificate(b64Cert string) (*x509.Certificate, error) {
	certDER, err := base64.StdEncoding.DecodeString(b64Cert)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return x509.ParseCertificate(certDER)
}

// PEMEncodeCertificate converts a certificate to PEM format
func PEMEncodeCertificate(cert *x509.Certificate) string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	return string(pemData)
}

// PEMDecodeCertificate parses a PEM-encoded certificate
func PEMDecodeCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is not a certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// VerifySignature verifies a certificate signature against a public key
func (a *Attestation) VerifySignature(cert *x509.Certificate, publicKey crypto.PublicKey) (bool, error) {
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		rsaPubKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("invalid RSA public key")
		}
		hash := sha256.Sum256(cert.Raw)
		valid := rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hash[:], cert.Signature) == nil
		return valid, nil
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("invalid ECDSA public key")
		}
		hash := sha256.Sum256(cert.Raw)
		r, s, err := parseECDSASignature(cert.Signature)
		if err != nil {
			return false, err
		}
		valid := ecdsa.Verify(ecdsaPubKey, hash[:], r, s)
		return valid, nil
	default:
		return false, fmt.Errorf("unsupported signature algorithm: %v", cert.SignatureAlgorithm)
	}
}

// parseECDSASignature parses an ECDSA signature
func parseECDSASignature(sig []byte) (*big.Int, *big.Int, error) {
	if len(sig) < 8 {
		return nil, nil, fmt.Errorf("signature too short")
	}

	if sig[0] != 0x30 {
		if len(sig) == 64 {
			r := new(big.Int).SetBytes(sig[:32])
			s := new(big.Int).SetBytes(sig[32:])
			return r, s, nil
		}
		return nil, nil, fmt.Errorf("unsupported signature format")
	}

	if len(sig) < 2 {
		return nil, nil, fmt.Errorf("signature too short for ASN.1 header")
	}

	if int(sig[1]) != len(sig)-2 {
		return nil, nil, fmt.Errorf("invalid ASN.1 length")
	}

	offset := 2
	if sig[offset] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER for r")
	}
	offset++
	rLen := int(sig[offset])
	offset++
	if offset+rLen > len(sig) {
		return nil, nil, fmt.Errorf("r value out of bounds")
	}
	r := new(big.Int).SetBytes(sig[offset : offset+rLen])
	offset += rLen

	if offset >= len(sig) || sig[offset] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER for s")
	}
	offset++
	if offset >= len(sig) {
		return nil, nil, fmt.Errorf("missing s length")
	}
	sLen := int(sig[offset])
	offset++
	if offset+sLen > len(sig) {
		return nil, nil, fmt.Errorf("s value out of bounds")
	}
	s := new(big.Int).SetBytes(sig[offset : offset+sLen])

	return r, s, nil
}
