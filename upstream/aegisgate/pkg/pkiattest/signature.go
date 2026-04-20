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
	"fmt"
)

// SignatureVerification validates cryptographic signatures
type SignatureVerification struct {
	trustAnchors []*TrustAnchor
}

// NewSignatureVerification creates a new signature verification service
func NewSignatureVerification(trustAnchors []*TrustAnchor) *SignatureVerification {
	return &SignatureVerification{
		trustAnchors: trustAnchors,
	}
}

// VerifyCertificateSignature verifies a certificate's signature
func (sv *SignatureVerification) VerifyCertificateSignature(cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, fmt.Errorf("certificate cannot be nil")
	}

	if len(cert.Signature) == 0 {
		return false, fmt.Errorf("certificate has no signature")
	}

	issuerPubKey, err := sv.findIssuerPublicKey(cert)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256(cert.Raw)

	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		return sv.verifyRSASignature(issuerPubKey, hashed[:], cert.Signature, cert.SignatureAlgorithm)
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return sv.verifyECDSASignature(issuerPubKey, hashed[:], cert.Signature)
	default:
		return false, fmt.Errorf("unsupported signature algorithm: %v", cert.SignatureAlgorithm)
	}
}

// findIssuerPublicKey finds the public key that signed a certificate
func (sv *SignatureVerification) findIssuerPublicKey(cert *x509.Certificate) (crypto.PublicKey, error) {
	if cert.AuthorityKeyId != nil {
		for _, anchor := range sv.trustAnchors {
			if string(anchor.Certificate.SubjectKeyId) == string(cert.AuthorityKeyId) {
				return anchor.Certificate.PublicKey, nil
			}
		}
	}

	for _, anchor := range sv.trustAnchors {
		if anchor.Certificate.Subject.CommonName == cert.Issuer.CommonName {
			return anchor.Certificate.PublicKey, nil
		}
	}

	return nil, fmt.Errorf("issuer public key not found for certificate")
}

// verifyRSASignature verifies an RSA signature
func (sv *SignatureVerification) verifyRSASignature(pubKey crypto.PublicKey, hash, signature []byte, algo x509.SignatureAlgorithm) (bool, error) {
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not RSA")
	}

	var cryptoAlg crypto.Hash
	switch algo {
	case x509.SHA256WithRSA:
		cryptoAlg = crypto.SHA256
	case x509.SHA384WithRSA:
		cryptoAlg = crypto.SHA384
	case x509.SHA512WithRSA:
		cryptoAlg = crypto.SHA512
	default:
		return false, fmt.Errorf("unsupported RSA signature algorithm")
	}

	err := rsa.VerifyPKCS1v15(rsaPubKey, cryptoAlg, hash, signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

// verifyECDSASignature verifies an ECDSA signature
func (sv *SignatureVerification) verifyECDSASignature(pubKey crypto.PublicKey, hash, signature []byte) (bool, error) {
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not ECDSA")
	}

	r, sInt, err := parseECDSASignature(signature)
	if err != nil {
		return false, err
	}

	valid := ecdsa.Verify(ecdsaPubKey, hash, r, sInt)
	return valid, nil
}
