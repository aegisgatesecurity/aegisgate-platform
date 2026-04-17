// Package pkiattest provides PKI attestation services for the AegisGate AI Security Gateway.
//
// This package implements cryptographic attestation, certificate validation,
// revocation checking, and trust anchor management to prevent trust lattice
// vulnerabilities in the MITM interception system.
//
// Main Features:
//   - Certificate chain validation and verification
//   - Digital signature verification (RSA, ECDSA)
//   - Trust anchor management with revocation support
//   - CRL (Certificate Revocation List) processing
//   - OCSP (Online Certificate Status Protocol) integration
//   - Certificate revocation caching and performance optimization
//
// Trust Lattice Protection:
//
//	The PKI Attestation system prevents the "trust lattice" vulnerability
//	by ensuring that:
//	1. All MITM-generated certificates are cryptographically signed
//	2. Certificate chains can be fully verified back to trust anchors
//	3. Revoked certificates are detected before being trusted
//	4. Backdoors or compromised CAs cannot silently compromise the system
package pkiattest
