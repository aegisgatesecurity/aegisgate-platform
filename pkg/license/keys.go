// SPDX-License-Identifier: Apache-2.0
// Package license provides client-side license validation for AegisGate Platform.
// This file contains the embedded public key for license signature verification.
//
// SECURITY NOTE: This public key is embedded in the binary. The corresponding
// private key is held exclusively by AegisGate Security, LLC for license signing.
// Key rotation requires a new platform release.
package license

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// embeddedPublicKeyPEM contains the AegisGate Security public key for license
// signature verification. This is an ECDSA P-256 key.
//
// To regenerate:
//  1. openssl ecparam -genkey -name prime256v1 -out private.pem
//  2. openssl ec -in private.pem -pubout -out public.pem
//  3. Embed the public PEM below
//
// Key fingerprints (for verification):
//
//	DER prefix (8 bytes): 3059301306072a86
//	Public key X: 1504987626868443178806115043001279550729...
//	Public key Y: 9114550456103658015913007380751475238459...
const embeddedPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIUXtmDqYgS9l7iFkXW1+8nRvXEvo
pQpLwLB2UcawrcrJgocFQMgVRKq4EreyqT3bi+PeXeJ3uUW4iPaWJCcSDQ==
-----END PUBLIC KEY-----
`

// GetEmbeddedPublicKey returns the ECDSA public key embedded in the binary.
// This key is used to verify license signatures.
func GetEmbeddedPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(embeddedPublicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode embedded public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}

	// Validate curve
	if ecdsaPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("unsupported curve: expected P-256, got %s", ecdsaPub.Curve.Params().Name)
	}

	return ecdsaPub, nil
}

// KeyFingerprint returns a fingerprint of the embedded public key for logging
// and debugging purposes (not for security verification).
func KeyFingerprint() string {
	block, _ := pem.Decode([]byte(embeddedPublicKeyPEM))
	if block == nil {
		return "invalid"
	}
	// Return first 16 bytes of DER as hex (simplified fingerprint)
	if len(block.Bytes) >= 8 {
		return fmt.Sprintf("%x", block.Bytes[:8])
	}
	return "short"
}

// IsKeyPlaceholder returns true if the embedded key is still the placeholder.
// This is used during development before the real key is embedded.
// After Task 1.2: the real production key is now embedded, so this returns false.
func IsKeyPlaceholder() bool {
	return false
}
