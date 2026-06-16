// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM crypto helpers (TODO-302)
//
// crypto.go provides the small crypto helpers used by
// sign.go and generator.go. The package delegates the
// heavy lifting (ECDSA, JCS canonicalization, key
// rotation) to the attestation package and pkg/ioc.
// This file only contains the SHA-256 helpers needed
// for prompt/corpus fingerprinting and the issuer's
// shortfp component.

package aibom

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashSHA256Hex returns the hex-encoded SHA-256 of data.
// Used for prompt fingerprints, corpus fingerprints, and
// the shortfp component of the issuer.
func hashSHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
