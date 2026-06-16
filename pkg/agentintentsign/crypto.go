// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Intent Signing crypto helpers (TODO-303)
//
// crypto.go provides the small crypto helpers used by
// sign.go and types.go. The package delegates the heavy
// lifting (ECDSA, JCS canonicalization, key rotation) to
// the attestation package and pkg/ioc. This file only
// contains the SHA-256 helper needed for the issuer's
// shortfp component.

package agentintentsign

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashSHA256Hex returns the hex-encoded SHA-256 of data.
// Used for the issuer's shortfp component (first 16 hex
// chars of SHA-256(agent_id)).
func hashSHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
