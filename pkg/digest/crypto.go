// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest crypto helpers
//
// crypto.go contains local crypto helpers (SHA-256 +
// hex) used by the digest's sign/verify path.

package digest

import (
	"crypto/sha256"
)

// hashSHA256HexShort returns the first 16 hex chars
// of SHA-256(s). Used for the issuer's shortfp.
func hashSHA256HexShort(s string) string {
	sum := sha256.Sum256([]byte(s))
	hex := hexEncode(sum[:])
	if len(hex) < 16 {
		return hex
	}
	return hex[:16]
}

// hexEncode is a minimal lowercase hex encoder.
func hexEncode(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexChars[c>>4]
		out[i*2+1] = hexChars[c&0x0f]
	}
	return string(out)
}
