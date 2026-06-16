// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CVE Entry crypto helpers (TODO-305)
//
// crypto.go contains the hash helper used by entry.go's
// buildIssuer. Implemented locally to keep pkg/cve's
// dependency surface minimal (no crypto/sha256 import
// in entry.go).

package cve

import "crypto/sha256"

// _hashSHA256Hex returns the hex-encoded SHA-256 of b.
func _hashSHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hexEncode(sum[:])
}

// hexEncode is a minimal hex encoder (lowercase). We
// implement it locally (instead of importing
// encoding/hex) to keep the package imports clean.
func hexEncode(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexChars[c>>4]
		out[i*2+1] = hexChars[c&0x0f]
	}
	return string(out)
}

// isHexString returns true if s is non-empty and
// contains only hex characters (0-9, a-f, A-F). Used by
// the issuer-format tests to validate the shortfp
// component. Pattern from TODO-301 C2 / TODO-303.
func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
