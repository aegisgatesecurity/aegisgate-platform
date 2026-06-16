// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Prompt Cache Poisoning Detection normalization (TODO-304)
//
// normalize.go provides the hash normalization policy for
// prompts. The policy is: lowercase + whitespace-collapse +
// trim. This is consistent with AIBOM's HashPrompt (TODO-302)
// and is a deliberate design choice: prompt-cache attacks
// frequently use case/whitespace variations to bypass naive
// detectors, and a deterministic hash means a poisoned
// prompt re-attests to the same hash across calls.

package promptcache

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// NormalizePrompt returns the canonical form of a prompt
// for hashing. The policy is:
//
//  1. Trim leading and trailing whitespace.
//  2. Convert to lowercase.
//  3. Collapse internal whitespace runs to a single space.
//
// The function is intentionally simple and side-effect free;
// it is the same algorithm AIBOM uses for prompts (see
// pkg/aibom/crypto.go's HashPrompt context). Two prompts
// that differ only in capitalization or whitespace produce
// the same hash.
//
// Example:
//
//	NormalizePrompt("  Hello, World!  ") == NormalizePrompt("hello, world!")
//	NormalizePrompt("Hello\nWorld")   == NormalizePrompt("hello world")
func NormalizePrompt(p string) string {
	// 1. Trim leading/trailing whitespace.
	p = strings.TrimSpace(p)
	// 2. Lowercase. Note: this is Unicode-aware via the
	// strings package (ToLower handles multi-byte
	// runes correctly). For prompt-cache purposes, ASCII
	// lowercasing is sufficient, but we use the full
	// Unicode-aware version for consistency with what
	// LLM providers do on the cache key side.
	p = strings.ToLower(p)
	// 3. Collapse internal whitespace runs to a single
	// space. We use Fields (which splits on any Unicode
	// whitespace) and Join with a single space, which
	// both trims and collapses in one pass. This is
	// the same approach AIBOM uses.
	return strings.Join(strings.Fields(p), " ")
}

// HashPrompt returns the SHA-256 hex digest of the
// normalized prompt. The result is a 64-character hex
// string. This is the value that goes into:
//
//   - PromptAttestation.PromptHash (the signed payload)
//   - The envelope subject (as the <id> component of
//     "aegisgate://prompt/<hash>")
//
// Both must use the SAME normalization, otherwise the
// verify path will reject the attestation. The verify path
// extracts the hash from the envelope subject and compares
// it to PromptAttestation.PromptHash; if the caller
// computed PromptHash with a different normalization, the
// comparison will fail.
//
// Example:
//
//	HashPrompt("Hello, World!")  // 64 hex chars
//	HashPrompt("hello, world!")  // same 64 hex chars
//	HashPrompt("HELLO, WORLD!")  // same 64 hex chars
func HashPrompt(p string) string {
	normalized := NormalizePrompt(p)
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// hashSHA256Hex returns the hex-encoded SHA-256 of data.
// Used for the issuer's shortfp component (first 16 hex
// chars of SHA-256(attestor_id)) and the CacheKey helper
// fingerprint.
func hashSHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
