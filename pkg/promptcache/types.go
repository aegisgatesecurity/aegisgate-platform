// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Prompt Cache Poisoning Detection types (TODO-304)
//
// types.go defines the data structures for prompt-cache
// attestations. The shapes here are the contract between
// the attestor (writer), the verifier (reader), and any
// auditor that inspects the attestation later.
//
// # Design rule
//
// PromptAttestation is what gets wrapped by the attestation
// envelope. Its fields are stable, sorted alphabetically
// at the top level by JSON tag, and serializable to JSON
// deterministically. The JCS canonicalizer (inside
// attestation.Sign) sorts keys at every level.

package promptcache

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// =====================================================================
// PromptAttestation
// =====================================================================

// PromptAttestation is the signed payload. The required
// fields (PromptHash, Source, ModelID, AttestorID,
// AttestedAt, CacheKey) are what the verifier checks; the
// rest is metadata.
//
// The struct is the canonical input to Attest. The envelope
// wraps the JSON-encoded form of this struct (after
// validation).
type PromptAttestation struct {
	// PromptHash is the SHA-256 hex of the normalized
	// prompt. The caller computes this with HashPrompt
	// (lowercase + whitespace-collapse, then SHA-256).
	// The envelope's subject is "aegisgate://prompt/<this>".
	PromptHash string `json:"prompt_hash"`
	// Source identifies where the prompt came from. Examples:
	// "user-supplied", "mcp-tool:acme-corp/calendar",
	// "system", "rag-corpus:policy-docs-v3". The signer
	// does not interpret this; it is stored verbatim in
	// the signed payload.
	Source string `json:"source"`
	// ModelID identifies the LLM model that the prompt
	// is intended for. Examples: "claude-3-5-sonnet-
	// 20241022", "openai/gpt-4-turbo". The signer does
	// not interpret this; it is stored verbatim.
	ModelID string `json:"model_id"`
	// AttestorID identifies WHO is making this attestation
	// claim. Examples: "acme-corp:prod-gateway",
	// "anthropic:managed", "aegisgate:cli". The signer
	// does not interpret this; it is stored verbatim.
	// The verifier checks that the envelope's issuer
	// references the same attestor_id (defense against
	// a compromised key writing fake attestations).
	AttestorID string `json:"attestor_id"`
	// AttestedAt is the timestamp when the attestation
	// was produced. Stored in the signed payload (NOT
	// just in the envelope metadata) so the auditor can
	// see the original signing time. Defaults to now()
	// in UTC if zero.
	AttestedAt time.Time `json:"attested_at"`
	// ValidUntil is the timestamp after which the
	// attestation is no longer valid. The verifier
	// rejects attestations where ValidUntil < now.
	// Defaults to AttestedAt + DefaultPromptCacheTTL
	// if zero. Clamped to AttestedAt + MaxPromptCacheTTL
	// at Sign time.
	ValidUntil time.Time `json:"valid_until"`
	// CacheKey is the opaque cache key the LLM provider
	// uses (e.g., the SHA-256 of the prompt's prefix,
	// or a vendor-specific key). Stored in the signed
	// payload so the auditor can correlate the
	// attestation with the cache entry it covers.
	// The signer does not interpret this; it is stored
	// verbatim. Empty is allowed (the verifier does
	// not check the cache key against the prompt hash
	// in v0.1; that's v0.2 scope).
	CacheKey string `json:"cache_key,omitempty"`
	// Metadata is an optional free-form metadata blob
	// (e.g., session id, request id, tenant id, content
	// type). The signer does not interpret it; it is
	// stored verbatim. Empty is fine.
	Metadata string `json:"metadata,omitempty"`
}

// Validate checks the PromptAttestation for required
// fields and length limits. Returns an error if any
// check fails.
//
// The check is performed BEFORE signing (so we never
// produce a signed envelope for an invalid attestation)
// and AGAIN at verify time (so a tampered envelope is
// rejected with the same errors as a fresh invalid one).
func (pa *PromptAttestation) Validate() error {
	if pa == nil {
		return fmt.Errorf("promptcache: PromptAttestation is nil")
	}
	if pa.PromptHash == "" {
		return fmt.Errorf("promptcache: prompt_hash is required")
	}
	if !isValidHexHash(pa.PromptHash) {
		return fmt.Errorf("promptcache: prompt_hash is not a valid SHA-256 hex (got %d chars, want 64 hex chars)", len(pa.PromptHash))
	}
	if pa.Source == "" {
		return fmt.Errorf("promptcache: source is required")
	}
	if len(pa.Source) > MaxSourceLen {
		return fmt.Errorf("promptcache: source too long (%d > %d)", len(pa.Source), MaxSourceLen)
	}
	if pa.ModelID == "" {
		return fmt.Errorf("promptcache: model_id is required")
	}
	if len(pa.ModelID) > MaxModelIDLen {
		return fmt.Errorf("promptcache: model_id too long (%d > %d)", len(pa.ModelID), MaxModelIDLen)
	}
	if pa.AttestorID == "" {
		return fmt.Errorf("promptcache: attestor_id is required")
	}
	if !isValidAttestorID(pa.AttestorID) {
		return fmt.Errorf("promptcache: attestor_id is malformed (allowed: ASCII letters, digits, '-', '_', '.', ':', '/', '@')")
	}
	if len(pa.AttestorID) > MaxAttestorIDLen {
		return fmt.Errorf("promptcache: attestor_id too long (%d > %d)", len(pa.AttestorID), MaxAttestorIDLen)
	}
	if pa.AttestedAt.IsZero() {
		return fmt.Errorf("promptcache: attested_at is required")
	}
	if pa.ValidUntil.IsZero() {
		return fmt.Errorf("promptcache: valid_until is required")
	}
	if len(pa.Metadata) > MaxMetadataLen {
		return fmt.Errorf("promptcache: metadata too long (%d > %d)", len(pa.Metadata), MaxMetadataLen)
	}
	return nil
}

// isValidHexHash checks that s is exactly 64 lowercase or
// uppercase hex characters (the length of a SHA-256 hex
// digest). Used by Validate to reject prompt_hash values
// that are not valid SHA-256 hex.
//
// We do not enforce lowercase or uppercase specifically
// (both are valid hex); we just require 64 hex chars.
func isValidHexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	return isHexString(s)
}

// isValidAttestorID checks the attestor_id format. The
// allowed format is intentionally permissive (attestors
// come from many ecosystems), but restricted enough to
// prevent control-character injection (matches the
// agent_id regex pattern from TODO-303).
//
// M1 fix (TODO-304 review): the previous regex comment
// here was a copy-paste from agent_id; the corrected
// regex [a-zA-Z0-9._:/@-]+ is the same permissive set
// but documented in context.
var attestorIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._:/@-]+$`)

func isValidAttestorID(s string) bool {
	return attestorIDPattern.MatchString(s)
}

// =====================================================================
// Errors
// =====================================================================

// ErrAttestationExpired is returned by Verify when the
// attestation's ValidUntil is in the past. Sentinel error
// so callers can use errors.Is to distinguish expiry from
// other failures.
var ErrAttestationExpired = errors.New("promptcache: attestation has expired")

// ErrAttestationNotYetValid is returned by Verify when the
// attestation's AttestedAt is in the future (a clock skew
// or forgery attempt). Sentinel error.
var ErrAttestationNotYetValid = errors.New("promptcache: attestation is not yet valid (attested_at in the future)")

// ErrPromptHashMismatch is returned by Verify when the
// envelope's subject hash does not match the attestation's
// prompt_hash. This means the envelope was either tampered
// with or the wrong envelope was supplied for the prompt.
// Sentinel error.
var ErrPromptHashMismatch = errors.New("promptcache: prompt hash mismatch (envelope subject does not match attestation prompt_hash)")

// ErrAttestorMismatch is returned by Verify when the
// envelope's issuer's attestor_id does not match the
// attestation's attestor_id. Defense against a compromised
// key writing fake attestations for a different attestor.
// Sentinel error.
var ErrAttestorMismatch = errors.New("promptcache: attestor mismatch (envelope issuer's attestor_id does not match attestation)")

// ErrInvalidSubject is returned by Verify when the envelope
// subject is not a valid aegisgate://prompt/<hash> URI.
var ErrInvalidSubject = errors.New("promptcache: envelope subject is not a valid prompt URI")

// ErrInvalidIssuer is returned by Verify when the envelope
// issuer is not a well-formed promptcache:shortfp:<16-hex>:
// <key-id>:<attestor-id> string.
var ErrInvalidIssuer = errors.New("promptcache: envelope issuer is not a valid promptcache issuer")
