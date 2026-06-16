// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Intent Signing types (TODO-303)
//
// types.go defines the data structures for A2A intent
// signing. The shapes here are the contract between the
// signer, the verifier, and the A2A middleware.
//
// # Design rule
//
// IntentTuple is what gets wrapped by the attestation
// envelope. Its fields are stable, sorted alphabetically
// at the top level by JSON tag, and serializable to JSON
// deterministically. The JCS canonicalizer (inside
// attestation.Sign) sorts keys at every level.

package agentintentsign

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// =====================================================================
// IntentTuple
// =====================================================================

// IntentTuple is the signed payload. The four required
// fields (AgentID, Intent, Justification, ValidUntil) are
// what the auditor verifies; the rest is metadata.
//
// The struct is the canonical input to Sign. The envelope
// wraps the JSON-encoded form of this struct (after
// validation).
type IntentTuple struct {
	// IntentID is the unique id for this intent (UUIDv4
	// in v0.1). Embedded in the envelope subject. The
	// caller generates this (or we generate it in Sign
	// if empty).
	IntentID string `json:"intent_id"`
	// AgentID is the identifier of the agent making the
	// intent declaration. Examples: "agent:acme-corp/
	// customer-support@v1.2.0", "model:openai/gpt-4-turbo".
	// The signer does not interpret this; it is stored
	// verbatim in the signed payload.
	AgentID string `json:"agent_id"`
	// Intent is the human-readable declaration of what
	// the agent intends to do. Example: "Read the user's
	// calendar for tomorrow". The intent is bound to the
	// signature; the agent cannot later deny it.
	Intent string `json:"intent"`
	// Justification is the human-readable reason for the
	// intent. Example: "The user asked me to summarize
	// their meetings". The justification is bound to the
	// signature; auditors can read it to understand WHY
	// the agent did what it did.
	Justification string `json:"justification"`
	// ValidUntil is the timestamp after which the intent
	// is no longer valid. The verifier rejects intents
	// where ValidUntil < now. Defaults to now+1h if zero.
	ValidUntil time.Time `json:"valid_until"`
	// IssuedAt is the timestamp when the intent was
	// signed. Stored in the signed payload (NOT just
	// in the envelope metadata) so the auditor can see
	// the original signing time, not just the envelope
	// creation time. Defaults to now() if zero.
	IssuedAt time.Time `json:"issued_at"`
	// Context is an optional free-form context blob
	// (e.g., a session id, a request id, a correlation
	// id). The signer does not interpret it; it is
	// stored verbatim. Empty is fine.
	Context string `json:"context,omitempty"`
}

// Validate checks the IntentTuple for required fields
// and length limits. Returns an error if any check fails.
//
// The check is performed BEFORE signing (so we never
// produce a signed envelope for an invalid tuple) and
// AGAIN at verify time (so a tampered envelope is
// rejected with the same errors as a fresh invalid one).
func (it *IntentTuple) Validate() error {
	if it == nil {
		return fmt.Errorf("agentintentsign: IntentTuple is nil")
	}
	if it.AgentID == "" {
		return fmt.Errorf("agentintentsign: agent_id is required")
	}
	if !isValidAgentID(it.AgentID) {
		return fmt.Errorf("agentintentsign: agent_id is malformed (allowed: ASCII letters, digits, '-', '_', '.', ':', '/', '@', 'v')")
	}
	if len(it.AgentID) > MaxAgentIDLen {
		return fmt.Errorf("agentintentsign: agent_id too long (%d > %d)", len(it.AgentID), MaxAgentIDLen)
	}
	if it.Intent == "" {
		return fmt.Errorf("agentintentsign: intent is required")
	}
	if len(it.Intent) > MaxIntentLen {
		return fmt.Errorf("agentintentsign: intent too long (%d > %d)", len(it.Intent), MaxIntentLen)
	}
	if it.Justification == "" {
		return fmt.Errorf("agentintentsign: justification is required")
	}
	if len(it.Justification) > MaxJustificationLen {
		return fmt.Errorf("agentintentsign: justification too long (%d > %d)", len(it.Justification), MaxJustificationLen)
	}
	if it.ValidUntil.IsZero() {
		return fmt.Errorf("agentintentsign: valid_until is required")
	}
	// valid_until must be in the future (the signer
	// can only sign for the future; you can't sign a
	// retroactively-valid intent because that's
	// basically a way to forge intents).
	// This is checked at Sign() time, not here, because
	// Validate is also called at verify time (where
	// the intent may already be in the past, and that's
	// the verifier's job to reject).
	return nil
}

// isValidAgentID checks the agent_id format. The allowed
// format is intentionally permissive (agents come from
// many ecosystems), but restricted enough to prevent
// control-character injection.
//
// Allowed: ASCII letters, digits, '-', '_', '.', ':', '/',
// '@', 'v' (for semver suffixes like "v1.2.0"). The 'v'
// is allowed as a standalone character (semver convention).
var agentIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._:/@-]+$`)

func isValidAgentID(s string) bool {
	return agentIDPattern.MatchString(s)
}

// =====================================================================
// Errors
// =====================================================================

// ErrIntentExpired is returned by Verify when the intent's
// ValidUntil is in the past. Sentinel error so callers can
// use errors.Is to distinguish expiry from other failures.
var ErrIntentExpired = errors.New("agentintentsign: intent has expired")

// ErrIntentNotYetValid is returned by Verify when the
// intent's IssuedAt is in the future (a clock skew or
// forgery attempt). Sentinel error.
var ErrIntentNotYetValid = errors.New("agentintentsign: intent is not yet valid (issued_at in the future)")

// ErrCrossAgentReplay is returned by Verify when the same
// intent is replayed from a different signing key. Sentinel
// error. (v0.1: detected by comparing the issuer's agent_id
// prefix; v0.2: detected by a replay cache.)
var ErrCrossAgentReplay = errors.New("agentintentsign: cross-agent replay detected (intent signed by a different key than expected)")

// ErrInvalidSubject is returned by Verify when the envelope
// subject is not a valid aegisgate://intent/<id> URI.
var ErrInvalidSubject = errors.New("agentintentsign: envelope subject is not a valid intent URI")
