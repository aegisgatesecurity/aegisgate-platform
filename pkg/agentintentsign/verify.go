// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Intent Signing JSON helpers (TODO-303)
//
// verify.go is the JSON-friendly shape of VerifyResult,
// used by the CLI's --json output and the HTTP verify
// endpoint. The struct is flat (no nested envelope) for
// human readability.

package agentintentsign

import "encoding/json"

// VerifyResultJSON is the flat, JSON-friendly shape of
// VerifyResult. The CLI and HTTP use this for --json
// output; humans prefer one line per field over a nested
// envelope.
type VerifyResultJSON struct {
	// Valid is true iff every check passed.
	Valid bool `json:"valid"`
	// Reason is a human-readable explanation. Empty when
	// Valid is true.
	Reason string `json:"reason,omitempty"`
	// Type is the envelope's registered type.
	Type string `json:"type,omitempty"`
	// Subject is the envelope's subject URI.
	Subject string `json:"subject,omitempty"`
	// Issuer is the envelope's issuer string.
	Issuer string `json:"issuer,omitempty"`
	// KeyID is the envelope's signing key id.
	KeyID string `json:"key_id,omitempty"`
	// IntentID is the IntentTuple's intent_id (extracted
	// from the decoded tuple).
	IntentID string `json:"intent_id,omitempty"`
	// AgentID is the IntentTuple's agent_id.
	AgentID string `json:"agent_id,omitempty"`
	// IssuedAt is the IntentTuple's issued_at.
	IssuedAt string `json:"issued_at,omitempty"`
	// ValidUntil is the IntentTuple's valid_until.
	ValidUntil string `json:"valid_until,omitempty"`
}

// ToJSON converts a VerifyResult to a VerifyResultJSON.
// The flattened shape is friendlier for CLI output.
func (v *VerifyResult) ToJSON() VerifyResultJSON {
	out := VerifyResultJSON{
		Valid:  v.Valid,
		Reason: v.Reason,
	}
	if v.Envelope != nil {
		out.Type = string(v.Envelope.Type)
		out.Subject = v.Envelope.Subject
		out.Issuer = v.Envelope.Issuer
		out.KeyID = v.Envelope.Signature.KeyID
	}
	if v.Tuple != nil {
		out.IntentID = v.Tuple.IntentID
		out.AgentID = v.Tuple.AgentID
		if !v.Tuple.IssuedAt.IsZero() {
			out.IssuedAt = v.Tuple.IssuedAt.Format("2006-01-02T15:04:05.000000000Z07:00")
		}
		if !v.Tuple.ValidUntil.IsZero() {
			out.ValidUntil = v.Tuple.ValidUntil.Format("2006-01-02T15:04:05.000000000Z07:00")
		}
	}
	return out
}

// jsonMarshalImpl is a thin wrapper around json.Marshal.
// Kept in this file (not in the test file) to keep the
// test file's import list minimal.
func jsonMarshalImpl(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
