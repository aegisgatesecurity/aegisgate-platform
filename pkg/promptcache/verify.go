// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Prompt Cache Poisoning Detection JSON helpers (TODO-304)
//
// verify.go is the JSON-friendly shape of VerifyResult,
// used by the CLI's --json output and the HTTP verify
// endpoint. The struct is flat (no nested envelope) for
// human readability.

package promptcache

import "encoding/json"

// VerifyResultJSON is the flat, JSON-friendly shape of
// VerifyResult. The CLI and HTTP use this for --json
// output; humans prefer one line per field over a nested
// envelope.
type VerifyResultJSON struct {
	// Valid is true iff every check passed.
	Valid bool `json:"valid"`
	// Reason is a human-readable explanation. Empty
	// when Valid is true.
	Reason string `json:"reason,omitempty"`
	// Type is the envelope's registered type.
	Type string `json:"type,omitempty"`
	// Subject is the envelope's subject URI.
	Subject string `json:"subject,omitempty"`
	// Issuer is the envelope's issuer string.
	Issuer string `json:"issuer,omitempty"`
	// KeyID is the envelope's signing key id.
	KeyID string `json:"key_id,omitempty"`
	// PromptHash is the PromptAttestation's prompt_hash.
	PromptHash string `json:"prompt_hash,omitempty"`
	// Source is the PromptAttestation's source.
	Source string `json:"source,omitempty"`
	// ModelID is the PromptAttestation's model_id.
	ModelID string `json:"model_id,omitempty"`
	// AttestorID is the PromptAttestation's attestor_id.
	AttestorID string `json:"attestor_id,omitempty"`
	// AttestedAt is the PromptAttestation's attested_at.
	AttestedAt string `json:"attested_at,omitempty"`
	// ValidUntil is the PromptAttestation's valid_until.
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
	if v.Attestation != nil {
		out.PromptHash = v.Attestation.PromptHash
		out.Source = v.Attestation.Source
		out.ModelID = v.Attestation.ModelID
		out.AttestorID = v.Attestation.AttestorID
		if !v.Attestation.AttestedAt.IsZero() {
			out.AttestedAt = v.Attestation.AttestedAt.Format("2006-01-02T15:04:05.000000000Z07:00")
		}
		if !v.Attestation.ValidUntil.IsZero() {
			out.ValidUntil = v.Attestation.ValidUntil.Format("2006-01-02T15:04:05.000000000Z07:00")
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
