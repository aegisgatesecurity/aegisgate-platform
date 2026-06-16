// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM verifier (TODO-302)
//
// verify.go provides the verify-side of AIBOM. The auditor
// receives a signed envelope (via the CLI, the HTTP endpoint,
// or a file), runs Verify, and gets a structured pass/fail
// result that includes the decoded BOM.
//
// verify.go is the bridge between "envelope signed correctly"
// and "envelope contents are a valid AIBOM BOM."
//
// It mirrors pkg/evaluator/verify.go and pkg/evidence/verify.go.
// The same pattern is used across all three Tier 5 features
// that ship on top of the envelope primitive.

package aibom

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
)

// VerifyResult is the structured output of VerifyEnvelope.
// It bundles the envelope, the decoded BOM, and a pass/fail
// decision.
//
// `Valid` is true only if:
//   - The envelope signature verifies.
//   - The payload is a valid BOM with all required fields.
//   - The envelope's Type is attestation.TypeAIBOM.
//   - The envelope's Subject is aegisgate://deployment/<id>.
type VerifyResult struct {
	// Valid is true iff every check passed.
	Valid bool `json:"valid"`
	// Reason is a human-readable explanation. Empty when
	// Valid is true. Contains the attestation error
	// reason (signature_invalid, expired, etc.) OR the
	// payload-validation error (missing field, etc.).
	Reason string `json:"reason,omitempty"`
	// BOM is the decoded BOM. nil only if the payload
	// itself was not valid JSON.
	BOM *BOM `json:"bom,omitempty"`
	// Envelope is the raw envelope as supplied.
	Envelope *attestation.Envelope `json:"envelope"`
}

// VerifyEnvelope verifies a signed AIBOM envelope. The flow:
//  1. attestation.Verify the envelope.
//  2. Type check.
//  3. Subject kind check (aegisgate://deployment/<id>).
//  4. Decode the payload as a BOM.
//  5. Sanity-check the BOM fields.
//
// Returns a VerifyResult describing the outcome. Never
// returns an error directly; all error modes are folded
// into the VerifyResult.Reason field.
func VerifyEnvelope(ctx context.Context, env *attestation.Envelope) *VerifyResult {
	out := &VerifyResult{Envelope: env}
	if env == nil {
		out.Reason = "envelope is nil"
		return out
	}
	// 1. Signature + envelope well-formedness.
	if err := attestation.Verify(env); err != nil {
		out.Reason = err.Error()
		return out
	}
	// 2. Type check.
	if env.Type != attestation.TypeAIBOM {
		out.Reason = fmt.Sprintf("envelope type is %q, want %q",
			env.Type, attestation.TypeAIBOM)
		return out
	}
	// 3. Subject kind check. Defense in depth (see TODO-301
	// M1 for the rationale).
	if !strings.HasPrefix(env.Subject, "aegisgate://deployment/") {
		out.Reason = fmt.Sprintf("envelope subject %q is not a deployment URI", env.Subject)
		return out
	}
	// 4. Decode the payload.
	bom, err := ParseBOM([]byte(env.RawPayload))
	if err != nil {
		out.Reason = fmt.Sprintf("decode BOM: %v", err)
		return out
	}
	// 5. Sanity-check the BOM fields.
	if err := validateBOM(bom); err != nil {
		out.Reason = fmt.Sprintf("invalid BOM: %v", err)
		return out
	}
	out.BOM = bom
	out.Valid = true
	return out
}

// ParseBOM decodes a BOM from JSON bytes. Used by the
// verify path and by callers that want to inspect a signed
// AIBOM without re-decoding the envelope's RawPayload.
func ParseBOM(payload []byte) (*BOM, error) {
	var bom BOM
	if err := json.Unmarshal(payload, &bom); err != nil {
		return nil, fmt.Errorf("aibom: parse BOM: %w", err)
	}
	return &bom, nil
}

// VerifyEnvelopeJSON is the convenience entry point for
// callers that receive the envelope as bytes.
func VerifyEnvelopeJSON(ctx context.Context, payload []byte) (*VerifyResult, error) {
	var env attestation.Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("aibom: parse envelope: %w", err)
	}
	return VerifyEnvelope(ctx, &env), nil
}

// validateBOM performs a lightweight semantic check on a
// decoded BOM. Catches the most common "garbage in a valid
// envelope" cases: missing fields, wrong format version,
// etc. Not a full CycloneDX schema validator (we trust
// the JCS canonicalizer for structural integrity).
func validateBOM(b *BOM) error {
	if b == nil {
		return fmt.Errorf("BOM is nil")
	}
	if b.BOMFormat != CycloneDXBOMFormat {
		return fmt.Errorf("bomFormat is %q, want %q", b.BOMFormat, CycloneDXBOMFormat)
	}
	if b.SpecVersion != CycloneDXSpecVersion {
		return fmt.Errorf("specVersion is %q, want %q", b.SpecVersion, CycloneDXSpecVersion)
	}
	if b.Version <= 0 {
		return fmt.Errorf("version is %d, want > 0", b.Version)
	}
	if b.SerialNumber == "" {
		return fmt.Errorf("serialNumber is missing")
	}
	if !strings.HasPrefix(b.SerialNumber, "urn:uuid:") {
		return fmt.Errorf("serialNumber %q is not a urn:uuid: URI", b.SerialNumber)
	}
	if b.Metadata.Timestamp.IsZero() {
		return fmt.Errorf("metadata.timestamp is missing")
	}
	if len(b.Metadata.Tools) == 0 {
		return fmt.Errorf("metadata.tools is empty")
	}
	if b.Metadata.Component.BOMRef == "" {
		return fmt.Errorf("metadata.component.bom-ref is missing")
	}
	if len(b.Components) == 0 {
		return fmt.Errorf("components is empty (an AIBOM must enumerate the 5 pillars)")
	}
	// m3 fix (TODO-301 lesson): we require the 5 protocol
	// pillars to be present. The AIBOM spec requires
	// explicit enumeration, not silent omission.
	requiredPillars := []string{
		"aegisgate-http",
		"aegisgate-mcp",
		"aegisgate-a2a",
		"aegisgate-acp",
		"aegisgate-anp",
	}
	presentPillars := make(map[string]bool, len(b.Components))
	for _, c := range b.Components {
		presentPillars[c.BOMRef] = true
	}
	for _, p := range requiredPillars {
		if !presentPillars[p] {
			return fmt.Errorf("required pillar %q is missing from components", p)
		}
	}
	return nil
}

// VerifyResultJSON is the JSON-friendly shape of VerifyResult
// (the BOM and Envelope fields are flattened for human
// inspection). The CLI/HTTP use this for the --json output.
type VerifyResultJSON struct {
	Valid         bool     `json:"valid"`
	Reason        string   `json:"reason,omitempty"`
	Type          string   `json:"type,omitempty"`
	Subject       string   `json:"subject,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	KeyID         string   `json:"key_id,omitempty"`
	DeploymentID  string   `json:"deployment_id,omitempty"`
	PlatformTier  string   `json:"platform_tier,omitempty"`
	PlatformVer   string   `json:"platform_version,omitempty"`
	SpecVersion   string   `json:"spec_version,omitempty"`
	BOMFormat     string   `json:"bom_format,omitempty"`
	ComponentRefs []string `json:"component_refs,omitempty"`
}

// ToJSON converts a VerifyResult to a VerifyResultJSON. The
// flattened shape is friendlier for CLI output (one line
// per field, no nested BOM).
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
		out.DeploymentID = deploymentIDFromBOM(v.BOM)
	}
	if v.BOM != nil {
		out.SpecVersion = v.BOM.SpecVersion
		out.BOMFormat = v.BOM.BOMFormat
		out.PlatformVer = v.BOM.Metadata.Component.Version
		// Extract the platform tier from the metadata
		// component properties.
		for _, p := range v.BOM.Metadata.Component.Properties {
			if p.Name == "aegisgate:platform_tier" {
				out.PlatformTier = p.Value
				break
			}
		}
		// Collect the component refs (sorted by the BOM;
		// the generator already sorts them).
		for _, c := range v.BOM.Components {
			out.ComponentRefs = append(out.ComponentRefs, c.BOMRef)
		}
	}
	return out
}
