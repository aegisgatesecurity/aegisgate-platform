// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.3.0+)
//
// types.go defines the data structures for evidence packages.
// The Manifest is the top-level signed artifact. The other types
// are the substructures embedded in it.
//
// v3.3.0+ Track 2.

package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// Manifest is the top-level evidence package artifact. Once signed,
// it is tamper-evident: any modification of any field invalidates
// the Signature. The signature is over a SHA-256 hash of the
// canonicalized manifest bytes (excluding the Signature field itself).
//
// JSON field names use snake_case to match the AegisGate HTTP API
// convention (see /api/v1/compliance/* responses).
type Manifest struct {
	// ManifestID is a UUIDv4 string uniquely identifying this package.
	ManifestID string `json:"manifest_id"`
	// Framework is the canonical framework name (e.g., "hipaa",
	// "eu_ai_act"). One package = one framework.
	Framework string `json:"framework"`
	// FrameworkVersion is the framework spec version. Optional, may
	// be empty for self-versioned frameworks.
	FrameworkVersion string `json:"framework_version,omitempty"`
	// Period is the time window this evidence covers.
	Period Period `json:"period"`
	// License is a snapshot of the customer license at the time of
	// build. We store the fingerprint, tier, modules, and customer
	// name - NEVER the raw license key.
	License LicenseBlock `json:"license"`
	// GeneratedAt is when this package was built.
	GeneratedAt time.Time `json:"generated_at"`
	// BuilderVersion is the AegisGate version that built this package.
	BuilderVersion string `json:"builder_version"`
	// FrameworkEvidence is the per-framework scan snapshot.
	FrameworkEvidence FrameworkEvidence `json:"framework_evidence"`
	// AuditAnchors is the audit-event coverage summary.
	AuditAnchors AuditAnchors `json:"audit_anchors"`
	// FrameworkCrossRefs is the cross-framework control mapping
	// for the framework being attested. Each entry maps a single
	// control in this manifest's framework to its cross-references
	// in MITRE ATLAS, NIST AI RMF, OWASP LLM Top 10, and CWE.
	//
	// This is the Tier 1 (TODO-402) wire-up of
	// pkg/compliance/framework_mapping.go. The field is omitted
	// from JSON when empty so legacy manifests are byte-identical
	// to their pre-Tier 1 form. An auditor verifying a v3.5.0+
	// manifest sees these cross-references at the top level
	// (parallel to AuditAnchors) without having to unpack the
	// per-framework scan snapshot.
	FrameworkCrossRefs []FrameworkCrossRef `json:"framework_cross_refs,omitempty"`
	// Attestation is an OPTIONAL envelope wrapping this manifest.
	// When present (v3.5.0+), the envelope is the authoritative
	// signature; the legacy Signature field below is mirrored
	// from the envelope for backward compatibility with
	// v3.4.0-beta.1 verifiers.
	//
	// When Attestation is nil (v3.4.0-beta.1 manifests), verifiers
	// use the legacy Signature field. The two paths are
	// interchangeable for verification: the envelope's signature
	// IS the manifest's signature (with the envelope's domain
	// separation prefix and JCS canonicalization).
	//
	// Tier 5 prep. See plans/ENVELOPE-DESIGN-v1.1-FROZEN.md §5.
	Attestation *attestation.Envelope `json:"attestation,omitempty"`
	// Signature is the ECDSA P-256 signature over the canonicalized
	// manifest bytes. See verify.go for the verification flow.
	//
	// Deprecated: use Manifest.Attestation (envelope) for v3.5.0+
	// verification. The Signature field is mirrored from the envelope
	// for backward compatibility and will be removed in v3.7.0.
	Signature Signature `json:"signature"`
}

// FrameworkCrossRef is one (control, target-frameworks) tuple
// from the cross-framework mapping. The SourceControl is a
// control ID in the manifest's primary framework (e.g., a HIPAA
// control ID). The Targets map canonical framework IDs to the
// cross-reference IDs in that framework.
//
// Example: a FrameworkCrossRef with SourceFramework="hipaa",
// SourceControl="164.312(a)(1)" and Targets={"mitre_atlas":
// ["AML.T0010"], "owasp_llm": ["LLM05"]} tells the auditor that
// HIPAA 164.312(a)(1) maps to MITRE ATLAS AML.T0010 and OWASP
// LLM05 in our framework_mapping library.
//
// The Confidence and Description fields are sourced from the
// MappingRelationship so the auditor can see the relationship
// strength and the human-readable description.
type FrameworkCrossRef struct {
	// SourceFramework is the manifest's primary framework
	// (e.g., "hipaa"). Redundant with Manifest.Framework but
	// useful for the auditor who reads a single cross-ref
	// out of context.
	SourceFramework string `json:"source_framework"`
	// SourceControl is the control ID in the SourceFramework.
	SourceControl string `json:"source_control"`
	// ControlName is the human-readable name of the control
	// (e.g., "Access Control"). Sourced from the scanner's
	// ControlCheckResult.ControlName; may be empty for
	// frameworks where the scanner does not supply a name.
	ControlName string `json:"control_name,omitempty"`
	// Targets maps canonical framework IDs (mitre_atlas,
	// nist_ai_rmf, owasp_llm, cwe) to a list of cross-
	// reference IDs in that framework. Empty targets are
	// omitted from the JSON.
	Targets map[string][]string `json:"targets"`
	// Confidence is the relationship confidence in [0,1] from
	// the MappingRelationship.
	Confidence float32 `json:"confidence"`
	// Description is the human-readable description of the
	// cross-framework relationship.
	Description string `json:"description,omitempty"`
	// Relationship is the relationship type from
	// MappingRelationship (e.g., "related", "exhibits",
	// "mitigates"). Empty when unknown.
	Relationship string `json:"relationship,omitempty"`
}

// Period is the time window an evidence package covers.
type Period struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// LicenseBlock is a license snapshot embedded in the manifest. We
// deliberately do NOT include the raw license key - only a fingerprint
// that auditors can correlate back to the customer record.
type LicenseBlock struct {
	// Fingerprint is a SHA-256 hash of the license key (hex-encoded).
	// Auditors can verify a customer owns the license by hashing the
	// supplied key and comparing.
	Fingerprint string `json:"fingerprint"`
	// Tier is the license tier at the time of build.
	Tier string `json:"tier"`
	// Customer is the customer name from the license payload.
	Customer string `json:"customer,omitempty"`
	// ExpiresAt is when the license expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// ModulesOwned is the list of compliance modules the customer
	// owned at the time of build.
	ModulesOwned []string `json:"modules_owned,omitempty"`
	// Valid is whether the license was valid at the time of build.
	Valid bool `json:"valid"`
}

// FrameworkEvidence is the per-framework scan snapshot. Mirrors the
// relevant fields of pkg/compliance.FrameworkScanResult so the
// evidence package is self-describing (auditors do not need to call
// back into the platform to read it).
type FrameworkEvidence struct {
	// Framework is the canonical framework name.
	Framework string `json:"framework"`
	// DisplayName is the human-readable name.
	DisplayName string `json:"display_name"`
	// Enforced is whether the framework is enforced for this license.
	Enforced bool `json:"enforced"`
	// Module is the billable module name (e.g., "hipaa").
	Module string `json:"module,omitempty"`
	// Score is the compliance score 0-100.
	Score float64 `json:"score"`
	// ControlsTotal is the total number of controls.
	ControlsTotal int `json:"controls_total"`
	// ControlsEnforced is the number of controls that pass.
	ControlsEnforced int `json:"controls_enforced"`
	// CompliancePct is ControlsEnforced / ControlsTotal * 100.
	CompliancePct float64 `json:"compliance_pct"`
	// ReasonEnforced is the reason code when Enforced=true.
	ReasonEnforced string `json:"reason_enforced,omitempty"`
	// ReasonNotEnforced is the reason code when Enforced=false.
	ReasonNotEnforced string `json:"reason_not_enforced,omitempty"`
	// MissingModules is the list of modules needed to enable the
	// framework, if not enforced.
	MissingModules []string `json:"missing_modules,omitempty"`
	// UpgradeHint is a human-readable upgrade prompt, if relevant.
	UpgradeHint string `json:"upgrade_hint,omitempty"`
	// ImplementationReady is whether the framework implementation exists.
	ImplementationReady bool `json:"implementation_ready"`
	// Assessment is the per-control pass/fail list, if available.
	// May be nil for free frameworks that do not produce assessments.
	Assessment *Assessment `json:"assessment,omitempty"`
}

// Assessment is the per-control pass/fail list for a framework. It is
// a snapshot of pkg/compliance.FrameworkAssessment flattened to a
// struct we can serialize independently of the compliance package.
type Assessment struct {
	// Controls is the list of per-control results.
	Controls []ControlResult `json:"controls"`
	// OverallPass is the count of controls that pass.
	OverallPass int `json:"overall_pass"`
	// OverallFail is the count of controls that fail.
	OverallFail int `json:"overall_fail"`
}

// ControlResult is the per-control evidence row.
type ControlResult struct {
	// ControlID is the framework-specific control identifier
	// (e.g., "164.312(a)(1)" for HIPAA, "Art.9" for EU AI Act).
	ControlID string `json:"control_id"`
	// Description is the human-readable control description.
	Description string `json:"description"`
	// Passed is whether the control is currently satisfied.
	Passed bool `json:"passed"`
	// Evidence is a free-form evidence string (typically a pattern
	// reference, an audit event hash, or a measurement).
	Evidence string `json:"evidence,omitempty"`
}

// AuditAnchors is the audit-event coverage summary. This is the
// "how much activity did you see?" signal in the evidence package.
// Auditors use it to confirm that the package is not vacuous (e.g.,
// 0 events in 90 days is a signal the platform is not in use).
type AuditAnchors struct {
	// EventCount is the total number of audit events in the period.
	EventCount int `json:"event_count"`
	// ByType is event counts grouped by logging.Event.Type.
	ByType map[string]int `json:"by_type,omitempty"`
	// BySeverity is event counts grouped by logging.Severity.
	BySeverity map[logging.Severity]int `json:"by_severity,omitempty"`
	// ByFramework is event counts grouped by Event.ComplianceFramework.
	// Auditors use this to see which frameworks generated the most
	// enforcement activity during the period.
	ByFramework map[string]int `json:"by_framework,omitempty"`
	// ByProtocol is event counts grouped by the AegisGate
	// protocol pillar ("http", "mcp", "a2a", "acp", "anp", or ""
	// for events not tagged with a protocol). v3.4.0 primitive
	// that powers the cross-protocol evidence aggregation: a CISO
	// can ask "how much activity did the platform see across all
	// 5 protocols in Q1?" and get a single signed answer.
	ByProtocol map[string]int `json:"by_protocol,omitempty"`
	// Source is "ring_buffer" or "unavailable" depending on whether
	// an EventSource was wired in at build time.
	Source string `json:"source"`
}

// Signature is the cryptographic signature on the manifest. The
// algorithm is ECDSA P-256 (NIST FIPS 186-4) with SEC 1 encoded
// signature bytes, matching pkg/trust/attestation.Generator.
type Signature struct {
	// Algorithm is the signature algorithm identifier.
	Algorithm string `json:"algorithm"`
	// KeyID is an opaque identifier for the signing key. Lets us
	// rotate keys without breaking verification (auditors can look
	// up the right public key by KeyID).
	KeyID string `json:"key_id"`
	// Value is the signature bytes (ASN.1 DER encoded, per ECDSA).
	Value []byte `json:"value"`
	// PublicKey is the SEC 1 encoded public key (X || Y, 64 bytes
	// for P-256). Auditors use this to verify without needing a
	// separate key-fetch step. For production, prefer fetching the
	// canonical public key from /.well-known/aegisgate-evidence-pubkey.pem.
	PublicKey []byte `json:"public_key,omitempty"`
	// SignedAt is when the signature was generated. May be slightly
	// different from Manifest.GeneratedAt (e.g., if the manifest
	// was rebuilt before storage).
	SignedAt time.Time `json:"signed_at"`
}

// EventSource provides audit-event counts over a time window.
// Implementations can be backed by a ring buffer, a database query,
// or a remote aggregator. If nil is passed to the Builder,
// AuditAnchors.Source is set to "unavailable" and the rest of the
// manifest still builds.
//
// This interface lives in the evidence package (not the logging
// package) because the storage strategy is an evidence-package
// concern, not a logging concern. A future v0.2 may move the
// interface to pkg/logging if a canonical implementation lands.
type EventSource interface {
	// CountByType returns event counts grouped by Event.Type
	// within the [start, end] window.
	CountByType(ctx context.Context, start, end time.Time) (map[string]int, error)
	// CountBySeverity returns event counts grouped by Severity
	// within the [start, end] window.
	CountBySeverity(ctx context.Context, start, end time.Time) (map[logging.Severity]int, error)
	// CountByFramework returns event counts grouped by
	// Event.ComplianceFramework within the [start, end] window.
	CountByFramework(ctx context.Context, start, end time.Time) (map[string]int, error)
	// CountByProtocol returns event counts grouped by the
	// AegisGate protocol pillar (http, mcp, a2a, acp, anp).
	// v3.4.0 primitive for cross-protocol evidence aggregation.
	CountByProtocol(ctx context.Context, start, end time.Time) (map[string]int, error)
}

// LicenseSnapshot is a convenience for building the LicenseBlock from
// a license.ValidationResult. The key is the license key; we hash it
// with SHA-256 to produce a fingerprint. Auditors can verify by
// hashing the customer-supplied key and comparing.
//
// We never log or serialize the raw key. The fingerprint is safe to
// embed in the manifest.
func LicenseSnapshot(key string, result *license.ValidationResult) LicenseBlock {
	block := LicenseBlock{
		Fingerprint: FingerprintKey(key),
		Tier:        tier.TierCommunity.String(),
		Valid:       false,
	}
	if result == nil {
		return block
	}
	block.Tier = result.Tier.String()
	block.Valid = result.Valid
	if result.Valid {
		block.Customer = result.Payload.Customer
		block.ExpiresAt = result.Payload.ExpiresAt
		block.ModulesOwned = result.Payload.Modules
	}
	return block
}

// FingerprintKey returns a hex-encoded SHA-256 hash of the license key.
// The fingerprint is safe to embed in a manifest (and to publish):
// knowing the fingerprint does not let an attacker recover the key.
// Empty input returns the SHA-256 of the empty string so the field is
// always populated.
func FingerprintKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
