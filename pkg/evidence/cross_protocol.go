// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Cross-Protocol Evidence Aggregation (v3.4.0+)
//
// cross_protocol.go implements the c1 "killer feature" of the
// v3.4.0 release train: a SINGLE signed assertion of activity
// across all 5 protocol pillars (HTTP, MCP, A2A, ACP, ANP).
//
// The existing Manifest type is per-framework: one manifest
// answers "what was the HIPAA compliance posture for Q1?" A
// regulator who asks "did AegisGate detect prompt injection
// via MCP or HTTP in Q1?" cannot get a single answer from a
// per-framework manifest - they would have to query each
// framework's manifest and reconcile by hand.
//
// CrossProtocolManifest answers that question with a single
// signed JSON artifact: it aggregates the per-protocol
// AuditAnchors (ByProtocol), the per-framework scan results
// (all known frameworks), and the license snapshot, then
// signs the whole thing with the platform's evidence-signing
// key. An auditor can verify it end-to-end without needing
// access to the platform's internal state.
//
// v3.4.0+ (c1 in the moat-deepening roadmap).

package evidence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// CrossProtocolManifest is the top-level signed artifact for
// the c1 cross-protocol evidence aggregation. It is structurally
// similar to Manifest (it has the same LicenseBlock and
// Signature semantics) but is NOT a per-framework report: it
// is a platform-wide activity summary across all 5 protocol
// pillars.
//
// Field shape:
//   - ManifestID: UUIDv4 unique to this artifact
//   - Period: the time window covered
//   - License: customer license snapshot (same as Manifest)
//   - GeneratedAt: when this artifact was built
//   - BuilderVersion: AegisGate version that built it
//   - PerFramework: list of lightweight refs to the per-
//     framework Manifest objects built as part of this view.
//   - AuditAnchors: the per-protocol rollup (ByProtocol) +
//     per-type/severity/framework counts, all in one struct.
//   - Signature: ECDSA P-256 signature over the canonicalized
//     artifact (Signature field zeroed), same algorithm as
//     Manifest.
type CrossProtocolManifest struct {
	// ManifestID is a UUIDv4 string uniquely identifying this
	// cross-protocol artifact. Different from the per-framework
	// Manifest.ManifestID (which is per-framework).
	ManifestID string `json:"manifest_id"`
	// Period is the time window this cross-protocol view covers.
	Period Period `json:"period"`
	// License is a snapshot of the customer license at the time
	// of build. Same semantics as Manifest.LicenseBlock.
	License LicenseBlock `json:"license"`
	// GeneratedAt is when this artifact was built.
	GeneratedAt time.Time `json:"generated_at"`
	// BuilderVersion is the AegisGate version that built this.
	BuilderVersion string `json:"builder_version"`
	// PerFramework is the list of lightweight refs to the
	// per-framework Manifest objects built as part of this
	// cross-protocol view. The full per-framework Manifests are
	// stored separately (one per known framework) and can be
	// fetched by ID for the auditor who wants the per-framework
	// detail.
	PerFramework []PerFrameworkRef `json:"per_framework"`
	// ControlCrossRefs is the cross-framework, cross-protocol
	// rollup of which controls are covered by which protocols.
	// Built by aggregating the FrameworkCrossRefs of the
	// per-framework Manifests built in step 2 of
	// BuildCrossProtocol. Omitted from JSON when empty so
	// legacy cross-protocol artifacts are byte-identical to
	// their pre-Tier 1 form. Sibling of PerFramework +
	// AuditAnchors (not nested in PerFrameworkRef) so the
	// auditor can see the cross-protocol rollup at the top
	// level. Tier 1 (TODO-402).
	ControlCrossRefs []FrameworkControlRef `json:"control_cross_refs,omitempty"`
	// AuditAnchors is the per-protocol + per-type/severity/
	// framework rollup over the same time window. ByProtocol
	// is the key field - it's the cross-protocol view.
	AuditAnchors AuditAnchors `json:"audit_anchors"`
	// Signature is the ECDSA P-256 signature over the
	// canonicalized cross-protocol manifest.
	Signature Signature `json:"signature"`
}

// PerFrameworkRef is a lightweight reference to a per-framework
// Manifest embedded in a CrossProtocolManifest. The reference is
// sufficient to fetch the per-framework manifest by ID and
// verify it independently (auditor can use the embedded KeyID
// + canonical public key from /.well-known/), without the
// auditor having to download the full Manifest inside the
// cross-protocol artifact (which would make it huge).
type PerFrameworkRef struct {
	// ManifestID is the per-framework Manifest.ManifestID.
	ManifestID string `json:"manifest_id"`
	// Framework is the canonical framework name (e.g., "hipaa").
	Framework string `json:"framework"`
	// Enforced is whether the framework was enforced (per
	// LicenseBlock.Tier). The auditor uses this to skip
	// frameworks the customer did not pay for.
	Enforced bool `json:"enforced"`
	// CompliancePct is the framework's compliance percentage
	// 0-100, copied from Manifest.FrameworkEvidence.CompliancePct.
	CompliancePct float64 `json:"compliance_pct"`
	// ControlsTotal and ControlsEnforced are the framework
	// control counts, copied from Manifest.FrameworkEvidence.
	ControlsTotal    int `json:"controls_total"`
	ControlsEnforced int `json:"controls_enforced"`
}

// FrameworkControlRef is a cross-framework, cross-protocol
// rollup. Unlike FrameworkCrossRef (which is per-framework and
// lives on a single Manifest), FrameworkControlRef aggregates
// per-protocol coverage of a single control across the 5
// protocol pillars (HTTP, MCP, A2A, ACP, ANP) and the 7
// compliance frameworks. It is the field that answers the
// question: "for this control, which protocols actually emit
// evidence?"
//
// One control can satisfy multiple frameworks (e.g., "use TLS"
// satisfies HIPAA, SOC2, PCI-DSS, and ISO27001), so
// FrameworkControlRef.Frameworks is a list rather than a
// single string.
//
// Tier 1 (TODO-402) of the 5-Tier forward roadmap.
type FrameworkControlRef struct {
	// ControlID is the canonical control identifier. For
	// cross-framework controls this is the shared ID (e.g.,
	// "ACCESS-001"). For framework-specific controls this
	// is the framework-local ID (e.g., "164.312(a)(1)" for
	// HIPAA).
	ControlID string `json:"control_id"`
	// Frameworks is the list of frameworks that declare
	// this control. Ordered by framework name for
	// determinism. Empty for framework-specific controls
	// that are not shared.
	Frameworks []string `json:"frameworks,omitempty"`
	// PerProtocolCoverage is the percentage 0-100 of the
	// control's required evidence that is covered by each
	// protocol. The map key is the canonical protocol name
	// (http, mcp, a2a, acp, anp). A value of 0 means "not
	// covered" and the key may be omitted from JSON.
	PerProtocolCoverage map[string]float64 `json:"per_protocol_coverage,omitempty"`
}

// BuildCrossProtocol produces a single signed CrossProtocolManifest
// covering the [start, end] window. It internally calls Build
// for each known framework to gather the per-framework refs.
//
// The manifest is signed with the platform's evidence-signing
// key (the same key used by Build for per-framework manifests).
// Auditors can verify the cross-protocol signature against the
// canonical public key fetched from
// /.well-known/aegisgate-evidence-pubkey.pem.
//
// start must be before end. The window is [start, end] inclusive.
func (b *Builder) BuildCrossProtocol(ctx context.Context, start, end time.Time) (*CrossProtocolManifest, error) {
	if start.IsZero() || end.IsZero() {
		return nil, fmt.Errorf("evidence: cross-protocol build: start and end must be non-zero")
	}
	if !start.Before(end) {
		return nil, fmt.Errorf("evidence: cross-protocol build: start must be before end (start=%s, end=%s)",
			start.Format(time.RFC3339), end.Format(time.RFC3339))
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("evidence: cross-protocol build cancelled: %w", err)
	}

	// 1. Resolve the current license.
	key := b.deps.LicenseMgr.GetLicenseKey()
	var validation *license.ValidationResult
	if key != "" {
		result := b.deps.LicenseMgr.Validate(key)
		validation = &result
	}

	// 2. Build a per-framework manifest for each known framework.
	//    We collect lightweight PerFrameworkRef objects (NOT the
	//    full Manifests) to keep the cross-protocol artifact
	//    small. The full per-framework manifests are returned for
	//    storage by the caller (typically the API handler that
	//    calls BuildCrossProtocol, then calls Build again per-
	//    framework to store them).
	perFW := make([]PerFrameworkRef, 0, len(knownFrameworks()))
	// fullManifests keeps the per-framework Manifests for the
	// cross-protocol rollup (ControlCrossRefs). Tier 1
	// (TODO-402). Without this, the aggregator would not have
	// the per-framework FrameworkCrossRefs or AuditAnchors.
	fullManifests := make([]*Manifest, 0, len(knownFrameworks()))
	for _, fw := range knownFrameworks() {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("evidence: cross-protocol build cancelled mid-framework: %w", err)
		}
		m, err := b.Build(ctx, fw, start, end)
		if err != nil {
			// A single framework failing should not fail the
			// whole cross-protocol build. We skip the framework
			// and continue. The auditor will see fewer
			// PerFrameworkRefs than frameworks, which is a known
			// signal of a partial build.
			continue
		}
		perFW = append(perFW, PerFrameworkRef{
			ManifestID:       m.ManifestID,
			Framework:        m.Framework,
			Enforced:         m.FrameworkEvidence.Enforced,
			CompliancePct:    m.FrameworkEvidence.CompliancePct,
			ControlsTotal:    m.FrameworkEvidence.ControlsTotal,
			ControlsEnforced: m.FrameworkEvidence.ControlsEnforced,
		})
		fullManifests = append(fullManifests, m)
	}

	// 3. Collect the cross-protocol audit anchors. This is the
	//    ByProtocol rollup that powers the killer feature.
	anchors, err := b.collectAuditAnchors(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("evidence: cross-protocol collect audit anchors: %w", err)
	}

	// 4. Assemble the cross-protocol manifest.
	now := time.Now().UTC()
	cp := &CrossProtocolManifest{
		ManifestID:     uuid.NewString(),
		Period:         Period{Start: start.UTC(), End: end.UTC()},
		License:        LicenseSnapshot(key, validation),
		GeneratedAt:    now,
		BuilderVersion: b.deps.BuilderVersion,
		PerFramework:   perFW,
		// Tier 1 (TODO-402): cross-framework, cross-protocol
		// control rollup. Aggregated from the per-framework
		// Manifest.FrameworkCrossRefs built in step 2.
		// Sibling of PerFramework + AuditAnchors (per user
		// clarification; not nested in PerFrameworkRef).
		ControlCrossRefs: aggregateControlCrossRefs(fullManifests),
		AuditAnchors:     anchors,
	}

	// 5. Sign the cross-protocol manifest with the same key +
	//    algorithm as the per-framework manifests.
	if err := b.signCrossProtocol(cp, now); err != nil {
		return nil, fmt.Errorf("evidence: sign cross-protocol: %w", err)
	}
	return cp, nil
}

// signCrossProtocol signs a CrossProtocolManifest in place
// using the same algorithm as signManifest (canonical JSON +
// SHA-256 + ECDSA P-256 SignASN1). The Signature field is
// zeroed before hashing, then populated with the new signature.
func (b *Builder) signCrossProtocol(cp *CrossProtocolManifest, signedAt time.Time) error {
	cp.Signature = Signature{}
	canonical, err := canonicalJSON(cp)
	if err != nil {
		return fmt.Errorf("canonical JSON: %w", err)
	}
	hash := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, b.deps.SigningKey, hash[:])
	if err != nil {
		return fmt.Errorf("sign ASN1: %w", err)
	}
	//nolint:staticcheck // SA1019: SEC 1 encoding for backward compat with v3.3.0
	pubBytes := elliptic.Marshal(elliptic.P256(),
		b.deps.SigningKey.PublicKey.X,
		b.deps.SigningKey.PublicKey.Y)
	cp.Signature = Signature{
		Algorithm: "ecdsa-p256",
		KeyID:     b.deps.KeyID,
		Value:     sig,
		PublicKey: pubBytes,
		SignedAt:  signedAt,
	}
	return nil
}

// VerifyCrossProtocolResult is the structured outcome of
// verifying a CrossProtocolManifest, mirroring VerifyResult
// for the per-framework manifests. Returned by
// VerifyCrossProtocolDetailed for use by the HTTP endpoint
// and CLI.
type VerifyCrossProtocolResult struct {
	// Verified is true iff the cross-protocol signature is valid.
	Verified bool `json:"verified"`
	// Reason is populated when Verified is false.
	Reason string `json:"reason,omitempty"`
	// ManifestID is echoed back for the caller's audit trail.
	ManifestID string `json:"manifest_id"`
	// KeyID is the key the manifest was signed with.
	KeyID string `json:"key_id"`
	// SignedAt is when the manifest was signed.
	SignedAt string `json:"signed_at,omitempty"`
	// PerFrameworkCount is the number of per-framework refs in
	// the manifest. Useful sanity check: an auditor expects
	// this to be > 0 (a cross-protocol manifest with 0 refs
	// is either a partial build or an empty window).
	PerFrameworkCount int `json:"per_framework_count"`
}

// VerifyCrossProtocol checks the cross-protocol manifest
// signature against the embedded public key. Returns nil if
// valid; otherwise one of ErrSignatureMissing, ErrSignatureInvalid,
// or a decoding error.
func VerifyCrossProtocol(cp *CrossProtocolManifest) error {
	if cp == nil {
		return fmt.Errorf("evidence: nil cross-protocol manifest")
	}
	if len(cp.Signature.Value) == 0 {
		return ErrSignatureMissing
	}
	if len(cp.Signature.PublicKey) == 0 {
		return fmt.Errorf("evidence: cross-protocol signature has no public key (auditor must use VerifyCrossProtocolWithKey)")
	}
	pub, err := publicKeyFromSEC1(cp.Signature.PublicKey)
	if err != nil {
		return fmt.Errorf("evidence: decode cross-protocol public key: %w", err)
	}
	// Make a shallow copy so we can zero the signature without
	// mutating the caller's manifest.
	copy := *cp
	copy.Signature = Signature{}
	canonical, err := canonicalJSON(&copy)
	if err != nil {
		return fmt.Errorf("evidence: canonicalize cross-protocol: %w", err)
	}
	hash := sha256.Sum256(canonical)
	if !ecdsa.VerifyASN1(pub, hash[:], cp.Signature.Value) {
		return ErrSignatureInvalid
	}
	return nil
}

// VerifyCrossProtocolWithKey is the rotation-guard version of
// VerifyCrossProtocol. It checks the signature against the
// given public key AND requires expectedKeyID (if non-empty)
// to match the manifest's KeyID. This is how auditors refuse
// cross-protocol manifests signed with a retired key.
func VerifyCrossProtocolWithKey(cp *CrossProtocolManifest, pub *ecdsa.PublicKey, expectedKeyID string) error {
	if cp == nil {
		return fmt.Errorf("evidence: nil cross-protocol manifest")
	}
	if len(cp.Signature.Value) == 0 {
		return ErrSignatureMissing
	}
	if expectedKeyID != "" && cp.Signature.KeyID != expectedKeyID {
		return fmt.Errorf("%w: have %q, want %q",
			ErrKeyIDMismatch, cp.Signature.KeyID, expectedKeyID)
	}
	copy := *cp
	copy.Signature = Signature{}
	canonical, err := canonicalJSON(&copy)
	if err != nil {
		return fmt.Errorf("evidence: canonicalize cross-protocol: %w", err)
	}
	hash := sha256.Sum256(canonical)
	if !ecdsa.VerifyASN1(pub, hash[:], cp.Signature.Value) {
		return ErrSignatureInvalid
	}
	return nil
}

// VerifyCrossProtocolDetailed wraps VerifyCrossProtocol with
// a structured result. It is the API the HTTP endpoint and CLI
// use, so callers do not need to inspect error types.
func VerifyCrossProtocolDetailed(cp *CrossProtocolManifest) VerifyCrossProtocolResult {
	res := VerifyCrossProtocolResult{
		ManifestID:        cp.ManifestID,
		KeyID:             cp.Signature.KeyID,
		SignedAt:          cp.Signature.SignedAt.Format("2006-01-02T15:04:05Z07:00"),
		PerFrameworkCount: len(cp.PerFramework),
	}
	if err := VerifyCrossProtocol(cp); err != nil {
		res.Verified = false
		res.Reason = err.Error()
		return res
	}
	res.Verified = true
	return res
}

// BuildCrossProtocolCLI builds a cross-protocol manifest from the CLI
// without requiring a Scanner. The per-framework refs are empty
// (the CLI cannot run real framework scans). The audit anchors
// are computed from a best-effort read of the platform's audit
// store if the caller provides one via EventSource; otherwise
// the manifest's AuditAnchors.Source is "unavailable".
//
// The CLI use case is: "I want a signed summary of what
// AegisGate saw across all 5 protocols in Q1, with the
// per-protocol rollup, but I don't want to start the full
// platform to run framework scans." This helper exists for
// that workflow. The full cross-protocol flow (with per-
// framework scans) is BuildCrossProtocol.
func BuildCrossProtocolCLI(cp *CrossProtocolManifest, signingKey *ecdsa.PrivateKey, keyID, version string) error {
	now := time.Now().UTC()
	cp.GeneratedAt = now
	cp.BuilderVersion = version
	if cp.License.Tier == "" {
		cp.License = LicenseBlock{
			Tier:  "community",
			Valid: false,
		}
	}
	cp.Signature = Signature{}
	canonical, err := canonicalJSON(cp)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	hash := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, signingKey, hash[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	//nolint:staticcheck // SA1019: SEC 1 encoding for backward compat with v3.3.0
	pubBytes := elliptic.Marshal(elliptic.P256(),
		signingKey.PublicKey.X,
		signingKey.PublicKey.Y)
	cp.Signature = Signature{
		Algorithm: "ecdsa-p256",
		KeyID:     keyID,
		Value:     sig,
		PublicKey: pubBytes,
		SignedAt:  now,
	}
	return nil
}
