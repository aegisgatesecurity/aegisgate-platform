// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.3.0+)
//
// builder.go is the orchestrator. Build(license, framework, start, end)
// returns a signed Manifest, or an error if any required input is
// missing. The Builder is safe to share across goroutines - it has
// no mutable state of its own (the signing key is held via the
// injected deps).
//
// v3.3.0+ Track 2.

package evidence

//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B (Sprint 19+). See plans/TECHNICAL-DEBT.md.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// knownFrameworks is the set of framework names accepted by Build.
// All identifiers are lowercase to match the TierManager convention.
// The free frameworks (atlas, owasp, nist_ai_rmf) are translated to
// the Scanner uppercase form at scan time via scannerFrameworkID().
func knownFrameworks() []string {
	return []string{
		"hipaa", "pci", "soc2", "iso42001", "fedramp", "fips",
		"eu_ai_act", "iso27001", "nist_csf", "cis", "cmmcl2",
		"nist800171", "hitrust", "tisax", "ccpa", "nist_ai_rmf",
		"csa_star", "nist_ai_600_1", "owasp_web",
		"atlas", "owasp", "gdpr",
	}
}

// scannerFrameworkID translates an evidence package framework ID
// (lowercase, e.g., "atlas") to the corresponding Scanner framework
// ID (uppercase, e.g., "ATLAS"). The two naming conventions exist
// because the TierManager uses lowercase IDs (matching the customer
// portal and gating API) while the compliance Scanner uses the full
// Framework constants (matching the regulatory text and external
// integrations). This translation is the bridge between them.
//
// If you add a new framework, update BOTH the TierManager and the
// Scanner, and add the translation here. The knownFrameworks() list
// above also needs the lowercase form.
func scannerFrameworkID(framework string) string {
	// All framework IDs are now lowercase canonical IDs.
	// The old uppercase constants (FrameworkATLAS = "ATLAS", etc.)
	// are kept for backward compatibility but the scanner and tier
	// manager use lowercase IDs throughout.
	return framework
}

// BuilderDeps is the set of dependencies the Builder needs. Most
// fields are required; the EventSource is optional (manifest builds
// without it, AuditAnchors.Source = "unavailable").
type BuilderDeps struct {
	// Scanner is the compliance scan engine. Required.
	Scanner *compliance.Scanner
	// LicenseMgr is the license manager. Required.
	LicenseMgr *license.Manager
	// SigningKey is the platform ECDSA P-256 key used to sign the
	// manifest's legacy Signature field. Required.
	SigningKey *ecdsa.PrivateKey
	// KeyID is the opaque identifier for the signing key. Required.
	KeyID string
	// BuilderVersion is the AegisGate version that appears in the
	// manifest. Required.
	BuilderVersion string
	// EventSource is the audit event aggregator. Optional; nil is OK.
	EventSource EventSource
	// KeyRing is the IOC keyring. OPTIONAL. When set, the builder
	// wraps the manifest in an attestation.Envelope (v3.5.0+ path)
	// in addition to the legacy c3 Signature. When nil, the builder
	// uses only the legacy c3 path (v3.4.0-beta.1 behavior).
	//
	// Tier 5 prep. See plans/ENVELOPE-DESIGN-v1.1-FROZEN.md §5.
	KeyRing *ioc.KeyRing
}

// Builder is the evidence-package orchestrator. Safe for concurrent use.
type Builder struct {
	deps BuilderDeps
}

// NewBuilder validates the deps and returns a Builder. Returns an
// error if any required dep is nil. This is the fail-closed entry
// point: a misconfigured Builder cannot accidentally emit an
// unsigned manifest.
func NewBuilder(deps BuilderDeps) (*Builder, error) {
	if deps.Scanner == nil {
		return nil, fmt.Errorf("evidence: Scanner is required")
	}
	if deps.LicenseMgr == nil {
		return nil, fmt.Errorf("evidence: LicenseMgr is required")
	}
	if deps.SigningKey == nil {
		return nil, fmt.Errorf("evidence: SigningKey is required")
	}
	if deps.KeyID == "" {
		return nil, fmt.Errorf("evidence: KeyID is required")
	}
	if deps.BuilderVersion == "" {
		return nil, fmt.Errorf("evidence: BuilderVersion is required")
	}
	return &Builder{deps: deps}, nil
}

// Build produces a signed Manifest for the given framework and
// time period. The manifest is deterministic in the sense that
// calling Build twice with the same inputs produces manifests with
// the same content fields (only the ManifestID, GeneratedAt, and
// Signature.SignedAt will differ).
//
// framework must be one of knownFrameworks().
// start must be before end. The window is [start, end] inclusive.
func (b *Builder) Build(ctx context.Context, framework string, start, end time.Time) (*Manifest, error) {
	if err := validateBuildInputs(framework, start, end); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("evidence: build cancelled: %w", err)
	}

	// 1. Resolve the current license.
	key := b.deps.LicenseMgr.GetLicenseKey()
	var validation *license.ValidationResult
	if key != "" {
		result := b.deps.LicenseMgr.Validate(key)
		validation = &result
	}

	// 2. Run the framework scan. We use the real compliance.Scanner
	//    so the per-control results match what /api/v1/compliance/report
	//    would return today.
	scanResult, assessment, err := b.deps.Scanner.ScanFramework(ctx, validation, scannerFrameworkID(framework))
	if err != nil {
		return nil, fmt.Errorf("evidence: scan framework %q: %w", framework, err)
	}

	// 3. Collect audit anchors (best-effort).
	anchors, err := b.collectAuditAnchors(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("evidence: collect audit anchors: %w", err)
	}

	// 4. Assemble the manifest.
	now := time.Now().UTC()
	manifest := &Manifest{
		ManifestID:       uuid.NewString(),
		Framework:        framework,
		FrameworkVersion: scanResult.DisplayName, // best-effort; future work can supply exact spec version
		Period: Period{
			Start: start.UTC(),
			End:   end.UTC(),
		},
		License:           LicenseSnapshot(key, validation),
		GeneratedAt:       now,
		BuilderVersion:    b.deps.BuilderVersion,
		FrameworkEvidence: toFrameworkEvidence(scanResult, assessment),
		AuditAnchors:      anchors,
		// Tier 1 (TODO-402): per-framework cross-framework
		// control references. Top-level field, parallel to
		// AuditAnchors. Built from the assessment's
		// per-control results, with each control ID looked
		// up in the pkg/compliance FrameworkMapping
		// library. nil -> omitted from JSON, so legacy
		// manifests are byte-identical.
		FrameworkCrossRefs: b.collectFrameworkCrossRefs(framework, assessment),
	}

	// 5. Sign the manifest. The signature is over a SHA-256 hash of
	//    the canonicalized manifest JSON (Signature field zeroed).
	if err := b.signManifest(manifest, now); err != nil {
		return nil, fmt.Errorf("evidence: sign manifest: %w", err)
	}
	return manifest, nil
}

// canonicalFrameworkID maps a library-emitted target framework
// name to a canonical, lowercase-with-underscores ID. The
// pkg/compliance library emits human-readable names (e.g.,
// "MITRE ATLAS", "NIST AI RMF") while the rest of the platform
// uses canonical IDs (e.g., "mitre_atlas", "nist_ai_rmf").
// Canonicalization at the wire-up boundary lets the auditor
// correlate the manifest's cross-references with the rest of
// the platform's reporting.
//
// Unknown values are returned lowercased + spaces-replaced so
// the manifest at least has a stable, URL-safe key. The
// fallback is intentionally permissive (does not drop unknown
// frameworks) to avoid silently losing audit data.
func canonicalFrameworkID(s string) string {
	switch s {
	case "MITRE ATLAS", "ATLAS", "mitre_atlas", "atlas":
		return "atlas"
	case "NIST AI RMF", "NIST.AI-1.500", "nist_ai_rmf":
		return "nist_ai_rmf"
	case "OWASP", "owasp", "OWASP LLM Top 10", "owasp_llm":
		return "owasp"
	case "OWASP Top 10", "owasp_web":
		return "owasp_web"
	case "GDPR", "gdpr":
		return "gdpr"
	case "CIS v8", "CIS", "cis":
		return "cis"
	case "NIST CSF 2.0", "nist_csf":
		return "nist_csf"
	case "NIST AI 600-1", "nist_ai_600_1":
		return "nist_ai_600_1"
	case "CSA STAR", "csa_star":
		return "csa_star"
	case "CCPA/CPRA", "CCPA", "ccpa":
		return "ccpa"
	case "ISO 27001", "iso27001":
		return "iso27001"
	case "CMMC Level 2", "cmmcl2":
		return "cmmcl2"
	case "NIST 800-171", "nist800171":
		return "nist800171"
	case "HITRUST CSF", "hitrust":
		return "hitrust"
	case "TISAX AL2", "tisax":
		return "tisax"
	case "CWE", "cwe":
		return "cwe"
	case "CVE", "cve":
		return "cve"
	}
	// Fallback: lowercase + spaces -> underscores.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '-' || c == '/' {
			out = append(out, '_')
			continue
		}
		if c >= 'A' && c <= 'Z' {
			out = append(out, c+('a'-'A'))
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// collectFrameworkCrossRefs walks the per-control results from
// the framework assessment and produces a slice of
// FrameworkCrossRef, one per control. Each entry's Targets map
// is populated by looking up the control ID in the
// pkg/compliance FrameworkMapping library.
//
// Returns nil (not an empty slice) when the assessment has no
// per-control results, so the manifest's FrameworkCrossRefs
// field is omitted from JSON entirely. The Builder does not
// return an error: a missing or unparseable mapping for a
// control produces a no-Targets entry (the auditor still sees
// the control is being attested).
//
// Tier 1 (TODO-402).
func (b *Builder) collectFrameworkCrossRefs(framework string, assessment *compliance.FrameworkAssessment) []FrameworkCrossRef {
	if assessment == nil || len(assessment.Results) == 0 {
		return nil
	}
	mapping := compliance.NewFrameworkMapping()
	if mapping == nil {
		// Library failure is non-fatal; we return what we can.
		return nil
	}
	out := make([]FrameworkCrossRef, 0, len(assessment.Results))
	for _, result := range assessment.Results {
		if result == nil || result.ControlID == "" {
			continue
		}
		// Look up cross-framework mappings for this control.
		rels := mapping.GetMappingsForControl(result.ControlID)
		targets := make(map[string][]string, 4)
		var (
			bestConfidence float32
			description    string
			relationship   string
		)
		for _, rel := range rels {
			if rel.TargetFramework == "" || len(rel.TargetControls) == 0 {
				continue
			}
			// Canonicalize the library's human-readable
			// framework name to the platform's canonical
			// ID. See canonicalFrameworkID.
			key := canonicalFrameworkID(rel.TargetFramework)
			// Append to the targets map; de-dupe within a
			// framework.
			existing := targets[key]
			for _, id := range rel.TargetControls {
				dup := false
				for _, e := range existing {
					if e == id {
						dup = true
						break
					}
				}
				if !dup {
					existing = append(existing, id)
				}
			}
			targets[key] = existing
			// Track the highest-confidence relationship for
			// the metadata fields.
			if rel.Confidence > bestConfidence {
				bestConfidence = rel.Confidence
				description = rel.Description
				relationship = rel.Relationship
			}
		}
		entry := FrameworkCrossRef{
			SourceFramework: framework,
			SourceControl:   result.ControlID,
			ControlName:     result.ControlName,
			Targets:         targets,
			Confidence:      bestConfidence,
			Description:     description,
			Relationship:    relationship,
		}
		// Skip entries with no targets AND no name: they add
		// noise to the manifest without giving the auditor
		// any new information. We keep entries with name but
		// no targets (the auditor still sees the control was
		// checked).
		if len(entry.Targets) == 0 && entry.ControlName == "" {
			continue
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// aggregateControlCrossRefs walks the per-framework Manifests
// and aggregates the FrameworkCrossRefs into a cross-protocol
// rollup. The rollup answers "for each shared control, which
// protocols emit evidence and what is the coverage?"
//
// For v3.5.0-alpha-1 the coverage math is simplified: a control
// that appears in the per-framework Manifest is treated as
// 100%-covered for the protocols the AuditAnchors.ByProtocol
// field reports. This is a meaningful approximation because
// the per-protocol evidence source is the audit ring buffer,
// which already counts per-protocol events. A more rigorous
// per-protocol coverage calculation is left as a follow-up
// (it requires per-protocol tagging on the audit events,
// which the framework-scanner does not currently produce).
//
// The aggregation is deterministic: ControlIDs are sorted
// alphabetically, Frameworks are sorted alphabetically, and
// PerProtocolCoverage keys are sorted. Two consecutive
// BuildCrossProtocol calls produce identical ControlCrossRefs
// (modulo the AggregatedAt timestamp on the wrapping manifest).
//
// Tier 1 (TODO-402).
func aggregateControlCrossRefs(perFrameworkManifests []*Manifest) []FrameworkControlRef {
	if len(perFrameworkManifests) == 0 {
		return nil
	}
	// Map: control ID -> set of frameworks -> set of protocols.
	// We use a nested map for O(1) lookups, then convert to the
	// sorted slice shape for determinism.
	type ctrlState struct {
		frameworks map[string]struct{}
		protocols  map[string]float64
	}
	byControl := make(map[string]*ctrlState)
	for _, m := range perFrameworkManifests {
		if m == nil {
			continue
		}
		// Pull protocols from AuditAnchors. Default to 100%
		// for any protocol in the ByProtocol map (the ring
		// buffer already counted events for it).
		protocols := make(map[string]float64, len(m.AuditAnchors.ByProtocol))
		for proto, count := range m.AuditAnchors.ByProtocol {
			// A non-zero count is "covered". The
			// 100% approximation is the v3.5.0-alpha-1
			// simplification; the per-protocol coverage
			// percentage is a follow-up.
			if count > 0 {
				protocols[proto] = 100.0
			}
		}
		for _, xref := range m.FrameworkCrossRefs {
			if xref.SourceControl == "" {
				continue
			}
			st, ok := byControl[xref.SourceControl]
			if !ok {
				st = &ctrlState{
					frameworks: make(map[string]struct{}),
					protocols:  make(map[string]float64),
				}
				byControl[xref.SourceControl] = st
			}
			if xref.SourceFramework != "" {
				st.frameworks[xref.SourceFramework] = struct{}{}
			}
			// Merge protocols (max coverage wins).
			for p, cov := range protocols {
				if cov > st.protocols[p] {
					st.protocols[p] = cov
				}
			}
			// If the control has Targets, also include the
			// target frameworks as the "frameworks" list.
			// This is what makes the rollup cross-framework:
			// a HIPAA control whose Targets include
			// "mitre_atlas" gets the "mitre_atlas" framework
			// added to its Frameworks list.
			for tf := range xref.Targets {
				st.frameworks[tf] = struct{}{}
			}
		}
	}
	if len(byControl) == 0 {
		return nil
	}
	// Deterministic ordering: sort by ControlID.
	controlIDs := make([]string, 0, len(byControl))
	for id := range byControl {
		controlIDs = append(controlIDs, id)
	}
	sort.Strings(controlIDs)
	out := make([]FrameworkControlRef, 0, len(controlIDs))
	for _, id := range controlIDs {
		st := byControl[id]
		// Sort frameworks.
		frameworks := make([]string, 0, len(st.frameworks))
		for fw := range st.frameworks {
			frameworks = append(frameworks, fw)
		}
		sort.Strings(frameworks)
		// Sort protocol coverage keys for determinism.
		protoKeys := make([]string, 0, len(st.protocols))
		for p := range st.protocols {
			protoKeys = append(protoKeys, p)
		}
		sort.Strings(protoKeys)
		perProto := make(map[string]float64, len(st.protocols))
		for _, p := range protoKeys {
			perProto[p] = st.protocols[p]
		}
		out = append(out, FrameworkControlRef{
			ControlID:           id,
			Frameworks:          frameworks,
			PerProtocolCoverage: perProto,
		})
	}
	return out
}

// collectAuditAnchors queries the EventSource if wired; otherwise
// returns an "unavailable" anchor set. The manifest still builds.
func (b *Builder) collectAuditAnchors(ctx context.Context, start, end time.Time) (AuditAnchors, error) {
	if b.deps.EventSource == nil {
		return AuditAnchors{Source: "unavailable"}, nil
	}
	byType, err := b.deps.EventSource.CountByType(ctx, start, end)
	if err != nil {
		return AuditAnchors{}, fmt.Errorf("count by type: %w", err)
	}
	bySev, err := b.deps.EventSource.CountBySeverity(ctx, start, end)
	if err != nil {
		return AuditAnchors{}, fmt.Errorf("count by severity: %w", err)
	}
	byFw, err := b.deps.EventSource.CountByFramework(ctx, start, end)
	if err != nil {
		return AuditAnchors{}, fmt.Errorf("count by framework: %w", err)
	}
	// CountByProtocol is the v3.4.0 primitive that powers the
	// cross-protocol evidence aggregation (c1). A failure here
	// is non-fatal: we still build the manifest, just with
	// ByProtocol omitted. The cross-protocol view is a
	// "nice to have" for now, not a regulatory requirement.
	byProto := map[string]int{}
	if p, perr := b.deps.EventSource.CountByProtocol(ctx, start, end); perr == nil {
		byProto = p
	}
	total := 0
	for _, n := range byType {
		total += n
	}
	return AuditAnchors{
		EventCount:  total,
		ByType:      byType,
		BySeverity:  bySev,
		ByFramework: byFw,
		ByProtocol:  byProto,
		Source:      "ring_buffer", // future: distinguish in-memory vs. db-backed
	}, nil
}

// signManifest computes the canonical hash of the manifest (Signature
// field zeroed) and signs it with the platform ECDSA P-256 key. The
// signature uses ASN.1 DER encoding, matching pkg/trust/attestation.
func (b *Builder) signManifest(m *Manifest, signedAt time.Time) error {
	// Tier 5 prep (v3.5.0+): if a KeyRing is configured, the
	// envelope is added BEFORE the legacy c3 signature is
	// computed. This ensures the legacy signature covers the
	// final manifest state (including the envelope). The
	// envelope itself wraps a canonicalized version of the
	// manifest WITHOUT the legacy signature (the signature
	// is in the to-be-signed envelope struct, not in the
	// manifest).
	if b.deps.KeyRing != nil {
		if err := b.signEnvelope(m); err != nil {
			// Envelope signing is non-fatal: if the envelope
			// fails (e.g., the KeyRing has no current key),
			// the manifest is still valid via the legacy
			// path.
			_ = err
		}
	}

	// Zero the signature field before hashing - we are signing the
	// manifest content, not the signature itself.
	zeroSig := Signature{}
	m.Signature = zeroSig

	canonical, err := canonicalJSON(m)
	if err != nil {
		return fmt.Errorf("canonical JSON: %w", err)
	}
	hash := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, b.deps.SigningKey, hash[:])
	if err != nil {
		return fmt.Errorf("sign ASN1: %w", err)
	}

	m.Signature = Signature{
		Algorithm: "ecdsa-p256",
		KeyID:     b.deps.KeyID,
		Value:     sig,
		//nolint:staticcheck // SA1019: elliptic.Marshal is deprecated as of Go 1.21
		// in favor of crypto/ecdh. Migration is planned for v3.4.0+ (see
		// legal-docs/21-self-attestation-v3.3.0.md §5.3 P1). For v3.3.0
		// we keep the existing SEC 1 encoding for backward compatibility
		// with pkg/trust/attestation.Generator.
		PublicKey: elliptic.Marshal(elliptic.P256(),
			b.deps.SigningKey.PublicKey.X,
			b.deps.SigningKey.PublicKey.Y),
		SignedAt: signedAt,
	}
	return nil
}

// signEnvelope wraps the manifest in an attestation.Envelope.
// Called only when b.deps.KeyRing is set. The envelope wraps
// the manifest's canonical JSON (the same bytes that the
// legacy c3 signature covers), so the envelope's signature
// and the legacy signature both attest to the same content.
//
// This function is called BEFORE signManifest's legacy
// signature is computed, so the legacy signature covers a
// manifest that already contains the envelope. The envelope
// itself wraps a canonicalized version of the manifest with
// the legacy signature field zeroed.
func (b *Builder) signEnvelope(m *Manifest) error {
	// Zero the legacy signature before canonicalizing for the
	// envelope's payload. The envelope will canonicalize the
	// result, and its own signature is over the canonical
	// form.
	tmp := *m
	tmp.Signature = Signature{}
	tmp.Attestation = nil // The envelope is being added now.
	manifestBytes, err := json.Marshal(&tmp)
	if err != nil {
		return fmt.Errorf("evidence: signEnvelope: marshal manifest: %w", err)
	}
	// Canonicalize via the envelope's JCS canonicalizer.
	canonicalPayload, err := attestation.CanonicalizeJSON(manifestBytes)
	if err != nil {
		return fmt.Errorf("evidence: signEnvelope: canonicalize: %w", err)
	}
	// The envelope subject is the manifest's aegisgate://manifest/<id>
	// URI per the Tier 5 URI-style grammar.
	subject := "aegisgate://manifest/" + m.ManifestID
	// The issuer is "<instance>:<key>". For the c3 path, we
	// don't have a stable instance-id (the c3 legacy key
	// doesn't track an instance). Use a synthetic instance-id
	// derived from the BuilderVersion; production callers
	// should override this via a future Builder option.
	instanceID := "c3-legacy:" + b.deps.BuilderVersion
	issuer := instanceID + ":" + b.deps.KeyID
	env, err := attestation.Sign(
		canonicalPayload,
		subject,
		attestation.TypeEvidenceManifest,
		issuer,
		b.deps.KeyRing,
		0, // no expiration; c3 manifests are long-lived
	)
	if err != nil {
		return fmt.Errorf("evidence: signEnvelope: attestation.Sign: %w", err)
	}
	m.Attestation = env
	return nil
}

// validateBuildInputs checks the framework and period are sane.
func validateBuildInputs(framework string, start, end time.Time) error {
	if framework == "" {
		return fmt.Errorf("evidence: framework is required")
	}
	found := false
	for _, f := range knownFrameworks() {
		if f == framework {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("evidence: unknown framework %q (known: %v)", framework, knownFrameworks())
	}
	if start.IsZero() || end.IsZero() {
		return fmt.Errorf("evidence: start and end must be non-zero")
	}
	if !start.Before(end) {
		return fmt.Errorf("evidence: start must be before end (start=%s, end=%s)",
			start.Format(time.RFC3339), end.Format(time.RFC3339))
	}
	return nil
}

// canonicalJSON returns the manifest serialized as compact JSON
// with sorted keys at every level. This is the form we hash and
// sign, so verification is independent of map iteration order.
//
// We use encoding/json with default settings - the Go JSON
// encoder sorts map keys alphabetically, which is exactly what
// we want. struct field order is determined by struct definition
// order, which is also deterministic.
func canonicalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// toFrameworkEvidence converts a compliance.FrameworkScanResult to
// our evidence.FrameworkEvidence. The two structs overlap but are
// not identical (evidence has Period, License, etc. that the scan
// result does not). This keeps the evidence package independent
// of changes to pkg/compliance.
func toFrameworkEvidence(scan *compliance.FrameworkScanResult, assessment *compliance.FrameworkAssessment) FrameworkEvidence {
	ev := FrameworkEvidence{
		Framework:           scan.Framework,
		DisplayName:         scan.DisplayName,
		Enforced:            scan.Enforced,
		Module:              scan.Module,
		Score:               scan.Score,
		ControlsTotal:       scan.ControlsTotal,
		ControlsEnforced:    scan.ControlsEnforced,
		CompliancePct:       scan.CompliancePct,
		ReasonEnforced:      scan.ReasonEnforced,
		ReasonNotEnforced:   scan.ReasonNotEnforced,
		MissingModules:      scan.MissingModules,
		UpgradeHint:         scan.UpgradeHint,
		ImplementationReady: scan.ImplementationReady,
	}
	if assessment != nil {
		ev.Assessment = toAssessment(assessment)
	}
	return ev
}

// toAssessment is currently a no-op because pkg/compliance has TWO
// competing FrameworkAssessment type declarations (a known tech-debt
// item in the platform). Once that is resolved, this function can be
// extended to copy per-control details into evidence.Assessment.
//
// For v0.1, the evidence package intentionally drops the per-control
// Assessment field on the manifest - it is set to nil by the caller.
// The framework-aggregate counts (Score, ControlsTotal,
// ControlsEnforced) are still copied from FrameworkScanResult above.
func toAssessment(_ *compliance.FrameworkAssessment) *Assessment {
	return nil
}
