// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Attestation Type Registry (v3.5.0+, Tier 5 prep)
//
// types.go defines the Type registry (which attestation types
// are valid) and the Subject grammar (URI-style per the
// Council of Mine's 8/8 unanimous Devil's Advocate decision on
// 2026-06-15d).
//
// Frozen 2026-06-15d.

package attestation

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Type is the schema identifier for the envelope's payload.
// Format: "<domain>.<schema-name>.v<major>".
//
// New types are added by appending to the allTypes slice (or
// via RegisterType at package init time for feature packages).
// ValidateType checks every envelope's Type against this list.
type Type string

// The 7 registered types (frozen 2026-06-15d).
// See plans/ENVELOPE-DESIGN-v1.1-FROZEN.md §4.1.
const (
	// c3 cross-protocol evidence manifest (shipped 2026-06-15c).
	// Migrated to the envelope in v3.5.0+.
	TypeEvidenceManifest Type = "evidence.manifest.v1"

	// c1 cross-protocol evidence rollup (shipped 2026-06-15c).
	TypeEvidenceCrossProtocol Type = "evidence.cross_protocol.v1"

	// TODO-301 AR-EaaS evaluation result.
	TypeEvaluatorRun Type = "evaluator.run.v1"

	// TODO-302 AIBOM (CycloneDX extension).
	TypeAIBOM Type = "aibom.cyclonedx.v1"

	// TODO-303 Agent Intent Signing.
	TypeAgentIntent Type = "a2a.intent.v1"

	// TODO-304 Prompt Cache Poisoning Detection attestation.
	TypePromptCacheAttestation Type = "promptcache.attestation.v1"

	// TODO-305 CVE-for-AI Feed entry.
	TypeCVEEntry Type = "cve.entry.v1"
)

// TypeSpec is the human-readable metadata for a registered
// type. Verifiers in other languages use this to look up the
// JSON Schema for the payload.
type TypeSpec struct {
	Domain      string
	Name        string
	Version     int
	SchemaURL   string
	Owner       string
	Description string
}

// allTypes is the registry. New types append here. The list is
// intentionally hard-coded (not a runtime map) so the set of
// valid types is auditable from source.
//
// The map's zero value is also valid: an empty registry means
// no types are registered. This is the "fresh install" state
// before any feature package has called RegisterType.
var allTypes = map[Type]TypeSpec{
	TypeEvidenceManifest: {
		Domain:      "evidence",
		Name:        "manifest",
		Version:     1,
		SchemaURL:   "https://aegisgatesecurity.io/schemas/evidence.manifest.v1.json",
		Owner:       "pkg/evidence",
		Description: "Per-framework compliance evidence manifest (c3 verifiable compliance primitive).",
	},
	TypeEvidenceCrossProtocol: {
		Domain:      "evidence",
		Name:        "cross_protocol",
		Version:     1,
		SchemaURL:   "https://aegisgatesecurity.io/schemas/evidence.cross_protocol.v1.json",
		Owner:       "pkg/evidence",
		Description: "Cross-protocol evidence rollup across the 5 protocol pillars.",
	},
	TypeEvaluatorRun: {
		Domain:      "evaluator",
		Name:        "run",
		Version:     1,
		SchemaURL:   "https://aegisgatesecurity.io/schemas/evaluator.run.v1.json",
		Owner:       "pkg/evaluator",
		Description: "AR-EaaS evaluation result (TODO-301).",
	},
	TypeAIBOM: {
		Domain:      "aibom",
		Name:        "cyclonedx",
		Version:     1,
		SchemaURL:   "https://aegisgatesecurity.io/schemas/aibom.cyclonedx.v1.json",
		Owner:       "pkg/aibom",
		Description: "AI Bill of Materials in CycloneDX format (TODO-302).",
	},
	TypeAgentIntent: {
		Domain:      "a2a",
		Name:        "intent",
		Version:     1,
		SchemaURL:   "https://aegisgatesecurity.io/schemas/a2a.intent.v1.json",
		Owner:       "pkg/a2a",
		Description: "Agent Intent Signing - cryptographic A2A intent binding (TODO-303).",
	},
	TypePromptCacheAttestation: {
		Domain:      "promptcache",
		Name:        "attestation",
		Version:     1,
		SchemaURL:   "https://aegisgatesecurity.io/schemas/promptcache.attestation.v1.json",
		Owner:       "pkg/promptcache",
		Description: "Prompt Cache Poisoning Detection attestation (TODO-304).",
	},
	TypeCVEEntry: {
		Domain:      "cve",
		Name:        "entry",
		Version:     1,
		SchemaURL:   "https://aegisgatesecurity.io/schemas/cve.entry.v1.json",
		Owner:       "pkg/cve",
		Description: "CVE-for-AI Feed entry (TODO-305).",
	},
}

// subjectScheme is the URI scheme for envelope subjects. This
// is a non-standard scheme; we register it as a "known opaque"
// scheme with net/url.
const subjectScheme = "aegisgate"

// knownKinds lists the registered subject kinds. The list is
// parallel to the Type registry but is a separate concept: a
// Type identifies the payload schema, a Kind identifies the
// subject's nature.
//
// Feature packages register new kinds via RegisterKind at
// package init time.
var knownKinds = map[string]bool{
	"prompt":     true,
	"deployment": true,
	"agent":      true,
	"manifest":   true,
	"ioc":        true,
	"evaluation": true,
	"cve":        true,
	"intent":     true,
}

// ValidateType returns an error if t is not in the registry.
// This is a defense against typos and unknown future versions.
func ValidateType(t Type) error {
	if _, ok := allTypes[t]; !ok {
		return fmt.Errorf("attestation: unknown type %q (not in registry)", string(t))
	}
	return nil
}

// RegisterType adds a new type to the registry. Typically
// called from package init() in feature packages. Returns
// an error if the type is already registered (prevents
// accidental double-registration).
func RegisterType(t Type, spec TypeSpec) error {
	if _, exists := allTypes[t]; exists {
		return fmt.Errorf("attestation: type %q already registered", string(t))
	}
	if spec.Domain == "" || spec.Name == "" {
		return fmt.Errorf("attestation: type %q missing domain or name", string(t))
	}
	if spec.Owner == "" {
		return fmt.Errorf("attestation: type %q missing owner package", string(t))
	}
	allTypes[t] = spec
	return nil
}

// RegisterKind adds a new subject kind to the registry. Called
// from package init() in feature packages.
func RegisterKind(kind string) error {
	if kind == "" {
		return fmt.Errorf("attestation: empty subject kind")
	}
	if !isASCII(kind) {
		return fmt.Errorf("attestation: non-ASCII subject kind %q", kind)
	}
	if knownKinds[kind] {
		return fmt.Errorf("attestation: subject kind %q already registered", kind)
	}
	knownKinds[kind] = true
	return nil
}

// parseSubject splits a Subject URL into its (kind, id) parts.
// Returns an error if the Subject is malformed (wrong scheme,
// missing components, unknown kind, or non-ASCII parts).
//
// Format: aegisgate://<kind>/<id>
//
// Go's net/url parses this as Scheme=aegisgate, Host=<kind>,
// Path=/<id>. The path may contain additional slashes
// (everything after the first segment is the id).
func parseSubject(subject string) (kind string, id string, err error) {
	if subject == "" {
		return "", "", fmt.Errorf("attestation: empty subject")
	}
	u, err := url.Parse(subject)
	if err != nil {
		return "", "", fmt.Errorf("attestation: parse subject %q: %w", subject, err)
	}
	if u.Scheme != subjectScheme {
		return "", "", fmt.Errorf("attestation: subject scheme %q (want %q)", u.Scheme, subjectScheme)
	}
	// Go's net/url puts the first path segment in Host (per
	// the generic URI grammar). For aegisgate://kind/id, the
	// kind is the Host, and the id is the Path (without the
	// leading slash).
	kind = u.Host
	id = strings.TrimPrefix(u.Path, "/")
	if kind == "" {
		return "", "", fmt.Errorf("attestation: empty subject kind (want aegisgate://<kind>/<id>)")
	}
	if id == "" {
		return "", "", fmt.Errorf("attestation: subject missing id (want aegisgate://<kind>/<id>)")
	}
	if !isASCII(kind) {
		return "", "", fmt.Errorf("attestation: non-ASCII subject kind %q", kind)
	}
	if !isASCII(id) {
		return "", "", fmt.Errorf("attestation: non-ASCII subject id %q", id)
	}
	return kind, id, nil
}

// validateSubject is the high-level validator: parses the
// Subject, checks the kind against the registry. The id is
// returned to the caller for feature-specific validation
// (which the feature package does in its own ValidateID func).
func validateSubject(subject string) (kind string, id string, err error) {
	kind, id, err = parseSubject(subject)
	if err != nil {
		return "", "", err
	}
	if !knownKinds[kind] {
		return "", "", fmt.Errorf("attestation: unknown subject kind %q", kind)
	}
	return kind, id, nil
}

// RegisteredTypes returns a sorted list of all registered
// types. Useful for CLI/diagnostic output.
func RegisteredTypes() []Type {
	out := make([]Type, 0, len(allTypes))
	for t := range allTypes {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// RegisteredKinds returns a sorted list of all registered
// subject kinds. Useful for CLI/diagnostic output.
func RegisteredKinds() []string {
	out := make([]string, 0, len(knownKinds))
	for k := range knownKinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
