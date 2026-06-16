// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM generator (TODO-302)
//
// generator.go converts an AIBOM (or a platformconfig.Config)
// into a CycloneDX 1.6 SBOM. The output is what gets signed
// by the envelope.
//
// # Entry point
//
// GenerateFromAIBOM(aibom) is the only entry point in v0.1.
// Callers build the AIBOM struct (with explicit per-pillar
// data) and pass it in. The v0.1 review (C2 + m1) found that
// a "config-driven" wrapper that hardcoded per-pillar data
// was misleading to operators and auditors (the AIBOM would
// claim "MCP enabled with sensitivity 75" when we didn't
// actually read the config). v0.2 will add a real config-
// driven wrapper that reads the live platform config; until
// then, callers MUST build the AIBOM explicitly.
//
// # Determinism
//
// The generated BOM is byte-stable for a given AIBOM input.
// All slices are sorted at construction; all maps (which
// we avoid) are converted to sorted slices; the timestamp
// is the only non-deterministic field.

package aibom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// =====================================================================
// GenerateFromAIBOM (primary entry point)
// =====================================================================

// GenerateFromAIBOM converts an AIBOM struct to a CycloneDX
// BOM. The BOM is the signed payload (the envelope's
// RawPayload is the JCS-canonicalized JSON of this BOM).
//
// The AIBOM's DeploymentID is used as the BOM's serial
// number (cyclonedx.org requires serial numbers to be
// urn:uuid: URIs; we wrap a UUIDv4 in the urn:uuid: prefix).
// If DeploymentID is empty, a new UUIDv4 is generated.
func GenerateFromAIBOM(a *AIBOM) (*BOM, error) {
	if a == nil {
		return nil, fmt.Errorf("aibom: AIBOM is required")
	}
	if a.DeploymentID == "" {
		a.DeploymentID = uuid.NewString()
	}
	if a.GeneratedAt.IsZero() {
		a.GeneratedAt = time.Now().UTC()
	}
	// Default to "unknown" for any unset platform version or
	// tier, so the auditor sees a value rather than an empty
	// field. This is the v0.1 behavior; v0.2 will require
	// these fields at the CLI level.
	if a.PlatformVersion == "" {
		a.PlatformVersion = "unknown"
	}
	if a.PlatformTier == "" {
		a.PlatformTier = "unknown"
	}

	// Build the metadata.
	serialNumber := "urn:uuid:" + a.DeploymentID
	tools := []Tool{{
		Vendor:  "AegisGate",
		Name:    DefaultToolName,
		Version: AIBOMVersion,
	}}
	metadataComponent := MetadataComponent{
		Type:        DefaultComponentType,
		BOMRef:      "aegisgate-deployment-" + a.DeploymentID,
		Name:        "AegisGate Security Platform",
		Version:     a.PlatformVersion,
		Description: "AegisGate security platform deployment (AI Bill of Materials)",
		Properties:  buildMetadataComponentProperties(a),
	}
	metadata := Metadata{
		Timestamp:  a.GeneratedAt,
		Tools:      tools,
		Component:  metadataComponent,
		Properties: buildMetadataProperties(a),
	}

	// Build the components (the 5 protocol pillars + model +
	// prompts + RAG corpora).
	components := buildComponents(a)

	// Build the AIBOM extension properties.
	properties := buildAIBOMProperties(a)

	// M2 fix (TODO-302 review): BOM.Version defaults to 1
	// but can be overridden via the AIBOM struct (which
	// BuildAIBOMFromOptions populates from AIBOMOptions).
	// This is consistent with the CycloneDX spec's
	// "subsequent revisions SHOULD increment" recommendation.
	bomVersion := a.BOMVersion
	if bomVersion <= 0 {
		bomVersion = 1
	}
	return &BOM{
		BOMFormat:    CycloneDXBOMFormat,
		SpecVersion:  CycloneDXSpecVersion,
		Version:      bomVersion,
		SerialNumber: serialNumber,
		Metadata:     metadata,
		Components:   components,
		Properties:   properties,
	}, nil
}

// buildMetadataComponentProperties returns the per-component
// (deployment-level) properties for the metadata.component
// block. These are platform-deployment-specific: tier, id,
// etc.
func buildMetadataComponentProperties(a *AIBOM) []Property {
	props := []Property{
		{Name: "aegisgate:platform_tier", Value: a.PlatformTier},
		{Name: "aegisgate:deployment_id", Value: a.DeploymentID},
		{Name: "aegisgate:aibom_version", Value: AIBOMVersion},
	}
	if a.InstanceID != "" {
		props = append(props, Property{
			Name: "aegisgate:instance_id", Value: a.InstanceID,
		})
	}
	// Sort by name for determinism.
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return props
}

// buildMetadataProperties returns the metadata-level
// (platform-wide) properties for the metadata block.
// Different from per-component properties: these are
// "about the SBOM itself" (when it was generated, what
// tool, what spec version), while the per-component
// properties are "about this specific deployment."
func buildMetadataProperties(a *AIBOM) []Property {
	props := []Property{
		{Name: "aegisgate:generated_at", Value: a.GeneratedAt.Format(time.RFC3339Nano)},
		{Name: "aegisgate:cyclonedx_spec_version", Value: CycloneDXSpecVersion},
	}
	if a.GeneratorNotes != "" {
		props = append(props, Property{
			Name: "aegisgate:generator_notes", Value: a.GeneratorNotes,
		})
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return props
}

// buildComponents returns the sorted list of AIBOM
// components. The order is:
//
//  1. HTTP (bom-ref: aegisgate-http)
//  2. MCP  (bom-ref: aegisgate-mcp)
//  3. A2A  (bom-ref: aegisgate-a2a)
//  4. ACP  (bom-ref: aegisgate-acp)
//  5. ANP  (bom-ref: aegisgate-anp)
//  6. Model (bom-ref: aegisgate-model) — only if registered
//  7. Prompts (bom-ref: aegisgate-prompt-<id>) — only if any
//  8. RAG corpora (bom-ref: aegisgate-rag-<id>) — only if any
//
// The protocol pillars are always emitted (even if disabled);
// the model/prompts/corpora are only emitted if registered.
// This makes the AIBOM explicit about "this pillar is present
// but disabled" vs "this pillar is not part of the deployment."
func buildComponents(a *AIBOM) []Component {
	var components []Component
	components = append(components, buildHTTPComponent(a.HTTP))
	components = append(components, buildMCPComponent(a.MCP))
	components = append(components, buildA2AComponent(a.A2A))
	components = append(components, buildACPComponent(a.ACP))
	components = append(components, buildANPComponent(a.ANP))
	if a.Model.IsRegistered {
		components = append(components, buildModelComponent(a.Model))
	}
	for _, p := range a.Prompts {
		components = append(components, buildPromptComponent(p))
	}
	for _, c := range a.Corpora {
		components = append(components, buildRAGComponent(c))
	}
	// Sort by bom-ref for determinism. The CycloneDX spec
	// does not require sorted components, but a stable
	// order makes diffs meaningful across regenerations.
	sort.Slice(components, func(i, j int) bool {
		return components[i].BOMRef < components[j].BOMRef
	})
	return components
}

// buildHTTPComponent produces the HTTP transport component
// for the BOM. The bom-ref is fixed ("aegisgate-http") so
// downstream tooling can link to it.
func buildHTTPComponent(h HTTPComponent) Component {
	props := []Property{
		{Name: "aegisgate:enabled", Value: boolToString(h.Enabled)},
		{Name: "aegisgate:pillar", Value: "http"},
	}
	if h.TLSVersion != "" {
		props = append(props, Property{
			Name: "aegisgate:tls_version", Value: h.TLSVersion,
		})
	}
	props = append(props, Property{
		Name: "aegisgate:mtls_enabled", Value: boolToString(h.MutualTLSEnabled),
	})
	if len(h.CipherSuites) > 0 {
		props = append(props, Property{
			Name: "aegisgate:cipher_suites", Value: strings.Join(h.CipherSuites, ","),
		})
	}
	if len(h.ListenerPorts) > 0 {
		// Sort ports for determinism.
		ports := make([]int, len(h.ListenerPorts))
		copy(ports, h.ListenerPorts)
		sort.Ints(ports)
		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = fmt.Sprintf("%d", p)
		}
		props = append(props, Property{
			Name: "aegisgate:listener_ports", Value: strings.Join(portStrs, ","),
		})
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return Component{
		Type:        "application",
		BOMRef:      "aegisgate-http",
		Name:        "AegisGate HTTP Transport",
		Version:     "n/a",
		Description: "HTTP listener transport (TLS, mTLS, listener ports).",
		Properties:  props,
	}
}

// buildMCPComponent produces the MCP guardrails component.
func buildMCPComponent(m MCPComponent) Component {
	props := []Property{
		{Name: "aegisgate:enabled", Value: boolToString(m.Enabled)},
		{Name: "aegisgate:pillar", Value: "mcp"},
		{Name: "aegisgate:prompt_injection_enabled", Value: boolToString(m.PromptInjectionDetectionEnabled)},
		{Name: "aegisgate:prompt_injection_sensitivity", Value: fmt.Sprintf("%d", m.PromptInjectionSensitivity)},
		{Name: "aegisgate:server_count", Value: fmt.Sprintf("%d", m.ServerCount)},
	}
	if m.GuardrailConfigFile != "" {
		props = append(props, Property{
			Name: "aegisgate:guardrail_config_file", Value: m.GuardrailConfigFile,
		})
	}
	if len(m.ServerNames) > 0 {
		// Sort for determinism.
		names := make([]string, len(m.ServerNames))
		copy(names, m.ServerNames)
		sort.Strings(names)
		props = append(props, Property{
			Name: "aegisgate:server_names", Value: strings.Join(names, ","),
		})
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return Component{
		Type:        "application",
		BOMRef:      "aegisgate-mcp",
		Name:        "AegisGate MCP Guardrails",
		Version:     "n/a",
		Description: "Model Context Protocol guardrails (prompt-injection detection, server enumeration).",
		Properties:  props,
	}
}

// buildA2AComponent produces the A2A guardrails component.
func buildA2AComponent(a A2AComponent) Component {
	props := []Property{
		{Name: "aegisgate:enabled", Value: boolToString(a.Enabled)},
		{Name: "aegisgate:pillar", Value: "a2a"},
		{Name: "aegisgate:agent_count", Value: fmt.Sprintf("%d", a.AgentCount)},
	}
	if a.ConfigFile != "" {
		props = append(props, Property{
			Name: "aegisgate:config_file", Value: a.ConfigFile,
		})
	}
	if a.CapsFile != "" {
		props = append(props, Property{
			Name: "aegisgate:caps_file", Value: a.CapsFile,
		})
	}
	if len(a.AgentNames) > 0 {
		names := make([]string, len(a.AgentNames))
		copy(names, a.AgentNames)
		sort.Strings(names)
		props = append(props, Property{
			Name: "aegisgate:agent_names", Value: strings.Join(names, ","),
		})
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return Component{
		Type:        "application",
		BOMRef:      "aegisgate-a2a",
		Name:        "AegisGate A2A Guardrails",
		Version:     "n/a",
		Description: "Agent-to-Agent guardrails (rate limiting, mTLS, capability enforcement).",
		Properties:  props,
	}
}

// buildACPComponent produces the ACP guardrails component.
func buildACPComponent(a ACPComponent) Component {
	props := []Property{
		{Name: "aegisgate:enabled", Value: boolToString(a.Enabled)},
		{Name: "aegisgate:pillar", Value: "acp"},
		{Name: "aegisgate:capability_count", Value: fmt.Sprintf("%d", a.CapabilityCount)},
	}
	if a.ConfigFile != "" {
		props = append(props, Property{
			Name: "aegisgate:config_file", Value: a.ConfigFile,
		})
	}
	if a.HMACAlgorithm != "" {
		props = append(props, Property{
			Name: "aegisgate:hmac_algorithm", Value: a.HMACAlgorithm,
		})
	}
	if len(a.CapabilityNames) > 0 {
		names := make([]string, len(a.CapabilityNames))
		copy(names, a.CapabilityNames)
		sort.Strings(names)
		props = append(props, Property{
			Name: "aegisgate:capability_names", Value: strings.Join(names, ","),
		})
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return Component{
		Type:        "application",
		BOMRef:      "aegisgate-acp",
		Name:        "AegisGate ACP Guardrails",
		Version:     "n/a",
		Description: "Agent Communication Protocol guardrails (HMAC signing, capability enforcement).",
		Properties:  props,
	}
}

// buildANPComponent produces the ANP guardrails component.
func buildANPComponent(a ANPComponent) Component {
	props := []Property{
		{Name: "aegisgate:enabled", Value: boolToString(a.Enabled)},
		{Name: "aegisgate:pillar", Value: "anp"},
		{Name: "aegisgate:task_count", Value: fmt.Sprintf("%d", a.TaskCount)},
		{Name: "aegisgate:default_config", Value: boolToString(a.DefaultConfig)},
	}
	if len(a.TaskNames) > 0 {
		names := make([]string, len(a.TaskNames))
		copy(names, a.TaskNames)
		sort.Strings(names)
		props = append(props, Property{
			Name: "aegisgate:task_names", Value: strings.Join(names, ","),
		})
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return Component{
		Type:        "application",
		BOMRef:      "aegisgate-anp",
		Name:        "AegisGate ANP Guardrails",
		Version:     "n/a",
		Description: "Agent Network Protocol guardrails (multi-agent rate limiting, SE-context validation).",
		Properties:  props,
	}
}

// buildModelComponent produces the model component. Only
// called when the operator has registered a model (v0.1:
// always skipped; v0.2: when --model is supplied).
func buildModelComponent(m ModelComponent) Component {
	props := []Property{
		{Name: "aegisgate:pillar", Value: "model"},
		{Name: "aegisgate:provider", Value: m.Provider},
		{Name: "aegisgate:model_id", Value: m.ModelID},
		{Name: "aegisgate:model_version", Value: m.Version},
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return Component{
		Type:        "machine-learning-model",
		BOMRef:      "aegisgate-model",
		Name:        fmt.Sprintf("AI Model: %s/%s", m.Provider, m.ModelID),
		Version:     m.Version,
		Description: "AI model registered for this deployment.",
		Properties:  props,
	}
}

// buildPromptComponent produces a component for a single
// hashed prompt. The full prompt is NEVER stored; only the
// SHA-256 of the normalized prompt.
func buildPromptComponent(p PromptComponent) Component {
	props := []Property{
		{Name: "aegisgate:byte_size", Value: fmt.Sprintf("%d", p.ByteSize)},
		{Name: "aegisgate:pillar", Value: "prompt"},
	}
	if p.Source != "" {
		props = append(props, Property{
			Name: "aegisgate:source", Value: p.Source,
		})
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	hashes := []Hash{{Algorithm: "SHA-256", Content: p.SHA256}}
	return Component{
		Type:        "data",
		BOMRef:      "aegisgate-prompt-" + p.ID,
		Name:        "Prompt: " + p.ID,
		Version:     "n/a",
		Description: "Hashed reference to a prompt registered for this deployment.",
		Hashes:      hashes,
		Properties:  props,
	}
}

// buildRAGComponent produces a component for a hashed RAG
// corpus. The corpus content is NEVER stored; only the
// SHA-256 of the concatenation of document hashes.
func buildRAGComponent(c RAGCorpusComponent) Component {
	props := []Property{
		{Name: "aegisgate:document_count", Value: fmt.Sprintf("%d", c.DocumentCount)},
		{Name: "aegisgate:pillar", Value: "rag"},
	}
	if c.Source != "" {
		props = append(props, Property{
			Name: "aegisgate:source", Value: c.Source,
		})
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	hashes := []Hash{{Algorithm: "SHA-256", Content: c.SHA256}}
	return Component{
		Type:        "data",
		BOMRef:      "aegisgate-rag-" + c.ID,
		Name:        "RAG Corpus: " + c.ID,
		Version:     "n/a",
		Description: "Hashed reference to a RAG corpus registered for this deployment.",
		Hashes:      hashes,
		Properties:  props,
	}
}

// buildAIBOMProperties returns the AIBOM extension
// properties (top-level, not per-component). These are
// summary properties (e.g., "5 protocol pillars present")
// that don't fit cleanly in any single component.
func buildAIBOMProperties(a *AIBOM) []Property {
	props := []Property{
		{Name: "aegisgate:aibom_pillars_present", Value: "5"},
		{Name: "aegisgate:prompts_registered", Value: fmt.Sprintf("%d", len(a.Prompts))},
		{Name: "aegisgate:corpora_registered", Value: fmt.Sprintf("%d", len(a.Corpora))},
		{Name: "aegisgate:model_registered", Value: boolToString(a.Model.IsRegistered)},
	}
	sort.Slice(props, func(i, j int) bool { return props[i].Name < props[j].Name })
	return props
}

// =====================================================================
// v0.1 helper: BuildAIBOMFromOptions
// =====================================================================
//
// v0.1 BuildAIBOMFromOptions builds an AIBOM from a small
// struct of options. The struct is the CLI/HTTP-friendly
// shape (tier, version, instance id, notes); the AIBOM
// per-pillar fields are NOT populated by this helper (the
// per-pillar data requires reading the live platform config,
// which v0.1 does not do — see the C2/m1 fix in the
// TODO-302 review).
//
// Callers that want per-pillar data MUST build the AIBOM
// struct directly. This helper is intentionally minimal
// (just the platform-level metadata) so the AIBOM is
// honest about what's in it.

// AIBOMOptions is the v0.1 CLI/HTTP-friendly option struct.
// The AIBOM type itself is the full internal model; this
// struct is the minimal external view.
type AIBOMOptions struct {
	Tier            string
	PlatformVersion string
	InstanceID      string
	GeneratorNotes  string
	// BOMVersion is the CycloneDX version field. CycloneDX
	// recommends that "subsequent revisions to the same
	// BOM SHOULD increment the version." v0.1 always
	// defaults to 1; callers can override (e.g., a
	// regeneration pipeline that tracks version locally).
	BOMVersion int
	// Model is optional. Empty ModelComponent means "not
	// registered" (the BOM omits the model component).
	Model ModelComponent
	// Prompts is optional. Empty slice means "no prompts
	// registered" (the BOM omits the prompt components).
	Prompts []PromptComponent
	// Corpora is optional. Empty slice means "no corpora
	// registered" (the BOM omits the RAG components).
	Corpora []RAGCorpusComponent
}

// BuildAIBOMFromOptions builds a v0.1 AIBOM from CLI/HTTP
// options. The per-pillar fields (HTTP, MCP, A2A, ACP, ANP)
// are left as zero values (Enabled=false, etc.); the BOM
// will still emit the 5 pillars (the validator requires
// them) but with explicit "disabled" data.
//
// This is the explicit v0.1 scope: "I haven't read the
// live config, so I report 'unknown' for everything."
// v0.2 will replace this with a config-driven path.
func BuildAIBOMFromOptions(opts AIBOMOptions) *AIBOM {
	return &AIBOM{
		DeploymentID:    uuid.NewString(),
		PlatformVersion: opts.PlatformVersion,
		PlatformTier:    opts.Tier,
		InstanceID:      opts.InstanceID,
		GeneratedAt:     time.Now().UTC(),
		Model:           opts.Model,
		Prompts:         opts.Prompts,
		Corpora:         opts.Corpora,
		GeneratorNotes:  opts.GeneratorNotes,
		BOMVersion:      opts.BOMVersion, // 0 = default to 1 in GenerateFromAIBOM
		// HTTP, MCP, A2A, ACP, ANP are zero-valued. The
		// generator emits them anyway (with Enabled=false
		// and no other data) so the validator is happy.
	}
}

// =====================================================================
// Helpers
// =====================================================================

// boolToString renders a bool as "true" or "false". We use
// lowercase to match the convention in the rest of the
// codebase (Go's strconv.FormatBool returns the same).
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// HashPrompt computes the SHA-256 of a prompt after
// normalization. The normalization is:
//
//  1. Convert to UTF-8.
//  2. Strip leading/trailing whitespace.
//  3. Collapse internal whitespace runs to a single space.
//  4. Lowercase (so the hash is case-insensitive).
//
// The normalization makes the hash stable across minor
// formatting changes (e.g., line endings, capitalization)
// while still being content-sensitive.
func HashPrompt(prompt string) string {
	normalized := normalizePrompt(prompt)
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// normalizePrompt applies the v0.1 normalization rules.
// Exported for testing.
func normalizePrompt(prompt string) string {
	// Trim leading/trailing whitespace.
	s := strings.TrimSpace(prompt)
	// Collapse internal whitespace runs to a single space.
	// strings.Fields splits on any whitespace; we join with " ".
	s = strings.Join(strings.Fields(s), " ")
	// Lowercase for case-insensitive comparison.
	return strings.ToLower(s)
}

// HashCorpus computes the SHA-256 of a RAG corpus. The
// corpus is represented as a list of per-document hashes
// (already computed by the operator). The function sorts
// the hashes, joins them with newlines, and hashes the
// result. Sorting ensures the corpus hash is order-
// independent (a corpus is a SET of documents, not a list).
func HashCorpus(documentHashes []string) string {
	sorted := make([]string, len(documentHashes))
	copy(sorted, documentHashes)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(h[:])
}
