// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM types (TODO-302)
//
// types.go defines the Go-side data model for the AIBOM.
// The model is a CycloneDX 1.6 SBOM with the aibom extension
// (https://cyclonedx.org/ext/ai/). We only model the fields
// we actually use — CycloneDX has many optional fields we
// leave out for simplicity.
//
// # Design rule
//
// Every field in the public types is either a string, an
// int, a bool, a slice of one of these, or a nested struct.
// The only time.Time is the metadata.timestamp. Maps are
// avoided (JCS canonicalization works on objects, not maps)
// and converted to sorted slices where needed.
//
// # Field order
//
// The Go struct field order does NOT affect JSON output
// order. The JCS canonicalizer sorts keys at every level,
// so the canonical output is deterministic regardless of
// struct definition order.

package aibom

import "time"

// =====================================================================
// CycloneDX 1.6 root types
// =====================================================================

// BOM is the root of a CycloneDX 1.6 SBOM with the aibom
// extension. The CycloneDX spec is permissive about extra
// fields, so the AIBOM-specific data is in the Properties
// field (standard CycloneDX extensibility mechanism) and
// the Components field (standard CycloneDX list).
type BOM struct {
	// BOMFormat is always "CycloneDX" (the spec requires it).
	BOMFormat string `json:"bomFormat"`
	// SpecVersion is the CycloneDX spec version (we emit "1.6").
	SpecVersion string `json:"specVersion"`
	// Version is the SBOM version (we emit 1; subsequent
	// regenerations of the same deployment bump this).
	Version int `json:"version"`
	// SerialNumber is a UUIDv4 unique to this SBOM instance.
	// CycloneDX requires it to be a valid urn:uuid: URI.
	SerialNumber string `json:"serialNumber,omitempty"`
	// Metadata is the SBOM metadata (tools, component, etc.).
	Metadata Metadata `json:"metadata"`
	// Components is the list of AIBOM components (the 5
	// protocol pillars, model, prompts, RAG corpora, etc.).
	Components []Component `json:"components"`
	// Properties is the list of AIBOM extension properties
	// (the 5 protocol pillars' enabled flags, severities,
	// fingerprints, etc.). CycloneDX's standard extensibility
	// mechanism; each property has a name and a value.
	Properties []Property `json:"properties,omitempty"`
}

// Metadata is the CycloneDX metadata block. Holds tools
// (what generated this SBOM), the component (what is being
// described), and timestamp/author.
type Metadata struct {
	// Timestamp is when the SBOM was generated (UTC, RFC 3339).
	Timestamp time.Time `json:"timestamp"`
	// Tools is the list of tools used to generate the SBOM.
	// Per CycloneDX, a tool is a {vendor, name, version} triple.
	Tools []Tool `json:"tools"`
	// Component is the "subject" of the SBOM (the thing being
	// described). For AegisGate, this is the platform itself.
	Component MetadataComponent `json:"component"`
	// Properties are platform-level properties (tier, instance
	// id, etc.). Different from per-component properties.
	Properties []Property `json:"properties,omitempty"`
}

// Tool is a {vendor, name, version} tool record per
// CycloneDX 1.6 spec. We always emit exactly one tool
// (the AIBOM generator itself).
type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MetadataComponent is the subject of the SBOM. For
// AegisGate, this is the platform itself (an "application"
// component with name "AegisGate Security Platform" and
// version = the platform version).
type MetadataComponent struct {
	// Type is the CycloneDX component type. We emit
	// "application" for the platform itself.
	Type string `json:"type"`
	// BOMRef is a unique reference id for this component
	// within the SBOM. CycloneDX uses it to link components
	// together (e.g., a prompt depends on a model). We emit
	// "aegisgate-deployment-<uuid>" for the platform.
	BOMRef string `json:"bom-ref"`
	// Name is the human-readable name.
	Name string `json:"name"`
	// Version is the version of the component (the
	// AegisGate version for the platform itself).
	Version string `json:"version"`
	// Description is a short human-readable description.
	Description string `json:"description,omitempty"`
	// Properties are component-level properties (the
	// deployment-specific data: tier, instance id, etc.).
	Properties []Property `json:"properties,omitempty"`
}

// Component is a CycloneDX 1.6 component. We use it to
// model the 5 protocol pillars (HTTP/MCP/A2A/ACP/ANP),
// the model, prompts, and RAG corpora.
type Component struct {
	// Type is the CycloneDX component type. We use
	// "application" for protocol pillars and the model,
	// "data" for RAG corpora, and "machine-learning-model"
	// for models. Prompt hashes go in Properties, not as
	// components, because CycloneDX does not have a
	// "prompt" component type.
	Type string `json:"type"`
	// BOMRef is a unique reference id for this component
	// (used by CycloneDX to link components together).
	BOMRef string `json:"bom-ref"`
	// Name is the human-readable name (e.g.,
	// "mcp-guardrails", "a2a-agents", "model").
	Name string `json:"name"`
	// Version is the component version (or "n/a" if not
	// applicable, e.g., for protocol pillars).
	Version string `json:"version,omitempty"`
	// Description is a short human-readable description.
	Description string `json:"description,omitempty"`
	// Hashes are content hashes for the component. We use
	// SHA-256 for prompts and RAG corpora. Empty for
	// protocol pillars.
	Hashes []Hash `json:"hashes,omitempty"`
	// Properties are component-level properties (per-pillar
	// configuration: enabled, fingerprint, etc.).
	Properties []Property `json:"properties,omitempty"`
}

// Hash is a CycloneDX content hash. The Algorithm is
// "SHA-256" (CycloneDX 1.6 supports SHA-1, SHA-256, SHA-512,
// MD5, SHA3-256, SHA3-512, BLAKE2b-256, BLAKE2b-512, BLAKE3).
type Hash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// Property is a CycloneDX {name, value} property. Used
// for AIBOM extension data that doesn't fit the standard
// Component model (e.g., per-pillar enabled flags, instance
// id, run id, etc.).
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// =====================================================================
// AIBOM extension types (the 5 pillars, model, prompts, RAG)
// =====================================================================

// AIBOM is the high-level container for the AIBOM-specific
// data. The AIBOM is then converted to a CycloneDX BOM
// (in the generator) and signed with the envelope. This
// struct is what callers build directly; the generator
// flattens it into the BOM.
//
// Why a separate struct? Two reasons:
//  1. It separates the "what to put in the AIBOM" concern
//     (AIBOM, caller-facing) from the "CycloneDX wire format"
//     concern (BOM, internal).
//  2. It makes the generator testable in isolation: pass an
//     AIBOM, get a BOM. No platformconfig needed.
type AIBOM struct {
	// DeploymentID is the unique id for this deployment's
	// AIBOM. Embedded in the envelope subject.
	DeploymentID string
	// PlatformVersion is the AegisGate version (e.g.,
	// "3.4.0-beta.1"). Embedded in metadata.component.version.
	PlatformVersion string
	// PlatformTier is the platform tier (e.g., "community",
	// "professional", "enterprise"). Embedded in
	// metadata.properties as "aegisgate:platform_tier".
	PlatformTier string
	// InstanceID is the operator's instance identifier.
	// Empty if the platform is using a default ID. Embedded
	// in metadata.properties as "aegisgate:instance_id".
	InstanceID string
	// GeneratedAt is when this AIBOM was generated.
	// Embedded in metadata.timestamp.
	GeneratedAt time.Time
	// HTTP describes the HTTP transport (TLS, mTLS).
	HTTP HTTPComponent
	// MCP describes the MCP guardrails.
	MCP MCPComponent
	// A2A describes the A2A guardrails.
	A2A A2AComponent
	// ACP describes the ACP guardrails.
	ACP ACPComponent
	// ANP describes the ANP guardrails.
	ANP ANPComponent
	// Model is the AI model registered for this deployment.
	// Empty for v0.1 (AegisGate does not host a model itself;
	// v0.2 will add operator-supplied model lists).
	Model ModelComponent
	// Prompts is the list of operator-supplied prompt hashes.
	// Empty for v0.1. v0.2 will add a CLI flag to register
	// prompts by file or directory.
	Prompts []PromptComponent
	// Corpora is the list of operator-supplied RAG corpus hashes.
	// Empty for v0.1. v0.2 will add a CLI flag to register
	// corpora by file or directory.
	Corpora []RAGCorpusComponent
	// GeneratorNotes is a free-form note from the operator
	// (e.g., "weekly prod snapshot"). Not signed separately;
	// included in the AIBOM as a property.
	GeneratorNotes string
	// BOMVersion is the CycloneDX version field. Zero
	// (the default) means "use version 1". Non-zero values
	// override (callers like regeneration pipelines can
	// track their own version counter).
	BOMVersion int
}

// HTTPComponent describes the HTTP transport for the AIBOM.
// Empty fields are emitted as "unknown" so the auditor
// sees that the value is not configured, not absent.
type HTTPComponent struct {
	// Enabled is true if the platform's HTTP listener is active.
	// In v0.1, this is always true (the platform always runs
	// an HTTP listener on the dashboard port).
	Enabled bool
	// TLSVersion is the TLS version (e.g., "1.3"). Empty if
	// TLS is disabled or not configured.
	TLSVersion string
	// MutualTLSEnabled is true if mTLS is required for the
	// dashboard / proxy listeners.
	MutualTLSEnabled bool
	// CipherSuites is the list of allowed cipher suites
	// (for human-readable auditing; the actual TLS config
	// is the source of truth, not the AIBOM).
	CipherSuites []string
	// ListenerPorts is the list of active listener ports
	// (proxy, dashboard, etc.).
	ListenerPorts []int
}

// MCPComponent describes the MCP (Model Context Protocol)
// guardrails for the AIBOM.
type MCPComponent struct {
	// Enabled is true if the MCP guardrails are active.
	Enabled bool
	// GuardrailConfigFile is the path to the MCP guardrail
	// config file (YAML). Empty if not configured.
	GuardrailConfigFile string
	// PromptInjectionDetectionEnabled mirrors the upstream
	// config.EnablePromptInjectionDetection.
	PromptInjectionDetectionEnabled bool
	// PromptInjectionSensitivity mirrors the upstream
	// config.PromptInjectionSensitivity (0-100).
	PromptInjectionSensitivity int
	// ServerCount is the number of MCP servers registered.
	// v0.1: not enumerated (no live registry in platformconfig).
	// v0.2: will be wired to pkg/mcpserver/registry.
	ServerCount int
	// ServerNames is the list of MCP server names. v0.1: empty.
	ServerNames []string
}

// A2AComponent describes the A2A (Agent-to-Agent) guardrails
// for the AIBOM.
type A2AComponent struct {
	// Enabled is true if the A2A guardrails are active.
	Enabled bool
	// ConfigFile is the path to the A2A config file.
	ConfigFile string
	// CapsFile is the path to the A2A capabilities file.
	CapsFile string
	// AgentCount is the number of A2A agents registered.
	// v0.1: not enumerated; v0.2 will wire to caps_loader.
	AgentCount int
	// AgentNames is the list of A2A agent names. v0.1: empty.
	AgentNames []string
}

// ACPComponent describes the ACP (Agent Communication Protocol)
// guardrails for the AIBOM.
type ACPComponent struct {
	// Enabled is true if the ACP guardrails are active.
	Enabled bool
	// ConfigFile is the path to the ACP config file.
	ConfigFile string
	// HMACAlgorithm is the HMAC algorithm (e.g., "SHA-256").
	// Empty if HMAC is disabled.
	HMACAlgorithm string
	// CapabilityCount is the number of capabilities registered.
	// v0.1: not enumerated; v0.2 will wire to acp_capabilities.
	CapabilityCount int
	// CapabilityNames is the list of capability names. v0.1: empty.
	CapabilityNames []string
}

// ANPComponent describes the ANP (Agent Network Protocol)
// guardrails for the AIBOM.
type ANPComponent struct {
	// Enabled is true if the ANP guardrails are active.
	Enabled bool
	// DefaultConfig is true if the ANP guard is using the
	// default config (no operator-supplied YAML).
	DefaultConfig bool
	// TaskCount is the number of ANP tasks registered.
	// v0.1: not enumerated; v0.2 will wire to anp.Registry.
	TaskCount int
	// TaskNames is the list of ANP task names. v0.1: empty.
	TaskNames []string
}

// ModelComponent describes the AI model registered for the
// deployment. v0.1: always empty (AegisGate does not host
// a model itself). v0.2: operator-supplied list of
// {provider, model_id, version} tuples.
type ModelComponent struct {
	// Provider is the model provider (e.g., "openai",
	// "anthropic", "self-hosted"). Empty if not registered.
	Provider string
	// ModelID is the model identifier (e.g., "gpt-4-turbo",
	// "claude-opus-4-20250514"). Empty if not registered.
	ModelID string
	// Version is the model version (provider-assigned).
	// Empty if not registered.
	Version string
	// IsRegistered is true if the operator has supplied
	// model information. v0.1: always false.
	IsRegistered bool
}

// PromptComponent is a hashed reference to a prompt. The
// full prompt is NOT stored in the AIBOM (it may contain
// sensitive data); only the SHA-256 of the normalized
// prompt is stored. The operator can re-derive the
// fingerprint from the prompt and compare.
type PromptComponent struct {
	// ID is a unique identifier for the prompt (operator-supplied
	// or auto-generated from the prompt file path).
	ID string
	// SHA256 is the SHA-256 hash of the normalized prompt
	// (lowercased, whitespace-collapsed, then SHA-256).
	SHA256 string
	// ByteSize is the size of the original prompt in bytes
	// (after normalization). For human-readable auditing.
	ByteSize int
	// Source is the operator-supplied source of the prompt
	// (e.g., "prompts/system.txt"). Free-form.
	Source string
}

// RAGCorpusComponent is a hashed reference to a RAG corpus.
// The full corpus is NOT stored; only the SHA-256 of the
// concatenation of document hashes is stored.
type RAGCorpusComponent struct {
	// ID is a unique identifier for the corpus.
	ID string
	// SHA256 is the SHA-256 of the concatenation of all
	// document SHA-256s in the corpus (sorted, newline-
	// separated, then hashed).
	SHA256 string
	// DocumentCount is the number of documents in the corpus.
	DocumentCount int
	// Source is the operator-supplied source path.
	Source string
}
