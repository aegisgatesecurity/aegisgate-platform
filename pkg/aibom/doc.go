// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM (AI Bill of Materials) — CycloneDX extension (TODO-302)
//
// doc.go is the package documentation for pkg/aibom.
//
// # What is AIBOM?
//
// An AI Bill of Materials is a CycloneDX SBOM extended with
// AI-specific component types: prompts, RAG corpora, models,
// MCP servers, A2A agents, ACP capabilities, and ANP tasks.
// The AIBOM spec (CycloneDX 1.6+, ext/ai) is the emerging
// standard for AI supply-chain transparency.
//
// # Why AegisGate
//
// AegisGate is positioned as a reference implementation
// for the AIBOM spec. The platform is the natural producer
// of an AIBOM because it sees the deployment's full AI
// exposure surface (5 protocol pillars + prompts + RAG +
// model) and can sign the result with the attestation
// envelope primitive (TODO-301 sibling feature).
//
// # v0.1 scope
//
// The AIBOM v0.1 enumerates AegisGate's own configuration:
//   - HTTP transport (TLS version, mTLS settings)
//   - MCP guardrails (enable_prompt_injection, sensitivity)
//   - A2A guardrails (enabled, config file, capabilities file)
//   - ACP guardrails (config file, HMAC settings)
//   - ANP guardrails (enabled, default config)
//   - Model: NOT REGISTERED in v0.1 (operator-supplied in v0.2)
//   - Prompts: empty list in v0.1 (operator-supplied in v0.2)
//   - RAG corpora: empty list in v0.1 (operator-supplied in v0.2)
//
// # Determinism
//
// The AIBOM is byte-stable for a given AegisGate configuration.
// All fields are sorted at every level (via the attestation
// envelope's JCS canonicalizer). The generated-at timestamp
// and run-id are the only non-deterministic fields.
//
// # Verification
//
// The AIBOM is wrapped in an attestation envelope. The
// auditor verifies with the same primitive as the c3
// evidence manifest and the AR-EaaS result:
//
//	$ aegisgate aibom verify aibom.json
//	VALID
//	  Type:       aibom.cyclonedx.v1
//	  Subject:    aegisgate://deployment/<id>
//	  Issuer:     ...
//	  KeyID:      ...
//
// # Wire target
//
//   - pkg/aibom/   (this package)
//   - cmd/aegisgate-platform/aibom_subcommand.go
//   - cmd/aegisgate-platform/aibom_http.go
//   - POST /api/v1/aibom/generate
//   - aegisgate aibom generate / aegisgate aibom verify
package aibom

// AIBOMVersion is the version of the AegisGate AIBOM spec.
// Bump when the schema changes in a wire-incompatible way.
const AIBOMVersion = "0.1.0"

// DefaultToolName is the tool name reported in the CycloneDX
// metadata.tools section.
const DefaultToolName = "aegisgate-aibom-generator"

// CycloneDXSpecVersion is the CycloneDX spec version this
// package emits. CycloneDX 1.6 is the first version with
// the aibom extension (https://cyclonedx.org/ext/ai/).
const CycloneDXSpecVersion = "1.6"

// CycloneDXBOMFormat is the constant CycloneDX uses for
// the bomFormat field.
const CycloneDXBOMFormat = "CycloneDX"

// DefaultComponentType is the CycloneDX "type" used for
// the metadata.component field. "application" is the right
// choice for a deployed platform (vs. "library" for a
// reusable library, "framework" for a framework, etc.).
const DefaultComponentType = "application"

// MaxPromptsPerAIBOM is the maximum number of prompts an
// operator can register. Prevents DoS via huge prompts[].
const MaxPromptsPerAIBOM = 10000

// MaxCorporaPerAIBOM is the maximum number of RAG corpora
// an operator can register. Prevents DoS via huge corpora[].
const MaxCorporaPerAIBOM = 1000
