// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Prompt Cache Poisoning Detection (TODO-304)
//
// doc.go is the package documentation for pkg/promptcache.
//
// # What is Prompt Cache Poisoning?
//
// LLM providers (Anthropic, OpenAI assistants API, etc.)
// cache prompt prefixes to reduce latency and cost. The
// cached prefix is reused across many requests. If an
// attacker can write a poisoned prefix into the cache, they
// can affect every subsequent request whose prefix matches.
//
// The attack surface is real:
//   - Shared prompt cache: many users share prefix space
//     (any tenant can poison a shared prefix).
//   - Tenant isolation: weak tenant boundaries allow
//     cross-tenant cache writes.
//   - Compromise-and-poison: a compromised upstream can
//     inject malicious prefixes that survive cache rotation.
//
// # The AegisGate detection primitive (v0.1)
//
// AegisGate's prompt-cache attestation works as follows:
//
//  1. The application calls Attest(prompt) BEFORE writing
//     a prompt prefix to the LLM provider's cache. The
//     attestation is a signed envelope wrapping the prompt
//     hash, the model id, the attestor id, and the timestamp.
//  2. The attestation (small, ~500 bytes) is stored
//     alongside the cache entry (or in a parallel ledger).
//  3. On cache read, the application calls Verify(env) to
//     check that:
//     a. The envelope signature is valid.
//     b. The envelope's subject matches the prompt hash.
//     c. The envelope has not expired.
//     d. The issuer's attestor_id matches what the
//     application expects (defense against a compromised
//     key writing fake attestations).
//
// A poisoned or tampered prompt fails verification and the
// application can refuse to use the cache entry (forcing a
// re-fetch from the upstream, which costs money but is
// safe).
//
// # Use the envelope
//
// The attestation is wrapped in the attestation envelope
// (shared with TODO-301/302/303). The envelope's subject is
// "aegisgate://prompt/<sha256-hex>" and the type is
// attestation.TypePromptCacheAttestation
// ("promptcache.attestation.v1").
//
// # Hash normalization policy
//
// Prompts are normalized BEFORE hashing. The normalization
// is:
//
//   - Convert to lowercase (case-insensitive matching).
//   - Collapse whitespace runs to a single space.
//   - Trim leading and trailing whitespace.
//
// This means two prompts that differ only in capitalization
// or whitespace produce the same attestation. This is
// consistent with AIBOM's HashPrompt (TODO-302 C1 fix) and
// is a deliberate design choice: prompt-cache attacks
// frequently use case/whitespace variations to bypass naive
// detectors.
//
// # v0.1 scope
//
//   - Sign + verify a single prompt attestation.
//   - Reject tampered payloads.
//   - Reject expired attestations.
//   - Reject unknown attestor_id (issuer format check).
//   - Functional-options API (per TODO-301 C1 / TODO-303).
//   - Clock injection (per TODO-303 m1 fix).
//   - Sentinel errors for errors.Is (per TODO-303).
//   - HTTP expected_key_id query param (per TODO-303 M3).
//
// # v0.2 scope (NOT YET IMPLEMENTED)
//
//   - Replay cache (in-process LRU; process-restart-safe
//     with the IOC store).
//   - Integration with pkg/ioc/: cache-poisoning events
//     become IOCs (the IOC store learns which prompt
//     hashes are flagged by which attestors).
//   - Cross-key replay detection (same prompt hash, two
//     different signing keys).
//   - Integration with pkg/mcp/ middleware (the
//     attestation becomes an optional header on MCP
//     requests).
package promptcache

// AttestationVersion is the AegisGate prompt-cache
// attestation protocol version. Bumped when the wire format
// changes in a backward-incompatible way.
const AttestationVersion = "0.1.0"

// DefaultSubjectKind is the URI scheme component for
// prompt-cache attestation subjects. The full subject is:
//
//	aegisgate://prompt/<sha256-hex>
//
// "prompt" is the registered subject kind (per
// pkg/attestation/types.go knownKinds).
const DefaultSubjectKind = "prompt"

// MaxSourceLen caps the source string length (e.g.,
// "user-supplied", "mcp-tool:acme", "system"). Prevents
// DoS via huge source strings (which would also inflate
// the signed payload).
const MaxSourceLen = 256

// MaxModelIDLen caps the model_id string length. Examples:
// "claude-3-5-sonnet-20241022", "openai/gpt-4-turbo".
const MaxModelIDLen = 256

// MaxAttestorIDLen caps the attestor_id string length.
// Examples: "acme-corp:prod-gateway", "anthropic:managed".
const MaxAttestorIDLen = 256

// MaxMetadataLen caps the free-form metadata blob length.
// Default zero (no metadata). Prevents DoS via huge
// metadata strings.
const MaxMetadataLen = 4096

// DefaultPromptCacheTTL is the default attestation validity
// period. 1 hour is the security-posture default: prompt
// caches are ephemeral (Anthropic and OpenAI evict
// aggressively), and a 1-hour attestation forces re-
// attestation on every meaningful reuse, which is the
// entire point of the detection mechanism.
const DefaultPromptCacheTTL = 1 * 60 * 60 * 1_000_000_000 // 1 hour in nanoseconds

// MaxPromptCacheTTL is the maximum attestation validity
// period. 24 hours is the security ceiling: anything longer
// means an attacker could replay a 6-month-old poisoned
// prompt by simply presenting an old envelope. The envelope's
// ValidUntil becomes a meaningful replay-detection signal.
const MaxPromptCacheTTL = 24 * 60 * 60 * 1_000_000_000 // 24 hours in nanoseconds
