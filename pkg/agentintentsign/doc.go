// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Intent Signing (TODO-303)
//
// doc.go is the package documentation for pkg/agentintentsign.
//
// # What is Agent Intent Signing?
//
// A2A (Agent-to-Agent) communication needs two things:
//
//  1. Identity: "I am agent X." (mTLS)
//  2. Intent: "I said I'd do Y for reason R." (intent binding)
//
// mTLS proves identity at the transport layer. Intent
// binding proves the agent's declaration of what it was
// going to do, signed with the agent's key. The intent
// tuple is:
//
//	(agent_id, intent, justification, valid_until, signature)
//
// The signature is over the canonical form of
// (agent_id, intent, justification, valid_until) using
// ECDSA P-256 (per the frozen envelope primitive).
//
// # Why this is separate from mTLS
//
// mTLS proves "this connection is from agent X." It does
// NOT prove "agent X said it would do Y." An intent
// binding is the cryptographic counterpart to the mTLS
// identity check, and it can be:
//
//   - Forwarded: the receiver can re-verify without
//     seeing the original mTLS session.
//   - Stored: an auditor can verify the intent months
//     later, with no mTLS context.
//   - Replayed: the receiver can reject the intent if
//     it has already been used (replay protection).
//
// # Use the envelope
//
// The intent is wrapped in the attestation envelope
// (shared with TODO-301/302). The envelope's subject is
// "aegisgate://intent/<intent-id>" and the type is
// attestation.TypeAgentIntent ("a2a.intent.v1").
//
// # v0.1 scope
//
//   - Sign + verify a single intent tuple.
//   - Reject expired intents.
//   - Reject tampered intents.
//   - Reject cross-agent replay (re-using agent_id + intent
//     from a different signing key).
//   - Functional-options API (per TODO-301 C1 / TODO-302 C2).
//
// # v0.2 scope (NOT YET IMPLEMENTED)
//
//   - Replay cache (in-process LRU; process-restart-safe
//     with the IOC store).
//   - Integration with pkg/a2a/ middleware (the intent
//     becomes an optional header on A2A requests).
//   - Policy enforcement (block the request if the intent
//     is missing, expired, or unauthorized).
package agentintentsign

// IntentVersion is the AegisGate A2A intent protocol version.
// Bumped when the wire format changes in a backward-
// incompatible way.
const IntentVersion = "0.1.0"

// DefaultSubjectKind is the URI scheme component for
// A2A intent subjects. The full subject is:
//
//	aegisgate://intent/<intent-id>
//
// "intent" is the registered subject kind (per
// pkg/attestation/types.go knownKinds).
const DefaultSubjectKind = "intent"

// MaxAgentIDLen caps the agent_id length. Prevents DoS
// via huge agent_id strings (which would also inflate the
// signed payload).
const MaxAgentIDLen = 256

// MaxIntentLen caps the intent string length. Same
// rationale as MaxAgentIDLen.
const MaxIntentLen = 4096

// MaxJustificationLen caps the justification string length.
const MaxJustificationLen = 1024

// DefaultIntentTTL is the default intent validity period.
// 1 hour is a reasonable default for A2A requests (most
// A2A flows complete in seconds, but the operator may
// have batched or queued workflows that take longer).
const DefaultIntentTTL = 1 * 60 * 60 * 1_000_000_000 // 1 hour in nanoseconds

// MaxIntentTTL is the maximum intent validity period.
// 24 hours prevents very-long-lived intents from being
// misused (e.g., signed once, replayed for weeks).
const MaxIntentTTL = 24 * 60 * 60 * 1_000_000_000 // 24 hours in nanoseconds
