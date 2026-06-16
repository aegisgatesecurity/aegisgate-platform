// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 3)
// =========================================================================
//
// types.go defines the public types for the Federated IOC (Indicator of
// Compromise) library. The IOC library is the network-effect moat of the
// AegisGate platform: every AegisGate instance produces hash-fingerprinted
// IOCs from local detections, signs attestations over them, and (opt-in)
// exchanges signed bundles with peer instances over a pull-based HTTP
// gossip protocol.
//
// Design principles (locked, see SESSION-ANCHOR 2026-06-14):
//
//   1. Hash-based, not ML. A SHA-256 fingerprint over a canonicalized
//      detection event is the IOC identifier. No transformer / embedding
//      model is introduced in the binary. The fingerprint is stable,
//      privacy-preserving (no raw payload in the input), and identical
//      for two instances that saw the same logical event.
//
//   2. ECDSA P-256 signing (not Ed25519). The migration to crypto/ecdh
//      is planned for v3.4.0 but is not yet done; we use the existing
//      SEC 1 / JCS manifest signing primitive that was proven in the
//      Track 6 cross_instance_lab_test.go. The wire format for
//      attestations and bundles mirrors the compliance manifest format
//      verbatim: { algorithm, keyId, value } envelope + embedded
//      public key. This means the same verifyManifestSignature path
//      works for IOCs and compliance manifests alike.
//
//   3. Privacy by construction. IOCs carry fingerprint + minimal
//      metadata (type, severity, first-seen, last-seen, count).
//      They NEVER carry raw detection payloads, source IPs, user
//      identifiers, or any other data that could be used to attribute
//      a detection to a specific customer or environment.
//
//   4. Opt-in, serverless. Sync is pull-based HTTP. Every instance is
//      a server (serves its own signed bundle) AND a client (pulls
//      peer bundles). No central server, no coordinator, no shared
//      state. Tiers gate the receive side; the send side is opt-in
//      per process flag.
//
//   5. Reuses the platform recording primitive. The IOC Producer
//      subscribes to logging.Record() / logging.QuickEvent() events
//      and turns a small allow-list of high-signal events into IOCs.
//      It does NOT introduce a new recorder / event sink.
//
// Naming note: the type is named IOCAttestation (not Attestation) to
// avoid visual confusion with pkg/trust/attestation.Attestation. They
// are unrelated types: trust attestations are compliance statements
// about an agent; IOC attestations are signed statements about an
// indicator of compromise.
//
// v3.5.0+ Track 6 Task 3.
// =========================================================================

package ioc

import (
	"time"
)

// FingerprintSize is the byte length of an IOC fingerprint. SHA-256
// produces 32 bytes; this is the size of the IOC Fingerprint type
// and is also the size of the canonical fingerprint field on the
// wire (hex-encoded to 64 characters).
const FingerprintSize = 32

// =========================================================================
// IOC - the Indicator of Compromise itself
// =========================================================================

// IOCType classifies what kind of threat the IOC represents. The
// type is part of the canonical fingerprint input, so two IOCs with
// the same fingerprint bytes but different IOCType values are
// considered distinct indicators.
type IOCType string

const (
	// IOCTypeProxyResponse indicates a notable proxy response
	// (e.g., a request that was blocked, a response that triggered
	// a prompt-injection or PII detection downstream). This is the
	// most common IOC type and is what most AegisGate instances
	// will produce.
	IOCTypeProxyResponse IOCType = "proxy_response"

	// IOCTypeAnomalyScore indicates a high-severity anomaly score
	// from the ML anomaly detector. Anomaly scores are typically
	// rarer than proxy responses but carry more signal per event.
	IOCTypeAnomalyScore IOCType = "anomaly_score"

	// IOCTypePromptInjection indicates a confirmed prompt-injection
	// detection. This is a high-confidence IOC: prompt-injection
	// detections are not flaky and the same payload against two
	// instances will produce the same fingerprint.
	IOCTypePromptInjection IOCType = "prompt_injection"

	// IOCTypeSecretLeak indicates a confirmed secret leak (one of
	// the 44 secret-scanning regexes matched). High-confidence IOC.
	IOCTypeSecretLeak IOCType = "secret_leak"

	// IOCTypePIIDetected indicates a PII detection (GDPR-relevant).
	// Note: PII IOCs carry NO PII themselves; only the fingerprint
	// of the detection event (which hashes the pattern, not the
	// value) is shared.
	IOCTypePIIDetected IOCType = "pii_detected"
)

// Severity is the severity of an IOC. We re-use the same string
// vocabulary as logging.Severity (critical, high, medium, low, info)
// so that the producer can convert directly without a mapping table.
// The IOC library does NOT import pkg/logging to keep the dependency
// surface minimal; the string is the contract.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// severityRank returns a numeric rank for severity comparison.
// Higher is more severe. Unknown severities rank as info.
func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// WorseSeverity returns the more severe of the two severities.
// Used by the producer when the same fingerprint is observed at
// multiple severities: we keep the worst.
func WorseSeverity(a, b Severity) Severity {
	if severityRank(a) >= severityRank(b) {
		return a
	}
	return b
}

// IOC is the Indicator of Compromise record. It is the unit that
// flows through the producer, the store, the bundle, and the sync
// protocol. IOCs are immutable once created; the Count field is
// updated in place as the producer observes additional matching
// events, and FirstSeen / LastSeen are updated accordingly.
//
// Wire format: JSON-encoded with the json tags below. The JSON
// form is what gets signed by IOCAttestation and what gets bundled
// into a Bundle. Field order in the struct is irrelevant for
// canonicalization (JCS sorts keys).
type IOC struct {
	// Fingerprint is the SHA-256 of the canonicalized detection
	// event (see fingerprint.go). Hex-encoded lowercase, 64 chars.
	// This is the IOC's primary key: two IOCs with the same
	// Fingerprint are the same IOC.
	Fingerprint string `json:"fingerprint"`

	// Type classifies the IOC. See IOCType constants.
	Type IOCType `json:"type"`

	// Severity is the highest severity observed for this IOC.
	// When a fingerprint is observed at multiple severities, we
	// keep the worst (most severe) one. Severity ordering is
	// critical > high > medium > low > info.
	Severity Severity `json:"severity"`

	// FirstSeen is the UTC time the IOC was first observed by
	// this instance. Stamped by the producer; never zero.
	FirstSeen time.Time `json:"firstSeen"`

	// LastSeen is the UTC time the IOC was most recently observed.
	// Updated on every matching event.
	LastSeen time.Time `json:"lastSeen"`

	// Count is the number of times this IOC has been observed by
	// this instance. A high count on a peer instance is a strong
	// signal that the IOC is widespread.
	Count int `json:"count"`

	// Source is a short, non-identifying label for where the IOC
	// came from. Examples: "proxy", "anomaly", "scanner". This
	// is INCLUDED in the fingerprint input (so two proxy
	// detections of the same payload fingerprint the same) but
	// is also kept on the IOC for display purposes. Never a
	// hostname, IP, or customer identifier.
	Source string `json:"source"`
}

// Valid reports whether the IOC has the minimum required fields
// to be stored / shared. An IOC with an empty fingerprint or an
// unknown IOCType is invalid.
func (i *IOC) Valid() bool {
	if i == nil {
		return false
	}
	if len(i.Fingerprint) != 64 {
		return false
	}
	switch i.Type {
	case IOCTypeProxyResponse, IOCTypeAnomalyScore, IOCTypePromptInjection,
		IOCTypeSecretLeak, IOCTypePIIDetected:
	default:
		return false
	}
	if i.Count <= 0 {
		return false
	}
	if i.FirstSeen.IsZero() || i.LastSeen.IsZero() {
		return false
	}
	return true
}
