// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 3)
// =========================================================================
//
// fingerprint.go computes a stable, privacy-preserving SHA-256 fingerprint
// over a detection event. The fingerprint is the IOC's primary key: two
// AegisGate instances that see the same logical event produce the same
// fingerprint, and the fingerprint cannot be reversed to recover the
// underlying payload.
//
// Canonicalization rules:
//
//   - JSON object with keys sorted lexicographically (UTF-8 byte order)
//   - No insignificant whitespace (matches RFC 8785 JCS subset we need:
//     sorted keys + no whitespace; we do NOT implement full JCS
//     number normalization or unicode normalization here, just the
//     sorting + whitespace removal that is needed for stability across
//     Go versions and across map iteration order)
//   - UTF-8 encoding throughout
//   - Array order is preserved (the order of detection events matters;
//     we do NOT sort arrays)
//   - Numbers are encoded in their natural JSON form
//
// Privacy rules (CRITICAL):
//
//   - The fingerprint input is the *Detection* struct, NOT the raw event.
//     The Detection struct only carries the non-identifying fields
//     (type, severity, pattern, threat type, threat level, compliance
//     framework, compliance control). It does NOT carry source IP,
//     user, client ID, request body, response body, or any other
//     payload data.
//   - If a caller passes a raw logging.Event with SourceIP/User/ClientID
//     populated, the fingerprint will STILL be computed only over the
//     non-identifying Detection fields. This is enforced by Fingerprint():
//     it never reads those fields from the event.
//
// This means: two instances that see the same prompt-injection payload
// from different customers produce the same fingerprint, and neither
// instance's customer data ever leaves the instance in a form that
// could be used to attribute the detection.
//
// v3.5.0+ Track 6 Task 3.
// =========================================================================

package ioc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Detection is the privacy-safe view of a detection event used as the
// fingerprint input. The fields are deliberately a subset of
// logging.Event: only non-identifying, stable fields that two
// AegisGate instances would produce identically for the same
// logical event.
//
// IMPORTANT: When adding fields here, think hard about whether they
// could be used to attribute the detection to a specific customer,
// environment, or user. If yes, do not add them. The whole point
// of the IOC library is that the fingerprint is the only thing
// that crosses the trust boundary.
type Detection struct {
	// Type is the logging.Event.Type (e.g., "proxy_response",
	// "anomaly_score", "prompt_injection"). Mapped to IOCType by
	// the producer.
	Type string `json:"type"`

	// Severity is the logging.Event.Severity ("critical", "high",
	// "medium", "low", "info"). The string is part of the
	// fingerprint input: a high-severity detection and a
	// low-severity detection of the same payload fingerprint
	// differently. This is intentional: severity is signal.
	Severity Severity `json:"severity"`

	// Pattern is the matched rule / regex name (e.g.,
	// "secret_aws_access_key", "pii_ssn_us", "prompt_injection_jailbreak_v3").
	// This is the most discriminating field: a high-fidelity IOC
	// has a specific pattern name. A null/empty pattern produces
	// a fingerprint that is stable across "any proxy response at
	// this severity", which is also useful (low-signal but real).
	Pattern string `json:"pattern,omitempty"`

	// ThreatType is the logging.Event.ThreatType (e.g.,
	// "credential_exposure", "data_exfiltration", "prompt_injection").
	ThreatType string `json:"threatType,omitempty"`

	// ThreatLevel is the logging.Event.ThreatLevel. This is a
	// string that some scanners emit ("imminent", "active", "potential").
	ThreatLevel string `json:"threatLevel,omitempty"`

	// ComplianceFramework is the logging.Event.ComplianceFramework
	// (e.g., "GDPR", "HIPAA", "SOC2"). This is the bridge to the
	// compliance evidence package: an IOC tagged as "GDPR" comes
	// from a detection that the platform also reports in the GDPR
	// evidence package.
	ComplianceFramework string `json:"complianceFramework,omitempty"`

	// ComplianceControl is the logging.Event.ComplianceControl
	// (e.g., "Art.32", "164.312(a)(1)"). Even more specific than
	// ComplianceFramework.
	ComplianceControl string `json:"complianceControl,omitempty"`
}

// Fingerprint computes the SHA-256 fingerprint of the Detection.
// Returns the hex-encoded lowercase 64-character string suitable
// for use as an IOC.Fingerprint value.
//
// Two Detections with identical field values produce identical
// fingerprints. Map iteration order does not affect the result
// because Detection is a fixed struct (no maps).
//
// The function is safe for concurrent use and contains no
// goroutines, channels, or shared state.
func Fingerprint(d Detection) string {
	canonical, err := canonicalJSON(d)
	if err != nil {
		// Should never happen: a struct with primitive fields
		// cannot fail to marshal. If it does, return a
		// well-defined zero fingerprint so the caller does not
		// panic. The IOC.Valid() check will reject the IOC.
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// FingerprintBytes returns the raw 32-byte fingerprint. Most
// callers want Fingerprint() (the hex string). This is provided
// for cases where binary comparison is needed (e.g., a Bloom
// filter of recently-seen fingerprints).
func FingerprintBytes(d Detection) []byte {
	canonical, err := canonicalJSON(d)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(canonical)
	return sum[:]
}

// canonicalJSON returns a canonical JSON encoding of v with sorted
// object keys. It works for any value that encoding/json can
// marshal, not just Detection.
//
// We implement this directly (not via the jcs package) because:
//  1. The IOC library has a small surface and we want zero new
//     dependencies.
//  2. Our canonicalization needs are narrower than full JCS: we
//     only need stability for struct values with primitive
//     fields, not for arbitrary user JSON.
//
// For struct values, encoding/json's default marshaling produces
// output with keys in struct-declaration order, which is already
// stable across runs. We still sort keys for nested maps to be
// safe.
//
// Array order is preserved.
func canonicalJSON(v interface{}) ([]byte, error) {
	// First marshal normally.
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Then unmarshal into a generic structure and re-marshal with
	// sorted keys. This is the simplest correct approach for
	// nested objects with arbitrary key sets.
	var generic interface{}
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, err
	}
	return marshalCanonical(generic)
}

// marshalCanonical marshals v with object keys sorted in
// lexicographic (UTF-8) order. Arrays preserve their original
// order. This is the JCS-like subset we need for fingerprint
// stability.
func marshalCanonical(v interface{}) ([]byte, error) {
	switch x := v.(type) {
	case map[string]interface{}:
		// Sort keys and marshal as an object.
		if len(x) == 0 {
			return []byte("{}"), nil
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			out = append(out, kb...)
			out = append(out, ':')
			child, err := marshalCanonical(x[k])
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
		}
		out = append(out, '}')
		return out, nil
	case []interface{}:
		out := []byte{'['}
		for i, e := range x {
			if i > 0 {
				out = append(out, ',')
			}
			child, err := marshalCanonical(e)
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
		}
		out = append(out, ']')
		return out, nil
	default:
		// Primitives: defer to encoding/json.
		return json.Marshal(x)
	}
}
