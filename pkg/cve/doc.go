// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CVE-for-AI Entry package (TODO-305)
//
// Package cve is the authoritative publisher for
// AegisGate-discovered AI/ML vulnerabilities. Each CVE
// entry is wrapped in the attestation envelope (the
// primitive shipped on 2026-06-16), so every entry is
// tamper-evident, third-party-verifiable, and key-id-
// pinable.
//
// The package does NOT host a CVE Numbering Authority
// (CNA). CVE IDs use the AegisGate prefix (AEGIS-YYYY-
// NNNN) to make the publisher unambiguous. Future work
// could apply for CNA status with MITRE; until then, the
// prefix is the source identifier.
//
// What v0.1 ships:
//   - CVEEntry struct (CVE 5.0-style schema, adapted for
//     AI/ML vulns: model, version-range, provider,
//     mitigations, references).
//   - Publish (sign) + Verify (verify) on the envelope.
//   - Withdrawal via a NEW envelope (immutability).
//   - Feed (list of envelopes) for the future static
//     portal at cve.aegisgatesecurity.io.
//
// What v0.1 does NOT ship:
//   - The static portal site (deferred).
//   - security.txt (RFC 9116) (deferred).
//   - Curation tooling (human process; out of scope).
//   - CNA application to MITRE (months of process).
//
// Design patterns (from the TODO-301/302/303/304 reviews):
//   - Functional options (SignerOption, no struct mutation).
//   - No caller mutation (t := *entry shallow copy).
//   - Shortfp issuer format (cve:shortfp:<16-hex>:<key-id>).
//   - Subject grammar aegisgate://cve/<CVE-ID>.
//   - Sentinel errors for errors.Is.
//   - Clock injection (Clock interface, VerifyWithClock).
//   - expected_key_id query param on HTTP verify (M3).
//   - Tail-match for tail-embedded fields (C2).
//   - isHexString for hex validation (C2).
//   - go test -count=0 for compile validation (gotcha 56).
//   - No time.Sleep in tests (gotcha 57).
//   - Don't fix failing tests by changing expectations
//     (gotcha 58).
//
// One deliberate deviation from the prior 4 Tier 5
// features: TTL = 0 means "no expiration" (CVE entries
// are immutable; withdrawal is a new envelope). This is
// documented in the code and in the self-review.

package cve
