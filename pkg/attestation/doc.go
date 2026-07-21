// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Envelope Attestation Primitive
// =========================================================================
//
// The envelope primitive is the cryptographic signed-attestation
// backbone of AegisGate. Every signed artifact produced by the
// platform (compliance evidence manifests, AIBOMs, AR-EaaS results,
// agent intent statements, prompt cache attestations, CVE-for-AI
// entries, IOC attestations) wraps its payload in this envelope.
//
// Lifecycle (4 operations):
//   - Sign:            create a new signed envelope from a payload
//   - Verify:          verify using the embedded public key
//   - VerifyWithKey:   verify using a caller-supplied public key
//   - VerifyOnline:    fetch the public key from /.well-known/ then verify
//
// Cryptography:
//   - ECDSA P-256 (FIPS 186-4, NIST P-256)
//   - SHA-256 for payload digest
//   - JSON Canonicalization Scheme (RFC 8785) for deterministic payload
//     hashing — required so signatures are stable across re-serialization
//
// Frozen 2026-06-15 (Council of Mine 8/8 unanimous Devil's Advocate
// on the design). See plans/THREAT-MODEL.md Section 2.6 for the
// 10 STRIDE threats addressed.
//
// =========================================================================

package attestation
