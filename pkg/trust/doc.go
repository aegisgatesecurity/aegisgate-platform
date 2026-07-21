// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Trust Framework (6th Pillar)
// =========================================================================
//
// The Trust Framework is the 6th pillar of AegisGate's 6-pillar
// coverage. It provides per-agent cryptographic identity, capability
// contracts, real-time trust scoring, anomaly detection, signed
// attestations, and a customer-facing HTTP API at /api/v1/trust/*.
//
// Promoted to first-class platform status in D16 (2026-07-20).
// Reference: plans/THREAT-MODEL.md Section 2.6 (10 STRIDE threats).
//
// Sub-packages (8 pre-built, ~8,500 LOC, 548 tests, 85-91% coverage):
//   - pkg/trust             (this package, 4,384 LOC)
//   - pkg/trust/identity    agent identity registry (ECDSA P-256 keypair)
//   - pkg/trust/contract    capability contracts (signed statements)
//   - pkg/trust/score       trust score engine (behavioral baseline + anomaly)
//   - pkg/trust/attestation signed attestations (uses pkg/attestation envelope)
//   - pkg/trust/dashboard   real-time agent map dashboard
//   - pkg/attestation       envelope primitive (frozen 2026-06-15, ECDSA P-256)
//   - pkg/digest            CISO posture digest (PDF + signed envelope)
//
// Customer-facing HTTP API at /api/v1/trust/* (tier-gated to
// Professional+ unless TrustConfig.RequireLicense=false):
//   GET /score                -> lifetime score for ?agent=ID
//   GET /score?session=ID     -> current score for a specific session
//   GET /sessions             -> list sessions
//   GET /attestations         -> list recent attestations
//   GET /attestations/latest  -> most recent attestation
//   GET /health               -> liveness (no auth)
//
// Design choice: per-agent identity (long-lived) + per-session
// accumulator (short-lived request lifecycle). Together they give:
//   - Engine.GetScore(agentID)      -> lifetime trust score for the agent
//   - Session.ScoreDelta(sessID)    -> how much the score changed this request
//
// Trust verdicts (threshold-driven):
//   - 80-100: TRUSTED    -> normal operation
//   - 50-79:  SUSPICIOUS -> log and alert, allow with audit
//   - 0-49:   BLOCKED    -> block all operations pending review
//
// v3.4.0+ freeze: Trust Framework is tier-included (Professional+),
// NOT a separately-billable module. See pricing decisions (2026-06-04).
//
// =========================================================================

package trust
