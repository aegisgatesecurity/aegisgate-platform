// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Evidence Packages (v3.3.0+)
//
// Package evidence produces auditor-ready, cryptographically signed
// evidence packages for compliance frameworks (HIPAA, PCI, SOC 2,
// ISO 42001, FedRAMP, FIPS 140, EU AI Act, etc.).
//
// An evidence package is a single, signed JSON artifact that bundles:
//   - the per-framework compliance scan result (control counts,
//     per-control pass/fail, score, reason)
//   - a snapshot of the customer license (tier, modules, expiration),
//   - audit event anchors (counts by type, severity, framework),
//   - a SHA-256 hash of the canonicalized manifest,
//   - an ECDSA P-256 signature over that hash (SEC 1 encoded, matching
//     pkg/trust/attestation.Generator).
//
// The package can be independently verified without re-running the
// underlying scans. CISOs hand these to their auditors; auditors
// verify the signature against the platform public key (published at
// /.well-known/aegisgate-evidence-pubkey.pem).
//
// Reuses (no duplication):
//   - pkg/compliance.Scanner for the framework scan
//   - pkg/license.Manager for the license snapshot
//   - pkg/logging.Event for the audit event model
//   - pkg/trust/attestation signing primitives (ECDSA P-256, SEC 1)
//
// v3.3.0+ Track 2 (posture check is Track 1).
package evidence
