// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - License Management
// =========================================================================
//
// Client-side license validation. No remote API calls for license
// checks — the license key is a self-contained signed JSON document
// that the platform can validate offline using the embedded public key.
//
// Cryptography:
//   - ECDSA P-256 (FIPS 186-4, NIST P-256)
//   - SHA-256 for digest
//   - The public key is embedded in the binary at build time;
//     the private key is held exclusively by AegisGate Security, LLC
//     for license signing. Key rotation requires a new platform release.
//
// License Key Format (base64-encoded JSON):
//
//	{
//	  "license_id":  "<uuid>",
//	  "tier":        "community|developer|professional|enterprise",
//	  "customer":    "<customer-identifier>",
//	  "issued_at":   "<RFC3339>",
//	  "expires_at":  "<RFC3339> or 'never' for perpetual",
//	  "features":    ["feature1", "feature2"],
//	  "modules":     ["hipaa", "pci", ...],   // compliance modules owned
//	  "signature":   "<base64 ECDSA signature>"
//	}
//
// Design Principles:
//   - Client-side validation: no remote API calls
//   - Cryptographic integrity: ECDSA P-256 signatures with SHA-256
//   - Graceful degradation: 7-day grace period after expiry
//   - Fallback to Community tier on any validation failure
//
// Tier 1.6+ (Path B): module-based gating is delegated to
// pkg/compliance/gating.go (the single source of truth for "is this
// compliance module actually shipped?").
//
// =========================================================================

package license
