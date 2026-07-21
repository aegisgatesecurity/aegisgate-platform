// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FIPS 140-2/140-3 Compliance Module
// =========================================================================
//
// FIPS 140 (Federal Information Processing Standard) is the US federal
// standard for cryptographic modules, validated by the NIST Cryptographic
// Module Validation Program (CMVP). This sub-package is the compliance
// module that wraps the existing FIPS crypto engine
// (upstream/aegisgate/pkg/crypto/fips/, 492 LOC) as AegisGate
// ControlDefinitions.
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a NIST CMVP-accredited Cryptographic Module
//   Validation Program laboratory. The FIPS mode in this codebase
//   is "FIPS-compliant" in the sense that:
//   - The Go stdlib crypto primitives used (AES-GCM, ECDSA P-256,
//     SHA-256/384/512) are FIPS-approved algorithms
//   - Approved cipher suites (ECDHE+AES-GCM) are used
//   - Approved key sizes are enforced
//   - Self-test is performed at startup
//   - Audit logging is supported
//
//   But the Go runtime itself is NOT a CMVP-validated module.
//   Customers who require CMVP-validated crypto (federal agencies,
//   defense contractors) must integrate a CMVP-validated module
//   (e.g., via PKCS#11) and run AegisGate in a CMVP-validated
//   execution environment. This is documented in the pricing page
//   disclaimer and the customer 1-pagers.
//
// Architecture:
//   - fips.go:         module wiring, pattern caches, 10 RegisterControl calls,
//                      8 CheckFunc implementations
//   - fips_test.go:    unit tests for each CheckFunc
//
// Tier & pricing:
//   - Required tier:  Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price:  $299/mo (founder-locked 2026-06-04)
//   - Module key:     "fips" (matches license.ModuleFIPS)
//
// To enable: customer purchases the FIPS 140 module in the customer
// portal; the Stripe webhook activates the module in their license.
// Until enabled, the FIPS 140 row in scan reports shows Enforced:
// false with Reason: module_not_owned.
//
// =========================================================================

package fips
