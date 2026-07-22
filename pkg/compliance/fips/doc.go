// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FIPS 140-2/140-3 Compliance Module
// =========================================================================
//
// FIPS 140 (Federal Information Processing Standard) is the US federal
// standard for cryptographic modules. AegisGate implements the FIPS 140-2
// and 140-3 compliance checks as a licensed add-on module.
//
// Architecture:
//   - fips.go:        module wiring, 11 RegisterControl calls,
//                     11 CheckFunc implementations
//   - fips_test.go:   unit tests
//
// Coverage: 11 of 11 in-scope FIPS 140-2/140-3 security areas mapped
// to AegisGate. All 11 are 100% automated. The areas NOT covered
// (hardware-level) are correctly out of scope for a software
// cryptographic module:
//
//   - FIPS 140-2 §4.5 / 140-3 §7.5 (Physical Security) — hardware
//   - FIPS 140-2 §4.8 / 140-3 §7.7 (EMI/EMC) — hardware
//   - FIPS 140-2 §4.6 (Operational Environment — physical aspects) — hardware
//
// These areas are CMVP-validated hardware concerns and are the
// customer's responsibility. See plans/V3X-CLOSE-OUT-PLAN-2026-07-21.md
// and plans/V3X-CLOSE-OUT-RELEVANCE-ANALYSIS-2026-07-21.md for the
// out-of-scope justification.
//
// Tier & pricing:
//   - Required tier:  Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price:  $299/mo (founder-locked 2026-06-04)
//   - Module key:     "fips" (matches license.ModuleFIPS)
//   - Version:        1.1 (v3.x Tier 1: 11/11 in-scope controls)
//
// Reference: FIPS 140-2: https://csrc.nist.gov/publications/detail/fips/140/2/final
//            FIPS 140-3: https://csrc.nist.gov/publications/detail/fips/140/3/final
//            SP 800-57 (Key Management): https://csrc.nist.gov/publications/detail/sp/800/57/part/1/rev-5/final
// =========================================================================

package fips
