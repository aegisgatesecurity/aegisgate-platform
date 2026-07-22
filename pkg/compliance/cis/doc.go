// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CIS Critical Security Controls v8 Module
// =========================================================================
//
// CIS Critical Security Controls v8 (formerly SANS Top 20) is the
// de-facto industry baseline for US enterprise security questionnaires.
// Appears in 80%+ of enterprise RFPs.
//
// Architecture:
//   - cis.go:        module wiring, 15 RegisterControl calls,
//                    15 CheckFunc implementations
//   - cis_test.go:   unit tests
//
// Coverage: 15 of 18 CIS v8 control families mapped to AegisGate. All
// 15 are 100% automated. The remaining 3 (CIS 14, 15, 18) are
// out-of-scope for a security scanner (they are process/human/customer-
// driven activities):
//
//   - CIS 14 (Security Awareness Training): out of scope (human training)
//   - CIS 15 (Service Provider Management): out of scope (vendor onboarding)
//   - CIS 18 (Penetration Testing): out of scope (external human testers)
//
// See plans/V3X-CLOSE-OUT-PLAN-2026-07-21.md and
// plans/V3X-CLOSE-OUT-RELEVANCE-ANALYSIS-2026-07-21.md for the
// out-of-scope justification. AegisGate can produce ARTIFACTS (e.g., a
// generated pen-test report template) but cannot perform human training,
// vendor onboarding, or external pen testing.
//
// Tier & pricing:
//   - Required tier:  Community (free, bundled with the platform)
//   - Module key:     "cis"
//   - Version:        1.1 (v3.x Tier 1: 15/15 in-scope controls)
//
// Reference: https://www.cisecurity.org/controls/cis-controls-list
//            CIS Critical Security Controls v8.0 (May 2024)
// =========================================================================

package cis
