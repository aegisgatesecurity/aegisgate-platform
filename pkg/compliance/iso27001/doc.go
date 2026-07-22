// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - ISO/IEC 27001:2022 Module
// =========================================================================
//
// ISO/IEC 27001:2022 is the international standard for Information Security
// Management Systems (ISMS). It is the de facto global standard for
// enterprise security certifications and appears in 60-70% of non-US
// enterprise RFPs.
//
// Architecture:
//   - iso27001.go:       module wiring, pattern caches, 60 RegisterControl
//                        calls, 60 CheckFunc implementations
//   - iso27001_test.go:  unit tests
//
// Coverage: 60 of 93 in-scope Annex A controls (scanner-checkable subset).
// The remaining 33 controls are correctly NOT registered because they
// are process/policy/HR concerns (NDA management, termination procedures,
// acceptable use training, asset management business processes, etc.)
// that a security scanner does not and SHOULD NOT implement.
//
// Mapping summary (v3.x Tier 1, 60 controls across 4 themes):
//   Annex A.5  Organizational      (23 controls registered; out-of-scope = 14)
//   Annex A.6  People             (5 controls; out-of-scope = 3)
//   Annex A.7  Physical           (7 controls; out-of-scope = 7)
//   Annex A.8  Technological      (25 controls; out-of-scope = 9)
//
// Out of scope for AegisGate (correctly NOT registered):
//   - Process/policy documentation (A.5.1, A.5.2, A.5.3, etc.)
//   - HR procedures (A.6.1, A.6.2, A.6.5)
//   - Physical security procedures (A.7.1, A.7.2, A.7.3, A.7.7, A.7.8, A.7.11, A.7.12)
//   - Supplier management processes (A.5.19-22 partial)
//
// See plans/V3X-CLOSE-OUT-PLAN-2026-07-21.md and
// plans/V3X-CLOSE-OUT-RELEVANCE-ANALYSIS-2026-07-21.md for the
// out-of-scope justification.
//
// Tier & pricing:
//   - Required tier:  Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price:  $99/mo (founder-locked 2026-06-04)
//   - Module key:     "iso_27001"
//
// Reference: ISO/IEC 27001:2022 Annex A
//            https://www.iso.org/standard/27001
//            ISO/IEC 27002:2022 (implementation guidance)
// =========================================================================

package iso27001
