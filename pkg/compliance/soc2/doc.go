// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOC 2 Type II Compliance Module
// =========================================================================
//
// SOC 2 (Service Organization Control 2) Type II compliance framework
// as a licensed add-on module. Implements 8 Trust Service Criteria
// controls across 4 categories (Security CC, Processing Integrity PI,
// Confidentiality C, AI Controls). Of the 8 controls, 5 have automated
// CheckFunc implementations; the remaining 3 are manual review items
// that the customer's auditor verifies out of band.
//
// Architecture:
//   - soc2.go:        module wiring, pattern caches, 8 RegisterControl calls,
//                     5 CheckFunc implementations
//   - soc2_test.go:   unit tests for each CheckFunc (5 controls * 3-4 cases
//                     = 15-20 tests; 80%+ per-package coverage target)
//
// Reference:
//   - AICPA Trust Services Criteria 2017 (revised 2022):
//     https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
//   - The existing pkg/compliance/soc2_framework.go (data structures)
//     is preserved for backward compatibility; this sub-package is the
//     active implementation that the Compliance Scan Engine calls.
//
// Tier & pricing:
//   - Required tier:  Developer+ (gated via pkg/compliance/gating.go)
//   - Monthly price:  $149/mo (founder-locked 2026-06-04)
//   - Module key:     "soc2" (matches license.ModuleSOC2)
//
// To enable: customer purchases the SOC 2 module in the customer
// portal; the Stripe webhook activates the module in their license.
// Until enabled, the SOC 2 row in scan reports shows Enforced: false
// with Reason: module_not_owned.
//
// =========================================================================

package soc2
