// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - ISO/IEC 42001 AI Management System Module
// =========================================================================
//
// ISO/IEC 42001:2023 (AI Management System) compliance framework as a
// licensed add-on module. Implements 8 controls across 5 ISO 42001
// clauses (4.0 Context, 5.0 Leadership, 6.0 Planning, 7.0 Support,
// 8.0 Operation, 9.0 Performance Evaluation, plus an AI-specific
// extension). Of the 8 controls, 5 have automated CheckFunc
// implementations; the remaining 3 are manual review items.
//
// Architecture:
//   - iso42001.go:       module wiring, pattern caches, 8 RegisterControl calls,
//                        5 CheckFunc implementations
//   - iso42001_test.go:  unit tests for each CheckFunc
//
// Reference:
//   - ISO/IEC 42001:2023 AI Management Systems:
//     https://www.iso.org/standard/81230.html
//
// Tier & pricing:
//   - Required tier:  Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price:  $79/mo (founder-locked 2026-06-04)
//   - Module key:     "iso_42001" (matches license.ModuleISO42001)
//
// To enable: customer purchases the ISO 42001 module in the customer
// portal; the Stripe webhook activates the module in their license.
// Until enabled, the ISO 42001 row in scan reports shows Enforced:
// false with Reason: module_not_owned.
//
// Note: this is the v3.4.0+ proper sub-package using the
// BaseComplianceModule pattern. The older pkg/compliance/enterprise/iso42001/
// sub-package (using the deprecated common.Framework interface)
// remains for backward compatibility but is not the active
// implementation. New code should import this package.
//
// =========================================================================

package iso42001
