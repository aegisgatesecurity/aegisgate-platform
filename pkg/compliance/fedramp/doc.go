// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP Compliance Module
// =========================================================================
//
// FedRAMP (Federal Risk and Authorization Management Program) is the
// US federal government's standardized approach to security assessment,
// authorization, and continuous monitoring of cloud products and
// services. Based on NIST SP 800-53 Rev. 5. This is the 7th and
// final compliance framework in the AegisGate Path B roadmap.
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a FedRAMP-accredited 3PAO. The FedRAMP module
//   generates the technical evidence (audit logs, IOC store, trust
//   framework attestations, compliance scan results) that a customer
//   uses in their FedRAMP A&A package (SAP, SAR, POA&M). The 3PAO
//   assessment and ATO issuance is the customer's responsibility.
//
// Coverage scope:
//   This module implements 8 controls selected from the highest-
//   priority FedRAMP control families for AI/ML systems. The full
//   FedRAMP Moderate catalog has ~323 controls; FedRAMP High has
//   ~421. The remaining ~315+ controls are documented in the
//   coverage audit (see plans/FULL-CODEBASE-AUDIT-2026-07-20.md
//   Finding #3) and would require 4-6 weeks of work to map all of
//   them. The 8 controls in this module represent the highest-
//   priority subset, and the rest are mapped to existing AegisGate
//   evidence artifacts (the customer's FedRAMP A&A package
//   references AegisGate's audit log / IOC store / trust framework
//   as the source of technical evidence).
//
// Architecture:
//   - fedramp.go:        module wiring, 8 RegisterControl calls,
//                        5 CheckFunc implementations, pattern caches
//   - fedramp_test.go:   unit tests for each CheckFunc
//
// Tier & pricing:
//   - Required tier:  Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price:  $499/mo (founder-locked 2026-06-04)
//   - Module key:     "fedramp" (matches license.ModuleFedRAMP)
//
// To enable: customer purchases the FedRAMP module in the customer
// portal; the Stripe webhook activates the module in their license.
// Until enabled, the FedRAMP row in scan reports shows Enforced:
// false with Reason: module_not_owned.
//
// =========================================================================

package fedramp
