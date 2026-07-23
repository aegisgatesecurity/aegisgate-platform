// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CCPA/CPRA Compliance Module
// =========================================================================
//
// CCPA/CPRA (California Consumer Privacy Act / California Privacy Rights
// Act) is California's comprehensive consumer privacy law. CCPA (2018)
// grants California residents the right to know, delete, opt-out, and
// non-discrimination regarding their personal information. CPRA (2020
// amendments, effective 2023) adds the right to correct, establishes the
// California Privacy Protection Agency (CPPA), and introduces additional
// obligations around data minimization and automated decision-making.
//
// This is the community-tier (free, bundled) compliance module in the
// AegisGate roadmap. It provides 12 in-scope controls:
//   - 7 automated controls (with CheckFunc implementations)
//   - 5 evidence-mapped controls (AegisGate generates the evidence
//     artifact the consumer attaches to their CCPA/CPRA compliance
//     documentation)
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a law firm or regulatory body. The CCPA/CPRA module
//   generates the technical evidence (audit logs, IOC store, trust
//   framework attestations, compliance scan results) that a customer
//   uses in their CCPA/CPRA compliance documentation. Legal review and
//   formal compliance attestation are the customer's responsibility.
//
// Coverage (12 in-scope controls):
//   Consumer Rights:
//     TK (Right to Know):           3 controls (3 automated + 0 evidence-mapped)
//     DR (Right to Delete):         2 controls (1 automated + 1 evidence-mapped)
//     OS (Right to Opt-Out/Sell):   3 controls (2 automated + 1 evidence-mapped)
//     NC (Right to Non-Discrimination): 2 controls (1 automated + 1 evidence-mapped)
//   Privacy Rights (CPRA additions):
//     PR (Privacy Rights):          2 controls (0 automated + 2 evidence-mapped)
//
// Module metadata:
//   - Framework:    "ccpa"
//   - Version:      "1.0"
//   - Required tier: Community (free, bundled)
//   - Dependencies: gdpr, soc2, ioc, trust
//
// Architecture:
//   - ccpa.go:       module wiring, registerControls, Dependencies, pattern caches
//   - ccpa_test.go:  unit tests (12 controls, 7 automated, 5 evidence-mapped)
//
// To enable: the CCPA/CPRA module is bundled at the Community tier — no
// separate purchase required. The module is activated by default for all
// AegisGate deployments.
//
// =========================================================================

package ccpa
