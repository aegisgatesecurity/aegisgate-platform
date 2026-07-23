// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - TISAX Compliance Module
// =========================================================================
//
// TISAX (Trusted Information Security Assessment Exchange) is the European
// automotive industry's information security assessment standard, based on
// ISO 27001 but tailored for the automotive supply chain. TISAX AL2
// (Assessment Level 2) provides a "plausibility check" by an accredited
// auditor, suitable for data with normal protection needs.
//
// This is the 12th compliance framework in the AegisGate roadmap
// (HIPAA, PCI-DSS, EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP,
// ISO 27001, NIST CSF, OWASP, CSA STAR, TISAX).
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT an accredited TISAX audit provider. The TISAX module
//   generates the technical evidence (audit logs, IOC store, trust framework
//   attestations, compliance scan results) that a customer uses in their
//   TISAX assessment package. The TISAX assessment and label issuance is
//   the customer's responsibility through an accredited TISAX audit provider
//   (e.g., TÜV, DEKRA).
//
// Coverage (35 controls across 5 families):
//   IS (Information Security):        8 controls (5 automated + 3 evidence-mapped)
//   OR (Organization & Risk):          7 controls (2 automated + 5 evidence-mapped)
//   DSC (Data & System Controls):      6 controls (3 automated + 3 evidence-mapped)
//   PP (Privacy & Personnel):          7 controls (1 automated + 6 evidence-mapped)
//   DP (Development & Prototyping):    7 controls (4 automated + 3 evidence-mapped)
//
//   16 automated controls (with CheckFunc implementations)
//   19 evidence-mapped controls (AegisGate generates the evidence artifact)
//   Total: 35 in-scope controls
//
// Module metadata:
//   - Framework:    "tisax"
//   - Version:      "1.0"
//   - Required tier: Enterprise (gated via pkg/compliance/gating.go)
//   - Monthly price: $599/mo (founder-locked 2026-07-22)
//
// Architecture (family-based file structure):
//   - tisax.go:      module wiring, registerControls, Dependencies, pattern caches
//   - is_or.go:      Information Security + Organization & Risk families
//   - dsc_pp_dp.go:  Data & System Controls + Privacy & Personnel + Development & Prototyping
//   - tisax_test.go: unit tests (35 controls, 16 automated, 19 evidence-mapped)
//
// To enable: customer purchases the TISAX module in the customer portal;
// the Stripe webhook activates the module in their license. Until enabled,
// the TISAX row in scan reports shows Enforced: false with Reason:
// module_not_owned.
//
// =========================================================================

package tisax
