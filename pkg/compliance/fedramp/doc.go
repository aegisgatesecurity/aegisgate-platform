// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP Compliance Module
// =========================================================================
//
// FedRAMP (Federal Risk and Authorization Management Program) is the
// US federal government's standardized approach to security assessment,
// authorization, and continuous monitoring of cloud products and
// services. Based on NIST SP 800-53 Rev. 5 controls.
//
// This is the 7th compliance framework in the AegisGate roadmap
// (HIPAA, PCI-DSS, EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP).
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a FedRAMP-accredited 3PAO (Third Party Assessment
//   Organization). The FedRAMP module generates the technical evidence
//   (audit logs, IOC store, trust framework attestations, compliance
//   scan results) that a customer uses in their FedRAMP A&A package
//   (SAP, SAR, POA&M). The 3PAO assessment and ATO (Authority to
//   Operate) issuance is the customer's responsibility.
//
// Coverage (Path C — full in-scope controls):
//   56 controls across 11 NIST 800-53 Rev. 5 families:
//     AC (Access Control):                 6 controls (5 automated + 1 evidence-mapped)
//     AU (Audit and Accountability):        7 controls (5 automated + 2 evidence-mapped)
//     IA (Identification & Authentication): 6 controls (5 automated + 1 evidence-mapped)
//     SC (System & Communications Protection):7 controls (7 automated)
//     CM (Configuration Management):        5 controls (4 automated + 1 evidence-mapped)
//     SI (System & Information Integrity):  6 controls (4 automated + 2 evidence-mapped)
//     IR (Incident Response):               5 controls (3 automated + 2 evidence-mapped)
//     SA (System & Services Acquisition):   5 controls (1 automated + 4 evidence-mapped)
//     SR (Supply Chain Risk Management):    5 controls (1 automated + 4 evidence-mapped)
//     RA (Risk Assessment):                 4 controls (3 automated + 1 evidence-mapped)
//     CA (Assessment & Authorization):      4 controls (1 automated + 3 evidence-mapped)
//
//   31 automated controls (with CheckFunc implementations)
//   25 evidence-mapped controls (AegisGate generates the evidence artifact)
//   Total: 56 in-scope controls
//
//   Out of scope: ~267 NIST 800-53 Rev. 5 controls that are
//   process/HR/physical/organizational (not scanner-checkable). These
//   are the customer's responsibility per the FedRAMP shared
//   responsibility model.
//
// Module metadata:
//   - Framework:    "fedramp"
//   - Version:      "2.0" (Path C: full in-scope coverage)
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $499/mo (founder-locked 2026-06-04)
//
// Architecture (family-based file structure):
//   - fedramp.go:     module wiring, registerControls, Dependencies, pattern caches
//   - ac.go:          Access Control family (AC-2, AC-3, AC-6, AC-14, AC-17, AC-24)
//   - au.go:          Audit and Accountability family (AU-2, AU-3, AU-6, AU-9, AU-10, AU-12, AU-16)
//   - ia.go:          Identification and Authentication family (IA-2, IA-3, IA-5, IA-6, IA-7, IA-8)
//   - sc.go:          System and Communications Protection family (SC-4, SC-7, SC-8, SC-12, SC-13, SC-23, SC-28)
//   - cm_si.go:       Configuration Management + System & Information Integrity (CM-2–CM-8, SI-2–SI-10)
//   - ir_sa_sr.go:    Incident Response, System & Services Acquisition, Supply Chain Risk Management
//   - ra_ca.go:       Risk Assessment, Assessment & Authorization
//   - fedramp_test.go: unit tests (56 controls, 31 automated, 25 evidence-mapped)
//
// To enable: customer purchases the FedRAMP module in the customer
// portal; the Stripe webhook activates the module in their license.
// Until enabled, the FedRAMP row in scan reports shows Enforced:
// false with Reason: module_not_owned.
//
// =========================================================================

package fedramp
