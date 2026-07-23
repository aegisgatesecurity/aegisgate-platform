// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC Level 2 Compliance Module
// =========================================================================
//
// CMMC Level 2 (Cybersecurity Maturity Model Certification, Level 2)
// is the DoD's framework for Defense Industrial Base (DIB) contractors
// handling Controlled Unclassified Information (CUI). Based on NIST SP
// 800-171 Rev. 2 with 14 domains and 110 practices, CMMC L2 requires
// third-party assessment by a C3PAO starting in 2025.
//
// This is the 8th compliance framework in the AegisGate roadmap
// (HIPAA, PCI-DSS, EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP,
// CMMC L2).
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a C3PAO (CMMC Third-Party Assessment Organization).
//   The CMMC L2 module generates the technical evidence (audit logs,
//   IOC store, trust framework attestations, compliance scan results)
//   that a customer uses in their CMMC assessment. The C3PAO assessment
//   and CMMC certification issuance is the customer's responsibility.
//
// Coverage (practical subset of 14 CMMC L2 domains):
//   52 controls across 14 CMMC domains:
//     AC (Access Control):                          8 controls (4 automated + 4 evidence-mapped)
//     AM (Asset Management):                        3 controls (2 automated + 1 evidence-mapped)
//     AU (Audit and Accountability):                4 controls (2 automated + 2 evidence-mapped)
//     CA (Assessment and Authorization):             3 controls (3 automated + 0 evidence-mapped)
//     CM (Configuration Management):                5 controls (3 automated + 2 evidence-mapped)
//     IA (Identification and Authentication):        5 controls (4 automated + 1 evidence-mapped)
//     IR (Incident Response):                         3 controls (2 automated + 1 evidence-mapped)
//     MA (Maintenance):                              2 controls (2 automated + 0 evidence-mapped)
//     MP (Media Protection):                         3 controls (1 automated + 2 evidence-mapped)
//     PE (Physical Protection):                      2 controls (1 automated + 1 evidence-mapped)
//     RA (Risk Assessment):                          3 controls (2 automated + 1 evidence-mapped)
//     SA (Situational Awareness):                    3 controls (2 automated + 1 evidence-mapped)
//     SC (System and Communications Protection):     4 controls (2 automated + 2 evidence-mapped)
//     SI (System and Information Integrity):          4 controls (2 automated + 2 evidence-mapped)
//
//   26 automated controls (with CheckFunc implementations)
//   26 evidence-mapped controls (AegisGate generates the evidence artifact)
//   Total: 52 in-scope controls
//
//   Out of scope: ~58 CMMC L2 practices that are process/HR/physical/
//   organizational (not scanner-checkable). These are the customer's
//   responsibility per the CMMC shared responsibility model.
//
// Module metadata:
//   - Framework:    "cmmcl2"
//   - Version:      "1.0"
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $499/mo (founder-locked 2026-06-04)
//
// Architecture (domain-based file structure):
//   - cmmcl2.go:       module wiring, registerControls, Dependencies, pattern caches
//   - ac.go:            Access Control domain (AC.1.001, AC.2.001–AC.2.007)
//   - am.go:            Asset Management domain (AM.1.001–AM.2.002)
//   - au.go:            Audit and Accountability domain (AU.1.001–AU.2.004)
//   - ca_cm.go:         Assessment & Authorization + Configuration Management
//   - ia_ir.go:         Identification & Authentication + Incident Response
//   - ma_mp_pe.go:      Maintenance + Media Protection + Physical Protection
//   - ra_sa_sc_si.go:   Risk Assessment + Situational Awareness +
//                       System & Communications Protection + System & Information Integrity
//   - cmmcl2_test.go:   unit tests (52 controls, 26 automated, 26 evidence-mapped)
//
// To enable: customer purchases the CMMC L2 module in the customer
// portal; the Stripe webhook activates the module in their license.
// Until enabled, the CMMC L2 row in scan reports shows Enforced:
// false with Reason: module_not_owned.
//
// =========================================================================

package cmmcl2
