// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 Compliance Module
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Protecting Controlled Unclassified Information
// in Nonfederal Systems and Organizations.
//
// NIST 800-171 is the compliance framework required for any nonfederal
// organization that processes, stores, or transmits Controlled Unclassified
// Information (CUI) on behalf of the US federal government. It defines
// 14 families of security requirements derived from NIST SP 800-53 Rev. 5.
//
// This is the 8th compliance framework in the AegisGate roadmap
// (HIPAA, PCI-DSS, EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP,
// NIST 800-171).
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a CMMC Assessor or C3PAO. The NIST 800-171 module
//   generates the technical evidence (audit logs, IOC store, trust
//   framework attestations, compliance scan results) that a customer
//   uses in their CMMC assessment or self-attestation (SPRS). The
//   CMMC assessment and certification are the customer's responsibility,
//   just as FedRAMP ATO and HIPAA audit are the customer's responsibility
//   for those respective frameworks.
//
// Coverage (50 controls: 25 automated + 25 evidence-mapped):
//   AC: Access Control                  (8 controls: 5 automated + 3 evidence)
//   AU: Audit and Accountability        (5 controls: 4 automated + 1 evidence)
//   CM/SI: Configuration Management +   (6 controls: 5 automated + 1 evidence)
//           System Integrity
//   IA: Identification and              (5 controls: 3 automated + 2 evidence)
//           Authentication
//   IR/RA: Incident Response +           (5 controls: 3 automated + 2 evidence)
//           Risk Assessment
//   SC: System and Communications       (6 controls: 5 automated + 1 evidence)
//           Protection
//   CP/MA/SA: Contingency Planning +     (6 controls: 1 automated + 5 evidence)
//           Maintenance + System Acquisition
//
// Module metadata:
//   - Framework:    "nist800171"
//   - Version:      "1.0"
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $399/mo
//
// Architecture (family-based file structure):
//   - nist800171.go: module wiring, registerControls, Dependencies, pattern caches
//   - ac.go:          Access Control family (AC-1 – AC-17)
//   - au.go:          Audit and Accountability family (AU-1 – AU-9)
//   - cm_si.go:       Configuration Management + System Integrity (CM-2 – SI-3)
//   - ia.go:          Identification and Authentication family (IA-1 – IA-8)
//   - ir_ra.go:       Incident Response + Risk Assessment (IR-1 – RA-3)
//   - sc.go:          System and Communications Protection (SC-4 – SC-23)
//   - cp_ma_sa.go:    Contingency Planning + Maintenance + System Acquisition (CP-1 – SA-5)
//   - nist800171_test.go: unit tests (50 controls, 25 automated, 25 evidence-mapped)
//
// =========================================================================

package nist800171
