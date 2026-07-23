// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HITRUST CSF Compliance Module
// =========================================================================
//
// HITRUST CSF (Common Security Framework) v11.2 is a certifiable
// framework that inherits from HIPAA, NIST SP 800-53, ISO 27001,
// PCI-DSS, and other standards. It provides a single framework for
// managing information risk across multiple regulatory requirements.
//
// This is the 11th compliance framework in the AegisGate roadmap
// (HIPAA, PCI-DSS, EU AI Act, SOC 2, ISO 42001, FIPS 140, FedRAMP,
// CIS, NIST CSF, ISO 27001, HITRUST CSF).
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a HITRUST-authorized External Assessor (EA). The
//   HITRUST CSF module generates the technical evidence (audit logs,
//   IOC store, trust framework attestations, compliance scan results)
//   that a customer uses in their HITRUST CSF Assessment and MyCSF
//   portal. The HITRUST CSF certification and External Assessment are
//   the customer's responsibility, just as HIPAA audit and Notified
//   Body certification are the customer's responsibility for HIPAA and
//   EU AI Act respectively.
//
// Coverage (43 in-scope controls):
//   AM (Access Management):            10 controls (7 automated + 3 evidence-mapped)
//   ID (Identity Management):           5 controls (3 automated + 2 evidence-mapped)
//   IP (Information Protection):        8 controls (5 automated + 3 evidence-mapped)
//   PE (Privacy & Endpoint):           10 controls (0 automated + 10 evidence-mapped)
//   Additional IP controls:             5 controls (3 automated + 2 evidence-mapped)
//   Additional PE controls:             5 controls (0 automated + 5 evidence-mapped)
//
//   18 automated controls (with CheckFunc implementations)
//   25 evidence-mapped controls (AegisGate generates the evidence artifact)
//   Total: 43 in-scope controls
//
//   Out of scope: ~300+ HITRUST CSF v11.2 control specifications that
//   are process/HR/physical/organizational (not scanner-checkable).
//   These are the customer's responsibility per the HITRUST shared
//   responsibility model.
//
// Module metadata:
//   - Framework:    "hitrust"
//   - Version:      "1.0"
//   - Required tier: Enterprise+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $799/mo (founder-locked 2026-07-22)
//
// Architecture (family-based file structure):
//   - hitrust.go:   module wiring, registerControls, Dependencies, pattern caches
//   - am.go:        Access Management family (AM-01 through AM-10)
//   - id_ip_pe.go:  Identity, Info Protection, Privacy & Endpoint families
//   - hitrust_test.go: unit tests (43 controls, 18 automated, 25 evidence-mapped)
//   - doc.go:       package documentation
//
// Dependencies:
//   - hipaa:     HIPAA Health Insurance Portability and Accountability Act
//   - iso27001:  ISO/IEC 27001 Information Security Management
//   - fips:      FIPS 140 Cryptographic Module Validation
//   - soc2:      SOC 2 Trust Services Criteria
//   - ioc:       Indicator of Compromise store
//   - trust:     Trust Framework attestations
//
// To enable: customer purchases the HITRUST module in the customer
// portal; the Stripe webhook activates the module in their license.
// Until enabled, the HITRUST row in scan reports shows Enforced:
// false with Reason: module_not_owned.
//
// =========================================================================

package hitrust
