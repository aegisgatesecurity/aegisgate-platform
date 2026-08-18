// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST CSF 2.0 Module
// =========================================================================
//
// NIST Cybersecurity Framework 2.0 (the de-facto US enterprise security
// framework). Appears in 60%+ of US enterprise RFPs.
//
// The 6 CSF 2.0 Functions map cleanly to AegisGate's 6-pillar coverage:
//   GOVERN    -> Platform governance, audit, compliance
//   IDENTIFY  -> Asset inventory, IOC store, threat model
//   PROTECT   -> Access control, encryption, output filtering
//   DETECT    -> Scanner, anomaly detection, IOC federation
//   RESPOND   -> Trust Framework attestations, audit log, kill switch
//   RECOVER   -> Audit log replay, hash-chain verification, IOC restore
//
// Architecture:
//   - nist_csf.go:              module wiring, 131 RegisterControl calls,
//                                23 CheckFunc implementations
//   - nist_csf_test.go:         unit tests
//   - tier_coverage_test.go:    tier/framework tests
//
// Tier & pricing:
//   - Required tier:  Professional ($79/mo)
//   - Module key:     "nist_csf"
//   - Version:        "2.0"
//
// Coverage:
//   - 131 subcategories across 6 functions and 22 categories
//   - 23 automated controls (with CheckFunc)
//   - 108 manual controls (evidence-mapped)
//
// Reference: https://www.nist.gov/cyberframework
//            NIST CSF 2.0 (February 26, 2024)
// =========================================================================

package nist_csf
