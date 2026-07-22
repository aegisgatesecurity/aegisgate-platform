// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Cross-Framework Control Mapping Module
// =========================================================================
//
// The Cross-Framework Control Mapping is the GRC-platform secret sauce:
// one AegisGate control (e.g., RBAC enforced with MFA) maps to many
// framework controls (SOC 2 CC6.1, ISO 27001 A.9.2, HIPAA §164.312(a),
// PCI 7.1, NIST CSF PR.AC-4, CIS 5, OWASP Web A01, etc.). Instead of
// writing 8 different evidence packages, the customer writes ONE and
// AegisGate fans it out to all 8 framework reports.
//
// This is the difference between "I spent 3 weeks preparing for SOC 2
// Type II" and "I clicked the AegisGate Compliance Report button and
// got a 47-page PDF in 12 seconds covering all 11 frameworks."
//
// Architecture:
//   - mapping.go:     the cross-framework mapping table + query API
//   - mapping_test.go: tests
//
// Public API:
//   - MapByControlID(aegisgateID)   -> external framework control IDs
//   - MapByFramework(framework, extID) -> AegisGate control IDs
//   - ListFrameworks()              -> all supported frameworks
//   - ListControls()                -> all AegisGate control IDs
//   - CoverageMatrix()              -> framework -> extID -> agIDs
//   - GenerateCoverageReport()      -> summary report
//   - FormatReport()                -> human-readable report string
//
// The GRC user flow is:
//   1. Run /api/v1/compliance/scan (existing endpoint)
//   2. For each compliant AegisGate control, fan out to all framework
//      controls that share evidence
//   3. Generate a single PDF/Markdown report with all frameworks
//   4. Auditor sees one set of evidence cited across many framework controls
//
// Reference: This pattern is called "control harmonization" in the
// GRC industry. Commercial tools (Drata, Vanta, Secureframe) do this
// at the data-collection level; AegisGate does it at the evidence
// generation level (deeper integration = less manual work).
// =========================================================================

package mapping
