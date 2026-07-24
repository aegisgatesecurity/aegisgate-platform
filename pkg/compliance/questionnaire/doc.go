// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Vendor Questionnaire Auto-Answer Engine
// =========================================================================
//
// Package questionnaire implements the Vendor Questionnaire Auto-Answer
// feature for the AegisGate platform. It maps compliance scanner results
// to pre-filled questionnaire answers for the SIG (Standardized
// Information Gathering) and CAIQ (Consensus Assessments Initiative
// Questionnaire) frameworks.
//
// The engine uses a keyword-to-answer mapping system where compliance
// scanner outputs (e.g., "mfa=true", "encryption_at_rest=aes-256") are
// matched against predefined answer rules. Each answer includes a
// confidence score:
//   - 0.8-1.0: answer derived from automated scan evidence
//   - 0.5-0.7: answer derived from policy inference or partial evidence
//   - 0.0-0.4: answer requires manual review (insufficient evidence)
//
// Usage:
//
//	engine := questionnaire.NewQuestionnaireEngine()
//
//	// Generate a SIG questionnaire from scan results
//	sigResp, err := engine.GenerateSIG("Acme Corp", scanResults)
//
//	// Generate a CAIQ questionnaire from scan results
//	caiqResp, err := engine.GenerateCAIQ("Acme Corp", scanResults)
//
//	// Export to CSV
//	csvBytes, err := questionnaire.ExportToCSV(sigResp)
//
//	// Export to structured text (PDF stub)
//	pdfBytes, err := questionnaire.ExportToPDF(caiqResp)
//
// The questionnaire engine follows the AegisGate compliance module
// architecture pattern and can be integrated with the existing
// Scanner (pkg/compliance/scanner.go) and FrameworkModule system
// (pkg/compliance/module.go).
//
// Question banks:
//   - SIG: 100 questions across Security, Availability, Processing
//     Integrity, Confidentiality, and Privacy
//   - CAIQ: 150 questions across Cloud Security, Compliance, Data
//     Privacy, Incident Response, and Risk Management
//
// Export formats:
//   - CSV (fully implemented)
//   - PDF (stub — returns structured text; real PDF requires wkhtmltopdf)
//
// =========================================================================

package questionnaire
