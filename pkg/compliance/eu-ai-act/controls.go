// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform
// =========================================================================
//
// EU AI Act Compliance Module - Control Definitions (v3.3.0 Phase 1)
//
// This file holds the 82 RegisterControl calls for the EU AI Act framework.
// The 8 categories map to Articles of Regulation 2024/1689 plus AegisGate
// AI-specific extensions. Of the 82 controls, 9 have automated CheckFunc
// implementations (defined in eu_ai_act.go); the remaining 73 are manual
// review items that the customer/auditor verifies out of band. This mix
// mirrors the HIPAA sub-package's pattern of automated + manual controls.
//
// Distribution: 8 (Art 5) + 10 (Art 9) + 8 (Art 10) + 10 (Art 11+12) +
//                14 (Art 13+14) + 12 (Art 15) + 10 (Art 51-55) + 10 (AI-*)
//                = 82 controls total.

package eu_ai_act

import (
	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerControls wires all 82 EU AI Act controls into the module.
// Called once from NewEUAIModule. The 9 automated controls reference
// check* methods defined in eu_ai_act.go; the rest are manual review.
func (m *EUAIModule) registerControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art5-001",
		Name:        "Subliminal Manipulation Techniques",
		Description: "EU AI Act 5(1)(a): Subliminal Manipulation Techniques",
		Category:    "Prohibited Practices",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkProhibitedPractices,
		References:  []string{"EU AI Act Article 5(1)(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art5-002",
		Name:        "Exploitation of Vulnerabilities",
		Description: "EU AI Act 5(1)(b): Exploitation of Vulnerabilities",
		Category:    "Prohibited Practices",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 5(1)(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art5-003",
		Name:        "Social Scoring by Public Authorities",
		Description: "EU AI Act 5(1)(c): Social Scoring by Public Authorities",
		Category:    "Prohibited Practices",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 5(1)(c)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art5-004",
		Name:        "Real-Time Remote Biometric Identification",
		Description: "EU AI Act 5(1)(h): Real-Time Remote Biometric Identification",
		Category:    "Prohibited Practices",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 5(1)(h)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art5-005",
		Name:        "Predictive Policing Individual Risk",
		Description: "EU AI Act 5(1)(d): Predictive Policing Individual Risk",
		Category:    "Prohibited Practices",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 5(1)(d)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art5-006",
		Name:        "Untargeted Scraping of Facial Images",
		Description: "EU AI Act 5(1)(e): Untargeted Scraping of Facial Images",
		Category:    "Prohibited Practices",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 5(1)(e)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art5-007",
		Name:        "Emotion Recognition in Workplace/Education",
		Description: "EU AI Act 5(1)(f): Emotion Recognition in Workplace/Education",
		Category:    "Prohibited Practices",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 5(1)(f)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art5-008",
		Name:        "Biometric Categorization of Sensitive Attributes",
		Description: "EU AI Act 5(1)(g): Biometric Categorization of Sensitive Attributes",
		Category:    "Prohibited Practices",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 5(1)(g)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-001",
		Name:        "Risk Management System Established",
		Description: "EU AI Act 9(1): Risk Management System Established",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRiskManagement,
		References:  []string{"EU AI Act Article 9(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-002",
		Name:        "Risk Identification and Analysis",
		Description: "EU AI Act 9(2)(a): Risk Identification and Analysis",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 9(2)(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-003",
		Name:        "Risk Estimation and Evaluation",
		Description: "EU AI Act 9(2)(b): Risk Estimation and Evaluation",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 9(2)(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-004",
		Name:        "Risk Mitigation Measures",
		Description: "EU AI Act 9(2)(c): Risk Mitigation Measures",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 9(2)(c)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-005",
		Name:        "Testing Procedures for Risk Mitigation",
		Description: "EU AI Act 9(2)(d): Testing Procedures for Risk Mitigation",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 9(2)(d)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-006",
		Name:        "Continuous Monitoring and Review",
		Description: "EU AI Act 9(2)(e): Continuous Monitoring and Review",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 9(2)(e)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-007",
		Name:        "Iteration Throughout Lifecycle",
		Description: "EU AI Act 9(3): Iteration Throughout Lifecycle",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 9(3)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-008",
		Name:        "Integration with Quality Management",
		Description: "EU AI Act 9(4): Integration with Quality Management",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 9(4)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-009",
		Name:        "Documentation of Known Risks",
		Description: "EU AI Act 9(5): Documentation of Known Risks",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 9(5)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art9-010",
		Name:        "Residual Risk Acceptability",
		Description: "EU AI Act 9(6): Residual Risk Acceptability",
		Category:    "Risk Management",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 9(6)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art10-001",
		Name:        "Training Data Quality and Relevance",
		Description: "EU AI Act 10(1): Training Data Quality and Relevance",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 10(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art10-002",
		Name:        "Data Governance and Management",
		Description: "EU AI Act 10(2): Data Governance and Management",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 10(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art10-003",
		Name:        "Bias Examination and Mitigation",
		Description: "EU AI Act 10(2)(a): Bias Examination and Mitigation",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 10(2)(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art10-004",
		Name:        "Data Preparation and Processing",
		Description: "EU AI Act 10(2)(b): Data Preparation and Processing",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 10(2)(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art10-005",
		Name:        "Dataset Representativeness",
		Description: "EU AI Act 10(3): Dataset Representativeness",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 10(3)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art10-006",
		Name:        "Statistical Properties of Datasets",
		Description: "EU AI Act 10(4): Statistical Properties of Datasets",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 10(4)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art10-007",
		Name:        "Possible Biases Identification",
		Description: "EU AI Act 10(5): Possible Biases Identification",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 10(5)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art10-008",
		Name:        "Data Provenance and Lineage",
		Description: "EU AI Act 10(6): Data Provenance and Lineage",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 10(6)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art11-001",
		Name:        "Technical Documentation Before Market",
		Description: "EU AI Act 11(1): Technical Documentation Before Market",
		Category:    "Technical Documentation",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTechnicalDocumentation,
		References:  []string{"EU AI Act Article 11(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art11-002",
		Name:        "System Characteristics Documentation",
		Description: "EU AI Act 11(1)(a): System Characteristics Documentation",
		Category:    "Technical Documentation",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 11(1)(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art11-003",
		Name:        "Design Specifications Documentation",
		Description: "EU AI Act 11(1)(b): Design Specifications Documentation",
		Category:    "Technical Documentation",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 11(1)(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art11-004",
		Name:        "Development Process Documentation",
		Description: "EU AI Act 11(1)(c): Development Process Documentation",
		Category:    "Technical Documentation",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 11(1)(c)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art11-005",
		Name:        "Intended Purpose Documentation",
		Description: "EU AI Act 11(1)(d): Intended Purpose Documentation",
		Category:    "Technical Documentation",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 11(1)(d)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art12-001",
		Name:        "Automatic Logging Capabilities",
		Description: "EU AI Act 12(1): Automatic Logging Capabilities",
		Category:    "Record Keeping",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecordKeeping,
		References:  []string{"EU AI Act Article 12(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art12-002",
		Name:        "Log Traceability",
		Description: "EU AI Act 12(2): Log Traceability",
		Category:    "Record Keeping",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 12(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art12-003",
		Name:        "Log Retention Period",
		Description: "EU AI Act 12(3): Log Retention Period",
		Category:    "Record Keeping",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 12(3)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art12-004",
		Name:        "Log Integrity and Tamper Evidence",
		Description: "EU AI Act 12(4): Log Integrity and Tamper Evidence",
		Category:    "Record Keeping",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 12(4)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art12-005",
		Name:        "Log Accessibility for Authorities",
		Description: "EU AI Act 12(5): Log Accessibility for Authorities",
		Category:    "Record Keeping",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 12(5)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art13-001",
		Name:        "System Designed for Transparency",
		Description: "EU AI Act 13(1): System Designed for Transparency",
		Category:    "Transparency",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTransparency,
		References:  []string{"EU AI Act Article 13(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art13-002",
		Name:        "Instructions for Use Provided",
		Description: "EU AI Act 13(2): Instructions for Use Provided",
		Category:    "Transparency",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 13(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art13-003",
		Name:        "System Capabilities Disclosure",
		Description: "EU AI Act 13(3)(a): System Capabilities Disclosure",
		Category:    "Transparency",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 13(3)(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art13-004",
		Name:        "System Limitations Disclosure",
		Description: "EU AI Act 13(3)(b): System Limitations Disclosure",
		Category:    "Transparency",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 13(3)(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art13-005",
		Name:        "Intended Purpose Disclosure",
		Description: "EU AI Act 13(3)(c): Intended Purpose Disclosure",
		Category:    "Transparency",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 13(3)(c)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art13-006",
		Name:        "Accuracy Levels Disclosure",
		Description: "EU AI Act 13(3)(d): Accuracy Levels Disclosure",
		Category:    "Transparency",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 13(3)(d)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art13-007",
		Name:        "Robustness Disclosure",
		Description: "EU AI Act 13(3)(e): Robustness Disclosure",
		Category:    "Transparency",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 13(3)(e)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art13-008",
		Name:        "Cybersecurity Measures Disclosure",
		Description: "EU AI Act 13(3)(f): Cybersecurity Measures Disclosure",
		Category:    "Transparency",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 13(3)(f)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art14-001",
		Name:        "Human Oversight Designed In",
		Description: "EU AI Act 14(1): Human Oversight Designed In",
		Category:    "Human Oversight",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkHumanOversight,
		References:  []string{"EU AI Act Article 14(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art14-002",
		Automated:   true,
		CheckFunc:   m.checkOversightMeasuresEffective,
		Name:        "Oversight Measures Effective",
		Description: "EU AI Act 14(2): Oversight Measures Effective",
		Category:    "Human Oversight",
		Severity:    compliance.SeverityHigh,
		References:  []string{"EU AI Act Article 14(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art14-003",
		Automated:   true,
		CheckFunc:   m.checkHumanReviewersCanIntervene,
		Name:        "Human Reviewers Can Intervene",
		Description: "EU AI Act 14(3): Human Reviewers Can Intervene",
		Category:    "Human Oversight",
		Severity:    compliance.SeverityHigh,
		References:  []string{"EU AI Act Article 14(3)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art14-004",
		Automated:   true,
		CheckFunc:   m.checkKillSwitchAbortCapability,
		Name:        "Kill Switch / Abort Capability",
		Description: "EU AI Act 14(4): Kill Switch / Abort Capability",
		Category:    "Human Oversight",
		Severity:    compliance.SeverityHigh,
		References:  []string{"EU AI Act Article 14(4)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art14-005",
		Name:        "Bias Monitoring by Humans",
		Description: "EU AI Act 14(5): Bias Monitoring by Humans",
		Category:    "Human Oversight",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 14(5)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art14-006",
		Name:        "Override Capability for Automated Decisions",
		Description: "EU AI Act 14(6): Override Capability for Automated Decisions",
		Category:    "Human Oversight",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 14(6)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-001",
		Name:        "Accuracy Level Appropriate",
		Description: "EU AI Act 15(1): Accuracy Level Appropriate",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccuracyRobustness,
		References:  []string{"EU AI Act Article 15(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-002",
		Name:        "Robustness Measures Implemented",
		Description: "EU AI Act 15(2): Robustness Measures Implemented",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-003",
		Name:        "Resilience to Errors and Faults",
		Description: "EU AI Act 15(3): Resilience to Errors and Faults",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(3)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-004",
		Name:        "Performance Monitoring in Operation",
		Description: "EU AI Act 15(4): Performance Monitoring in Operation",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(4)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-005",
		Name:        "Cybersecurity Measures Appropriate",
		Description: "EU AI Act 15(5): Cybersecurity Measures Appropriate",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(5)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-006",
		Name:        "Protection Against Unauthorized Access",
		Description: "EU AI Act 15(5)(a): Protection Against Unauthorized Access",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(5)(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-007",
		Name:        "Data Poisoning Mitigation",
		Description: "EU AI Act 15(5)(b): Data Poisoning Mitigation",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCybersecurity,
		References:  []string{"EU AI Act Article 15(5)(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-008",
		Name:        "Model Poisoning Mitigation",
		Description: "EU AI Act 15(5)(c): Model Poisoning Mitigation",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(5)(c)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-009",
		Name:        "Adversarial Attack Mitigation",
		Description: "EU AI Act 15(5)(d): Adversarial Attack Mitigation",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(5)(d)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-010",
		Name:        "Training Data Confidentiality",
		Description: "EU AI Act 15(5)(e): Training Data Confidentiality",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(5)(e)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-011",
		Name:        "Model Parameter Integrity",
		Description: "EU AI Act 15(5)(f): Model Parameter Integrity",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(5)(f)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art15-012",
		Name:        "System Service Availability",
		Description: "EU AI Act 15(5)(g): System Service Availability",
		Category:    "Accuracy and Robustness",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"EU AI Act Article 15(5)(g)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art51-001",
		Name:        "Technical Documentation for GPAI",
		Description: "EU AI Act 51(1)(a): Technical Documentation for GPAI",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 51(1)(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art51-002",
		Name:        "Downstream Provider Information",
		Description: "EU AI Act 51(1)(b): Downstream Provider Information",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 51(1)(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art51-003",
		Name:        "Copyright Compliance Policy",
		Description: "EU AI Act 51(1)(c): Copyright Compliance Policy",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 51(1)(c)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art51-004",
		Name:        "Training Data Summary Disclosure",
		Description: "EU AI Act 51(1)(d): Training Data Summary Disclosure",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 51(1)(d)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art52-001",
		Name:        "AI Office Request Compliance",
		Description: "EU AI Act 52(1): AI Office Request Compliance",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 52(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art53-001",
		Name:        "Systemic Risk Classification",
		Description: "EU AI Act 53(1): Systemic Risk Classification",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 53(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art53-002",
		Name:        "State-of-the-Art Evaluation",
		Description: "EU AI Act 53(1)(a): State-of-the-Art Evaluation",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 53(1)(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art53-003",
		Name:        "Systemic Risk Assessment Documented",
		Description: "EU AI Act 53(1)(b): Systemic Risk Assessment Documented",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 53(1)(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art55-001",
		Name:        "Code of Conduct Adherence",
		Description: "EU AI Act 55(1): Code of Conduct Adherence",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 55(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-Art55-002",
		Name:        "Voluntary Commitments and Best Practices",
		Description: "EU AI Act 55(2): Voluntary Commitments and Best Practices",
		Category:    "GPAI Models",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"EU AI Act Article 55(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-001",
		Name:        "Prompt Injection Protection",
		Description: "EU AI Act AegisGate extension: Prompt Injection Protection",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPromptInjectionProtection,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-002",
		Automated:   true,
		CheckFunc:   m.checkTrainingDataSanitization,
		Name:        "Training Data Sanitization",
		Description: "EU AI Act AegisGate extension: Training Data Sanitization",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-003",
		Automated:   true,
		CheckFunc:   m.checkAIOutputFiltering,
		Name:        "AI System Output Filtering",
		Description: "EU AI Act AegisGate extension: AI System Output Filtering",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-004",
		Name:        "AI Model Bias Detection",
		Description: "EU AI Act AegisGate extension: AI Model Bias Detection",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-005",
		Automated:   true,
		CheckFunc:   m.checkHallucinationDetection,
		Name:        "AI Model Hallucination Detection",
		Description: "EU AI Act AegisGate extension: AI Model Hallucination Detection",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-006",
		Automated:   true,
		CheckFunc:   m.checkAgentCapabilityAttestation,
		Name:        "AI Agent Capability Attestation",
		Description: "EU AI Act AegisGate extension: AI Agent Capability Attestation",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-007",
		Automated:   true,
		CheckFunc:   m.checkModelVersioningLineage,
		Name:        "AI Model Versioning and Lineage",
		Description: "EU AI Act AegisGate extension: AI Model Versioning and Lineage",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-008",
		Name:        "AI Model Red Team Testing",
		Description: "EU AI Act AegisGate extension: AI Model Red Team Testing",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-009",
		Name:        "AI Model Interpretability and Explainability",
		Description: "EU AI Act AegisGate extension: AI Model Interpretability and Explainability",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "EUAIAct-AI-010",
		Name:        "AI System Kill Switch and Rollback",
		Description: "EU AI Act AegisGate extension: AI System Kill Switch and Rollback",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"EU AI Act Article AegisGate extension"},
	})

}
