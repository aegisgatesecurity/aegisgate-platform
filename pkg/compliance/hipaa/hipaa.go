// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HIPAA Compliance Module
// =========================================================================
//
// HIPAA Security Rule (45 CFR §164.306–§164.318) compliance controls as a
// licensed add-on module. Covers Security Standards, Administrative
// Safeguards, Physical Safeguards, Technical Safeguards, Organizational
// Requirements, Documentation Requirements, AI Controls, and Breach
// Notification.
//
// Module metadata:
//   - Framework:     "hipaa"
//   - Version:       "2.2"
//   - Required tier: Developer ($49/mo)
//   - Controls:      54 (35 automated, 19 manual)
//   - Categories:    8
//
// Architecture:
//   - hipaa.go:        module wiring, 54 RegisterControl calls,
//                      35 CheckFunc implementations
//   - hipaa_test.go:   unit tests
//   - tier_coverage_test.go: tier/framework tests
//
// Reference: HIPAA Security Rule, 45 CFR Part 164, Subpart C
//            HHS Guidance on HIPAA Security Rule (2003, amended 2013)
// =========================================================================

// Package hipaa provides HIPAA compliance controls as a licensed add-on module.
package hipaa

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// HIPAAModule implements HIPAA compliance controls.
type HIPAAModule struct {
	*compliance.BaseComplianceModule
	phiPatterns []*regexp.Regexp
}

// NewHIPAAModule creates a new HIPAA compliance module.
func NewHIPAAModule() *HIPAAModule {
	m := &HIPAAModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("hipaa", "2.2", core.TierDeveloper),
	}

	m.initPHIPatterns()
	m.registerControls()

	return m
}

// initPHIPatterns initializes patterns for detecting PHI.
func (m *HIPAAModule) initPHIPatterns() {
	// HIPAA-defined PHI identifiers
	m.phiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\d{3}-\d{2}-\d{4}`),                               // SSN
		regexp.MustCompile(`(?i)\d{10,16}`),                                       // Medical Record Number
		regexp.MustCompile(`(?i)[A-Z]\d{7}`),                                      // Health Plan ID
		regexp.MustCompile(`(?i)\d{2}[/-]\d{2}[/-]\d{4}`),                         // DOB
		regexp.MustCompile(`(?i)[A-Z]{2}\d{6}`),                                   // Account Number
		regexp.MustCompile(`(?i)\d{3}[-.\s]?\d{3}[-.\s]?\d{4}`),                   // Phone
		regexp.MustCompile(`(?i)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`), // Email
		regexp.MustCompile(`(?i)\d{5}[-\s]?\d{4}`),                                // ZIP+4
	}
}

// ============================================================================
// Control Registration — 54 controls
// ============================================================================

// registerControls registers all HIPAA Security Rule controls.
func (m *HIPAAModule) registerControls() {
	// ── Security Standards (§164.306) — 4 controls, 0 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-SS-01",
		Name:        "Ensure confidentiality, integrity, and availability of ePHI",
		Description: "§164.306(a)(1): Protect ePHI against threats to confidentiality, integrity, and availability",
		Category:    "Security Standards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCIAEPHI,
		References:  []string{"HIPAA §164.306(a)(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-SS-02",
		Name:        "Protect against anticipated threats to ePHI",
		Description: "§164.306(a)(2): Protect against any reasonably anticipated threats or hazards to security or integrity of ePHI",
		Category:    "Security Standards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThreatProtection,
		References:  []string{"HIPAA §164.306(a)(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-SS-03",
		Name:        "Protect against unauthorized use or disclosure",
		Description: "§164.306(a)(3): Protect against reasonably anticipated, inappropriate uses or disclosures of ePHI",
		Category:    "Security Standards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkUnauthorizedDisclosure,
		References:  []string{"HIPAA §164.306(a)(3)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-SS-04",
		Name:        "Ensure workforce compliance",
		Description: "§164.306(a)(4): Ensure compliance by the workforce with policies and procedures",
		Category:    "Security Standards",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HIPAA §164.306(a)(4)"},
	})

	// ── Administrative Safeguards (§164.308) — 22 controls, 9 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-01",
		Name:        "Security Management Process — Risk Analysis",
		Description: "§164.308(a)(1)(ii)(A): Conduct an accurate and thorough assessment of potential risks and vulnerabilities to ePHI confidentiality, integrity, and availability",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRiskAnalysis,
		References:  []string{"HIPAA §164.308(a)(1)(ii)(A)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-02",
		Name:        "Security Management Process — Risk Management",
		Description: "§164.308(a)(1)(ii)(B): Implement measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRiskManagement,
		References:  []string{"HIPAA §164.308(a)(1)(ii)(B)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-03",
		Name:        "Security Management Process — Sanction Policy",
		Description: "§164.308(a)(1)(ii)(C): Apply appropriate sanctions against workforce members who fail to comply with security policies and procedures",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HIPAA §164.308(a)(1)(ii)(C)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-04",
		Name:        "Security Management Process — Log-in Monitoring (Addressable)",
		Description: "§164.308(a)(1)(ii)(D): Implement procedures for monitoring log-in attempts and reporting discrepancies (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLogInMonitoring,
		References:  []string{"HIPAA §164.308(a)(1)(ii)(D)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-05",
		Name:        "Assigned Security Responsibility",
		Description: "§164.308(a)(2): Identify the security official responsible for the development and implementation of policies and procedures",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HIPAA §164.308(a)(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-06",
		Name:        "Workforce Security — Authorization (Addressable)",
		Description: "§164.308(a)(3)(ii)(A): Implement policies and procedures to ensure that all members of its workforce have appropriate access to ePHI (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HIPAA §164.308(a)(3)(ii)(A)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-07",
		Name:        "Workforce Security — Clearance (Addressable)",
		Description: "§164.308(a)(3)(ii)(B): Implement procedures to determine that access of workforce members to ePHI is appropriate (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HIPAA §164.308(a)(3)(ii)(B)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-08",
		Name:        "Workforce Security — Termination Procedures (Addressable)",
		Description: "§164.308(a)(3)(ii)(C): Implement procedures to terminate access to ePHI when workforce member employment ends (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HIPAA §164.308(a)(3)(ii)(C)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-09",
		Name:        "Information Access Management — Access Authorization (Addressable)",
		Description: "§164.308(a)(4)(ii)(A): Implement policies and procedures for granting access to ePHI (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessAuthorization,
		References:  []string{"HIPAA §164.308(a)(4)(ii)(A)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-10",
		Name:        "Information Access Management — Access Establishment/Modification (Addressable)",
		Description: "§164.308(a)(4)(ii)(B): Implement policies and procedures for establishing and modifying access to ePHI (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessModification,
		References:  []string{"HIPAA §164.308(a)(4)(ii)(B)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-11",
		Name:        "Security Awareness and Training — Security Reminders (Addressable)",
		Description: "§164.308(a)(5)(ii)(A): Implement periodic security updates and reminders (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HIPAA §164.308(a)(5)(ii)(A)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-12",
		Name:        "Security Awareness and Training — Protection from Malicious Software (Addressable)",
		Description: "§164.308(a)(5)(ii)(B): Implement policies and procedures for protection from malicious software (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMaliciousSoftware,
		References:  []string{"HIPAA §164.308(a)(5)(ii)(B)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-13",
		Name:        "Security Awareness and Training — Log-in Monitoring (Addressable)",
		Description: "§164.308(a)(5)(ii)(C): Implement procedures for monitoring log-in attempts and reporting discrepancies as part of training (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkLoginMonitoringTraining,
		References:  []string{"HIPAA §164.308(a)(5)(ii)(C)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-14",
		Name:        "Security Awareness and Training — Password Management (Addressable)",
		Description: "§164.308(a)(5)(ii)(D): Implement procedures for creating, changing, and safeguarding passwords (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPasswordManagement,
		References:  []string{"HIPAA §164.308(a)(5)(ii)(D)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-15",
		Name:        "Security Incident Procedures",
		Description: "§164.308(a)(6): Implement policies and procedures to address security incidents",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkSecurityIncident,
		References:  []string{"HIPAA §164.308(a)(6)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-16",
		Name:        "Contingency Plan — Data Backup Plan (Required)",
		Description: "§164.308(a)(7)(ii)(A): Establish and implement procedures to create and maintain retrievable exact copies of ePHI (REQUIRED)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDataBackup,
		References:  []string{"HIPAA §164.308(a)(7)(ii)(A)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-17",
		Name:        "Contingency Plan — Disaster Recovery Plan (Required)",
		Description: "§164.308(a)(7)(ii)(B): Establish and implement procedures to restore any loss of data (REQUIRED)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDisasterRecovery,
		References:  []string{"HIPAA §164.308(a)(7)(ii)(B)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-18",
		Name:        "Contingency Plan — Emergency Mode Operations (Required)",
		Description: "§164.308(a)(7)(ii)(C): Establish and implement procedures to enable continuation of critical business processes (REQUIRED)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEmergencyMode,
		References:  []string{"HIPAA §164.308(a)(7)(ii)(C)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-19",
		Name:        "Contingency Plan — Testing and Revision (Addressable)",
		Description: "§164.308(a)(7)(ii)(D): Implement procedures for periodic testing and revision of contingency plans (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkContingencyTesting,
		References:  []string{"HIPAA §164.308(a)(7)(ii)(D)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-20",
		Name:        "Contingency Plan — Applications and Data Criticality Analysis (Addressable)",
		Description: "§164.308(a)(7)(ii)(E): Assess the relative criticality of specific applications and data (ADDRESSABLE)",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCriticalityAnalysis,
		References:  []string{"HIPAA §164.308(a)(7)(ii)(E)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-21",
		Name:        "Evaluation",
		Description: "§164.308(a)(8): Perform a periodic technical and nontechnical evaluation to establish extent of security protections",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HIPAA §164.308(a)(8)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-22",
		Name:        "Business Associate Contracts",
		Description: "§164.308(b)(1): Establish contracts with business associates that satisfactorily address security requirements",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"HIPAA §164.308(b)(1)"},
	})

	// ── Physical Safeguards (§164.310) — 10 controls, 4 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-01",
		Name:        "Facility Access Controls — Contingency Operations (Addressable)",
		Description: "§164.310(a)(2)(i): Establish procedures to restore lost data due to emergency situation (ADDRESSABLE)",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HIPAA §164.310(a)(2)(i)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-02",
		Name:        "Facility Access Controls — Facility Security Plan (Addressable)",
		Description: "§164.310(a)(2)(ii): Implement policies and procedures to safeguard facility and equipment (ADDRESSABLE)",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HIPAA §164.310(a)(2)(ii)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-03",
		Name:        "Facility Access Controls — Access Control and Validation (Addressable)",
		Description: "§164.310(a)(2)(iii): Implement procedures to control and validate access to facilities (ADDRESSABLE)",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HIPAA §164.310(a)(2)(iii)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-04",
		Name:        "Facility Access Controls — Maintenance Records (Addressable)",
		Description: "§164.310(a)(2)(iv): Implement policies and procedures to document repairs and modifications to physical components (ADDRESSABLE)",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HIPAA §164.310(a)(2)(iv)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-05",
		Name:        "Workstation Use",
		Description: "§164.310(b): Implement policies specifying proper functions to be performed and manner of performance for workstations with ePHI access",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkWorkstationUse,
		References:  []string{"HIPAA §164.310(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-06",
		Name:        "Workstation Security",
		Description: "§164.310(c): Implement physical and technical safeguards for workstations with ePHI access",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkWorkstationSecurity,
		References:  []string{"HIPAA §164.310(c)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-07",
		Name:        "Device and Media Controls — Disposal (Required)",
		Description: "§164.310(d)(2)(i): Implement policies and procedures to address final disposition of ePHI and media (REQUIRED)",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMediaDisposal,
		References:  []string{"HIPAA §164.310(d)(2)(i)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-08",
		Name:        "Device and Media Controls — Media Re-use (Required)",
		Description: "§164.310(d)(2)(ii): Implement procedures for removal of ePHI from electronic media before reuse (REQUIRED)",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMediaReuse,
		References:  []string{"HIPAA §164.310(d)(2)(ii)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-09",
		Name:        "Device and Media Controls — Accountability (Addressable)",
		Description: "§164.310(d)(2)(iii): Maintain accountability for movement of media containing ePHI (ADDRESSABLE)",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HIPAA §164.310(d)(2)(iii)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-10",
		Name:        "Device and Media Controls — Data Backup and Storage (Addressable)",
		Description: "§164.310(d)(2)(iv): Create retrievable, exact copies of ePHI before moving equipment (ADDRESSABLE)",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMediaDataBackup,
		References:  []string{"HIPAA §164.310(d)(2)(iv)"},
	})

	// ── Technical Safeguards (§164.312) — 9 controls, 9 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-01",
		Name:        "Access Control — Unique User Identification (Required)",
		Description: "§164.312(a)(2)(i): Assign a unique name and/or number for identifying and tracking user identity (REQUIRED)",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkUniqueUserID,
		References:  []string{"HIPAA §164.312(a)(2)(i)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-02",
		Name:        "Access Control — Emergency Access (Required)",
		Description: "§164.312(a)(2)(ii): Establish procedures for obtaining necessary ePHI during an emergency (REQUIRED)",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEmergencyAccess,
		References:  []string{"HIPAA §164.312(a)(2)(ii)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-03",
		Name:        "Access Control — Automatic Logoff (Addressable)",
		Description: "§164.312(a)(2)(iii): Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity (ADDRESSABLE)",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAutoLogoff,
		References:  []string{"HIPAA §164.312(a)(2)(iii)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-04",
		Name:        "Access Control — Encryption and Decryption (Addressable)",
		Description: "§164.312(a)(2)(iv): Implement a mechanism to encrypt and decrypt ePHI (ADDRESSABLE)",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionDecryption,
		References:  []string{"HIPAA §164.312(a)(2)(iv)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-05",
		Name:        "Audit Controls",
		Description: "§164.312(b): Implement hardware, software, and/or procedural mechanisms that record and examine activity",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAuditControls,
		References:  []string{"HIPAA §164.312(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-06",
		Name:        "Integrity Controls",
		Description: "§164.312(c)(1): Implement policies and procedures to protect ePHI from improper alteration or destruction",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIntegrityControls,
		References:  []string{"HIPAA §164.312(c)(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-07",
		Name:        "Person or Entity Authentication",
		Description: "§164.312(d): Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAuthentication,
		References:  []string{"HIPAA §164.312(d)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-08",
		Name:        "Transmission Security — Integrity Controls (Addressable)",
		Description: "§164.312(e)(2)(i): Implement security measures to ensure electronically transmitted ePHI is not improperly modified (ADDRESSABLE)",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTransmissionIntegrity,
		References:  []string{"HIPAA §164.312(e)(2)(i)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-09",
		Name:        "Transmission Security — Encryption (Addressable)",
		Description: "§164.312(e)(2)(ii): Implement a mechanism to encrypt ePHI whenever deemed appropriate (ADDRESSABLE)",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTransmissionEncryption,
		References:  []string{"HIPAA §164.312(e)(2)(ii)"},
	})

	// ── Organizational Requirements (§164.314) — 2 controls, 0 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-OR-01",
		Name:        "Business Associate Contracts",
		Description: "§164.314(a): Establish contract terms that satisfy applicable requirements with business associates",
		Category:    "Organizational Requirements",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"HIPAA §164.314(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-OR-02",
		Name:        "Other Arrangements",
		Description: "§164.314(b): Implement terms for other arrangements when a contract is not feasible",
		Category:    "Organizational Requirements",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HIPAA §164.314(b)"},
	})

	// ── Documentation Requirements (§164.316) — 3 controls, 0 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-DR-01",
		Name:        "Documentation Requirements",
		Description: "§164.316(a): Maintain policies and procedures implemented to comply with this subpart in written or electronic form",
		Category:    "Documentation Requirements",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDocumentationRequirements,
		References:  []string{"HIPAA §164.316(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-DR-02",
		Name:        "Implementation Specifications",
		Description: "§164.316(b)(1): Implement implementation specifications as written and maintained documentation",
		Category:    "Documentation Requirements",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkImplementationSpecs,
		References:  []string{"HIPAA §164.316(b)(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-DR-03",
		Name:        "Documentation Maintenance",
		Description: "§164.316(b)(2): Maintain documentation for a minimum of 6 years from creation or last effective date",
		Category:    "Documentation Requirements",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDocumentationMaintenance,
		References:  []string{"HIPAA §164.316(b)(2)"},
	})

	// ── AI Controls — 2 controls, 2 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AI-01",
		Name:        "AI Model PHI Protection",
		Description: "Ensure AI models do not retain or expose Protected Health Information through model inference or training",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIPHIProtection,
		References:  []string{"HIPAA §164.316(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AI-02",
		Name:        "AI Training Data Sanitization",
		Description: "Verify AI training data has been properly de-identified per HIPAA Safe Harbor or Expert Determination methods",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAITrainingData,
		References:  []string{"HIPAA §164.316(a)"},
	})

	// ── Breach Notification Rule — 2 controls, 0 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-BN-01",
		Name:        "Breach Notification — Risk Assessment",
		Description: "§164.402: Perform a risk assessment to determine if an impermissible use or disclosure constitutes a breach",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBreachRiskAssessment,
		References:  []string{"HIPAA §164.402"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-BN-02",
		Name:        "Breach Notification — Individual Notification",
		Description: "§164.404: Notify affected individuals of a breach of unsecured PHI without unreasonable delay and no later than 60 days",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBreachIndividualNotification,
		References:  []string{"HIPAA §164.404"},
	})
}

// ============================================================================
// Check Implementations — 23 automated controls
// ============================================================================

// --- Administrative Safeguards ---

func (m *HIPAAModule) checkRiskAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"risk_analysis", "risk_assessment"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-01",
			ControlName: "Security Management Process — Risk Analysis",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Risk analysis and assessment procedures detected",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-01",
			ControlName: "Security Management Process — Risk Analysis",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial risk analysis controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive risk analysis and risk assessment procedures per §164.308(a)(1)(ii)(A)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-01",
			ControlName: "Security Management Process — Risk Analysis",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No risk analysis procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Conduct an accurate and thorough assessment of potential risks and vulnerabilities to ePHI per §164.308(a)(1)(ii)(A)",
		}, nil
	}
}

func (m *HIPAAModule) checkRiskManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"risk_management", "risk_treatment", "risk_mitigation"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-02",
			ControlName: "Security Management Process — Risk Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Risk management, treatment, and mitigation measures detected",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-02",
			ControlName: "Security Management Process — Risk Management",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial risk management measures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive risk management, treatment, and mitigation procedures per §164.308(a)(1)(ii)(B)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-02",
			ControlName: "Security Management Process — Risk Management",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No risk management measures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level per §164.308(a)(1)(ii)(B)",
		}, nil
	}
}

// checkLogInMonitoring verifies log-in monitoring (addressable).
// Maps to HIPAA §164.308(a)(1)(ii)(D).
func (m *HIPAAModule) checkLogInMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled")
	hasLogInTracking := strings.Contains(inputStr, "login_tracking") || strings.Contains(inputStr, "log_in_tracking") || strings.Contains(inputStr, "auth_log")
	hasAnomalyDetection := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "trust_score")
	hasReporting := strings.Contains(inputStr, "reporting") || strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "log_in_reporting")

	present := 0
	missing := []string{}
	if hasAuditLog {
		present++
	} else {
		missing = append(missing, "audit log")
	}
	if hasLogInTracking {
		present++
	} else {
		missing = append(missing, "login_tracking")
	}
	if hasAnomalyDetection {
		present++
	} else {
		missing = append(missing, "anomaly detection")
	}
	if hasReporting {
		present++
	} else {
		missing = append(missing, "alerting/reporting")
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-04",
			ControlName: "Security Management Process — Log-in Monitoring (Addressable)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Log-in monitoring verified: audit log + login tracking + anomaly detection + alerting",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-04",
			ControlName: "Security Management Process — Log-in Monitoring (Addressable)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No log-in monitoring configured",
			Timestamp:   time.Now(),
			Remediation: "Enable audit log + login_tracking + anomaly detection + alerting per §164.308(a)(1)(ii)(D)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-AS-04",
		ControlName: "Security Management Process — Log-in Monitoring (Addressable)",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityHigh,
		Message:     "Partial log-in monitoring: " + hipaaCount(present) + "/4 configured; missing: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable the missing log-in monitoring components",
	}, nil
}

func (m *HIPAAModule) checkMaliciousSoftware(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"antivirus", "anti-malware", "malware_protection", "endpoint_protection"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-12",
			ControlName: "Security Awareness and Training — Protection from Malicious Software (Addressable)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "All malicious software protection measures detected",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-12",
			ControlName: "Security Awareness and Training — Protection from Malicious Software (Addressable)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial malicious software protection detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive antivirus, anti-malware, and endpoint protection per §164.308(a)(5)(ii)(B)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-12",
			ControlName: "Security Awareness and Training — Protection from Malicious Software (Addressable)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No malicious software protection detected",
			Timestamp:   time.Now(),
			Remediation: "Implement antivirus, anti-malware, malware_protection, and endpoint_protection per §164.308(a)(5)(ii)(B)",
		}, nil
	}
}

func (m *HIPAAModule) checkPasswordManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"password_policy", "password_complexity", "password_rotation", "password_management"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-14",
			ControlName: "Security Awareness and Training — Password Management (Addressable)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "All password management procedures detected",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-14",
			ControlName: "Security Awareness and Training — Password Management (Addressable)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial password management procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive password policy, complexity, rotation, and management per §164.308(a)(5)(ii)(D)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-14",
			ControlName: "Security Awareness and Training — Password Management (Addressable)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No password management procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement password_policy, password_complexity, password_rotation, and password_management per §164.308(a)(5)(ii)(D)",
		}, nil
	}
}

func (m *HIPAAModule) checkSecurityIncident(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"incident_response", "incident_procedure", "incident_handling"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-15",
			ControlName: "Security Incident Procedures",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Security incident procedures fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-15",
			ControlName: "Security Incident Procedures",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial security incident procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive incident response, procedures, and handling per §164.308(a)(6)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-15",
			ControlName: "Security Incident Procedures",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No security incident procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement incident_response, incident_procedure, and incident_handling per §164.308(a)(6)",
		}, nil
	}
}

func (m *HIPAAModule) checkDataBackup(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"backup_plan", "data_backup", "backup_strategy"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-16",
			ControlName: "Contingency Plan — Data Backup Plan (Required)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data backup plan fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-16",
			ControlName: "Contingency Plan — Data Backup Plan (Required)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial data backup plan detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive backup plan, data backup, and backup strategy per §164.308(a)(7)(ii)(A)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-16",
			ControlName: "Contingency Plan — Data Backup Plan (Required)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No data backup plan detected",
			Timestamp:   time.Now(),
			Remediation: "Establish and implement procedures to create and maintain retrievable exact copies of ePHI per §164.308(a)(7)(ii)(A)",
		}, nil
	}
}

func (m *HIPAAModule) checkDisasterRecovery(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"disaster_recovery", "recovery_plan", "dr_plan"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-17",
			ControlName: "Contingency Plan — Disaster Recovery Plan (Required)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Disaster recovery plan fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-17",
			ControlName: "Contingency Plan — Disaster Recovery Plan (Required)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial disaster recovery plan detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive disaster recovery, recovery plan, and DR plan per §164.308(a)(7)(ii)(B)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-17",
			ControlName: "Contingency Plan — Disaster Recovery Plan (Required)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No disaster recovery plan detected",
			Timestamp:   time.Now(),
			Remediation: "Establish and implement procedures to restore any loss of data per §164.308(a)(7)(ii)(B)",
		}, nil
	}
}

func (m *HIPAAModule) checkEmergencyMode(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"emergency_mode", "emergency_operations", "business_continuity"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-18",
			ControlName: "Contingency Plan — Emergency Mode Operations (Required)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Emergency mode operations fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-18",
			ControlName: "Contingency Plan — Emergency Mode Operations (Required)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial emergency mode operations detected",
			Timestamp:   time.Now(),
			Remediation: "Implement emergency mode, emergency operations, and business continuity per §164.308(a)(7)(ii)(C)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-18",
			ControlName: "Contingency Plan — Emergency Mode Operations (Required)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No emergency mode operations detected",
			Timestamp:   time.Now(),
			Remediation: "Establish and implement procedures to enable continuation of critical business processes per §164.308(a)(7)(ii)(C)",
		}, nil
	}
}

func (m *HIPAAModule) checkContingencyTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"contingency_test", "disaster_recovery_test", "failover_test"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-19",
			ControlName: "Contingency Plan — Testing and Revision (Addressable)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Contingency testing and revision procedures fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-19",
			ControlName: "Contingency Plan — Testing and Revision (Addressable)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial contingency testing procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement contingency test, disaster recovery test, and failover test per §164.308(a)(7)(ii)(D)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-19",
			ControlName: "Contingency Plan — Testing and Revision (Addressable)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No contingency testing procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement procedures for periodic testing and revision of contingency plans per §164.308(a)(7)(ii)(D)",
		}, nil
	}
}

// --- Physical Safeguards ---

func (m *HIPAAModule) checkWorkstationUse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"workstation_use", "workstation_policy", "workstation_standard"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-05",
			ControlName: "Workstation Use",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Workstation use policies fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-05",
			ControlName: "Workstation Use",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial workstation use policies detected",
			Timestamp:   time.Now(),
			Remediation: "Implement workstation use, workstation policy, and workstation standard per §164.310(b)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-05",
			ControlName: "Workstation Use",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No workstation use policies detected",
			Timestamp:   time.Now(),
			Remediation: "Implement policies specifying proper functions to be performed and manner of performance for workstations per §164.310(b)",
		}, nil
	}
}

func (m *HIPAAModule) checkWorkstationSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"workstation_security", "workstation_lock", "screen_lock", "workstation_restriction"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-06",
			ControlName: "Workstation Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Workstation security safeguards fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-06",
			ControlName: "Workstation Security",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial workstation security safeguards detected",
			Timestamp:   time.Now(),
			Remediation: "Implement workstation security, workstation lock, screen lock, and workstation restriction per §164.310(c)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-06",
			ControlName: "Workstation Security",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No workstation security safeguards detected",
			Timestamp:   time.Now(),
			Remediation: "Implement physical and technical safeguards for workstations with ePHI access per §164.310(c)",
		}, nil
	}
}

func (m *HIPAAModule) checkMediaDisposal(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"media_disposal", "data_destruction", "sanitization", "secure_disposal"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-07",
			ControlName: "Device and Media Controls — Disposal (Required)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Media disposal procedures fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-07",
			ControlName: "Device and Media Controls — Disposal (Required)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial media disposal procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement media disposal, data destruction, sanitization, and secure disposal per §164.310(d)(2)(i)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-07",
			ControlName: "Device and Media Controls — Disposal (Required)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No media disposal procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement policies and procedures to address final disposition of ePHI and media per §164.310(d)(2)(i)",
		}, nil
	}
}

func (m *HIPAAModule) checkMediaReuse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"media_reuse", "media_sanitization", "wipe_media"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-08",
			ControlName: "Device and Media Controls — Media Re-use (Required)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Media re-use sanitization procedures fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-08",
			ControlName: "Device and Media Controls — Media Re-use (Required)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial media re-use procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement media reuse, media sanitization, and wipe media per §164.310(d)(2)(ii)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-PS-08",
			ControlName: "Device and Media Controls — Media Re-use (Required)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No media re-use sanitization procedures detected",
			Timestamp:   time.Now(),
			Remediation: "Implement procedures for removal of ePHI from electronic media before reuse per §164.310(d)(2)(ii)",
		}, nil
	}
}

// --- Technical Safeguards ---

func (m *HIPAAModule) checkUniqueUserID(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"unique_user_id", "unique_identification", "user_identification"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-01",
			ControlName: "Access Control — Unique User Identification (Required)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Unique user identification fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-01",
			ControlName: "Access Control — Unique User Identification (Required)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial unique user identification detected",
			Timestamp:   time.Now(),
			Remediation: "Implement unique user ID, unique identification, and user identification per §164.312(a)(2)(i)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-01",
			ControlName: "Access Control — Unique User Identification (Required)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No unique user identification detected",
			Timestamp:   time.Now(),
			Remediation: "Assign a unique name and/or number for identifying and tracking user identity per §164.312(a)(2)(i)",
		}, nil
	}
}

func (m *HIPAAModule) checkAutoLogoff(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"auto_logoff", "session_timeout", "idle_timeout", "automatic_logoff"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-03",
			ControlName: "Access Control — Automatic Logoff (Addressable)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Automatic logoff fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-03",
			ControlName: "Access Control — Automatic Logoff (Addressable)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial automatic logoff detected",
			Timestamp:   time.Now(),
			Remediation: "Implement auto logoff, session timeout, idle timeout, and automatic logoff per §164.312(a)(2)(iii)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-03",
			ControlName: "Access Control — Automatic Logoff (Addressable)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "No automatic logoff detected",
			Timestamp:   time.Now(),
			Remediation: "Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity per §164.312(a)(2)(iii)",
		}, nil
	}
}

func (m *HIPAAModule) checkEncryptionDecryption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"encryption", "decryption", "aes", "encrypt"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-04",
			ControlName: "Access Control — Encryption and Decryption (Addressable)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Encryption and decryption mechanisms fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-04",
			ControlName: "Access Control — Encryption and Decryption (Addressable)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial encryption and decryption mechanisms detected",
			Timestamp:   time.Now(),
			Remediation: "Implement encryption, decryption, AES, and encrypt mechanisms per §164.312(a)(2)(iv)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-04",
			ControlName: "Access Control — Encryption and Decryption (Addressable)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No encryption and decryption mechanisms detected",
			Timestamp:   time.Now(),
			Remediation: "Implement a mechanism to encrypt and decrypt ePHI per §164.312(a)(2)(iv)",
		}, nil
	}
}

func (m *HIPAAModule) checkAuditControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled")
	hasIntegrity := strings.Contains(inputStr, "log_integrity") || strings.Contains(inputStr, "signed_logs")

	if hasAudit && hasIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-05",
			ControlName: "Audit Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Audit logging with integrity verification detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-TS-05",
		ControlName: "Audit Controls",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityCritical,
		Message:     "Audit controls require enhancement",
		Timestamp:   time.Now(),
		Remediation: "Enable comprehensive audit logging with integrity verification per §164.312(b)",
	}, nil
}

func (m *HIPAAModule) checkIntegrityControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHashing := strings.Contains(inputStr, "hash") || strings.Contains(inputStr, "checksum")
	hasSigning := strings.Contains(inputStr, "sign") || strings.Contains(inputStr, "signature")

	if hasHashing || hasSigning {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-06",
			ControlName: "Integrity Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data integrity mechanism detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-TS-06",
		ControlName: "Integrity Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No data integrity controls detected",
		Timestamp:   time.Now(),
		Remediation: "Implement hashing or digital signatures for data integrity per §164.312(c)(1)",
	}, nil
}

func (m *HIPAAModule) checkAuthentication(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"authentication", "auth_method", "mfa", "multi_factor"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-07",
			ControlName: "Person or Entity Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Authentication mechanisms fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-07",
			ControlName: "Person or Entity Authentication",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial authentication mechanisms detected",
			Timestamp:   time.Now(),
			Remediation: "Implement authentication, auth method, MFA, and multi-factor per §164.312(d)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-07",
			ControlName: "Person or Entity Authentication",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No authentication mechanisms detected",
			Timestamp:   time.Now(),
			Remediation: "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed per §164.312(d)",
		}, nil
	}
}

func (m *HIPAAModule) checkTransmissionIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	keywords := []string{"tls", "integrity_check", "transmission_integrity", "hmac"}
	found := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			found++
		}
	}
	switch {
	case found == len(keywords):
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-08",
			ControlName: "Transmission Security — Integrity Controls (Addressable)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Transmission integrity controls fully implemented",
			Timestamp:   time.Now(),
		}, nil
	case found > 0:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-08",
			ControlName: "Transmission Security — Integrity Controls (Addressable)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial transmission integrity controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement TLS, integrity check, transmission integrity, and HMAC per §164.312(e)(2)(i)",
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-08",
			ControlName: "Transmission Security — Integrity Controls (Addressable)",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No transmission integrity controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement security measures to ensure electronically transmitted ePHI is not improperly modified per §164.312(e)(2)(i)",
		}, nil
	}
}

func (m *HIPAAModule) checkTransmissionEncryption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")
	hasTLS13 := strings.Contains(inputStr, "tls1.3") || strings.Contains(inputStr, "tls_13")
	hasSSL := strings.Contains(inputStr, "ssl")

	if hasTLS13 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-09",
			ControlName: "Transmission Security — Encryption (Addressable)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS 1.3 enabled for transmission encryption",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS || hasSSL {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-09",
			ControlName: "Transmission Security — Encryption (Addressable)",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS/SSL detected but not TLS 1.3",
			Timestamp:   time.Now(),
			Remediation: "Upgrade to TLS 1.3 for maximum transmission security per §164.312(e)(2)(ii)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-TS-09",
		ControlName: "Transmission Security — Encryption (Addressable)",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No TLS encryption detected",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.3 for all data transmission per §164.312(e)(2)(ii)",
	}, nil
}

// --- AI Controls ---

func (m *HIPAAModule) checkAIPHIProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	phiFound := m.detectPHI(string(input))

	if len(phiFound) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AI-01",
			ControlName: "AI Model PHI Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No PHI detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-AI-01",
		ControlName: "AI Model PHI Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "PHI patterns detected in AI model data",
		Details:     "Detected patterns in input data",
		Timestamp:   time.Now(),
		Remediation: "Implement PHI scrubbing for all AI model inputs and outputs",
	}, nil
}

func (m *HIPAAModule) checkAITrainingData(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDeID := strings.Contains(inputStr, "de_identified") || strings.Contains(inputStr, "anonymized")
	phiFound := m.detectPHI(inputStr)

	if hasDeID && len(phiFound) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AI-02",
			ControlName: "AI Training Data Sanitization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Training data properly de-identified",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-AI-02",
		ControlName: "AI Training Data Sanitization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Training data may contain identifiable PHI",
		Timestamp:   time.Now(),
		Remediation: "Apply HIPAA Safe Harbor or Expert Determination de-identification methods",
	}, nil
}

// ── P1 Compliance Automation Expansion: Additional automated controls ──

func (m *HIPAAModule) checkCIAEPHI(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasConfidentiality := strings.Contains(s, "encrypt") || strings.Contains(s, "access_control")
	hasIntegrity := strings.Contains(s, "integrity") || strings.Contains(s, "hash") || strings.Contains(s, "checksum")
	hasAvailability := strings.Contains(s, "backup") || strings.Contains(s, "redundancy") || strings.Contains(s, "disaster_recovery")
	score := 0
	if hasConfidentiality {
		score++
	}
	if hasIntegrity {
		score++
	}
	if hasAvailability {
		score++
	}
	if score == 3 {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-SS-01", ControlName: "Ensure confidentiality, integrity, and availability of ePHI", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Confidentiality, integrity, and availability measures all detected", Timestamp: time.Now(), References: []string{"HIPAA §164.306(a)(1)"}}, nil
	}
	if score > 0 {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-SS-01", ControlName: "Ensure confidentiality, integrity, and availability of ePHI", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Partial CIA measures detected (" + hipaaCount(score) + "/3)", Timestamp: time.Now(), References: []string{"HIPAA §164.306(a)(1)"}, Remediation: "Implement all three: encryption/access control (confidentiality), integrity controls, and backup/recovery (availability)"}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-SS-01", ControlName: "Ensure confidentiality, integrity, and availability of ePHI", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "No CIA measures detected", Timestamp: time.Now(), References: []string{"HIPAA §164.306(a)(1)"}, Remediation: "Implement encryption, access control, integrity controls, and backup/recovery"}, nil
}

func (m *HIPAAModule) checkThreatProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasThreatProtection := strings.Contains(s, "threat_detection") || strings.Contains(s, "intrusion_detection") || strings.Contains(s, "ids") || strings.Contains(s, "ips") || strings.Contains(s, "malware_detection") || strings.Contains(s, "antivirus")
	if hasThreatProtection {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-SS-02", ControlName: "Protect against anticipated threats to ePHI", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Threat protection measures detected", Timestamp: time.Now(), References: []string{"HIPAA §164.306(a)(2)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-SS-02", ControlName: "Protect against anticipated threats to ePHI", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Threat protection indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.306(a)(2)"}, Remediation: "Implement threat detection and intrusion prevention systems"}, nil
}

func (m *HIPAAModule) checkUnauthorizedDisclosure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAccessControl := strings.Contains(s, "access_control") || strings.Contains(s, "rbac")
	hasAuditLog := strings.Contains(s, "audit_log") || strings.Contains(s, "audit_trail") || strings.Contains(s, "logging_enabled")
	if hasAccessControl && hasAuditLog {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-SS-03", ControlName: "Protect against unauthorized use or disclosure", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Access control and audit logging detected for unauthorized disclosure prevention", Timestamp: time.Now(), References: []string{"HIPAA §164.306(a)(3)"}}, nil
	}
	if hasAccessControl || hasAuditLog {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-SS-03", ControlName: "Protect against unauthorized use or disclosure", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Partial unauthorized disclosure prevention detected", Timestamp: time.Now(), References: []string{"HIPAA §164.306(a)(3)"}, Remediation: "Implement both access control and audit logging"}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-SS-03", ControlName: "Protect against unauthorized use or disclosure", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "No unauthorized disclosure prevention detected", Timestamp: time.Now(), References: []string{"HIPAA §164.306(a)(3)"}, Remediation: "Implement access control and audit logging"}, nil
}

func (m *HIPAAModule) checkAccessAuthorization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAccessAuth := strings.Contains(s, "access_authorization") || strings.Contains(s, "role_assignment") || strings.Contains(s, "rbac") || strings.Contains(s, "access_grant")
	if hasAccessAuth {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-AS-09", ControlName: "Information Access Management — Access Authorization", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Access authorization controls detected", Timestamp: time.Now(), References: []string{"HIPAA §164.308(a)(4)(ii)(A)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-AS-09", ControlName: "Information Access Management — Access Authorization", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Access authorization indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.308(a)(4)(ii)(A)"}, Remediation: "Implement role-based access authorization for ePHI"}, nil
}

func (m *HIPAAModule) checkAccessModification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAccessMod := strings.Contains(s, "access_modification") || strings.Contains(s, "role_modification") || strings.Contains(s, "access_management") || strings.Contains(s, "access_review")
	if hasAccessMod {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-AS-10", ControlName: "Information Access Management — Access Establishment/Modification", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Access establishment and modification controls detected", Timestamp: time.Now(), References: []string{"HIPAA §164.308(a)(4)(ii)(B)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-AS-10", ControlName: "Information Access Management — Access Establishment/Modification", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Access modification indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.308(a)(4)(ii)(B)"}, Remediation: "Implement procedures for establishing and modifying ePHI access"}, nil
}

func (m *HIPAAModule) checkLoginMonitoringTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasLoginMonitoring := strings.Contains(s, "login_monitoring") || strings.Contains(s, "session_tracking") || strings.Contains(s, "log_monitoring") || strings.Contains(s, "login_attempt")
	if hasLoginMonitoring {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-AS-13", ControlName: "Security Awareness and Training — Log-in Monitoring", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Log-in monitoring procedures detected", Timestamp: time.Now(), References: []string{"HIPAA §164.308(a)(5)(ii)(C)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-AS-13", ControlName: "Security Awareness and Training — Log-in Monitoring", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Log-in monitoring indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.308(a)(5)(ii)(C)"}, Remediation: "Implement log-in monitoring and reporting procedures"}, nil
}

func (m *HIPAAModule) checkCriticalityAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasCriticality := strings.Contains(s, "criticality_analysis") || strings.Contains(s, "data_classification") || strings.Contains(s, "application_criticality") || strings.Contains(s, "asset_criticality")
	if hasCriticality {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-AS-20", ControlName: "Contingency Plan — Applications and Data Criticality Analysis", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Application and data criticality analysis detected", Timestamp: time.Now(), References: []string{"HIPAA §164.308(a)(7)(ii)(E)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-AS-20", ControlName: "Contingency Plan — Applications and Data Criticality Analysis", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Criticality analysis indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.308(a)(7)(ii)(E)"}, Remediation: "Perform criticality analysis of applications and data containing ePHI"}, nil
}

func (m *HIPAAModule) checkMediaDataBackup(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasMediaBackup := strings.Contains(s, "media_backup") || strings.Contains(s, "data_backup") || strings.Contains(s, "equipment_backup") || strings.Contains(s, "backup_before_move")
	if hasMediaBackup {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-PS-10", ControlName: "Device and Media Controls — Data Backup and Storage", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Media data backup controls detected", Timestamp: time.Now(), References: []string{"HIPAA §164.310(d)(2)(iv)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-PS-10", ControlName: "Device and Media Controls — Data Backup and Storage", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Media data backup indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.310(d)(2)(iv)"}, Remediation: "Implement data backup procedures before moving equipment containing ePHI"}, nil
}

func (m *HIPAAModule) checkEmergencyAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasEmergencyAccess := strings.Contains(s, "emergency_access") || strings.Contains(s, "break_glass") || strings.Contains(s, "emergency_override") || strings.Contains(s, "crisis_access")
	if hasEmergencyAccess {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-TS-02", ControlName: "Access Control — Emergency Access", Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical, Message: "Emergency access procedures detected", Timestamp: time.Now(), References: []string{"HIPAA §164.312(a)(2)(ii)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-TS-02", ControlName: "Access Control — Emergency Access", Status: compliance.StatusPartial, Severity: compliance.SeverityCritical, Message: "Emergency access indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.312(a)(2)(ii)"}, Remediation: "Implement break-glass or emergency access procedures for ePHI during emergencies"}, nil
}

func (m *HIPAAModule) checkDocumentationRequirements(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasDocumentation := strings.Contains(s, "policy_documentation") || strings.Contains(s, "documentation") || strings.Contains(s, "policy_management") || strings.Contains(s, "procedure_documentation")
	if hasDocumentation {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-DR-01", ControlName: "Documentation Requirements", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Policy and procedure documentation detected", Timestamp: time.Now(), References: []string{"HIPAA §164.316(a)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-DR-01", ControlName: "Documentation Requirements", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Documentation indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.316(a)"}, Remediation: "Maintain policies and procedures in written or electronic form"}, nil
}

func (m *HIPAAModule) checkImplementationSpecs(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasImplSpecs := strings.Contains(s, "implementation_spec") || strings.Contains(s, "config_documentation") || strings.Contains(s, "implementation_documentation") || strings.Contains(s, "specification_documentation")
	if hasImplSpecs {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-DR-02", ControlName: "Implementation Specifications", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Implementation specification documentation detected", Timestamp: time.Now(), References: []string{"HIPAA §164.316(b)(1)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-DR-02", ControlName: "Implementation Specifications", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Implementation specification indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.316(b)(1)"}, Remediation: "Document implementation specifications in written or electronic form"}, nil
}

func (m *HIPAAModule) checkDocumentationMaintenance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasDocMaintenance := strings.Contains(s, "document_retention") || strings.Contains(s, "retention_policy") || strings.Contains(s, "documentation_retention") || strings.Contains(s, "retention_period")
	if hasDocMaintenance {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-DR-03", ControlName: "Documentation Maintenance", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Documentation retention and maintenance controls detected", Timestamp: time.Now(), References: []string{"HIPAA §164.316(b)(2)"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-DR-03", ControlName: "Documentation Maintenance", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Documentation retention indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.316(b)(2)"}, Remediation: "Maintain documentation for minimum 6 years from creation or last effective date"}, nil
}

func (m *HIPAAModule) checkBreachRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasBreachAssessment := strings.Contains(s, "breach_risk_assessment") || strings.Contains(s, "breach_analysis") || strings.Contains(s, "breach_assessment") || strings.Contains(s, "risk_assessment_breach")
	if hasBreachAssessment {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-BN-01", ControlName: "Breach Notification — Risk Assessment", Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical, Message: "Breach risk assessment procedures detected", Timestamp: time.Now(), References: []string{"HIPAA §164.402"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-BN-01", ControlName: "Breach Notification — Risk Assessment", Status: compliance.StatusPartial, Severity: compliance.SeverityCritical, Message: "Breach risk assessment indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.402"}, Remediation: "Implement breach risk assessment procedures"}, nil
}

func (m *HIPAAModule) checkBreachIndividualNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasIndividualNotif := strings.Contains(s, "individual_notification") || strings.Contains(s, "breach_notification") || strings.Contains(s, "affected_individual_notification") || strings.Contains(s, "breach_notice")
	if hasIndividualNotif {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-BN-02", ControlName: "Breach Notification — Individual Notification", Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical, Message: "Individual breach notification procedures detected", Timestamp: time.Now(), References: []string{"HIPAA §164.404"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HIPAA-BN-02", ControlName: "Breach Notification — Individual Notification", Status: compliance.StatusPartial, Severity: compliance.SeverityCritical, Message: "Individual notification indicators not detected", Timestamp: time.Now(), References: []string{"HIPAA §164.404"}, Remediation: "Implement procedures to notify affected individuals within 60 days of breach discovery"}, nil
}

// ============================================================================
// Helpers
// ============================================================================

// hipaaCount is a small helper to avoid importing strconv in every check.
func hipaaCount(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 0 {
		return "-hipaaCount(-n)"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// detectPHI scans input for potential PHI patterns.
func (m *HIPAAModule) detectPHI(input string) []string {
	found := []string{}
	for _, pattern := range m.phiPatterns {
		if pattern.MatchString(input) {
			found = append(found, pattern.String())
		}
	}
	return found
}

// Dependencies returns required modules.
func (m *HIPAAModule) Dependencies() []string {
	return []string{"scanner"}
}
