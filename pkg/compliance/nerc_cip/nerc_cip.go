// Package nerc_cip implements NERC CIP (Critical Infrastructure Protection) compliance
// controls for the AegisGate platform. NERC CIP standards (CIP-002 through CIP-014)
// establish cybersecurity requirements for Bulk Electric System (BES) Cyber Systems
// to ensure the reliable operation of the North American electric grid.
package nerc_cip

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// NERCCIPModule implements compliance checking for NERC CIP standards.
type NERCCIPModule struct {
	*compliance.BaseComplianceModule
	nercPatterns []*regexp.Regexp
}

// NewNERCCIPModule creates a new NERC CIP compliance module.
func NewNERCCIPModule() *NERCCIPModule {
	m := &NERCCIPModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("nerc_cip", "6", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns initializes regex patterns for BES (Bulk Electric System) data detection.
func (m *NERCCIPModule) initPatterns() {
	m.nercPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b\d{3}-\d{2}-\d{4}\b`),         // SSN pattern
		regexp.MustCompile(`(?i)\bscada\b`),                     // SCADA systems
		regexp.MustCompile(`(?i)\bbes\b.*\bcyber\b`),            // BES cyber references
		regexp.MustCompile(`(?i)\bgrid\b.*\bcontrol\b`),         // Grid control systems
		regexp.MustCompile(`(?i)\bsubstation\b`),                // Substation references
		regexp.MustCompile(`(?i)\bnerc\b`),                      // NERC references
		regexp.MustCompile(`(?i)\bcip[-_]\d{3}\b`),              // CIP-XXX standard refs
		regexp.MustCompile(`(?i)\bbulk\s+electric\b`),           // Bulk electric system
		regexp.MustCompile(`(?i)\btransmission\s+operator\b`),   // Transmission operator
		regexp.MustCompile(`(?i)\breliability\s+coordinator\b`), // Reliability coordinator
	}
}

// detectBESData checks if input contains Bulk Electric System data patterns.
func (m *NERCCIPModule) detectBESData(input string) bool {
	lower := strings.ToLower(input)
	for _, pattern := range m.nercPatterns {
		if pattern.MatchString(lower) {
			return true
		}
	}
	return false
}

// registerControls registers all NERC CIP compliance controls.
func (m *NERCCIPModule) registerControls() {
	// =========================================================
	// Cyber System Categorization (CS) — 5 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CS-01",
		Name:        "BES Cyber System Categorization",
		Description: "Identify and categorize BES Cyber Systems according to their impact rating (high, medium, low) as required by CIP-002",
		Category:    "Cyber System Categorization",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBESCyberSystemCategorization,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CS-02",
		Name:        "Impact Rating Assignment",
		Description: "Assign impact ratings to BES Cyber Systems based on their potential impact on the reliable operation of the Bulk Electric System",
		Category:    "Cyber System Categorization",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkImpactRatingAssignment,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CS-03",
		Name:        "BES Cyber Asset Inventory",
		Description: "Maintain a comprehensive inventory of all BES Cyber Assets including asset identification, classification, and ownership per CIP-002",
		Category:    "Cyber System Categorization",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBESCyberAssetInventory,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CS-04",
		Name:        "Cyber System Boundary Definition",
		Description: "Define and document the logical and physical boundaries of BES Cyber Systems to identify all interconnected assets and interfaces per CIP-002",
		Category:    "Cyber System Categorization",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CS-05",
		Name:        "Categorization Documentation Review",
		Description: "Review and update BES Cyber System categorization documentation at least annually or when system changes occur per CIP-002",
		Category:    "Cyber System Categorization",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================
	// Security Management (SM) — 4 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SM-01",
		Name:        "Security Management Controls",
		Description: "Implement and document cyber security policies consistent with CIP-003 requirements for medium and high impact BES Cyber Systems",
		Category:    "Security Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityManagementControls,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SM-02",
		Name:        "Cyber Security Policy Approval",
		Description: "Obtain senior management or board approval for cyber security policies and document the approval process per CIP-003",
		Category:    "Security Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCyberSecurityPolicyApproval,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SM-03",
		Name:        "Security Program Review",
		Description: "Conduct at least annual reviews of the cyber security program to ensure continued effectiveness and alignment with organizational objectives per CIP-003",
		Category:    "Security Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SM-04",
		Name:        "Exception Management Process",
		Description: "Establish and document a process for requesting, approving, and tracking exceptions to cyber security requirements per CIP-003",
		Category:    "Security Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================
	// Personnel & Training (PT) — 5 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PT-01",
		Name:        "Personnel Risk Assessment",
		Description: "Conduct personnel risk assessments including background checks for personnel with cyber access to BES Cyber Systems per CIP-004",
		Category:    "Personnel & Training",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPersonnelRiskAssessment,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PT-02",
		Name:        "Cyber Security Training",
		Description: "Implement and maintain cyber security awareness and training programs for personnel with access to BES Cyber Systems",
		Category:    "Personnel & Training",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCyberSecurityTraining,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PT-03",
		Name:        "Access Management Program",
		Description: "Implement an access management program defining roles, responsibilities, and procedures for granting and revoking cyber access to BES Cyber Systems per CIP-004",
		Category:    "Personnel & Training",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessManagementProgram,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PT-04",
		Name:        "Personnel Termination Procedures",
		Description: "Establish procedures for removing cyber and physical access upon personnel termination or role change within one business day per CIP-004",
		Category:    "Personnel & Training",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PT-05",
		Name:        "Training Records Retention",
		Description: "Maintain records of cyber security training completion for personnel with access to BES Cyber Systems for the duration of access plus a defined retention period per CIP-004",
		Category:    "Personnel & Training",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================
	// Electronic Security (EP) — 5 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-EP-01",
		Name:        "Electronic Security Perimeter",
		Description: "Define and implement Electronic Security Perimeters (ESPs) for BES Cyber Systems with all access points identified and monitored per CIP-005",
		Category:    "Electronic Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkElectronicSecurityPerimeter,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-EP-02",
		Name:        "Electronic Access Monitoring",
		Description: "Monitor and log all electronic access within Electronic Security Perimeters including intrusion detection and access logging per CIP-005",
		Category:    "Electronic Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkElectronicAccessMonitoring,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-EP-03",
		Name:        "Network Security Architecture",
		Description: "Implement network security architecture controls including firewall rules, network segmentation, and traffic filtering for BES Cyber System networks per CIP-005",
		Category:    "Electronic Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkSecurityArchitecture,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-EP-04",
		Name:        "Intrusion Detection System",
		Description: "Deploy and maintain intrusion detection or prevention systems monitoring the Electronic Security Perimeter for unauthorized access attempts per CIP-005",
		Category:    "Electronic Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIntrusionDetection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-EP-05",
		Name:        "Dial-up Access Management",
		Description: "Implement controls for dial-up connectivity to BES Cyber Systems including authentication, encryption, and activity logging per CIP-005",
		Category:    "Electronic Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================
	// Physical Security (PS) — 5 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PS-01",
		Name:        "Physical Security Perimeter",
		Description: "Define and maintain Physical Security Perimeters for BES Cyber Systems with appropriate access controls per CIP-006",
		Category:    "Physical Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPhysicalSecurityPerimeter,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PS-02",
		Name:        "Transmission Station Security",
		Description: "Conduct physical security threat assessments and implement security measures for transmission stations and substations per CIP-014",
		Category:    "Physical Security",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PS-03",
		Name:        "Physical Access Control Systems",
		Description: "Implement physical access control systems including badges, biometrics, or other authentication methods for all physical access points to BES Cyber Systems per CIP-006",
		Category:    "Physical Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPhysicalAccessControlSystems,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PS-04",
		Name:        "Visitor Access Management",
		Description: "Implement visitor access management procedures including escort requirements, logging, and access authorization for all visitors to Physical Security Perimeters per CIP-006",
		Category:    "Physical Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkVisitorAccessManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PS-05",
		Name:        "Physical Security Monitoring",
		Description: "Implement continuous physical security monitoring including CCTV, alarm systems, and guard patrols for Physical Security Perimeters containing BES Cyber Systems per CIP-006",
		Category:    "Physical Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	// =========================================================
	// System Security (SS) — 6 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SS-01",
		Name:        "System Security Management",
		Description: "Implement system security management controls including baseline configurations, security patches, and system hardening per CIP-007",
		Category:    "System Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemSecurityManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SS-02",
		Name:        "Patch Management",
		Description: "Implement and document a patch management program for BES Cyber Systems including vulnerability assessment and timely patch deployment per CIP-007",
		Category:    "System Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPatchManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SS-03",
		Name:        "Malware Prevention",
		Description: "Deploy and maintain malware prevention controls including antivirus, anti-malware, and endpoint protection for BES Cyber Systems per CIP-007",
		Category:    "System Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMalwarePrevention,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SS-04",
		Name:        "Port and Service Hardening",
		Description: "Implement port and service hardening controls including disabling unnecessary ports, services, and protocols on BES Cyber Systems per CIP-007",
		Category:    "System Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPortServiceHardening,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SS-05",
		Name:        "Security Event Monitoring",
		Description: "Implement security event monitoring for BES Cyber Systems including alert configuration, event correlation, and automated response capabilities per CIP-007",
		Category:    "System Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityEventMonitoring,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SS-06",
		Name:        "Log Review Procedures",
		Description: "Establish and document procedures for reviewing security logs and event data from BES Cyber Systems on a regular schedule per CIP-007",
		Category:    "System Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkLogReviewProcedures,
	})

	// =========================================================
	// Incident Response (IR) — 4 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IR-01",
		Name:        "Incident Response & Reporting",
		Description: "Develop and maintain a cyber security incident response plan and report qualifying cyber security incidents per CIP-008",
		Category:    "Incident Response",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponseReporting,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IR-02",
		Name:        "Incident Classification",
		Description: "Establish incident classification procedures defining severity levels, response priorities, and escalation criteria for cyber security incidents affecting BES Cyber Systems per CIP-008",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentClassification,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IR-03",
		Name:        "Incident Response Testing",
		Description: "Conduct periodic testing of the incident response plan including tabletop exercises, simulations, and after-action reviews per CIP-008",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponseTesting,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IR-04",
		Name:        "Forensic Analysis Capability",
		Description: "Maintain forensic analysis capabilities including tools, procedures, and trained personnel for investigating cyber security incidents affecting BES Cyber Systems per CIP-008",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================
	// Recovery Planning (RP) — 4 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-RP-01",
		Name:        "Recovery Planning",
		Description: "Develop and maintain recovery plans for BES Cyber Systems including business continuity and disaster recovery per CIP-009",
		Category:    "Recovery Planning",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecoveryPlanning,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-RP-02",
		Name:        "Recovery Plan Testing",
		Description: "Conduct periodic testing of recovery plans for BES Cyber Systems including functional exercises and recovery procedure validation per CIP-009",
		Category:    "Recovery Planning",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecoveryPlanTesting,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-RP-03",
		Name:        "Backup Power and Communications",
		Description: "Ensure availability of backup power and communications systems for BES Cyber Systems to support recovery operations during disruptions per CIP-009",
		Category:    "Recovery Planning",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-RP-04",
		Name:        "Recovery Time Objectives",
		Description: "Define and document recovery time objectives for BES Cyber Systems based on their impact rating and operational criticality per CIP-009",
		Category:    "Recovery Planning",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================
	// Configuration Management (CM) — 5 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CM-01",
		Name:        "Configuration Change Management",
		Description: "Implement configuration change management controls for BES Cyber Systems including baseline configuration and change testing per CIP-010",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConfigurationChangeManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CM-02",
		Name:        "Baseline Configuration",
		Description: "Establish and maintain baseline configurations for BES Cyber Systems including hardware, software, and security settings per CIP-010",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBaselineConfiguration,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CM-03",
		Name:        "Change Testing",
		Description: "Implement change testing procedures for configuration changes to BES Cyber Systems including test environment validation and risk assessment per CIP-010",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeTesting,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CM-04",
		Name:        "Configuration Integrity Verification",
		Description: "Implement configuration integrity verification controls including file integrity monitoring and unauthorized change detection for BES Cyber Systems per CIP-010",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CM-05",
		Name:        "Rollback Procedures",
		Description: "Establish and document rollback procedures for configuration changes to BES Cyber Systems to enable rapid restoration to a known-good state per CIP-010",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================
	// Information Protection (IP) — 4 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IP-01",
		Name:        "Information Protection",
		Description: "Implement information protection controls for BES Cyber System Information including data classification and handling per CIP-011",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInformationProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IP-02",
		Name:        "Data Classification",
		Description: "Establish and apply data classification schemes for BES Cyber System Information defining handling, storage, and transmission requirements per CIP-011",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataClassification,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IP-03",
		Name:        "BES Cyber System Information Sharing",
		Description: "Establish procedures for sharing BES Cyber System Information with external parties including access agreements and information handling requirements per CIP-011",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IP-04",
		Name:        "Information Disposal Procedures",
		Description: "Implement information disposal procedures for BES Cyber System Information including secure deletion, media sanitization, and disposal documentation per CIP-011",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================
	// Supply Chain (SC) — 4 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SC-01",
		Name:        "Supply Chain Risk Management",
		Description: "Implement supply chain risk management controls for BES Cyber Systems including vendor risk assessment and procurement security per CIP-013",
		Category:    "Supply Chain",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSupplyChainRiskManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SC-02",
		Name:        "Vendor Cyber Security Requirements",
		Description: "Establish and enforce cyber security requirements for vendors and suppliers providing products or services for BES Cyber Systems per CIP-013",
		Category:    "Supply Chain",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVendorCyberSecurityRequirements,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SC-03",
		Name:        "Software Integrity Verification",
		Description: "Implement software integrity verification controls including signature verification, hash validation, and tamper detection for software deployed on BES Cyber Systems per CIP-013",
		Category:    "Supply Chain",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SC-04",
		Name:        "Supply Chain Incident Notification",
		Description: "Establish procedures for notifying appropriate entities of supply chain cyber security incidents affecting BES Cyber Systems per CIP-013",
		Category:    "Supply Chain",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================
	// AI Governance (AI) — 4 controls
	// =========================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-AI-01",
		Name:        "AI Model BES Data Protection",
		Description: "Ensure AI models do not expose Bulk Electric System operational data, SCADA identifiers, or grid control system information",
		Category:    "AI Governance",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelBESDataProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-AI-02",
		Name:        "AI Audit Trail for BES Operations",
		Description: "Maintain comprehensive AI audit trails for all AI-assisted decisions affecting BES Cyber Systems including model logging and operational accountability",
		Category:    "AI Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrailBES,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-AI-03",
		Name:        "AI Model Validation for Grid Operations",
		Description: "Conduct validation and verification of AI models used in BES grid operations including accuracy testing, bias assessment, and operational safety evaluation per AI governance requirements",
		Category:    "AI Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-AI-04",
		Name:        "AI Decision Override Capability",
		Description: "Maintain human override capabilities for all AI-assisted decisions affecting BES Cyber Systems to ensure operator intervention and control per AI governance requirements",
		Category:    "AI Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})
}

// =========================================================
// Check functions for each control
// =========================================================

// --- Cyber System Categorization (CS) ---

func (m *NERCCIPModule) checkBESCyberSystemCategorization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"bes_cyber_system", "cyber_asset_categorization", "bes_categorization", "cyber_system_identification"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-CS-01",
				ControlName: "BES Cyber System Categorization",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityCritical,
				Message:     "BES Cyber System categorization controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-CS-01",
		ControlName: "BES Cyber System Categorization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "BES Cyber System categorization policy not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement BES Cyber System identification and categorization per CIP-002",
	}, nil
}

func (m *NERCCIPModule) checkImpactRatingAssignment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"impact_rating", "high_impact", "medium_impact", "low_impact", "impact_assessment"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-CS-02",
				ControlName: "Impact Rating Assignment",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Impact rating assignment controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-CS-02",
		ControlName: "Impact Rating Assignment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Impact rating assignment controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Assign impact ratings to all BES Cyber Systems per CIP-002",
	}, nil
}

func (m *NERCCIPModule) checkBESCyberAssetInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"cyber_asset_inventory", "asset_inventory", "bes_inventory", "asset_register", "cyber_asset_register"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-CS-03",
				ControlName: "BES Cyber Asset Inventory",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "BES Cyber Asset inventory controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-CS-03",
		ControlName: "BES Cyber Asset Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "BES Cyber Asset inventory controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Maintain a comprehensive inventory of all BES Cyber Assets per CIP-002",
	}, nil
}

// --- Security Management (SM) ---

func (m *NERCCIPModule) checkSecurityManagementControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"security_management", "cip_security_policy", "security_controls", "cyber_security_policy"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SM-01",
				ControlName: "Security Management Controls",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Security management controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-SM-01",
		ControlName: "Security Management Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Security management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement and document cyber security policies per CIP-003",
	}, nil
}

func (m *NERCCIPModule) checkCyberSecurityPolicyApproval(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"policy_approval", "management_approval", "board_approval", "policy_authorization", "senior_management_approval"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SM-02",
				ControlName: "Cyber Security Policy Approval",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Cyber security policy approval controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-SM-02",
		ControlName: "Cyber Security Policy Approval",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cyber security policy approval controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Obtain senior management or board approval for cyber security policies per CIP-003",
	}, nil
}

// --- Personnel & Training (PT) ---

func (m *NERCCIPModule) checkPersonnelRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"personnel_risk", "background_check", "personnel_assessment", "personnel_screening"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-PT-01",
				ControlName: "Personnel Risk Assessment",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Personnel risk assessment controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-PT-01",
		ControlName: "Personnel Risk Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Personnel risk assessment controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement personnel risk assessments and background checks per CIP-004",
	}, nil
}

func (m *NERCCIPModule) checkCyberSecurityTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"cyber_security_training", "security_awareness", "training_program", "security_training"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-PT-02",
				ControlName: "Cyber Security Training",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityMedium,
				Message:     "Cyber security training controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-PT-02",
		ControlName: "Cyber Security Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Cyber security training controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement cyber security awareness training per CIP-004",
	}, nil
}

func (m *NERCCIPModule) checkAccessManagementProgram(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"access_management", "access_management_program", "role_management", "access_revocation", "access_governance"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-PT-03",
				ControlName: "Access Management Program",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Access management program controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-PT-03",
		ControlName: "Access Management Program",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Access management program controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement an access management program defining roles and access procedures per CIP-004",
	}, nil
}

// --- Electronic Security (EP) ---

func (m *NERCCIPModule) checkElectronicSecurityPerimeter(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"electronic_security_perimeter", "esp_defined", "security_perimeter", "electronic_perimeter"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-EP-01",
				ControlName: "Electronic Security Perimeter",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityCritical,
				Message:     "Electronic Security Perimeter controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-EP-01",
		ControlName: "Electronic Security Perimeter",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Electronic Security Perimeter controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Define and implement Electronic Security Perimeters per CIP-005",
	}, nil
}

func (m *NERCCIPModule) checkElectronicAccessMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	checks := map[string]bool{
		"access_monitoring":   false,
		"log_monitoring":      false,
		"intrusion_detection": false,
	}
	inputStr := strings.ToLower(string(input))

	for kw := range checks {
		if strings.Contains(inputStr, kw) {
			checks[kw] = true
		}
	}

	matched := 0
	for _, v := range checks {
		if v {
			matched++
		}
	}

	switch {
	case matched >= 3:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-EP-02",
			ControlName: "Electronic Access Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Electronic access monitoring controls verified",
			Timestamp:   time.Now(),
		}, nil
	case matched >= 2:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-EP-02",
			ControlName: "Electronic Access Monitoring",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial electronic access monitoring controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement all electronic access monitoring controls: access monitoring, log monitoring, and intrusion detection per CIP-005",
			Details:     fmt.Sprintf("Detected %d of 3 monitoring controls", matched),
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-EP-02",
			ControlName: "Electronic Access Monitoring",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Electronic access monitoring controls not detected",
			Timestamp:   time.Now(),
			Remediation: "Implement electronic access monitoring, logging, and intrusion detection per CIP-005",
		}, nil
	}
}

func (m *NERCCIPModule) checkNetworkSecurityArchitecture(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	checks := map[string]bool{
		"firewall_rules":       false,
		"network_segmentation": false,
		"traffic_filtering":    false,
	}
	inputStr := strings.ToLower(string(input))

	for kw := range checks {
		if strings.Contains(inputStr, kw) {
			checks[kw] = true
		}
	}

	matched := 0
	for _, v := range checks {
		if v {
			matched++
		}
	}

	switch {
	case matched >= 3:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-EP-03",
			ControlName: "Network Security Architecture",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network security architecture controls verified",
			Timestamp:   time.Now(),
		}, nil
	case matched >= 2:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-EP-03",
			ControlName: "Network Security Architecture",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial network security architecture controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement all network security architecture controls: firewall rules, network segmentation, and traffic filtering per CIP-005",
			Details:     fmt.Sprintf("Detected %d of 3 network security controls", matched),
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-EP-03",
			ControlName: "Network Security Architecture",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network security architecture controls not detected",
			Timestamp:   time.Now(),
			Remediation: "Implement network security architecture including firewalls, segmentation, and traffic filtering per CIP-005",
		}, nil
	}
}

// --- Physical Security (PS) ---

func (m *NERCCIPModule) checkPhysicalSecurityPerimeter(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"physical_security", "physical_access", "physical_perimeter", "physical_safeguards"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-PS-01",
				ControlName: "Physical Security Perimeter",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Physical Security Perimeter controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-PS-01",
		ControlName: "Physical Security Perimeter",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Physical Security Perimeter controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement Physical Security Perimeters for BES Cyber Systems per CIP-006",
	}, nil
}

func (m *NERCCIPModule) checkPhysicalAccessControlSystems(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"access_control_system", "badge_access", "biometric_access", "physical_authentication", "card_reader"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-PS-03",
				ControlName: "Physical Access Control Systems",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Physical access control systems verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-PS-03",
		ControlName: "Physical Access Control Systems",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Physical access control systems not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement physical access control systems including badges and biometrics per CIP-006",
	}, nil
}

func (m *NERCCIPModule) checkVisitorAccessManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"visitor_access", "visitor_management", "visitor_escort", "visitor_log", "visitor_authorization"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-PS-04",
				ControlName: "Visitor Access Management",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityMedium,
				Message:     "Visitor access management controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-PS-04",
		ControlName: "Visitor Access Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Visitor access management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement visitor access management procedures including escort and logging per CIP-006",
	}, nil
}

// --- System Security (SS) ---

func (m *NERCCIPModule) checkSystemSecurityManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"system_security", "security_baseline", "system_hardening", "baseline_configuration"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SS-01",
				ControlName: "System Security Management",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "System security management controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-SS-01",
		ControlName: "System Security Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "System security management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement system security management and baseline configurations per CIP-007",
	}, nil
}

func (m *NERCCIPModule) checkPatchManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"patch_management", "vulnerability_management", "security_patches", "patch_deployment"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SS-02",
				ControlName: "Patch Management",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityCritical,
				Message:     "Patch management controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-SS-02",
		ControlName: "Patch Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Patch management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement patch management program per CIP-007",
	}, nil
}

func (m *NERCCIPModule) checkMalwarePrevention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"malware_prevention", "antivirus", "anti-malware", "endpoint_protection", "malware_detection"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SS-03",
				ControlName: "Malware Prevention",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Malware prevention controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-SS-03",
		ControlName: "Malware Prevention",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Malware prevention controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Deploy and maintain malware prevention controls including antivirus per CIP-007",
	}, nil
}

func (m *NERCCIPModule) checkPortServiceHardening(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	checks := map[string]bool{
		"port_hardening":    false,
		"service_hardening": false,
		"unnecessary_ports": false,
	}
	inputStr := strings.ToLower(string(input))

	for kw := range checks {
		if strings.Contains(inputStr, kw) {
			checks[kw] = true
		}
	}

	// Also check for keyword-based matches
	keywords := []string{"port_hardening", "service_hardening", "unnecessary_ports", "disabled_services", "protocol_hardening"}
	matched := 0
	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			matched++
		}
	}

	switch {
	case matched >= 3:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-SS-04",
			ControlName: "Port and Service Hardening",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Port and service hardening controls verified",
			Timestamp:   time.Now(),
		}, nil
	case matched >= 2:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-SS-04",
			ControlName: "Port and Service Hardening",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial port and service hardening controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement all port and service hardening controls including disabling unnecessary ports, services, and protocols per CIP-007",
			Details:     fmt.Sprintf("Detected %d of 3+ hardening controls", matched),
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-SS-04",
			ControlName: "Port and Service Hardening",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Port and service hardening controls not detected",
			Timestamp:   time.Now(),
			Remediation: "Implement port and service hardening including disabling unnecessary ports and services per CIP-007",
		}, nil
	}
}

// --- Incident Response (IR) ---

func (m *NERCCIPModule) checkIncidentResponseReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"incident_response", "incident_handling", "response_plan", "incident_reporting"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-IR-01",
				ControlName: "Incident Response & Reporting",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityCritical,
				Message:     "Incident response and reporting controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-IR-01",
		ControlName: "Incident Response & Reporting",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Incident response and reporting controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Develop and maintain incident response plan per CIP-008",
	}, nil
}

func (m *NERCCIPModule) checkIncidentClassification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"incident_classification", "severity_level", "incident_severity", "escalation_criteria", "incident_priority"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-IR-02",
				ControlName: "Incident Classification",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Incident classification controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-IR-02",
		ControlName: "Incident Classification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident classification controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Establish incident classification procedures defining severity levels and escalation criteria per CIP-008",
	}, nil
}

// --- Recovery Planning (RP) ---

func (m *NERCCIPModule) checkRecoveryPlanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	checks := map[string]bool{
		"recovery_plan":       false,
		"business_continuity": false,
		"disaster_recovery":   false,
	}
	inputStr := strings.ToLower(string(input))

	for kw := range checks {
		if strings.Contains(inputStr, kw) {
			checks[kw] = true
		}
	}

	matched := 0
	for _, v := range checks {
		if v {
			matched++
		}
	}

	switch {
	case matched >= 3:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-RP-01",
			ControlName: "Recovery Planning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Recovery planning controls verified",
			Timestamp:   time.Now(),
		}, nil
	case matched >= 2:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-RP-01",
			ControlName: "Recovery Planning",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial recovery planning controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive recovery planning including recovery plans, business continuity, and disaster recovery per CIP-009",
			Details:     fmt.Sprintf("Detected %d of 3 recovery planning controls", matched),
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-RP-01",
			ControlName: "Recovery Planning",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Recovery planning controls not detected",
			Timestamp:   time.Now(),
			Remediation: "Develop recovery plans for BES Cyber Systems per CIP-009",
		}, nil
	}
}

func (m *NERCCIPModule) checkRecoveryPlanTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"recovery_testing", "recovery_test", "dr_test", "recovery_exercise", "recovery_validation"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-RP-02",
				ControlName: "Recovery Plan Testing",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Recovery plan testing controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-RP-02",
		ControlName: "Recovery Plan Testing",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Recovery plan testing controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Conduct periodic testing of recovery plans for BES Cyber Systems per CIP-009",
	}, nil
}

// --- Configuration Management (CM) ---

func (m *NERCCIPModule) checkConfigurationChangeManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"change_management", "configuration_management", "change_control", "baseline_change"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-CM-01",
				ControlName: "Configuration Change Management",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Configuration change management controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-CM-01",
		ControlName: "Configuration Change Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Configuration change management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement configuration change management per CIP-010",
	}, nil
}

func (m *NERCCIPModule) checkBaselineConfiguration(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"baseline_configuration", "configuration_baseline", "baseline_settings", "baseline_config", "known_good_config"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-CM-02",
				ControlName: "Baseline Configuration",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Baseline configuration controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-CM-02",
		ControlName: "Baseline Configuration",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Baseline configuration controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Establish and maintain baseline configurations for BES Cyber Systems per CIP-010",
	}, nil
}

func (m *NERCCIPModule) checkChangeTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"change_testing", "test_environment", "change_validation", "test_before_deployment", "change_test"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-CM-03",
				ControlName: "Change Testing",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Change testing controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-CM-03",
		ControlName: "Change Testing",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Change testing controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement change testing procedures including test environment validation per CIP-010",
	}, nil
}

// --- Information Protection (IP) ---

func (m *NERCCIPModule) checkInformationProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"information_protection", "data_classification", "bes_data_protection", "cip_information"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-IP-01",
				ControlName: "Information Protection",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Information protection controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-IP-01",
		ControlName: "Information Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Information protection controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement information protection controls for BES Cyber System Information per CIP-011",
	}, nil
}

func (m *NERCCIPModule) checkDataClassification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"data_classification", "classification_scheme", "data_handling", "classification_levels", "information_classification"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-IP-02",
				ControlName: "Data Classification",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Data classification controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-IP-02",
		ControlName: "Data Classification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Data classification controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Establish and apply data classification schemes for BES Cyber System Information per CIP-011",
	}, nil
}

// --- Supply Chain (SC) ---

func (m *NERCCIPModule) checkSupplyChainRiskManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"supply_chain_risk", "vendor_risk", "procurement_security", "supply_chain_management"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SC-01",
				ControlName: "Supply Chain Risk Management",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Supply chain risk management controls verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-SC-01",
		ControlName: "Supply Chain Risk Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Supply chain risk management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement supply chain risk management per CIP-013",
	}, nil
}

func (m *NERCCIPModule) checkVendorCyberSecurityRequirements(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"vendor_requirements", "supplier_security", "vendor_cyber_security", "procurement_requirements", "vendor_security_requirements"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SC-02",
				ControlName: "Vendor Cyber Security Requirements",
				Status:      compliance.StatusCompliant,
				Severity:    compliance.SeverityHigh,
				Message:     "Vendor cyber security requirements verified",
				Timestamp:   time.Now(),
			}, nil
		}
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-SC-02",
		ControlName: "Vendor Cyber Security Requirements",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vendor cyber security requirements not detected",
		Timestamp:   time.Now(),
		Remediation: "Establish and enforce cyber security requirements for vendors and suppliers per CIP-013",
	}, nil
}

// --- AI Governance (AI) ---

func (m *NERCCIPModule) checkAIModelBESDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	if m.detectBESData(string(input)) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-AI-01",
			ControlName: "AI Model BES Data Protection",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "BES operational data patterns detected in AI model data",
			Timestamp:   time.Now(),
			Remediation: "Remove BES Cyber System data, SCADA identifiers, and grid control information from AI model data",
			Details:     "Bulk Electric System data patterns detected - AI models must not expose BES operational data",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NERC-CIP-AI-01",
		ControlName: "AI Model BES Data Protection",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "AI model BES data protection verified",
		Timestamp:   time.Now(),
	}, nil
}

func (m *NERCCIPModule) checkAIAuditTrailBES(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	checks := map[string]bool{
		"ai_audit":        false,
		"model_logging":   false,
		"bes_audit_trail": false,
	}
	inputStr := strings.ToLower(string(input))

	for kw := range checks {
		if strings.Contains(inputStr, kw) {
			checks[kw] = true
		}
	}

	matched := 0
	for _, v := range checks {
		if v {
			matched++
		}
	}

	switch {
	case matched >= 3:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-AI-02",
			ControlName: "AI Audit Trail for BES Operations",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI audit trail for BES operations verified",
			Timestamp:   time.Now(),
		}, nil
	case matched >= 2:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-AI-02",
			ControlName: "AI Audit Trail for BES Operations",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AI audit trail controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive AI audit trail including model logging and BES operational accountability",
			Details:     fmt.Sprintf("Detected %d of 3 AI audit trail controls", matched),
		}, nil
	default:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-AI-02",
			ControlName: "AI Audit Trail for BES Operations",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI audit trail controls not detected",
			Timestamp:   time.Now(),
			Remediation: "Implement AI audit trail controls for BES operations",
		}, nil
	}
}

// ============================================================================
// Promoted CheckFunc implementations — P4 Compliance Automation Expansion
// ============================================================================

func (m *NERCCIPModule) checkIntrusionDetection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIDS := strings.Contains(inputStr, "intrusion_detection") || strings.Contains(inputStr, "ids") || strings.Contains(inputStr, "ips")
	hasMonitoring := strings.Contains(inputStr, "ids_monitoring") || strings.Contains(inputStr, "network_monitoring") || strings.Contains(inputStr, "perimeter_monitoring")
	if hasIDS && hasMonitoring {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NERC-CIP-EP-04", ControlName: "Intrusion Detection System", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Intrusion detection system detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasIDS {
		violations = append(violations, "IDS not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "IDS monitoring not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NERC-CIP-EP-04", ControlName: "Intrusion Detection System", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "IDS gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Deploy intrusion detection system"}, nil
}

func (m *NERCCIPModule) checkSecurityEventMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "security_event_monitoring") || strings.Contains(inputStr, "event_monitoring") || strings.Contains(inputStr, "siem")
	if hasMonitoring {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NERC-CIP-SS-05", ControlName: "Security Event Monitoring", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Security event monitoring detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NERC-CIP-SS-05", ControlName: "Security Event Monitoring", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Security event monitoring not detected", Timestamp: time.Now(), Remediation: "Implement security event monitoring"}, nil
}

func (m *NERCCIPModule) checkLogReviewProcedures(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReview := strings.Contains(inputStr, "log_review_procedures") || strings.Contains(inputStr, "log_review") || strings.Contains(inputStr, "log_analysis")
	if hasReview {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NERC-CIP-SS-06", ControlName: "Log Review Procedures", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Log review procedures detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NERC-CIP-SS-06", ControlName: "Log Review Procedures", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Log review not detected", Timestamp: time.Now(), Remediation: "Implement log review procedures"}, nil
}

func (m *NERCCIPModule) checkIncidentResponseTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTesting := strings.Contains(inputStr, "incident_response_testing") || strings.Contains(inputStr, "ir_testing") || strings.Contains(inputStr, "ir_test")
	if hasTesting {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NERC-CIP-IR-03", ControlName: "Incident Response Testing", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Incident response testing detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NERC-CIP-IR-03", ControlName: "Incident Response Testing", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "IR testing not detected", Timestamp: time.Now(), Remediation: "Implement incident response testing"}, nil
}
