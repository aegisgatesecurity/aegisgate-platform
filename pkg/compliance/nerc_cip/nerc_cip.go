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
		BaseComplianceModule: compliance.NewBaseComplianceModule("nerc_cip", "v5", core.TierProfessional),
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
	// CIP-002: BES Cyber System Categorization
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CS-001",
		Name:        "BES Cyber System Categorization",
		Description: "Identify and categorize BES Cyber Systems according to their impact rating (high, medium, low) as required by CIP-002",
		Category:    "Cyber System Categorization",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBESCyberSystemCategorization,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CS-002",
		Name:        "Impact Rating Assignment",
		Description: "Assign impact ratings to BES Cyber Systems based on their potential impact on the reliable operation of the Bulk Electric System",
		Category:    "Cyber System Categorization",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkImpactRatingAssignment,
	})

	// CIP-003: Security Management Controls
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SM-001",
		Name:        "Security Management Controls",
		Description: "Implement and document cyber security policies consistent with CIP-003 requirements for medium and high impact BES Cyber Systems",
		Category:    "Security Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityManagementControls,
	})

	// CIP-004: Personnel & Training
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PT-001",
		Name:        "Personnel Risk Assessment",
		Description: "Conduct personnel risk assessments including background checks for personnel with cyber access to BES Cyber Systems per CIP-004",
		Category:    "Personnel & Training",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPersonnelRiskAssessment,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PT-002",
		Name:        "Cyber Security Training",
		Description: "Implement and maintain cyber security awareness and training programs for personnel with access to BES Cyber Systems",
		Category:    "Personnel & Training",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCyberSecurityTraining,
	})

	// CIP-005: Electronic Security Perimeters
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-EP-001",
		Name:        "Electronic Security Perimeter",
		Description: "Define and implement Electronic Security Perimeters (ESPs) for BES Cyber Systems with all access points identified and monitored per CIP-005",
		Category:    "Electronic Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkElectronicSecurityPerimeter,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-EP-002",
		Name:        "Electronic Access Monitoring",
		Description: "Monitor and log all electronic access within Electronic Security Perimeters including intrusion detection and access logging per CIP-005",
		Category:    "Electronic Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkElectronicAccessMonitoring,
	})

	// CIP-006/014: Physical Security
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PS-001",
		Name:        "Physical Security Perimeter",
		Description: "Define and maintain Physical Security Perimeters for BES Cyber Systems with appropriate access controls per CIP-006",
		Category:    "Physical Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPhysicalSecurityPerimeter,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-PS-002",
		Name:        "Transmission Station Security",
		Description: "Conduct physical security threat assessments and implement security measures for transmission stations and substations per CIP-014",
		Category:    "Physical Security",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
	})

	// CIP-007: System Security Management
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SS-001",
		Name:        "System Security Management",
		Description: "Implement system security management controls including baseline configurations, security patches, and system hardening per CIP-007",
		Category:    "System Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemSecurityManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SS-002",
		Name:        "Patch Management",
		Description: "Implement and document a patch management program for BES Cyber Systems including vulnerability assessment and timely patch deployment per CIP-007",
		Category:    "System Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPatchManagement,
	})

	// CIP-008: Incident Response
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IR-001",
		Name:        "Incident Response & Reporting",
		Description: "Develop and maintain a cyber security incident response plan and report qualifying cyber security incidents per CIP-008",
		Category:    "Incident Response",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponseReporting,
	})

	// CIP-009: Recovery Planning
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-RP-001",
		Name:        "Recovery Planning",
		Description: "Develop and maintain recovery plans for BES Cyber Systems including business continuity and disaster recovery per CIP-009",
		Category:    "Recovery Planning",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecoveryPlanning,
	})

	// CIP-010: Configuration Change Management
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-CM-001",
		Name:        "Configuration Change Management",
		Description: "Implement configuration change management controls for BES Cyber Systems including baseline configuration and change testing per CIP-010",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConfigurationChangeManagement,
	})

	// CIP-011: Information Protection
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-IP-001",
		Name:        "Information Protection",
		Description: "Implement information protection controls for BES Cyber System Information including data classification and handling per CIP-011",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInformationProtection,
	})

	// CIP-013: Supply Chain Risk Management
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-SC-001",
		Name:        "Supply Chain Risk Management",
		Description: "Implement supply chain risk management controls for BES Cyber Systems including vendor risk assessment and procurement security per CIP-013",
		Category:    "Supply Chain",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSupplyChainRiskManagement,
	})

	// AI-Specific Controls
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-AI-001",
		Name:        "AI Model BES Data Protection",
		Description: "Ensure AI models do not expose Bulk Electric System operational data, SCADA identifiers, or grid control system information",
		Category:    "AI Governance",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelBESDataProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NERC-CIP-AI-002",
		Name:        "AI Audit Trail for BES Operations",
		Description: "Maintain comprehensive AI audit trails for all AI-assisted decisions affecting BES Cyber Systems including model logging and operational accountability",
		Category:    "AI Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrailBES,
	})
}

// Check functions for each control

func (m *NERCCIPModule) checkBESCyberSystemCategorization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"bes_cyber_system", "cyber_asset_categorization", "bes_categorization", "cyber_system_identification"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-CS-001",
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
		ControlID:   "NERC-CIP-CS-001",
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
				ControlID:   "NERC-CIP-CS-002",
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
		ControlID:   "NERC-CIP-CS-002",
		ControlName: "Impact Rating Assignment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Impact rating assignment controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Assign impact ratings to all BES Cyber Systems per CIP-002",
	}, nil
}

func (m *NERCCIPModule) checkSecurityManagementControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"security_management", "cip_security_policy", "security_controls", "cyber_security_policy"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SM-001",
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
		ControlID:   "NERC-CIP-SM-001",
		ControlName: "Security Management Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Security management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement and document cyber security policies per CIP-003",
	}, nil
}

func (m *NERCCIPModule) checkPersonnelRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"personnel_risk", "background_check", "personnel_assessment", "personnel_screening"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-PT-001",
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
		ControlID:   "NERC-CIP-PT-001",
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
				ControlID:   "NERC-CIP-PT-002",
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
		ControlID:   "NERC-CIP-PT-002",
		ControlName: "Cyber Security Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Cyber security training controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement cyber security awareness training per CIP-004",
	}, nil
}

func (m *NERCCIPModule) checkElectronicSecurityPerimeter(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"electronic_security_perimeter", "esp_defined", "security_perimeter", "electronic_perimeter"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-EP-001",
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
		ControlID:   "NERC-CIP-EP-001",
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
			ControlID:   "NERC-CIP-EP-002",
			ControlName: "Electronic Access Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Electronic access monitoring controls verified",
			Timestamp:   time.Now(),
		}, nil
	case matched >= 2:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-EP-002",
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
			ControlID:   "NERC-CIP-EP-002",
			ControlName: "Electronic Access Monitoring",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Electronic access monitoring controls not detected",
			Timestamp:   time.Now(),
			Remediation: "Implement electronic access monitoring, logging, and intrusion detection per CIP-005",
		}, nil
	}
}

func (m *NERCCIPModule) checkPhysicalSecurityPerimeter(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"physical_security", "physical_access", "physical_perimeter", "physical_safeguards"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-PS-001",
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
		ControlID:   "NERC-CIP-PS-001",
		ControlName: "Physical Security Perimeter",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Physical Security Perimeter controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement Physical Security Perimeters for BES Cyber Systems per CIP-006",
	}, nil
}

func (m *NERCCIPModule) checkSystemSecurityManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"system_security", "security_baseline", "system_hardening", "baseline_configuration"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SS-001",
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
		ControlID:   "NERC-CIP-SS-001",
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
				ControlID:   "NERC-CIP-SS-002",
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
		ControlID:   "NERC-CIP-SS-002",
		ControlName: "Patch Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Patch management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement patch management program per CIP-007",
	}, nil
}

func (m *NERCCIPModule) checkIncidentResponseReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"incident_response", "incident_handling", "response_plan", "incident_reporting"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-IR-001",
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
		ControlID:   "NERC-CIP-IR-001",
		ControlName: "Incident Response & Reporting",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Incident response and reporting controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Develop and maintain incident response plan per CIP-008",
	}, nil
}

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
			ControlID:   "NERC-CIP-RP-001",
			ControlName: "Recovery Planning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Recovery planning controls verified",
			Timestamp:   time.Now(),
		}, nil
	case matched >= 2:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-RP-001",
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
			ControlID:   "NERC-CIP-RP-001",
			ControlName: "Recovery Planning",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Recovery planning controls not detected",
			Timestamp:   time.Now(),
			Remediation: "Develop recovery plans for BES Cyber Systems per CIP-009",
		}, nil
	}
}

func (m *NERCCIPModule) checkConfigurationChangeManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"change_management", "configuration_management", "change_control", "baseline_change"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-CM-001",
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
		ControlID:   "NERC-CIP-CM-001",
		ControlName: "Configuration Change Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Configuration change management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement configuration change management per CIP-010",
	}, nil
}

func (m *NERCCIPModule) checkInformationProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"information_protection", "data_classification", "bes_data_protection", "cip_information"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-IP-001",
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
		ControlID:   "NERC-CIP-IP-001",
		ControlName: "Information Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Information protection controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement information protection controls for BES Cyber System Information per CIP-011",
	}, nil
}

func (m *NERCCIPModule) checkSupplyChainRiskManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	keywords := []string{"supply_chain_risk", "vendor_risk", "procurement_security", "supply_chain_management"}
	inputStr := strings.ToLower(string(input))

	for _, kw := range keywords {
		if strings.Contains(inputStr, kw) {
			return &compliance.ControlCheckResult{
				Framework:   m.Framework(),
				ControlID:   "NERC-CIP-SC-001",
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
		ControlID:   "NERC-CIP-SC-001",
		ControlName: "Supply Chain Risk Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Supply chain risk management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement supply chain risk management per CIP-013",
	}, nil
}

func (m *NERCCIPModule) checkAIModelBESDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	if m.detectBESData(string(input)) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-AI-001",
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
		ControlID:   "NERC-CIP-AI-001",
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
			ControlID:   "NERC-CIP-AI-002",
			ControlName: "AI Audit Trail for BES Operations",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI audit trail for BES operations verified",
			Timestamp:   time.Now(),
		}, nil
	case matched >= 2:
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NERC-CIP-AI-002",
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
			ControlID:   "NERC-CIP-AI-002",
			ControlName: "AI Audit Trail for BES Operations",
			Status:      compliance.StatusNonCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI audit trail controls not detected",
			Timestamp:   time.Now(),
			Remediation: "Implement AI audit trail controls for BES operations",
		}, nil
	}
}
