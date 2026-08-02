// Package sox provides SOX (Sarbanes-Oxley Act) compliance controls as a licensed add-on module.
package sox

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// SOXModule implements SOX compliance controls.
type SOXModule struct {
	*compliance.BaseComplianceModule
	soxPatterns []*regexp.Regexp
}

// NewSOXModule creates a new SOX compliance module.
func NewSOXModule() *SOXModule {
	m := &SOXModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("sox", "2002", core.TierProfessional),
	}

	m.initSOXPatterns()
	m.registerControls()

	return m
}

// initSOXPatterns initializes patterns for detecting financial data.
func (m *SOXModule) initSOXPatterns() {
	m.soxPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),                                      // SSN
		regexp.MustCompile(`(?i)\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`),              // Credit card number
		regexp.MustCompile(`(?i)(?:routing|aba)\s*\d{9}`),                              // ABA routing
		regexp.MustCompile(`(?i)account\s*(?:number|#)?\s*[A-Za-z0-9]{6,20}`),           // Financial account
		regexp.MustCompile(`(?i)sox\s*(?:compliant|control|section)`),                  // SOX marker
	}
}

// registerControls registers all SOX compliance controls.
func (m *SOXModule) registerControls() {
	// Internal Controls (IC)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-IC-001",
		Name:        "Internal Control Assessment",
		Description: "Organizations must assess internal controls over financial reporting",
		Category:    "Internal Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInternalControlAssessment,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-IC-002",
		Name:        "Control Environment",
		Description: "Maintain a strong control environment with clear policies",
		Category:    "Internal Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkControlEnvironment,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-IC-003",
		Name:        "Risk Assessment Framework",
		Description: "Implement enterprise risk assessment for financial reporting risks",
		Category:    "Internal Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
	})

	// Financial Reporting (FR)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-001",
		Name:        "Financial Statement Integrity",
		Description: "Ensure accuracy and completeness of financial statements",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFinancialStatementIntegrity,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-002",
		Name:        "Real-Time Disclosure (Section 409)",
		Description: "Material events must be disclosed on rapid and current basis",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRealTimeDisclosure,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-003",
		Name:        "Audit Committee Oversight",
		Description: "Independent audit committee oversight of financial reporting",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
	})

	// Data Protection (DP)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-001",
		Name:        "Records Retention (Section 802)",
		Description: "Maintain and retain records for required periods",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecordsRetention,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-002",
		Name:        "Data Integrity Controls",
		Description: "Ensure data integrity in financial systems",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDataIntegrity,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-003",
		Name:        "Access Controls for Financial Systems",
		Description: "RBAC and MFA for financial system access",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFinancialAccessControls,
	})

	// IT General Controls (IT)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-IT-001",
		Name:        "Change Management",
		Description: "All system changes follow approved change management process",
		Category:    "IT General Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-IT-002",
		Name:        "IT Security Controls",
		Description: "Technical security controls for financial IT systems",
		Category:    "IT General Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkITSecurityControls,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-IT-003",
		Name:        "Backup and Recovery",
		Description: "Financial system backup and disaster recovery",
		Category:    "IT General Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBackupRecovery,
	})

	// Whistleblower Protection (WP)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-WP-001",
		Name:        "Whistleblower Protection (Section 806)",
		Description: "Protections for employees reporting fraud",
		Category:    "Whistleblower Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-WP-002",
		Name:        "Anonymous Reporting Mechanism",
		Description: "Maintain anonymous reporting channels for financial misconduct",
		Category:    "Whistleblower Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAnonymousReporting,
	})

	// AI-Specific (AI)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AI-001",
		Name:        "AI Model Financial Data Protection",
		Description: "AI models must not retain or expose financial reporting data",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelFinancialProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AI-002",
		Name:        "AI Audit Trail for Financial Reports",
		Description: "Audit trails for AI systems processing financial data",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrailFinancial,
	})
}

// Check implementations

func (m *SOXModule) checkInternalControlAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasICAssessment := strings.Contains(inputStr, "internal_control_assessment") ||
		strings.Contains(inputStr, "icfr") ||
		strings.Contains(inputStr, "control_testing")

	if hasICAssessment {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-IC-001",
			ControlName: "Internal Control Assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Internal control assessment over financial reporting detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-IC-001",
		ControlName: "Internal Control Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Internal control assessment over financial reporting not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement internal control assessment and ICFR testing procedures per SOX Section 404",
	}, nil
}

func (m *SOXModule) checkControlEnvironment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasControlEnv := strings.Contains(inputStr, "control_environment") ||
		strings.Contains(inputStr, "tone_at_top") ||
		strings.Contains(inputStr, "governance_policy")

	if hasControlEnv {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-IC-002",
			ControlName: "Control Environment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Strong control environment with governance policies detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-IC-002",
		ControlName: "Control Environment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Control environment and governance policies not detected",
		Timestamp:   time.Now(),
		Remediation: "Establish a strong control environment with clear tone-at-top governance policies",
	}, nil
}

func (m *SOXModule) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRiskAssessment := strings.Contains(inputStr, "risk_assessment") ||
		strings.Contains(inputStr, "risk_framework") ||
		strings.Contains(inputStr, "financial_risk")

	if hasRiskAssessment {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-IC-003",
			ControlName: "Risk Assessment Framework",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Enterprise risk assessment framework for financial reporting detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-IC-003",
		ControlName: "Risk Assessment Framework",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Risk assessment framework for financial reporting not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement an enterprise risk assessment framework addressing financial reporting risks",
	}, nil
}

func (m *SOXModule) checkFinancialStatementIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFinancialIntegrity := strings.Contains(inputStr, "financial_statement") ||
		strings.Contains(inputStr, "reporting_integrity") ||
		strings.Contains(inputStr, "financial_accuracy")

	if hasFinancialIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-FR-001",
			ControlName: "Financial Statement Integrity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Financial statement integrity and accuracy controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-FR-001",
		ControlName: "Financial Statement Integrity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Financial statement integrity controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement controls ensuring accuracy and completeness of financial statements",
	}, nil
}

func (m *SOXModule) checkRealTimeDisclosure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRealTimeDisclosure := strings.Contains(inputStr, "real_time_disclosure") ||
		strings.Contains(inputStr, "material_event") ||
		strings.Contains(inputStr, "current_report")

	if hasRealTimeDisclosure {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-FR-002",
			ControlName: "Real-Time Disclosure (Section 409)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Real-time disclosure controls for material events detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-FR-002",
		ControlName: "Real-Time Disclosure (Section 409)",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Real-time disclosure controls for material events not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement rapid disclosure procedures for material events per SOX Section 409",
	}, nil
}

func (m *SOXModule) checkRecordsRetention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRecordsRetention := strings.Contains(inputStr, "records_retention") ||
		strings.Contains(inputStr, "data_retention_policy") ||
		strings.Contains(inputStr, "retention_schedule")

	if hasRecordsRetention {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-001",
			ControlName: "Records Retention (Section 802)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Records retention controls per Section 802 detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-001",
		ControlName: "Records Retention (Section 802)",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Records retention controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement records retention policies per SOX Section 802 requirements",
	}, nil
}

func (m *SOXModule) checkDataIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDataIntegrity := strings.Contains(inputStr, "data_integrity") ||
		strings.Contains(inputStr, "reconciliation") ||
		strings.Contains(inputStr, "data_validation")

	if hasDataIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-002",
			ControlName: "Data Integrity Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data integrity controls for financial systems detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-002",
		ControlName: "Data Integrity Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Data integrity controls for financial systems not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement data integrity controls including reconciliation and validation for financial systems",
	}, nil
}

func (m *SOXModule) checkFinancialAccessControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccessControl := strings.Contains(inputStr, "access_control")
	hasRBAC := strings.Contains(inputStr, "rbac")
	hasMFA := strings.Contains(inputStr, "mfa")
	hasFinancialAccess := strings.Contains(inputStr, "financial_access")

	found := 0
	total := 4
	if hasAccessControl {
		found++
	}
	if hasRBAC {
		found++
	}
	if hasMFA {
		found++
	}
	if hasFinancialAccess {
		found++
	}

	if found == total {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-003",
			ControlName: "Access Controls for Financial Systems",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Full RBAC and MFA access controls for financial systems detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-003",
			ControlName: "Access Controls for Financial Systems",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial access controls for financial systems detected",
			Timestamp:   time.Now(),
			Remediation: "Implement complete RBAC and MFA access controls for all financial systems",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-003",
		ControlName: "Access Controls for Financial Systems",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Access controls for financial systems not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement RBAC and MFA access controls for all financial systems per SOX requirements",
	}, nil
}

func (m *SOXModule) checkChangeManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasChangeManagement := strings.Contains(inputStr, "change_management") ||
		strings.Contains(inputStr, "change_control") ||
		strings.Contains(inputStr, "cab_approval")

	if hasChangeManagement {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-IT-001",
			ControlName: "Change Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Change management process controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-IT-001",
		ControlName: "Change Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Change management process controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement approved change management process with CAB approval for all system changes",
	}, nil
}

func (m *SOXModule) checkITSecurityControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasITSecurity := strings.Contains(inputStr, "it_security") ||
		strings.Contains(inputStr, "security_controls") ||
		strings.Contains(inputStr, "vulnerability_management")

	if hasITSecurity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-IT-002",
			ControlName: "IT Security Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "IT security controls for financial systems detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-IT-002",
		ControlName: "IT Security Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "IT security controls for financial systems not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement technical security controls including vulnerability management for financial IT systems",
	}, nil
}

func (m *SOXModule) checkBackupRecovery(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBackupRecovery := strings.Contains(inputStr, "backup_recovery")
	hasDisasterRecovery := strings.Contains(inputStr, "disaster_recovery")
	hasBusinessContinuity := strings.Contains(inputStr, "business_continuity")

	found := 0
	total := 3
	if hasBackupRecovery {
		found++
	}
	if hasDisasterRecovery {
		found++
	}
	if hasBusinessContinuity {
		found++
	}

	if found == total {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-IT-003",
			ControlName: "Backup and Recovery",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Full backup, disaster recovery, and business continuity controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-IT-003",
			ControlName: "Backup and Recovery",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial backup and recovery controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement complete backup recovery, disaster recovery, and business continuity controls",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-IT-003",
		ControlName: "Backup and Recovery",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Backup and recovery controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement backup recovery, disaster recovery, and business continuity controls for financial systems",
	}, nil
}

func (m *SOXModule) checkAnonymousReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAnonymousReporting := strings.Contains(inputStr, "anonymous_reporting") ||
		strings.Contains(inputStr, "whistleblower_hotline") ||
		strings.Contains(inputStr, "ethics_line")

	if hasAnonymousReporting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-WP-002",
			ControlName: "Anonymous Reporting Mechanism",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Anonymous reporting mechanism for financial misconduct detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-WP-002",
		ControlName: "Anonymous Reporting Mechanism",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Anonymous reporting mechanism not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement anonymous reporting channels including whistleblower hotline and ethics line",
	}, nil
}

func (m *SOXModule) checkAIModelFinancialProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	financialFound := m.detectFinancialData(string(input))

	if len(financialFound) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-AI-001",
			ControlName: "AI Model Financial Data Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No financial data patterns detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-AI-001",
		ControlName: "AI Model Financial Data Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Financial data patterns detected in AI model data",
		Details:     "Detected financial data patterns in input data",
		Timestamp:   time.Now(),
		Remediation: "Implement financial data scrubbing for all AI model inputs and outputs per SOX requirements",
	}, nil
}

func (m *SOXModule) checkAIAuditTrailFinancial(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAIAuditTrail := strings.Contains(inputStr, "ai_audit_trail")
	hasModelLogging := strings.Contains(inputStr, "model_logging")
	hasFinancialAuditTrail := strings.Contains(inputStr, "financial_audit_trail")

	found := 0
	total := 3
	if hasAIAuditTrail {
		found++
	}
	if hasModelLogging {
		found++
	}
	if hasFinancialAuditTrail {
		found++
	}

	if found == total {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-AI-002",
			ControlName: "AI Audit Trail for Financial Reports",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Complete AI audit trail for financial reporting detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-AI-002",
			ControlName: "AI Audit Trail for Financial Reports",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AI audit trail controls for financial reporting detected",
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive AI audit trail including ai_audit_trail, model_logging, and financial_audit_trail",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-AI-002",
		ControlName: "AI Audit Trail for Financial Reports",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI audit trail controls for financial reporting not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement AI audit trail, model logging, and financial audit trail for all AI systems processing financial data",
	}, nil
}

// detectFinancialData scans input for potential financial data patterns.
func (m *SOXModule) detectFinancialData(input string) []string {
	found := []string{}
	for _, pattern := range m.soxPatterns {
		if pattern.MatchString(input) {
			found = append(found, pattern.String())
		}
	}
	return found
}

// Dependencies returns required modules.
func (m *SOXModule) Dependencies() []string {
	return []string{"scanner"}
}