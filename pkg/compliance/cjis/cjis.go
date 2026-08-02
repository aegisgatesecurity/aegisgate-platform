// Package cjis provides CJIS Security Policy compliance controls as a licensed add-on module.
package cjis

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// CJISModule implements CJIS Security Policy compliance controls.
type CJISModule struct {
	*compliance.BaseComplianceModule
	cjiPatterns []*regexp.Regexp
}

// NewCJISModule creates a new CJIS compliance module.
func NewCJISModule() *CJISModule {
	m := &CJISModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("cjis", "5.9.1", core.TierEnterprise),
	}

	m.initCJIPatterns()
	m.registerControls()

	return m
}

// initCJIPatterns initializes patterns for detecting Criminal Justice Information.
func (m *CJISModule) initCJIPatterns() {
	// CJIS-defined CJI identifiers
	m.cjiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),                 // SSN
		regexp.MustCompile(`(?i)\d{2}-\d{6}`),                   // Case number (YY-XXXXXX)
		regexp.MustCompile(`(?i)fbi\s*\d{8,10}`),                // FBI number
		regexp.MustCompile(`(?i)ncic\s*\d{8,12}`),               // NCIC number
		regexp.MustCompile(`(?i)ori\s*[A-Za-z0-9]{7,9}`),        // ORI number
		regexp.MustCompile(`(?i)\d{2}[/-]\d{2}[/-]\d{4}`),       // Date of birth
		regexp.MustCompile(`(?i)case\s*#\s*\d{2}-\d{6}`),        // Case number with prefix
		regexp.MustCompile(`(?i)arrest\s*#\s*[A-Za-z0-9-]+`),    // Arrest number
		regexp.MustCompile(`(?i)offender\s*id\s*[A-Za-z0-9-]+`), // Offender ID
	}
}

// registerControls registers all CJIS Security Policy v5.9.1 controls.
func (m *CJISModule) registerControls() {
	// Information Management (IM)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IM-001",
		Name:        "Information Management Policy",
		Description: "Policies and procedures for managing Criminal Justice Information throughout its lifecycle",
		Category:    "Information Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInformationManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IM-002",
		Name:        "Media Protection",
		Description: "Protect CJI stored on physical and electronic media through encryption and access controls",
		Category:    "Information Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMediaProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IM-003",
		Name:        "Record Retention",
		Description: "Implement data retention policies for Criminal Justice Information in compliance with CJIS requirements",
		Category:    "Information Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRecordRetention,
	})

	// Personnel Security (PS)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PS-001",
		Name:        "Personnel Security Policy",
		Description: "Ensure all personnel with CJI access undergo background checks and security screening",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPersonnelSecurity,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PS-002",
		Name:        "Security Awareness Training",
		Description: "Provide security awareness training for all personnel accessing CJI",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityAwarenessTraining,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PS-003",
		Name:        "Incident Response Training",
		Description: "Provide incident response training for personnel with CJI access",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponseTraining,
	})

	// Access Control (AC)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-001",
		Name:        "Access Control Policy",
		Description: "Implement role-based access controls to restrict CJI access to authorized personnel",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccessControl,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-002",
		Name:        "Account Management",
		Description: "Implement procedures for creating, managing, and disabling accounts with CJI access",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccountManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-003",
		Name:        "Audit and Accountability",
		Description: "Implement audit logging for all access to Criminal Justice Information",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAuditAccountability,
	})

	// Physical Protection (PP)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PP-001",
		Name:        "Physical Protection Policy",
		Description: "Implement physical security controls for facilities housing CJI systems (customer responsibility)",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PP-002",
		Name:        "Mobile Device Security",
		Description: "Implement mobile device management for all devices that access CJI",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMobileDeviceSecurity,
	})

	// Cryptography (CR)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CR-001",
		Name:        "Encryption at Rest",
		Description: "Encrypt CJI at rest using FIPS 140-2 validated cryptographic modules (AES-256)",
		Category:    "Cryptography",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionAtRest,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CR-002",
		Name:        "Encryption in Transit",
		Description: "Encrypt CJI in transit using TLS 1.2 or higher (TLS 1.3 recommended)",
		Category:    "Cryptography",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionInTransit,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CR-003",
		Name:        "Key Management",
		Description: "Implement cryptographic key management procedures including rotation and secure storage",
		Category:    "Cryptography",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkKeyManagement,
	})

	// AI-Specific (AI)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AI-001",
		Name:        "AI Model CJI Protection",
		Description: "Ensure AI models do not retain or expose Criminal Justice Information",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelCJIProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AI-002",
		Name:        "AI Audit Trail",
		Description: "Maintain audit trails for all AI model interactions involving Criminal Justice Information",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrail,
	})
}

// Check implementations

func (m *CJISModule) checkInformationManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInfoPolicy := strings.Contains(inputStr, "information_management_policy") || strings.Contains(inputStr, "data_classification")

	if hasInfoPolicy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IM-001",
			ControlName: "Information Management Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Information management policy and data classification controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IM-001",
		ControlName: "Information Management Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Information management policy and data classification controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement information management policy with CJI data classification",
	}, nil
}

func (m *CJISModule) checkMediaProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMediaProtection := strings.Contains(inputStr, "media_protection")
	hasEncryptionAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "disk_encrypted")

	if hasMediaProtection && hasEncryptionAtRest {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IM-002",
			ControlName: "Media Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Media protection and encryption at rest detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasMediaProtection || hasEncryptionAtRest {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IM-002",
			ControlName: "Media Protection",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial media protection controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement both media protection policies and encryption at rest for CJI media",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IM-002",
		ControlName: "Media Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No media protection controls detected",
		Timestamp:   time.Now(),
		Remediation: "Implement media protection policies and encryption at rest for all CJI storage media",
	}, nil
}

func (m *CJISModule) checkRecordRetention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRecordRetention := strings.Contains(inputStr, "record_retention") || strings.Contains(inputStr, "data_retention_policy")

	if hasRecordRetention {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IM-003",
			ControlName: "Record Retention",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Record retention policy detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IM-003",
		ControlName: "Record Retention",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Record retention policy not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement CJI record retention policies per CJIS Security Policy requirements",
	}, nil
}

func (m *CJISModule) checkPersonnelSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPersonnelSecurity := strings.Contains(inputStr, "personnel_security") || strings.Contains(inputStr, "background_checks") || strings.Contains(inputStr, "screening")

	if hasPersonnelSecurity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-PS-001",
			ControlName: "Personnel Security Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Personnel security screening and background checks detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-PS-001",
		ControlName: "Personnel Security Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Personnel security controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement background checks and security screening for all personnel with CJI access",
	}, nil
}

func (m *CJISModule) checkSecurityAwarenessTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTraining := strings.Contains(inputStr, "security_training") || strings.Contains(inputStr, "security_awareness")

	if hasTraining {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-PS-002",
			ControlName: "Security Awareness Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Security awareness training program detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-PS-002",
		ControlName: "Security Awareness Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Security awareness training program not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement mandatory security awareness training for all CJI access personnel",
	}, nil
}

func (m *CJISModule) checkIncidentResponseTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRTraining := strings.Contains(inputStr, "incident_response_training") || strings.Contains(inputStr, "ir_training")

	if hasIRTraining {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-PS-003",
			ControlName: "Incident Response Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Incident response training program detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-PS-003",
		ControlName: "Incident Response Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Incident response training program not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement incident response training for all personnel with CJI access",
	}, nil
}

func (m *CJISModule) checkAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccessControl := strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac")

	if hasAccessControl {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AC-001",
			ControlName: "Access Control Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Access control policy with RBAC detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AC-001",
		ControlName: "Access Control Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Access control policy not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement role-based access control for all CJI systems",
	}, nil
}

func (m *CJISModule) checkAccountManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccountMgmt := strings.Contains(inputStr, "account_management") || strings.Contains(inputStr, "user_provisioning")

	if hasAccountMgmt {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AC-002",
			ControlName: "Account Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Account management and user provisioning controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AC-002",
		ControlName: "Account Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Account management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement account management procedures including user provisioning and deprovisioning",
	}, nil
}

func (m *CJISModule) checkAuditAccountability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled") || strings.Contains(inputStr, "logging_enabled")

	if hasAuditLog {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AC-003",
			ControlName: "Audit and Accountability",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Audit logging and accountability controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AC-003",
		ControlName: "Audit and Accountability",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Audit logging controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable comprehensive audit logging for all CJI access events",
	}, nil
}

func (m *CJISModule) checkMobileDeviceSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMDM := strings.Contains(inputStr, "mobile_device_management") || strings.Contains(inputStr, "mdm") || strings.Contains(inputStr, "device_enrollment")

	if hasMDM {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-PP-002",
			ControlName: "Mobile Device Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Mobile device management and enrollment controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-PP-002",
		ControlName: "Mobile Device Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Mobile device management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement mobile device management for all devices that access CJI",
	}, nil
}

func (m *CJISModule) checkEncryptionAtRest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptionAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted") || strings.Contains(inputStr, "aes_256") || strings.Contains(inputStr, "fips")

	if hasEncryptionAtRest {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-CR-001",
			ControlName: "Encryption at Rest",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "CJI encryption at rest with FIPS-validated module detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-CR-001",
		ControlName: "Encryption at Rest",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "CJI encryption at rest not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement AES-256 encryption at rest with FIPS 140-2 validated modules for all CJI storage",
	}, nil
}

func (m *CJISModule) checkEncryptionInTransit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS13 := strings.Contains(inputStr, "tls1.3") || strings.Contains(inputStr, "tls_13")
	hasTLS := strings.Contains(inputStr, "https") || strings.Contains(inputStr, "tls")

	if hasTLS13 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-CR-002",
			ControlName: "Encryption in Transit",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS 1.3 enabled for CJI transmission security",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-CR-002",
			ControlName: "Encryption in Transit",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS detected but not TLS 1.3",
			Timestamp:   time.Now(),
			Remediation: "Upgrade to TLS 1.3 for maximum CJI transmission security per CJIS requirements",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-CR-002",
		ControlName: "Encryption in Transit",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No TLS encryption detected for CJI in transit",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.3 for all CJI data transmission per CJIS Security Policy",
	}, nil
}

func (m *CJISModule) checkKeyManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasKeyManagement := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "kms")

	if hasKeyManagement {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-CR-003",
			ControlName: "Key Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic key management and rotation controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-CR-003",
		ControlName: "Key Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cryptographic key management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement key management procedures including rotation and secure storage per CJIS requirements",
	}, nil
}

func (m *CJISModule) checkAIModelCJIProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	cjiFound := m.detectCJI(string(input))

	if len(cjiFound) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AI-001",
			ControlName: "AI Model CJI Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No Criminal Justice Information detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AI-001",
		ControlName: "AI Model CJI Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Criminal Justice Information patterns detected in AI model data",
		Details:     "Detected CJI patterns in input data",
		Timestamp:   time.Now(),
		Remediation: "Implement CJI scrubbing for all AI model inputs and outputs per CJIS Security Policy",
	}, nil
}

func (m *CJISModule) checkAIAuditTrail(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := strings.Contains(inputStr, "audit_log")
	hasAIAuditTrail := strings.Contains(inputStr, "ai_audit_trail")
	hasModelLogging := strings.Contains(inputStr, "model_logging")

	violations := []string{}
	if !hasAuditLog {
		violations = append(violations, "audit log")
	}
	if !hasAIAuditTrail {
		violations = append(violations, "AI audit trail")
	}
	if !hasModelLogging {
		violations = append(violations, "model logging")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AI-002",
			ControlName: "AI Audit Trail",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI audit trail with model logging detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if len(violations) < 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AI-002",
			ControlName: "AI Audit Trail",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AI audit controls: missing " + strings.Join(violations, ", "),
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive AI audit trail including audit_log, ai_audit_trail, and model_logging",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AI-002",
		ControlName: "AI Audit Trail",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI audit trail controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement audit logging, AI audit trail, and model logging for all CJI-related AI interactions",
	}, nil
}

// detectCJI scans input for potential Criminal Justice Information patterns.
func (m *CJISModule) detectCJI(input string) []string {
	found := []string{}
	for _, pattern := range m.cjiPatterns {
		if pattern.MatchString(input) {
			found = append(found, pattern.String())
		}
	}
	return found
}

// Dependencies returns required modules.
func (m *CJISModule) Dependencies() []string {
	return []string{"scanner"}
}
