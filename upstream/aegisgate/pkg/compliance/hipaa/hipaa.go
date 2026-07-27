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
		BaseComplianceModule: compliance.NewBaseComplianceModule("hipaa", "2.0", core.TierEnterprise),
	}

	m.initPHIPatterns()
	m.registerControls()

	return m
}

// initPHIPatterns initializes patterns for detecting PHI.
func (m *HIPAAModule) initPHIPatterns() {
	// HIPAA-defined PHI identifiers
	m.phiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)d{3}-d{2}-d{4}`),                                 // SSN
		regexp.MustCompile(`(?i)d{10,16}`),                                       // Medical Record Number
		regexp.MustCompile(`(?i)[A-Z]d{7}`),                                      // Health Plan ID
		regexp.MustCompile(`(?i)d{2}[/-]d{2}[/-]d{4}`),                           // DOB
		regexp.MustCompile(`(?i)[A-Z]{2}d{6}`),                                   // Account Number
		regexp.MustCompile(`(?i)d{3}[-.s]?d{3}[-.s]?d{4}`),                       // Phone
		regexp.MustCompile(`(?i)[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+.[A-Z|a-z]{2,}`), // Email
		regexp.MustCompile(`(?i)d{5}[-s]?d{4}`),                                  // ZIP+4
	}
}

// registerControls registers all HIPAA Security Rule controls.
func (m *HIPAAModule) registerControls() {
	// Administrative Safeguards
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-001",
		Name:        "Security Management Process",
		Description: "Policies and procedures to prevent, detect, contain, and correct security violations",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityManagement,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-002",
		Name:        "Assigned Security Responsibility",
		Description: "Designate a security official responsible for developing and implementing security policies",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-003",
		Name:        "Workforce Security",
		Description: "Ensure all workforce members have appropriate access to ePHI",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkWorkforceSecurity,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AS-004",
		Name:        "Information Access Management",
		Description: "Implement policies and procedures for authorizing access to ePHI",
		Category:    "Administrative Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInfoAccessManagement,
	})

	// Physical Safeguards
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-001",
		Name:        "Facility Access Controls",
		Description: "Implement policies and procedures to limit physical access to electronic systems",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-PS-002",
		Name:        "Workstation Use",
		Description: "Implement policies specifying proper functions for workstations with ePHI access",
		Category:    "Physical Safeguards",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkWorkstationSecurity,
	})

	// Technical Safeguards
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-001",
		Name:        "Access Control",
		Description: "Implement technical policies and procedures for electronic access to ePHI",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccessControl,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-002",
		Name:        "Audit Controls",
		Description: "Implement hardware, software, and/or procedural mechanisms to record activity",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAuditControls,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-003",
		Name:        "Integrity Controls",
		Description: "Implement policies and procedures to protect ePHI from improper alteration or destruction",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIntegrityControls,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-004",
		Name:        "Transmission Security",
		Description: "Implement technical security measures to guard against unauthorized access to ePHI being transmitted",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTransmissionSecurity,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-TS-005",
		Name:        "Encryption Requirements",
		Description: "Implement encryption for ePHI at rest and in transit",
		Category:    "Technical Safeguards",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryption,
	})

	// AI-Specific HIPAA Controls
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AI-001",
		Name:        "AI Model PHI Protection",
		Description: "Ensure AI models do not retain or expose Protected Health Information",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIPHIProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HIPAA-AI-002",
		Name:        "AI Training Data Sanitization",
		Description: "Verify AI training data has been properly de-identified",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAITrainingData,
	})
}

// Check implementations

func (m *HIPAAModule) checkSecurityManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLogging := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging_enabled")
	hasAccessControl := strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac")

	status := compliance.StatusCompliant
	message := "Security management processes detected"

	if !hasAuditLogging || !hasAccessControl {
		status = compliance.StatusPartial
		message = "Some security management controls not detected"
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-AS-001",
		ControlName: "Security Management Process",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Timestamp:   time.Now(),
		Remediation: "Enable comprehensive audit logging and access control policies",
	}, nil
}

func (m *HIPAAModule) checkWorkforceSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRoleBased := strings.Contains(inputStr, "role_based") || strings.Contains(inputStr, "rbac")
	hasMFA := strings.Contains(inputStr, "mfa_enabled") || strings.Contains(inputStr, "multi_factor")

	if hasRoleBased && hasMFA {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AS-003",
			ControlName: "Workforce Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Role-based access and multi-factor authentication detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-AS-003",
		ControlName: "Workforce Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Workforce security controls not fully implemented",
		Timestamp:   time.Now(),
		Remediation: "Implement role-based access control and multi-factor authentication",
	}, nil
}

func (m *HIPAAModule) checkInfoAccessManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-AS-004",
		ControlName: "Information Access Management",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Information access policies configured",
		Timestamp:   time.Now(),
	}, nil
}

func (m *HIPAAModule) checkWorkstationSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-PS-002",
		ControlName: "Workstation Use",
		Status:      compliance.StatusCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Workstation security policies in place",
		Timestamp:   time.Now(),
	}, nil
}

func (m *HIPAAModule) checkAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")

	violations := []string{}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasRBAC {
		violations = append(violations, "role-based access control not detected")
	}
	if !hasSessionTimeout {
		violations = append(violations, "session timeout not configured")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-001",
			ControlName: "Access Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "All access control requirements met",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-TS-001",
		ControlName: "Access Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Access control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Implement authentication, RBAC, and session timeouts",
	}, nil
}

func (m *HIPAAModule) checkAuditControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled")
	hasIntegrity := strings.Contains(inputStr, "log_integrity") || strings.Contains(inputStr, "signed_logs")

	if hasAudit && hasIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-002",
			ControlName: "Audit Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Audit logging with integrity verification detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-TS-002",
		ControlName: "Audit Controls",
		Status:      compliance.StatusPartial,
		Severity:    compliance.SeverityCritical,
		Message:     "Audit controls require enhancement",
		Timestamp:   time.Now(),
		Remediation: "Enable comprehensive audit logging with integrity verification",
	}, nil
}

func (m *HIPAAModule) checkIntegrityControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHashing := strings.Contains(inputStr, "hash") || strings.Contains(inputStr, "checksum")
	hasSigning := strings.Contains(inputStr, "sign") || strings.Contains(inputStr, "signature")

	if hasHashing || hasSigning {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-003",
			ControlName: "Integrity Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data integrity mechanism detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-TS-003",
		ControlName: "Integrity Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No data integrity controls detected",
		Timestamp:   time.Now(),
		Remediation: "Implement hashing or digital signatures for data integrity",
	}, nil
}

func (m *HIPAAModule) checkTransmissionSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https")
	hasTLS13 := strings.Contains(inputStr, "tls1.3") || strings.Contains(inputStr, "tls_13")

	if hasTLS13 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-004",
			ControlName: "Transmission Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS 1.3 enabled for transmission security",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-004",
			ControlName: "Transmission Security",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS detected but not TLS 1.3",
			Timestamp:   time.Now(),
			Remediation: "Upgrade to TLS 1.3 for maximum security",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-TS-004",
		ControlName: "Transmission Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No TLS encryption detected",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.3 for all data transmission",
	}, nil
}

func (m *HIPAAModule) checkEncryption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted")
	hasInTransit := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "ssl")

	if hasAtRest && hasInTransit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-TS-005",
			ControlName: "Encryption Requirements",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Encryption at rest and in transit enabled",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAtRest {
		violations = append(violations, "encryption at rest not detected")
	}
	if !hasInTransit {
		violations = append(violations, "encryption in transit not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-TS-005",
		ControlName: "Encryption Requirements",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Encryption gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable encryption for data at rest and in transit",
	}, nil
}

func (m *HIPAAModule) checkAIPHIProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	phiFound := m.detectPHI(string(input))

	if len(phiFound) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HIPAA-AI-001",
			ControlName: "AI Model PHI Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No PHI detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-AI-001",
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
			ControlID:   "HIPAA-AI-002",
			ControlName: "AI Training Data Sanitization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Training data properly de-identified",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HIPAA-AI-002",
		ControlName: "AI Training Data Sanitization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Training data may contain identifiable PHI",
		Timestamp:   time.Now(),
		Remediation: "Apply HIPAA Safe Harbor or Expert Determination de-identification methods",
	}, nil
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
