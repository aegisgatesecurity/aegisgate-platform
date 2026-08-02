// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// GLBA Compliance Module
// =========================================================================

package glba

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// GLBAModule implements GLBA (Gramm-Leach-Bliley Act) compliance controls.
type GLBAModule struct {
	*compliance.BaseComplianceModule
	npiPatterns []*regexp.Regexp
}

// NewGLBAModule creates a new GLBA compliance module.
func NewGLBAModule() *GLBAModule {
	m := &GLBAModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("glba", "1999", core.TierProfessional),
	}

	m.initNPIPatterns()
	m.registerControls()

	return m
}

// initNPIPatterns initializes patterns for detecting nonpublic personal information.
func (m *GLBAModule) initNPIPatterns() {
	m.npiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),                                          // SSN
		regexp.MustCompile(`(?i)\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`),                 // Credit card
		regexp.MustCompile(`(?i)account\s*(?:number|#)?\s*[A-Za-z0-9]{6,20}`),             // Bank account
		regexp.MustCompile(`(?i)credit\s*score\s*:?\s*\d{3}`),                            // Credit score
		regexp.MustCompile(`(?i)nonpublic\s*personal|npi|financial\s*privacy`),            // GLBA marker
	}
}

// registerControls registers all GLBA compliance controls.
func (m *GLBAModule) registerControls() {
	// Financial Privacy Rule (FP)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-FP-001",
		Name:        "Privacy Notice",
		Description: "Financial institutions must provide clear privacy notices to customers",
		Category:    "Financial Privacy Rule",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPrivacyNotice,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-FP-002",
		Name:        "Opt-Out Rights",
		Description: "Customers must have the right to opt out of information sharing",
		Category:    "Financial Privacy Rule",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkOptOutRights,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-FP-003",
		Name:        "Information Sharing Safeguards",
		Description: "Controls on sharing NPI with nonaffiliated third parties",
		Category:    "Financial Privacy Rule",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInformationSharingSafeguards,
	})

	// Safeguards Rule (SG)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-SG-001",
		Name:        "Information Security Program",
		Description: "Develop, implement, and maintain a comprehensive information security program",
		Category:    "Safeguards Rule",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkInformationSecurityProgram,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-SG-002",
		Name:        "Risk Assessment",
		Description: "Regular risk assessments for NPI handling",
		Category:    "Safeguards Rule",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-SG-003",
		Name:        "Access Controls",
		Description: "Logical and physical access controls for NPI",
		Category:    "Safeguards Rule",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccessControls,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-SG-004",
		Name:        "Vendor Management",
		Description: "Oversight of service providers handling NPI",
		Category:    "Safeguards Rule",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVendorManagement,
	})

	// Data Protection (DP)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-DP-001",
		Name:        "Encryption at Rest",
		Description: "NPI must be encrypted at rest",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionAtRest,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-DP-002",
		Name:        "Encryption in Transit",
		Description: "NPI must be encrypted in transit (TLS 1.2+)",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionInTransit,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-DP-003",
		Name:        "Data Retention and Disposal",
		Description: "Policies for NPI retention and secure disposal",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataRetentionDisposal,
	})

	// Pretexting Protection (PP)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-PP-001",
		Name:        "Pretexting Prevention (Section 521)",
		Description: "Prohibit obtaining NPI through false pretenses",
		Category:    "Pretexting Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPretextingPrevention,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-PP-002",
		Name:        "Customer Authentication",
		Description: "Strong customer authentication for NPI access",
		Category:    "Pretexting Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCustomerAuthentication,
	})

	// AI-Specific (AI)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-AI-001",
		Name:        "AI Model NPI Protection",
		Description: "AI models must not retain or expose nonpublic personal information",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelNPIProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GLBA-AI-002",
		Name:        "AI Audit Trail for Financial Privacy",
		Description: "Audit logging for AI interactions involving NPI",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrailFinancialPrivacy,
	})
}

// Check implementations

// Financial Privacy Rule checks

func (m *GLBAModule) checkPrivacyNotice(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPrivacyNotice := strings.Contains(inputStr, "privacy_notice") || strings.Contains(inputStr, "privacy_disclosure") || strings.Contains(inputStr, "initial_notice")

	if hasPrivacyNotice {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-FP-001",
			ControlName: "Privacy Notice",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Privacy notice and disclosure controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-FP-001",
		ControlName: "Privacy Notice",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Privacy notice controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement clear privacy notices and initial disclosures to customers per GLBA Financial Privacy Rule",
	}, nil
}

func (m *GLBAModule) checkOptOutRights(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasOptOut := strings.Contains(inputStr, "opt_out") || strings.Contains(inputStr, "information_sharing_opt_out") || strings.Contains(inputStr, "privacy_choice")

	if hasOptOut {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-FP-002",
			ControlName: "Opt-Out Rights",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Opt-out rights and privacy choice controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-FP-002",
		ControlName: "Opt-Out Rights",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Opt-out rights controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement opt-out rights allowing customers to restrict information sharing per GLBA Financial Privacy Rule",
	}, nil
}

func (m *GLBAModule) checkInformationSharingSafeguards(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSharingSafeguards := strings.Contains(inputStr, "information_sharing") || strings.Contains(inputStr, "third_party_sharing") || strings.Contains(inputStr, "nonaffiliated_disclosure")

	if hasSharingSafeguards {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-FP-003",
			ControlName: "Information Sharing Safeguards",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Information sharing safeguards and nonaffiliated disclosure controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-FP-003",
		ControlName: "Information Sharing Safeguards",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Information sharing safeguards not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement controls for sharing NPI with nonaffiliated third parties per GLBA Financial Privacy Rule",
	}, nil
}

// Safeguards Rule checks

func (m *GLBAModule) checkInformationSecurityProgram(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecProgram := strings.Contains(inputStr, "security_program") || strings.Contains(inputStr, "information_security_plan") || strings.Contains(inputStr, "risk_assessment")

	if hasSecProgram {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-SG-001",
			ControlName: "Information Security Program",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Information security program and risk assessment controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-SG-001",
		ControlName: "Information Security Program",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Information security program controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Develop and implement a comprehensive information security program per GLBA Safeguards Rule",
	}, nil
}

func (m *GLBAModule) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRiskAssessment := strings.Contains(inputStr, "risk_assessment") || strings.Contains(inputStr, "npi_risk") || strings.Contains(inputStr, "threat_analysis")

	if hasRiskAssessment {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-SG-002",
			ControlName: "Risk Assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "NPI risk assessment and threat analysis controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-SG-002",
		ControlName: "Risk Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "NPI risk assessment controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement regular risk assessments for NPI handling per GLBA Safeguards Rule",
	}, nil
}

func (m *GLBAModule) checkAccessControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccessControl := strings.Contains(inputStr, "access_control")
	hasRBAC := strings.Contains(inputStr, "rbac")
	hasNPIAccess := strings.Contains(inputStr, "npi_access")

	detected := []string{}
	if hasAccessControl {
		detected = append(detected, "access controls")
	}
	if hasRBAC {
		detected = append(detected, "RBAC")
	}
	if hasNPIAccess {
		detected = append(detected, "NPI access controls")
	}

	if len(detected) == 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-SG-003",
			ControlName: "Access Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Comprehensive NPI access controls detected: access controls, RBAC, and NPI access restrictions",
			Timestamp:   time.Now(),
		}, nil
	}

	if len(detected) > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-SG-003",
			ControlName: "Access Controls",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial access controls detected: " + strings.Join(detected, ", "),
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive access controls including access_control, rbac, and npi_access for NPI per GLBA Safeguards Rule",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-SG-003",
		ControlName: "Access Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "NPI access controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement logical and physical access controls for NPI including RBAC per GLBA Safeguards Rule",
	}, nil
}

func (m *GLBAModule) checkVendorManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVendorMgmt := strings.Contains(inputStr, "vendor_management") || strings.Contains(inputStr, "service_provider") || strings.Contains(inputStr, "contractual_safeguards")

	if hasVendorMgmt {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-SG-004",
			ControlName: "Vendor Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vendor management and service provider oversight controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-SG-004",
		ControlName: "Vendor Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vendor management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement vendor management and service provider oversight with contractual safeguards per GLBA Safeguards Rule",
	}, nil
}

// Data Protection checks

func (m *GLBAModule) checkEncryptionAtRest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryption := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted") || strings.Contains(inputStr, "aes_256")

	if hasEncryption {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-DP-001",
			ControlName: "Encryption at Rest",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "NPI encryption at rest controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-DP-001",
		ControlName: "Encryption at Rest",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "NPI encryption at rest controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement encryption at rest for all NPI using AES-256 or equivalent per GLBA Safeguards Rule",
	}, nil
}

func (m *GLBAModule) checkEncryptionInTransit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS13 := strings.Contains(inputStr, "tls1.3") || strings.Contains(inputStr, "tls_13")
	hasHTTPS := strings.Contains(inputStr, "https")

	if hasTLS13 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-DP-002",
			ControlName: "Encryption in Transit",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "NPI encryption in transit with TLS 1.3 detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasHTTPS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-DP-002",
			ControlName: "Encryption in Transit",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "HTTPS detected but TLS 1.3 not confirmed; NPI requires strong transit encryption",
			Timestamp:   time.Now(),
			Remediation: "Upgrade to TLS 1.3 for all NPI in-transit encryption per GLBA Safeguards Rule",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-DP-002",
		ControlName: "Encryption in Transit",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "NPI encryption in transit controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement TLS 1.2+ encryption for all NPI in transit per GLBA Safeguards Rule",
	}, nil
}

func (m *GLBAModule) checkDataRetentionDisposal(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRetention := strings.Contains(inputStr, "data_retention") || strings.Contains(inputStr, "secure_disposal") || strings.Contains(inputStr, "npi_retention")

	if hasRetention {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-DP-003",
			ControlName: "Data Retention and Disposal",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "NPI data retention and secure disposal controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-DP-003",
		ControlName: "Data Retention and Disposal",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "NPI data retention and disposal controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement data retention and secure disposal policies for NPI per GLBA Safeguards Rule",
	}, nil
}

// Pretexting Protection checks

func (m *GLBAModule) checkPretextingPrevention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPretexting := strings.Contains(inputStr, "pretexting_prevention") || strings.Contains(inputStr, "fraud_detection") || strings.Contains(inputStr, "identity_verification")

	if hasPretexting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-PP-001",
			ControlName: "Pretexting Prevention (Section 521)",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Pretexting prevention and identity verification controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-PP-001",
		ControlName: "Pretexting Prevention (Section 521)",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Pretexting prevention controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement pretexting prevention, fraud detection, and identity verification per GLBA Section 521",
	}, nil
}

func (m *GLBAModule) checkCustomerAuthentication(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "customer_authentication") || strings.Contains(inputStr, "mfa") || strings.Contains(inputStr, "identity_verification")

	if hasAuth {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-PP-002",
			ControlName: "Customer Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Customer authentication and MFA controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-PP-002",
		ControlName: "Customer Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Customer authentication controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement strong customer authentication including MFA for NPI access per GLBA",
	}, nil
}

// AI-Specific checks

func (m *GLBAModule) checkAIModelNPIProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	npiFound := m.detectNPI(string(input))

	if len(npiFound) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-AI-001",
			ControlName: "AI Model NPI Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No NPI detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-AI-001",
		ControlName: "AI Model NPI Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "NPI patterns detected in AI model data",
		Details:     "Detected NPI patterns in input data",
		Timestamp:   time.Now(),
		Remediation: "Implement NPI scrubbing for all AI model inputs and outputs per GLBA requirements",
	}, nil
}

func (m *GLBAModule) checkAIAuditTrailFinancialPrivacy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditTrail := strings.Contains(inputStr, "ai_audit_trail")
	hasModelLogging := strings.Contains(inputStr, "model_logging")
	hasNPIAuditLog := strings.Contains(inputStr, "npi_audit_log")

	violations := []string{}
	if !hasAuditTrail {
		violations = append(violations, "AI audit trail")
	}
	if !hasModelLogging {
		violations = append(violations, "model logging")
	}
	if !hasNPIAuditLog {
		violations = append(violations, "NPI audit log")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-AI-002",
			ControlName: "AI Audit Trail for Financial Privacy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI audit trail with NPI audit logging detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if len(violations) < 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "GLBA-AI-002",
			ControlName: "AI Audit Trail for Financial Privacy",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AI audit controls: missing " + strings.Join(violations, ", "),
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive AI audit trail including ai_audit_trail, model_logging, and npi_audit_log",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "GLBA-AI-002",
		ControlName: "AI Audit Trail for Financial Privacy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI audit trail controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement AI audit trail, model logging, and NPI audit logging for all AI interactions involving financial data",
	}, nil
}

// detectNPI scans input for potential nonpublic personal information patterns.
func (m *GLBAModule) detectNPI(input string) []string {
	found := []string{}
	for _, pattern := range m.npiPatterns {
		if pattern.MatchString(input) {
			found = append(found, pattern.String())
		}
	}
	return found
}

// Dependencies returns required modules.
func (m *GLBAModule) Dependencies() []string {
	return []string{"scanner"}
}