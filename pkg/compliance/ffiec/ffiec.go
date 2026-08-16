// Package ffiec provides FFIEC compliance controls as a licensed add-on module.
// FFIEC (Federal Financial Institutions Examination Council) provides interagency
// guidance for banking and financial institutions covering information security,
// authentication, IT examination, and outsourcing/vendor management.
package ffiec

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// FFIECModule implements FFIEC compliance controls.
type FFIECModule struct {
	*compliance.BaseComplianceModule
	infoSecPatterns     []*regexp.Regexp
	authPatterns        []*regexp.Regexp
	examPatterns        []*regexp.Regexp
	outsourcingPatterns []*regexp.Regexp
}

// NewFFIECModule creates a new FFIEC compliance module.
func NewFFIECModule() *FFIECModule {
	m := &FFIECModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("ffiec", "FFIEC-2024", core.TierProfessional),
	}

	m.initPatterns()
	m.registerControls()

	return m
}

func (m *FFIECModule) initPatterns() {
	m.infoSecPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)FFIEC`),
		regexp.MustCompile(`(?i)federal\s*financial`),
		regexp.MustCompile(`(?i)examination`),
		regexp.MustCompile(`(?i)banking\s*regulator`),
	}
	m.authPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)multi\s*factor`),
		regexp.MustCompile(`(?i)\bMFA\b`),
		regexp.MustCompile(`(?i)strong\s*authentication`),
		regexp.MustCompile(`(?i)transaction\s*signing`),
	}
	m.examPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)penetration\s*test`),
		regexp.MustCompile(`(?i)vulnerability\s*assessment`),
		regexp.MustCompile(`(?i)audit\s*program`),
	}
	m.outsourcingPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)third\s*party`),
		regexp.MustCompile(`(?i)vendor`),
		regexp.MustCompile(`(?i)outsourcing`),
		regexp.MustCompile(`(?i)service\s*provider`),
	}
}

func (m *FFIECModule) registerControls() {
	// Information Security (IS)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-001",
		Name:        "Information Security Program",
		Description: "Financial institutions must establish a formal information security program aligned with FFIEC guidance",
		Category:    "Information Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkInfoSecProgram,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-002",
		Name:        "Risk Assessment",
		Description: "Institutions must conduct periodic risk assessments of information systems and operations",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-003",
		Name:        "Board/Management Oversight",
		Description: "Board of directors and senior management must oversee the information security program",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBoardOversight,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-004",
		Name:        "Security Controls Validation",
		Description: "Institutions must validate the effectiveness of security controls through testing and monitoring",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityControlsValidation,
	})

	// Authentication (AU)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AU-001",
		Name:        "Multi-Factor Authentication",
		Description: "Financial institutions must implement multi-factor authentication for high-risk transactions",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMFA,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AU-002",
		Name:        "Customer Authentication Strength",
		Description: "Customer authentication mechanisms must be assessed for strength and layered security",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCustomerAuthStrength,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AU-003",
		Name:        "Transaction Authentication",
		Description: "High-risk transactions must employ transaction-level authentication and signing",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTransactionAuth,
	})

	// IT Examination (EX)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-001",
		Name:        "Audit Program",
		Description: "Institutions must maintain a comprehensive IT audit program aligned with FFIEC examination standards",
		Category:    "IT Examination",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditProgram,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-002",
		Name:        "Vulnerability Assessment",
		Description: "Institutions must conduct regular vulnerability assessments of information systems",
		Category:    "IT Examination",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityAssessment,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-003",
		Name:        "Penetration Testing",
		Description: "Institutions must perform periodic penetration testing to validate security posture",
		Category:    "IT Examination",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPenetrationTesting,
	})

	// Outsourcing (OS)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-OS-001",
		Name:        "Third-Party Provider Risk",
		Description: "Institutions must assess and manage risk associated with third-party technology service providers",
		Category:    "Outsourcing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThirdPartyRisk,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-OS-002",
		Name:        "Vendor Management Program",
		Description: "Institutions must maintain a vendor management program covering due diligence, contracts, and ongoing monitoring",
		Category:    "Outsourcing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVendorManagement,
	})
}

// CheckFunc implementations — each returns *compliance.ControlCheckResult.

func (m *FFIECModule) checkInfoSecProgram(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.infoSecPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "FFIEC-IS-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "FFIEC information security program reference detected",
				Details:   "FFIEC requires a formal information security program aligned with interagency guidance",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-IS-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No information security program patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "risk assessment") && (strings.Contains(content, "ffiec") || strings.Contains(content, "banking") || strings.Contains(content, "financial")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-IS-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Risk assessment reference detected — verify periodic FFIEC-aligned assessment",
			Details:   "Institutions must conduct periodic risk assessments of information systems and operations",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-IS-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No risk assessment patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkBoardOversight(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if (strings.Contains(content, "board") || strings.Contains(content, "management oversight")) && (strings.Contains(content, "security") || strings.Contains(content, "ffiec")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-IS-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Board/management oversight reference detected — verify security program governance",
			Details:   "Board of directors and senior management must oversee the information security program",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-IS-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No board/management oversight patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkSecurityControlsValidation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "security controls") && (strings.Contains(content, "validation") || strings.Contains(content, "testing") || strings.Contains(content, "monitoring")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-IS-004",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Security controls validation reference detected — verify control effectiveness testing",
			Details:   "Institutions must validate the effectiveness of security controls through testing and monitoring",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-IS-004",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No security controls validation patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkMFA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.authPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "FFIEC-AU-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Multi-factor authentication reference detected — verify MFA for high-risk transactions",
				Details:   "FFIEC requires multi-factor authentication for high-risk transactions",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-AU-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No multi-factor authentication patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkCustomerAuthStrength(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "authentication") && (strings.Contains(content, "customer") || strings.Contains(content, "layered")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-AU-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Customer authentication reference detected — verify layered security and strength assessment",
			Details:   "Customer authentication mechanisms must be assessed for strength and layered security",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-AU-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No customer authentication strength patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkTransactionAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "transaction") && (strings.Contains(content, "signing") || strings.Contains(content, "authentication") || strings.Contains(content, "sign")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-AU-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Transaction authentication reference detected — verify transaction-level authentication",
			Details:   "High-risk transactions must employ transaction-level authentication and signing",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-AU-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No transaction authentication patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkAuditProgram(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.examPatterns {
		if p.MatchString(content) && strings.Contains(strings.ToLower(string(input)), "audit") {
			return &compliance.ControlCheckResult{
				ControlID: "FFIEC-EX-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityHigh,
				Message:   "IT audit program reference detected — verify FFIEC examination alignment",
				Details:   "Institutions must maintain a comprehensive IT audit program aligned with FFIEC examination standards",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-EX-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No audit program patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkVulnerabilityAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "vulnerability assessment") || strings.Contains(content, "vulnerability scan") {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-EX-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Vulnerability assessment reference detected — verify regular assessment schedule",
			Details:   "Institutions must conduct regular vulnerability assessments of information systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-EX-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No vulnerability assessment patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkPenetrationTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "penetration test") || strings.Contains(content, "pentest") {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-EX-003",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Penetration testing reference detected — verify periodic testing program",
			Details:   "Institutions must perform periodic penetration testing to validate security posture",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-EX-003",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No penetration testing patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkThirdPartyRisk(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.outsourcingPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "FFIEC-OS-001",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityHigh,
				Message:   "Third-party provider reference detected — verify risk assessment of service providers",
				Details:   "Institutions must assess and manage risk associated with third-party technology service providers",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-OS-001",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No third-party provider risk patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkVendorManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "vendor") && (strings.Contains(content, "management") || strings.Contains(content, "due diligence") || strings.Contains(content, "contract") || strings.Contains(content, "monitoring")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-OS-002",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Vendor management reference detected — verify program covers due diligence and monitoring",
			Details:   "Institutions must maintain a vendor management program covering due diligence, contracts, and ongoing monitoring",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-OS-002",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No vendor management patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// GetPatterns returns the detection patterns for this module.
func (m *FFIECModule) GetPatterns() []*regexp.Regexp {
	var all []*regexp.Regexp
	all = append(all, m.infoSecPatterns...)
	all = append(all, m.authPatterns...)
	all = append(all, m.examPatterns...)
	all = append(all, m.outsourcingPatterns...)
	return all
}

// Framework returns the framework identifier.
func (m *FFIECModule) Framework() string {
	return "FFIEC"
}

// Version returns the framework version.
func (m *FFIECModule) Version() string {
	return "2024"
}

// LastUpdated returns the last update time.
func (m *FFIECModule) LastUpdated() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}

// String returns a string representation.
func (m *FFIECModule) String() string {
	return fmt.Sprintf("FFIEC Module (v%s, %d controls)", m.Version(), len(m.infoSecPatterns)+len(m.authPatterns)+len(m.examPatterns)+len(m.outsourcingPatterns))
}
