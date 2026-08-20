// Package ffiec provides FFIEC compliance controls as a licensed add-on module.
// FFIEC (Federal Financial Institutions Examination Council) provides interagency
// guidance for banking and financial institutions covering information security,
// authentication, IT examination, outsourcing/vendor management, business continuity,
// data governance, and AI model risk management.
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
	bcPatterns          []*regexp.Regexp
	dgPatterns          []*regexp.Regexp
	aiPatterns          []*regexp.Regexp
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
		regexp.MustCompile(`(?i)incident\s*response`),
		regexp.MustCompile(`(?i)threat\s*intelligence`),
		regexp.MustCompile(`(?i)cybersecurity\s*maturity`),
		regexp.MustCompile(`(?i)security\s*reporting`),
	}
	m.authPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)multi\s*factor`),
		regexp.MustCompile(`(?i)\bMFA\b`),
		regexp.MustCompile(`(?i)strong\s*authentication`),
		regexp.MustCompile(`(?i)transaction\s*signing`),
		regexp.MustCompile(`(?i)layered\s*security`),
		regexp.MustCompile(`(?i)fraud\s*detection`),
		regexp.MustCompile(`(?i)customer\s*education`),
	}
	m.examPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)penetration\s*test`),
		regexp.MustCompile(`(?i)vulnerability\s*assessment`),
		regexp.MustCompile(`(?i)audit\s*program`),
		regexp.MustCompile(`(?i)examination\s*readiness`),
		regexp.MustCompile(`(?i)regulatory\s*reporting`),
		regexp.MustCompile(`(?i)self\s*assessment`),
		regexp.MustCompile(`(?i)examiner\s*findings`),
	}
	m.outsourcingPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)third\s*party`),
		regexp.MustCompile(`(?i)vendor`),
		regexp.MustCompile(`(?i)outsourcing`),
		regexp.MustCompile(`(?i)service\s*provider`),
		regexp.MustCompile(`(?i)service\s*level\s*agreement`),
		regexp.MustCompile(`(?i)cloud\s*service`),
		regexp.MustCompile(`(?i)contingency\s*planning`),
	}
	m.bcPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)business\s*continuity`),
		regexp.MustCompile(`(?i)disaster\s*recovery`),
		regexp.MustCompile(`(?i)third\s*party\s*recovery`),
		regexp.MustCompile(`(?i)pandemic\s*planning`),
		regexp.MustCompile(`(?i)incident\s*response\s*coordination`),
		regexp.MustCompile(`(?i)business\s*impact\s*analysis`),
	}
	m.dgPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)data\s*classification`),
		regexp.MustCompile(`(?i)data\s*loss\s*prevention`),
		regexp.MustCompile(`(?i)\bDLP\b`),
		regexp.MustCompile(`(?i)customer\s*data\s*privacy`),
		regexp.MustCompile(`(?i)data\s*retention`),
		regexp.MustCompile(`(?i)data\s*disposal`),
	}
	m.aiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)AI\s*model\s*risk`),
		regexp.MustCompile(`(?i)model\s*validation`),
		regexp.MustCompile(`(?i)AI\s*explainability`),
		regexp.MustCompile(`(?i)credit\s*decision`),
		regexp.MustCompile(`(?i)machine\s*learning`),
		regexp.MustCompile(`(?i)model\s*governance`),
	}
}

func (m *FFIECModule) registerControls() {
	// =========================================================================
	// Information Security (IS) — 8 controls (5 auto, 3 manual)
	// =========================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-01",
		Name:        "Information Security Program",
		Description: "Financial institutions must establish a formal information security program aligned with FFIEC guidance",
		Category:    "Information Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkInfoSecProgram,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-02",
		Name:        "Risk Assessment",
		Description: "Institutions must conduct periodic risk assessments of information systems and operations",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-03",
		Name:        "Board/Management Oversight",
		Description: "Board of directors and senior management must oversee the information security program",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBoardOversight,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-04",
		Name:        "Security Controls Validation",
		Description: "Institutions must validate the effectiveness of security controls through testing and monitoring",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityControlsValidation,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-05",
		Name:        "Incident Response Program",
		Description: "Institutions must maintain a formal incident response program with documented procedures and reporting",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponse,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-06",
		Name:        "Threat Intelligence Program",
		Description: "Institutions should establish a threat intelligence program to identify and respond to emerging cyber threats",
		Category:    "Information Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkThreatIntelProgram,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-07",
		Name:        "Cybersecurity Maturity Assessment",
		Description: "Institutions must assess cybersecurity maturity using the FFIEC Cybersecurity Assessment Tool",
		Category:    "Information Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-IS-08",
		Name:        "Information Security Reporting",
		Description: "Institutions must report information security metrics to the board and senior management periodically",
		Category:    "Information Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================================
	// Authentication (AU) — 6 controls (4 auto, 2 manual)
	// =========================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AU-01",
		Name:        "Multi-Factor Authentication",
		Description: "Financial institutions must implement multi-factor authentication for high-risk transactions",
		Category:    "Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMFA,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AU-02",
		Name:        "Customer Authentication Strength",
		Description: "Customer authentication mechanisms must be assessed for strength and layered security",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCustomerAuthStrength,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AU-03",
		Name:        "Transaction Authentication",
		Description: "High-risk transactions must employ transaction-level authentication and signing",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTransactionAuth,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AU-04",
		Name:        "Layered Security Program",
		Description: "Institutions must implement a layered security program that uses multiple controls to protect high-risk transactions",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLayeredSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AU-05",
		Name:        "Fraud Detection Systems",
		Description: "Institutions must deploy fraud detection systems to monitor and respond to suspicious transaction activity",
		Category:    "Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFraudDetection,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AU-06",
		Name:        "Customer Education on Authentication",
		Description: "Institutions must provide customer education programs on authentication risks and safeguarding credentials",
		Category:    "Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================================
	// IT Examination (EX) — 7 controls (4 auto, 3 manual)
	// =========================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-01",
		Name:        "Audit Program",
		Description: "Institutions must maintain a comprehensive IT audit program aligned with FFIEC examination standards",
		Category:    "IT Examination",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditProgram,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-02",
		Name:        "Vulnerability Assessment",
		Description: "Institutions must conduct regular vulnerability assessments of information systems",
		Category:    "IT Examination",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityAssessment,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-03",
		Name:        "Penetration Testing",
		Description: "Institutions must perform periodic penetration testing to validate security posture",
		Category:    "IT Examination",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPenetrationTesting,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-04",
		Name:        "IT Examination Readiness",
		Description: "Institutions must maintain examination readiness through documentation, evidence, and pre-examination preparation",
		Category:    "IT Examination",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkExamReadiness,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-05",
		Name:        "Regulatory Reporting Requirements",
		Description: "Institutions must meet FFIEC regulatory reporting requirements for IT-related incidents and examinations",
		Category:    "IT Examination",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-06",
		Name:        "Self-Assessment Checklist",
		Description: "Institutions must complete FFIEC self-assessment checklists to evaluate compliance posture before examinations",
		Category:    "IT Examination",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-EX-07",
		Name:        "Examiner Findings Remediation",
		Description: "Institutions must remediate examiner findings within required timeframes and document corrective actions",
		Category:    "IT Examination",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	// =========================================================================
	// Outsourcing (OS) — 6 controls (4 auto, 2 manual)
	// =========================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-OS-01",
		Name:        "Third-Party Provider Risk",
		Description: "Institutions must assess and manage risk associated with third-party technology service providers",
		Category:    "Outsourcing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThirdPartyRisk,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-OS-02",
		Name:        "Vendor Management Program",
		Description: "Institutions must maintain a vendor management program covering due diligence, contracts, and ongoing monitoring",
		Category:    "Outsourcing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVendorManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-OS-03",
		Name:        "Service Level Agreements",
		Description: "Institutions must establish service level agreements with third-party providers defining performance and security expectations",
		Category:    "Outsourcing",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSLA,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-OS-04",
		Name:        "Outsourcing Risk Assessment",
		Description: "Institutions must conduct outsourcing risk assessments covering strategic, operational, and compliance risks",
		Category:    "Outsourcing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkOutsourcingRiskAssessment,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-OS-05",
		Name:        "Cloud Service Provider Due Diligence",
		Description: "Institutions must perform due diligence on cloud service providers including security, compliance, and data residency",
		Category:    "Outsourcing",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-OS-06",
		Name:        "Contingency Planning for Outsourced Services",
		Description: "Institutions must maintain contingency plans for outsourced services including exit strategies and alternative providers",
		Category:    "Outsourcing",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =========================================================================
	// Business Continuity (BC) — 6 controls (3 auto, 3 manual)
	// =========================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-BC-01",
		Name:        "Business Continuity Plan",
		Description: "Institutions must maintain a business continuity plan aligned with FFIEC business continuity management guidance",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBusinessContinuityPlan,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-BC-02",
		Name:        "Disaster Recovery Testing",
		Description: "Institutions must test disaster recovery capabilities periodically to validate recovery objectives",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDisasterRecoveryTesting,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-BC-03",
		Name:        "Third-Party Recovery Capabilities",
		Description: "Institutions must assess third-party service provider recovery capabilities and integrate them into continuity planning",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThirdPartyRecovery,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-BC-04",
		Name:        "Pandemic Planning",
		Description: "Institutions must maintain a pandemic planning framework that addresses workforce and operational resilience",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-BC-05",
		Name:        "Cyber Incident Response Coordination",
		Description: "Institutions must coordinate cyber incident response with business continuity and disaster recovery procedures",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-BC-06",
		Name:        "Business Impact Analysis",
		Description: "Institutions must conduct business impact analyses to identify critical functions and recovery priorities",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBusinessImpactAnalysis,
	})

	// =========================================================================
	// Data Governance (DG) — 4 controls (3 auto, 1 manual)
	// =========================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-DG-01",
		Name:        "Data Classification and Handling",
		Description: "Institutions must implement data classification and handling procedures for sensitive financial information",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataClassification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-DG-02",
		Name:        "Data Loss Prevention",
		Description: "Institutions must deploy data loss prevention controls to protect sensitive customer and institutional data",
		Category:    "Data Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataLossPrevention,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-DG-03",
		Name:        "Customer Data Privacy",
		Description: "Institutions must protect customer data privacy in accordance with FFIEC and GLBA privacy requirements",
		Category:    "Data Governance",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCustomerDataPrivacy,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-DG-04",
		Name:        "Data Retention and Disposal",
		Description: "Institutions must establish data retention and disposal policies aligned with regulatory and operational requirements",
		Category:    "Data Governance",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDataRetentionDisposal,
	})

	// =========================================================================
	// AI Controls (AI) — 3 controls (2 auto, 1 manual)
	// =========================================================================
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AI-01",
		Name:        "AI Model Risk Management for Banking",
		Description: "Institutions must implement AI model risk management practices for models used in banking operations and decision-making",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIModelRisk,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AI-02",
		Name:        "AI Model Validation and Testing",
		Description: "Institutions must validate and test AI models for accuracy, fairness, and robustness before deployment",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIModelValidation,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FFIEC-AI-03",
		Name:        "AI Explainability for Credit Decisions",
		Description: "Institutions must ensure AI models used for credit decisions provide explainability and transparency for regulatory review",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})
}

// =========================================================================
// CheckFunc implementations — each returns *compliance.ControlCheckResult.
// =========================================================================

// ---------------------------------------------------------------------------
// Information Security (IS)
// ---------------------------------------------------------------------------

func (m *FFIECModule) checkInfoSecProgram(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.infoSecPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "FFIEC-IS-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "FFIEC information security program reference detected",
				Details:   "FFIEC requires a formal information security program aligned with interagency guidance",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-IS-01",
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
			ControlID: "FFIEC-IS-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Risk assessment reference detected — verify periodic FFIEC-aligned assessment",
			Details:   "Institutions must conduct periodic risk assessments of information systems and operations",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-IS-02",
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
			ControlID: "FFIEC-IS-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Board/management oversight reference detected — verify security program governance",
			Details:   "Board of directors and senior management must oversee the information security program",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-IS-03",
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
			ControlID: "FFIEC-IS-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Security controls validation reference detected — verify control effectiveness testing",
			Details:   "Institutions must validate the effectiveness of security controls through testing and monitoring",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-IS-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No security controls validation patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkIncidentResponse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "incident response") && (strings.Contains(content, "program") || strings.Contains(content, "plan") || strings.Contains(content, "procedure") || strings.Contains(content, "ffiec")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-IS-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Incident response program reference detected — verify formal procedures and reporting",
			Details:   "Institutions must maintain a formal incident response program with documented procedures and reporting",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-IS-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No incident response program patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ---------------------------------------------------------------------------
// Authentication (AU)
// ---------------------------------------------------------------------------

func (m *FFIECModule) checkMFA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.authPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "FFIEC-AU-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Multi-factor authentication reference detected — verify MFA for high-risk transactions",
				Details:   "FFIEC requires multi-factor authentication for high-risk transactions",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-AU-01",
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
			ControlID: "FFIEC-AU-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Customer authentication reference detected — verify layered security and strength assessment",
			Details:   "Customer authentication mechanisms must be assessed for strength and layered security",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-AU-02",
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
			ControlID: "FFIEC-AU-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Transaction authentication reference detected — verify transaction-level authentication",
			Details:   "High-risk transactions must employ transaction-level authentication and signing",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-AU-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No transaction authentication patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkLayeredSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "layered security") || (strings.Contains(content, "layered") && strings.Contains(content, "security")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-AU-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Layered security program reference detected — verify multiple control layers for high-risk transactions",
			Details:   "Institutions must implement a layered security program using multiple controls to protect high-risk transactions",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-AU-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No layered security program patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ---------------------------------------------------------------------------
// IT Examination (EX)
// ---------------------------------------------------------------------------

func (m *FFIECModule) checkAuditProgram(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.examPatterns {
		if p.MatchString(content) && strings.Contains(strings.ToLower(string(input)), "audit") {
			return &compliance.ControlCheckResult{
				ControlID: "FFIEC-EX-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityHigh,
				Message:   "IT audit program reference detected — verify FFIEC examination alignment",
				Details:   "Institutions must maintain a comprehensive IT audit program aligned with FFIEC examination standards",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-EX-01",
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
			ControlID: "FFIEC-EX-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Vulnerability assessment reference detected — verify regular assessment schedule",
			Details:   "Institutions must conduct regular vulnerability assessments of information systems",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-EX-02",
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
			ControlID: "FFIEC-EX-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Penetration testing reference detected — verify periodic testing program",
			Details:   "Institutions must perform periodic penetration testing to validate security posture",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-EX-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No penetration testing patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkExamReadiness(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "examination readiness") || (strings.Contains(content, "examination") && strings.Contains(content, "readiness")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-EX-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "IT examination readiness reference detected — verify documentation and evidence preparation",
			Details:   "Institutions must maintain examination readiness through documentation, evidence, and pre-examination preparation",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-EX-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No examination readiness patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ---------------------------------------------------------------------------
// Outsourcing (OS)
// ---------------------------------------------------------------------------

func (m *FFIECModule) checkThirdPartyRisk(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.outsourcingPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "FFIEC-OS-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityHigh,
				Message:   "Third-party provider reference detected — verify risk assessment of service providers",
				Details:   "Institutions must assess and manage risk associated with third-party technology service providers",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-OS-01",
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
			ControlID: "FFIEC-OS-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Vendor management reference detected — verify program covers due diligence and monitoring",
			Details:   "Institutions must maintain a vendor management program covering due diligence, contracts, and ongoing monitoring",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-OS-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No vendor management patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkSLA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "service level") && (strings.Contains(content, "agreement") || strings.Contains(content, "sla") || strings.Contains(content, "contract")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-OS-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Service level agreement reference detected — verify SLA defines performance and security expectations",
			Details:   "Institutions must establish service level agreements with third-party providers defining performance and security expectations",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-OS-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No service level agreement patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkOutsourcingRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if (strings.Contains(content, "outsourcing") || strings.Contains(content, "third party") || strings.Contains(content, "third-party")) && (strings.Contains(content, "risk assessment") || strings.Contains(content, "risk management")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-OS-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Outsourcing risk assessment reference detected — verify strategic, operational, and compliance risk coverage",
			Details:   "Institutions must conduct outsourcing risk assessments covering strategic, operational, and compliance risks",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-OS-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No outsourcing risk assessment patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ---------------------------------------------------------------------------
// Business Continuity (BC)
// ---------------------------------------------------------------------------

func (m *FFIECModule) checkBusinessContinuityPlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "business continuity") && (strings.Contains(content, "plan") || strings.Contains(content, "program") || strings.Contains(content, "ffiec") || strings.Contains(content, "banking")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-BC-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Business continuity plan reference detected — verify FFIEC-aligned continuity planning",
			Details:   "Institutions must maintain a business continuity plan aligned with FFIEC business continuity management guidance",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-BC-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No business continuity plan patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkDisasterRecoveryTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if (strings.Contains(content, "disaster recovery") || strings.Contains(content, "dr test")) && (strings.Contains(content, "test") || strings.Contains(content, "testing") || strings.Contains(content, "exercise")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-BC-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Disaster recovery testing reference detected — verify periodic DR testing program",
			Details:   "Institutions must test disaster recovery capabilities periodically to validate recovery objectives",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-BC-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No disaster recovery testing patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkThirdPartyRecovery(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if (strings.Contains(content, "third party") || strings.Contains(content, "third-party") || strings.Contains(content, "service provider")) && (strings.Contains(content, "recovery") || strings.Contains(content, "continuity") || strings.Contains(content, "resilience")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-BC-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Third-party recovery capabilities reference detected — verify provider recovery assessment",
			Details:   "Institutions must assess third-party service provider recovery capabilities and integrate them into continuity planning",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-BC-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No third-party recovery capability patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ---------------------------------------------------------------------------
// Data Governance (DG)
// ---------------------------------------------------------------------------

func (m *FFIECModule) checkDataClassification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "data classification") && (strings.Contains(content, "handling") || strings.Contains(content, "policy") || strings.Contains(content, "sensitive") || strings.Contains(content, "confidential")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-DG-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Data classification and handling reference detected — verify procedures for sensitive financial information",
			Details:   "Institutions must implement data classification and handling procedures for sensitive financial information",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-DG-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No data classification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkDataLossPrevention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "data loss prevention") || strings.Contains(content, "dlp") {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-DG-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Data loss prevention reference detected — verify DLP controls for sensitive data",
			Details:   "Institutions must deploy data loss prevention controls to protect sensitive customer and institutional data",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-DG-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No data loss prevention patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkCustomerDataPrivacy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if (strings.Contains(content, "customer data") || strings.Contains(content, "customer privacy") || strings.Contains(content, "data privacy")) && (strings.Contains(content, "privacy") || strings.Contains(content, "glba") || strings.Contains(content, "ffiec") || strings.Contains(content, "protection")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-DG-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Customer data privacy reference detected — verify GLBA and FFIEC privacy compliance",
			Details:   "Institutions must protect customer data privacy in accordance with FFIEC and GLBA privacy requirements",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-DG-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No customer data privacy patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// ---------------------------------------------------------------------------
// AI Controls (AI)
// ---------------------------------------------------------------------------

func (m *FFIECModule) checkAIModelRisk(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if (strings.Contains(content, "ai model") || strings.Contains(content, "machine learning") || strings.Contains(content, "model risk")) && (strings.Contains(content, "risk management") || strings.Contains(content, "governance") || strings.Contains(content, "banking") || strings.Contains(content, "ffiec")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-AI-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "AI model risk management reference detected — verify model risk practices for banking operations",
			Details:   "Institutions must implement AI model risk management practices for models used in banking operations and decision-making",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-AI-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No AI model risk management patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *FFIECModule) checkAIModelValidation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if (strings.Contains(content, "model validation") || strings.Contains(content, "model testing")) && (strings.Contains(content, "ai") || strings.Contains(content, "machine learning") || strings.Contains(content, "accuracy") || strings.Contains(content, "fairness") || strings.Contains(content, "robustness")) {
		return &compliance.ControlCheckResult{
			ControlID: "FFIEC-AI-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "AI model validation reference detected — verify validation for accuracy, fairness, and robustness",
			Details:   "Institutions must validate and test AI models for accuracy, fairness, and robustness before deployment",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "FFIEC-AI-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No AI model validation patterns detected",
		Timestamp: time.Now(),
	}, nil
}

// =========================================================================
// Public API methods
// =========================================================================

// GetPatterns returns the detection patterns for this module.
func (m *FFIECModule) GetPatterns() []*regexp.Regexp {
	var all []*regexp.Regexp
	all = append(all, m.infoSecPatterns...)
	all = append(all, m.authPatterns...)
	all = append(all, m.examPatterns...)
	all = append(all, m.outsourcingPatterns...)
	all = append(all, m.bcPatterns...)
	all = append(all, m.dgPatterns...)
	all = append(all, m.aiPatterns...)
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
	totalPatterns := len(m.infoSecPatterns) + len(m.authPatterns) + len(m.examPatterns) + len(m.outsourcingPatterns) + len(m.bcPatterns) + len(m.dgPatterns) + len(m.aiPatterns)
	return fmt.Sprintf("FFIEC Module (v%s, %d controls, %d patterns)", m.Version(), len(m.Controls()), totalPatterns)
}

// ============================================================================
// Promoted CheckFunc implementations — P4 Compliance Automation Expansion
// ============================================================================

func (m *FFIECModule) checkThreatIntelProgram(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasProgram := strings.Contains(inputStr, "threat_intelligence_program") || strings.Contains(inputStr, "threat_intel") || strings.Contains(inputStr, "intel_program")
	hasFeeds := strings.Contains(inputStr, "threat_feeds") || strings.Contains(inputStr, "intel_feeds") || strings.Contains(inputStr, "ioc_feed")
	if hasProgram && hasFeeds {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-IS-06", ControlName: "Threat Intelligence Program", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Threat intelligence program detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasProgram {
		violations = append(violations, "threat intelligence program not configured")
	}
	if !hasFeeds {
		violations = append(violations, "threat feeds not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-IS-06", ControlName: "Threat Intelligence Program", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Threat intel gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement threat intelligence program with feeds"}, nil
}

func (m *FFIECModule) checkFraudDetection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDetection := strings.Contains(inputStr, "fraud_detection") || strings.Contains(inputStr, "fraud_monitoring") || strings.Contains(inputStr, "fraud_analytics")
	if hasDetection {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-AU-05", ControlName: "Fraud Detection Systems", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Fraud detection systems detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-AU-05", ControlName: "Fraud Detection Systems", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Fraud detection not detected", Timestamp: time.Now(), Remediation: "Implement fraud detection systems"}, nil
}

func (m *FFIECModule) checkCyberIRCoordination(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCoord := strings.Contains(inputStr, "cyber_incident_coordination") || strings.Contains(inputStr, "incident_coordination") || strings.Contains(inputStr, "ir_coordination")
	if hasCoord {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-BC-05", ControlName: "Cyber Incident Response Coordination", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Cyber incident response coordination detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-BC-05", ControlName: "Cyber Incident Response Coordination", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Cyber IR coordination not detected", Timestamp: time.Now(), Remediation: "Implement cyber incident response coordination"}, nil
}

func (m *FFIECModule) checkBusinessImpactAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBIA := strings.Contains(inputStr, "business_impact_analysis") || strings.Contains(inputStr, "bia") || strings.Contains(inputStr, "impact_analysis")
	if hasBIA {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-BC-06", ControlName: "Business Impact Analysis", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Business impact analysis detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-BC-06", ControlName: "Business Impact Analysis", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "BIA not detected", Timestamp: time.Now(), Remediation: "Implement business impact analysis"}, nil
}

func (m *FFIECModule) checkDataRetentionDisposal(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRetention := strings.Contains(inputStr, "data_retention") || strings.Contains(inputStr, "retention_policy") || strings.Contains(inputStr, "retention_disposal")
	if hasRetention {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-DG-04", ControlName: "Data Retention and Disposal", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Data retention and disposal detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FFIEC-DG-04", ControlName: "Data Retention and Disposal", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Data retention not detected", Timestamp: time.Now(), Remediation: "Implement data retention and disposal policies"}, nil
}
