// Package hitech provides HITECH Act compliance controls as a licensed add-on module.
// HITECH (Health Information Technology for Economic and Clinical Health Act) extends
// HIPAA with breach notification requirements, enhanced penalties, and audit log
// requirements for electronic health records (EHR).
package hitech

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// HITECHModule implements HITECH Act compliance controls.
type HITECHModule struct {
	*compliance.BaseComplianceModule
	breachPatterns        []*regexp.Regexp
	auditPatterns         []*regexp.Regexp
	ehrPatterns           []*regexp.Regexp
	penaltyPatterns       []*regexp.Regexp
	businessAssocPatterns []*regexp.Regexp
	patientRightsPatterns []*regexp.Regexp
	aiControlPatterns     []*regexp.Regexp
}

// NewHITECHModule creates a new HITECH compliance module.
func NewHITECHModule() *HITECHModule {
	m := &HITECHModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("hitech", "HITECH-2009", core.TierProfessional),
	}

	m.initPatterns()
	m.registerControls()

	return m
}

func (m *HITECHModule) initPatterns() {
	m.breachPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)breach\s*(?:notification|report|incident)`),
		regexp.MustCompile(`(?i)unsecured\s*(?:phi|protected\s*health)`),
		regexp.MustCompile(`(?i)breach\s*affecting\s*(?:more\s*than|over)\s*\d+`),
		regexp.MustCompile(`(?i)breach\s*risk\s*assessment`),
		regexp.MustCompile(`(?i)substitute\s*notice`),
		regexp.MustCompile(`(?i)breach\s*(?:documentation|registry|log)`),
	}
	m.auditPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit\s*(?:log|trail|record)\s*(?:access|entry|modification)`),
		regexp.MustCompile(`(?i)ehr\s*(?:access|log|audit)`),
		regexp.MustCompile(`(?i)meaningful\s*use`),
		regexp.MustCompile(`(?i)certified\s*(?:ehr|health\s*it)`),
		regexp.MustCompile(`(?i)audit\s*log\s*(?:retention|retain|retain|policy)`),
		regexp.MustCompile(`(?i)user\s*access\s*review`),
	}
	m.ehrPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)electronic\s*health\s*record|ehr`),
		regexp.MustCompile(`(?i)health\s*information\s*exchange|hie`),
		regexp.MustCompile(`(?i)clinical\s*decision\s*support`),
		regexp.MustCompile(`(?i)e?\s*prescribing|eprescribe`),
		regexp.MustCompile(`(?i)certified\s*(?:ehr|health\s*it|technology)`),
	}
	m.penaltyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)penalty\s*(?:tier|structure|level)`),
		regexp.MustCompile(`(?i)annual\s*(?:penalty\s*)?cap`),
		regexp.MustCompile(`(?i)attorney\s*general`),
		regexp.MustCompile(`(?i)inflation\s*adjust|penalty\s*inflation`),
		regexp.MustCompile(`(?i)repeat\s*(?:violation|offense)|willful\s*neglect`),
	}
	m.businessAssocPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)business\s*associate\s*(?:agreement|contract|baa)`),
		regexp.MustCompile(`(?i)subcontractor`),
		regexp.MustCompile(`(?i)business\s*associate\s*(?:liable|liability|compliance)`),
		regexp.MustCompile(`(?i)ba\s*breach\s*(?:notification|report)`),
		regexp.MustCompile(`(?i)flow[\s-]?down`),
	}
	m.patientRightsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)electronic\s*copy\s*(?:of|health|record)`),
		regexp.MustCompile(`(?i)access\s*fee|cost[\s-]?based`),
		regexp.MustCompile(`(?i)accounting\s*of\s*disclosures`),
		regexp.MustCompile(`(?i)restrict\s*disclosure|restriction\s*request`),
		regexp.MustCompile(`(?i)confidential\s*communication|alternative\s*address`),
	}
	m.aiControlPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ai\s*(?:model|algorithm)\s*(?:phi|protected|health)`),
		regexp.MustCompile(`(?i)(?:de[\s-]?identif|anonymiz|pseudonym)\w*`),
		regexp.MustCompile(`(?i)clinical\s*decision\s*support.*audit|cds\s*audit`),
		regexp.MustCompile(`(?i)patient\s*safety\s*monitor`),
		regexp.MustCompile(`(?i)ai\s*bias\s*(?:detect|monitor|eval|mitigat)`),
		regexp.MustCompile(`(?i)ai\s*explainab|model\s*interpretab|explain\s*decision`),
	}
}

func (m *HITECHModule) registerControls() {
	// ===== Breach Notification (BN) — 8 controls (6 auto, 2 manual) =====

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-01",
		Name:        "Breach Notification Requirement",
		Description: "Covered entities must notify affected individuals of a breach of unsecured PHI within 60 days",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBreachNotification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-02",
		Name:        "HHS Breach Reporting",
		Description: "Breaches affecting 500+ individuals must be reported to HHS within 60 days",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkHHSReporting,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-03",
		Name:        "Media Notification",
		Description: "Breaches affecting 500+ residents of a state must be reported to local media",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMediaNotification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-04",
		Name:        "Annual Breach Log",
		Description: "Breaches affecting fewer than 500 individuals must be logged and reported annually to HHS",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAnnualBreachLog,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-05",
		Name:        "Breach Risk Assessment",
		Description: "Covered entities must conduct a risk assessment to determine if a breach of unsecured PHI has occurred",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBreachRiskAssessment,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-06",
		Name:        "Substitute Notice for Insufficient Contact",
		Description: "If insufficient contact information exists for 10+ individuals, substitute notice must be provided",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSubstituteNotice,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-07",
		Name:        "Breach Notification Content Requirements",
		Description: "Breach notifications must include description of breach, types of information, steps to protect, and contact information",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   m.checkBreachNotificationContent,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BN-08",
		Name:        "Breach Documentation and Registry",
		Description: "All breach notifications and supporting documentation must be retained for six years",
		Category:    "Breach Notification",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkBreachDocumentation,
	})

	// ===== Enhanced Penalties (EP) — 5 controls (3 auto, 2 manual) =====

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EP-01",
		Name:        "Tiered Penalty Structure",
		Description: "HITECH establishes tiered civil monetary penalties based on culpability",
		Category:    "Enhanced Penalties",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPenaltyStructure,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EP-02",
		Name:        "Annual Penalty Cap",
		Description: "Annual cap on penalties per violation tier (adjusted for inflation)",
		Category:    "Enhanced Penalties",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPenaltyCap,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EP-03",
		Name:        "State Attorney General Enforcement",
		Description: "State attorneys general may bring civil actions to enforce HIPAA and HITECH provisions",
		Category:    "Enhanced Penalties",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkStateAGEnforcement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EP-04",
		Name:        "Penalty Inflation Adjustment",
		Description: "Civil monetary penalties must be adjusted for inflation in accordance with Federal Civil Penalties Inflation Adjustment Act",
		Category:    "Enhanced Penalties",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkPenaltyInflation,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EP-05",
		Name:        "Repeat Violation Escalation",
		Description: "Penalties escalate for repeat violations and willful neglect that is not corrected within 30 days",
		Category:    "Enhanced Penalties",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		CheckFunc:   m.checkRepeatViolationEscalation,
	})

	// ===== EHR Audit (EA) — 6 controls (4 auto, 2 manual) =====

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EA-01",
		Name:        "EHR Access Audit Logging",
		Description: "EHR systems must maintain audit logs of all access to electronic PHI",
		Category:    "EHR Audit",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEHRAuditLogging,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EA-02",
		Name:        "Audit Log Tamper Protection",
		Description: "Audit logs must be protected from alteration or deletion",
		Category:    "EHR Audit",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditLogTamperProtection,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EA-03",
		Name:        "Meaningful Use Attestation",
		Description: "Providers must attest to meaningful use of certified EHR technology",
		Category:    "EHR Audit",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMeaningfulUse,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EA-04",
		Name:        "Audit Log Retention",
		Description: "Audit logs must be retained for a minimum of six years from the date of creation",
		Category:    "EHR Audit",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditLogRetention,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EA-05",
		Name:        "EHR User Access Reviews",
		Description: "Periodic reviews of user access to EHR systems must be conducted to verify appropriate access levels",
		Category:    "EHR Audit",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkEHRUserAccessReviews,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-EA-06",
		Name:        "Certified EHR Technology Verification",
		Description: "Organizations must verify that their EHR technology is certified under the ONC Health IT Certification Program",
		Category:    "EHR Audit",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   m.checkCertifiedEHRTechnology,
	})

	// ===== Business Associate (BA) — 5 controls (3 auto, 2 manual) =====

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BA-01",
		Name:        "Business Associate Direct Liability",
		Description: "HITECH makes business associates directly liable for HIPAA violations",
		Category:    "Business Associate",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBALiability,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BA-02",
		Name:        "Subcontractor Flow-Down",
		Description: "Business associates must flow down HIPAA obligations to subcontractors",
		Category:    "Business Associate",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSubcontractorFlowDown,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BA-03",
		Name:        "Business Associate Agreement Requirements",
		Description: "Business associate agreements must include required HITECH provisions including breach notification and safeguards",
		Category:    "Business Associate",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBAARequirements,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BA-04",
		Name:        "BA Compliance Monitoring",
		Description: "Covered entities must monitor business associate compliance with HIPAA and HITECH requirements",
		Category:    "Business Associate",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkBAComplianceMonitoring,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-BA-05",
		Name:        "BA Breach Notification to Covered Entity",
		Description: "Business associates must notify covered entities of a breach within 60 days of discovery",
		Category:    "Business Associate",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		CheckFunc:   m.checkBABreachNotification,
	})

	// ===== Patient Rights (PR) — 5 controls (3 auto, 2 manual) =====

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-PR-01",
		Name:        "Right to Electronic Copy of Health Record",
		Description: "Individuals have the right to receive an electronic copy of their health record in the format of their choice",
		Category:    "Patient Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkElectronicCopyRight,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-PR-02",
		Name:        "Access Fee Limitations",
		Description: "Fees for providing electronic copies of health records must be cost-based and reasonable",
		Category:    "Patient Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAccessFeeLimitations,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-PR-03",
		Name:        "Accounting of Disclosures",
		Description: "Individuals have the right to an accounting of disclosures of their PHI made in the prior three years",
		Category:    "Patient Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccountingOfDisclosures,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-PR-04",
		Name:        "Right to Restrict Disclosures",
		Description: "Individuals may request restrictions on disclosures of their PHI, including to health plans for self-paid services",
		Category:    "Patient Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkRightToRestrict,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-PR-05",
		Name:        "Confidential Communications",
		Description: "Individuals may request that communications regarding their health information be sent by alternative means",
		Category:    "Patient Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   m.checkConfidentialCommunications,
	})

	// ===== AI Controls (AI) — 6 controls (4 auto, 2 manual) =====

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-AI-01",
		Name:        "AI Model PHI Protection",
		Description: "AI models that process PHI must implement safeguards to protect health information during inference and storage",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelPHIProtection,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-AI-02",
		Name:        "AI Training Data De-identification",
		Description: "Training data for AI models must be de-identified in accordance with HIPAA Safe Harbor or Expert Determination methods",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAITrainingDataDeIdentification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-AI-03",
		Name:        "AI Clinical Decision Support Audit",
		Description: "AI-based clinical decision support tools must maintain audit trails of recommendations and clinician overrides",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIClinicalDecisionSupport,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-AI-04",
		Name:        "AI Patient Safety Monitoring",
		Description: "AI systems used in healthcare must be continuously monitored for patient safety risks and adverse events",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIPatientSafetyMonitoring,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-AI-05",
		Name:        "AI Bias Detection in Healthcare",
		Description: "AI models used in clinical settings must be evaluated for bias across demographic groups to ensure equitable care",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIBiasDetection,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITECH-AI-06",
		Name:        "AI Explainability for Clinical Use",
		Description: "AI clinical decision support systems must provide explainability and interpretability for clinicians and patients",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		CheckFunc:   m.checkAIExplainability,
	})
}

// ===== CheckFunc implementations — Breach Notification (BN) =====

func (m *HITECHModule) checkBreachNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.breachPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "HITECH-BN-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "Potential breach notification content detected",
				Details:   "HITECH requires individual notification within 60 days of breach discovery",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No breach notification patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkHHSReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "500+") || strings.Contains(content, "more than 500") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BN-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Large-scale breach detected — HHS reporting required within 60 days",
			Details:   "Breaches affecting 500+ individuals require immediate HHS notification",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No large-scale breach indicators detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkMediaNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	for _, p := range m.breachPatterns {
		if p.MatchString(content) && strings.Contains(content, "media") {
			return &compliance.ControlCheckResult{
				ControlID: "HITECH-BN-03",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityHigh,
				Message:   "Media notification may be required for this breach",
				Details:   "Breaches affecting 500+ state residents require media notification",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No media notification triggers detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAnnualBreachLog(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "breach") && strings.Contains(content, "annual") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BN-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Annual breach log entry detected — verify HHS annual report is filed",
			Details:   "Breaches under 500 individuals must be logged and reported annually to HHS",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No annual breach log entries detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkBreachRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "risk assessment") && strings.Contains(content, "breach") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BN-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Breach risk assessment detected — verify four-factor risk assessment is documented",
			Details:   "Risk assessment must evaluate: (1) nature and extent of PHI, (2) who accessed/obtained PHI, (3) whether PHI was acquired or viewed, (4) extent to which risk has been mitigated",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No breach risk assessment indicators detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkSubstituteNotice(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "substitute notice") || strings.Contains(content, "insufficient contact") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BN-06",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Substitute notice requirement detected — verify notice is provided via prominent website or media",
			Details:   "When contact info is insufficient for 10+ individuals, substitute notice must be posted on the covered entity's website for 90 days or provided through major media",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-06",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No substitute notice triggers detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkBreachNotificationContent(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	requiredElements := []string{"description", "type", "steps", "contact"}
	found := 0
	for _, elem := range requiredElements {
		if strings.Contains(content, elem) {
			found++
		}
	}
	if found >= 3 {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BN-07",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Breach notification content detected — verify all required elements are included",
			Details:   "Notification must include: description of what happened, types of information involved, steps individuals can take, contact procedures",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-07",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No breach notification content gaps detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkBreachDocumentation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "breach") && (strings.Contains(content, "documentation") || strings.Contains(content, "registry")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BN-08",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Breach documentation reference detected — verify records are retained for six years",
			Details:   "All breach notifications, risk assessments, and supporting documentation must be retained for six years from the date of breach",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BN-08",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No breach documentation references detected",
		Timestamp: time.Now(),
	}, nil
}

// ===== CheckFunc implementations — Enhanced Penalties (EP) =====

func (m *HITECHModule) checkPenaltyStructure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "penalty") && strings.Contains(content, "tier") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EP-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Penalty tier reference detected — verify correct tier classification",
			Details:   "HITECH tiered penalties: (1) no knowledge, (2) reasonable cause, (3) willful neglect-corrected, (4) willful neglect-not corrected",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EP-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No penalty tier references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkPenaltyCap(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "annual cap") || strings.Contains(content, "penalty cap") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EP-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Annual penalty cap reference detected — verify inflation-adjusted amount",
			Details:   "Annual cap per violation tier is adjusted for inflation per HHS rulemaking",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EP-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No penalty cap references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkStateAGEnforcement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "attorney general") || strings.Contains(content, "state ag") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EP-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "State Attorney General enforcement reference detected — verify compliance posture",
			Details:   "State AGs may bring civil actions to enforce HIPAA/HITECH on behalf of state residents, including seeking damages and penalties",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EP-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No State AG enforcement references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkPenaltyInflation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "inflation") && (strings.Contains(content, "penalty") || strings.Contains(content, "adjustment")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EP-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Penalty inflation adjustment reference detected — verify current inflation-adjusted amounts",
			Details:   "Civil monetary penalties must be adjusted annually for inflation per the Federal Civil Penalties Inflation Adjustment Act",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EP-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No penalty inflation adjustment references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkRepeatViolationEscalation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "repeat") && strings.Contains(content, "violation") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EP-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "Repeat violation escalation detected — verify penalties are escalated appropriately",
			Details:   "Penalties for willful neglect not corrected within 30 days can reach $50,000 per violation, with repeat violations subject to maximum penalties",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EP-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No repeat violation escalation references detected",
		Timestamp: time.Now(),
	}, nil
}

// ===== CheckFunc implementations — EHR Audit (EA) =====

func (m *HITECHModule) checkEHRAuditLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.auditPatterns {
		if p.MatchString(content) {
			return &compliance.ControlCheckResult{
				ControlID: "HITECH-EA-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "EHR audit log content detected — verify access logging is enabled",
				Details:   "EHR systems must log all access to electronic PHI",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EA-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No EHR audit log patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAuditLogTamperProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "audit log") && (strings.Contains(content, "delete") || strings.Contains(content, "modify") || strings.Contains(content, "alter")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EA-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Audit log modification detected — tamper protection may be violated",
			Details:   "Audit logs must be protected from alteration or deletion",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EA-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No audit log tamper indicators detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkMeaningfulUse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "meaningful use") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EA-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Meaningful use attestation reference detected — verify EHR certification",
			Details:   "Providers must attest to meaningful use of certified EHR technology",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EA-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No meaningful use references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAuditLogRetention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "audit log") && (strings.Contains(content, "retention") || strings.Contains(content, "retain") || strings.Contains(content, "retain") || strings.Contains(content, "six year")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EA-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Audit log retention reference detected — verify retention policy meets six-year minimum",
			Details:   "Audit logs must be retained for a minimum of six years from creation or last effective date",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EA-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No audit log retention references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkEHRUserAccessReviews(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "user access") && (strings.Contains(content, "review") || strings.Contains(content, "audit") || strings.Contains(content, "recertif")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EA-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "EHR user access review detected — verify periodic reviews are documented",
			Details:   "User access to EHR systems must be reviewed periodically to verify appropriate access levels and least-privilege enforcement",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EA-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No EHR user access review references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkCertifiedEHRTechnology(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "certified") && (strings.Contains(content, "ehr") || strings.Contains(content, "health it")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-EA-06",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Certified EHR technology reference detected — verify current ONC certification",
			Details:   "EHR technology must be certified under the ONC Health IT Certification Program, including all required functional and security criteria",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-EA-06",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No certified EHR technology references detected",
		Timestamp: time.Now(),
	}, nil
}

// ===== CheckFunc implementations — Business Associate (BA) =====

func (m *HITECHModule) checkBALiability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "business associate") && strings.Contains(content, "liable") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BA-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Business associate liability reference detected — verify direct liability compliance",
			Details:   "HITECH makes business associates directly liable for HIPAA violations",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BA-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No BA liability references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkSubcontractorFlowDown(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "subcontractor") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BA-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Subcontractor reference detected — verify HIPAA obligations are flowed down",
			Details:   "Business associates must flow down HIPAA obligations to subcontractors",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BA-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No subcontractor references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkBAARequirements(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "business associate agreement") || strings.Contains(content, "baa") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BA-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Business associate agreement reference detected — verify required HITECH provisions are included",
			Details:   "BAA must include: breach notification requirements, safeguards, subcontractor flow-down, access reports, and compliance with HIPAA Security Rule",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BA-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No BAA references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkBAComplianceMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "business associate") && (strings.Contains(content, "monitor") || strings.Contains(content, "compliance") || strings.Contains(content, "audit")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BA-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "BA compliance monitoring reference detected — verify monitoring program is in place",
			Details:   "Covered entities must monitor business associate compliance through periodic audits, security questionnaires, and breach notification procedures",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BA-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No BA compliance monitoring references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkBABreachNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "business associate") && strings.Contains(content, "breach") && (strings.Contains(content, "notify") || strings.Contains(content, "notification") || strings.Contains(content, "report")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-BA-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "BA breach notification reference detected — verify 60-day notification timeline to covered entity",
			Details:   "Business associates must notify the covered entity of a breach without unreasonable delay and no later than 60 days after discovery",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-BA-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No BA breach notification references detected",
		Timestamp: time.Now(),
	}, nil
}

// ===== CheckFunc implementations — Patient Rights (PR) =====

func (m *HITECHModule) checkElectronicCopyRight(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "electronic copy") || (strings.Contains(content, "access") && strings.Contains(content, "health record")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-PR-01",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Electronic copy request detected — verify individual's right to electronic format is honored",
			Details:   "HITECH grants individuals the right to receive an electronic copy of their health record in the format and manner requested, if readily producible",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-PR-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No electronic copy right references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAccessFeeLimitations(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "access fee") || strings.Contains(content, "cost-based") || strings.Contains(content, "cost based") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-PR-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Access fee reference detected — verify fees are cost-based and reasonable",
			Details:   "Fees for electronic copies must be limited to cost-based labor and supply costs, and must be reasonable",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-PR-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No access fee references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAccountingOfDisclosures(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "accounting of disclosures") || (strings.Contains(content, "accounting") && strings.Contains(content, "disclosure")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-PR-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "Accounting of disclosures request detected — verify three-year disclosure log is maintained",
			Details:   "Individuals have the right to an accounting of disclosures of their PHI made in the prior three years, including date, recipient, and description",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-PR-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No accounting of disclosures references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkRightToRestrict(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "restrict") && strings.Contains(content, "disclosure") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-PR-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Disclosure restriction request detected — verify restriction process is in place",
			Details:   "Individuals may request restrictions on disclosures, including mandatory restrictions on disclosures to health plans for self-paid services",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-PR-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No disclosure restriction references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkConfidentialCommunications(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "confidential communication") || strings.Contains(content, "alternative address") || strings.Contains(content, "alternative means") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-PR-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityMedium,
			Message:   "Confidential communication request detected — verify alternative means are accommodated",
			Details:   "Individuals may request that communications regarding their health information be sent by alternative means or to alternative locations",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-PR-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityMedium,
		Message:   "No confidential communication references detected",
		Timestamp: time.Now(),
	}, nil
}

// ===== CheckFunc implementations — AI Controls (AI) =====

func (m *HITECHModule) checkAIModelPHIProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := string(input)
	for _, p := range m.aiControlPatterns {
		if p.MatchString(content) && (strings.Contains(strings.ToLower(content), "phi") || strings.Contains(strings.ToLower(content), "protected health") || strings.Contains(strings.ToLower(content), "model")) {
			return &compliance.ControlCheckResult{
				ControlID: "HITECH-AI-01",
				Status:    compliance.StatusNonCompliant,
				Severity:  compliance.SeverityCritical,
				Message:   "AI model PHI processing detected — verify safeguards are in place",
				Details:   "AI models that process PHI must implement encryption, access controls, and audit logging to protect health information during inference and storage",
				Timestamp: time.Now(),
			}, nil
		}
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-AI-01",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No AI model PHI processing patterns detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAITrainingDataDeIdentification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "de-identif") || strings.Contains(content, "deidentif") || strings.Contains(content, "anonymiz") || strings.Contains(content, "pseudonym") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-AI-02",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "AI training data de-identification detected — verify HIPAA-compliant method is used",
			Details:   "Training data must be de-identified using either the HIPAA Safe Harbor method (removal of 18 identifiers) or Expert Determination method (statistical verification of low re-identification risk)",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-AI-02",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No AI training data de-identification references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAIClinicalDecisionSupport(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "clinical decision support") || strings.Contains(content, "cds") {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-AI-03",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "AI clinical decision support detected — verify audit trails are maintained",
			Details:   "AI-based clinical decision support tools must maintain audit trails of recommendations, clinician reviews, overrides, and outcomes",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-AI-03",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No AI clinical decision support references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAIPatientSafetyMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "patient safety") && (strings.Contains(content, "monitor") || strings.Contains(content, "ai") || strings.Contains(content, "algorithm")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-AI-04",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityCritical,
			Message:   "AI patient safety monitoring detected — verify continuous monitoring is in place",
			Details:   "AI systems used in healthcare must be continuously monitored for patient safety risks, including adverse events, model drift, and unexpected outputs",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-AI-04",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityCritical,
		Message:   "No AI patient safety monitoring references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAIBiasDetection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "bias") && (strings.Contains(content, "ai") || strings.Contains(content, "model") || strings.Contains(content, "algorithm")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-AI-05",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "AI bias detection reference detected — verify bias evaluation is conducted across demographic groups",
			Details:   "AI models used in clinical settings must be evaluated for bias across race, ethnicity, gender, age, and other demographic factors to ensure equitable care",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-AI-05",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No AI bias detection references detected",
		Timestamp: time.Now(),
	}, nil
}

func (m *HITECHModule) checkAIExplainability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	content := strings.ToLower(string(input))
	if strings.Contains(content, "explainab") || strings.Contains(content, "interpretab") || (strings.Contains(content, "explain") && strings.Contains(content, "ai")) {
		return &compliance.ControlCheckResult{
			ControlID: "HITECH-AI-06",
			Status:    compliance.StatusNonCompliant,
			Severity:  compliance.SeverityHigh,
			Message:   "AI explainability reference detected — verify clinical use has explainability features",
			Details:   "AI clinical decision support systems must provide explainability and interpretability, including rationale for recommendations and confidence scores for clinicians and patients",
			Timestamp: time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		ControlID: "HITECH-AI-06",
		Status:    compliance.StatusCompliant,
		Severity:  compliance.SeverityHigh,
		Message:   "No AI explainability references detected",
		Timestamp: time.Now(),
	}, nil
}

// ===== Metadata and utility methods =====

// GetPatterns returns the detection patterns for this module.
func (m *HITECHModule) GetPatterns() []*regexp.Regexp {
	var all []*regexp.Regexp
	all = append(all, m.breachPatterns...)
	all = append(all, m.auditPatterns...)
	all = append(all, m.ehrPatterns...)
	all = append(all, m.penaltyPatterns...)
	all = append(all, m.businessAssocPatterns...)
	all = append(all, m.patientRightsPatterns...)
	all = append(all, m.aiControlPatterns...)
	return all
}

// Framework returns the framework identifier.
func (m *HITECHModule) Framework() string {
	return "HITECH"
}

// Version returns the framework version.
func (m *HITECHModule) Version() string {
	return "2009"
}

// LastUpdated returns the last update time.
func (m *HITECHModule) LastUpdated() time.Time {
	return time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
}

// String returns a string representation.
func (m *HITECHModule) String() string {
	return fmt.Sprintf("HITECH Module (v%s, %d controls)", m.Version(), len(m.GetPatterns()))
}

// Dependencies returns required modules.
func (m *HITECHModule) Dependencies() []string {
	return []string{"scanner", "auth", "persistence", "audit"}
}
