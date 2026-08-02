// Package ferpa provides FERPA (Family Educational Rights and Privacy Act) compliance controls as a licensed add-on module.
package ferpa

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// FERPAModule implements FERPA compliance controls.
type FERPAModule struct {
	*compliance.BaseComplianceModule
	ferpaPatterns []*regexp.Regexp
}

// NewFERPAModule creates a new FERPA compliance module.
func NewFERPAModule() *FERPAModule {
	m := &FERPAModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("ferpa", "34cfr99", core.TierProfessional),
	}

	m.initFERPAPatterns()
	m.registerControls()

	return m
}

// initFERPAPatterns initializes patterns for detecting student PII in education records.
func (m *FERPAModule) initFERPAPatterns() {
	m.ferpaPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),                             // SSN
		regexp.MustCompile(`(?i)student\s*(?:id|#)\s*[A-Za-z0-9]{5,12}`),    // Student ID
		regexp.MustCompile(`(?i)ferpa\s*(?:protected|record|confidential)`), // FERPA record marker
		regexp.MustCompile(`(?i)education\s*record`),                        // Education record
		regexp.MustCompile(`(?i)opt\s*out|withhold\s*directory`),            // Directory info opt-out
	}
}

// registerControls registers all FERPA 34 CFR 99 compliance controls.
func (m *FERPAModule) registerControls() {
	// Student Education Records (ER)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-001",
		Name:        "Education Records Access",
		Description: "Students have the right to access their education records under FERPA",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEducationRecordsAccess,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-002",
		Name:        "Record Amendment Rights",
		Description: "Students can request amendment of inaccurate or misleading education records",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecordAmendment,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-003",
		Name:        "Record Destruction Policy",
		Description: "Institutions must have policies for destroying education records when no longer needed",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecordDestruction,
	})

	// Directory Information (DI)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DI-001",
		Name:        "Directory Information Classification",
		Description: "Institutions must classify which data elements constitute directory information",
		Category:    "Directory Information",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDirectoryInfoClassification,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DI-002",
		Name:        "Opt-Out Mechanism",
		Description: "Students must be able to opt out of directory information disclosure",
		Category:    "Directory Information",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkOptOutMechanism,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DI-003",
		Name:        "Disclosure Consent",
		Description: "Written consent required before disclosing non-directory PII from education records",
		Category:    "Directory Information",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDisclosureConsent,
	})

	// Consent & Disclosure (CD)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-001",
		Name:        "Authorized Disclosure",
		Description: "Only authorized disclosures under FERPA exceptions are permitted without written consent",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuthorizedDisclosure,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-002",
		Name:        "Health/Safety Exception",
		Description: "Emergency disclosure of education records allowed for health and safety purposes",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkHealthSafetyException,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-003",
		Name:        "Law Enforcement Unit Records",
		Description: "Separate records must be maintained for campus law enforcement unit records under FERPA",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLawEnforcementRecords,
	})

	// Data Security (DS)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-001",
		Name:        "Administrative Data Safeguards",
		Description: "Administrative safeguards for protecting education records including governance and access controls",
		Category:    "Data Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAdministrativeSafeguards,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-002",
		Name:        "Physical Data Safeguards",
		Description: "Physical security of education record storage (customer responsibility)",
		Category:    "Data Security",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-003",
		Name:        "Technical Data Safeguards",
		Description: "Technical controls including encryption, access logs, and multi-factor authentication for education records",
		Category:    "Data Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTechnicalSafeguards,
	})

	// AI-Specific (AI)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-001",
		Name:        "AI Model Student Data Protection",
		Description: "AI models must not retain or expose student PII from education records",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelStudentDataProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-002",
		Name:        "AI Training Data Consent",
		Description: "Explicit consent required before using student data for AI training purposes",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAITrainingDataConsent,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-003",
		Name:        "AI Audit Trail for Education Records",
		Description: "Audit logging required for AI interactions involving education records",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrail,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-004",
		Name:        "AI Bias Detection in Education",
		Description: "Detect and mitigate bias in AI systems making education-related decisions",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIBiasDetection,
	})
}

// Check implementations

func (m *FERPAModule) checkEducationRecordsAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRecordsAccess := strings.Contains(inputStr, "education_records_access") || strings.Contains(inputStr, "student_access") || strings.Contains(inputStr, "records_access_policy")

	if hasRecordsAccess {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-ER-001",
			ControlName: "Education Records Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Education records access and student access controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-ER-001",
		ControlName: "Education Records Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Education records access controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement education records access policy ensuring students can review their records per FERPA",
	}, nil
}

func (m *FERPAModule) checkRecordAmendment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAmendment := strings.Contains(inputStr, "record_amendment") || strings.Contains(inputStr, "amendment_request") || strings.Contains(inputStr, "dispute_resolution")

	if hasAmendment {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-ER-002",
			ControlName: "Record Amendment Rights",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Record amendment and dispute resolution controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-ER-002",
		ControlName: "Record Amendment Rights",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Record amendment and dispute resolution controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement record amendment request process and dispute resolution procedures per FERPA",
	}, nil
}

func (m *FERPAModule) checkRecordDestruction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDestruction := strings.Contains(inputStr, "record_destruction") || strings.Contains(inputStr, "data_retention_policy") || strings.Contains(inputStr, "secure_disposal")

	if hasDestruction {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-ER-003",
			ControlName: "Record Destruction Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Record destruction and secure disposal controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-ER-003",
		ControlName: "Record Destruction Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Record destruction policy not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement record destruction and secure disposal policies for education records no longer needed",
	}, nil
}

func (m *FERPAModule) checkDirectoryInfoClassification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDirectoryInfo := strings.Contains(inputStr, "directory_information") || strings.Contains(inputStr, "public_directory") || strings.Contains(inputStr, "student_directory")

	if hasDirectoryInfo {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DI-001",
			ControlName: "Directory Information Classification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Directory information classification controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DI-001",
		ControlName: "Directory Information Classification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Directory information classification not detected",
		Timestamp:   time.Now(),
		Remediation: "Classify which data elements constitute directory information per FERPA requirements",
	}, nil
}

func (m *FERPAModule) checkOptOutMechanism(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasOptOut := strings.Contains(inputStr, "opt_out") || strings.Contains(inputStr, "directory_opt_out") || strings.Contains(inputStr, "withhold_directory")

	if hasOptOut {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DI-002",
			ControlName: "Opt-Out Mechanism",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Directory information opt-out mechanism detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DI-002",
		ControlName: "Opt-Out Mechanism",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Directory information opt-out mechanism not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement opt-out mechanism allowing students to withhold directory information per FERPA",
	}, nil
}

func (m *FERPAModule) checkDisclosureConsent(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDisclosureConsent := strings.Contains(inputStr, "disclosure_consent") || strings.Contains(inputStr, "written_consent") || strings.Contains(inputStr, "consent_form")

	if hasDisclosureConsent {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DI-003",
			ControlName: "Disclosure Consent",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Written disclosure consent controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DI-003",
		ControlName: "Disclosure Consent",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Disclosure consent controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement written consent requirement before disclosing non-directory PII per FERPA",
	}, nil
}

func (m *FERPAModule) checkAuthorizedDisclosure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuthDisclosure := strings.Contains(inputStr, "authorized_disclosure") || strings.Contains(inputStr, "disclosure_policy") || strings.Contains(inputStr, "ferpa_exceptions")

	if hasAuthDisclosure {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CD-001",
			ControlName: "Authorized Disclosure",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Authorized disclosure and FERPA exceptions controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CD-001",
		ControlName: "Authorized Disclosure",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Authorized disclosure controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement authorized disclosure policy with FERPA exceptions per 34 CFR 99.31",
	}, nil
}

func (m *FERPAModule) checkHealthSafetyException(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHealthSafety := strings.Contains(inputStr, "health_safety_exception") || strings.Contains(inputStr, "emergency_disclosure") || strings.Contains(inputStr, "safety_exception")

	if hasHealthSafety {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CD-002",
			ControlName: "Health/Safety Exception",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Health and safety emergency disclosure controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CD-002",
		ControlName: "Health/Safety Exception",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Health and safety exception controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement health and safety emergency disclosure procedures per FERPA 34 CFR 99.31(a)(10)",
	}, nil
}

func (m *FERPAModule) checkLawEnforcementRecords(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLERecords := strings.Contains(inputStr, "law_enforcement_records") || strings.Contains(inputStr, "campus_police") || strings.Contains(inputStr, "security_records")

	if hasLERecords {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CD-003",
			ControlName: "Law Enforcement Unit Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Law enforcement unit record separation controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CD-003",
		ControlName: "Law Enforcement Unit Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Law enforcement unit record controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement separate records for campus law enforcement unit per FERPA requirements",
	}, nil
}

func (m *FERPAModule) checkAdministrativeSafeguards(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAdminSafeguards := strings.Contains(inputStr, "administrative_safeguards") || strings.Contains(inputStr, "data_governance") || strings.Contains(inputStr, "access_controls")

	if hasAdminSafeguards {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DS-001",
			ControlName: "Administrative Data Safeguards",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Administrative safeguards for education records detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DS-001",
		ControlName: "Administrative Data Safeguards",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Administrative safeguards not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement administrative safeguards including data governance and access controls for education records",
	}, nil
}

func (m *FERPAModule) checkTechnicalSafeguards(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryption := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted")
	hasAuditLog := strings.Contains(inputStr, "audit_log")
	hasMFA := strings.Contains(inputStr, "mfa") || strings.Contains(inputStr, "multi_factor")

	detected := []string{}
	if hasEncryption {
		detected = append(detected, "encryption at rest")
	}
	if hasAuditLog {
		detected = append(detected, "audit logging")
	}
	if hasMFA {
		detected = append(detected, "multi-factor authentication")
	}

	if len(detected) == 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DS-003",
			ControlName: "Technical Data Safeguards",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Technical safeguards detected: encryption at rest, audit logging, and MFA",
			Timestamp:   time.Now(),
		}, nil
	}

	if len(detected) > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DS-003",
			ControlName: "Technical Data Safeguards",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial technical safeguards detected: " + strings.Join(detected, ", "),
			Timestamp:   time.Now(),
			Remediation: "Implement all technical safeguards: encryption at rest, audit logging, and multi-factor authentication",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DS-003",
		ControlName: "Technical Data Safeguards",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No technical safeguards for education records detected",
		Timestamp:   time.Now(),
		Remediation: "Implement encryption at rest, audit logging, and multi-factor authentication for education records per FERPA",
	}, nil
}

func (m *FERPAModule) checkAIModelStudentDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	piiFound := m.detectStudentPII(string(input))

	if len(piiFound) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-AI-001",
			ControlName: "AI Model Student Data Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No student PII detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-AI-001",
		ControlName: "AI Model Student Data Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Student PII patterns detected in AI model data",
		Details:     "Detected student PII patterns in input data",
		Timestamp:   time.Now(),
		Remediation: "Implement student PII scrubbing for all AI model inputs and outputs per FERPA requirements",
	}, nil
}

func (m *FERPAModule) checkAITrainingDataConsent(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasConsent := strings.Contains(inputStr, "ai_training_consent") || strings.Contains(inputStr, "student_data_consent") || strings.Contains(inputStr, "opt_in_policy")

	if hasConsent {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-AI-002",
			ControlName: "AI Training Data Consent",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI training data consent controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-AI-002",
		ControlName: "AI Training Data Consent",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "AI training data consent controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement explicit consent requirement before using student data for AI training per FERPA",
	}, nil
}

func (m *FERPAModule) checkAIAuditTrail(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := strings.Contains(inputStr, "ai_audit_trail")
	hasModelLogging := strings.Contains(inputStr, "model_logging")
	hasEduRecordLogging := strings.Contains(inputStr, "education_record_logging")

	violations := []string{}
	if !hasAuditLog {
		violations = append(violations, "AI audit trail")
	}
	if !hasModelLogging {
		violations = append(violations, "model logging")
	}
	if !hasEduRecordLogging {
		violations = append(violations, "education record logging")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-AI-003",
			ControlName: "AI Audit Trail for Education Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI audit trail with education record logging detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if len(violations) < 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-AI-003",
			ControlName: "AI Audit Trail for Education Records",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AI audit controls: missing " + strings.Join(violations, ", "),
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive AI audit trail including ai_audit_trail, model_logging, and education_record_logging",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-AI-003",
		ControlName: "AI Audit Trail for Education Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI audit trail controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement AI audit trail, model logging, and education record logging for all AI interactions with education records",
	}, nil
}

func (m *FERPAModule) checkAIBiasDetection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBiasDetection := strings.Contains(inputStr, "bias_detection") || strings.Contains(inputStr, "fairness_audit") || strings.Contains(inputStr, "equity_review")

	if hasBiasDetection {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-AI-004",
			ControlName: "AI Bias Detection in Education",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI bias detection and equity review controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-AI-004",
		ControlName: "AI Bias Detection in Education",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI bias detection controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement bias detection and fairness audit for AI systems making education-related decisions",
	}, nil
}

// detectStudentPII scans input for potential student PII patterns.
func (m *FERPAModule) detectStudentPII(input string) []string {
	found := []string{}
	for _, pattern := range m.ferpaPatterns {
		if pattern.MatchString(input) {
			found = append(found, pattern.String())
		}
	}
	return found
}

// Dependencies returns required modules.
func (m *FERPAModule) Dependencies() []string {
	return []string{"scanner"}
}
