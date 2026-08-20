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
	// =====================================================
	// Student Education Records (ER) — 8 controls (6 auto, 2 manual)
	// =====================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-01",
		Name:        "Education Records Access",
		Description: "Students have the right to access their education records under FERPA",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEducationRecordsAccess,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-02",
		Name:        "Record Amendment Rights",
		Description: "Students can request amendment of inaccurate or misleading education records",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecordAmendment,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-03",
		Name:        "Record Destruction Policy",
		Description: "Institutions must have policies for destroying education records when no longer needed",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecordDestruction,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-04",
		Name:        "Right to Inspect Records",
		Description: "Students and eligible parents must be able to inspect and review education records within 45 days of a request",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRightToInspectRecords,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-05",
		Name:        "Records Custodian Designation",
		Description: "Institution must designate an official custodian of education records responsible for FERPA compliance",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRecordsCustodian,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-06",
		Name:        "Annual Notification of Rights",
		Description: "Institution must provide annual notification to students of their FERPA rights",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAnnualNotificationOfRights,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-07",
		Name:        "Record Access Log",
		Description: "Maintain a log of all parties who have accessed student education records",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecordAccessLog,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-ER-08",
		Name:        "Records Retention Schedule",
		Description: "Institution must establish and document a records retention schedule for all education records",
		Category:    "Student Education Records",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRecordsRetentionSchedule,
	})

	// =====================================================
	// Directory Information (DI) — 6 controls (5 auto, 1 manual)
	// =====================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DI-01",
		Name:        "Directory Information Classification",
		Description: "Institutions must classify which data elements constitute directory information",
		Category:    "Directory Information",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDirectoryInfoClassification,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DI-02",
		Name:        "Opt-Out Mechanism",
		Description: "Students must be able to opt out of directory information disclosure",
		Category:    "Directory Information",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkOptOutMechanism,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DI-03",
		Name:        "Disclosure Consent",
		Description: "Written consent required before disclosing non-directory PII from education records",
		Category:    "Directory Information",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDisclosureConsent,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DI-04",
		Name:        "Annual Directory Information Notice",
		Description: "Institution must provide annual notice of directory information categories and opt-out rights",
		Category:    "Directory Information",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAnnualDirectoryInfoNotice,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DI-05",
		Name:        "Directory Info Disclosure Tracking",
		Description: "Track and log all disclosures of directory information to third parties",
		Category:    "Directory Information",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDirectoryInfoDisclosureTracking,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DI-06",
		Name:        "Limited Directory Information Policy",
		Description: "Institution must establish a policy defining limited directory information categories for specific disclosures",
		Category:    "Directory Information",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	// =====================================================
	// Consent & Disclosure (CD) — 8 controls (5 auto, 3 manual)
	// =====================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-01",
		Name:        "Authorized Disclosure",
		Description: "Only authorized disclosures under FERPA exceptions are permitted without written consent",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuthorizedDisclosure,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-02",
		Name:        "Health/Safety Exception",
		Description: "Emergency disclosure of education records allowed for health and safety purposes",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkHealthSafetyException,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-03",
		Name:        "Law Enforcement Unit Records",
		Description: "Separate records must be maintained for campus law enforcement unit records under FERPA",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLawEnforcementRecords,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-04",
		Name:        "School Official Exception",
		Description: "Disclosures to school officials with legitimate educational interest must be documented and controlled",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSchoolOfficialException,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-05",
		Name:        "Transfer School Enrollment",
		Description: "Education records may be transferred to a school where the student enrolls or intends to enroll",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTransferSchoolEnrollment,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-06",
		Name:        "Financial Aid Disclosure",
		Description: "Disclosure of education records for financial aid purposes must be limited to necessary parties",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-07",
		Name:        "Accrediting Organization Disclosure",
		Description: "Disclosure to accrediting organizations must be documented and limited to accreditation purposes",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CD-08",
		Name:        "Court Order/Subpoena Compliance",
		Description: "Institution must have procedures for responding to court orders and subpoenas for education records",
		Category:    "Consent & Disclosure",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	// =====================================================
	// Data Security (DS) — 8 controls (5 auto, 3 manual)
	// =====================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-01",
		Name:        "Administrative Data Safeguards",
		Description: "Administrative safeguards for protecting education records including governance and access controls",
		Category:    "Data Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAdministrativeSafeguards,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-02",
		Name:        "Physical Data Safeguards",
		Description: "Physical security of education record storage (customer responsibility)",
		Category:    "Data Security",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-03",
		Name:        "Technical Data Safeguards",
		Description: "Technical controls including encryption, access logs, and multi-factor authentication for education records",
		Category:    "Data Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkTechnicalSafeguards,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-04",
		Name:        "Encryption of Education Records",
		Description: "Education records must be encrypted at rest and in transit to protect student PII",
		Category:    "Data Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionOfEducationRecords,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-05",
		Name:        "Access Control for Education Records",
		Description: "Role-based access controls must restrict education record access to authorized personnel only",
		Category:    "Data Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessControlForEducationRecords,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-06",
		Name:        "Data Breach Response Plan",
		Description: "Institution must maintain a documented data breach response plan for education records",
		Category:    "Data Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBreachResponsePlan,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-07",
		Name:        "Third-Party Service Provider Security",
		Description: "Third-party service providers handling education records must meet FERPA security requirements",
		Category:    "Data Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-DS-08",
		Name:        "Data Minimization for Education Records",
		Description: "Only the minimum necessary education record data should be collected, stored, and shared",
		Category:    "Data Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDataMinimizationForEducationRecords,
	})

	// =====================================================
	// AI Controls (AI) — 6 controls (5 auto, 1 manual)
	// =====================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-01",
		Name:        "AI Model Student Data Protection",
		Description: "AI models must not retain or expose student PII from education records",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelStudentDataProtection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-02",
		Name:        "AI Training Data Consent",
		Description: "Explicit consent required before using student data for AI training purposes",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAITrainingDataConsent,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-03",
		Name:        "AI Audit Trail for Education Records",
		Description: "Audit logging required for AI interactions involving education records",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrail,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-04",
		Name:        "AI Bias Detection in Education",
		Description: "Detect and mitigate bias in AI systems making education-related decisions",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIBiasDetection,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-05",
		Name:        "AI-Generated Content Disclosure for Education",
		Description: "AI-generated content in education records must be disclosed and labeled as AI-generated",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIGeneratedContentDisclosure,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-AI-06",
		Name:        "AI Model Retraining with Student Data Governance",
		Description: "Governance controls for AI model retraining using student data including approval and review processes",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIRetrainingGovernance,
	})

	// =====================================================
	// Compliance & Enforcement (CE) — 9 controls (5 auto, 4 manual)
	// =====================================================

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CE-01",
		Name:        "FERPA Designation",
		Description: "Institution must formally designate FERPA compliance responsibilities and accountable personnel",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFERPADesignation,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CE-02",
		Name:        "Policy Documentation",
		Description: "Institution must maintain documented FERPA policies and procedures available to all stakeholders",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPolicyDocumentation,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CE-03",
		Name:        "Training Program for Staff",
		Description: "Annual FERPA training must be provided to all staff with access to education records",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTrainingProgramForStaff,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CE-04",
		Name:        "Internal Compliance Audits",
		Description: "Regular internal audits must be conducted to verify FERPA compliance across the institution",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInternalComplianceAudits,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CE-05",
		Name:        "Student Complaint Process",
		Description: "Institution must provide a process for students to file FERPA complaints internally",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkStudentComplaintProcess,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CE-06",
		Name:        "DOE Complaint Investigation",
		Description: "Institution must cooperate with U.S. Department of Education FERPA complaint investigations",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CE-07",
		Name:        "Corrective Action Plans",
		Description: "Institution must develop and implement corrective action plans for FERPA violations",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CE-08",
		Name:        "FERPA Affidavit Requirements",
		Description: "Institution must maintain FERPA affidavits for third-party disclosures of education records",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FERPA-CE-09",
		Name:        "State Education Authority Reporting",
		Description: "Institution must report FERPA compliance status to state education authorities as required",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
	})
}

// =====================================================
// Check implementations — Student Education Records (ER)
// =====================================================

func (m *FERPAModule) checkEducationRecordsAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRecordsAccess := strings.Contains(inputStr, "education_records_access") || strings.Contains(inputStr, "student_access") || strings.Contains(inputStr, "records_access_policy")

	if hasRecordsAccess {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-ER-01",
			ControlName: "Education Records Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Education records access and student access controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-ER-01",
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
			ControlID:   "FERPA-ER-02",
			ControlName: "Record Amendment Rights",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Record amendment and dispute resolution controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-ER-02",
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
			ControlID:   "FERPA-ER-03",
			ControlName: "Record Destruction Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Record destruction and secure disposal controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-ER-03",
		ControlName: "Record Destruction Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Record destruction policy not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement record destruction and secure disposal policies for education records no longer needed",
	}, nil
}

func (m *FERPAModule) checkRightToInspectRecords(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInspect := strings.Contains(inputStr, "inspect_records") || strings.Contains(inputStr, "review_records") || strings.Contains(inputStr, "right_to_inspect")

	if hasInspect {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-ER-04",
			ControlName: "Right to Inspect Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Right to inspect and review education records controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-ER-04",
		ControlName: "Right to Inspect Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Right to inspect records controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement procedures allowing students to inspect and review education records within 45 days of request per FERPA",
	}, nil
}

func (m *FERPAModule) checkAnnualNotificationOfRights(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasNotification := strings.Contains(inputStr, "annual_notification") || strings.Contains(inputStr, "ferpa_rights_notice") || strings.Contains(inputStr, "student_rights_notification")

	if hasNotification {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-ER-06",
			ControlName: "Annual Notification of Rights",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Annual notification of FERPA rights controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-ER-06",
		ControlName: "Annual Notification of Rights",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Annual notification of FERPA rights not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement annual notification to students of their FERPA rights per 34 CFR 99.7",
	}, nil
}

func (m *FERPAModule) checkRecordAccessLog(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccessLog := strings.Contains(inputStr, "record_access_log") || strings.Contains(inputStr, "access_log") || strings.Contains(inputStr, "disclosure_log")

	if hasAccessLog {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-ER-07",
			ControlName: "Record Access Log",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Record access logging controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-ER-07",
		ControlName: "Record Access Log",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Record access logging controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement access logging for all parties who access or request student education records per FERPA",
	}, nil
}

// =====================================================
// Check implementations — Directory Information (DI)
// =====================================================

func (m *FERPAModule) checkDirectoryInfoClassification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDirectoryInfo := strings.Contains(inputStr, "directory_information") || strings.Contains(inputStr, "public_directory") || strings.Contains(inputStr, "student_directory")

	if hasDirectoryInfo {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DI-01",
			ControlName: "Directory Information Classification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Directory information classification controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DI-01",
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
			ControlID:   "FERPA-DI-02",
			ControlName: "Opt-Out Mechanism",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Directory information opt-out mechanism detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DI-02",
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
			ControlID:   "FERPA-DI-03",
			ControlName: "Disclosure Consent",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Written disclosure consent controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DI-03",
		ControlName: "Disclosure Consent",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Disclosure consent controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement written consent requirement before disclosing non-directory PII per FERPA",
	}, nil
}

func (m *FERPAModule) checkAnnualDirectoryInfoNotice(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasNotice := strings.Contains(inputStr, "directory_info_notice") || strings.Contains(inputStr, "annual_directory_notice") || strings.Contains(inputStr, "directory_categories_notice")

	if hasNotice {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DI-04",
			ControlName: "Annual Directory Information Notice",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Annual directory information notice controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DI-04",
		ControlName: "Annual Directory Information Notice",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Annual directory information notice not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement annual notice of directory information categories and opt-out rights per FERPA 34 CFR 99.37",
	}, nil
}

func (m *FERPAModule) checkDirectoryInfoDisclosureTracking(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTracking := strings.Contains(inputStr, "disclosure_tracking") || strings.Contains(inputStr, "directory_disclosure_log") || strings.Contains(inputStr, "third_party_disclosure_log")

	if hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DI-05",
			ControlName: "Directory Info Disclosure Tracking",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Directory information disclosure tracking controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DI-05",
		ControlName: "Directory Info Disclosure Tracking",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Directory information disclosure tracking not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement tracking and logging of all directory information disclosures to third parties per FERPA",
	}, nil
}

// =====================================================
// Check implementations — Consent & Disclosure (CD)
// =====================================================

func (m *FERPAModule) checkAuthorizedDisclosure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuthDisclosure := strings.Contains(inputStr, "authorized_disclosure") || strings.Contains(inputStr, "disclosure_policy") || strings.Contains(inputStr, "ferpa_exceptions")

	if hasAuthDisclosure {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CD-01",
			ControlName: "Authorized Disclosure",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Authorized disclosure and FERPA exceptions controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CD-01",
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
			ControlID:   "FERPA-CD-02",
			ControlName: "Health/Safety Exception",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Health and safety emergency disclosure controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CD-02",
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
			ControlID:   "FERPA-CD-03",
			ControlName: "Law Enforcement Unit Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Law enforcement unit record separation controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CD-03",
		ControlName: "Law Enforcement Unit Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Law enforcement unit record controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement separate records for campus law enforcement unit per FERPA requirements",
	}, nil
}

func (m *FERPAModule) checkSchoolOfficialException(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSchoolOfficial := strings.Contains(inputStr, "school_official_exception") || strings.Contains(inputStr, "legitimate_educational_interest") || strings.Contains(inputStr, "school_official_disclosure")

	if hasSchoolOfficial {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CD-04",
			ControlName: "School Official Exception",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "School official exception and legitimate educational interest controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CD-04",
		ControlName: "School Official Exception",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "School official exception controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement documented school official exception with legitimate educational interest criteria per 34 CFR 99.31(a)(1)",
	}, nil
}

func (m *FERPAModule) checkTransferSchoolEnrollment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTransfer := strings.Contains(inputStr, "transfer_enrollment") || strings.Contains(inputStr, "records_transfer") || strings.Contains(inputStr, "school_transfer_disclosure")

	if hasTransfer {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CD-05",
			ControlName: "Transfer School Enrollment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Transfer school enrollment disclosure controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CD-05",
		ControlName: "Transfer School Enrollment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Transfer school enrollment disclosure controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement procedures for transferring education records to schools where students enroll per 34 CFR 99.31(a)(2)",
	}, nil
}

// =====================================================
// Check implementations — Data Security (DS)
// =====================================================

func (m *FERPAModule) checkAdministrativeSafeguards(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAdminSafeguards := strings.Contains(inputStr, "administrative_safeguards") || strings.Contains(inputStr, "data_governance") || strings.Contains(inputStr, "access_controls")

	if hasAdminSafeguards {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DS-01",
			ControlName: "Administrative Data Safeguards",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Administrative safeguards for education records detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DS-01",
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
			ControlID:   "FERPA-DS-03",
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
			ControlID:   "FERPA-DS-03",
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
		ControlID:   "FERPA-DS-03",
		ControlName: "Technical Data Safeguards",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No technical safeguards for education records detected",
		Timestamp:   time.Now(),
		Remediation: "Implement encryption at rest, audit logging, and multi-factor authentication for education records per FERPA",
	}, nil
}

func (m *FERPAModule) checkEncryptionOfEducationRecords(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_at_rest_encrypted")
	hasInTransit := strings.Contains(inputStr, "encryption_in_transit") || strings.Contains(inputStr, "tls_enabled") || strings.Contains(inputStr, "data_in_transit_encrypted")

	if hasAtRest && hasInTransit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DS-04",
			ControlName: "Encryption of Education Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Encryption of education records at rest and in transit detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasAtRest || hasInTransit {
		missing := []string{}
		if !hasAtRest {
			missing = append(missing, "encryption at rest")
		}
		if !hasInTransit {
			missing = append(missing, "encryption in transit")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DS-04",
			ControlName: "Encryption of Education Records",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial encryption controls: missing " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Implement encryption for education records both at rest and in transit per FERPA security requirements",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DS-04",
		ControlName: "Encryption of Education Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Encryption of education records not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement encryption at rest and in transit for all education records containing student PII per FERPA",
	}, nil
}

func (m *FERPAModule) checkAccessControlForEducationRecords(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccessControl := strings.Contains(inputStr, "role_based_access") || strings.Contains(inputStr, "rbac_education_records") || strings.Contains(inputStr, "access_control_policy")

	if hasAccessControl {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DS-05",
			ControlName: "Access Control for Education Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Role-based access controls for education records detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DS-05",
		ControlName: "Access Control for Education Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Access controls for education records not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement role-based access controls restricting education record access to authorized personnel per FERPA",
	}, nil
}

func (m *FERPAModule) checkDataMinimizationForEducationRecords(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMinimization := strings.Contains(inputStr, "data_minimization") || strings.Contains(inputStr, "minimum_necessary_data") || strings.Contains(inputStr, "data_collection_limit")

	if hasMinimization {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-DS-08",
			ControlName: "Data Minimization for Education Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Data minimization controls for education records detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-DS-08",
		ControlName: "Data Minimization for Education Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Data minimization controls for education records not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement data minimization policies ensuring only necessary education record data is collected and stored per FERPA",
	}, nil
}

// =====================================================
// Check implementations — AI Controls (AI)
// =====================================================

func (m *FERPAModule) checkAIModelStudentDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	piiFound := m.detectStudentPII(string(input))

	if len(piiFound) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-AI-01",
			ControlName: "AI Model Student Data Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No student PII detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-AI-01",
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
			ControlID:   "FERPA-AI-02",
			ControlName: "AI Training Data Consent",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI training data consent controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-AI-02",
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
			ControlID:   "FERPA-AI-03",
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
			ControlID:   "FERPA-AI-03",
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
		ControlID:   "FERPA-AI-03",
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
			ControlID:   "FERPA-AI-04",
			ControlName: "AI Bias Detection in Education",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI bias detection and equity review controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-AI-04",
		ControlName: "AI Bias Detection in Education",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI bias detection controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement bias detection and fairness audit for AI systems making education-related decisions",
	}, nil
}

func (m *FERPAModule) checkAIGeneratedContentDisclosure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasContentDisclosure := strings.Contains(inputStr, "ai_content_disclosure") || strings.Contains(inputStr, "ai_generated_label") || strings.Contains(inputStr, "ai_content_attribution")

	if hasContentDisclosure {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-AI-05",
			ControlName: "AI-Generated Content Disclosure for Education",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI-generated content disclosure and labeling controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-AI-05",
		ControlName: "AI-Generated Content Disclosure for Education",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI-generated content disclosure controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement disclosure and labeling of AI-generated content in education records per FERPA requirements",
	}, nil
}

// =====================================================
// Check implementations — Compliance & Enforcement (CE)
// =====================================================

func (m *FERPAModule) checkFERPADesignation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDesignation := strings.Contains(inputStr, "ferpa_designation") || strings.Contains(inputStr, "ferpa_officer") || strings.Contains(inputStr, "compliance_designation")

	if hasDesignation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CE-01",
			ControlName: "FERPA Designation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "FERPA compliance designation and accountable personnel detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CE-01",
		ControlName: "FERPA Designation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "FERPA compliance designation not detected",
		Timestamp:   time.Now(),
		Remediation: "Designate an official responsible for FERPA compliance and document accountability per FERPA requirements",
	}, nil
}

func (m *FERPAModule) checkPolicyDocumentation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicyDocs := strings.Contains(inputStr, "ferpa_policy") || strings.Contains(inputStr, "policy_documentation") || strings.Contains(inputStr, "ferpa_procedures")

	if hasPolicyDocs {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CE-02",
			ControlName: "Policy Documentation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "FERPA policy documentation and procedures detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CE-02",
		ControlName: "Policy Documentation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "FERPA policy documentation not detected",
		Timestamp:   time.Now(),
		Remediation: "Maintain documented FERPA policies and procedures available to all stakeholders per FERPA requirements",
	}, nil
}

func (m *FERPAModule) checkTrainingProgramForStaff(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTraining := strings.Contains(inputStr, "ferpa_training") || strings.Contains(inputStr, "staff_training_program") || strings.Contains(inputStr, "annual_training")

	if hasTraining {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CE-03",
			ControlName: "Training Program for Staff",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "FERPA staff training program controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CE-03",
		ControlName: "Training Program for Staff",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "FERPA staff training program not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement annual FERPA training for all staff with access to education records per FERPA best practices",
	}, nil
}

func (m *FERPAModule) checkInternalComplianceAudits(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudits := strings.Contains(inputStr, "internal_compliance_audit") || strings.Contains(inputStr, "ferpa_audit") || strings.Contains(inputStr, "compliance_review")

	if hasAudits {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CE-04",
			ControlName: "Internal Compliance Audits",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Internal FERPA compliance audit controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CE-04",
		ControlName: "Internal Compliance Audits",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Internal FERPA compliance audit controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement regular internal audits to verify FERPA compliance across the institution per FERPA best practices",
	}, nil
}

func (m *FERPAModule) checkStudentComplaintProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasComplaintProcess := strings.Contains(inputStr, "student_complaint_process") || strings.Contains(inputStr, "ferpa_complaint") || strings.Contains(inputStr, "grievance_procedure")

	if hasComplaintProcess {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FERPA-CE-05",
			ControlName: "Student Complaint Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Student FERPA complaint process controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FERPA-CE-05",
		ControlName: "Student Complaint Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Student FERPA complaint process not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement a process for students to file FERPA complaints internally with clear procedures and timelines",
	}, nil
}

// =====================================================
// Helper functions
// =====================================================

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

// ============================================================================
// Promoted CheckFunc implementations — P4 Compliance Automation Expansion
// ============================================================================

func (m *FERPAModule) checkRecordsCustodian(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCustodian := strings.Contains(inputStr, "records_custodian") || strings.Contains(inputStr, "data_custodian") || strings.Contains(inputStr, "ferpa_custodian")
	if hasCustodian {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FERPA-ER-05", ControlName: "Records Custodian Designation", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Records custodian designation detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FERPA-ER-05", ControlName: "Records Custodian Designation", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Records custodian not detected", Timestamp: time.Now(), Remediation: "Designate a records custodian for FERPA compliance"}, nil
}

func (m *FERPAModule) checkRecordsRetentionSchedule(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSchedule := strings.Contains(inputStr, "retention_schedule") || strings.Contains(inputStr, "records_retention") || strings.Contains(inputStr, "retention_policy")
	if hasSchedule {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FERPA-ER-08", ControlName: "Records Retention Schedule", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Records retention schedule detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FERPA-ER-08", ControlName: "Records Retention Schedule", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Records retention schedule not detected", Timestamp: time.Now(), Remediation: "Establish a records retention schedule"}, nil
}

func (m *FERPAModule) checkBreachResponsePlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPlan := strings.Contains(inputStr, "breach_response_plan") || strings.Contains(inputStr, "data_breach_response") || strings.Contains(inputStr, "breach_response")
	if hasPlan {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FERPA-DS-06", ControlName: "Data Breach Response Plan", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Data breach response plan detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FERPA-DS-06", ControlName: "Data Breach Response Plan", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Data breach response plan not detected", Timestamp: time.Now(), Remediation: "Implement a data breach response plan"}, nil
}

func (m *FERPAModule) checkAIRetrainingGovernance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasGovernance := strings.Contains(inputStr, "ai_retraining_governance") || strings.Contains(inputStr, "retraining_governance") || strings.Contains(inputStr, "model_retraining")
	hasApproval := strings.Contains(inputStr, "retraining_approval") || strings.Contains(inputStr, "retraining_review") || strings.Contains(inputStr, "retraining_oversight")
	if hasGovernance && hasApproval {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FERPA-AI-06", ControlName: "AI Model Retraining with Student Data Governance", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "AI retraining governance detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasGovernance {
		violations = append(violations, "retraining governance not configured")
	}
	if !hasApproval {
		violations = append(violations, "retraining approval not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "FERPA-AI-06", ControlName: "AI Model Retraining with Student Data Governance", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "AI retraining gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement AI retraining governance with approval"}, nil
}
