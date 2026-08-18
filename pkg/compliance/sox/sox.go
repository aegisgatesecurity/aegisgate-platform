// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOX Compliance Module
// =========================================================================
//
// Sarbanes-Oxley Act of 2002 (SOX) compliance controls as a licensed
// add-on module. Covers COSO Internal Control – Integrated Framework,
// ITGC controls, SOX legislative sections, data protection, financial
// reporting, whistleblower protection, and AI controls.
//
// Module metadata:
//   - Framework:     "sox"
//   - Version:       "2002"
//   - Required tier: Professional ($199/mo)
//   - Controls:      80 (27 automated, 53 manual)
//   - Categories:    15
//
// Architecture:
//   - sox.go:              module wiring, 80 RegisterControl calls,
//                          27 CheckFunc implementations
//   - sox_test.go:         unit tests
//   - tier_coverage_test.go: tier/framework tests
//
// Reference: Sarbanes-Oxley Act of 2002 (Pub.L. 107–204)
//            COSO Internal Control – Integrated Framework (2013)
// =========================================================================

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
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),                               // SSN
		regexp.MustCompile(`(?i)\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`),      // Credit card number
		regexp.MustCompile(`(?i)(?:routing|aba)\s*\d{9}`),                     // ABA routing
		regexp.MustCompile(`(?i)account\s*(?:number|#)?\s*[A-Za-z0-9]{6,20}`), // Financial account
		regexp.MustCompile(`(?i)sox\s*(?:compliant|control|section)`),         // SOX marker
	}
}

// ============================================================================
// Control Registration — 80 controls
// ============================================================================

// registerControls registers all SOX compliance controls.
func (m *SOXModule) registerControls() {
	// ── COSO Control Environment (CE) — 5 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CE-01",
		Name:        "Demonstrates commitment to integrity and ethical values",
		Description: "The organization demonstrates a commitment to integrity and ethical values.",
		Category:    "COSO Control Environment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"COSO Principle 1", "SOX Section 404"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CE-02",
		Name:        "Board independence and oversight",
		Description: "The board of directors demonstrates independence from management and exercises oversight.",
		Category:    "COSO Control Environment",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"COSO Principle 2", "SOX Section 301"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CE-03",
		Name:        "Organizational structure with appropriate authority and responsibility",
		Description: "Management establishes an organizational structure with appropriate authority and responsibility.",
		Category:    "COSO Control Environment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"COSO Principle 3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CE-04",
		Name:        "Commitment to competence",
		Description: "The organization demonstrates a commitment to attracting, developing, and retaining competent individuals.",
		Category:    "COSO Control Environment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"COSO Principle 4"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CE-05",
		Name:        "Accountability and enforcement of accountability",
		Description: "The organization holds individuals accountable for their internal control responsibilities.",
		Category:    "COSO Control Environment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkControlEnvironment,
		References:  []string{"COSO Principle 5", "SOX Section 404(a)"},
	})

	// ── COSO Risk Assessment (RA) — 4 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-RA-01",
		Name:        "Clear objectives to support risk identification",
		Description: "The organization specifies objectives with sufficient clarity to enable risk identification.",
		Category:    "COSO Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
		References:  []string{"COSO Principle 6", "SOX Section 404"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-RA-02",
		Name:        "Risk identification and analysis",
		Description: "The organization identifies and analyzes risk to the achievement of its objectives.",
		Category:    "COSO Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"COSO Principle 7"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-RA-03",
		Name:        "Fraud risk assessment",
		Description: "The organization considers the potential for fraud in assessing risks to the achievement of objectives.",
		Category:    "COSO Risk Assessment",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"COSO Principle 8", "SOX Section 404"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-RA-04",
		Name:        "Significant change identification",
		Description: "The organization identifies and assesses changes that could significantly impact the system of internal control.",
		Category:    "COSO Risk Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"COSO Principle 9"},
	})

	// ── COSO Control Activities (CA) — 3 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CA-01",
		Name:        "Selection and development of control activities",
		Description: "The organization selects and develops control activities that contribute to the mitigation of risks.",
		Category:    "COSO Control Activities",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"COSO Principle 10"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CA-02",
		Name:        "Policies and procedures deployed",
		Description: "The organization selects and develops general control activities over technology.",
		Category:    "COSO Control Activities",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"COSO Principle 11"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CA-03",
		Name:        "Technology controls deployed",
		Description: "The organization deploys control activities through policies and procedures in technology systems.",
		Category:    "COSO Control Activities",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkITSecurityControls,
		References:  []string{"COSO Principle 12"},
	})

	// ── COSO Information & Communication (IC) — 3 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-IC-01",
		Name:        "Relevant and quality information",
		Description: "The organization obtains or generates and uses relevant, quality information to support the functioning of internal control.",
		Category:    "COSO Information & Communication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataIntegrity,
		References:  []string{"COSO Principle 13"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-IC-02",
		Name:        "Internal communication",
		Description: "The organization internally communicates information necessary to support the functioning of internal control.",
		Category:    "COSO Information & Communication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"COSO Principle 14"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-IC-03",
		Name:        "External communication",
		Description: "The organization communicates with external parties regarding matters affecting the functioning of internal control.",
		Category:    "COSO Information & Communication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"COSO Principle 15"},
	})

	// ── COSO Monitoring Activities (MA) — 2 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-MA-01",
		Name:        "Ongoing evaluations",
		Description: "The organization conducts ongoing evaluations to ascertain whether internal control is present and functioning.",
		Category:    "COSO Monitoring Activities",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInternalControlAssessment,
		References:  []string{"COSO Principle 16"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-MA-02",
		Name:        "Separate evaluations",
		Description: "The organization conducts separate evaluations to ascertain whether internal control is present and functioning.",
		Category:    "COSO Monitoring Activities",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"COSO Principle 17"},
	})

	// ── ITGC - Access Management (AM) — 5 controls, 3 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AM-01",
		Name:        "User Access Provisioning",
		Description: "User access to financial systems is provisioned based on approved access requests.",
		Category:    "ITGC - Access Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFinancialAccessControls,
		References:  []string{"SOX ITGC - Access Management", "SOX Section 404"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AM-02",
		Name:        "User Access Review",
		Description: "User access to financial systems is periodically reviewed and recertified.",
		Category:    "ITGC - Access Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX ITGC - Access Management"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AM-03",
		Name:        "Privileged Access Management",
		Description: "Privileged access to financial systems is controlled and monitored.",
		Category:    "ITGC - Access Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPrivilegedAccess,
		References:  []string{"SOX ITGC - Access Management"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AM-04",
		Name:        "Authentication Mechanisms",
		Description: "Authentication mechanisms including MFA are deployed for financial system access.",
		Category:    "ITGC - Access Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuthentication,
		References:  []string{"SOX ITGC - Access Management"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AM-05",
		Name:        "Access Removal and Deprovisioning",
		Description: "User access is promptly removed upon termination or role change.",
		Category:    "ITGC - Access Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX ITGC - Access Management"},
	})

	// ── ITGC - Change Management (CM) — 5 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CM-01",
		Name:        "Change Request Authorization",
		Description: "All system changes require authorized change requests before implementation.",
		Category:    "ITGC - Change Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeManagement,
		References:  []string{"SOX ITGC - Change Management"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CM-02",
		Name:        "Change Testing and Approval",
		Description: "Changes are tested and approved before migration to production.",
		Category:    "ITGC - Change Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX ITGC - Change Management"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CM-03",
		Name:        "Emergency Change Controls",
		Description: "Emergency changes are controlled with post-implementation review and documentation.",
		Category:    "ITGC - Change Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX ITGC - Change Management"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CM-04",
		Name:        "Source Code Version Control",
		Description: "Source code is maintained under version control with audit trails.",
		Category:    "ITGC - Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Change Management"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CM-05",
		Name:        "Change Documentation",
		Description: "All changes are documented with business justification and approval records.",
		Category:    "ITGC - Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Change Management"},
	})

	// ── ITGC - Computer Operations (CO) — 5 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CO-01",
		Name:        "Backup and Recovery",
		Description: "Financial system backups are performed and recovery procedures are tested.",
		Category:    "ITGC - Computer Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBackupRecovery,
		References:  []string{"SOX ITGC - Computer Operations"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CO-02",
		Name:        "Job Scheduling and Processing",
		Description: "Scheduled jobs and batch processing for financial systems are controlled and monitored.",
		Category:    "ITGC - Computer Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Computer Operations"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CO-03",
		Name:        "Problem Management",
		Description: "Problem management processes ensure issues in financial systems are tracked and resolved.",
		Category:    "ITGC - Computer Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Computer Operations"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CO-04",
		Name:        "Environmental Controls",
		Description: "Environmental controls protect financial system infrastructure from physical threats.",
		Category:    "ITGC - Computer Operations",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"SOX ITGC - Computer Operations"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-CO-05",
		Name:        "Data Center Physical Security",
		Description: "Physical security controls protect data center facilities housing financial systems.",
		Category:    "ITGC - Computer Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Computer Operations"},
	})

	// ── ITGC - Program Development (PD) — 5 controls, 0 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PD-01",
		Name:        "System Development Life Cycle",
		Description: "A formal SDLC methodology is followed for financial system development.",
		Category:    "ITGC - Program Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Program Development"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PD-02",
		Name:        "Requirements Management",
		Description: "Requirements for financial systems are documented, reviewed, and approved.",
		Category:    "ITGC - Program Development",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"SOX ITGC - Program Development"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PD-03",
		Name:        "Testing and Quality Assurance",
		Description: "Financial systems undergo formal testing and quality assurance before deployment.",
		Category:    "ITGC - Program Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Program Development"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PD-04",
		Name:        "User Acceptance Testing",
		Description: "User acceptance testing is performed and documented for financial systems.",
		Category:    "ITGC - Program Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Program Development"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PD-05",
		Name:        "Data Migration Controls",
		Description: "Data migration controls ensure integrity of financial data during system conversions.",
		Category:    "ITGC - Program Development",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX ITGC - Program Development"},
	})

	// ── ITGC - Program Changes (PC) — 5 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PC-01",
		Name:        "Change Authorization",
		Description: "Program changes to financial systems require formal authorization.",
		Category:    "ITGC - Program Changes",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX ITGC - Program Changes"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PC-02",
		Name:        "Migration to Production",
		Description: "Migration of program changes to production is controlled and documented.",
		Category:    "ITGC - Program Changes",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX ITGC - Program Changes"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PC-03",
		Name:        "Rollback Procedures",
		Description: "Rollback procedures are in place for failed program changes.",
		Category:    "ITGC - Program Changes",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Program Changes"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PC-04",
		Name:        "Segregation of Duties",
		Description: "Segregation of duties is enforced between development, testing, and production migration.",
		Category:    "ITGC - Program Changes",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSegregationOfDuties,
		References:  []string{"SOX ITGC - Program Changes"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-PC-05",
		Name:        "Code Review",
		Description: "Code reviews are performed and documented for changes to financial systems.",
		Category:    "ITGC - Program Changes",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX ITGC - Program Changes"},
	})

	// ── SOX Legislative Sections — 10 controls, 3 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S201",
		Name:        "Auditor Independence",
		Description: "External auditor independence is maintained per SOX Section 201 requirements.",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Section 201"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S302",
		Name:        "Corporate Responsibility for Financial Reports",
		Description: "Corporate responsibility for financial reports is maintained per SOX Section 302.",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"SOX Section 302"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S401",
		Name:        "Reports on Form 10-K Disclosures",
		Description: "Disclosures on Form 10-K are complete and accurate per SOX Section 401.",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Section 401"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S404a",
		Name:        "Management Assessment of Internal Controls",
		Description: "Management assesses and reports on internal controls over financial reporting per SOX Section 404(a).",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkICAssessment,
		References:  []string{"SOX Section 404(a)"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S404b",
		Name:        "External Auditor Attestation on Internal Controls",
		Description: "External auditor attests to internal controls over financial reporting per SOX Section 404(b).",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Section 404(b)"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S409",
		Name:        "Real-Time Issuer Disclosure",
		Description: "Material events are disclosed on a rapid and current basis per SOX Section 409.",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRealTimeDisclosure,
		References:  []string{"SOX Section 409"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S802",
		Name:        "Records Retention",
		Description: "Records are retained for required periods per SOX Section 802.",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecordsRetention,
		References:  []string{"SOX Section 802"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S806",
		Name:        "Whistleblower Protection",
		Description: "Whistleblower protections are maintained per SOX Section 806.",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Section 806"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S906",
		Name:        "Corporate Responsibility for Financial Reports",
		Description: "Corporate responsibility for financial reports is certified per SOX Section 906.",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Section 906"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-S1107",
		Name:        "Fair Disclosure (Regulation FD)",
		Description: "Fair disclosure practices are followed per Regulation FD and SEC Rule 10b-5.",
		Category:    "SOX Legislative Sections",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"Regulation FD", "SEC Rule 10b-5"},
	})

	// ── Data Protection (DP) — 10 controls, 8 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-01",
		Name:        "Data Classification",
		Description: "Financial data is classified according to sensitivity and criticality.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataClassification,
		References:  []string{"SOX Data Protection"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-02",
		Name:        "Encryption at Rest",
		Description: "Financial data at rest is encrypted using industry-standard algorithms.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionAtRest,
		References:  []string{"SOX Data Protection"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-03",
		Name:        "Encryption in Transit",
		Description: "Financial data in transit is encrypted using TLS or equivalent protocols.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionInTransit,
		References:  []string{"SOX Data Protection"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-04",
		Name:        "Data Masking",
		Description: "Sensitive financial data is masked in non-production environments.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Data Protection"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-05",
		Name:        "Data Loss Prevention",
		Description: "Data loss prevention controls detect and prevent unauthorized exfiltration of financial data.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDLP,
		References:  []string{"SOX Data Protection"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-06",
		Name:        "Audit Logging",
		Description: "Audit logging is enabled for all financial system access and transactions.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditLogging,
		References:  []string{"SOX Data Protection"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-07",
		Name:        "Log Integrity",
		Description: "Audit log integrity is protected against tampering and unauthorized modification.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLogIntegrity,
		References:  []string{"SOX Data Protection"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-08",
		Name:        "Data Retention and Disposal",
		Description: "Financial data is retained and disposed of according to documented retention policies.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataRetentionDisposal,
		References:  []string{"SOX Data Protection", "SOX Section 802"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-09",
		Name:        "Segregation of Duties",
		Description: "Segregation of duties is enforced for financial data access and processing.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Data Protection"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-DP-10",
		Name:        "Reconciliation Controls",
		Description: "Financial data reconciliation controls ensure accuracy and completeness of records.",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkReconciliation,
		References:  []string{"SOX Data Protection"},
	})

	// ── Financial Reporting (FR) — 10 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-01",
		Name:        "Financial Statement Integrity",
		Description: "Financial statements are accurate, complete, and properly presented.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFinancialStatementIntegrity,
		References:  []string{"SOX Financial Reporting"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-02",
		Name:        "SEC Reporting Controls",
		Description: "SEC reporting controls ensure timely and accurate filings.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Financial Reporting", "SEC Form 10-K"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-03",
		Name:        "GAAP Compliance",
		Description: "Financial reporting complies with US Generally Accepted Accounting Principles.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Financial Reporting", "US GAAP"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-04",
		Name:        "Financial Close Process",
		Description: "The financial close process is controlled and documented.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Financial Reporting"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-05",
		Name:        "Journal Entry Controls",
		Description: "Journal entries are controlled with appropriate review and approval.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Financial Reporting"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-06",
		Name:        "Account Reconciliation",
		Description: "Account reconciliations are performed and reviewed on a regular basis.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Financial Reporting"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-07",
		Name:        "Financial Reporting Risk Assessment",
		Description: "Financial reporting risks are identified and assessed.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX Financial Reporting"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-08",
		Name:        "Disclosure Committee",
		Description: "A disclosure committee oversees financial reporting disclosures.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX Financial Reporting"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-09",
		Name:        "Materiality Assessment",
		Description: "Materiality is assessed for financial reporting and disclosure decisions.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX Financial Reporting"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-FR-10",
		Name:        "Subsequent Events Review",
		Description: "Subsequent events are reviewed for potential impact on financial statements.",
		Category:    "Financial Reporting",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX Financial Reporting"},
	})

	// ── Whistleblower Protection (WP) — 4 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-WP-01",
		Name:        "Whistleblower Protection Policy",
		Description: "A whistleblower protection policy is established and communicated per SOX Section 806.",
		Category:    "Whistleblower Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Section 806"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-WP-02",
		Name:        "Anonymous Reporting Mechanism",
		Description: "Anonymous reporting channels are available for reporting financial misconduct.",
		Category:    "Whistleblower Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAnonymousReporting,
		References:  []string{"SOX Section 806"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-WP-03",
		Name:        "Investigation Procedures",
		Description: "Procedures are in place for investigating whistleblower reports of financial misconduct.",
		Category:    "Whistleblower Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"SOX Section 806"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-WP-04",
		Name:        "Non-Retaliation Policy",
		Description: "A non-retaliation policy protects whistleblowers from adverse actions.",
		Category:    "Whistleblower Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX Section 806"},
	})

	// ── AI Controls (AI) — 4 controls, 3 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AI-01",
		Name:        "AI Model Financial Data Protection",
		Description: "AI models must not retain or expose financial reporting data.",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelFinancialProtection,
		References:  []string{"SOX AI Controls"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AI-02",
		Name:        "AI Audit Trail for Financial Reports",
		Description: "Audit trails are maintained for AI systems processing financial data.",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrailFinancial,
		References:  []string{"SOX AI Controls"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AI-03",
		Name:        "AI Model Governance for Financial Systems",
		Description: "AI models used in financial systems are governed with appropriate oversight.",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"SOX AI Controls"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "SOX-AI-04",
		Name:        "AI Output Validation for Financial Reporting",
		Description: "AI outputs used in financial reporting are validated for accuracy and completeness.",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIOutputValidation,
		References:  []string{"SOX AI Controls"},
	})
}

// ============================================================================
// Check Function Implementations — 27 automated checks
// ============================================================================

func (m *SOXModule) checkInternalControlAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasICAssessment := strings.Contains(inputStr, "internal_control_assessment") ||
		strings.Contains(inputStr, "icfr") ||
		strings.Contains(inputStr, "control_testing")

	if hasICAssessment {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-MA-01",
			ControlName: "Ongoing evaluations",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Internal control assessment over financial reporting detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-MA-01",
		ControlName: "Ongoing evaluations",
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
			ControlID:   "SOX-CE-05",
			ControlName: "Accountability and enforcement of accountability",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Strong control environment with governance policies detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-CE-05",
		ControlName: "Accountability and enforcement of accountability",
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
			ControlID:   "SOX-RA-01",
			ControlName: "Clear objectives to support risk identification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Enterprise risk assessment framework for financial reporting detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-RA-01",
		ControlName: "Clear objectives to support risk identification",
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
			ControlID:   "SOX-FR-01",
			ControlName: "Financial Statement Integrity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Financial statement integrity and accuracy controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-FR-01",
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
			ControlID:   "SOX-S409",
			ControlName: "Real-Time Issuer Disclosure",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Real-time disclosure controls for material events detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-S409",
		ControlName: "Real-Time Issuer Disclosure",
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
			ControlID:   "SOX-S802",
			ControlName: "Records Retention",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Records retention controls per Section 802 detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-S802",
		ControlName: "Records Retention",
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
			ControlID:   "SOX-IC-01",
			ControlName: "Relevant and quality information",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data integrity controls for financial information detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-IC-01",
		ControlName: "Relevant and quality information",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Data integrity controls for financial information not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement data integrity controls including reconciliation and validation for financial information",
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
			ControlID:   "SOX-AM-01",
			ControlName: "User Access Provisioning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Full RBAC and MFA access controls for financial systems detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if found > 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-AM-01",
			ControlName: "User Access Provisioning",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial access controls for financial systems detected",
			Timestamp:   time.Now(),
			Remediation: "Implement complete RBAC and MFA access controls for all financial systems",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-AM-01",
		ControlName: "User Access Provisioning",
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
			ControlID:   "SOX-CM-01",
			ControlName: "Change Request Authorization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Change management process controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-CM-01",
		ControlName: "Change Request Authorization",
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
			ControlID:   "SOX-CA-03",
			ControlName: "Technology controls deployed",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "IT security controls for financial systems detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-CA-03",
		ControlName: "Technology controls deployed",
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
			ControlID:   "SOX-CO-01",
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
			ControlID:   "SOX-CO-01",
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
		ControlID:   "SOX-CO-01",
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
			ControlID:   "SOX-WP-02",
			ControlName: "Anonymous Reporting Mechanism",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Anonymous reporting mechanism for financial misconduct detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-WP-02",
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
			ControlID:   "SOX-AI-01",
			ControlName: "AI Model Financial Data Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No financial data patterns detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-AI-01",
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
			ControlID:   "SOX-AI-02",
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
			ControlID:   "SOX-AI-02",
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
		ControlID:   "SOX-AI-02",
		ControlName: "AI Audit Trail for Financial Reports",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI audit trail controls for financial reporting not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement AI audit trail, model logging, and financial audit trail for all AI systems processing financial data",
	}, nil
}

func (m *SOXModule) checkPrivilegedAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPrivilegedAccess := strings.Contains(inputStr, "privileged_access") ||
		strings.Contains(inputStr, "pam") ||
		strings.Contains(inputStr, "root_access") ||
		strings.Contains(inputStr, "admin_access") ||
		strings.Contains(inputStr, "sudo")

	if hasPrivilegedAccess {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-AM-03",
			ControlName: "Privileged Access Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Privileged access management controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-AM-03",
		ControlName: "Privileged Access Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Privileged access management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement privileged access management with PAM, root access controls, and admin access monitoring",
	}, nil
}

func (m *SOXModule) checkAuthentication(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuthentication := strings.Contains(inputStr, "authentication") ||
		strings.Contains(inputStr, "mfa") ||
		strings.Contains(inputStr, "multi_factor") ||
		strings.Contains(inputStr, "sso") ||
		strings.Contains(inputStr, "auth_enabled")

	if hasAuthentication {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-AM-04",
			ControlName: "Authentication Mechanisms",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Authentication mechanisms including MFA detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-AM-04",
		ControlName: "Authentication Mechanisms",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Authentication mechanisms not detected",
		Timestamp:   time.Now(),
		Remediation: "Deploy authentication mechanisms including MFA and SSO for financial system access",
	}, nil
}

func (m *SOXModule) checkSegregationOfDuties(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSOD := strings.Contains(inputStr, "segregation_of_duties") ||
		strings.Contains(inputStr, "sod") ||
		strings.Contains(inputStr, "dual_control") ||
		strings.Contains(inputStr, "split_separation")

	if hasSOD {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-PC-04",
			ControlName: "Segregation of Duties",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Segregation of duties controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-PC-04",
		ControlName: "Segregation of Duties",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Segregation of duties controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement segregation of duties between development, testing, and production migration",
	}, nil
}

func (m *SOXModule) checkICAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasICAssessment := strings.Contains(inputStr, "internal_control_assessment") ||
		strings.Contains(inputStr, "icfr") ||
		strings.Contains(inputStr, "section_404") ||
		strings.Contains(inputStr, "management_assessment") ||
		strings.Contains(inputStr, "control_testing")

	if hasICAssessment {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-S404a",
			ControlName: "Management Assessment of Internal Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Management assessment of internal controls per SOX Section 404(a) detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-S404a",
		ControlName: "Management Assessment of Internal Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Management assessment of internal controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement management assessment of internal controls over financial reporting per SOX Section 404(a)",
	}, nil
}

func (m *SOXModule) checkDataClassification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasClassification := strings.Contains(inputStr, "data_classification") ||
		strings.Contains(inputStr, "classification_scheme") ||
		strings.Contains(inputStr, "data_categorization") ||
		strings.Contains(inputStr, "sensitive_data")

	if hasClassification {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-01",
			ControlName: "Data Classification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data classification controls for financial data detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-01",
		ControlName: "Data Classification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Data classification controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement data classification scheme for financial data based on sensitivity and criticality",
	}, nil
}

func (m *SOXModule) checkEncryptionAtRest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptionAtRest := strings.Contains(inputStr, "encryption_at_rest") ||
		strings.Contains(inputStr, "data_encrypted") ||
		strings.Contains(inputStr, "aes") ||
		strings.Contains(inputStr, "at_rest_encryption")

	if hasEncryptionAtRest {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-02",
			ControlName: "Encryption at Rest",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Encryption at rest for financial data detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-02",
		ControlName: "Encryption at Rest",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Encryption at rest for financial data not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement encryption at rest using AES or equivalent for all financial data",
	}, nil
}

func (m *SOXModule) checkEncryptionInTransit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptionInTransit := strings.Contains(inputStr, "tls") ||
		strings.Contains(inputStr, "tls1.2") ||
		strings.Contains(inputStr, "tls1.3") ||
		strings.Contains(inputStr, "https") ||
		strings.Contains(inputStr, "encryption_in_transit") ||
		strings.Contains(inputStr, "in_transit")

	if hasEncryptionInTransit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-03",
			ControlName: "Encryption in Transit",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Encryption in transit for financial data detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-03",
		ControlName: "Encryption in Transit",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Encryption in transit for financial data not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement TLS 1.2+ or HTTPS for all financial data in transit",
	}, nil
}

func (m *SOXModule) checkDLP(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDLP := strings.Contains(inputStr, "dlp") ||
		strings.Contains(inputStr, "data_loss_prevention") ||
		strings.Contains(inputStr, "data_leak_prevention") ||
		strings.Contains(inputStr, "exfiltration")

	if hasDLP {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-05",
			ControlName: "Data Loss Prevention",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data loss prevention controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-05",
		ControlName: "Data Loss Prevention",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Data loss prevention controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement DLP controls to detect and prevent unauthorized exfiltration of financial data",
	}, nil
}

func (m *SOXModule) checkAuditLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLogging := strings.Contains(inputStr, "audit_log") ||
		strings.Contains(inputStr, "logging_enabled") ||
		strings.Contains(inputStr, "audit_enabled") ||
		strings.Contains(inputStr, "log_management")

	if hasAuditLogging {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-06",
			ControlName: "Audit Logging",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit logging for financial system access detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-06",
		ControlName: "Audit Logging",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit logging for financial system access not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable audit logging for all financial system access and transactions",
	}, nil
}

func (m *SOXModule) checkLogIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLogIntegrity := strings.Contains(inputStr, "log_integrity") ||
		strings.Contains(inputStr, "hash_chain") ||
		strings.Contains(inputStr, "log_tampering") ||
		strings.Contains(inputStr, "log_protection") ||
		strings.Contains(inputStr, "immutable_log")

	if hasLogIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-07",
			ControlName: "Log Integrity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit log integrity controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-07",
		ControlName: "Log Integrity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit log integrity controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement log integrity controls using hash chains or immutable log storage",
	}, nil
}

func (m *SOXModule) checkDataRetentionDisposal(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRetentionDisposal := strings.Contains(inputStr, "data_retention") ||
		strings.Contains(inputStr, "retention_policy") ||
		strings.Contains(inputStr, "retention_schedule") ||
		strings.Contains(inputStr, "data_disposal")

	if hasRetentionDisposal {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-08",
			ControlName: "Data Retention and Disposal",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data retention and disposal controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-08",
		ControlName: "Data Retention and Disposal",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Data retention and disposal controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement documented data retention and disposal policies for financial data",
	}, nil
}

func (m *SOXModule) checkReconciliation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReconciliation := strings.Contains(inputStr, "reconciliation") ||
		strings.Contains(inputStr, "account_reconciliation") ||
		strings.Contains(inputStr, "data_validation") ||
		strings.Contains(inputStr, "financial_reconciliation")

	if hasReconciliation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-DP-10",
			ControlName: "Reconciliation Controls",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Financial data reconciliation controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-DP-10",
		ControlName: "Reconciliation Controls",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Financial data reconciliation controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement reconciliation controls including account reconciliation and data validation for financial data",
	}, nil
}

func (m *SOXModule) checkAIOutputValidation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAIOutputValidation := strings.Contains(inputStr, "ai_output_validation") ||
		strings.Contains(inputStr, "output_validation") ||
		strings.Contains(inputStr, "model_validation") ||
		strings.Contains(inputStr, "ai_verification")

	if hasAIOutputValidation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "SOX-AI-04",
			ControlName: "AI Output Validation for Financial Reporting",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI output validation controls for financial reporting detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "SOX-AI-04",
		ControlName: "AI Output Validation for Financial Reporting",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI output validation controls for financial reporting not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement AI output validation including model validation and verification for financial reporting",
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
