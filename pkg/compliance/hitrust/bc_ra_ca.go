// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HITRUST CSF BC/RA/CA Families
// =========================================================================
//
// HITRUST CSF v11.2 — Business Continuity (BC), Regulatory Assessment (RA),
// and Change Management (CA) families.
//
// In-scope controls (30 total: 12 automated + 18 manual):
//
//   BC (Business Continuity): 10 controls (5 automated + 5 manual)
//   RA (Regulatory Assessment): 10 controls (2 automated + 8 manual)
//   CA (Change Management): 10 controls (5 automated + 5 manual)
//
// =========================================================================

package hitrust

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerBCRACAControls wires the BC, RA, and CA family controls into the module.
func (m *HITRUSTModule) registerBCRACAControls() {
	m.registerBCControls()
	m.registerRAControls()
	m.registerCAControls()
}

// ── BC: Business Continuity ───────────────────────────────────────

// registerBCControls wires the BC family controls.
func (m *HITRUSTModule) registerBCControls() {
	// BC-01: Contingency Planning Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-01",
		Name:        "Contingency Planning Policy",
		Description: "HITRUST CSF v11.2 BC-01: Contingency planning policy documented and reviewed",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-1"},
	})

	// BC-02: Contingency Plan (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-02",
		Name:        "Contingency Plan",
		Description: "HITRUST CSF v11.2 BC-02: Contingency plan documented — recovery procedures, roles, and responsibilities",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-2"},
	})

	// BC-03: Contingency Training (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-03",
		Name:        "Contingency Training",
		Description: "HITRUST CSF v11.2 BC-03: Contingency training — personnel trained on contingency procedures",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-3"},
	})

	// BC-04: Contingency Plan Testing (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-04",
		Name:        "Contingency Plan Testing",
		Description: "HITRUST CSF v11.2 BC-04: Contingency plan testing — regular testing of contingency plans",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkContingencyTest,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-4"},
	})

	// BC-05: Alternate Storage (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-05",
		Name:        "Alternate Storage",
		Description: "HITRUST CSF v11.2 BC-05: Alternate storage — backup data stored at alternate location",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAlternateStorage,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-9(1)"},
	})

	// BC-06: System Backup (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-06",
		Name:        "System Backup",
		Description: "HITRUST CSF v11.2 BC-06: System backup — automated backup of system data and configurations",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemBackup,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-9"},
	})

	// BC-07: System Recovery and Reconstitution (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-07",
		Name:        "System Recovery and Reconstitution",
		Description: "HITRUST CSF v11.2 BC-07: System recovery and reconstitution — procedures for recovery after disruption",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemRecovery,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-10"},
	})

	// BC-08: Alternate Communications (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-08",
		Name:        "Alternate Communications",
		Description: "HITRUST CSF v11.2 BC-08: Alternate communications — backup communications during disruptions",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-8"},
	})

	// BC-09: Alternate Processing (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-09",
		Name:        "Alternate Processing",
		Description: "HITRUST CSF v11.2 BC-09: Alternate processing — backup processing site for continuity",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAlternateProcessing,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-7"},
	})

	// BC-10: Long-Term Storage (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-10",
		Name:        "Long-Term Storage",
		Description: "HITRUST CSF v11.2 BC-10: Long-term storage — long-term retention of backup data",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-9(2)"},
	})
}

// ── RA: Regulatory Assessment ─────────────────────────────────────

// registerRAControls wires the RA family controls.
func (m *HITRUSTModule) registerRAControls() {
	// RA-01: Compliance Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-01",
		Name:        "Compliance Policy",
		Description: "HITRUST CSF v11.2 RA-01: Compliance policy documented and reviewed — defines compliance procedures",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PM-9"},
	})

	// RA-02: Security Assessment (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-02",
		Name:        "Security Assessment",
		Description: "HITRUST CSF v11.2 RA-02: Security assessment — periodic assessment of security controls",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityAssessment,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CA-2"},
	})

	// RA-03: Assessment Authorization (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-03",
		Name:        "Assessment Authorization",
		Description: "HITRUST CSF v11.2 RA-03: Assessment authorization — formal authorization for assessments",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CA-2"},
	})

	// RA-04: Continuous Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-04",
		Name:        "Continuous Monitoring",
		Description: "HITRUST CSF v11.2 RA-04: Continuous monitoring — ongoing monitoring of security controls",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkContinuousMonitoring,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CA-7"},
	})

	// RA-05: Plan of Action and Milestones (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-05",
		Name:        "Plan of Action and Milestones",
		Description: "HITRUST CSF v11.2 RA-05: Plan of action and milestones — POA&M for remediation of findings",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CA-5"},
	})

	// RA-06: Privacy Assessment (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-06",
		Name:        "Privacy Assessment",
		Description: "HITRUST CSF v11.2 RA-06: Privacy assessment — assessment of privacy controls and risks",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// RA-07: Security Assessment Plan (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-07",
		Name:        "Security Assessment Plan",
		Description: "HITRUST CSF v11.2 RA-07: Security assessment plan — documented plan for security assessments",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// RA-08: Assessment Report (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-08",
		Name:        "Assessment Report",
		Description: "HITRUST CSF v11.2 RA-08: Assessment report — documented results of security assessments",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// RA-09: Remediation Actions (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-09",
		Name:        "Remediation Actions",
		Description: "HITRUST CSF v11.2 RA-09: Remediation actions — documented actions to remediate assessment findings",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// RA-10: Independent Assessment (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-RA-10",
		Name:        "Independent Assessment",
		Description: "HITRUST CSF v11.2 RA-10: Independent assessment — assessments performed by independent parties",
		Category:    "Regulatory Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})
}

// ── CA: Change Management ─────────────────────────────────────────

// registerCAControls wires the CA family controls.
func (m *HITRUSTModule) registerCAControls() {
	// CA-01: Change Management Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-01",
		Name:        "Change Management Policy",
		Description: "HITRUST CSF v11.2 CA-01: Change management policy documented and reviewed",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-1"},
	})

	// CA-02: Configuration Baseline (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-02",
		Name:        "Configuration Baseline",
		Description: "HITRUST CSF v11.2 CA-02: Configuration baseline — documented baseline configurations",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkConfigBaseline,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-2"},
	})

	// CA-03: Change Control Board (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-03",
		Name:        "Change Control Board",
		Description: "HITRUST CSF v11.2 CA-03: Change control board — established board for reviewing and approving changes",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-3"},
	})

	// CA-04: Security Impact Analysis (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-04",
		Name:        "Security Impact Analysis",
		Description: "HITRUST CSF v11.2 CA-04: Security impact analysis — analysis of security impact for proposed changes",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-4"},
	})

	// CA-05: Access Restrictions for Change (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-05",
		Name:        "Access Restrictions for Change",
		Description: "HITRUST CSF v11.2 CA-05: Access restrictions for change — access controls for change processes",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkChangeAccessRestrictions,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-5"},
	})

	// CA-06: Configuration Settings (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-06",
		Name:        "Configuration Settings",
		Description: "HITRUST CSF v11.2 CA-06: Configuration settings — security configuration settings documented",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCAConfigSettings,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-6"},
	})

	// CA-07: Least Functionality (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-07",
		Name:        "Least Functionality",
		Description: "HITRUST CSF v11.2 CA-07: Least functionality — systems restricted to essential functions",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkLeastFunctionality,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-7"},
	})

	// CA-08: Component Inventory (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-08",
		Name:        "Component Inventory",
		Description: "HITRUST CSF v11.2 CA-08: Component inventory — automated inventory of system components for change management",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCAComponentInventory,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-8"},
	})

	// CA-09: Test and Validation (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-09",
		Name:        "Test and Validation",
		Description: "HITRUST CSF v11.2 CA-09: Test and validation — changes tested and validated before deployment",
		Category:    "Change Management",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-3(2)"},
	})

	// CA-10: Software Usage and Restrictions (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-10",
		Name:        "Software Usage and Restrictions",
		Description: "HITRUST CSF v11.2 CA-10: Software usage and restrictions — controls on software installation and usage",
		Category:    "Change Management",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})
}

// ── BC Family Automated Checks ────────────────────────────────────

// checkSystemBackup verifies system backup procedures. Maps to HITRUST BC-06.
func (m *HITRUSTModule) checkSystemBackup(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBackup := strings.Contains(inputStr, "system_backup") || strings.Contains(inputStr, "backup") || strings.Contains(inputStr, "data_backup")
	hasAutoBackup := strings.Contains(inputStr, "automated_backup") || strings.Contains(inputStr, "auto_backup") || strings.Contains(inputStr, "backup_automation")
	hasVerification := strings.Contains(inputStr, "backup_verification") || strings.Contains(inputStr, "verification") || strings.Contains(inputStr, "backup_integrity")

	if hasBackup && hasAutoBackup && hasVerification {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-BC-06",
			ControlName: "System Backup",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "System backup verified (backup + automation + verification)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasBackup {
		violations = append(violations, "system backup not configured")
	}
	if !hasAutoBackup {
		violations = append(violations, "automated backup not configured")
	}
	if !hasVerification {
		violations = append(violations, "backup verification not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-BC-06",
		ControlName: "System Backup",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "System backup gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure automated system backup with integrity verification",
	}, nil
}

// ── RA Family Automated Checks ────────────────────────────────────

// checkSecurityAssessment verifies security assessment. Maps to HITRUST RA-02.
func (m *HITRUSTModule) checkSecurityAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAssessment := strings.Contains(inputStr, "security_assessment") || strings.Contains(inputStr, "assessment") || strings.Contains(inputStr, "control_assessment")
	hasPeriodic := strings.Contains(inputStr, "periodic") || strings.Contains(inputStr, "scheduled_assessment") || strings.Contains(inputStr, "assessment_schedule")
	hasFindings := strings.Contains(inputStr, "assessment_findings") || strings.Contains(inputStr, "findings") || strings.Contains(inputStr, "assessment_report")

	if hasAssessment && hasPeriodic && hasFindings {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-RA-02",
			ControlName: "Security Assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Security assessment verified (assessment + periodic + findings)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAssessment {
		violations = append(violations, "security assessment not configured")
	}
	if !hasPeriodic {
		violations = append(violations, "periodic assessment not configured")
	}
	if !hasFindings {
		violations = append(violations, "assessment findings not tracked")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-RA-02",
		ControlName: "Security Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Security assessment gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure periodic security assessments with findings tracking",
	}, nil
}

// checkContinuousMonitoring verifies continuous monitoring. Maps to HITRUST RA-04.
func (m *HITRUSTModule) checkContinuousMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "continuous_monitoring") || strings.Contains(inputStr, "monitoring") || m.hasAudit(inputStr)
	hasAlerting := strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alerts") || strings.Contains(inputStr, "siem")
	hasReporting := strings.Contains(inputStr, "monitoring_report") || strings.Contains(inputStr, "reporting") || strings.Contains(inputStr, "status_report")

	if hasMonitoring && hasAlerting && hasReporting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-RA-04",
			ControlName: "Continuous Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Continuous monitoring verified (monitoring + alerting + reporting)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "continuous monitoring not configured")
	}
	if !hasAlerting {
		violations = append(violations, "alerting not configured")
	}
	if !hasReporting {
		violations = append(violations, "monitoring reporting not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-RA-04",
		ControlName: "Continuous Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Continuous monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure continuous monitoring with alerting and reporting",
	}, nil
}

// ── CA Family Automated Checks ────────────────────────────────────

// checkCAComponentInventory verifies component inventory for change management.
// Maps to HITRUST CA-08.
func (m *HITRUSTModule) checkCAComponentInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "component_inventory") || strings.Contains(inputStr, "inventory") || strings.Contains(inputStr, "asset_inventory")
	hasChangeTracking := strings.Contains(inputStr, "change_tracking") || strings.Contains(inputStr, "change_detection") || strings.Contains(inputStr, "drift_detection")
	hasAudit := m.hasAudit(inputStr)

	if hasInventory && hasChangeTracking && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-CA-08",
			ControlName: "Component Inventory",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Component inventory verified (inventory + change tracking + audit)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasInventory {
		violations = append(violations, "component inventory not configured")
	}
	if !hasChangeTracking {
		violations = append(violations, "change tracking not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-CA-08",
		ControlName: "Component Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Component inventory gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure component inventory with change tracking and audit logging",
	}, nil
}

// ── P3 Promotion CheckFuncs ────────────────────────────────────────

// checkContingencyTest verifies contingency plan testing config. Maps to HITRUST BC-04.
func (m *HITRUSTModule) checkContingencyTest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTest := strings.Contains(inputStr, "recovery_test") || strings.Contains(inputStr, "dr_test") || strings.Contains(inputStr, "contingency_test")
	hasSchedule := strings.Contains(inputStr, "scheduled") || strings.Contains(inputStr, "periodic") || strings.Contains(inputStr, "schedule")
	hasRecovery := strings.Contains(inputStr, "recovery") || strings.Contains(inputStr, "disaster_recovery") || strings.Contains(inputStr, "backup")
	if hasTest && hasSchedule && hasRecovery {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-BC-04", ControlName: "Contingency Plan Testing", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Contingency plan testing verified (test + schedule + recovery)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasTest {
		violations = append(violations, "contingency testing not configured")
	}
	if !hasSchedule {
		violations = append(violations, "testing schedule not configured")
	}
	if !hasRecovery {
		violations = append(violations, "recovery procedures not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-BC-04", ControlName: "Contingency Plan Testing", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Contingency plan testing gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure periodic contingency plan testing with recovery procedures"}, nil
}

// checkAlternateStorage verifies alternate storage config. Maps to HITRUST BC-05.
func (m *HITRUSTModule) checkAlternateStorage(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasOffsite := strings.Contains(inputStr, "offsite") || strings.Contains(inputStr, "alternate_storage") || strings.Contains(inputStr, "off_site_storage")
	hasBackup := strings.Contains(inputStr, "backup") || strings.Contains(inputStr, "data_backup") || strings.Contains(inputStr, "system_backup")
	hasEncryption := m.hasEncryption(inputStr)
	if hasOffsite && hasBackup && hasEncryption {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-BC-05", ControlName: "Alternate Storage", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Alternate storage verified (offsite + backup + encryption)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasOffsite {
		violations = append(violations, "offsite storage not configured")
	}
	if !hasBackup {
		violations = append(violations, "backup not configured")
	}
	if !hasEncryption {
		violations = append(violations, "encryption not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-BC-05", ControlName: "Alternate Storage", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Alternate storage gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure offsite backup storage with encryption"}, nil
}

// checkSystemRecovery verifies system recovery config. Maps to HITRUST BC-07.
func (m *HITRUSTModule) checkSystemRecovery(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRecovery := strings.Contains(inputStr, "system_recovery") || strings.Contains(inputStr, "recovery_procedures") || strings.Contains(inputStr, "disaster_recovery")
	hasReconstitution := strings.Contains(inputStr, "reconstitution") || strings.Contains(inputStr, "recovery") || strings.Contains(inputStr, "restoration")
	hasTested := strings.Contains(inputStr, "recovery_test") || strings.Contains(inputStr, "tested") || strings.Contains(inputStr, "dr_test")
	if hasRecovery && hasReconstitution && hasTested {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-BC-07", ControlName: "System Recovery and Reconstitution", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "System recovery verified (recovery + reconstitution + tested)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasRecovery {
		violations = append(violations, "recovery procedures not configured")
	}
	if !hasReconstitution {
		violations = append(violations, "reconstitution not configured")
	}
	if !hasTested {
		violations = append(violations, "recovery testing not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-BC-07", ControlName: "System Recovery and Reconstitution", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "System recovery gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure system recovery with reconstitution procedures and testing"}, nil
}

// checkAlternateProcessing verifies alternate processing config. Maps to HITRUST BC-09.
func (m *HITRUSTModule) checkAlternateProcessing(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAlternate := strings.Contains(inputStr, "alternate_processing") || strings.Contains(inputStr, "failover") || strings.Contains(inputStr, "backup_site")
	hasAuto := strings.Contains(inputStr, "automated_failover") || strings.Contains(inputStr, "auto_failover") || strings.Contains(inputStr, "automatic")
	hasTested := strings.Contains(inputStr, "failover_test") || strings.Contains(inputStr, "tested") || strings.Contains(inputStr, "recovery_test")
	if hasAlternate && hasAuto && hasTested {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-BC-09", ControlName: "Alternate Processing", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Alternate processing verified (alternate + auto failover + tested)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasAlternate {
		violations = append(violations, "alternate processing site not configured")
	}
	if !hasAuto {
		violations = append(violations, "automated failover not configured")
	}
	if !hasTested {
		violations = append(violations, "failover testing not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-BC-09", ControlName: "Alternate Processing", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Alternate processing gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure alternate processing site with automated failover and testing"}, nil
}

// checkConfigBaseline verifies configuration baseline. Maps to HITRUST CA-02.
func (m *HITRUSTModule) checkConfigBaseline(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBaseline := strings.Contains(inputStr, "baseline_configuration") || strings.Contains(inputStr, "config_baseline") || strings.Contains(inputStr, "baseline")
	hasDoc := strings.Contains(inputStr, "configuration_documentation") || strings.Contains(inputStr, "documentation") || strings.Contains(inputStr, "config_settings")
	hasEnforcement := strings.Contains(inputStr, "enforcement") || strings.Contains(inputStr, "enforced") || strings.Contains(inputStr, "drift_detection")
	if hasBaseline && hasDoc && hasEnforcement {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-CA-02", ControlName: "Configuration Baseline", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Configuration baseline verified (baseline + documentation + enforcement)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasBaseline {
		violations = append(violations, "configuration baseline not configured")
	}
	if !hasDoc {
		violations = append(violations, "configuration documentation not configured")
	}
	if !hasEnforcement {
		violations = append(violations, "enforcement not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-CA-02", ControlName: "Configuration Baseline", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Configuration baseline gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure baseline with documentation and drift detection enforcement"}, nil
}

// checkChangeAccessRestrictions verifies access restrictions for change. Maps to HITRUST CA-05.
func (m *HITRUSTModule) checkChangeAccessRestrictions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRestriction := strings.Contains(inputStr, "change_access_restriction") || strings.Contains(inputStr, "change_control") || strings.Contains(inputStr, "change_approval")
	hasRBAC := m.hasRBAC(inputStr)
	hasAudit := m.hasAudit(inputStr)
	if hasRestriction && hasRBAC && hasAudit {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-CA-05", ControlName: "Access Restrictions for Change", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Change access restrictions verified (restriction + RBAC + audit)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasRestriction {
		violations = append(violations, "change access restriction not configured")
	}
	if !hasRBAC {
		violations = append(violations, "RBAC not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-CA-05", ControlName: "Access Restrictions for Change", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Change access restriction gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure change access restrictions with RBAC and audit logging"}, nil
}

// checkCAConfigSettings verifies configuration settings. Maps to HITRUST CA-06.
func (m *HITRUSTModule) checkCAConfigSettings(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSettings := strings.Contains(inputStr, "configuration_settings") || strings.Contains(inputStr, "config_settings") || strings.Contains(inputStr, "security_settings")
	hasEnforcement := strings.Contains(inputStr, "enforcement") || strings.Contains(inputStr, "enforced") || strings.Contains(inputStr, "settings_enforced")
	hasDoc := strings.Contains(inputStr, "documentation") || strings.Contains(inputStr, "config_documentation") || strings.Contains(inputStr, "configuration_documentation")
	if hasSettings && hasEnforcement && hasDoc {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-CA-06", ControlName: "Configuration Settings", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Configuration settings verified (settings + enforcement + documentation)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasSettings {
		violations = append(violations, "configuration settings not configured")
	}
	if !hasEnforcement {
		violations = append(violations, "enforcement not configured")
	}
	if !hasDoc {
		violations = append(violations, "documentation not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-CA-06", ControlName: "Configuration Settings", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Configuration settings gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure security settings with enforcement and documentation"}, nil
}

// checkLeastFunctionality verifies least functionality. Maps to HITRUST CA-07.
func (m *HITRUSTModule) checkLeastFunctionality(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLeast := strings.Contains(inputStr, "least_functionality") || strings.Contains(inputStr, "essential_services") || strings.Contains(inputStr, "minimal_services")
	hasRestriction := strings.Contains(inputStr, "functionality_restriction") || strings.Contains(inputStr, "service_restrictions") || strings.Contains(inputStr, "software_restrictions")
	hasEnforcement := strings.Contains(inputStr, "enforcement") || strings.Contains(inputStr, "enforced") || m.hasRBAC(inputStr)
	if hasLeast && hasRestriction && hasEnforcement {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-CA-07", ControlName: "Least Functionality", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Least functionality verified (least + restriction + enforcement)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasLeast {
		violations = append(violations, "least functionality not configured")
	}
	if !hasRestriction {
		violations = append(violations, "service restrictions not configured")
	}
	if !hasEnforcement {
		violations = append(violations, "enforcement not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-CA-07", ControlName: "Least Functionality", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Least functionality gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure least functionality with service restrictions and enforcement"}, nil
}
