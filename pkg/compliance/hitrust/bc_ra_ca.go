// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HITRUST CSF BC/RA/CA Families
// =========================================================================
//
// HITRUST CSF v11.2 — Business Continuity (BC), Regulatory Assessment (RA),
// and Change Management (CA) families.
//
// In-scope controls (30 total: 4 automated + 26 manual):
//
//   BC (Business Continuity): 10 controls (1 automated + 9 manual)
//   RA (Regulatory Assessment): 10 controls (2 automated + 8 manual)
//   CA (Change Management): 10 controls (1 automated + 9 manual)
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
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CP-4"},
	})

	// BC-05: Alternate Storage (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-BC-05",
		Name:        "Alternate Storage",
		Description: "HITRUST CSF v11.2 BC-05: Alternate storage — backup data stored at alternate location",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
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
		Automated:   false,
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
		Automated:   false,
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
		Automated:   false,
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
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-5"},
	})

	// CA-06: Configuration Settings (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-06",
		Name:        "Configuration Settings",
		Description: "HITRUST CSF v11.2 CA-06: Configuration settings — security configuration settings documented",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-6"},
	})

	// CA-07: Least Functionality (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-CA-07",
		Name:        "Least Functionality",
		Description: "HITRUST CSF v11.2 CA-07: Least functionality — systems restricted to essential functions",
		Category:    "Change Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
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
