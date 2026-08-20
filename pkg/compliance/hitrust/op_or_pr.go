// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HITRUST CSF OP/OR/PR Families
// =========================================================================
//
// HITRUST CSF v11.2 — Operations (OP), Organizational Risk (OR),
// and Program (PR) families.
//
// In-scope controls (45 total: 15 automated + 30 manual):
//
//   OP (Operations): 20 controls (8 automated + 12 manual)
//   OR (Organizational Risk): 10 controls (5 automated + 5 manual)
//   PR (Program): 15 controls (2 automated + 13 manual)
//
// =========================================================================

package hitrust

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerOPOrPRControls wires the OP, OR, and PR family controls into the module.
func (m *HITRUSTModule) registerOPOrPRControls() {
	m.registerOPControls()
	m.registerORControls()
	m.registerPRControls()
}

// ── OP: Operations ────────────────────────────────────────────────

// registerOPControls wires the OP family controls.
func (m *HITRUSTModule) registerOPControls() {
	// OP-01: Operational Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-01",
		Name:        "Operational Policy",
		Description: "HITRUST CSF v11.2 OP-01: Operational policy documented and reviewed — defines operational procedures and responsibilities",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 OP-1"},
	})

	// OP-02: Configuration Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-02",
		Name:        "Configuration Management",
		Description: "HITRUST CSF v11.2 OP-02: Configuration management — baseline configurations established and maintained",
		Category:    "Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConfigManagement,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-2"},
	})

	// OP-03: Change Control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-03",
		Name:        "Change Control",
		Description: "HITRUST CSF v11.2 OP-03: Change control — proposed changes reviewed and approved before implementation",
		Category:    "Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeControl,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-3"},
	})

	// OP-04: Change Monitoring (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-04",
		Name:        "Change Monitoring",
		Description: "HITRUST CSF v11.2 OP-04: Change monitoring — system changes monitored for security impact",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkChangeMonitoring,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-4"},
	})

	// OP-05: Access Restrictions for Change (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-05",
		Name:        "Access Restrictions for Change",
		Description: "HITRUST CSF v11.2 OP-05: Access restrictions for change — access to change tools and environments restricted",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkHITRUSTChangeAccessRestrictions,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-5"},
	})

	// OP-06: Configuration Settings (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-06",
		Name:        "Configuration Settings",
		Description: "HITRUST CSF v11.2 OP-06: Configuration settings — security settings enforced and monitored",
		Category:    "Operations",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConfigSettings,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-6"},
	})

	// OP-07: Least Functionality (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-07",
		Name:        "Least Functionality",
		Description: "HITRUST CSF v11.2 OP-07: Least functionality — systems configured with minimal functionality",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-7"},
	})

	// OP-08: System Component Inventory (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-08",
		Name:        "System Component Inventory",
		Description: "HITRUST CSF v11.2 OP-08: System component inventory — accurate inventory of system components maintained",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkComponentInventory,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-8"},
	})

	// OP-09: Baseline Configuration (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-09",
		Name:        "Baseline Configuration",
		Description: "HITRUST CSF v11.2 OP-09: Baseline configuration — documented baseline configurations for systems",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-2(1)"},
	})

	// OP-10: Automated Change Support (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-10",
		Name:        "Automated Change Support",
		Description: "HITRUST CSF v11.2 OP-10: Automated change support — automated tools support change management processes",
		Category:    "Operations",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkAutomatedChangeSupport,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-3(1)"},
	})

	// OP-11: Test and Validation (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-11",
		Name:        "Test and Validation",
		Description: "HITRUST CSF v11.2 OP-11: Test and validation — changes tested and validated before deployment",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-3(2)"},
	})

	// OP-12: Security and Privacy Plans (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-12",
		Name:        "Security and Privacy Plans",
		Description: "HITRUST CSF v11.2 OP-12: Security and privacy plans — documented plans for system security and privacy",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PL-1"},
	})

	// OP-13: System Architecture (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-13",
		Name:        "System Architecture",
		Description: "HITRUST CSF v11.2 OP-13: System architecture — documented system architecture and design",
		Category:    "Operations",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// OP-14: Capacity Planning (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-14",
		Name:        "Capacity Planning",
		Description: "HITRUST CSF v11.2 OP-14: Capacity planning — monitoring and planning for system capacity requirements",
		Category:    "Operations",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkCapacityPlanning,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// OP-15: Environmental Controls (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-15",
		Name:        "Environmental Controls",
		Description: "HITRUST CSF v11.2 OP-15: Environmental controls — power, temperature, and humidity controls for facilities",
		Category:    "Operations",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PE-9"},
	})

	// OP-16: Physical Access Control (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-16",
		Name:        "Physical Access Control",
		Description: "HITRUST CSF v11.2 OP-16: Physical access control — access controls for physical facilities",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PE-3"},
	})

	// OP-17: Physical Monitoring (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-17",
		Name:        "Physical Monitoring",
		Description: "HITRUST CSF v11.2 OP-17: Physical monitoring — surveillance and monitoring of physical facilities",
		Category:    "Operations",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PE-6"},
	})

	// OP-18: Maintenance Personnel (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-18",
		Name:        "Maintenance Personnel",
		Description: "HITRUST CSF v11.2 OP-18: Maintenance personnel — controls for personnel performing system maintenance",
		Category:    "Operations",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 MA-5"},
	})

	// OP-19: Controlled Maintenance (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-19",
		Name:        "Controlled Maintenance",
		Description: "HITRUST CSF v11.2 OP-19: Controlled maintenance — maintenance activities scheduled, controlled, and documented",
		Category:    "Operations",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkControlledMaintenance,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 MA-2"},
	})

	// OP-20: Maintenance Tools (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OP-20",
		Name:        "Maintenance Tools",
		Description: "HITRUST CSF v11.2 OP-20: Maintenance tools — controls for tools used in system maintenance",
		Category:    "Operations",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 MA-3"},
	})
}

// ── OR: Organizational Risk ───────────────────────────────────────

// registerORControls wires the OR family controls.
func (m *HITRUSTModule) registerORControls() {
	// OR-01: Risk Assessment Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-01",
		Name:        "Risk Assessment Policy",
		Description: "HITRUST CSF v11.2 OR-01: Risk assessment policy documented and reviewed — defines risk assessment procedures",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 RA-1"},
	})

	// OR-02: Security Categorization (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-02",
		Name:        "Security Categorization",
		Description: "HITRUST CSF v11.2 OR-02: Security categorization — systems and information categorized by impact level",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityCategorization,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 RA-2"},
	})

	// OR-03: Risk Assessment (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-03",
		Name:        "Risk Assessment",
		Description: "HITRUST CSF v11.2 OR-03: Risk assessment — periodic risk assessments to identify threats and vulnerabilities",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 RA-3"},
	})

	// OR-04: Vulnerability Scanning (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-04",
		Name:        "Vulnerability Scanning",
		Description: "HITRUST CSF v11.2 OR-04: Vulnerability scanning — automated scanning for vulnerabilities on systems",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityScanning,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 RA-5"},
	})

	// OR-05: Vulnerability Remediation (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-05",
		Name:        "Vulnerability Remediation",
		Description: "HITRUST CSF v11.2 OR-05: Vulnerability remediation — timely remediation of identified vulnerabilities",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnRemediation,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 RA-5(4)"},
	})

	// OR-06: Threat Identification (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-06",
		Name:        "Threat Identification",
		Description: "HITRUST CSF v11.2 OR-06: Threat identification — identification of threats to systems and data",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// OR-07: Risk Monitoring (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-07",
		Name:        "Risk Monitoring",
		Description: "HITRUST CSF v11.2 OR-07: Risk monitoring — ongoing monitoring of risk levels and trends",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRiskMonitoring,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// OR-08: Risk Response (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-08",
		Name:        "Risk Response",
		Description: "HITRUST CSF v11.2 OR-08: Risk response — documented response plans for identified risks",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// OR-09: Supply Chain Risk Management (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-09",
		Name:        "Supply Chain Risk Management",
		Description: "HITRUST CSF v11.2 OR-09: Supply chain risk management — controls for managing risk in the supply chain",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SR-1"},
	})

	// OR-10: Security Authorization (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-OR-10",
		Name:        "Security Authorization",
		Description: "HITRUST CSF v11.2 OR-10: Security authorization — formal authorization of systems to operate",
		Category:    "Organizational Risk",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CA-2"},
	})
}

// ── PR: Program ───────────────────────────────────────────────────

// registerPRControls wires the PR family controls.
func (m *HITRUSTModule) registerPRControls() {
	// PR-01: Security Planning Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-01",
		Name:        "Security Planning Policy",
		Description: "HITRUST CSF v11.2 PR-01: Security planning policy documented and reviewed",
		Category:    "Program",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PL-1"},
	})

	// PR-02: System Security Plan (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-02",
		Name:        "System Security Plan",
		Description: "HITRUST CSF v11.2 PR-02: System security plan — documented plan for system security controls",
		Category:    "Program",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PL-2"},
	})

	// PR-03: Rules of Behavior (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-03",
		Name:        "Rules of Behavior",
		Description: "HITRUST CSF v11.2 PR-03: Rules of behavior — documented rules for system usage and user responsibilities",
		Category:    "Program",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PL-4"},
	})

	// PR-04: Information Security Program Plan (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-04",
		Name:        "Information Security Program Plan",
		Description: "HITRUST CSF v11.2 PR-04: Information security program plan — overall program plan for information security",
		Category:    "Program",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// PR-05: Security Awareness Training (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-05",
		Name:        "Security Awareness Training",
		Description: "HITRUST CSF v11.2 PR-05: Security awareness training — training provided to all personnel",
		Category:    "Program",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityAwareness,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 AT-2"},
	})

	// PR-06: Role-Based Training (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-06",
		Name:        "Role-Based Training",
		Description: "HITRUST CSF v11.2 PR-06: Role-based training — specialized training based on roles and responsibilities",
		Category:    "Program",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRoleBasedTraining,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 AT-3"},
	})

	// PR-07: Training Records (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-07",
		Name:        "Training Records",
		Description: "HITRUST CSF v11.2 PR-07: Training records — documentation of training completion and content",
		Category:    "Program",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 AT-4"},
	})

	// PR-08: Security Personnel Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-08",
		Name:        "Security Personnel Policy",
		Description: "HITRUST CSF v11.2 PR-08: Security personnel policy — policy for personnel security and screening",
		Category:    "Program",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PS-1"},
	})

	// PR-09: Personnel Screening (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-09",
		Name:        "Personnel Screening",
		Description: "HITRUST CSF v11.2 PR-09: Personnel screening — background screening for personnel with access to systems",
		Category:    "Program",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PS-3"},
	})

	// PR-10: Personnel Termination (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-10",
		Name:        "Personnel Termination",
		Description: "HITRUST CSF v11.2 PR-10: Personnel termination — procedures for terminating personnel access",
		Category:    "Program",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PS-4"},
	})

	// PR-11: Personnel Transfer (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-11",
		Name:        "Personnel Transfer",
		Description: "HITRUST CSF v11.2 PR-11: Personnel transfer — procedures for personnel transfers and access changes",
		Category:    "Program",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PS-5"},
	})

	// PR-12: Access Agreements (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-12",
		Name:        "Access Agreements",
		Description: "HITRUST CSF v11.2 PR-12: Access agreements — signed agreements for system access",
		Category:    "Program",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PS-6"},
	})

	// PR-13: Third-Party Personnel Security (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-13",
		Name:        "Third-Party Personnel Security",
		Description: "HITRUST CSF v11.2 PR-13: Third-party personnel security — security requirements for third-party personnel",
		Category:    "Program",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PS-7"},
	})

	// PR-14: Personnel Sanctions (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-14",
		Name:        "Personnel Sanctions",
		Description: "HITRUST CSF v11.2 PR-14: Personnel sanctions — sanctions for security policy violations",
		Category:    "Program",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PS-8"},
	})

	// PR-15: Position Risk Designation (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PR-15",
		Name:        "Position Risk Designation",
		Description: "HITRUST CSF v11.2 PR-15: Position risk designation — risk levels assigned to positions based on access",
		Category:    "Program",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 PS-2"},
	})
}

// ── OP Family Automated Checks ────────────────────────────────────

// checkConfigManagement verifies configuration management. Maps to HITRUST OP-02.
func (m *HITRUSTModule) checkConfigManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasConfigMgmt := strings.Contains(inputStr, "configuration_management") || strings.Contains(inputStr, "config_management") || strings.Contains(inputStr, "cm_enabled")
	hasBaseline := strings.Contains(inputStr, "baseline_configuration") || strings.Contains(inputStr, "baseline") || strings.Contains(inputStr, "secure_baseline")
	hasInventory := strings.Contains(inputStr, "inventory") || strings.Contains(inputStr, "component_inventory")

	if hasConfigMgmt && hasBaseline && hasInventory {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-OP-02",
			ControlName: "Configuration Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Configuration management verified (CM + baseline + inventory)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasConfigMgmt {
		violations = append(violations, "configuration management not configured")
	}
	if !hasBaseline {
		violations = append(violations, "baseline configuration not configured")
	}
	if !hasInventory {
		violations = append(violations, "component inventory not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-OP-02",
		ControlName: "Configuration Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Configuration management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure configuration management with baseline configurations and component inventory",
	}, nil
}

// checkChangeControl verifies change control processes. Maps to HITRUST OP-03.
func (m *HITRUSTModule) checkChangeControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasChangeControl := strings.Contains(inputStr, "change_control") || strings.Contains(inputStr, "change_management") || strings.Contains(inputStr, "change_approval")
	hasApproval := strings.Contains(inputStr, "approval") || strings.Contains(inputStr, "change_review") || strings.Contains(inputStr, "review")
	hasAudit := m.hasAudit(inputStr)

	if hasChangeControl && hasApproval && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-OP-03",
			ControlName: "Change Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Change control verified (change control + approval + audit)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasChangeControl {
		violations = append(violations, "change control not configured")
	}
	if !hasApproval {
		violations = append(violations, "approval process not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-OP-03",
		ControlName: "Change Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Change control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure change control with approval process and audit logging",
	}, nil
}

// checkConfigSettings verifies configuration settings. Maps to HITRUST OP-06.
func (m *HITRUSTModule) checkConfigSettings(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasConfigSettings := strings.Contains(inputStr, "configuration_settings") || strings.Contains(inputStr, "config_settings") || strings.Contains(inputStr, "security_settings")
	hasEnforcement := strings.Contains(inputStr, "enforcement") || strings.Contains(inputStr, "settings_enforced") || strings.Contains(inputStr, "enforced")
	hasHardening := strings.Contains(inputStr, "hardening") || strings.Contains(inputStr, "cis_benchmark") || strings.Contains(inputStr, "secure_baseline")

	if hasConfigSettings && hasEnforcement && hasHardening {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-OP-06",
			ControlName: "Configuration Settings",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Configuration settings verified (settings + enforcement + hardening)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasConfigSettings {
		violations = append(violations, "configuration settings not configured")
	}
	if !hasEnforcement {
		violations = append(violations, "enforcement not configured")
	}
	if !hasHardening {
		violations = append(violations, "hardening not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-OP-06",
		ControlName: "Configuration Settings",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Configuration settings gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure security settings with enforcement and hardening baselines",
	}, nil
}

// checkComponentInventory verifies system component inventory. Maps to HITRUST OP-08.
func (m *HITRUSTModule) checkComponentInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "component_inventory") || strings.Contains(inputStr, "inventory") || strings.Contains(inputStr, "asset_inventory")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "asset_tracking") || strings.Contains(inputStr, "inventory_management")
	hasUpdates := strings.Contains(inputStr, "inventory_updates") || strings.Contains(inputStr, "auto_update") || strings.Contains(inputStr, "inventory_refresh")

	if hasInventory && hasTracking && hasUpdates {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-OP-08",
			ControlName: "System Component Inventory",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Component inventory verified (inventory + tracking + updates)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasInventory {
		violations = append(violations, "component inventory not configured")
	}
	if !hasTracking {
		violations = append(violations, "inventory tracking not configured")
	}
	if !hasUpdates {
		violations = append(violations, "inventory updates not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-OP-08",
		ControlName: "System Component Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Component inventory gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure component inventory with tracking and automated updates",
	}, nil
}

// checkControlledMaintenance verifies controlled maintenance. Maps to HITRUST OP-19.
func (m *HITRUSTModule) checkControlledMaintenance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMaintenance := strings.Contains(inputStr, "controlled_maintenance") || strings.Contains(inputStr, "maintenance") || strings.Contains(inputStr, "maintenance_schedule")
	hasSchedule := strings.Contains(inputStr, "schedule") || strings.Contains(inputStr, "scheduled") || strings.Contains(inputStr, "maintenance_window")
	hasAudit := m.hasAudit(inputStr)

	if hasMaintenance && hasSchedule && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-OP-19",
			ControlName: "Controlled Maintenance",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Controlled maintenance verified (maintenance + schedule + audit)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMaintenance {
		violations = append(violations, "controlled maintenance not configured")
	}
	if !hasSchedule {
		violations = append(violations, "maintenance schedule not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-OP-19",
		ControlName: "Controlled Maintenance",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Controlled maintenance gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure controlled maintenance with scheduling and audit logging",
	}, nil
}

// ── OR Family Automated Checks ────────────────────────────────────

// checkRiskAssessment verifies risk assessment. Maps to HITRUST OR-03.
func (m *HITRUSTModule) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRiskAssessment := strings.Contains(inputStr, "risk_assessment") || strings.Contains(inputStr, "risk_analysis") || strings.Contains(inputStr, "risk_evaluation")
	hasThreats := strings.Contains(inputStr, "threat") || strings.Contains(inputStr, "threat_identification") || strings.Contains(inputStr, "threats")
	hasVuln := strings.Contains(inputStr, "vulnerability") || m.hasVulnScan(inputStr) || strings.Contains(inputStr, "vulnerabilities")

	if hasRiskAssessment && hasThreats && hasVuln {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-OR-03",
			ControlName: "Risk Assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Risk assessment verified (assessment + threats + vulnerabilities)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRiskAssessment {
		violations = append(violations, "risk assessment not configured")
	}
	if !hasThreats {
		violations = append(violations, "threat identification not configured")
	}
	if !hasVuln {
		violations = append(violations, "vulnerability identification not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-OR-03",
		ControlName: "Risk Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Risk assessment gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure risk assessment with threat and vulnerability identification",
	}, nil
}

// checkVulnerabilityScanning verifies vulnerability scanning. Maps to HITRUST OR-04.
func (m *HITRUSTModule) checkVulnerabilityScanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnScan := m.hasVulnScan(inputStr) || strings.Contains(inputStr, "vulnerability_scanning") || strings.Contains(inputStr, "vuln_scan")
	hasAutoScan := strings.Contains(inputStr, "automated_scan") || strings.Contains(inputStr, "scheduled_scan") || strings.Contains(inputStr, "auto_scan")
	hasReporting := strings.Contains(inputStr, "scan_report") || strings.Contains(inputStr, "reporting") || strings.Contains(inputStr, "scan_results")

	if hasVulnScan && hasAutoScan && hasReporting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-OR-04",
			ControlName: "Vulnerability Scanning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability scanning verified (scanning + automated + reporting)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasVulnScan {
		violations = append(violations, "vulnerability scanning not configured")
	}
	if !hasAutoScan {
		violations = append(violations, "automated scanning not configured")
	}
	if !hasReporting {
		violations = append(violations, "scan reporting not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-OR-04",
		ControlName: "Vulnerability Scanning",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability scanning gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure automated vulnerability scanning with reporting",
	}, nil
}

// checkVulnRemediation verifies vulnerability remediation. Maps to HITRUST OR-05.
func (m *HITRUSTModule) checkVulnRemediation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRemediation := strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "vuln_remediation") || strings.Contains(inputStr, "vulnerability_remediation")
	hasPatch := strings.Contains(inputStr, "patch") || strings.Contains(inputStr, "patching") || strings.Contains(inputStr, "patch_management")
	hasTracking := strings.Contains(inputStr, "remediation_tracking") || strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "sla")

	if hasRemediation && hasPatch && hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-OR-05",
			ControlName: "Vulnerability Remediation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability remediation verified (remediation + patching + tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRemediation {
		violations = append(violations, "vulnerability remediation not configured")
	}
	if !hasPatch {
		violations = append(violations, "patching not configured")
	}
	if !hasTracking {
		violations = append(violations, "remediation tracking not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-OR-05",
		ControlName: "Vulnerability Remediation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability remediation gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure vulnerability remediation with patching and tracking",
	}, nil
}

// ── PR Family Automated Checks ────────────────────────────────────

// checkSecurityAwareness verifies security awareness training. Maps to HITRUST PR-05.
func (m *HITRUSTModule) checkSecurityAwareness(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTraining := strings.Contains(inputStr, "security_awareness") || strings.Contains(inputStr, "awareness_training") || strings.Contains(inputStr, "training")
	hasCompletion := strings.Contains(inputStr, "training_completion") || strings.Contains(inputStr, "completion") || strings.Contains(inputStr, "training_records")
	hasTracking := strings.Contains(inputStr, "training_tracking") || strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "training_management")

	if hasTraining && hasCompletion && hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-PR-05",
			ControlName: "Security Awareness Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Security awareness training verified (training + completion + tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasTraining {
		violations = append(violations, "security awareness training not configured")
	}
	if !hasCompletion {
		violations = append(violations, "training completion tracking not configured")
	}
	if !hasTracking {
		violations = append(violations, "training management not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-PR-05",
		ControlName: "Security Awareness Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Security awareness training gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure security awareness training with completion tracking and management",
	}, nil
}

// checkRoleBasedTraining verifies role-based training. Maps to HITRUST PR-06.
func (m *HITRUSTModule) checkRoleBasedTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRoleTraining := strings.Contains(inputStr, "role_based_training") || strings.Contains(inputStr, "role_training") || strings.Contains(inputStr, "specialized_training")
	hasRoles := strings.Contains(inputStr, "roles") || strings.Contains(inputStr, "role") || m.hasRBAC(inputStr)
	hasCompletion := strings.Contains(inputStr, "training_completion") || strings.Contains(inputStr, "completion") || strings.Contains(inputStr, "training_records")

	if hasRoleTraining && hasRoles && hasCompletion {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-PR-06",
			ControlName: "Role-Based Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Role-based training verified (role training + roles + completion)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRoleTraining {
		violations = append(violations, "role-based training not configured")
	}
	if !hasRoles {
		violations = append(violations, "roles not defined")
	}
	if !hasCompletion {
		violations = append(violations, "training completion not tracked")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-PR-06",
		ControlName: "Role-Based Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Role-based training gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure role-based training with role definitions and completion tracking",
	}, nil
}

// ── P3 Promotion CheckFuncs ────────────────────────────────────────

// checkChangeMonitoring verifies change monitoring config. Maps to HITRUST OP-04.
func (m *HITRUSTModule) checkChangeMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "change_monitoring") || strings.Contains(inputStr, "drift_detection") || strings.Contains(inputStr, "change_detection")
	hasAudit := m.hasAudit(inputStr)
	hasAlerting := strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alerts") || strings.Contains(inputStr, "siem")
	if hasMonitoring && hasAudit && hasAlerting {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OP-04", ControlName: "Change Monitoring", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Change monitoring verified (monitoring + audit + alerting)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "change monitoring not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}
	if !hasAlerting {
		violations = append(violations, "alerting not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OP-04", ControlName: "Change Monitoring", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Change monitoring gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure change monitoring with audit and alerting"}, nil
}

// checkAutomatedChangeSupport verifies automated change support. Maps to HITRUST OP-10.
func (m *HITRUSTModule) checkAutomatedChangeSupport(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuto := strings.Contains(inputStr, "automated_change") || strings.Contains(inputStr, "change_automation") || strings.Contains(inputStr, "ci_cd")
	hasAudit := m.hasAudit(inputStr)
	hasControl := strings.Contains(inputStr, "change_control") || strings.Contains(inputStr, "change_approval") || strings.Contains(inputStr, "approval")
	if hasAuto && hasAudit && hasControl {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OP-10", ControlName: "Automated Change Support", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Automated change support verified (automation + audit + control)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasAuto {
		violations = append(violations, "automated change not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}
	if !hasControl {
		violations = append(violations, "change control not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OP-10", ControlName: "Automated Change Support", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Automated change support gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure automated change with audit logging and change control"}, nil
}

// checkCapacityPlanning verifies capacity planning config. Maps to HITRUST OP-14.
func (m *HITRUSTModule) checkCapacityPlanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCapacity := strings.Contains(inputStr, "capacity_planning") || strings.Contains(inputStr, "capacity_monitoring") || strings.Contains(inputStr, "resource_monitoring")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "alerts") || strings.Contains(inputStr, "alerting")
	hasThreshold := strings.Contains(inputStr, "threshold") || strings.Contains(inputStr, "capacity_threshold") || strings.Contains(inputStr, "resource_limit")
	if hasCapacity && hasMonitoring && hasThreshold {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OP-14", ControlName: "Capacity Planning", Status: compliance.StatusCompliant, Severity: compliance.SeverityLow, Message: "Capacity planning verified (capacity + monitoring + threshold)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasCapacity {
		violations = append(violations, "capacity planning not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "monitoring not configured")
	}
	if !hasThreshold {
		violations = append(violations, "threshold not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OP-14", ControlName: "Capacity Planning", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityLow, Message: "Capacity planning gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure capacity planning with monitoring and threshold alerts"}, nil
}

// checkSecurityCategorization verifies security categorization. Maps to HITRUST OR-02.
func (m *HITRUSTModule) checkSecurityCategorization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCat := strings.Contains(inputStr, "security_categorization") || strings.Contains(inputStr, "impact_level") || strings.Contains(inputStr, "fips_199")
	hasLabel := strings.Contains(inputStr, "categorization") || strings.Contains(inputStr, "classification") || strings.Contains(inputStr, "data_classification")
	hasPolicy := strings.Contains(inputStr, "policy") || strings.Contains(inputStr, "categorization_policy") || strings.Contains(inputStr, "access_control")
	if hasCat && hasLabel && hasPolicy {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OR-02", ControlName: "Security Categorization", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Security categorization verified (categorization + labeling + policy)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasCat {
		violations = append(violations, "security categorization not configured")
	}
	if !hasLabel {
		violations = append(violations, "categorization labeling not configured")
	}
	if !hasPolicy {
		violations = append(violations, "categorization policy not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OR-02", ControlName: "Security Categorization", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Security categorization gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure security categorization with labeling and policy"}, nil
}

// checkRiskMonitoring verifies risk monitoring config. Maps to HITRUST OR-07.
func (m *HITRUSTModule) checkRiskMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "risk_monitoring") || strings.Contains(inputStr, "risk_tracking") || strings.Contains(inputStr, "risk_dashboard")
	hasAssessment := strings.Contains(inputStr, "risk_assessment") || strings.Contains(inputStr, "risk_analysis") || strings.Contains(inputStr, "assessment")
	hasAlerting := strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alerts") || strings.Contains(inputStr, "siem")
	if hasMonitoring && hasAssessment && hasAlerting {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OR-07", ControlName: "Risk Monitoring", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Risk monitoring verified (monitoring + assessment + alerting)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "risk monitoring not configured")
	}
	if !hasAssessment {
		violations = append(violations, "risk assessment not configured")
	}
	if !hasAlerting {
		violations = append(violations, "alerting not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OR-07", ControlName: "Risk Monitoring", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Risk monitoring gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure risk monitoring with assessment and alerting"}, nil
}

// ===== P5 Comprehensive Review: Additional CheckFunc implementations =====

func (m *HITRUSTModule) checkHITRUSTChangeAccessRestrictions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasChangeAccess := strings.Contains(inputStr, "change_access") || strings.Contains(inputStr, "change_restriction") || strings.Contains(inputStr, "change_tool_access") || strings.Contains(inputStr, "change_control_access")
	if hasChangeAccess {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OP-05", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Access restrictions for change detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "HITRUST-OP-05", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Access restrictions for change not configured", Timestamp: time.Now(), Remediation: "Implement access restrictions for change tools"}, nil
}
