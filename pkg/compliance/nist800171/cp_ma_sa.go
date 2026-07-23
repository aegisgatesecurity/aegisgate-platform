// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 CP/MA/SA Families
// =========================================================================
//
// NIST SP 800-171 §3.5 (Contingency Planning), §3.7 (Maintenance),
// §3.12 (System and Services Acquisition)
//
// CP (Contingency Planning): 2 controls (0 automated + 2 evidence-mapped)
// MA (Maintenance): 1 control (0 automated + 1 evidence-mapped)
// SA (System & Services Acquisition): 3 controls (1 automated + 2 evidence-mapped)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerCPMASAControls wires CP, MA, and SA family controls.
func (m *NIST800171Module) registerCPMASAControls() {
	m.registerCPControls()
	m.registerMAControls()
	m.registerSAControls()
}

// registerCPControls wires Contingency Planning controls.
func (m *NIST800171Module) registerCPControls() {
	// CP-1: Contingency Planning Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CP-1",
		Name:        "Contingency Planning Policy",
		Description: "NIST 800-171 CP-1 (3.5.1): Contingency planning policy and procedures documented",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.1", "NIST SP 800-53 Rev. 5 CP-1"},
	})

	// CP-9: Backup (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CP-9",
		Name:        "System Backup",
		Description: "NIST 800-171 CP-9 (3.5.2): System backup — data backed up at defined intervals",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemBackup,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.2", "NIST SP 800-53 Rev. 5 CP-9"},
	})

	// CP-2: Contingency Plan (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CP-2",
		Name:        "Contingency Plan",
		Description: "NIST 800-171 CP-2 (3.5.3): Contingency plan documented and tested",
		Category:    "Contingency Planning",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.5.3", "NIST SP 800-53 Rev. 5 CP-2"},
	})
}

// registerMAControls wires Maintenance controls.
func (m *NIST800171Module) registerMAControls() {
	// MA-2: Controlled Maintenance (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-MA-2",
		Name:        "Controlled Maintenance",
		Description: "NIST 800-171 MA-2 (3.7.1): Controlled maintenance of system components",
		Category:    "Maintenance",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.7.1", "NIST SP 800-53 Rev. 5 MA-2"},
	})
}

// registerSAControls wires System and Services Acquisition controls.
func (m *NIST800171Module) registerSAControls() {
	// SA-4: Acquisition Process (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SA-4",
		Name:        "Acquisition Process",
		Description: "NIST 800-171 SA-4 (3.12.1): Acquisition process includes security requirements",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.12.1", "NIST SP 800-53 Rev. 5 SA-4"},
	})

	// SA-5: System Development Process (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SA-5",
		Name:        "System Development Process",
		Description: "NIST 800-171 SA-5 (3.12.2): System development process includes security considerations",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.12.2", "NIST SP 800-53 Rev. 5 SA-5"},
	})

	// SA-9: External System Services (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SA-9",
		Name:        "External System Services",
		Description: "NIST 800-171 SA-9 (3.12.3): External system services controlled and monitored",
		Category:    "System and Services Acquisition",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkExternalSystemServices,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.12.3", "NIST SP 800-53 Rev. 5 SA-9"},
	})
}

// --- CP/MA/SA Check Functions ---

func (m *NIST800171Module) checkSystemBackup(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBackup := strings.Contains(inputStr, "backup") || strings.Contains(inputStr, "data_backup") || strings.Contains(inputStr, "disaster_recovery")
	hasRetention := strings.Contains(inputStr, "retention") || strings.Contains(inputStr, "backup_retention") || strings.Contains(inputStr, "7_day")

	if hasBackup {
		status := compliance.StatusCompliant
		msg := "System backup controls verified (backup configured)"
		if hasRetention {
			msg = "System backup controls verified (backup + retention policy)"
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CP-9",
			ControlName: "System Backup",
			Status:      status,
			Severity:    compliance.SeverityHigh,
			Message:     msg,
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-CP-9",
		ControlName: "System Backup",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "System backup not configured",
		Timestamp:   time.Now(),
		Remediation: "Configure system backup (backup.enabled=true, backup.retention=7d)",
	}, nil
}

func (m *NIST800171Module) checkExternalSystemServices(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBoundary := strings.Contains(inputStr, "boundary") || strings.Contains(inputStr, "trust_boundary") || strings.Contains(inputStr, "proxy")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging")
	hasApproval := strings.Contains(inputStr, "approval") || strings.Contains(inputStr, "authorized") || strings.Contains(inputStr, "trust")

	if hasBoundary && (hasMonitoring || hasApproval) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SA-9",
			ControlName: "External System Services",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "External system services verified (boundary + monitoring/approval)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasBoundary {
		violations = append(violations, "trust boundary controls not detected")
	}
	if !hasMonitoring && !hasApproval {
		violations = append(violations, "external system monitoring or approval not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SA-9",
		ControlName: "External System Services",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "External system services gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure trust boundaries and external system monitoring",
	}, nil
}
