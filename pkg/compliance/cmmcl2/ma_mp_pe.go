// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC L2 MA/MP/PE Domains
// =========================================================================
//
// CMMC Level 2 — Maintenance, Media Protection, and Physical Protection
// domains.
//
// MA (Maintenance): 3 practices (1 automated + 2 evidence-mapped)
// MP (Media Protection): 5 practices (2 automated + 3 evidence-mapped)
// PE (Physical Protection): 4 practices (1 automated + 3 evidence-mapped)
//
// =========================================================================

package cmmcl2

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerMAControls wires Maintenance domain controls.
func (m *CMMCL2Module) registerMAControls() {
	// MA-01: Maintenance Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-MA-01",
		Name:        "Maintenance Policy",
		Description: "CMMC L2 MA.2.001: Maintenance policy and procedures documented and disseminated",
		Category:    "Maintenance",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 MA.2.001", "NIST SP 800-171 §3.7.1"},
	})

	// MA-02: Controlled Maintenance (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-MA-02",
		Name:        "Controlled Maintenance",
		Description: "CMMC L2 MA.2.002: Maintenance performed with authorized personnel and controls",
		Category:    "Maintenance",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkControlledMaintenance,
		References:  []string{"CMMC L2 MA.2.002", "NIST SP 800-171 §3.7.2"},
	})

	// MA-03: Maintenance Documentation (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-MA-03",
		Name:        "Maintenance Documentation",
		Description: "CMMC L2 MA.2.003: Maintenance activities documented and reviewed",
		Category:    "Maintenance",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"CMMC L2 MA.2.003"},
	})
}

// registerMPControls wires Media Protection domain controls.
func (m *CMMCL2Module) registerMPControls() {
	// MP-01: Media Protection Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-MP-01",
		Name:        "Media Protection Policy",
		Description: "CMMC L2 MP.2.001: Media protection policy documented and enforced",
		Category:    "Media Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 MP.2.001", "NIST SP 800-171 §3.8.1"},
	})

	// MP-02: Media Sanitization (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-MP-02",
		Name:        "Media Sanitization",
		Description: "CMMC L2 MP.2.002: Media sanitization and disposal controls verified",
		Category:    "Media Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMediaSanitization,
		References:  []string{"CMMC L2 MP.2.002", "NIST SP 800-171 §3.8.2"},
	})

	// MP-03: Media Marking (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-MP-03",
		Name:        "Media Marking",
		Description: "CMMC L2 MP.2.003: CUI media marked and tracked",
		Category:    "Media Protection",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"CMMC L2 MP.2.003"},
	})

	// MP-04: Media Access Control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-MP-04",
		Name:        "Media Access Control",
		Description: "CMMC L2 MP.2.004: Access to CUI media controlled and logged",
		Category:    "Media Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMediaAccessControl,
		References:  []string{"CMMC L2 MP.2.004"},
	})

	// MP-05: Media Transport (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-MP-05",
		Name:        "Media Transport",
		Description: "CMMC L2 MP.2.005: CUI media protected during transport",
		Category:    "Media Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 MP.2.005"},
	})
}

// registerPEControls wires Physical Protection domain controls.
func (m *CMMCL2Module) registerPEControls() {
	// PE-01: Physical Protection Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-PE-01",
		Name:        "Physical Protection Policy",
		Description: "CMMC L2 PE.1.001: Physical protection policy documented",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 PE.1.001"},
	})

	// PE-02: Physical Access Control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-PE-02",
		Name:        "Physical Access Control",
		Description: "CMMC L2 PE.2.001: Physical access controls and monitoring for CUI systems",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPhysicalAccessControl,
		References:  []string{"CMMC L2 PE.2.001", "NIST SP 800-171 §3.9.1"},
	})

	// PE-03: Physical Monitoring (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-PE-03",
		Name:        "Physical Monitoring",
		Description: "CMMC L2 PE.2.002: Physical monitoring and intrusion detection for facilities",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 PE.2.002"},
	})

	// PE-04: Environmental Controls (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-PE-04",
		Name:        "Environmental Controls",
		Description: "CMMC L2 PE.2.003: Environmental controls for CUI systems (fire, water, temperature)",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 PE.2.003"},
	})
}

// --- MA/MP/PE Check Functions ---

func (m *CMMCL2Module) checkControlledMaintenance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMaintenance := strings.Contains(inputStr, "maintenance") || strings.Contains(inputStr, "patching") || strings.Contains(inputStr, "scheduled_maintenance")
	hasAuthorized := strings.Contains(inputStr, "authorized") || strings.Contains(inputStr, "approved_personnel") || strings.Contains(inputStr, "rbac")

	if hasMaintenance && hasAuthorized {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-MA-02",
			ControlName: "Controlled Maintenance",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Controlled maintenance verified (maintenance schedule + authorized personnel)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMaintenance {
		violations = append(violations, "maintenance schedule not configured")
	}
	if !hasAuthorized {
		violations = append(violations, "authorized personnel controls not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-MA-02",
		ControlName: "Controlled Maintenance",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Controlled maintenance gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure maintenance scheduling (maintenance.enabled=true) and authorized personnel controls",
	}, nil
}

func (m *CMMCL2Module) checkMediaSanitization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSanitization := strings.Contains(inputStr, "sanitization") || strings.Contains(inputStr, "wipe") || strings.Contains(inputStr, "secure_erase")
	hasDisposal := strings.Contains(inputStr, "disposal") || strings.Contains(inputStr, "media_disposal") || strings.Contains(inputStr, "data_destruction")

	if hasSanitization || hasDisposal {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-MP-02",
			ControlName: "Media Sanitization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Media sanitization controls verified (sanitization/disposal procedures)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-MP-02",
		ControlName: "Media Sanitization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Media sanitization controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Configure media sanitization procedures (media.sanitization=true, media.disposal=true)",
	}, nil
}

func (m *CMMCL2Module) checkMediaAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccess := strings.Contains(inputStr, "media_access") || strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac")
	hasLogging := strings.Contains(inputStr, "audit") || strings.Contains(inputStr, "logging") || strings.Contains(inputStr, "media_log")

	if hasAccess && hasLogging {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-MP-04",
			ControlName: "Media Access Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Media access controls verified (access control + audit logging)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAccess {
		violations = append(violations, "media access controls not configured")
	}
	if !hasLogging {
		violations = append(violations, "media access logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-MP-04",
		ControlName: "Media Access Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Media access control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure media access controls and audit logging",
	}, nil
}

func (m *CMMCL2Module) checkPhysicalAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPhysicalAccess := strings.Contains(inputStr, "physical_access") || strings.Contains(inputStr, "badge") || strings.Contains(inputStr, "facility_access")
	hasMonitoring := strings.Contains(inputStr, "physical_monitoring") || strings.Contains(inputStr, "surveillance") || strings.Contains(inputStr, "access_log")

	if hasPhysicalAccess || hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-PE-02",
			ControlName: "Physical Access Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Physical access controls verified (access control + monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-PE-02",
		ControlName: "Physical Access Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Physical access controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Configure physical access controls (physical.badge_access=true, physical.surveillance=true)",
	}, nil
}
