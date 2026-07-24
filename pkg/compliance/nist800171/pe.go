// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 PE (Physical Protection) Family
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Physical Protection family (PE)
// §3.10 — Controls for physical protection of CUI systems.
//
// In-scope PE controls (3 controls: 1 automated + 2 evidence-mapped):
//   PE-1  Physical Protection Policy/Procedures   (evidence-mapped)
//   PE-2  Physical Access Authorization            (automated)
//   PE-3  Physical Access Control                  (evidence-mapped)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerPEControls wires the PE family controls into the module.
func (m *NIST800171Module) registerPEControls() {
	// PE-1: Physical Protection Policy and Procedures (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-PE-1",
		Name:        "Physical Protection Policy and Procedures",
		Description: "NIST 800-171 PE-1 (3.10.1): Physical protection policy and procedures documented, reviewed, and disseminated",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.10.1", "NIST SP 800-53 Rev. 5 PE-1"},
	})

	// PE-2: Physical Access Authorization (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-PE-2",
		Name:        "Physical Access Authorization",
		Description: "NIST 800-171 PE-2 (3.10.2): Physical access authorization with access lists and role-based access",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPhysicalAccessAuthorization,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.10.2", "NIST SP 800-53 Rev. 5 PE-2"},
	})

	// PE-3: Physical Access Control (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-PE-3",
		Name:        "Physical Access Control",
		Description: "NIST 800-171 PE-3 (3.10.3): Physical access controls for CUI systems with monitoring and escort procedures",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.10.3", "NIST SP 800-53 Rev. 5 PE-3"},
	})
}

// checkPhysicalAccessAuthorization verifies physical access authorization
// controls are in place. Maps to PE-2.
func (m *NIST800171Module) checkPhysicalAccessAuthorization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccessList := strings.Contains(inputStr, "access_list") || strings.Contains(inputStr, "authorized_personnel") || strings.Contains(inputStr, "access_control")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles") || strings.Contains(inputStr, "authorization")
	hasLogging := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging") || strings.Contains(inputStr, "access_log")

	if hasAccessList && hasRBAC {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-PE-2",
			ControlName: "Physical Access Authorization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Physical access authorization verified (access list + role-based access)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasAccessList && hasLogging {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-PE-2",
			ControlName: "Physical Access Authorization",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Physical access authorization verified (access list + logging)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAccessList {
		violations = append(violations, "physical access list not configured")
	}
	if !hasRBAC && !hasLogging {
		violations = append(violations, "role-based access or logging not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-PE-2",
		ControlName: "Physical Access Authorization",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Physical access authorization gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure physical access lists and role-based authorization (physical.access_list=true)",
	}, nil
}
