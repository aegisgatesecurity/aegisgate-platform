// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 PS (Personnel Security) Family
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Personnel Security family (PS)
// §3.9 — Controls for personnel security.
//
// In-scope PS controls (4 controls: 2 automated + 2 evidence-mapped):
//   PS-1  Personnel Security Policy/Procedures   (evidence-mapped)
//   PS-2  Personnel Screening                     (automated)
//   PS-3  Personnel Termination/Transfer         (automated)
//   PS-4  Personnel Termination Procedures        (evidence-mapped)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerPSControls wires the PS family controls into the module.
func (m *NIST800171Module) registerPSControls() {
	// PS-1: Personnel Security Policy and Procedures (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-PS-1",
		Name:        "Personnel Security Policy and Procedures",
		Description: "NIST 800-171 PS-1 (3.9.1): Personnel security policy and procedures documented, reviewed, and disseminated",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.9.1", "NIST SP 800-53 Rev. 5 PS-1"},
	})

	// PS-2: Personnel Screening (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-PS-2",
		Name:        "Personnel Screening",
		Description: "NIST 800-171 PS-2 (3.9.2): Personnel screening before access with background verification",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPersonnelScreening,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.9.2", "NIST SP 800-53 Rev. 5 PS-2"},
	})

	// PS-3: Personnel Termination/Transfer (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-PS-3",
		Name:        "Personnel Termination and Transfer",
		Description: "NIST 800-171 PS-3 (3.9.3): Personnel termination and transfer procedures with access revocation",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPersonnelTermination,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.9.3", "NIST SP 800-53 Rev. 5 PS-3"},
	})

	// PS-4: Personnel Termination Procedures (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-PS-4",
		Name:        "Personnel Termination Procedures",
		Description: "NIST 800-171 PS-4: Personnel termination procedures documented with access revocation timelines",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.9", "NIST SP 800-53 Rev. 5 PS-4"},
	})
}

// checkPersonnelScreening verifies personnel screening processes are
// in place. Maps to PS-2.
func (m *NIST800171Module) checkPersonnelScreening(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasScreening := strings.Contains(inputStr, "background_check") || strings.Contains(inputStr, "screening") || strings.Contains(inputStr, "personnel_screening")
	hasVerification := strings.Contains(inputStr, "verification") || strings.Contains(inputStr, "identity_verification") || strings.Contains(inputStr, "verified")
	hasAccessControl := strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "authorization")

	if hasScreening && (hasVerification || hasAccessControl) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-PS-2",
			ControlName: "Personnel Screening",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Personnel screening verified (screening + verification/access control)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasScreening {
		violations = append(violations, "personnel screening not configured")
	}
	if !hasVerification && !hasAccessControl {
		violations = append(violations, "verification or access control not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-PS-2",
		ControlName: "Personnel Screening",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Personnel screening gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure personnel screening and background verification (personnel.screening=true)",
	}, nil
}

// checkPersonnelTermination verifies termination and transfer procedures
// with access revocation. Maps to PS-3.
func (m *NIST800171Module) checkPersonnelTermination(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTermination := strings.Contains(inputStr, "termination") || strings.Contains(inputStr, "offboarding") || strings.Contains(inputStr, "deprovisioning")
	hasAccessRevoke := strings.Contains(inputStr, "access_revocation") || strings.Contains(inputStr, "revocation") || strings.Contains(inputStr, "deprovisioning")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging") || strings.Contains(inputStr, "tracking")

	if hasTermination && hasAccessRevoke {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-PS-3",
			ControlName: "Personnel Termination and Transfer",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Personnel termination controls verified (offboarding + access revocation)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTermination && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-PS-3",
			ControlName: "Personnel Termination and Transfer",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Termination procedures detected but access revocation not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable automated access revocation on termination (personnel.auto_revocation=true)",
		}, nil
	}

	violations := []string{}
	if !hasTermination {
		violations = append(violations, "termination/offboarding procedures not detected")
	}
	if !hasAccessRevoke {
		violations = append(violations, "access revocation not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-PS-3",
		ControlName: "Personnel Termination and Transfer",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Personnel termination gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure termination/offboarding procedures with access revocation (personnel.offboarding=true)",
	}, nil
}
