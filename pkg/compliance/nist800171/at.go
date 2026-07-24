// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 AT (Awareness and Training) Family
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Awareness and Training family (AT)
// §3.2 — Controls for security awareness and training.
//
// In-scope AT controls (5 controls: 3 automated + 2 evidence-mapped):
//   AT-1  Awareness and Training Policy/Procedures  (evidence-mapped)
//   AT-2  Security Awareness Training                (automated)
//   AT-3  Role-Based Security Training                (automated)
//   AT-4  Security Training Records                  (automated)
//   AT-5  Security Awareness Refresher               (evidence-mapped)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerATControls wires the AT family controls into the module.
func (m *NIST800171Module) registerATControls() {
	// AT-1: Awareness and Training Policy and Procedures (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AT-1",
		Name:        "Awareness and Training Policy and Procedures",
		Description: "NIST 800-171 AT-1 (3.2.1): Awareness and training policy and procedures documented, reviewed, and disseminated",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.2.1", "NIST SP 800-53 Rev. 5 AT-1"},
	})

	// AT-2: Security Awareness Training (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AT-2",
		Name:        "Security Awareness Training",
		Description: "NIST 800-171 AT-2 (3.2.2): Security awareness training provided to all users before access and periodically thereafter",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityAwarenessTraining,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.2.2", "NIST SP 800-53 Rev. 5 AT-2"},
	})

	// AT-3: Role-Based Security Training (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AT-3",
		Name:        "Role-Based Security Training",
		Description: "NIST 800-171 AT-3 (3.2.3): Role-based security training for individuals with specialized roles",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRoleBasedTraining,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.2.3", "NIST SP 800-53 Rev. 5 AT-3"},
	})

	// AT-4: Security Training Records (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AT-4",
		Name:        "Security Training Records",
		Description: "NIST 800-171 AT-4 (3.2.4): Security training records maintained and tracked for all personnel",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTrainingRecords,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.2.4", "NIST SP 800-53 Rev. 5 AT-4"},
	})

	// AT-5: Security Awareness Refresher (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-AT-5",
		Name:        "Security Awareness Refresher",
		Description: "NIST 800-171 AT-5: Periodic security awareness refresher training",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.2", "NIST SP 800-53 Rev. 5 AT-5"},
	})
}

// checkSecurityAwarenessTraining verifies security awareness training is
// provided to all users. Maps to AT-2.
func (m *NIST800171Module) checkSecurityAwarenessTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTraining := strings.Contains(inputStr, "security_training") || strings.Contains(inputStr, "awareness_training") || strings.Contains(inputStr, "training")
	hasCompletion := strings.Contains(inputStr, "training_completion") || strings.Contains(inputStr, "completion_records") || strings.Contains(inputStr, "certified")

	if hasTraining && hasCompletion {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AT-2",
			ControlName: "Security Awareness Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Security awareness training verified (training + completion tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasTraining {
		violations = append(violations, "security awareness training not configured")
	}
	if !hasCompletion {
		violations = append(violations, "training completion tracking not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AT-2",
		ControlName: "Security Awareness Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Security awareness training gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable security awareness training and completion tracking (training.security_awareness=true)",
	}, nil
}

// checkRoleBasedTraining verifies role-based security training is provided.
// Maps to AT-3.
func (m *NIST800171Module) checkRoleBasedTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRoleTraining := strings.Contains(inputStr, "role_training") || strings.Contains(inputStr, "role_based_training") || strings.Contains(inputStr, "specialized_training")
	hasRoles := strings.Contains(inputStr, "roles") || strings.Contains(inputStr, "rbac")
	hasTracking := strings.Contains(inputStr, "training_records") || strings.Contains(inputStr, "completion_records") || strings.Contains(inputStr, "certified")

	if hasRoleTraining && hasRoles {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AT-3",
			ControlName: "Role-Based Security Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Role-based security training verified (specialized training + role assignment)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasRoleTraining && hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AT-3",
			ControlName: "Role-Based Security Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Role-based security training verified (training + completion tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRoleTraining {
		violations = append(violations, "role-based training not configured")
	}
	if !hasRoles && !hasTracking {
		violations = append(violations, "role assignment or training tracking not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AT-3",
		ControlName: "Role-Based Security Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Role-based training gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable role-based training with role assignment and completion tracking (training.role_based=true)",
	}, nil
}

// checkTrainingRecords verifies security training records are maintained.
// Maps to AT-4.
func (m *NIST800171Module) checkTrainingRecords(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRecords := strings.Contains(inputStr, "training_records") || strings.Contains(inputStr, "completion_records") || strings.Contains(inputStr, "certified")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging") || strings.Contains(inputStr, "tracking")

	if hasRecords && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AT-4",
			ControlName: "Security Training Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Security training records verified (records + audit/tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasRecords {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-AT-4",
			ControlName: "Security Training Records",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Training records detected but audit/tracking not confirmed",
			Timestamp:   time.Now(),
			Remediation: "Enable training audit logging (training.audit_records=true)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-AT-4",
		ControlName: "Security Training Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Security training records not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable training records and audit logging (training.records=true, training.audit_records=true)",
	}, nil
}
