// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 SA (Security Assessment) Family
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Security Assessment family (SA)
// §3.12 — Controls for security assessment and authorization.
//
// In-scope SA controls (5 controls: 3 automated + 2 evidence-mapped):
//   SA-1  Security Assessment Policy/Procedures  (evidence-mapped)
//   SA-2  Security Assessments                    (automated)
//   SA-3  Continuous Monitoring                    (automated)
//   SA-4  Acquisition Process                      (evidence-mapped)
//   SA-5  System Development Process                (evidence-mapped)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerSAControls2 wires Security Assessment controls (SA-1 through SA-3).
// Note: SA-4, SA-5, SA-9 are in cp_ma_sa.go; this adds the remaining SA controls.
func (m *NIST800171Module) registerSAControls2() {
	// SA-1: Security Assessment Policy and Procedures (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SA-1",
		Name:        "Security Assessment Policy and Procedures",
		Description: "NIST 800-171 SA-1 (3.12.1): Security assessment policy and procedures documented, reviewed, and disseminated",
		Category:    "Security Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.12.1", "NIST SP 800-53 Rev. 5 SA-1"},
	})

	// SA-2: Security Assessments (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SA-2",
		Name:        "Security Assessments",
		Description: "NIST 800-171 SA-2 (3.12.2): Security assessments performed at defined intervals and when changes occur",
		Category:    "Security Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityAssessments,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.12.2", "NIST SP 800-53 Rev. 5 CA-2"},
	})

	// SA-3: Continuous Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SA-3",
		Name:        "Continuous Monitoring",
		Description: "NIST 800-171 SA-3 (3.12.3): Continuous monitoring of security controls with automated scanning",
		Category:    "Security Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkContinuousMonitoring,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.12.3", "NIST SP 800-53 Rev. 5 CA-7"},
	})
}

// checkSecurityAssessments verifies security assessments are performed.
// Maps to SA-2.
func (m *NIST800171Module) checkSecurityAssessments(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAssessment := strings.Contains(inputStr, "assessment") || strings.Contains(inputStr, "security_assessment") || strings.Contains(inputStr, "audit")
	hasSchedule := strings.Contains(inputStr, "schedule") || strings.Contains(inputStr, "periodic") || strings.Contains(inputStr, "annual")
	hasResults := strings.Contains(inputStr, "results") || strings.Contains(inputStr, "findings") || strings.Contains(inputStr, "report")

	if hasAssessment && (hasSchedule || hasResults) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SA-2",
			ControlName: "Security Assessments",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Security assessments verified (assessment + scheduling/results)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAssessment {
		violations = append(violations, "security assessment not configured")
	}
	if !hasSchedule && !hasResults {
		violations = append(violations, "assessment schedule or results not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SA-2",
		ControlName: "Security Assessments",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Security assessment gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure periodic security assessments (assessment.enabled=true, assessment.schedule=annual)",
	}, nil
}

// checkContinuousMonitoring verifies continuous monitoring is in place.
// Maps to SA-3.
func (m *NIST800171Module) checkContinuousMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "continuous_monitoring") || strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem")
	hasScanning := strings.Contains(inputStr, "vulnerability") || strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "scan")
	hasAlerting := strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "reporting")

	if hasMonitoring && hasScanning {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SA-3",
			ControlName: "Continuous Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Continuous monitoring verified (monitoring + vulnerability scanning)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasMonitoring && hasAlerting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SA-3",
			ControlName: "Continuous Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Continuous monitoring verified (monitoring + alerting)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "continuous monitoring not configured")
	}
	if !hasScanning && !hasAlerting {
		violations = append(violations, "vulnerability scanning or alerting not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SA-3",
		ControlName: "Continuous Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Continuous monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable continuous monitoring and vulnerability scanning (monitoring.continuous=true, scanner.enabled=true)",
	}, nil
}
