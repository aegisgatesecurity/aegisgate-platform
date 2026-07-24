// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC L2 AT + PS Domains
// =========================================================================
//
// CMMC Level 2 — Awareness & Training (AT) + Personnel Security (PS)
//
// AT (Awareness & Training): 5 practices (2 automated + 3 evidence-mapped)
// PS (Personnel Security): 4 practices (2 automated + 2 evidence-mapped)
//
// =========================================================================

package cmmcl2

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerATControls wires Awareness & Training domain controls.
func (m *CMMCL2Module) registerATControls() {
	// AT-01: Security Awareness Training Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AT-01",
		Name:        "Security Awareness Training Policy",
		Description: "CMMC L2 AT.2.001: Security awareness training policy documented and disseminated",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 AT.2.001", "NIST SP 800-171 §3.2.1"},
	})

	// AT-02: Security Awareness Training Content (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AT-02",
		Name:        "Security Awareness Training Content",
		Description: "CMMC L2 AT.2.002: Security awareness training covers CUI identification, reporting, and handling",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityAwarenessTraining,
		References:  []string{"CMMC L2 AT.2.002", "NIST SP 800-171 §3.2.2"},
	})

	// AT-03: Role-Based Training (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AT-03",
		Name:        "Role Based Training",
		Description: "CMMC L2 AT.2.003: Role-based security training for individuals with CUI access responsibilities",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 AT.2.003", "NIST SP 800-171 §3.2.3"},
	})

	// AT-04: Training Records (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AT-04",
		Name:        "Training Records",
		Description: "CMMC L2 AT.2.004: Security training records maintained and tracked for compliance",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkTrainingRecords,
		References:  []string{"CMMC L2 AT.2.004", "NIST SP 800-171 §3.2.4"},
	})

	// AT-05: Phishing Awareness (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AT-05",
		Name:        "Phishing Awareness",
		Description: "CMMC L2 AT.2.005: Phishing awareness and social engineering training documented and tracked",
		Category:    "Awareness and Training",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 AT.2.005", "NIST SP 800-171 §3.2.5"},
	})
}

// registerPSControls wires Personnel Security domain controls.
func (m *CMMCL2Module) registerPSControls() {
	// PS-01: Personnel Screening (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-PS-01",
		Name:        "Personnel Screening",
		Description: "CMMC L2 PS.2.001: Personnel screening and vetting for CUI access",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 PS.2.001", "NIST SP 800-171 §3.9.1"},
	})

	// PS-02: Personnel Termination (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-PS-02",
		Name:        "Personnel Termination",
		Description: "CMMC L2 PS.2.002: Personnel termination and transfer procedures for CUI access revocation",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 PS.2.002", "NIST SP 800-171 §3.9.2"},
	})

	// PS-03: Access Revocation (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-PS-03",
		Name:        "Access Revocation",
		Description: "CMMC L2 PS.2.003: Automated access revocation upon personnel termination or transfer",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessRevocation,
		References:  []string{"CMMC L2 PS.2.003", "NIST SP 800-171 §3.9.3"},
	})

	// PS-04: Personnel Sanctions (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-PS-04",
		Name:        "Personnel Sanctions",
		Description: "CMMC L2 PS.2.004: Personnel sanctions process for security violations with audit trail",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPersonnelSanctions,
		References:  []string{"CMMC L2 PS.2.004", "NIST SP 800-171 §3.9.4"},
	})
}

// --- AT Check Functions ---

// checkSecurityAwarenessTraining verifies security awareness training is
// configured and tracked. Maps to CMMC L2 AT.2.002.
func (m *CMMCL2Module) checkSecurityAwarenessTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTraining := strings.Contains(inputStr, "security_training") || strings.Contains(inputStr, "awareness_training") || strings.Contains(inputStr, "training")
	hasCUI := strings.Contains(inputStr, "cui") || strings.Contains(inputStr, "controlled_unclassified") || strings.Contains(inputStr, "classification")

	if hasTraining && hasCUI {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AT-02",
			ControlName: "Security Awareness Training Content",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Security awareness training verified (training content + CUI coverage)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasTraining {
		violations = append(violations, "security awareness training not configured")
	}
	if !hasCUI {
		violations = append(violations, "CUI identification training not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AT-02",
		ControlName: "Security Awareness Training Content",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Security awareness training gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure security awareness training (security_training=true) with CUI identification content",
	}, nil
}

// checkTrainingRecords verifies training records are maintained and tracked.
// Maps to CMMC L2 AT.2.004.
func (m *CMMCL2Module) checkTrainingRecords(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTracking := strings.Contains(inputStr, "training_records") || strings.Contains(inputStr, "training_tracking") || strings.Contains(inputStr, "training")
	hasCompletion := strings.Contains(inputStr, "completion") || strings.Contains(inputStr, "certification") || strings.Contains(inputStr, "compliance")

	if hasTracking && hasCompletion {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AT-04",
			ControlName: "Training Records",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityLow,
			Message:     "Training records verified (tracking + completion tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasTracking {
		violations = append(violations, "training tracking not configured")
	}
	if !hasCompletion {
		violations = append(violations, "training completion records not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AT-04",
		ControlName: "Training Records",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityLow,
		Message:     "Training records gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure training records tracking (training_records=true) with completion certification",
	}, nil
}

// --- PS Check Functions ---

// checkAccessRevocation verifies automated access revocation is in place.
// Maps to CMMC L2 PS.2.003.
func (m *CMMCL2Module) checkAccessRevocation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRevocation := strings.Contains(inputStr, "access_revocation") || strings.Contains(inputStr, "deprovisioning") || strings.Contains(inputStr, "revocation")
	hasAutomation := strings.Contains(inputStr, "automated") || strings.Contains(inputStr, "auto_deprovision") || strings.Contains(inputStr, "scim")

	if hasRevocation && hasAutomation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-PS-03",
			ControlName: "Access Revocation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Access revocation verified (automated deprovisioning)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRevocation {
		violations = append(violations, "access revocation process not configured")
	}
	if !hasAutomation {
		violations = append(violations, "automated deprovisioning not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-PS-03",
		ControlName: "Access Revocation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Access revocation gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure automated access revocation (access_revocation=true, auto_deprovision=true)",
	}, nil
}

// checkPersonnelSanctions verifies personnel sanctions process has audit trail.
// Maps to CMMC L2 PS.2.004.
func (m *CMMCL2Module) checkPersonnelSanctions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSanctions := strings.Contains(inputStr, "sanctions") || strings.Contains(inputStr, "disciplinary") || strings.Contains(inputStr, "violation")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_trail") || strings.Contains(inputStr, "logging")

	if hasSanctions && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-PS-04",
			ControlName: "Personnel Sanctions",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Personnel sanctions verified (sanctions process + audit trail)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSanctions {
		violations = append(violations, "personnel sanctions process not configured")
	}
	if !hasAudit {
		violations = append(violations, "sanctions audit trail not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-PS-04",
		ControlName: "Personnel Sanctions",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Personnel sanctions gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure personnel sanctions tracking (sanctions=true) with audit trail (audit_log=true)",
	}, nil
}
