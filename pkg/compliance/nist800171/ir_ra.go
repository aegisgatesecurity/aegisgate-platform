// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 IR/RA Families
// =========================================================================
//
// NIST SP 800-171 §3.6 (Incident Response) and §3.11 (Risk Assessment)
//
// IR (Incident Response): 5 controls (3 automated + 2 evidence-mapped)
// RA (Risk Assessment): 5 controls (3 automated + 2 evidence-mapped)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerIRRAControls wires IR and RA family controls into the module.
func (m *NIST800171Module) registerIRRAControls() {
	// IR: Incident Response family (5 controls)
	m.registerIRControls()
	// RA: Risk Assessment family (5 controls)
	m.registerRAControls()
}

// registerIRControls wires Incident Response controls.
func (m *NIST800171Module) registerIRControls() {
	// IR-1: Incident Response Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IR-1",
		Name:        "Incident Response Policy",
		Description: "NIST 800-171 IR-1 (3.6.1): Incident response policy and procedures documented",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIRPolicy,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.6.1", "NIST SP 800-53 Rev. 5 IR-1"},
	})

	// IR-4: Incident Handling (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IR-4",
		Name:        "Incident Handling",
		Description: "NIST 800-171 IR-4 (3.6.2): Incident handling — detect, report, and respond to incidents",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentHandling,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.6.2", "NIST SP 800-53 Rev. 5 IR-4"},
	})

	// IR-5: Incident Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IR-5",
		Name:        "Incident Monitoring",
		Description: "NIST 800-171 IR-5 (3.6.3): Incident monitoring and tracking",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIncidentMonitoring,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.6.3", "NIST SP 800-53 Rev. 5 IR-5"},
	})

	// IR-6: Incident Reporting (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IR-6",
		Name:        "Incident Reporting",
		Description: "NIST 800-171 IR-6 (3.6.4): Incident reporting to designated authorities",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentReporting,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.6.4", "NIST SP 800-53 Rev. 5 IR-6"},
	})

	// IR-8: Incident Response Plan (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-IR-8",
		Name:        "Incident Response Plan",
		Description: "NIST 800-171 IR-8 (3.6.5): Incident response plan documented and tested",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIRPlan,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.6.5", "NIST SP 800-53 Rev. 5 IR-8"},
	})
}

// registerRAControls wires Risk Assessment controls.
func (m *NIST800171Module) registerRAControls() {
	// RA-2: Vulnerability Scanning (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-RA-2",
		Name:        "Vulnerability Scanning",
		Description: "NIST 800-171 RA-2 (3.11.2): Vulnerability scanning and remediation",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityScanning,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.11.2", "NIST SP 800-53 Rev. 5 RA-5"},
	})

	// RA-3: Risk Assessment (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-RA-3",
		Name:        "Risk Assessment",
		Description: "NIST 800-171 RA-3 (3.11.3): Risk assessment documented and reviewed",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRiskAssessment,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.11.3", "NIST SP 800-53 Rev. 5 RA-3"},
	})

	// RA-5: Vulnerability Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-RA-5",
		Name:        "Vulnerability Monitoring",
		Description: "NIST 800-171 RA-5 (3.11.4): Continuous vulnerability monitoring and threat intelligence",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityMonitoring,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.11.4", "NIST SP 800-53 Rev. 5 RA-5"},
	})

	// RA-1: Risk Assessment Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-RA-1",
		Name:        "Risk Assessment Policy",
		Description: "NIST 800-171 RA-1 (3.11.1): Risk assessment policy and procedures documented",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRAPolicy,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.11.1", "NIST SP 800-53 Rev. 5 RA-1"},
	})

	// RA-7: Threat Intelligence (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-RA-7",
		Name:        "Threat Intelligence",
		Description: "NIST 800-171 RA-7: Threat intelligence feeds and monitoring",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkThreatIntel,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.11", "NIST SP 800-53 Rev. 5 RA-7"},
	})
}

// --- IR/RA Check Functions ---

func (m *NIST800171Module) checkIncidentHandling(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIncidentResp := strings.Contains(inputStr, "incident_response") || strings.Contains(inputStr, "incident_handling")
	hasIOC := strings.Contains(inputStr, "ioc") || strings.Contains(inputStr, "indicator")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem")

	if (hasIncidentResp || hasIOC) && hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IR-4",
			ControlName: "Incident Handling",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident handling controls verified (detection + response + monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasIncidentResp && !hasIOC {
		violations = append(violations, "incident response procedures not detected")
	}
	if !hasMonitoring {
		violations = append(violations, "incident monitoring not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IR-4",
		ControlName: "Incident Handling",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident handling gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable incident response procedures and monitoring (ir.enabled=true, monitoring.siem=true)",
	}, nil
}

func (m *NIST800171Module) checkIncidentMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "alert")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "ticket") || strings.Contains(inputStr, "incident_tracking")

	if hasMonitoring && hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IR-5",
			ControlName: "Incident Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Incident monitoring verified (SIEM/monitoring + tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "incident monitoring not configured")
	}
	if !hasTracking {
		violations = append(violations, "incident tracking not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IR-5",
		ControlName: "Incident Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Incident monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable incident monitoring (monitoring.enabled=true) and tracking (ir.tracking=true)",
	}, nil
}

func (m *NIST800171Module) checkIncidentReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReporting := strings.Contains(inputStr, "reporting") || strings.Contains(inputStr, "incident_report") || strings.Contains(inputStr, "notification")
	hasAuditLog := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}

	if hasReporting && hasAuditLog {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-IR-6",
			ControlName: "Incident Reporting",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident reporting verified (reporting + audit logging)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasReporting {
		violations = append(violations, "incident reporting not configured")
	}
	if !hasAuditLog {
		violations = append(violations, "audit logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-IR-6",
		ControlName: "Incident Reporting",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident reporting gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure incident reporting (ir.reporting=true) and audit logging",
	}, nil
}

func (m *NIST800171Module) checkVulnerabilityScanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnScan := strings.Contains(inputStr, "vulnerability") || strings.Contains(inputStr, "vuln_scan") || strings.Contains(inputStr, "cve")
	hasRemediation := strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "patching") || strings.Contains(inputStr, "fix")

	if hasVulnScan && hasRemediation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-RA-2",
			ControlName: "Vulnerability Scanning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability scanning verified (scanning + remediation)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasVulnScan {
		violations = append(violations, "vulnerability scanning not configured")
	}
	if !hasRemediation {
		violations = append(violations, "remediation process not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-RA-2",
		ControlName: "Vulnerability Scanning",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability scanning gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable vulnerability scanning and remediation workflows",
	}, nil
}

func (m *NIST800171Module) checkVulnerabilityMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "continuous_monitoring")
	hasThreatIntel := strings.Contains(inputStr, "threat_intel") || strings.Contains(inputStr, "ioc") || strings.Contains(inputStr, "threat_feed")

	if hasMonitoring && hasThreatIntel {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-RA-5",
			ControlName: "Vulnerability Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability monitoring verified (monitoring + threat intelligence)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "continuous monitoring not configured")
	}
	if !hasThreatIntel {
		violations = append(violations, "threat intelligence feeds not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-RA-5",
		ControlName: "Vulnerability Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable continuous monitoring and threat intelligence feeds",
	}, nil
}

// checkRAPolicy verifies risk assessment policy. Maps to NIST800171-RA-1.
func (m *NIST800171Module) checkRAPolicy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := strings.Contains(inputStr, "risk_assessment_policy") || strings.Contains(inputStr, "risk_policy") || strings.Contains(inputStr, "assessment_policy")
	hasSchedule := strings.Contains(inputStr, "scheduled") || strings.Contains(inputStr, "periodic") || strings.Contains(inputStr, "schedule")
	hasAssessment := strings.Contains(inputStr, "risk_assessment") || strings.Contains(inputStr, "assessment") || strings.Contains(inputStr, "risk_analysis")
	if hasPolicy && hasSchedule && hasAssessment {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-RA-1", ControlName: "Risk Assessment Policy", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Risk assessment policy verified (policy + schedule + assessment)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasPolicy {
		violations = append(violations, "risk assessment policy not configured")
	}
	if !hasSchedule {
		violations = append(violations, "schedule not configured")
	}
	if !hasAssessment {
		violations = append(violations, "assessment not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-RA-1", ControlName: "Risk Assessment Policy", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Risk assessment policy gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure risk assessment policy with scheduling"}, nil
}

// checkRiskAssessment verifies risk assessment. Maps to NIST800171-RA-3.
func (m *NIST800171Module) checkRiskAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAssessment := strings.Contains(inputStr, "risk_assessment") || strings.Contains(inputStr, "risk_analysis") || strings.Contains(inputStr, "threat_assessment")
	hasVuln := strings.Contains(inputStr, "vulnerability") || strings.Contains(inputStr, "vulnerabilities") || strings.Contains(inputStr, "scanner")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "findings")
	if hasAssessment && hasVuln && hasTracking {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-RA-3", ControlName: "Risk Assessment", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Risk assessment verified (assessment + vuln + tracking)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasAssessment {
		violations = append(violations, "risk assessment not configured")
	}
	if !hasVuln {
		violations = append(violations, "vulnerability scanning not configured")
	}
	if !hasTracking {
		violations = append(violations, "findings tracking not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-RA-3", ControlName: "Risk Assessment", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Risk assessment gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure risk assessment with vulnerability scanning and tracking"}, nil
}

// checkThreatIntel verifies threat intelligence. Maps to NIST800171-RA-7.
func (m *NIST800171Module) checkThreatIntel(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasThreatIntel := strings.Contains(inputStr, "threat_intel") || strings.Contains(inputStr, "threat_intelligence") || strings.Contains(inputStr, "threat_intel")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "ioc")
	hasAlerting := strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alerts") || strings.Contains(inputStr, "threat")
	if hasThreatIntel && hasMonitoring && hasAlerting {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-RA-7", ControlName: "Threat Intelligence", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Threat intelligence verified (intel + monitoring + alerting)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasThreatIntel {
		violations = append(violations, "threat intelligence not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "monitoring not configured")
	}
	if !hasAlerting {
		violations = append(violations, "alerting not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-RA-7", ControlName: "Threat Intelligence", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Threat intelligence gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure threat intelligence with monitoring and alerting"}, nil
}

// checkIRPolicy verifies incident response policy. Maps to NIST800171-IR-1.
func (m *NIST800171Module) checkIRPolicy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := strings.Contains(inputStr, "incident_response_policy") || strings.Contains(inputStr, "ir_policy") || strings.Contains(inputStr, "response_policy")
	hasIR := strings.Contains(inputStr, "incident_response") || strings.Contains(inputStr, "incident_handling") || strings.Contains(inputStr, "incident")
	hasProcedures := strings.Contains(inputStr, "procedures") || strings.Contains(inputStr, "ir_procedures") || strings.Contains(inputStr, "response_procedures")
	if hasPolicy && hasIR && hasProcedures {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-IR-1", ControlName: "Incident Response Policy", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "IR policy verified (policy + IR + procedures)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasPolicy {
		violations = append(violations, "IR policy not configured")
	}
	if !hasIR {
		violations = append(violations, "incident response not configured")
	}
	if !hasProcedures {
		violations = append(violations, "procedures not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-IR-1", ControlName: "Incident Response Policy", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "IR policy gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure IR policy with procedures"}, nil
}

// checkIRPlan verifies incident response plan. Maps to NIST800171-IR-8.
func (m *NIST800171Module) checkIRPlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPlan := strings.Contains(inputStr, "incident_response_plan") || strings.Contains(inputStr, "ir_plan") || strings.Contains(inputStr, "incident_plan")
	hasProcedures := strings.Contains(inputStr, "procedures") || strings.Contains(inputStr, "response_procedures") || strings.Contains(inputStr, "ir_procedures")
	hasRoles := strings.Contains(inputStr, "roles") || strings.Contains(inputStr, "responsibilities") || strings.Contains(inputStr, "ir_roles")
	if hasPlan && hasProcedures && hasRoles {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-IR-8", ControlName: "Incident Response Plan", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "IR plan verified (plan + procedures + roles)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasPlan {
		violations = append(violations, "IR plan not configured")
	}
	if !hasProcedures {
		violations = append(violations, "procedures not configured")
	}
	if !hasRoles {
		violations = append(violations, "roles not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "NIST800171-IR-8", ControlName: "Incident Response Plan", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "IR plan gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure IR plan with procedures and roles"}, nil
}
