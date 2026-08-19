// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HITRUST CSF IR/SD/AI Families
// =========================================================================
//
// HITRUST CSF v11.2 — Incident Response (IR), Supplier/Development (SD),
// and AI Controls (AI) families.
//
// In-scope controls (40 total: 6 automated + 34 manual):
//
//   IR (Incident Response): 15 controls (3 automated + 12 manual)
//   SD (Supplier/Development): 15 controls (1 automated + 14 manual)
//   AI (AI Controls): 10 controls (2 automated + 8 manual)
//
// =========================================================================

package hitrust

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerIRSDControls wires the IR, SD, and AI family controls into the module.
func (m *HITRUSTModule) registerIRSDControls() {
	m.registerIRControls()
	m.registerSDControls()
	m.registerAIControls()
}

// ── IR: Incident Response ─────────────────────────────────────────

// registerIRControls wires the IR family controls.
func (m *HITRUSTModule) registerIRControls() {
	// IR-01: Incident Response Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-01",
		Name:        "Incident Response Policy",
		Description: "HITRUST CSF v11.2 IR-01: Incident response policy documented and reviewed",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IR-1"},
	})

	// IR-02: Incident Response Plan (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-02",
		Name:        "Incident Response Plan",
		Description: "HITRUST CSF v11.2 IR-02: Incident response plan — documented plan for incident handling",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIRPlan,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IR-2"},
	})

	// IR-03: Incident Response Training (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-03",
		Name:        "Incident Response Training",
		Description: "HITRUST CSF v11.2 IR-03: Incident response training — personnel trained on incident response procedures",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IR-3"},
	})

	// IR-04: Incident Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-04",
		Name:        "Incident Monitoring",
		Description: "HITRUST CSF v11.2 IR-04: Incident monitoring — automated monitoring for security incidents",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentMonitoring,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IR-5"},
	})

	// IR-05: Incident Reporting (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-05",
		Name:        "Incident Reporting",
		Description: "HITRUST CSF v11.2 IR-05: Incident reporting — procedures for reporting security incidents",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IR-6"},
	})

	// IR-06: Incident Response Plan Testing (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-06",
		Name:        "Incident Response Plan Testing",
		Description: "HITRUST CSF v11.2 IR-06: Incident response plan testing — regular testing of the IR plan",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IR-4"},
	})

	// IR-07: Incident Handling (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-07",
		Name:        "Incident Handling",
		Description: "HITRUST CSF v11.2 IR-07: Incident handling — automated handling and containment of incidents",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentHandling,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IR-4"},
	})

	// IR-08: Incident Information Collection (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-08",
		Name:        "Incident Information Collection",
		Description: "HITRUST CSF v11.2 IR-08: Incident information collection — systematic collection of incident data",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// IR-09: Evidentiary Preservation (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-09",
		Name:        "Evidentiary Preservation",
		Description: "HITRUST CSF v11.2 IR-09: Evidentiary preservation — preservation of evidence for investigations",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// IR-10: Incident Communication (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-10",
		Name:        "Incident Communication",
		Description: "HITRUST CSF v11.2 IR-10: Incident communication — procedures for communicating during incidents",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// IR-11: Forensic Analysis (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-11",
		Name:        "Forensic Analysis",
		Description: "HITRUST CSF v11.2 IR-11: Forensic analysis — procedures for forensic analysis of incidents",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// IR-12: Incident Mitigation (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-12",
		Name:        "Incident Mitigation",
		Description: "HITRUST CSF v11.2 IR-12: Incident mitigation — procedures for mitigating incident impact",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// IR-13: Recovery (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-13",
		Name:        "Recovery",
		Description: "HITRUST CSF v11.2 IR-13: Recovery — procedures for recovering from security incidents",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// IR-14: Post-Incident Review (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-14",
		Name:        "Post-Incident Review",
		Description: "HITRUST CSF v11.2 IR-14: Post-incident review — review of incidents to improve response",
		Category:    "Incident Response",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// IR-15: Incident Response Assistance (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IR-15",
		Name:        "Incident Response Assistance",
		Description: "HITRUST CSF v11.2 IR-15: Incident response assistance — resources for incident response support",
		Category:    "Incident Response",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})
}

// ── SD: Supplier/Development ──────────────────────────────────────

// registerSDControls wires the SD family controls.
func (m *HITRUSTModule) registerSDControls() {
	// SD-01: Supply Chain Risk Management Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-01",
		Name:        "Supply Chain Risk Management Policy",
		Description: "HITRUST CSF v11.2 SD-01: Supply chain risk management policy documented and reviewed",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SR-1"},
	})

	// SD-02: Supply Chain Risk Assessment (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-02",
		Name:        "Supply Chain Risk Assessment",
		Description: "HITRUST CSF v11.2 SD-02: Supply chain risk assessment — assessment of supply chain risks",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SR-2"},
	})

	// SD-03: Supply Chain Plan (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-03",
		Name:        "Supply Chain Plan",
		Description: "HITRUST CSF v11.2 SD-03: Supply chain plan — documented plan for supply chain risk management",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SR-3"},
	})

	// SD-04: Acquisition Strategies (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-04",
		Name:        "Acquisition Strategies",
		Description: "HITRUST CSF v11.2 SD-04: Acquisition strategies — security requirements in acquisition strategies",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SR-4"},
	})

	// SD-05: System Security Engineering (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-05",
		Name:        "System Security Engineering",
		Description: "HITRUST CSF v11.2 SD-05: System security engineering — security engineering principles applied to systems",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SA-8"},
	})

	// SD-06: Developer Configuration Management (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-06",
		Name:        "Developer Configuration Management",
		Description: "HITRUST CSF v11.2 SD-06: Developer configuration management — CM requirements for developers",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SA-10"},
	})

	// SD-07: Developer Security Testing (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-07",
		Name:        "Developer Security Testing",
		Description: "HITRUST CSF v11.2 SD-07: Developer security testing — security testing requirements for developers",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SA-11"},
	})

	// SD-08: Supply Chain Protection (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-08",
		Name:        "Supply Chain Protection",
		Description: "HITRUST CSF v11.2 SD-08: Supply chain protection — controls to protect supply chain integrity",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SR-5"},
	})

	// SD-09: Acquisition Process (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-09",
		Name:        "Acquisition Process",
		Description: "HITRUST CSF v11.2 SD-09: Acquisition process — security requirements in the acquisition process",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SA-2"},
	})

	// SD-10: System Documentation (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-10",
		Name:        "System Documentation",
		Description: "HITRUST CSF v11.2 SD-10: System documentation — automated verification of system documentation completeness",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkSystemDocumentation,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SA-5"},
	})

	// SD-11: Developer Screening (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-11",
		Name:        "Developer Screening",
		Description: "HITRUST CSF v11.2 SD-11: Developer screening — screening requirements for developers and contractors",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SA-9"},
	})

	// SD-12: External System Services (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-12",
		Name:        "External System Services",
		Description: "HITRUST CSF v11.2 SD-12: External system services — security requirements for external service providers",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SA-9"},
	})

	// SD-13: System Disposal (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-13",
		Name:        "System Disposal",
		Description: "HITRUST CSF v11.2 SD-13: System disposal — procedures for secure disposal of systems and components",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 MP-6"},
	})

	// SD-14: Information Transfer (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-14",
		Name:        "Information Transfer",
		Description: "HITRUST CSF v11.2 SD-14: Information transfer — controls for transferring information between systems",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 AC-21"},
	})

	// SD-15: Software Supply Chain Security (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-SD-15",
		Name:        "Software Supply Chain Security",
		Description: "HITRUST CSF v11.2 SD-15: Software supply chain security — controls for securing the software supply chain",
		Category:    "Supplier/Development",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})
}

// ── AI: AI Controls ───────────────────────────────────────────────

// registerAIControls wires the AI family controls.
func (m *HITRUSTModule) registerAIControls() {
	// AI-01: AI Model Data Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-01",
		Name:        "AI Model Data Protection",
		Description: "HITRUST CSF v11.2 AI-01: AI model data protection — encryption and access controls for AI training and model data",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelDataProtection,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})

	// AI-02: AI Audit Trail (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-02",
		Name:        "AI Audit Trail",
		Description: "HITRUST CSF v11.2 AI-02: AI audit trail — logging and auditing of AI model usage and decisions",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrail,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})

	// AI-03: AI Model Governance (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-03",
		Name:        "AI Model Governance",
		Description: "HITRUST CSF v11.2 AI-03: AI model governance — governance framework for AI model development and deployment",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})

	// AI-04: AI Output Validation (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-04",
		Name:        "AI Output Validation",
		Description: "HITRUST CSF v11.2 AI-04: AI output validation — validation of AI model outputs for accuracy and safety",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})

	// AI-05: AI Training Data Controls (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-05",
		Name:        "AI Training Data Controls",
		Description: "HITRUST CSF v11.2 AI-05: AI training data controls — controls for the quality, integrity, and security of training data",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})

	// AI-06: AI Model Inventory (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-06",
		Name:        "AI Model Inventory",
		Description: "HITRUST CSF v11.2 AI-06: AI model inventory — comprehensive inventory of AI models in use",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})

	// AI-07: AI Bias Testing (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-07",
		Name:        "AI Bias Testing",
		Description: "HITRUST CSF v11.2 AI-07: AI bias testing — testing for bias in AI model outputs and decisions",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})

	// AI-08: AI Model Retention (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-08",
		Name:        "AI Model Retention",
		Description: "HITRUST CSF v11.2 AI-08: AI model retention — retention policies for AI models and training data",
		Category:    "AI Controls",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})

	// AI-09: AI Privacy Impact (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-09",
		Name:        "AI Privacy Impact",
		Description: "HITRUST CSF v11.2 AI-09: AI privacy impact — assessment of privacy impacts from AI model usage",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})

	// AI-10: AI Third-Party Risk (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-AI-10",
		Name:        "AI Third-Party Risk",
		Description: "HITRUST CSF v11.2 AI-10: AI third-party risk — management of risks from third-party AI services and models",
		Category:    "AI Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 AI Supplement"},
	})
}

// ── IR Family Automated Checks ────────────────────────────────────

// checkIRPlan verifies incident response plan. Maps to HITRUST IR-02.
func (m *HITRUSTModule) checkIRPlan(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRPlan := strings.Contains(inputStr, "incident_response_plan") || strings.Contains(inputStr, "ir_plan") || strings.Contains(inputStr, "incident_plan")
	hasProcedures := strings.Contains(inputStr, "procedures") || strings.Contains(inputStr, "response_procedures") || strings.Contains(inputStr, "ir_procedures")
	hasRoles := strings.Contains(inputStr, "roles") || strings.Contains(inputStr, "ir_roles") || strings.Contains(inputStr, "responsibilities")

	if hasIRPlan && hasProcedures && hasRoles {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IR-02",
			ControlName: "Incident Response Plan",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "IR plan verified (plan + procedures + roles)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasIRPlan {
		violations = append(violations, "incident response plan not configured")
	}
	if !hasProcedures {
		violations = append(violations, "response procedures not configured")
	}
	if !hasRoles {
		violations = append(violations, "roles and responsibilities not defined")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IR-02",
		ControlName: "Incident Response Plan",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "IR plan gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Document incident response plan with procedures and roles",
	}, nil
}

// checkIncidentMonitoring verifies incident monitoring. Maps to HITRUST IR-04.
func (m *HITRUSTModule) checkIncidentMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "incident_monitoring") || strings.Contains(inputStr, "monitoring") || m.hasAudit(inputStr)
	hasDetection := strings.Contains(inputStr, "incident_detection") || strings.Contains(inputStr, "detection") || strings.Contains(inputStr, "siem")
	hasAlerting := strings.Contains(inputStr, "incident_alerting") || strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alerts")

	if hasMonitoring && hasDetection && hasAlerting {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IR-04",
			ControlName: "Incident Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident monitoring verified (monitoring + detection + alerting)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMonitoring {
		violations = append(violations, "incident monitoring not configured")
	}
	if !hasDetection {
		violations = append(violations, "incident detection not configured")
	}
	if !hasAlerting {
		violations = append(violations, "incident alerting not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IR-04",
		ControlName: "Incident Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure incident monitoring with detection and alerting",
	}, nil
}

// checkIncidentHandling verifies incident handling. Maps to HITRUST IR-07.
func (m *HITRUSTModule) checkIncidentHandling(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHandling := strings.Contains(inputStr, "incident_handling") || strings.Contains(inputStr, "incident_response") || strings.Contains(inputStr, "handling")
	hasContainment := strings.Contains(inputStr, "containment") || strings.Contains(inputStr, "isolation") || strings.Contains(inputStr, "auto_containment")
	hasAudit := m.hasAudit(inputStr)

	if hasHandling && hasContainment && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IR-07",
			ControlName: "Incident Handling",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident handling verified (handling + containment + audit)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasHandling {
		violations = append(violations, "incident handling not configured")
	}
	if !hasContainment {
		violations = append(violations, "containment not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IR-07",
		ControlName: "Incident Handling",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident handling gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure incident handling with containment and audit logging",
	}, nil
}

// ── SD Family Automated Checks ────────────────────────────────────

// checkSystemDocumentation verifies system documentation. Maps to HITRUST SD-10.
func (m *HITRUSTModule) checkSystemDocumentation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDocs := strings.Contains(inputStr, "system_documentation") || strings.Contains(inputStr, "documentation") || strings.Contains(inputStr, "system_docs")
	hasComplete := strings.Contains(inputStr, "documentation_complete") || strings.Contains(inputStr, "complete") || strings.Contains(inputStr, "docs_verified")
	hasUpToDate := strings.Contains(inputStr, "documentation_current") || strings.Contains(inputStr, "up_to_date") || strings.Contains(inputStr, "current") || strings.Contains(inputStr, "version_control")

	if hasDocs && hasComplete && hasUpToDate {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-SD-10",
			ControlName: "System Documentation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityLow,
			Message:     "System documentation verified (docs + complete + up-to-date)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasDocs {
		violations = append(violations, "system documentation not configured")
	}
	if !hasComplete {
		violations = append(violations, "documentation completeness not verified")
	}
	if !hasUpToDate {
		violations = append(violations, "documentation currency not verified")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-SD-10",
		ControlName: "System Documentation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityLow,
		Message:     "System documentation gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure system documentation with completeness and currency verification",
	}, nil
}

// ── AI Family Automated Checks ────────────────────────────────────

// checkAIModelDataProtection verifies AI model data protection. Maps to HITRUST AI-01.
func (m *HITRUSTModule) checkAIModelDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasProtection := strings.Contains(inputStr, "ai_model_data_protection") || strings.Contains(inputStr, "model_data_protection") || strings.Contains(inputStr, "ai_data_protection")
	hasEncryption := m.hasEncryption(inputStr) || strings.Contains(inputStr, "encryption")
	hasAccessControl := strings.Contains(inputStr, "access_control") || m.hasRBAC(inputStr) || strings.Contains(inputStr, "data_access_control")

	if hasProtection && hasEncryption && hasAccessControl {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-AI-01",
			ControlName: "AI Model Data Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "AI model data protection verified (protection + encryption + access control)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasProtection {
		violations = append(violations, "AI model data protection not configured")
	}
	if !hasEncryption {
		violations = append(violations, "encryption not configured for AI data")
	}
	if !hasAccessControl {
		violations = append(violations, "access control not configured for AI data")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-AI-01",
		ControlName: "AI Model Data Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "AI model data protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure AI model data protection with encryption and access controls",
	}, nil
}

// checkAIAuditTrail verifies AI audit trail. Maps to HITRUST AI-02.
func (m *HITRUSTModule) checkAIAuditTrail(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditTrail := strings.Contains(inputStr, "ai_audit_trail") || strings.Contains(inputStr, "ai_audit") || strings.Contains(inputStr, "model_audit")
	hasLogging := m.hasAudit(inputStr) || strings.Contains(inputStr, "ai_logging") || strings.Contains(inputStr, "model_logging")
	hasTracking := strings.Contains(inputStr, "ai_usage_tracking") || strings.Contains(inputStr, "usage_tracking") || strings.Contains(inputStr, "decision_tracking")

	if hasAuditTrail && hasLogging && hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-AI-02",
			ControlName: "AI Audit Trail",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI audit trail verified (audit trail + logging + usage tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAuditTrail {
		violations = append(violations, "AI audit trail not configured")
	}
	if !hasLogging {
		violations = append(violations, "AI logging not configured")
	}
	if !hasTracking {
		violations = append(violations, "AI usage tracking not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-AI-02",
		ControlName: "AI Audit Trail",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI audit trail gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure AI audit trail with logging and usage tracking",
	}, nil
}
