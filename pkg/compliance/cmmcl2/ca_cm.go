// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC L2 CA + CM Domains
// =========================================================================
//
// CMMC Level 2 — Assessment and Authorization (CA) + Configuration Management (CM)
// NIST SP 800-171 Rev. 2 §3.9 (CA) + §3.4 (CM) practices
//
// In-scope CA controls (3 of ~3 CA practices):
//   CA.1.001  Security assessment                      (automated)
//   CA.2.001  Plan of action                            (automated)
//   CA.2.002  Continuous monitoring                      (automated)
//
// In-scope CM controls (5 of ~9 CM practices):
//   CM.1.001  Baseline configuration                    (evidence-mapped)
//   CM.2.001  Change control                            (automated)
//   CM.2.002  Component inventory                        (automated)
//   CM.2.003  Configuration restrictions                (evidence-mapped)
//   CM.2.004  Secure configuration                      (evidence-mapped)
//
// =========================================================================

package cmmcl2

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerCAControls wires the CA domain controls into the module.
func (m *CMMCL2Module) registerCAControls() {
	// CA.1.001: Security assessment (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CA-01",
		Name:        "Security Assessment",
		Description: "CMMC L2 CA.1.001: Periodically assess security controls — compliance scanning and vulnerability assessment",
		Category:    "Assessment and Authorization",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityAssessment,
		References:  []string{"CMMC L2 CA.1.001", "NIST SP 800-171 §3.9.1"},
	})

	// CA.2.001: Plan of action (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CA-02",
		Name:        "Plan Of Action",
		Description: "CMMC L2 CA.2.001: Develop and implement a plan of action and milestones — remediation tracking",
		Category:    "Assessment and Authorization",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPlanOfAction,
		References:  []string{"CMMC L2 CA.2.001", "NIST SP 800-171 §3.9.2"},
	})

	// CA.2.002: Continuous monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CA-03",
		Name:        "Continuous Monitoring",
		Description: "CMMC L2 CA.2.002: Monitor security controls on an ongoing basis — CCM scanning and drift detection",
		Category:    "Assessment and Authorization",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkContinuousMonitoring,
		References:  []string{"CMMC L2 CA.2.002", "NIST SP 800-171 §3.9.3"},
	})
}

// registerCMControls wires the CM domain controls into the module.
func (m *CMMCL2Module) registerCMControls() {
	// CM.1.001: Baseline configuration (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-01",
		Name:        "Baseline Configuration",
		Description: "CMMC L2 CM.1.001: Establish and maintain baseline configurations. AegisGate generates the baseline configuration evidence for the customer's CMMC assessment.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCMBaselineConfig,
		References:  []string{"CMMC L2 CM.1.001", "NIST SP 800-171 §3.4.1"},
	})

	// CM.2.001: Change control (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-02",
		Name:        "Change Control",
		Description: "CMMC L2 CM.2.001: Control changes to the system — change log, review, and approval",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkChangeControl,
		References:  []string{"CMMC L2 CM.2.001", "NIST SP 800-171 §3.4.2"},
	})

	// CM.2.002: Component inventory (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-03",
		Name:        "Component Inventory",
		Description: "CMMC L2 CM.2.002: Track and maintain component inventory — SBOM and version tracking",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkComponentInventory,
		References:  []string{"CMMC L2 CM.2.002", "NIST SP 800-171 §3.4.6"},
	})

	// CM.2.003: Configuration restrictions (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-04",
		Name:        "Configuration Restrictions",
		Description: "CMMC L2 CM.2.003: Define and enforce configuration restrictions. AegisGate generates the configuration restriction evidence for the customer's CMMC assessment.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCMConfigRestrictions,
		References:  []string{"CMMC L2 CM.2.003", "NIST SP 800-171 §3.4.7"},
	})

	// CM.2.004: Secure configuration (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-05",
		Name:        "Secure Configuration",
		Description: "CMMC L2 CM.2.004: Implement secure configuration settings. AegisGate generates the secure configuration evidence for the customer's CMMC assessment.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCMSecureConfig,
		References:  []string{"CMMC L2 CM.2.004", "NIST SP 800-171 §3.4.8"},
	})

	// CM.2.005: Software restrictions (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-06",
		Name:        "Software Restrictions",
		Description: "CMMC L2 CM.2.005: Restrict software installation to authorized software with allowlisting",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSoftwareRestrictions,
		References:  []string{"CMMC L2 CM.2.005", "NIST SP 800-171 §3.4.9"},
	})

	// CM.2.006: Configuration change log (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-07",
		Name:        "Configuration Change Log",
		Description: "CMMC L2 CM.2.006: Maintain configuration change log with version control",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkConfigurationChangeLog,
		References:  []string{"CMMC L2 CM.2.006", "NIST SP 800-171 §3.4.10"},
	})

	// CM.2.007: Security impact analysis (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-08",
		Name:        "Security Impact Analysis",
		Description: "CMMC L2 CM.2.007: Analyze security impact of configuration changes. AegisGate generates the impact analysis evidence for the customer's CMMC assessment.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 CM.2.007", "NIST SP 800-171 §3.4.11"},
	})

	// CM.2.008: Baseline configuration enforcement (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-09",
		Name:        "Baseline Configuration Enforcement",
		Description: "CMMC L2 CM.2.008: Enforce baseline configuration settings with drift detection",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBaselineEnforcement,
		References:  []string{"CMMC L2 CM.2.008", "NIST SP 800-171 §3.4.12"},
	})

	// CM.2.009: Configuration settings documentation (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-CM-10",
		Name:        "Configuration Settings Documentation",
		Description: "CMMC L2 CM.2.009: Document and maintain configuration settings documentation. AegisGate generates the configuration documentation evidence for the customer's CMMC assessment.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkCMConfigDocs,
		References:  []string{"CMMC L2 CM.2.009", "NIST SP 800-171 §3.4.13"},
	})
}

// --- CA CheckFuncs ---

// checkSecurityAssessment verifies security controls are periodically
// assessed. Maps to CMMC L2 CA.1.001.
func (m *CMMCL2Module) checkSecurityAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCompliance := strings.Contains(inputStr, "compliance") || strings.Contains(inputStr, "scanner")
	hasVulnAssessment := strings.Contains(inputStr, "vulnerability") || strings.Contains(inputStr, "threat")
	hasAuditLog := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled")

	if hasCompliance && (hasVulnAssessment || hasAuditLog) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-CA-01",
			ControlName: "Security Assessment",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Security assessment controls verified (compliance scanning + vulnerability assessment)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasCompliance {
		violations = append(violations, "compliance scanning not configured")
	}
	if !hasVulnAssessment && !hasAuditLog {
		violations = append(violations, "no vulnerability assessment or audit logging detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-CA-01",
		ControlName: "Security Assessment",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Security assessment gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable compliance scanning (compliance.enabled=true) and vulnerability assessment or audit logging",
	}, nil
}

// checkPlanOfAction verifies remediation tracking is in place.
// Maps to CMMC L2 CA.2.001.
func (m *CMMCL2Module) checkPlanOfAction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRemediation := strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "poam")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "milestones")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "review")

	if hasRemediation && (hasTracking || hasAudit) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-CA-02",
			ControlName: "Plan Of Action",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Plan of action tracking verified (remediation + tracking/audit)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRemediation {
		violations = append(violations, "remediation tracking not configured")
	}
	if !hasTracking && !hasAudit {
		violations = append(violations, "no milestone tracking or audit review detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-CA-02",
		ControlName: "Plan Of Action",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Plan of action gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable remediation tracking (poam.enabled=true) and milestone/audit review",
	}, nil
}

// checkContinuousMonitoring verifies ongoing security control monitoring.
// Maps to CMMC L2 CA.2.002.
func (m *CMMCL2Module) checkContinuousMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCCM := strings.Contains(inputStr, "ccm") || strings.Contains(inputStr, "continuous_monitoring")
	hasScan := strings.Contains(inputStr, "scan") || strings.Contains(inputStr, "scanner")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "drift")

	if (hasCCM || hasMonitoring) && hasScan {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-CA-03",
			ControlName: "Continuous Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Continuous monitoring verified (CCM/monitoring + scanning)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasCCM && !hasMonitoring {
		violations = append(violations, "continuous monitoring not configured")
	}
	if !hasScan {
		violations = append(violations, "security scanning not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-CA-03",
		ControlName: "Continuous Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Continuous monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable continuous compliance monitoring (ccm.enabled=true) and security scanning",
	}, nil
}

// --- CM CheckFuncs ---

// checkChangeControl verifies change management controls are in place.
// Maps to CMMC L2 CM.2.001.
func (m *CMMCL2Module) checkChangeControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasChangeLog := strings.Contains(inputStr, "change_log") || strings.Contains(inputStr, "audit_log")
	hasReview := strings.Contains(inputStr, "review") || strings.Contains(inputStr, "approval")
	hasVersion := strings.Contains(inputStr, "version") || strings.Contains(inputStr, "config_version")

	if hasChangeLog && (hasReview || hasVersion) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-CM-02",
			ControlName: "Change Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Change control verified (audit log + review/version tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasChangeLog {
		violations = append(violations, "change log not configured")
	}
	if !hasReview && !hasVersion {
		violations = append(violations, "no change review or version tracking detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-CM-02",
		ControlName: "Change Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Change control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable change logging (change_log=true) and configure review/approval workflows",
	}, nil
}

// checkComponentInventory verifies SBOM and dependency tracking.
// Maps to CMMC L2 CM.2.002.
func (m *CMMCL2Module) checkComponentInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx")
	hasDeps := strings.Contains(inputStr, "dependencies") || strings.Contains(inputStr, "dependency")
	hasVersion := strings.Contains(inputStr, "version")

	if hasSBOM && hasDeps {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-CM-03",
			ControlName: "Component Inventory",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Component inventory verified (SBOM + dependency tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSBOM {
		violations = append(violations, "SBOM not configured")
	}
	if !hasDeps {
		violations = append(violations, "dependency tracking not configured")
	}
	if !hasVersion {
		violations = append(violations, "version tracking not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-CM-03",
		ControlName: "Component Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Component inventory gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable SBOM generation (sbom.enabled=true) and dependency tracking. Ensure all components have version metadata.",
	}, nil
}

// checkSoftwareRestrictions verifies software installation restrictions.
// Maps to CMMC L2 CM.2.005.
func (m *CMMCL2Module) checkSoftwareRestrictions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAllowlist := strings.Contains(inputStr, "allowlist") || strings.Contains(inputStr, "whitelist") || strings.Contains(inputStr, "authorized_software")
	hasRestriction := strings.Contains(inputStr, "software_restriction") || strings.Contains(inputStr, "installation_policy") || strings.Contains(inputStr, "app_control")

	if hasAllowlist && hasRestriction {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-CM-06",
			ControlName: "Software Restrictions",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Software restrictions verified (allowlisting + installation policy)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAllowlist {
		violations = append(violations, "software allowlisting not configured")
	}
	if !hasRestriction {
		violations = append(violations, "software installation restrictions not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-CM-06",
		ControlName: "Software Restrictions",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Software restrictions gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure software allowlisting (allowlist=true) and installation policy (software_restriction=true)",
	}, nil
}

// checkConfigurationChangeLog verifies configuration change logging and
// version control. Maps to CMMC L2 CM.2.006.
func (m *CMMCL2Module) checkConfigurationChangeLog(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasChangeLog := strings.Contains(inputStr, "change_log") || strings.Contains(inputStr, "config_version") || strings.Contains(inputStr, "version_control")
	hasApproval := strings.Contains(inputStr, "approval") || strings.Contains(inputStr, "change_approval") || strings.Contains(inputStr, "review")

	if hasChangeLog && hasApproval {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-CM-07",
			ControlName: "Configuration Change Log",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Configuration change log verified (change logging + approval process)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasChangeLog {
		violations = append(violations, "configuration change log not configured")
	}
	if !hasApproval {
		violations = append(violations, "change approval process not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-CM-07",
		ControlName: "Configuration Change Log",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Configuration change log gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable configuration change logging (change_log=true, version_control=true) and change approval process",
	}, nil
}

// checkBaselineEnforcement verifies baseline configuration enforcement
// with drift detection. Maps to CMMC L2 CM.2.008.
func (m *CMMCL2Module) checkBaselineEnforcement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBaseline := strings.Contains(inputStr, "baseline") || strings.Contains(inputStr, "config_baseline") || strings.Contains(inputStr, "golden_image")
	hasDrift := strings.Contains(inputStr, "drift") || strings.Contains(inputStr, "drift_detection") || strings.Contains(inputStr, "configuration_monitoring")

	if hasBaseline && hasDrift {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-CM-09",
			ControlName: "Baseline Configuration Enforcement",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Baseline configuration enforcement verified (baseline + drift detection)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasBaseline {
		violations = append(violations, "configuration baseline not defined")
	}
	if !hasDrift {
		violations = append(violations, "configuration drift detection not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-CM-09",
		ControlName: "Baseline Configuration Enforcement",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Baseline enforcement gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Define configuration baseline (config_baseline=true) and enable drift detection (drift_detection=true)",
	}, nil
}

// checkCMBaselineConfig verifies baseline configuration. Maps to CMMCL2-CM-01.
func (m *CMMCL2Module) checkCMBaselineConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBaseline := strings.Contains(inputStr, "baseline_configuration") || strings.Contains(inputStr, "config_baseline") || strings.Contains(inputStr, "baseline")
	hasDrift := strings.Contains(inputStr, "drift_detection") || strings.Contains(inputStr, "change_detection") || strings.Contains(inputStr, "change_tracking")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging_enabled") || strings.Contains(inputStr, "siem")
	if hasBaseline && hasDrift && hasAudit {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-CM-01", ControlName: "Baseline Configuration", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Baseline configuration verified (baseline + drift + audit)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasBaseline {
		violations = append(violations, "baseline configuration not configured")
	}
	if !hasDrift {
		violations = append(violations, "drift detection not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-CM-01", ControlName: "Baseline Configuration", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Baseline config gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure baseline with drift detection and audit logging"}, nil
}

// checkCMConfigRestrictions verifies configuration restrictions. Maps to CMMCL2-CM-04.
func (m *CMMCL2Module) checkCMConfigRestrictions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRestrictions := strings.Contains(inputStr, "config_restrictions") || strings.Contains(inputStr, "configuration_limits") || strings.Contains(inputStr, "security_config")
	hasEnforcement := strings.Contains(inputStr, "enforcement") || strings.Contains(inputStr, "enforced") || strings.Contains(inputStr, "settings_enforced")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging_enabled") || strings.Contains(inputStr, "siem")
	if hasRestrictions && hasEnforcement && hasAudit {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-CM-04", ControlName: "Configuration Restrictions", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Configuration restrictions verified (restrictions + enforcement + audit)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasRestrictions {
		violations = append(violations, "configuration restrictions not configured")
	}
	if !hasEnforcement {
		violations = append(violations, "enforcement not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-CM-04", ControlName: "Configuration Restrictions", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Configuration restrictions gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure security restrictions with enforcement and audit"}, nil
}

// checkCMSecureConfig verifies secure configuration. Maps to CMMCL2-CM-05.
func (m *CMMCL2Module) checkCMSecureConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecure := strings.Contains(inputStr, "secure_configuration") || strings.Contains(inputStr, "security_hardening") || strings.Contains(inputStr, "cis_benchmark")
	hasBaseline := strings.Contains(inputStr, "baseline") || strings.Contains(inputStr, "hardening") || strings.Contains(inputStr, "secure_baseline")
	hasEnforcement := strings.Contains(inputStr, "enforcement") || strings.Contains(inputStr, "enforced") || strings.Contains(inputStr, "enforced")
	if hasSecure && hasBaseline && hasEnforcement {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-CM-05", ControlName: "Secure Configuration", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Secure configuration verified (secure + baseline + enforcement)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasSecure {
		violations = append(violations, "secure configuration not configured")
	}
	if !hasBaseline {
		violations = append(violations, "baseline hardening not configured")
	}
	if !hasEnforcement {
		violations = append(violations, "enforcement not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-CM-05", ControlName: "Secure Configuration", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Secure configuration gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure secure baseline with hardening and enforcement"}, nil
}

// checkCMConfigDocs verifies configuration settings documentation. Maps to CMMCL2-CM-10.
func (m *CMMCL2Module) checkCMConfigDocs(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDocs := strings.Contains(inputStr, "configuration_documentation") || strings.Contains(inputStr, "config_documentation") || strings.Contains(inputStr, "settings_documentation")
	hasSettings := strings.Contains(inputStr, "configuration_settings") || strings.Contains(inputStr, "config_settings") || strings.Contains(inputStr, "security_settings")
	hasVersion := strings.Contains(inputStr, "version_control") || strings.Contains(inputStr, "documentation") || strings.Contains(inputStr, "up_to_date")
	if hasDocs && hasSettings && hasVersion {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-CM-10", ControlName: "Configuration Settings Documentation", Status: compliance.StatusCompliant, Severity: compliance.SeverityLow, Message: "Config documentation verified (docs + settings + version control)", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasDocs {
		violations = append(violations, "configuration documentation not configured")
	}
	if !hasSettings {
		violations = append(violations, "configuration settings not configured")
	}
	if !hasVersion {
		violations = append(violations, "version control not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CMMCL2-CM-10", ControlName: "Configuration Settings Documentation", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityLow, Message: "Config documentation gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Configure documentation with settings and version control"}, nil
}
