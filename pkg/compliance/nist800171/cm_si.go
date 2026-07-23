// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - NIST 800-171 CM/SI (Configuration Management
// + System and Information Integrity) Family
// =========================================================================
//
// NIST SP 800-171 Rev. 2 — Configuration Management (CM) and System and
// Information Integrity (SI) families for protecting CUI.
//
// In-scope CM+SI controls (6 controls: 5 automated + 1 evidence-mapped):
//   CM-2  Baseline Configuration                (automated)
//   CM-3  Configuration Change Control            (evidence-mapped)
//   CM-5  Access Restrictions for Change          (automated)
//   CM-6  Configuration Settings                  (automated)
//   SI-2  Flaw Remediation                        (automated)
//   SI-3  Malicious Code Protection               (automated)
//
// =========================================================================

package nist800171

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerCMSIControls wires the CM and SI family controls into the module.
func (m *NIST800171Module) registerCMSIControls() {
	// CM-2: Baseline Configuration (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CM-2",
		Name:        "Baseline Configuration",
		Description: "NIST 800-171 CM-2 (3.4.1): Baseline configuration established and documented for system components",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkBaselineConfig,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.4.1", "NIST SP 800-53 Rev. 5 CM-2"},
	})

	// CM-3: Configuration Change Control (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CM-3",
		Name:        "Configuration Change Control",
		Description: "NIST 800-171 CM-3 (3.4.2): Configuration change control — proposed changes reviewed, approved, and documented before implementation",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.4.2", "NIST SP 800-53 Rev. 5 CM-3"},
	})

	// CM-5: Access Restrictions for Change (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CM-5",
		Name:        "Access Restrictions for Change",
		Description: "NIST 800-171 CM-5 (3.4.4): Access restrictions for change — define and enforce authorized changes with audit trail",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAccessRestrictionsForChange,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.4.4", "NIST SP 800-53 Rev. 5 CM-5"},
	})

	// CM-6: Configuration Settings (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-CM-6",
		Name:        "Configuration Settings",
		Description: "NIST 800-171 CM-6 (3.4.5): Configuration settings enforced with secure defaults — no permissive defaults in production",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkConfigSettings,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.4.5", "NIST SP 800-53 Rev. 5 CM-6"},
	})

	// SI-2: Flaw Remediation (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SI-2",
		Name:        "Flaw Remediation",
		Description: "NIST 800-171 SI-2 (3.14.1): Flaw remediation — identify, report, and correct system flaws with vulnerability scanning and patch management",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFlawRemediation,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.14.1", "NIST SP 800-53 Rev. 5 SI-2"},
	})

	// SI-3: Malicious Code Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "NIST800171-SI-3",
		Name:        "Malicious Code Protection",
		Description: "NIST 800-171 SI-3 (3.14.2): Malicious code protection — detect and destroy malicious code, scan at entry/exit points",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMaliciousCodeProtection,
		References:  []string{"NIST SP 800-171 Rev. 2 §3.14.2", "NIST SP 800-53 Rev. 5 SI-3"},
	})
}

// checkBaselineConfig verifies that baseline configurations are established
// and documented for system components. Maps to CM-2.
func (m *NIST800171Module) checkBaselineConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx")
	hasVersion := strings.Contains(inputStr, "version") || strings.Contains(inputStr, "baseline")
	hasDependencies := strings.Contains(inputStr, "dependencies") || strings.Contains(inputStr, "packages")

	if hasSBOM && hasVersion && hasDependencies {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CM-2",
			ControlName: "Baseline Configuration",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Baseline configuration verified (SBOM, version tracking, dependency inventory)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasSBOM || hasVersion {
		missing := []string{}
		if !hasSBOM {
			missing = append(missing, "SBOM not configured")
		}
		if !hasVersion {
			missing = append(missing, "version tracking not detected")
		}
		if !hasDependencies {
			missing = append(missing, "dependency inventory not configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CM-2",
			ControlName: "Baseline Configuration",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Baseline configuration partial: " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Enable SBOM generation (sbom.enabled=true) and dependency scanning for all system components",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-CM-2",
		ControlName: "Baseline Configuration",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No baseline configuration detected (missing SBOM, version tracking, and dependency inventory)",
		Timestamp:   time.Now(),
		Remediation: "Enable SBOM generation, version tracking, and dependency scanning for all system components",
	}, nil
}

// checkAccessRestrictionsForChange verifies that access restrictions for
// changes are defined and enforced with an audit trail. Maps to CM-5.
func (m *NIST800171Module) checkAccessRestrictionsForChange(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasAudit := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled") || strings.Contains(inputStr, "logging_enabled")
	hasChangeControl := strings.Contains(inputStr, "change_control") || strings.Contains(inputStr, "review") || strings.Contains(inputStr, "approval")

	if hasRBAC && hasAudit && hasChangeControl {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CM-5",
			ControlName: "Access Restrictions for Change",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Access restrictions for change verified (RBAC + audit trail + change control)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRBAC {
		violations = append(violations, "RBAC not configured for change access")
	}
	if !hasAudit {
		violations = append(violations, "audit trail not configured for changes")
	}
	if !hasChangeControl {
		violations = append(violations, "change control process not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-CM-5",
		ControlName: "Access Restrictions for Change",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Change access restriction gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable RBAC for change access, audit trail for all changes, and formal change control process",
	}, nil
}

// checkConfigSettings verifies configuration settings are enforced with
// secure defaults. Maps to CM-6.
func (m *NIST800171Module) checkConfigSettings(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecureDefaults := strings.Contains(inputStr, "secure_default") || strings.Contains(inputStr, "secure_defaults")
	hasConfigAudit := strings.Contains(inputStr, "config_audit") || strings.Contains(inputStr, "configuration")
	hasEnforcement := strings.Contains(inputStr, "policy_enforcement") || strings.Contains(inputStr, "hardening")

	if hasSecureDefaults && (hasConfigAudit || hasEnforcement) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-CM-6",
			ControlName: "Configuration Settings",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Configuration settings verified (secure defaults + configuration audit/enforcement)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSecureDefaults {
		violations = append(violations, "secure defaults not configured")
	}
	if !hasConfigAudit && !hasEnforcement {
		violations = append(violations, "configuration audit or enforcement not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-CM-6",
		ControlName: "Configuration Settings",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Configuration settings gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable secure defaults (security.secure_defaults=true) and configuration audit/enforcement",
	}, nil
}

// checkFlawRemediation verifies vulnerability scanning and patch
// management are in place. Maps to SI-2.
func (m *NIST800171Module) checkFlawRemediation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasScanner := strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "vulnerability") || strings.Contains(inputStr, "scan")
	hasPatch := strings.Contains(inputStr, "patch") || strings.Contains(inputStr, "remediation")
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "aibom") || strings.Contains(inputStr, "cyclonedx")

	if hasScanner && (hasPatch || hasSBOM) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SI-2",
			ControlName: "Flaw Remediation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Flaw remediation verified (vulnerability scanning + patch management)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasScanner {
		violations = append(violations, "vulnerability scanner not configured")
	}
	if !hasPatch && !hasSBOM {
		violations = append(violations, "patch management or SBOM not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SI-2",
		ControlName: "Flaw Remediation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Flaw remediation gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable vulnerability scanning (scanner.enabled=true) and patch management or SBOM tracking",
	}, nil
}

// checkMaliciousCodeProtection verifies malicious code detection and
// destruction mechanisms are in place. Maps to SI-3.
func (m *NIST800171Module) checkMaliciousCodeProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMalwareScan := strings.Contains(inputStr, "malware_scan") || strings.Contains(inputStr, "antivirus") || strings.Contains(inputStr, "scanner")
	hasIOC := strings.Contains(inputStr, "ioc") || strings.Contains(inputStr, "indicators") || strings.Contains(inputStr, "threat_intel")
	hasPromptInjection := strings.Contains(inputStr, "prompt_injection") || strings.Contains(inputStr, "input_validation") || strings.Contains(inputStr, "sanitization")

	if hasMalwareScan && (hasIOC || hasPromptInjection) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "NIST800171-SI-3",
			ControlName: "Malicious Code Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Malicious code protection verified (scanning + IOC/prompt injection detection)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMalwareScan {
		violations = append(violations, "malware scanning not configured")
	}
	if !hasIOC && !hasPromptInjection {
		violations = append(violations, "IOC or prompt injection detection not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "NIST800171-SI-3",
		ControlName: "Malicious Code Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Malicious code protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable malware scanning (scanner.enabled=true) and IOC/prompt injection detection for AI workloads",
	}, nil
}
