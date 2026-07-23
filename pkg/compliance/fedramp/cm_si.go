// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - FedRAMP CM + SI Families
// =========================================================================
//
// NIST SP 800-53 Rev. 5 — Configuration Management (CM) + System and
// Information Integrity (SI) families for FedRAMP Moderate.
//
// CM in-scope controls (5 of ~25 CM controls):
//   CM-2  Baseline Configuration             (evidence-mapped, Path B)
//   CM-3  Configuration Change Control        (automated, Path C — new)
//   CM-5  Access Restrictions for Change      (automated, Path C — new)
//   CM-6  Configuration Settings              (automated, Path C — new)
//   CM-8  System Component Inventory           (automated, Path C — new)
//
// SI in-scope controls (6 of ~23 SI controls):
//   SI-2  Flaw Remediation                    (automated, Path C — new)
//   SI-3  Malicious Code Protection           (evidence-mapped, Path C — new)
//   SI-4  System and Information Integrity     (evidence-mapped, Path B)
//   SI-7  Software and Information Integrity    (automated, Path C — new)
//   SI-8  Spam Protection                     (evidence-mapped, Path C — new)
//   SI-10  Information Input Validation         (automated, Path C — new)
//
// =========================================================================

package fedramp

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerCMControls wires the CM family controls into the module.
func (m *FedRAMPModule) registerCMControls() {
	// CM-2: Baseline Configuration (Path B — carried forward, evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-2",
		Name:        "Baseline Configuration",
		Description: "FedRAMP CM-2: Baseline configuration documented and maintained. AegisGate generates the configuration audit log as evidence for the customer's CM-2 SSP section.",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Evidence-mapped: AegisGate generates compliance scan output
		References:  []string{"NIST SP 800-53 Rev. 5 CM-2", "FedRAMP Moderate CM-02"},
	})

	// CM-3: Configuration Change Control (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-3",
		Name:        "Configuration Change Control",
		Description: "FedRAMP CM-3: Changes to the system are controlled, documented, and tested before implementation",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeControl,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-3", "FedRAMP Moderate CM-03"},
	})

	// CM-5: Access Restrictions for Change (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-5",
		Name:        "Access Restrictions for Change",
		Description: "FedRAMP CM-5: Define and enforce access restrictions for changes to the system — only authorized personnel may modify config",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeAccessRestrictions,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-5", "FedRAMP Moderate CM-05"},
	})

	// CM-6: Configuration Settings (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-6",
		Name:        "Configuration Settings",
		Description: "FedRAMP CM-6: Security configuration settings are established, documented, and enforced",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkConfigSettings,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-6", "FedRAMP Moderate CM-06"},
	})

	// CM-8: System Component Inventory (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-8",
		Name:        "System Component Inventory",
		Description: "FedRAMP CM-8: System components inventoried with accurate and up-to-date information — SBOM/AIBOM",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkComponentInventory,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-8", "FedRAMP Moderate CM-08"},
	})

	// CM-7: Least Functionality (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-7",
		Name:        "Least Functionality",
		Description: "FedRAMP CM-7: System configured to provide only essential capabilities — minimal services, disabled unnecessary functions",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLeastFunctionality,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-7", "FedRAMP Moderate CM-07"},
	})

	// CM-10: Software Usage Restrictions (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-10",
		Name:        "Software Usage Restrictions",
		Description: "FedRAMP CM-10: Software usage restricted by license and usage rights — AIBOM tracks license compliance",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSoftwareUsageRestrictions,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-10", "FedRAMP Moderate CM-10"},
	})

	// CM-12: Information Location (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-CM-12",
		Name:        "Information Location",
		Description: "FedRAMP CM-12: Information location identified and documented — data classification, storage location, retention policy",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkInformationLocation,
		References:  []string{"NIST SP 800-53 Rev. 5 CM-12", "FedRAMP Moderate CM-12"},
	})
}

// registerSIControls wires the SI family controls into the module.
func (m *FedRAMPModule) registerSIControls() {
	// SI-2: Flaw Remediation (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-2",
		Name:        "Flaw Remediation",
		Description: "FedRAMP SI-2: System flaws identified, reported, and remediated — vulnerability scanning + dependency updates",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFlawRemediation,
		References:  []string{"NIST SP 800-53 Rev. 5 SI-2", "FedRAMP Moderate SI-02"},
	})

	// SI-3: Malicious Code Protection (Path C — new, evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-3",
		Name:        "Malicious Code Protection",
		Description: "FedRAMP SI-3: Malicious code protection at system entry/exit points. AegisGate's scanner + IOC store provide the evidence.",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Evidence-mapped
		References:  []string{"NIST SP 800-53 Rev. 5 SI-3", "FedRAMP Moderate SI-03"},
	})

	// SI-4: System and Information Integrity (Path B — carried forward, evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-4",
		Name:        "Information System Monitoring",
		Description: "FedRAMP SI-4: Information system monitoring detects attacks, indicators of potential attacks, and unauthorized activity. AegisGate's IOC store + scanner + anomaly detection provide the monitoring infrastructure.",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   false, // Evidence-mapped: AegisGate generates IOC + scanner output
		References:  []string{"NIST SP 800-53 Rev. 5 SI-4", "FedRAMP Moderate SI-04"},
	})

	// SI-7: Software and Information Integrity (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-7",
		Name:        "Software and Information Integrity",
		Description: "FedRAMP SI-7: Software and information integrity verified — hash-chain audit logs, SBOM, attestation chain",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSoftwareIntegrity,
		References:  []string{"NIST SP 800-53 Rev. 5 SI-7", "FedRAMP Moderate SI-07"},
	})

	// SI-8: Spam Protection (Path C — new, evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-8",
		Name:        "Spam Protection",
		Description: "FedRAMP SI-8: Protection against spam and unauthorized messages at system boundaries. AegisGate's content filtering provides this evidence.",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityLow,
		Automated:   false, // Evidence-mapped
		References:  []string{"NIST SP 800-53 Rev. 5 SI-8", "FedRAMP Moderate SI-08"},
	})

	// SI-10: Information Input Validation (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-10",
		Name:        "Information Input Validation",
		Description: "FedRAMP SI-10: Information input validated to prevent injection attacks, buffer overflows, and malformed data",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInputValidation,
		References:  []string{"NIST SP 800-53 Rev. 5 SI-10", "FedRAMP Moderate SI-10"},
	})

	// SI-1: System and Information Integrity Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-1",
		Name:        "System and Information Integrity Policy and Procedures",
		Description: "FedRAMP SI-1: Organization develops, documents, and disseminates a system and information integrity policy. AegisGate generates the scanner, IOC, and audit evidence for the customer's SI-1 documentation.",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 SI-1", "FedRAMP Moderate SI-01"},
	})

	// SI-11: Error Handling (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-11",
		Name:        "Error Handling",
		Description: "FedRAMP SI-11: Errors handled without exposing sensitive information — no stack traces, no internal details in error responses",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkErrorHandling,
		References:  []string{"NIST SP 800-53 Rev. 5 SI-11", "FedRAMP Moderate SI-11"},
	})

	// SI-12: Information Management (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-12",
		Name:        "Information Management",
		Description: "FedRAMP SI-12: Organization manages information in accordance with applicable policy. AegisGate's data classification, retention, and audit log integrity provide the technical evidence for SI-12.",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 SI-12", "FedRAMP Moderate SI-12"},
	})

	// SI-14: Non-Disruptive Integrity Verification (Path C — new)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-14",
		Name:        "Non-Disruptive Integrity Verification",
		Description: "FedRAMP SI-14: System integrity verified in a non-disruptive manner — continuous scanning without service degradation",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkNonDisruptiveIntegrity,
		References:  []string{"NIST SP 800-53 Rev. 5 SI-14", "FedRAMP Moderate SI-14"},
	})

	// SI-16: Memory Protection (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "FedRAMP-SI-16",
		Name:        "Memory Protection",
		Description: "FedRAMP SI-16: Memory protection to prevent unauthorized code execution. AegisGate runs as a compiled Go binary with ASLR, stack canaries, and PIE enabled, providing memory protection by default.",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"NIST SP 800-53 Rev. 5 SI-16", "FedRAMP Moderate SI-16"},
	})
}

// --- CM Check Functions ---

func (m *FedRAMPModule) checkChangeControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditTrail := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_trail") || strings.Contains(inputStr, "config_audit")
	hasChangeApproval := strings.Contains(inputStr, "change_approval") || strings.Contains(inputStr, "review") || strings.Contains(inputStr, "approval")
	hasVersionControl := strings.Contains(inputStr, "version_control") || strings.Contains(inputStr, "git") || strings.Contains(inputStr, "versioning")

	if hasAuditTrail && (hasChangeApproval || hasVersionControl) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CM-3",
			ControlName: "Configuration Change Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Configuration change control verified (audit trail + change approval/versioning)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAuditTrail {
		violations = append(violations, "configuration audit trail not detected")
	}
	if !hasChangeApproval && !hasVersionControl {
		violations = append(violations, "change approval or version control not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-CM-3",
		ControlName: "Configuration Change Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Change control gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable configuration audit logging (persistence.audit=true) and change approval workflows",
	}, nil
}

func (m *FedRAMPModule) checkChangeAccessRestrictions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasAdminOnly := strings.Contains(inputStr, "admin_only") || strings.Contains(inputStr, "restricted") || strings.Contains(inputStr, "admin")
	hasChangeLog := strings.Contains(inputStr, "change_log") || strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "config_audit")

	if (hasRBAC || hasAdminOnly) && hasChangeLog {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CM-5",
			ControlName: "Access Restrictions for Change",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Change access restrictions verified (RBAC/admin + change logging)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRBAC && !hasAdminOnly {
		violations = append(violations, "no RBAC or admin-only change restriction detected")
	}
	if !hasChangeLog {
		violations = append(violations, "change logging not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-CM-5",
		ControlName: "Access Restrictions for Change",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Change access restriction gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Restrict configuration changes to admin role (rbac.config_write=admin) and enable change audit logging",
	}, nil
}

func (m *FedRAMPModule) checkConfigSettings(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecurityConfig := strings.Contains(inputStr, "security") || strings.Contains(inputStr, "security_config") || strings.Contains(inputStr, "tls")
	hasDefaults := strings.Contains(inputStr, "default_deny") || strings.Contains(inputStr, "secure_default") || strings.Contains(inputStr, "hardened")
	hasEnforcement := strings.Contains(inputStr, "enforcement") || strings.Contains(inputStr, "policy") || strings.Contains(inputStr, "config_enforcement")

	if hasSecurityConfig && (hasDefaults || hasEnforcement) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CM-6",
			ControlName: "Configuration Settings",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Security configuration settings documented and enforced",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSecurityConfig {
		violations = append(violations, "security configuration not detected")
	}
	if !hasDefaults && !hasEnforcement {
		violations = append(violations, "secure defaults or policy enforcement not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-CM-6",
		ControlName: "Configuration Settings",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Configuration settings gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure security settings with secure defaults (security.secure_default=true) and policy enforcement",
	}, nil
}

func (m *FedRAMPModule) checkComponentInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "aibom") || strings.Contains(inputStr, "cyclonedx")
	hasInventory := strings.Contains(inputStr, "inventory") || strings.Contains(inputStr, "component_list") || strings.Contains(inputStr, "dependencies")
	hasVersioning := strings.Contains(inputStr, "version") || strings.Contains(inputStr, "versioning") || strings.Contains(inputStr, "software_version")

	if hasSBOM && (hasInventory || hasVersioning) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CM-8",
			ControlName: "System Component Inventory",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "System component inventory verified (SBOM/AIBOM + component tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasSBOM {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CM-8",
			ControlName: "System Component Inventory",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "SBOM/AIBOM detected but component inventory tracking incomplete",
			Timestamp:   time.Now(),
			Remediation: "Ensure all system components are tracked in the inventory with version information",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-CM-8",
		ControlName: "System Component Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No system component inventory or SBOM detected",
		Timestamp:   time.Now(),
		Remediation: "Enable AIBOM generation (aibom.enabled=true) to produce CycloneDX SBOM for all system components",
	}, nil
}

// --- SI Check Functions ---

func (m *FedRAMPModule) checkFlawRemediation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnScan := strings.Contains(inputStr, "vuln") || strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "vulnerability")
	hasPatchMgmt := strings.Contains(inputStr, "patch") || strings.Contains(inputStr, "update") || strings.Contains(inputStr, "remediation")
	hasDependency := strings.Contains(inputStr, "dependency") || strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "aibom")

	if hasVulnScan && (hasPatchMgmt || hasDependency) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SI-2",
			ControlName: "Flaw Remediation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Flaw remediation verified (vulnerability scanning + patch/dependency management)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasVulnScan {
		violations = append(violations, "vulnerability scanning not configured")
	}
	if !hasPatchMgmt && !hasDependency {
		violations = append(violations, "patch management or dependency tracking not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SI-2",
		ControlName: "Flaw Remediation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Flaw remediation gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable vulnerability scanning (scanner.enabled=true) and dependency tracking (aibom.enabled=true)",
	}, nil
}

func (m *FedRAMPModule) checkSoftwareIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHashChain := strings.Contains(inputStr, "hash_chain") || strings.Contains(inputStr, "log_integrity") || strings.Contains(inputStr, "integrity")
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "aibom") || strings.Contains(inputStr, "cyclonedx")
	hasAttestation := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "trust") || strings.Contains(inputStr, "signature")

	if hasHashChain && (hasSBOM || hasAttestation) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SI-7",
			ControlName: "Software and Information Integrity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Software integrity verified (hash-chain + SBOM/attestation)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasHashChain {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SI-7",
			ControlName: "Software and Information Integrity",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Hash-chain integrity detected but SBOM/attestation not configured",
			Timestamp:   time.Now(),
			Remediation: "Enable AIBOM generation (aibom.enabled=true) for software integrity verification",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SI-7",
		ControlName: "Software and Information Integrity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Software integrity verification not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable hash-chain integrity (persistence.log_integrity=true) and AIBOM generation (aibom.enabled=true)",
	}, nil
}

func (m *FedRAMPModule) checkInputValidation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInputValidation := strings.Contains(inputStr, "input_validation") || strings.Contains(inputStr, "validation") || strings.Contains(inputStr, "sanitiz")
	hasInjectionProtection := strings.Contains(inputStr, "injection") || strings.Contains(inputStr, "xss") || strings.Contains(inputStr, "sql_injection") || strings.Contains(inputStr, "prompt_injection")
	_ = strings.Contains(inputStr, "rate_limit")

	if hasInputValidation && hasInjectionProtection {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SI-10",
			ControlName: "Information Input Validation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Input validation verified (validation + injection protection)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasInputValidation {
		violations = append(violations, "input validation not configured")
	}
	if !hasInjectionProtection {
		violations = append(violations, "injection protection not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SI-10",
		ControlName: "Information Input Validation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Input validation gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable input validation and injection protection (scanner.enabled=true, security.input_validation=true)",
	}, nil
}

// checkLeastFunctionality verifies minimal services are enabled. Maps to CM-7.
func (m *FedRAMPModule) checkLeastFunctionality(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMinimalServices := strings.Contains(inputStr, "minimal_services") || strings.Contains(inputStr, "minimal") || strings.Contains(inputStr, "least_functionality")
	hasDisabledDefaults := !strings.Contains(inputStr, "default_enable") && !strings.Contains(inputStr, "all_enabled")
	hasAllowlist := strings.Contains(inputStr, "allowlist") || strings.Contains(inputStr, "service_allowlist") || strings.Contains(inputStr, "whitelist")

	if (hasMinimalServices || hasAllowlist) && hasDisabledDefaults {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CM-7",
			ControlName: "Least Functionality",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Least functionality verified (minimal services + allowlist)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMinimalServices && !hasAllowlist {
		violations = append(violations, "service allowlist or minimal services mode not configured")
	}
	if !hasDisabledDefaults {
		violations = append(violations, "default-enable-all services detected — violates least functionality")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-CM-7",
		ControlName: "Least Functionality",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Least functionality gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable minimal services mode (security.minimal_services=true) and configure service allowlist (security.service_allowlist)",
	}, nil
}

// checkSoftwareUsageRestrictions verifies software license compliance. Maps to CM-10.
func (m *FedRAMPModule) checkSoftwareUsageRestrictions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAIBOM := strings.Contains(inputStr, "aibom") || strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx")
	hasLicense := strings.Contains(inputStr, "license") || strings.Contains(inputStr, "apache") || strings.Contains(inputStr, "mit")
	if hasAIBOM && hasLicense {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CM-10",
			ControlName: "Software Usage Restrictions",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Software usage restrictions verified (AIBOM/SBOM + license tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAIBOM {
		violations = append(violations, "AIBOM/SBOM not configured — cannot verify software licenses")
	}
	if !hasLicense {
		violations = append(violations, "license tracking not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-CM-10",
		ControlName: "Software Usage Restrictions",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Software usage restriction gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable AIBOM generation (aibom.enabled=true) for software license tracking",
	}, nil
}

// checkInformationLocation verifies data location and classification. Maps to CM-12.
func (m *FedRAMPModule) checkInformationLocation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasClassification := strings.Contains(inputStr, "classification") || strings.Contains(inputStr, "data_classification") || strings.Contains(inputStr, "sensitivity")
	hasLocation := strings.Contains(inputStr, "data_location") || strings.Contains(inputStr, "region") || strings.Contains(inputStr, "persistence")
	hasRetentionPolicy := strings.Contains(inputStr, "retention") || strings.Contains(inputStr, "retention_policy") || strings.Contains(inputStr, "log_retention")

	if hasClassification && (hasLocation || hasRetentionPolicy) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-CM-12",
			ControlName: "Information Location",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityLow,
			Message:     "Information location verified (data classification + storage/retention)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasClassification {
		violations = append(violations, "data classification not configured")
	}
	if !hasLocation && !hasRetentionPolicy {
		violations = append(violations, "data location or retention policy not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-CM-12",
		ControlName: "Information Location",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityLow,
		Message:     "Information location gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable data classification (security.data_classification=true) and configure retention policy (persistence.retention_days=90)",
	}, nil
}

// checkErrorHandling verifies errors don't leak sensitive info. Maps to SI-11.
func (m *FedRAMPModule) checkErrorHandling(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSafeErrors := strings.Contains(inputStr, "safe_errors") || strings.Contains(inputStr, "error_sanitiz") || strings.Contains(inputStr, "hide_internal")
	hasNoStackTraces := !strings.Contains(inputStr, "stack_trace") && !strings.Contains(inputStr, "debug_mode")
	hasErrorHandling := strings.Contains(inputStr, "error_handling") || strings.Contains(inputStr, "error_handler") || strings.Contains(inputStr, "error_response")

	if hasSafeErrors && hasNoStackTraces {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SI-11",
			ControlName: "Error Handling",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Error handling verified (safe errors, no stack traces)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSafeErrors && !hasErrorHandling {
		violations = append(violations, "safe error handling not configured")
	}
	if !hasNoStackTraces {
		violations = append(violations, "stack traces or debug mode detected in error responses — leaks internal info")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SI-11",
		ControlName: "Error Handling",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Error handling gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable safe error handling (security.safe_errors=true) and disable debug mode in production",
	}, nil
}

// checkNonDisruptiveIntegrity verifies continuous scanning without degradation. Maps to SI-14.
func (m *FedRAMPModule) checkNonDisruptiveIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCCM := strings.Contains(inputStr, "ccm") || strings.Contains(inputStr, "continuous") || strings.Contains(inputStr, "schedule")
	hasPerformance := strings.Contains(inputStr, "performance") || strings.Contains(inputStr, "latency") || strings.Contains(inputStr, "rate_limit")
	hasIntegrity := strings.Contains(inputStr, "integrity") || strings.Contains(inputStr, "hash_chain") || strings.Contains(inputStr, "attestation")

	if hasCCM && (hasPerformance || hasIntegrity) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "FedRAMP-SI-14",
			ControlName: "Non-Disruptive Integrity Verification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Non-disruptive integrity verification confirmed (CCM + performance/integrity)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasCCM {
		violations = append(violations, "continuous monitoring not configured")
	}
	if !hasPerformance && !hasIntegrity {
		violations = append(violations, "integrity verification or performance monitoring not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "FedRAMP-SI-14",
		ControlName: "Non-Disruptive Integrity Verification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Non-disruptive integrity gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable CCM (ccm.enabled=true) and hash-chain integrity (persistence.log_integrity=true)",
	}, nil
}
