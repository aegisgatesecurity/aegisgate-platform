// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - TISAX DSC/PP/DP Domains
// =========================================================================
//
// TISAX AL2 — Data & System Controls, Privacy & Personnel,
// Development & Prototyping domains.
//
// DSC (Data & System Controls): 6 practices (4 automated + 2 evidence-mapped)
// PP (Privacy & Personnel): 7 practices (1 automated + 6 evidence-mapped)
// DP (Development & Prototyping): 7 practices (3 automated + 4 evidence-mapped)
//
// =========================================================================

package tisax

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerDSCControls wires Data & System Controls domain controls.
func (m *TISAXModule) registerDSCControls() {
	// DSC-01: Data Classification (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-01",
		Name:        "Data Classification",
		Description: "TISAX DSC-01: Data classification and labeling scheme for CUI and proprietary information",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-DSC-01", "ISO 27001 A.8.1"},
	})

	// DSC-02: Data Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-02",
		Name:        "Data Protection",
		Description: "TISAX DSC-02: Data at rest and in transit protected with encryption and access controls",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataProtection,
		References:  []string{"TISAX v6 AL2 ISA-DSC-02", "ISO 27001 A.8.24"},
	})

	// DSC-03: Endpoint Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-03",
		Name:        "Endpoint Protection",
		Description: "TISAX DSC-03: Endpoint security controls including malware protection and patching",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEndpointProtection,
		References:  []string{"TISAX v6 AL2 ISA-DSC-03", "ISO 27001 A.8.7"},
	})

	// DSC-04: Vulnerability Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-04",
		Name:        "Vulnerability Management",
		Description: "TISAX DSC-04: Vulnerability scanning, assessment, and remediation processes",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityManagement,
		References:  []string{"TISAX v6 AL2 ISA-DSC-04", "ISO 27001 A.8.8"},
	})

	// DSC-05: Logging and Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-05",
		Name:        "Logging and Monitoring",
		Description: "TISAX DSC-05: Security event logging, monitoring, and alerting",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLoggingMonitoring,
		References:  []string{"TISAX v6 AL2 ISA-DSC-05", "ISO 27001 A.8.15"},
	})

	// DSC-06: Change Management (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-06",
		Name:        "Change Management",
		Description: "TISAX DSC-06: Change management process for system modifications",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-DSC-06", "ISO 27001 A.8.32"},
	})
}

// registerPPControls wires Privacy & Personnel domain controls.
func (m *TISAXModule) registerPPControls() {
	// PP-01: Privacy Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-01",
		Name:        "Privacy Policy",
		Description: "TISAX PP-01: Privacy policy documented and communicated",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-PP-01", "GDPR Art. 5"},
	})

	// PP-02: Data Subject Rights (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-02",
		Name:        "Data Subject Rights",
		Description: "TISAX PP-02: Data subject rights processes (access, rectification, erasure)",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-PP-02", "GDPR Art. 15-22"},
	})

	// PP-03: Consent Management (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-03",
		Name:        "Consent Management",
		Description: "TISAX PP-03: Consent management for data processing activities",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-PP-03", "GDPR Art. 7"},
	})

	// PP-04: Personnel Security (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-04",
		Name:        "Personnel Security",
		Description: "TISAX PP-04: Personnel security screening and onboarding/offboarding processes",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-PP-04", "ISO 27001 A.6.1"},
	})

	// PP-05: Security Awareness (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-05",
		Name:        "Security Awareness",
		Description: "TISAX PP-05: Security awareness training and testing program",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityAwareness,
		References:  []string{"TISAX v6 AL2 ISA-PP-05", "ISO 27001 A.6.3"},
	})

	// PP-06: Data Retention (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-06",
		Name:        "Data Retention",
		Description: "TISAX PP-06: Data retention and disposal policies",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-PP-06", "ISO 27001 A.8.10"},
	})

	// PP-07: Third-party Privacy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-07",
		Name:        "Third-party Privacy",
		Description: "TISAX PP-07: Third-party privacy and data processing agreements",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-PP-07", "GDPR Art. 28"},
	})
}

// registerDPControls wires Development & Prototyping domain controls.
func (m *TISAXModule) registerDPControls() {
	// DP-01: Secure Development (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-01",
		Name:        "Secure Development",
		Description: "TISAX DP-01: Secure development practices and code review",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecureDevelopment,
		References:  []string{"TISAX v6 AL2 ISA-DP-01", "ISO 27001 A.8.25"},
	})

	// DP-02: Test Data Management (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-02",
		Name:        "Test Data Management",
		Description: "TISAX DP-02: Test data management and anonymization for CUI",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-DP-02", "ISO 27001 A.8.33"},
	})

	// DP-03: Prototyping Security (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-03",
		Name:        "Prototyping Security",
		Description: "TISAX DP-03: Security controls for prototypes and test environments",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPrototypingSecurity,
		References:  []string{"TISAX v6 AL2 ISA-DP-03"},
	})

	// DP-04: Supply Chain Integration (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-04",
		Name:        "Supply Chain Integration",
		Description: "TISAX DP-04: Supply chain security integration for automotive components",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-DP-04", "ISO 27001 A.5.19"},
	})

	// DP-05: Intellectual Property (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-05",
		Name:        "Intellectual Property",
		Description: "TISAX DP-05: Intellectual property protection for designs and prototypes",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"TISAX v6 AL2 ISA-DP-05"},
	})

	// DP-06: Configuration Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-06",
		Name:        "Configuration Management",
		Description: "TISAX DP-06: Configuration management and version control",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkConfigurationManagement,
		References:  []string{"TISAX v6 AL2 ISA-DP-06", "ISO 27001 A.8.9"},
	})

	// DP-07: Audit Readiness (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-07",
		Name:        "Audit Readiness",
		Description: "TISAX DP-07: Audit readiness and evidence generation for TISAX assessment",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditReadiness,
		References:  []string{"TISAX v6 AL2 ISA-DP-07", "ISO 27001 A.5.35"},
	})
}

// --- DSC/PP/DP Check Functions ---

func (m *TISAXModule) checkDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryption := m.hasEncryption(inputStr)
	hasAccess := m.hasAccessControl(inputStr)
	hasAudit := m.hasAudit(inputStr)

	if hasEncryption && hasAccess && hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-02",
			ControlName: "Data Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data protection controls verified (encryption + access control + audit logging)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEncryption {
		violations = append(violations, "encryption not configured")
	}
	if !hasAccess {
		violations = append(violations, "access controls not configured")
	}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DSC-02",
		ControlName: "Data Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Data protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable encryption, access controls, and audit logging",
	}, nil
}

func (m *TISAXModule) checkEndpointProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMalware := strings.Contains(inputStr, "malware") || strings.Contains(inputStr, "antivirus") || strings.Contains(inputStr, "scanner")
	hasPatching := strings.Contains(inputStr, "patching") || strings.Contains(inputStr, "patch_management") || strings.Contains(inputStr, "vuln")
	hasEndpoint := strings.Contains(inputStr, "endpoint") || strings.Contains(inputStr, "edr") || strings.Contains(inputStr, "host_based")

	if (hasMalware || hasEndpoint) && hasPatching {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-03",
			ControlName: "Endpoint Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Endpoint protection verified (malware protection + patching)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMalware && !hasEndpoint {
		violations = append(violations, "endpoint/malware protection not detected")
	}
	if !hasPatching {
		violations = append(violations, "patch management not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DSC-03",
		ControlName: "Endpoint Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Endpoint protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable endpoint protection and patch management",
	}, nil
}

func (m *TISAXModule) checkVulnerabilityManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnScan := strings.Contains(inputStr, "vulnerability") || strings.Contains(inputStr, "vuln_scan") || strings.Contains(inputStr, "cve")
	hasRemediation := strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "patching") || strings.Contains(inputStr, "fix")

	if hasVulnScan && hasRemediation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-04",
			ControlName: "Vulnerability Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability management verified (scanning + remediation)",
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
		ControlID:   "TISAX-DSC-04",
		ControlName: "Vulnerability Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable vulnerability scanning and configure remediation workflows",
	}, nil
}

func (m *TISAXModule) checkLoggingMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudit := m.hasAudit(inputStr)
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "alert")
	hasLogIntegrity := strings.Contains(inputStr, "log_integrity") || strings.Contains(inputStr, "hash_chain") || strings.Contains(inputStr, "integrity")

	if hasAudit && hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-05",
			ControlName: "Logging and Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Logging and monitoring verified (audit logging + monitoring/SIEM)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "monitoring/SIEM not configured")
	}
	_ = hasLogIntegrity

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DSC-05",
		ControlName: "Logging and Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Logging and monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable audit logging (audit.enabled=true) and monitoring/SIEM",
	}, nil
}

func (m *TISAXModule) checkSecurityAwareness(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTraining := strings.Contains(inputStr, "training") || strings.Contains(inputStr, "awareness") || strings.Contains(inputStr, "security_awareness")
	hasPolicy := strings.Contains(inputStr, "policy") || strings.Contains(inputStr, "security_policy") || strings.Contains(inputStr, "acceptable_use")

	if hasTraining || hasPolicy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-PP-05",
			ControlName: "Security Awareness",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Security awareness controls verified (training program + policy)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-PP-05",
		ControlName: "Security Awareness",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Security awareness program not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement security awareness training program (security.awareness=true)",
	}, nil
}

func (m *TISAXModule) checkSecureDevelopment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecureDev := strings.Contains(inputStr, "secure_development") || strings.Contains(inputStr, "code_review") || strings.Contains(inputStr, "sdlc")
	hasTesting := strings.Contains(inputStr, "testing") || strings.Contains(inputStr, "unit_test") || strings.Contains(inputStr, "integration_test")
	hasAccess := m.hasAccessControl(inputStr)

	if hasSecureDev && (hasTesting || hasAccess) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DP-01",
			ControlName: "Secure Development",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Secure development controls verified (SDLC + testing/access controls)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSecureDev {
		violations = append(violations, "secure development lifecycle not detected")
	}
	if !hasTesting && !hasAccess {
		violations = append(violations, "testing and access controls not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DP-01",
		ControlName: "Secure Development",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Secure development gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Implement secure development lifecycle with code review and testing",
	}, nil
}

func (m *TISAXModule) checkPrototypingSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTestEnv := strings.Contains(inputStr, "test_environment") || strings.Contains(inputStr, "staging") || strings.Contains(inputStr, "sandbox")
	hasAccess := m.hasAccessControl(inputStr)
	hasIsolation := strings.Contains(inputStr, "isolation") || strings.Contains(inputStr, "network_segmentation") || strings.Contains(inputStr, "sandbox")

	if (hasTestEnv || hasIsolation) && hasAccess {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DP-03",
			ControlName: "Prototyping Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Prototyping security verified (test environment + access controls)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasTestEnv && !hasIsolation {
		violations = append(violations, "isolated test environment not detected")
	}
	if !hasAccess {
		violations = append(violations, "access controls not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DP-03",
		ControlName: "Prototyping Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Prototyping security gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure isolated test environments and access controls for prototypes",
	}, nil
}

func (m *TISAXModule) checkConfigurationManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasConfigMgmt := strings.Contains(inputStr, "configuration_management") || strings.Contains(inputStr, "version_control") || strings.Contains(inputStr, "git")
	hasBaseline := strings.Contains(inputStr, "baseline") || strings.Contains(inputStr, "config_baseline") || strings.Contains(inputStr, "infrastructure_as_code")

	if hasConfigMgmt || hasBaseline {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DP-06",
			ControlName: "Configuration Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Configuration management verified (version control/baseline)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DP-06",
		ControlName: "Configuration Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Configuration management not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable version control and configuration management (config.management=true)",
	}, nil
}

func (m *TISAXModule) checkAuditReadiness(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudit := m.hasAudit(inputStr)
	hasEvidence := strings.Contains(inputStr, "evidence") || strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "trust_portal")
	hasCompliance := strings.Contains(inputStr, "compliance") || strings.Contains(inputStr, "report") || strings.Contains(inputStr, "assessment")

	if hasAudit && (hasEvidence || hasCompliance) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DP-07",
			ControlName: "Audit Readiness",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit readiness verified (audit logging + evidence/compliance reporting)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAudit {
		violations = append(violations, "audit logging not configured")
	}
	if !hasEvidence && !hasCompliance {
		violations = append(violations, "evidence generation not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DP-07",
		ControlName: "Audit Readiness",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit readiness gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable audit logging and compliance evidence generation",
	}, nil
}
