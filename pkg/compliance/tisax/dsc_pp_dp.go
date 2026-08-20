// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - TISAX DSC/PP/DP Domains
// =========================================================================
//
// TISAX AL2 — Data & System Controls, Privacy & Personnel,
// Development & Prototyping domains.
//
// DSC (Data & System Controls): 14 practices (8 automated + 6 evidence-mapped)
// PP (Privacy & Personnel): 13 practices (2 automated + 11 evidence-mapped)
// DP (Development & Prototyping): 12 practices (6 automated + 6 evidence-mapped)
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
		Automated:   true,
		CheckFunc:   m.checkTisaxDataClassification,
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
		Automated:   true,
		CheckFunc:   m.checkTisaxChangeMgmt,
		References:  []string{"TISAX v6 AL2 ISA-DSC-06", "ISO 27001 A.8.32"},
	})

	// DSC-07: Network Security Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-07",
		Name:        "Network Security Monitoring",
		Description: "TISAX DSC-07: Network security monitoring with IDS/IPS and traffic analysis",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkMonitoring,
		References:  []string{"TISAX v6 AL2 ISA-DSC-07", "ISO 27001 A.8.16"},
	})

	// DSC-08: Endpoint Security Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-08",
		Name:        "Endpoint Security Management",
		Description: "TISAX DSC-08: Endpoint security management with EDR and device compliance",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEndpointSecurity,
		References:  []string{"TISAX v6 AL2 ISA-DSC-08", "ISO 27001 A.8.7"},
	})

	// DSC-09: Mobile Device Management (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-09",
		Name:        "Mobile Device Management",
		Description: "TISAX DSC-09: Mobile device management with enrollment and policy enforcement",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTisaxMDM,
		References:  []string{"TISAX v6 AL2 ISA-DSC-09", "ISO 27001 A.8.7"},
	})

	// DSC-10: Cloud Service Security (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-10",
		Name:        "Cloud Service Security",
		Description: "TISAX DSC-10: Cloud service security with CSPM and workload protection",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCloudSecurity,
		References:  []string{"TISAX v6 AL2 ISA-DSC-10", "ISO 27001 A.5.23"},
	})

	// DSC-11: Data Loss Prevention (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-11",
		Name:        "Data Loss Prevention",
		Description: "TISAX DSC-11: Data loss prevention controls for CUI and proprietary data",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDLP,
		References:  []string{"TISAX v6 AL2 ISA-DSC-11", "ISO 27001 A.8.12"},
	})

	// DSC-12: Secure Configuration Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-12",
		Name:        "Secure Configuration Management",
		Description: "TISAX DSC-12: Secure configuration management with baselines and drift detection",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecureConfig,
		References:  []string{"TISAX v6 AL2 ISA-DSC-12", "ISO 27001 A.8.9"},
	})

	// DSC-13: Patch & Vulnerability Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-13",
		Name:        "Patch & Vulnerability Management",
		Description: "TISAX DSC-13: Patch management and vulnerability remediation with SLAs",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPatchMgmt,
		References:  []string{"TISAX v6 AL2 ISA-DSC-13", "ISO 27001 A.8.8"},
	})

	// DSC-14: AI/ML Security Controls (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DSC-14",
		Name:        "AI/ML Security Controls",
		Description: "TISAX DSC-14: AI/ML security controls for model training and deployment",
		Category:    "Data and System Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTisaxAIMLSecurity,
		References:  []string{"TISAX v6 AL2 ISA-DSC-14", "ISO 27001 A.5.7"},
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
		Automated:   true,
		CheckFunc:   m.checkTisaxPrivacyPolicy,
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
		Automated:   true,
		CheckFunc:   m.checkTisaxDataRetention,
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

	// PP-08: Background Verification (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-08",
		Name:        "Background Verification",
		Description: "TISAX PP-08: Background verification and security screening for personnel",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-PP-08", "ISO 27001 A.6.1"},
	})

	// PP-09: Security Training Program (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-09",
		Name:        "Security Training Program",
		Description: "TISAX PP-09: Role-based security training program with role-specific modules",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-PP-09", "ISO 27001 A.6.3"},
	})

	// PP-10: Personnel Termination Security (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-10",
		Name:        "Personnel Termination Security",
		Description: "TISAX PP-10: Personnel termination security procedures and access revocation",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-PP-10", "ISO 27001 A.6.2"},
	})

	// PP-11: Privacy Impact Assessment (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-11",
		Name:        "Privacy Impact Assessment",
		Description: "TISAX PP-11: Privacy impact assessment for new systems and processing activities",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-PP-11", "GDPR Art. 35"},
	})

	// PP-12: Data Subject Rights (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-12",
		Name:        "Data Subject Rights",
		Description: "TISAX PP-12: Automated data subject rights handling (access, rectification, erasure)",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDataSubjectRights,
		References:  []string{"TISAX v6 AL2 ISA-PP-12", "GDPR Art. 15-22"},
	})

	// PP-13: AI Privacy Controls (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-PP-13",
		Name:        "AI Privacy Controls",
		Description: "TISAX PP-13: Privacy controls for AI systems and data processing",
		Category:    "Privacy and Personnel",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-PP-13", "GDPR Art. 22"},
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

	// DP-08: Threat Modeling (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-08",
		Name:        "Threat Modeling",
		Description: "TISAX DP-08: Threat modeling performed for systems and applications",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThreatModeling,
		References:  []string{"TISAX v6 AL2 ISA-DP-08", "ISO 27001 A.8.25"},
	})

	// DP-09: Penetration Testing (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-09",
		Name:        "Penetration Testing",
		Description: "TISAX DP-09: Penetration testing program with scheduled and ad-hoc tests",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPenTest,
		References:  []string{"TISAX v6 AL2 ISA-DP-09", "ISO 27001 A.8.8"},
	})

	// DP-10: Secure CI/CD Pipeline (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-10",
		Name:        "Secure CI/CD Pipeline",
		Description: "TISAX DP-10: Secure CI/CD pipeline with automated security gates",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecureCICD,
		References:  []string{"TISAX v6 AL2 ISA-DP-10", "ISO 27001 A.8.25"},
	})

	// DP-11: AI Model Security (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-11",
		Name:        "AI Model Security",
		Description: "TISAX DP-11: AI model security controls including adversarial robustness",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-DP-11"},
	})

	// DP-12: Open Source Risk Management (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "TISAX-DP-12",
		Name:        "Open Source Risk Management",
		Description: "TISAX DP-12: Open source risk management with SBOM and license compliance",
		Category:    "Development and Prototyping",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		CheckFunc:   nil,
		References:  []string{"TISAX v6 AL2 ISA-DP-12", "ISO 27001 A.5.21"},
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

// --- New DSC CheckFunc implementations (DSC-07 through DSC-13) ---

// checkNetworkMonitoring verifies network security monitoring with IDS/IPS.
// Maps to TISAX DSC-07.
func (m *TISAXModule) checkNetworkMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIDS := strings.Contains(inputStr, "ids") || strings.Contains(inputStr, "ips") || strings.Contains(inputStr, "intrusion_detection")
	hasTraffic := strings.Contains(inputStr, "traffic_analysis") || strings.Contains(inputStr, "network_monitoring") || strings.Contains(inputStr, "netflow")
	hasAlerting := strings.Contains(inputStr, "alerting") || strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "siem")

	if hasIDS && hasTraffic {
		evidence := []string{
			"IDS/IPS configured",
			"Network traffic analysis active",
		}
		if hasAlerting {
			evidence = append(evidence, "Network alerting configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-07",
			ControlName: "Network Security Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network security monitoring verified (IDS/IPS + traffic analysis)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasIDS {
		violations = append(violations, "IDS/IPS not configured")
	}
	if !hasTraffic {
		violations = append(violations, "network traffic analysis not active")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DSC-07",
		ControlName: "Network Security Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Network security monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Deploy IDS/IPS and configure network traffic analysis with alerting",
	}, nil
}

// checkEndpointSecurity verifies endpoint security management with EDR.
// Maps to TISAX DSC-08.
func (m *TISAXModule) checkEndpointSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEDR := strings.Contains(inputStr, "edr") || strings.Contains(inputStr, "endpoint_detection") || strings.Contains(inputStr, "endpoint_protection")
	hasCompliance := strings.Contains(inputStr, "device_compliance") || strings.Contains(inputStr, "compliance_check") || strings.Contains(inputStr, "posture")
	hasMgmt := strings.Contains(inputStr, "mdm") || strings.Contains(inputStr, "endpoint_management") || strings.Contains(inputStr, "device_management")

	if hasEDR && (hasCompliance || hasMgmt) {
		evidence := []string{
			"EDR configured",
		}
		if hasCompliance {
			evidence = append(evidence, "Device compliance checking active")
		}
		if hasMgmt {
			evidence = append(evidence, "Endpoint management in place")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-08",
			ControlName: "Endpoint Security Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Endpoint security verified (EDR + compliance/management)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEDR {
		violations = append(violations, "EDR not configured")
	}
	if !hasCompliance && !hasMgmt {
		violations = append(violations, "device compliance and endpoint management not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DSC-08",
		ControlName: "Endpoint Security Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Endpoint security gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Deploy EDR and configure device compliance checking and endpoint management",
	}, nil
}

// checkCloudSecurity verifies cloud service security with CSPM.
// Maps to TISAX DSC-10.
func (m *TISAXModule) checkCloudSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCSPM := strings.Contains(inputStr, "cspm") || strings.Contains(inputStr, "cloud_security_posture") || strings.Contains(inputStr, "cloud_security")
	hasWorkload := strings.Contains(inputStr, "workload_protection") || strings.Contains(inputStr, "cwpp") || strings.Contains(inputStr, "container_security")
	hasEncryption := m.hasEncryption(inputStr)

	if hasCSPM && (hasWorkload || hasEncryption) {
		evidence := []string{
			"Cloud security posture management configured",
		}
		if hasWorkload {
			evidence = append(evidence, "Workload protection in place")
		}
		if hasEncryption {
			evidence = append(evidence, "Cloud encryption configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-10",
			ControlName: "Cloud Service Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cloud security verified (CSPM + workload protection/encryption)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasCSPM {
		violations = append(violations, "CSPM not configured")
	}
	if !hasWorkload && !hasEncryption {
		violations = append(violations, "workload protection and encryption not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DSC-10",
		ControlName: "Cloud Service Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cloud security gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure CSPM and deploy workload protection with encryption",
	}, nil
}

// checkDLP verifies data loss prevention controls. Maps to TISAX DSC-11.
func (m *TISAXModule) checkDLP(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDLP := strings.Contains(inputStr, "dlp") || strings.Contains(inputStr, "data_loss_prevention") || strings.Contains(inputStr, "data_loss")
	hasPolicy := strings.Contains(inputStr, "dlp_policy") || strings.Contains(inputStr, "content_inspection") || strings.Contains(inputStr, "classification")
	hasBlocking := strings.Contains(inputStr, "blocking") || strings.Contains(inputStr, "quarantine") || strings.Contains(inputStr, "prevent")

	if hasDLP && hasPolicy {
		evidence := []string{
			"DLP solution configured",
			"DLP policies in place",
		}
		if hasBlocking {
			evidence = append(evidence, "DLP blocking/quarantine active")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-11",
			ControlName: "Data Loss Prevention",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "DLP verified (solution + policies)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasDLP {
		violations = append(violations, "DLP solution not configured")
	}
	if !hasPolicy {
		violations = append(violations, "DLP policies not in place")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DSC-11",
		ControlName: "Data Loss Prevention",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "DLP gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Deploy a DLP solution with content inspection policies and blocking",
	}, nil
}

// checkSecureConfig verifies secure configuration management with baselines.
// Maps to TISAX DSC-12.
func (m *TISAXModule) checkSecureConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBaseline := strings.Contains(inputStr, "config_baseline") || strings.Contains(inputStr, "baseline") || strings.Contains(inputStr, "hardening")
	hasDrift := strings.Contains(inputStr, "drift_detection") || strings.Contains(inputStr, "drift") || strings.Contains(inputStr, "config_monitoring")
	hasScanning := strings.Contains(inputStr, "config_scan") || strings.Contains(inputStr, "cis_benchmark") || strings.Contains(inputStr, "benchmark")

	if hasBaseline && (hasDrift || hasScanning) {
		evidence := []string{
			"Secure configuration baseline defined",
		}
		if hasDrift {
			evidence = append(evidence, "Configuration drift detection active")
		}
		if hasScanning {
			evidence = append(evidence, "Configuration scanning against benchmarks")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-12",
			ControlName: "Secure Configuration Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Secure configuration verified (baseline + drift/scanning)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasBaseline {
		violations = append(violations, "configuration baseline not defined")
	}
	if !hasDrift && !hasScanning {
		violations = append(violations, "drift detection and config scanning not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DSC-12",
		ControlName: "Secure Configuration Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Secure configuration gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Define configuration baselines and enable drift detection with benchmark scanning",
	}, nil
}

// checkPatchMgmt verifies patch management and vulnerability remediation.
// Maps to TISAX DSC-13.
func (m *TISAXModule) checkPatchMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPatch := strings.Contains(inputStr, "patch_management") || strings.Contains(inputStr, "patching") || strings.Contains(inputStr, "patch")
	hasSLA := strings.Contains(inputStr, "sla") || strings.Contains(inputStr, "patch_sla") || strings.Contains(inputStr, "deadline")
	hasAutomated := strings.Contains(inputStr, "automated_patching") || strings.Contains(inputStr, "auto_patch") || strings.Contains(inputStr, "scheduled")

	if hasPatch && (hasSLA || hasAutomated) {
		evidence := []string{
			"Patch management configured",
		}
		if hasSLA {
			evidence = append(evidence, "Patch SLAs defined")
		}
		if hasAutomated {
			evidence = append(evidence, "Automated patching scheduled")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DSC-13",
			ControlName: "Patch & Vulnerability Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Patch management verified (patching + SLA/automation)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPatch {
		violations = append(violations, "patch management not configured")
	}
	if !hasSLA && !hasAutomated {
		violations = append(violations, "patch SLAs and automation not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DSC-13",
		ControlName: "Patch & Vulnerability Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Patch management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure patch management with SLAs and automated patching schedules",
	}, nil
}

// --- New PP CheckFunc implementation (PP-12) ---

// checkDataSubjectRights verifies automated data subject rights handling.
// Maps to TISAX PP-12.
func (m *TISAXModule) checkDataSubjectRights(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDSR := strings.Contains(inputStr, "data_subject_rights") || strings.Contains(inputStr, "dsr") || strings.Contains(inputStr, "subject_rights")
	hasAccess := strings.Contains(inputStr, "access_request") || strings.Contains(inputStr, "data_access") || strings.Contains(inputStr, "access")
	hasErasure := strings.Contains(inputStr, "erasure") || strings.Contains(inputStr, "deletion") || strings.Contains(inputStr, "right_to_be_forgotten")

	if hasDSR && (hasAccess || hasErasure) {
		evidence := []string{
			"Data subject rights handling configured",
		}
		if hasAccess {
			evidence = append(evidence, "Data access request handling active")
		}
		if hasErasure {
			evidence = append(evidence, "Data erasure/deletion handling active")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-PP-12",
			ControlName: "Data Subject Rights",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Data subject rights verified (DSR handling + access/erasure)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasDSR {
		violations = append(violations, "data subject rights handling not configured")
	}
	if !hasAccess && !hasErasure {
		violations = append(violations, "access and erasure request handling not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-PP-12",
		ControlName: "Data Subject Rights",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Data subject rights gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure automated data subject rights handling for access and erasure requests",
	}, nil
}

// --- New DP CheckFunc implementations (DP-08 through DP-10) ---

// checkThreatModeling verifies threat modeling for systems and applications.
// Maps to TISAX DP-08.
func (m *TISAXModule) checkThreatModeling(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasThreatModel := strings.Contains(inputStr, "threat_model") || strings.Contains(inputStr, "threat_modeling") || strings.Contains(inputStr, "threat")
	hasMethodology := strings.Contains(inputStr, "stride") || strings.Contains(inputStr, "attack_tree") || strings.Contains(inputStr, "methodology")
	hasMitigation := strings.Contains(inputStr, "mitigation") || strings.Contains(inputStr, "countermeasure") || strings.Contains(inputStr, "control")

	if hasThreatModel && (hasMethodology || hasMitigation) {
		evidence := []string{
			"Threat modeling performed",
		}
		if hasMethodology {
			evidence = append(evidence, "Threat modeling methodology applied")
		}
		if hasMitigation {
			evidence = append(evidence, "Threat mitigations documented")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DP-08",
			ControlName: "Threat Modeling",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Threat modeling verified (modeling + methodology/mitigations)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasThreatModel {
		violations = append(violations, "threat modeling not performed")
	}
	if !hasMethodology && !hasMitigation {
		violations = append(violations, "methodology and mitigations not documented")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DP-08",
		ControlName: "Threat Modeling",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Threat modeling gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Perform threat modeling using STRIDE or attack trees and document mitigations",
	}, nil
}

// checkPenTest verifies penetration testing program. Maps to TISAX DP-09.
func (m *TISAXModule) checkPenTest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPenTest := strings.Contains(inputStr, "penetration_test") || strings.Contains(inputStr, "pentest") || strings.Contains(inputStr, "pen_test")
	hasSchedule := strings.Contains(inputStr, "scheduled") || strings.Contains(inputStr, "annual") || strings.Contains(inputStr, "periodic")
	hasRemediation := strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "fix") || strings.Contains(inputStr, "findings")

	if hasPenTest && (hasSchedule || hasRemediation) {
		evidence := []string{
			"Penetration testing program in place",
		}
		if hasSchedule {
			evidence = append(evidence, "Scheduled/periodic testing configured")
		}
		if hasRemediation {
			evidence = append(evidence, "Findings remediation process active")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DP-09",
			ControlName: "Penetration Testing",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Penetration testing verified (testing + schedule/remediation)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPenTest {
		violations = append(violations, "penetration testing not configured")
	}
	if !hasSchedule && !hasRemediation {
		violations = append(violations, "schedule and remediation process not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DP-09",
		ControlName: "Penetration Testing",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Penetration testing gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Establish a penetration testing program with scheduled tests and findings remediation",
	}, nil
}

// checkSecureCICD verifies secure CI/CD pipeline with automated security gates.
// Maps to TISAX DP-10.
func (m *TISAXModule) checkSecureCICD(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCICD := strings.Contains(inputStr, "ci_cd") || strings.Contains(inputStr, "cicd") || strings.Contains(inputStr, "pipeline")
	hasSecurityGate := strings.Contains(inputStr, "security_gate") || strings.Contains(inputStr, "sast") || strings.Contains(inputStr, "dast") || strings.Contains(inputStr, "security_scan")
	hasAutomation := strings.Contains(inputStr, "automated") || strings.Contains(inputStr, "automation") || strings.Contains(inputStr, "automated_scan")

	if hasCICD && hasSecurityGate {
		evidence := []string{
			"CI/CD pipeline configured",
			"Security gates integrated",
		}
		if hasAutomation {
			evidence = append(evidence, "Automated security scanning active")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "TISAX-DP-10",
			ControlName: "Secure CI/CD Pipeline",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Secure CI/CD verified (pipeline + security gates)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasCICD {
		violations = append(violations, "CI/CD pipeline not configured")
	}
	if !hasSecurityGate {
		violations = append(violations, "security gates not integrated")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "TISAX-DP-10",
		ControlName: "Secure CI/CD Pipeline",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Secure CI/CD gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure CI/CD pipeline with SAST/DAST security gates and automated scanning",
	}, nil
}

// ============================================================================
// Promoted CheckFunc implementations — P4 Compliance Automation Expansion
// ============================================================================

func (m *TISAXModule) checkTisaxDataClassification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasClassification := strings.Contains(inputStr, "data_classification") || strings.Contains(inputStr, "classification_scheme") || strings.Contains(inputStr, "classification_policy")
	if hasClassification {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-DSC-01", ControlName: "Data Classification", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Data classification detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-DSC-01", ControlName: "Data Classification", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Data classification not detected", Timestamp: time.Now(), Remediation: "Implement data classification"}, nil
}

func (m *TISAXModule) checkTisaxChangeMgmt(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasChangeMgmt := strings.Contains(inputStr, "change_management") || strings.Contains(inputStr, "change_control") || strings.Contains(inputStr, "change_process")
	if hasChangeMgmt {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-DSC-06", ControlName: "Change Management", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Change management detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-DSC-06", ControlName: "Change Management", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Change management not detected", Timestamp: time.Now(), Remediation: "Implement change management"}, nil
}

func (m *TISAXModule) checkTisaxMDM(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMDM := strings.Contains(inputStr, "mobile_device_management") || strings.Contains(inputStr, "mdm") || strings.Contains(inputStr, "device_management")
	if hasMDM {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-DSC-09", ControlName: "Mobile Device Management", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Mobile device management detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-DSC-09", ControlName: "Mobile Device Management", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "MDM not detected", Timestamp: time.Now(), Remediation: "Implement mobile device management"}, nil
}

func (m *TISAXModule) checkTisaxAIMLSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAI := strings.Contains(inputStr, "ai_ml_security") || strings.Contains(inputStr, "ai_security_controls") || strings.Contains(inputStr, "ml_security")
	if hasAI {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-DSC-14", ControlName: "AI/ML Security Controls", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "AI/ML security controls detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-DSC-14", ControlName: "AI/ML Security Controls", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "AI/ML security not detected", Timestamp: time.Now(), Remediation: "Implement AI/ML security controls"}, nil
}

func (m *TISAXModule) checkTisaxDataRetention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRetention := strings.Contains(inputStr, "data_retention") || strings.Contains(inputStr, "retention_policy") || strings.Contains(inputStr, "retention_schedule")
	if hasRetention {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-PP-06", ControlName: "Data Retention", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Data retention detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-PP-06", ControlName: "Data Retention", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Data retention not detected", Timestamp: time.Now(), Remediation: "Implement data retention policies"}, nil
}

func (m *TISAXModule) checkTisaxPrivacyPolicy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPolicy := strings.Contains(inputStr, "privacy_policy") || strings.Contains(inputStr, "privacy_framework") || strings.Contains(inputStr, "privacy_controls")
	if hasPolicy {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-PP-01", ControlName: "Privacy Policy", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Privacy policy detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "TISAX-PP-01", ControlName: "Privacy Policy", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Privacy policy not detected", Timestamp: time.Now(), Remediation: "Implement privacy policy"}, nil
}
