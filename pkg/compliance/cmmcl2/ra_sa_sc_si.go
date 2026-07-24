// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC L2 RA/SA/SC/SI Domains
// =========================================================================
//
// CMMC Level 2 — Risk Assessment, Situational Awareness,
// System and Communications Protection, System and Information Integrity
//
// RA (Risk Assessment): 3 practices (2 automated + 1 evidence-mapped)
// SA (Situational Awareness): 3 practices (2 automated + 1 evidence-mapped)
// SC (System & Comms Protection): 4 practices (2 automated + 2 evidence-mapped)
// SI (System & Info Integrity): 6 practices (5 automated + 1 evidence-mapped)
//
// =========================================================================

package cmmcl2

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerRAControls wires Risk Assessment domain controls.
func (m *CMMCL2Module) registerRAControls() {
	// RA-01: Risk Assessment Policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-RA-01",
		Name:        "Risk Assessment Policy",
		Description: "CMMC L2 RA.2.001: Risk assessment policy documented and reviewed",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 RA.2.001", "NIST SP 800-171 §3.11.1"},
	})

	// RA-02: Vulnerability Scanning (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-RA-02",
		Name:        "Vulnerability Scanning",
		Description: "CMMC L2 RA.2.002: Vulnerability scanning and remediation verified",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityScanning,
		References:  []string{"CMMC L2 RA.2.002", "NIST SP 800-171 §3.11.2"},
	})

	// RA-03: Threat Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-RA-03",
		Name:        "Threat Monitoring",
		Description: "CMMC L2 RA.2.003: Threat intelligence and monitoring configured",
		Category:    "Risk Assessment",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThreatMonitoring,
		References:  []string{"CMMC L2 RA.2.003"},
	})
}

// registerSAControls wires Situational Awareness domain controls.
func (m *CMMCL2Module) registerSAControls() {
	// SA-01: Security Awareness Training (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SA-01",
		Name:        "Security Awareness Training",
		Description: "CMMC L2 SA.2.001: Security awareness training policy and program",
		Category:    "Situational Awareness",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 SA.2.001", "NIST SP 800-171 §3.12.1"},
	})

	// SA-02: Insider Threat (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SA-02",
		Name:        "Insider Threat",
		Description: "CMMC L2 SA.2.002: Insider threat awareness and monitoring",
		Category:    "Situational Awareness",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInsiderThreat,
		References:  []string{"CMMC L2 SA.2.002"},
	})

	// SA-03: Threat Intelligence (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SA-03",
		Name:        "Threat Intelligence",
		Description: "CMMC L2 SA.2.003: Threat intelligence feeds and indicators monitored",
		Category:    "Situational Awareness",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkThreatIntelligence,
		References:  []string{"CMMC L2 SA.2.003"},
	})
}

// registerSCControls wires System and Communications Protection domain controls.
func (m *CMMCL2Module) registerSCControls() {
	// SC-01: Boundary Protection (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-01",
		Name:        "Boundary Protection",
		Description: "CMMC L2 SC.2.001: System boundary protection and network segmentation",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CMMC L2 SC.2.001", "NIST SP 800-171 §3.13.1"},
	})

	// SC-02: Encryption in Transit (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-02",
		Name:        "Encryption in Transit",
		Description: "CMMC L2 SC.2.002: Data encrypted in transit using TLS 1.2+",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEncryptionInTransit,
		References:  []string{"CMMC L2 SC.2.002", "NIST SP 800-171 §3.13.8"},
	})

	// SC-03: Encryption at Rest (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-03",
		Name:        "Encryption at Rest",
		Description: "CMMC L2 SC.2.003: CUI encrypted at rest using FIPS-validated cryptography",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEncryptionAtRest,
		References:  []string{"CMMC L2 SC.2.003", "NIST SP 800-171 §3.13.11"},
	})

	// SC-04: Network Architecture (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SC-04",
		Name:        "Network Architecture",
		Description: "CMMC L2 SC.2.004: Network architecture documented with security controls",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 SC.2.004"},
	})
}

// registerSIControls wires System and Information Integrity domain controls.
func (m *CMMCL2Module) registerSIControls() {
	// SI-01: Flaw Remediation (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SI-01",
		Name:        "Flaw Remediation",
		Description: "CMMC L2 SI.2.001: Flaw remediation and patch management verified",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFlawRemediation,
		References:  []string{"CMMC L2 SI.2.001", "NIST SP 800-171 §3.14.1"},
	})

	// SI-02: Malicious Code Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SI-02",
		Name:        "Malicious Code Protection",
		Description: "CMMC L2 SI.2.002: Malicious code detection and protection verified",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMaliciousCodeProtection,
		References:  []string{"CMMC L2 SI.2.002", "NIST SP 800-171 §3.14.2"},
	})

	// SI-03: System Monitoring (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SI-03",
		Name:        "System Monitoring",
		Description: "CMMC L2 SI.2.003: System monitoring and alerting configured",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSystemMonitoring,
		References:  []string{"CMMC L2 SI.2.003"},
	})

	// SI-04: Information Integrity (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SI-04",
		Name:        "Information Integrity",
		Description: "CMMC L2 SI.2.004: Information integrity controls and checksums verified",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkInformationIntegrity,
		References:  []string{"CMMC L2 SI.2.004"},
	})

	// SI-05: Security Alerts (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SI-05",
		Name:        "Security Alerts",
		Description: "CMMC L2 SI.2.005: Security alert and advisory processing",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityAlerts,
		References:  []string{"CMMC L2 SI.2.005"},
	})

	// SI-06: Information Handling (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-SI-06",
		Name:        "Information Handling",
		Description: "CMMC L2 SI.2.006: Information handling and retention policies. AegisGate generates the information handling evidence for the customer's CMMC assessment.",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CMMC L2 SI.2.006"},
	})
}

// --- RA/SA/SC/SI Check Functions ---

func (m *CMMCL2Module) checkVulnerabilityScanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnScan := strings.Contains(inputStr, "vulnerability") || strings.Contains(inputStr, "vuln_scan") || strings.Contains(inputStr, "cve")
	hasRemediation := strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "patching") || strings.Contains(inputStr, "fix")

	if hasVulnScan && hasRemediation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-RA-02",
			ControlName: "Vulnerability Scanning",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability scanning and remediation verified",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasVulnScan {
		violations = append(violations, "vulnerability scanning not configured")
	}
	if !hasRemediation {
		violations = append(violations, "remediation/patching process not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-RA-02",
		ControlName: "Vulnerability Scanning",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability scanning gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable vulnerability scanning (vuln.scan_enabled=true) and configure remediation workflows",
	}, nil
}

func (m *CMMCL2Module) checkThreatMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasThreatIntel := strings.Contains(inputStr, "threat_intel") || strings.Contains(inputStr, "ioc") || strings.Contains(inputStr, "threat_feed")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "alert")

	if hasThreatIntel && hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-RA-03",
			ControlName: "Threat Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Threat monitoring verified (threat intelligence + monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasThreatIntel {
		violations = append(violations, "threat intelligence feeds not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "threat monitoring not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-RA-03",
		ControlName: "Threat Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Threat monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable threat intelligence feeds (threat.intel_enabled=true) and SIEM monitoring",
	}, nil
}

func (m *CMMCL2Module) checkInsiderThreat(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInsiderThreat := strings.Contains(inputStr, "insider_threat") || strings.Contains(inputStr, "user_behavior") || strings.Contains(inputStr, "anomaly_detection")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "siem")

	if hasInsiderThreat && hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SA-02",
			ControlName: "Insider Threat",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Insider threat controls verified (detection + monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasInsiderThreat {
		violations = append(violations, "insider threat detection not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "user monitoring not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SA-02",
		ControlName: "Insider Threat",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Insider threat gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable insider threat detection (insider_threat.enabled=true) and user behavior monitoring",
	}, nil
}

func (m *CMMCL2Module) checkThreatIntelligence(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasThreatFeed := strings.Contains(inputStr, "threat_intel") || strings.Contains(inputStr, "ioc") || strings.Contains(inputStr, "threat_feed")
	hasIOCStore := strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "indicator") || strings.Contains(inputStr, "indicator_of_compromise")

	if hasThreatFeed || hasIOCStore {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SA-03",
			ControlName: "Threat Intelligence",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Threat intelligence feeds configured",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SA-03",
		ControlName: "Threat Intelligence",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Threat intelligence feeds not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable threat intelligence feeds (threat.intel_enabled=true, ioc.enabled=true)",
	}, nil
}

func (m *CMMCL2Module) checkEncryptionInTransit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https") || strings.Contains(inputStr, "tls_1_2")
	hasEncryption := false
	for _, p := range m.encryptionPatterns {
		if p.MatchString(inputStr) {
			hasEncryption = true
			break
		}
	}

	if hasTLS || hasEncryption {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-02",
			ControlName: "Encryption in Transit",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Encryption in transit verified (TLS/encryption enabled)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-02",
		ControlName: "Encryption in Transit",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Encryption in transit not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2+ for all communications (security.tls_min_version=1.2)",
	}, nil
}

func (m *CMMCL2Module) checkEncryptionAtRest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptionAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted") || strings.Contains(inputStr, "aes_256")
	hasFIPS := strings.Contains(inputStr, "fips_140") || strings.Contains(inputStr, "fips_mode") || strings.Contains(inputStr, "cmvp")

	if hasEncryptionAtRest || hasFIPS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SC-03",
			ControlName: "Encryption at Rest",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Encryption at rest verified (AES-256/FIPS-validated cryptography)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SC-03",
		ControlName: "Encryption at Rest",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Encryption at rest not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable encryption at rest (security.encryption_at_rest=true) with FIPS-validated cryptography",
	}, nil
}

func (m *CMMCL2Module) checkFlawRemediation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPatching := strings.Contains(inputStr, "patching") || strings.Contains(inputStr, "patch_management") || strings.Contains(inputStr, "vuln_remediation")
	hasVulnScan := strings.Contains(inputStr, "vulnerability") || strings.Contains(inputStr, "vuln_scan") || strings.Contains(inputStr, "cve")

	if hasPatching && hasVulnScan {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SI-01",
			ControlName: "Flaw Remediation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Flaw remediation verified (vulnerability scanning + patch management)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPatching {
		violations = append(violations, "patch management not configured")
	}
	if !hasVulnScan {
		violations = append(violations, "vulnerability scanning not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SI-01",
		ControlName: "Flaw Remediation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Flaw remediation gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable vulnerability scanning and patch management",
	}, nil
}

func (m *CMMCL2Module) checkMaliciousCodeProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMalwareScan := strings.Contains(inputStr, "malware") || strings.Contains(inputStr, "antivirus") || strings.Contains(inputStr, "malicious_code")
	hasScanner := strings.Contains(inputStr, "scanner") || strings.Contains(inputStr, "pattern_detection") || strings.Contains(inputStr, "ioc")

	if hasMalwareScan || hasScanner {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SI-02",
			ControlName: "Malicious Code Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Malicious code protection verified (malware scanning/pattern detection)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SI-02",
		ControlName: "Malicious Code Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Malicious code protection not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable malware scanning and pattern-based threat detection",
	}, nil
}

func (m *CMMCL2Module) checkSystemMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "logging_enabled") || strings.Contains(inputStr, "log_integrity")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "alert")

	if hasAuditLog && hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SI-03",
			ControlName: "System Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "System monitoring verified (audit logging + SIEM/monitoring)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAuditLog {
		violations = append(violations, "audit logging not configured")
	}
	if !hasMonitoring {
		violations = append(violations, "system monitoring not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SI-03",
		ControlName: "System Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "System monitoring gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable audit logging (audit.enabled=true) and system monitoring (monitoring.enabled=true)",
	}, nil
}

func (m *CMMCL2Module) checkInformationIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasHashChain := strings.Contains(inputStr, "hash_chain") || strings.Contains(inputStr, "integrity_check") || strings.Contains(inputStr, "checksum")
	hasValidation := strings.Contains(inputStr, "input_validation") || strings.Contains(inputStr, "data_integrity") || strings.Contains(inputStr, "integrity")

	if hasHashChain || hasValidation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SI-04",
			ControlName: "Information Integrity",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Information integrity controls verified (hash chain/integrity checks)",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SI-04",
		ControlName: "Information Integrity",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Information integrity controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable integrity checking (integrity.hash_chain=true) and input validation",
	}, nil
}

// checkSecurityAlerts verifies security alert and advisory processing.
// Maps to CMMC L2 SI.2.005.
func (m *CMMCL2Module) checkSecurityAlerts(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSecurityAlerts := strings.Contains(inputStr, "security_alerts") || strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "siem")
	hasNotification := strings.Contains(inputStr, "notification") || strings.Contains(inputStr, "advisory") || strings.Contains(inputStr, "advisories")

	if hasSecurityAlerts && hasNotification {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-SI-05",
			ControlName: "Security Alerts",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Security alerts verified (alerts + notification/advisory processing)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSecurityAlerts {
		violations = append(violations, "security alerts not configured")
	}
	if !hasNotification {
		violations = append(violations, "security advisory notification not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-SI-05",
		ControlName: "Security Alerts",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Security alerts gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure security alerts (security_alerts=true) and advisory notification processing",
	}, nil
}
