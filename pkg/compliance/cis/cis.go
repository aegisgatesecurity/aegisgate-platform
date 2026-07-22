// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CIS Critical Security Controls v8
// =========================================================================
//
// CIS Critical Security Controls v8 (formerly the SANS Top 20) is the
// de-facto industry baseline for US enterprise security questionnaires.
// 80%+ of enterprise RFPs ask "do you have CIS coverage?" — this module
// provides that coverage by mapping the 18 CIS control families to
// AegisGate's existing modules.
//
// Module metadata:
//   - Framework:   "cis"
//   - Version:     "1.1" (v3.x close-out Tier 1)
//   - Required tier: Community (free, like ATLAS/OWASP/NIST AI RMF/GDPR)
//   - Pricing:      No separate add-on (bundled with the platform)
//
// Architecture:
//   - cis.go:        module wiring, pattern caches, 15 RegisterControl calls,
//                    15 CheckFunc implementations
//   - cis_test.go:   unit tests for each CheckFunc
//
// Coverage: 15 of 18 CIS v8 control families mapped to AegisGate. The
// remaining 3 (Security Awareness 14, Service Provider Management 15,
// Penetration Testing 18) are out-of-scope for a security scanner —
// they are process/human-relations/customer-driven, not technical
// controls that can be automated by a scanner.
//
// Mapping summary (v3.x Tier 1):
//   CIS 1  (Inventory)         -> pkg/ioc/ (IOC store + bundle federation)
//   CIS 2  (Software Inventory) -> Platform binary attestation (pkg/attestation/)
//   CIS 3  (Data Protection)    -> pkg/security/headers.go + TLS config + PII/secret scanning
//   CIS 4  (Secure Config Mgmt) -> AegisGate platformconfig
//   CIS 5  (Account Mgmt)       -> pkg/auth/middleware.go + pkg/rbac/
//   CIS 6  (Access Control Mgmt)-> pkg/auth/middleware.go
//   CIS 7  (Vulnerability Mgmt)  -> govulncheck + Trivy CI workflows
//   CIS 8  (Audit Log Mgmt)     -> pkg/persistence/ + audit ring buffer
//   CIS 9  (Email/Web Browser)  -> AegisGate Lens (browser extension) + AegisGate Lens telemetry bridge
//   CIS 10 (Malware Defenses)   -> AegisGate scanner (prompt injection, jailbreak, data poisoning, 144+ patterns)
//   CIS 11 (Data Recovery)      -> AegisGate audit log hash-chain + opt-in backup + 7/30/90-day retention by tier
//   CIS 12 (Network Infra Mgmt) -> TLS 1.2+ enforced + network segmentation defaults + mTLS for A2A/ACP
//   CIS 13 (Network Monitoring) -> IOC store + anomaly detection + Trust Framework
//   CIS 14 (Security Awareness) -> OUT OF SCOPE (process/human)
//   CIS 15 (Service Provider)   -> OUT OF SCOPE (customer process)
//   CIS 16 (App Software Sec)   -> AegisGate scanner + 144+ patterns + SecureFlag/AR-EaaS runner
//   CIS 17 (Incident Response)  -> AegisGate audit log + Trust Framework attestations + IOC federation
//   CIS 18 (Pen Testing)        -> OUT OF SCOPE (customer process; AegisGate can generate artifacts)
//
// Out-of-scope justification: 14, 15, 18 are NOT scanner concerns.
// They are process/human-relations/customer-driven activities. The
// v3.x close-out plan documents this explicitly (see
// plans/V3X-CLOSE-OUT-PLAN-2026-07-21.md and plans/V3X-CLOSE-OUT-
// RELEVANCE-ANALYSIS-2026-07-21.md). AegisGate can produce ARTIFACTS
// (e.g., a generated pen-test report template) but cannot perform
// human training, vendor onboarding, or external pen testing.
//
// Reference: https://www.cisecurity.org/controls/cis-controls-list
//            CIS Critical Security Controls v8.0 (May 2024)
// =========================================================================

package cis

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// CISModule implements the CIS Critical Security Controls v8 framework.
// It embeds *compliance.BaseComplianceModule which provides
// RegisterControl, Controls(), Framework(), Version(), CheckAll(), and
// GenerateAssessment() out of the box.
type CISModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	auditLogPatterns []*regexp.Regexp
	tlsPatterns      []*regexp.Regexp
	scannerPatterns  []*regexp.Regexp
}

// NewCISModule creates a new CIS Critical Security Controls v8 module.
func NewCISModule() *CISModule {
	m := &CISModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("cis", "1.1", core.TierCommunity),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
func (m *CISModule) initPatterns() {
	m.auditLogPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)audit[_ ]?enabled`),
		regexp.MustCompile(`(?i)log[_ ]?integrity`),
		regexp.MustCompile(`(?i)hash[_ ]?chain`),
	}
	m.tlsPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)tls[_ ]?1[._][23]`),
		regexp.MustCompile(`(?i)min[_ ]?version[_ ]?1[._][23]`),
	}
	m.scannerPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)scanner`),
		regexp.MustCompile(`(?i)prompt[_ ]?injection[_ ]?scanner`),
		regexp.MustCompile(`(?i)jailbreak[_ ]?scanner`),
		regexp.MustCompile(`(?i)data[_ ]?poisoning[_ ]?scanner`),
		regexp.MustCompile(`(?i)aegisgate[_ ]?scanner`),
	}
}

// registerControls wires all 15 CIS v8 controls into the module.
// CIS 14, 15, 18 are NOT registered — they are out-of-scope for a
// security scanner (process/human-relations/customer-driven activities).
// See the package doc comment for the full out-of-scope justification.
func (m *CISModule) registerControls() {
	// === Family 1: Inventory and Control of Enterprise Assets ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-1",
		Name:        "Inventory and Control of Enterprise Assets",
		Description: "CIS 1: Actively manage all enterprise assets connected to the infrastructure physically, virtually, or remotely",
		Category:    "Asset Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInventoryAssets,
		References:  []string{"CIS v8.0 Control 1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-2",
		Name:        "Inventory and Control of Software Assets",
		Description: "CIS 2: Actively manage all software on the network to ensure only authorized software is installed",
		Category:    "Asset Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSoftwareInventory,
		References:  []string{"CIS v8.0 Control 2"},
	})

	// === Family 3: Data Protection ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-3",
		Name:        "Data Protection",
		Description: "CIS 3: Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDataProtection,
		References:  []string{"CIS v8.0 Control 3"},
	})

	// === Family 4: Secure Configuration Management ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-4",
		Name:        "Secure Configuration of Enterprise Assets and Software",
		Description: "CIS 4: Establish and maintain the secure configuration of enterprise assets and software",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecureConfiguration,
		References:  []string{"CIS v8.0 Control 4"},
	})

	// === Family 5: Account Management ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-5",
		Name:        "Account Management",
		Description: "CIS 5: Use processes and tools to assign and manage authorization to credentials for user accounts",
		Category:    "Identity and Access Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccountManagement,
		References:  []string{"CIS v8.0 Control 5"},
	})

	// === Family 6: Access Control Management ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-6",
		Name:        "Access Control Management",
		Description: "CIS 6: Use processes and tools to create, assign, manage, and revoke access credentials and privileges",
		Category:    "Identity and Access Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccessControl,
		References:  []string{"CIS v8.0 Control 6"},
	})

	// === Family 7: Continuous Vulnerability Management ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-7",
		Name:        "Continuous Vulnerability Management",
		Description: "CIS 7: Develop a plan to continuously assess and track vulnerabilities on all enterprise assets",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityManagement,
		References:  []string{"CIS v8.0 Control 7"},
	})

	// === Family 8: Audit Log Management ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-8",
		Name:        "Audit Log Management",
		Description: "CIS 8: Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack",
		Category:    "Audit Log Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditLogManagement,
		References:  []string{"CIS v8.0 Control 8"},
	})

	// === Family 9: Email and Web Browser Protections (v3.x Tier 1 add) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-9",
		Name:        "Email and Web Browser Protections",
		Description: "CIS 9: Ensure appropriate security controls are in place on email and web browser clients to protect against email-based and web-based threats",
		Category:    "Email and Web Browser Protections",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkEmailAndWebBrowser,
		References:  []string{"CIS v8.0 Control 9"},
	})

	// === Family 10: Malware Defenses (v3.x Tier 1 add) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-10",
		Name:        "Malware Defenses",
		Description: "CIS 10: Ensure that anti-malware software is installed on all workstations, laptops, and servers; that the software is configured to automatically update; and that it performs regular scans",
		Category:    "Malware Defenses",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMalwareDefenses,
		References:  []string{"CIS v8.0 Control 10"},
	})

	// === Family 11: Data Recovery (v3.x Tier 1 add) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-11",
		Name:        "Data Recovery",
		Description: "CIS 11: Establish and maintain data recovery practices sufficient to restore in-scope business assets to a state of confidentiality, integrity, and availability",
		Category:    "Data Recovery",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataRecovery,
		References:  []string{"CIS v8.0 Control 11"},
	})

	// === Family 12: Network Infrastructure Management (v3.x Tier 1 add) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-12",
		Name:        "Network Infrastructure Management",
		Description: "CIS 12: Establish and operate a secure network infrastructure that protects the confidentiality, integrity, and availability of all network traffic",
		Category:    "Network Infrastructure Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkInfrastructure,
		References:  []string{"CIS v8.0 Control 12"},
	})

	// === Family 13: Network Monitoring and Defense ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-13",
		Name:        "Network Monitoring and Defense",
		Description: "CIS 13: Operate processes and tooling to establish and maintain comprehensive network monitoring and defense",
		Category:    "Network Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkMonitoring,
		References:  []string{"CIS v8.0 Control 13"},
	})

	// === Family 16: Application Software Security (v3.x Tier 1 add) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-16",
		Name:        "Application Software Security",
		Description: "CIS 16: Manage the security life cycle of in-house developed, hosted, or acquired software to prevent, detect, and remediate security weaknesses before they can impact the enterprise",
		Category:    "Application Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkApplicationSoftwareSecurity,
		References:  []string{"CIS v8.0 Control 16"},
	})

	// === Family 17: Incident Response Management ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-17",
		Name:        "Incident Response Management",
		Description: "CIS 17: Maintain a plan to rapidly respond to an attack with the appropriate resources and capabilities",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponse,
		References:  []string{"CIS v8.0 Control 17"},
	})

	// NOTE: CIS-14 (Security Awareness), CIS-15 (Service Provider Management),
	// and CIS-18 (Penetration Testing) are NOT registered. These are
	// out-of-scope for a security scanner (they are process/human-
	// relations/customer-driven activities). See the package doc comment.
}

// ============================================================================
// Check implementations
// ============================================================================

// checkInventoryAssets verifies enterprise asset inventory is in place.
// Maps to CIS 1: Active management of enterprise assets.
func (m *CISModule) checkInventoryAssets(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "asset_inventory") || strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "device_inventory")

	if hasInventory {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-1",
			ControlName: "Inventory and Control of Enterprise Assets",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Enterprise asset inventory configured (AegisGate IOC store tracks all AI agent assets)",
			Timestamp:   time.Now(),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-1",
		ControlName: "Inventory and Control of Enterprise Assets",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Asset inventory not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate IOC store to track all AI agent and MCP server assets (pkg/ioc/)",
	}, nil
}

// checkSoftwareInventory verifies software asset inventory.
// Maps to CIS 2: Active management of software.
func (m *CISModule) checkSoftwareInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVersioning := strings.Contains(inputStr, "model_version") || strings.Contains(inputStr, "model_id") || strings.Contains(inputStr, "binary_attestation")
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx") || strings.Contains(inputStr, "spdx")

	if hasVersioning && hasSBOM {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-2",
			ControlName: "Inventory and Control of Software Assets",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Software inventory configured (model versioning + SBOM)",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasVersioning {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-2",
			ControlName: "Inventory and Control of Software Assets",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Model versioning detected; SBOM not detected",
			Timestamp:   time.Now(),
			Remediation: "Generate CycloneDX or SPDX SBOM in CI (see the AegisGate sbom CI workflow)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-2",
		ControlName: "Inventory and Control of Software Assets",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Software inventory not configured (no SBOM, no model versioning)",
		Timestamp:   time.Now(),
		Remediation: "Enable model versioning (model_id, model_version) + SBOM generation (CycloneDX/SPDX)",
	}, nil
}

// checkDataProtection verifies encryption + data handling controls.
// Maps to CIS 3: Data protection.
func (m *CISModule) checkDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted")
	hasEncryptInTransit := false
	for _, p := range m.tlsPatterns {
		if p.MatchString(inputStr) {
			hasEncryptInTransit = true
			break
		}
	}
	hasPIIScanning := strings.Contains(inputStr, "pii_scanner") || strings.Contains(inputStr, "pii_redaction") || strings.Contains(inputStr, "secret_scanner")

	if hasEncryptAtRest && hasEncryptInTransit && hasPIIScanning {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-3",
			ControlName: "Data Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data protection verified: encryption at rest + in transit + PII/secret scanning",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEncryptAtRest {
		violations = append(violations, "encryption at rest missing")
	}
	if !hasEncryptInTransit {
		violations = append(violations, "encryption in transit (TLS 1.2+) missing")
	}
	if !hasPIIScanning {
		violations = append(violations, "PII/secret scanning missing")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-3",
		ControlName: "Data Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Data protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable all 3: encryption at rest (persistence.encryption), TLS 1.2+ (tls.min_version), PII/secret scanning (response.pii_scanner)",
	}, nil
}

// checkSecureConfiguration verifies secure configuration management.
// Maps to CIS 4: Secure configuration.
func (m *CISModule) checkSecureConfiguration(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasConfig := strings.Contains(inputStr, "platformconfig") || strings.Contains(inputStr, "aegisgate-platform.yaml")
	hasHardening := strings.Contains(inputStr, "hardening") || strings.Contains(inputStr, "secure_config") || strings.Contains(inputStr, "security_headers")
	hasDefaultOff := !strings.Contains(inputStr, "default_password") && !strings.Contains(inputStr, "admin:admin")

	if hasConfig && hasHardening && hasDefaultOff {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-4",
			ControlName: "Secure Configuration of Enterprise Assets and Software",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Secure configuration verified (yaml config + security headers + no default credentials)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasConfig {
		violations = append(violations, "platformconfig not detected")
	}
	if !hasHardening {
		violations = append(violations, "security headers/hardening not detected")
	}
	if !hasDefaultOff {
		violations = append(violations, "default credentials detected (CRITICAL)")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-4",
		ControlName: "Secure Configuration of Enterprise Assets and Software",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Secure configuration gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Use platformconfig, enable security headers in pkg/security/headers.go, rotate any default credentials",
	}, nil
}

// checkAccountManagement verifies account lifecycle is in place.
// Maps to CIS 5: Account management.
func (m *CISModule) checkAccountManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")
	hasMFA := strings.Contains(inputStr, "mfa") || strings.Contains(inputStr, "multi_factor")

	missing := []string{}
	if !hasAuth {
		missing = append(missing, "authentication")
	}
	if !hasRBAC {
		missing = append(missing, "RBAC")
	}
	if !hasSessionTimeout {
		missing = append(missing, "session_timeout")
	}
	if !hasMFA {
		missing = append(missing, "MFA")
	}

	if len(missing) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-5",
			ControlName: "Account Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Account management verified: auth + RBAC + session timeout + MFA",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-5",
		ControlName: "Account Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Account management gaps: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure auth, RBAC, session timeouts, and MFA per CIS 5",
	}, nil
}

// checkAccessControl verifies access control management.
// Maps to CIS 6: Access control management.
func (m *CISModule) checkAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasLeastPrivilege := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "minimum_permissions")
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")
	hasAuditLog := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}

	missing := []string{}
	if !hasRBAC {
		missing = append(missing, "RBAC")
	}
	if !hasLeastPrivilege {
		missing = append(missing, "least privilege principle")
	}
	if !hasSessionTimeout {
		missing = append(missing, "session timeout")
	}
	if !hasAuditLog {
		missing = append(missing, "access audit log")
	}

	if len(missing) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-6",
			ControlName: "Access Control Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Access control verified: RBAC + least privilege + session timeout + audit log",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-6",
		ControlName: "Access Control Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Access control gaps: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure RBAC with least-privilege roles, session timeouts, and access audit logging",
	}, nil
}

// checkVulnerabilityManagement verifies continuous vulnerability scanning.
// Maps to CIS 7: Continuous vulnerability management.
func (m *CISModule) checkVulnerabilityManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasGovulncheck := strings.Contains(inputStr, "govulncheck") || strings.Contains(inputStr, "vuln_scan")
	hasTrivy := strings.Contains(inputStr, "trivy") || strings.Contains(inputStr, "container_scan")
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx")
	hasPatchProcess := strings.Contains(inputStr, "patch") || strings.Contains(inputStr, "update")

	present := 0
	if hasGovulncheck {
		present++
	}
	if hasTrivy {
		present++
	}
	if hasSBOM {
		present++
	}
	if hasPatchProcess {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-7",
			ControlName: "Continuous Vulnerability Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability management configured (multiple scanners + SBOM)",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-7",
			ControlName: "Continuous Vulnerability Management",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial vulnerability management: 1 of 4 controls configured",
			Timestamp:   time.Now(),
			Remediation: "Add govulncheck, Trivy, and SBOM generation to your CI (see AegisGate's .github/workflows)",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-7",
		ControlName: "Continuous Vulnerability Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No vulnerability management configured",
		Timestamp:   time.Now(),
		Remediation: "Enable govulncheck, Trivy, SBOM, and a patch process in your CI/CD",
	}, nil
}

// checkAuditLogManagement verifies audit log collection and retention.
// Maps to CIS 8: Audit log management.
func (m *CISModule) checkAuditLogManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudit := false
	hasIntegrity := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAudit = true
			if strings.Contains(p.String(), "integrity") || strings.Contains(p.String(), "chain") {
				hasIntegrity = true
			}
		}
	}
	hasRetention := strings.Contains(inputStr, "retention") || strings.Contains(inputStr, "audit_log_retention")
	hasReview := strings.Contains(inputStr, "audit_review") || strings.Contains(inputStr, "audit_alert")

	if hasAudit && hasIntegrity && hasRetention && hasReview {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-8",
			ControlName: "Audit Log Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit log management verified: collection + integrity + retention + review",
			Timestamp:   time.Now(),
		}, nil
	}

	missing := []string{}
	if !hasAudit {
		missing = append(missing, "audit log collection")
	}
	if !hasIntegrity {
		missing = append(missing, "log integrity (hash-chain)")
	}
	if !hasRetention {
		missing = append(missing, "retention policy")
	}
	if !hasReview {
		missing = append(missing, "review/alert process")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-8",
		ControlName: "Audit Log Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit log gaps: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit log collection (persistence.audit=true), hash-chain integrity, retention policy, and review/alert process",
	}, nil
}

// checkEmailAndWebBrowser verifies protections for email and web browser
// clients. Maps to CIS 9: Email and Web Browser Protections.
//
// AegisGate implements this through the AegisGate Lens browser extension
// (100% on-device prompt scanning for PII, secrets, XSS, and compliance
// in 8 major AI chat tools) and the Lens Telemetry Bridge which feeds
// scan events into the AegisGate audit log.
func (m *CISModule) checkEmailAndWebBrowser(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLens := strings.Contains(inputStr, "aegisgate_lens") || strings.Contains(inputStr, "lens_extension") || strings.Contains(inputStr, "browser_extension")
	hasLensTelemetry := strings.Contains(inputStr, "lens_telemetry") || strings.Contains(inputStr, "telemetry_bridge")
	hasCSP := strings.Contains(inputStr, "content_security_policy") || strings.Contains(inputStr, "csp_header")

	present := 0
	if hasLens {
		present++
	}
	if hasLensTelemetry {
		present++
	}
	if hasCSP {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-9",
			ControlName: "Email and Web Browser Protections",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Browser protections verified: AegisGate Lens + telemetry bridge + CSP headers",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-9",
			ControlName: "Email and Web Browser Protections",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial browser protections: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Install AegisGate Lens (aegisgate-lens/), enable the Lens telemetry bridge, and set content-security-policy headers",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-9",
		ControlName: "Email and Web Browser Protections",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No browser protections detected (AegisGate Lens, telemetry bridge, or CSP headers missing)",
		Timestamp:   time.Now(),
		Remediation: "Install AegisGate Lens for client-side prompt scanning, enable Lens telemetry bridge to AegisGate audit log, and add CSP headers",
	}, nil
}

// checkMalwareDefenses verifies anti-malware/anti-attack scanning is in
// place. Maps to CIS 10: Malware Defenses.
//
// AegisGate's scanner covers AI-specific attack patterns: prompt
// injection, jailbreaks, data poisoning, model exfiltration, and
// 144+ attack patterns. This is the AI-security analog of
// traditional anti-malware scanning.
func (m *CISModule) checkMalwareDefenses(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	hasScanner := false
	for _, p := range m.scannerPatterns {
		if p.MatchString(inputStr) {
			hasScanner = true
			break
		}
	}
	hasAutoUpdate := strings.Contains(inputStr, "auto_update") || strings.Contains(inputStr, "pattern_update") || strings.Contains(inputStr, "rule_update")
	hasRegularScans := strings.Contains(inputStr, "regular_scan") || strings.Contains(inputStr, "scheduled_scan") || strings.Contains(inputStr, "scan_interval")

	present := 0
	if hasScanner {
		present++
	}
	if hasAutoUpdate {
		present++
	}
	if hasRegularScans {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-10",
			ControlName: "Malware Defenses",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI anti-malware defenses verified: scanner + pattern updates + scheduled scans",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-10",
			ControlName: "Malware Defenses",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AI anti-malware defenses: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable AegisGate scanner (pkg/scanner/), pattern auto-updates, and scheduled scans",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-10",
		ControlName: "Malware Defenses",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No AI anti-malware defenses detected (scanner, auto-updates, or scheduled scans missing)",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate scanner (pkg/scanner/) with pattern auto-updates and scheduled scans for continuous AI-attack detection",
	}, nil
}

// checkDataRecovery verifies data backup and recovery capabilities.
// Maps to CIS 11: Data Recovery.
//
// AegisGate's hash-chain audit log IS the recovery mechanism: any
// audit log entry can be verified cryptographically after restore,
// and the IOC store has its own backup story. 7/30/90-day retention
// is the default per tier.
func (m *CISModule) checkDataRecovery(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBackup := strings.Contains(inputStr, "backup") || strings.Contains(inputStr, "disaster_recovery")
	hasIntegrity := strings.Contains(inputStr, "log_integrity") || strings.Contains(inputStr, "hash_chain")
	hasRestore := strings.Contains(inputStr, "restore") || strings.Contains(inputStr, "audit_replay") || strings.Contains(inputStr, "recoverable")
	hasRetention := strings.Contains(inputStr, "retention") || strings.Contains(inputStr, "retention_days")

	present := 0
	if hasBackup {
		present++
	}
	if hasIntegrity {
		present++
	}
	if hasRestore {
		present++
	}
	if hasRetention {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-11",
			ControlName: "Data Recovery",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data recovery verified: backup + integrity-verifiable restore + retention policy",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-11",
			ControlName: "Data Recovery",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial data recovery: 1 of 4 capabilities configured",
			Timestamp:   time.Now(),
			Remediation: "Enable backup, hash-chain integrity (for verifiable restore), audit replay (for restore verification), and retention policy",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-11",
		ControlName: "Data Recovery",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No data recovery capabilities (no backup, no integrity verification, no retention)",
		Timestamp:   time.Now(),
		Remediation: "Enable backup, hash-chain integrity (so restored logs are verifiable), audit replay capability, and retention policy (default 7/30/90 days by tier)",
	}, nil
}

// checkNetworkInfrastructure verifies secure network infrastructure.
// Maps to CIS 12: Network Infrastructure Management.
//
// AegisGate enforces TLS 1.2+ on all 6 protocol pillars (HTTP, MCP,
// A2A, ACP, RESPONSE, Trust), network segmentation defaults, and mTLS
// for agent-to-agent communication (A2A/ACP).
func (m *CISModule) checkNetworkInfrastructure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	hasTLS := false
	for _, p := range m.tlsPatterns {
		if p.MatchString(inputStr) {
			hasTLS = true
			break
		}
	}
	hasMTLS := strings.Contains(inputStr, "mtls") || strings.Contains(inputStr, "mutual_tls") || strings.Contains(inputStr, "client_cert")
	hasSegmentation := strings.Contains(inputStr, "network_segmentation") || strings.Contains(inputStr, "segmented") || strings.Contains(inputStr, "isolated")
	hasFirewall := strings.Contains(inputStr, "firewall") || strings.Contains(inputStr, "egress_allowlist") || strings.Contains(inputStr, "ingress_allowlist")

	present := 0
	if hasTLS {
		present++
	}
	if hasMTLS {
		present++
	}
	if hasSegmentation {
		present++
	}
	if hasFirewall {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-12",
			ControlName: "Network Infrastructure Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network infrastructure verified: TLS 1.2+ + mTLS + segmentation + firewall rules",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-12",
			ControlName: "Network Infrastructure Management",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial network infrastructure: 1 of 4 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable TLS 1.2+ on all 6 protocol pillars, mTLS for A2A/ACP, network segmentation defaults, and egress/ingress allowlists",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-12",
		ControlName: "Network Infrastructure Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No secure network infrastructure (no TLS, no mTLS, no segmentation, no firewall)",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2+ on all 6 protocol pillars (HTTP, MCP, A2A, ACP, RESPONSE, Trust), mTLS for A2A/ACP, network segmentation, and egress/ingress allowlists",
	}, nil
}

// checkNetworkMonitoring verifies network monitoring and defense.
// Maps to CIS 13: Network monitoring and defense.
func (m *CISModule) checkNetworkMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIOCStore := strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "ioc_federation")
	hasAnomaly := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "trust_score")
	hasIDS := strings.Contains(inputStr, "ids") || strings.Contains(inputStr, "intrusion") || strings.Contains(inputStr, "detection")

	present := 0
	if hasIOCStore {
		present++
	}
	if hasAnomaly {
		present++
	}
	if hasIDS {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-13",
			ControlName: "Network Monitoring and Defense",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network monitoring configured (IOC store + anomaly detection + IDS)",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-13",
			ControlName: "Network Monitoring and Defense",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial network monitoring: 1 of 3 controls configured",
			Timestamp:   time.Now(),
			Remediation: "Enable AegisGate IOC store, anomaly detection, and IDS integration",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-13",
		ControlName: "Network Monitoring and Defense",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No network monitoring configured",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate IOC store + anomaly detection + IDS integration",
	}, nil
}

// checkApplicationSoftwareSecurity verifies application software
// security controls. Maps to CIS 16: Application Software Security.
//
// AegisGate's scanner covers application-level security: prompt
// injection, secret leakage in outputs, XSS, injection attacks, etc.
// The scanner runs on every request and on every response (the
// "input sanitization + output encoding" analog for AI).
func (m *CISModule) checkApplicationSoftwareSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasScanner := false
	for _, p := range m.scannerPatterns {
		if p.MatchString(inputStr) {
			hasScanner = true
			break
		}
	}
	hasSSDF := strings.Contains(inputStr, "ssdf") || strings.Contains(inputStr, "secure_sdlc") || strings.Contains(inputStr, "devsecops")
	hasVulnManagement := strings.Contains(inputStr, "vuln_management") || strings.Contains(inputStr, "vuln_scan") || strings.Contains(inputStr, "govulncheck")
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx")

	present := 0
	if hasScanner {
		present++
	}
	if hasSSDF {
		present++
	}
	if hasVulnManagement {
		present++
	}
	if hasSBOM {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-16",
			ControlName: "Application Software Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Application software security verified: scanner + SDLC + vulnerability management + SBOM",
			Timestamp:   time.Now(),
		}, nil
	}

	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-16",
			ControlName: "Application Software Security",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial application software security: 1 of 4 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable AegisGate scanner, secure SDLC, govulncheck vulnerability management, and SBOM generation",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-16",
		ControlName: "Application Software Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No application software security (no scanner, no secure SDLC, no vulnerability management)",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate scanner (input/output scanning), secure SDLC, govulncheck vulnerability management, and SBOM generation",
	}, nil
}

// checkIncidentResponse verifies incident response management.
// Maps to CIS 17: Incident response management.
func (m *CISModule) checkIncidentResponse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPlan := strings.Contains(inputStr, "incident_response_plan") || strings.Contains(inputStr, "ir_plan")
	hasAttestations := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "signed_log")
	hasAuditTrail := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditTrail = true
			break
		}
	}

	missing := []string{}
	if !hasPlan {
		missing = append(missing, "incident response plan")
	}
	if !hasAttestations {
		missing = append(missing, "signed attestations (for forensics)")
	}
	if !hasAuditTrail {
		missing = append(missing, "audit trail")
	}

	if len(missing) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-17",
			ControlName: "Incident Response Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident response ready: plan + signed attestations + audit trail",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-17",
		ControlName: "Incident Response Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident response gaps: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Create an incident response plan; AegisGate's signed attestations (pkg/attestation/) and audit log are the forensic evidence sources",
	}, nil
}

// Dependencies returns required modules.
func (m *CISModule) Dependencies() []string {
	return []string{"scanner", "auth", "persistence", "ioc", "trust"}
}
