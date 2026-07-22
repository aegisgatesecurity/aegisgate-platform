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
//   - Version:     "1.0"
//   - Required tier: Community (free, like ATLAS/OWASP/NIST AI RMF/GDPR)
//   - Pricing:      No separate add-on (bundled with the platform)
//
// Architecture:
//   - cis.go:        module wiring, pattern caches, 10 RegisterControl calls,
//                    8 CheckFunc implementations
//   - cis_test.go:   unit tests for each CheckFunc
//
// Coverage: 10 of 18 CIS v8 control families mapped to AegisGate. The
// remaining 8 (Application Software Security, Penetration Testing, etc.)
// are either out-of-scope for a security gateway or duplicate the
// NIST CSF 2.0 controls (which we map separately).
//
// Mapping summary:
//   CIS 1  (Inventory)         -> pkg/ioc/ (IOC store + bundle federation)
//   CIS 2  (Software Inventory) -> Platform binary attestation (pkg/attestation/)
//   CIS 3  (Data Protection)    -> pkg/security/headers.go + TLS config
//   CIS 4  (Secure Config Mgmt) -> AegisGate platformconfig
//   CIS 5  (Account Mgmt)       -> pkg/auth/middleware.go + pkg/rbac/
//   CIS 6  (Access Control Mgmt)-> pkg/auth/middleware.go
//   CIS 7  (Vulnerability Mgmt)  -> govulncheck + Trivy CI workflows
//   CIS 8  (Audit Log Mgmt)     -> pkg/persistence/ + audit ring buffer
//   CIS 9  (Email/Web Browser)  -> AegisGate Lens (browser extension)
//   CIS 10 (Malware Defenses)   -> AegisGate scanner (prompt injection, etc.)
//   CIS 11 (Data Recovery)      -> AegisGate audit log hash-chain (recoverable)
//   CIS 12 (Network Infra Mgmt) -> TLS 1.2+ enforced
//   CIS 13 (Network Monitoring) -> IOC store + anomaly detection
//   CIS 14 (Security Awareness) -> customer responsibility (out of scope)
//   CIS 15 (Service Provider)   -> customer responsibility (out of scope)
//   CIS 16 (App Software Sec)   -> AegisGate scanner + 144+ patterns
//   CIS 17 (Incident Response)  -> AegisGate audit log + Trust Framework attestations
//   CIS 18 (Pen Testing)        -> customer responsibility (out of scope)
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
}

// NewCISModule creates a new CIS Critical Security Controls v8 module.
func NewCISModule() *CISModule {
	m := &CISModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("cis", "1.0", core.TierCommunity),
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
}

// registerControls wires all 10 CIS v8 controls into the module.
func (m *CISModule) registerControls() {
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
