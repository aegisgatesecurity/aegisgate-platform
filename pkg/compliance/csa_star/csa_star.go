// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CSA STAR (Cloud Controls Matrix) Module
// =========================================================================
//
// CSA STAR (Security, Trust, Assurance, and Risk) is the Cloud Security
// Alliance's framework for cloud security assurance. It is required for
// SaaS enterprise sales and is the de facto cloud security certification.
// The 16 Cloud Controls Matrix (CCM) domains provide comprehensive cloud
// security coverage.
//
// Module metadata:
//   - Framework:   "csa_star"
//   - Version:     "1.0" (v3.x Tier 1, new module)
//   - Required tier: Community (free, like CIS/OWASP/NIST CSF)
//   - Pricing:      No separate add-on (bundled with the platform)
//
// Architecture:
//   - csa_star.go:       module wiring, 16 RegisterControl calls,
//                        16 CheckFunc implementations
//   - csa_star_test.go:  unit tests
//
// Coverage: 16 of 16 CCM domains (100% in-scope). All 16 domains are
// scanner-checkable through the same pattern as the other v3.x modules.
//
// Reference: CSA Cloud Controls Matrix v4.0
//            https://cloudsecurityalliance.org/research/cloud-controls-matrix/
//            https://docs.cloudsecurityalliance.org/
// =========================================================================

package csa_star

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// CSASTARModule implements the CSA STAR (Cloud Controls Matrix) compliance
// framework.
type CSASTARModule struct {
	*compliance.BaseComplianceModule
}

// NewCSASTARModule creates a new CSA STAR compliance module.
func NewCSASTARModule() *CSASTARModule {
	m := &CSASTARModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("csa_star", "1.0", core.TierCommunity),
	}
	m.registerControls()
	return m
}

// registerControls wires all 16 CSA STAR (Cloud Controls Matrix) domains
// into the module.
func (m *CSASTARModule) registerControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-AIS",
		Name:        "Application & Interface Security",
		Description: "CCM v4.0 AIS: Application & Interface Security - security of application interfaces and services",
		Category:    "Application & Interface Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkApplicationSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-AAI",
		Name:        "Audit Assurance & Interface",
		Description: "CCM v4.0 AAI: Audit Assurance & Interface - independent audits and assurance",
		Category:    "Audit & Assurance",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditAssurance,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-BCR",
		Name:        "Business Continuity Mgmt & Operational Resilience",
		Description: "CCM v4.0 BCR: Business Continuity Management and Operational Resilience",
		Category:    "Business Continuity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBusinessContinuity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-CBK",
		Name:        "Change Control & Configuration Management",
		Description: "CCM v4.0 CBK: Change Control and Configuration Management",
		Category:    "Change Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeControl,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-CEK",
		Name:        "Cryptography, Encryption & Key Management",
		Description: "CCM v4.0 CEK: Cryptography, Encryption and Key Management",
		Category:    "Cryptography",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCryptography,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-DSP",
		Name:        "Data Security & Privacy",
		Description: "CCM v4.0 DSP: Data Security and Privacy (data classification, PII handling, retention)",
		Category:    "Data Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDataSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-GRC",
		Name:        "Governance, Risk Mgmt & Compliance",
		Description: "CCM v4.0 GRC: Governance, Risk Management and Compliance",
		Category:    "Governance",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkGovernance,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-HRS",
		Name:        "Human Resources Security",
		Description: "CCM v4.0 HRS: Human Resources Security (background checks, onboarding/offboarding)",
		Category:    "Human Resources",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkHRSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-IAM",
		Name:        "Identity & Access Management",
		Description: "CCM v4.0 IAM: Identity and Access Management (RBAC, MFA, least privilege)",
		Category:    "Identity & Access",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIAM,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-IKY",
		Name:        "Interoperability & Portability",
		Description: "CCM v4.0 IKY: Interoperability and Portability (data export, API standards)",
		Category:    "Interoperability",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkInteroperability,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-IPY",
		Name:        "Infrastructure & Platform Security",
		Description: "CCM v4.0 IPY: Infrastructure and Platform Security (network, compute, storage)",
		Category:    "Infrastructure",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInfrastructure,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-IVS",
		Name:        "Inventory & Visibility",
		Description: "CCM v4.0 IVS: Asset Inventory and Visibility (CMDB, asset discovery)",
		Category:    "Inventory",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkInventory,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-LOG",
		Name:        "Logging & Monitoring",
		Description: "CCM v4.0 LOG: Logging and Monitoring (audit log, anomaly detection, alerting)",
		Category:    "Logging",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkLogging,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-STA",
		Name:        "Supply Chain Mgmt, Transparency & Accountability",
		Description: "CCM v4.0 STA: Supply Chain Management, Transparency, and Accountability",
		Category:    "Supply Chain",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSupplyChain,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-SEF",
		Name:        "Security Incident Mgmt, E-Disc & Forensics",
		Description: "CCM v4.0 SEF: Security Incident Management, E-Discovery and Forensics",
		Category:    "Incident Mgmt",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkIncidentManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CSA-STAR-TVM",
		Name:        "Threat & Vulnerability Management",
		Description: "CCM v4.0 TVM: Threat and Vulnerability Management",
		Category:    "Threat & Vuln Mgmt",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkThreatVulnerability,
	})
}

// ============================================================================
// Check implementations (16 controls)
// ============================================================================

// standardSTARCheck is a helper that uses a 2-4 marker pattern to verify
// compliant/partial/non_compliant status.
func (m *CSASTARModule) standardSTARCheck(ctx context.Context, id, name, sevStr string, severity compliance.Severity, input []byte, required []string, message string) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	present := 0
	missing := []string{}
	for _, r := range required {
		if strings.Contains(inputStr, r) {
			present++
		} else {
			missing = append(missing, r)
		}
	}
	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   id,
			ControlName: name,
			Status:      compliance.StatusCompliant,
			Severity:    severity,
			Message:     message + " (compliant)",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   id,
			ControlName: name,
			Status:      compliance.StatusNonCompliant,
			Severity:    severity,
			Message:     message + " (no controls detected; missing: " + strings.Join(missing, ", ") + ")",
			Timestamp:   time.Now(),
			Remediation: "Configure the missing controls: " + strings.Join(missing, ", "),
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   id,
		ControlName: name,
		Status:      compliance.StatusPartial,
		Severity:    severity,
		Message:     message + " (partial: " + csaCount(present) + "/" + csaCount(len(required)) + " configured; missing: " + strings.Join(missing, ", ") + ")",
		Timestamp:   time.Now(),
		Remediation: "Configure the missing controls: " + strings.Join(missing, ", "),
	}, nil
}

// AIS - Application & Interface Security
func (m *CSASTARModule) checkApplicationSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-AIS", "Application & Interface Security", "AIS",
		compliance.SeverityCritical, input,
		[]string{"api_security", "input_validation", "owasp", "sast"},
		"Application & interface security configured")
}

// AAI - Audit Assurance & Interface
func (m *CSASTARModule) checkAuditAssurance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-AAI", "Audit Assurance & Interface", "AAI",
		compliance.SeverityHigh, input,
		[]string{"audit_log", "audit_review", "compliance_check", "audit_report"},
		"Audit assurance configured")
}

// BCR - Business Continuity
func (m *CSASTARModule) checkBusinessContinuity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-BCR", "Business Continuity Mgmt & Operational Resilience", "BCR",
		compliance.SeverityHigh, input,
		[]string{"business_continuity", "disaster_recovery", "redundancy", "backup"},
		"Business continuity configured")
}

// CBK - Change Control & Configuration Management
func (m *CSASTARModule) checkChangeControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-CBK", "Change Control & Configuration Management", "CBK",
		compliance.SeverityHigh, input,
		[]string{"change_management", "config_baseline", "config_drift", "change_approval"},
		"Change control configured")
}

// CEK - Cryptography, Encryption & Key Management
func (m *CSASTARModule) checkCryptography(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-CEK", "Cryptography, Encryption & Key Management", "CEK",
		compliance.SeverityCritical, input,
		[]string{"aes_256", "rsa_2048", "key_management", "key_rotation"},
		"Cryptography configured (AES-256 + RSA-2048 + key management)")
}

// DSP - Data Security & Privacy
func (m *CSASTARModule) checkDataSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-DSP", "Data Security & Privacy", "DSP",
		compliance.SeverityCritical, input,
		[]string{"data_classification", "pii_scanner", "encryption_at_rest", "data_retention"},
		"Data security & privacy configured")
}

// GRC - Governance, Risk Management & Compliance
func (m *CSASTARModule) checkGovernance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-GRC", "Governance, Risk Mgmt & Compliance", "GRC",
		compliance.SeverityHigh, input,
		[]string{"risk_assessment", "compliance_review", "governance_policy", "audit_trail"},
		"Governance configured")
}

// HRS - Human Resources Security
func (m *CSASTARModule) checkHRSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-HRS", "Human Resources Security", "HRS",
		compliance.SeverityMedium, input,
		[]string{"background_check", "security_awareness", "termination_process", "nda"},
		"HR security configured")
}

// IAM - Identity & Access Management
func (m *CSASTARModule) checkIAM(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-IAM", "Identity & Access Management", "IAM",
		compliance.SeverityCritical, input,
		[]string{"rbac", "mfa", "least_privilege", "access_review"},
		"IAM configured (RBAC + MFA + least privilege + access review)")
}

// IKY - Interoperability & Portability
func (m *CSASTARModule) checkInteroperability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-IKY", "Interoperability & Portability", "IKY",
		compliance.SeverityLow, input,
		[]string{"api_standards", "data_export", "open_formats", "portability"},
		"Interoperability & portability configured")
}

// IPY - Infrastructure & Platform Security
func (m *CSASTARModule) checkInfrastructure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-IPY", "Infrastructure & Platform Security", "IPY",
		compliance.SeverityHigh, input,
		[]string{"network_security", "compute_hardening", "storage_encryption", "vulnerability_patching"},
		"Infrastructure security configured")
}

// IVS - Inventory & Visibility
func (m *CSASTARModule) checkInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-IVS", "Inventory & Visibility", "IVS",
		compliance.SeverityMedium, input,
		[]string{"asset_inventory", "cmdb", "asset_discovery", "shadow_it"},
		"Inventory & visibility configured")
}

// LOG - Logging & Monitoring
func (m *CSASTARModule) checkLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-LOG", "Logging & Monitoring", "LOG",
		compliance.SeverityCritical, input,
		[]string{"audit_log", "anomaly_detection", "alerting", "siem"},
		"Logging & monitoring configured")
}

// STA - Supply Chain Management, Transparency & Accountability
func (m *CSASTARModule) checkSupplyChain(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-STA", "Supply Chain Mgmt, Transparency & Accountability", "STA",
		compliance.SeverityHigh, input,
		[]string{"vendor_inventory", "sbom", "vendor_assessment", "supply_chain_monitoring"},
		"Supply chain transparency configured")
}

// SEF - Security Incident Management, E-Discovery & Forensics
func (m *CSASTARModule) checkIncidentManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-SEF", "Security Incident Mgmt, E-Disc & Forensics", "SEF",
		compliance.SeverityCritical, input,
		[]string{"incident_response", "e_discovery", "forensic_log", "evidence_preservation"},
		"Incident management & forensics configured")
}

// TVM - Threat & Vulnerability Management
func (m *CSASTARModule) checkThreatVulnerability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return m.standardSTARCheck(ctx, "CSA-STAR-TVM", "Threat & Vulnerability Management", "TVM",
		compliance.SeverityCritical, input,
		[]string{"vulnerability_scan", "govulncheck", "trivy", "patch_management"},
		"Threat & vulnerability management configured")
}

// csaCount is a small helper to avoid importing strconv.
func csaCount(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-csaCount(-n)"
	}
	digits := "0123456789"
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// Dependencies returns required modules. CSA STAR depends on the scanner
// (for vulnerability management) and the persistence layer (for audit log).
func (m *CSASTARModule) Dependencies() []string {
	return []string{"scanner", "persistence"}
}
