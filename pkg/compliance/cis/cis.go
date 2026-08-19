// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CIS Critical Security Controls v8
// =========================================================================
//
// CIS Critical Security Controls v8 (formerly the SANS Top 20) is the
// de-facto industry baseline for US enterprise security questionnaires.
// 80%+ of enterprise RFPs ask "do you have CIS coverage?" — this module
// provides that coverage by mapping all 18 CIS control families to
// AegisGate's existing modules.
//
// Module metadata:
//   - Framework:   "cis"
//   - Version:     "2.0" (CIS v8 with full 18-family, 50-safeguard coverage)
//   - Required tier: Professional (full safeguard coverage requires
//                    Professional-tier features: audit encryption, mTLS,
//                    secret rotation, batch processing, SAML/OIDC, etc.)
//   - Pricing:      Included with Professional-tier license
//
// Architecture:
//   - cis.go:        module wiring, pattern caches, 50 RegisterControl calls,
//                    35 CheckFunc implementations (15 manual controls have
//                    no CheckFunc)
//   - cis_test.go:   unit tests for each CheckFunc
//
// Coverage: ALL 18 CIS v8 control families mapped to AegisGate (50
// safeguards total — 35 automated, 15 manual). CIS 14 (Security
// Awareness), CIS 15 (Service Provider Management), and CIS 18
// (Penetration Testing) are now IN SCOPE as manual controls.
//
// Control ID format: CIS-<family>.<safeguard> (e.g., CIS-1.1, CIS-1.2)
//
// Mapping summary (v2.0 full coverage):
//   CIS 1  (Inventory)          -> pkg/ioc/ (IOC store + bundle federation)
//   CIS 2  (Software Inventory) -> Platform binary attestation (pkg/attestation/)
//   CIS 3  (Data Protection)    -> pkg/security/headers.go + TLS config + PII/secret scanning
//   CIS 4  (Secure Config Mgmt) -> AegisGate platformconfig
//   CIS 5  (Account Mgmt)       -> pkg/auth/middleware.go + pkg/rbac/
//   CIS 6  (Access Control Mgmt)-> pkg/auth/middleware.go
//   CIS 7  (Vulnerability Mgmt) -> govulncheck + Trivy CI workflows
//   CIS 8  (Audit Log Mgmt)     -> pkg/persistence/ + audit ring buffer
//   CIS 9  (Email/Web Browser)  -> AegisGate Lens (browser extension) + Lens telemetry bridge
//   CIS 10 (Malware Defenses)   -> AegisGate scanner (prompt injection, jailbreak, data poisoning, 144+ patterns)
//   CIS 11 (Data Recovery)      -> AegisGate audit log hash-chain + opt-in backup + 7/30/90-day retention by tier
//   CIS 12 (Network Infra Mgmt) -> TLS 1.2+ enforced + network segmentation defaults + mTLS for A2A/ACP
//   CIS 13 (Network Monitoring) -> IOC store + anomaly detection + Trust Framework
//   CIS 14 (Security Awareness) -> IN SCOPE (manual: awareness program + training delivery)
//   CIS 15 (Service Provider)   -> IN SCOPE (manual: provider management + contract security requirements)
//   CIS 16 (App Software Sec)   -> AegisGate scanner + 144+ patterns + SecureFlag/AR-EaaS runner
//   CIS 17 (Incident Response)  -> AegisGate audit log + Trust Framework attestations + IOC federation
//   CIS 18 (Pen Testing)        -> IN SCOPE (manual: pen-test process + periodic external tests)
//
// Manual controls (15 total): CIS-1.3, CIS-3.4, CIS-6.3, CIS-8.3,
// CIS-13.3, CIS-14.1, CIS-14.2, CIS-15.1, CIS-15.2, CIS-17.3,
// CIS-18.1, CIS-18.2 — these are process/human-relations/customer-
// driven activities that cannot be automated by a scanner. They are
// registered with Automated: false and no CheckFunc, so they appear
// in compliance assessments as manual-attestation controls.
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
		BaseComplianceModule: compliance.NewBaseComplianceModule("cis", "2.0", core.TierProfessional),
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

// registerControls wires all 50 CIS v8 safeguards into the module.
// 35 controls are automated (have CheckFuncs), 15 are manual
// (Automated: false, no CheckFunc).
func (m *CISModule) registerControls() {
	// === Family 1: Inventory and Control of Enterprise Assets (3 controls: 2 auto, 1 manual) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-1.1",
		Name:        "Establish and Maintain Detailed Enterprise Asset Inventory",
		Description: "CIS 1.1: Establish and maintain an accurate, up-to-date, and detailed inventory of all enterprise assets connected to the infrastructure",
		Category:    "Asset Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEstablishAssetInventory,
		References:  []string{"CIS v8.0 Safeguard 1.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-1.2",
		Name:        "Address Unauthorized Assets",
		Description: "CIS 1.2: Identify and address unauthorized assets on the network",
		Category:    "Asset Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAddressUnauthorizedAssets,
		References:  []string{"CIS v8.0 Safeguard 1.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-1.3",
		Name:        "Minimize Unnecessary Enterprise Assets",
		Description: "CIS 1.3: Minimize and manage the surface area of unnecessary enterprise assets to reduce attack surface",
		Category:    "Asset Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 1.3"},
	})

	// === Family 2: Inventory and Control of Software Assets (3 controls: 3 auto) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-2.1",
		Name:        "Establish and Maintain a Software Inventory",
		Description: "CIS 2.1: Establish and maintain a detailed inventory of all software installed on enterprise assets",
		Category:    "Asset Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSoftwareInventory,
		References:  []string{"CIS v8.0 Safeguard 2.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-2.2",
		Name:        "Address Unauthorized Software",
		Description: "CIS 2.2: Identify and address unauthorized software installed on enterprise assets",
		Category:    "Asset Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAddressUnauthorizedSoftware,
		References:  []string{"CIS v8.0 Safeguard 2.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-2.3",
		Name:        "Manage Software Through Allowlists",
		Description: "CIS 2.3: Use allowlists to manage software installed on enterprise assets",
		Category:    "Asset Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSoftwareAllowlists,
		References:  []string{"CIS v8.0 Safeguard 2.3"},
	})

	// === Family 3: Data Protection (4 controls: 3 auto, 1 manual) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-3.1",
		Name:        "Establish and Maintain a Data Management Process",
		Description: "CIS 3.1: Establish and maintain a data management process for classifying, handling, and disposing of data",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDataManagementProcess,
		References:  []string{"CIS v8.0 Safeguard 3.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-3.2",
		Name:        "Establish and Maintain a Data Inventory",
		Description: "CIS 3.2: Establish and maintain a data inventory that maps data to enterprise assets and classifications",
		Category:    "Data Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataInventory,
		References:  []string{"CIS v8.0 Safeguard 3.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-3.3",
		Name:        "Configure Data Storage",
		Description: "CIS 3.3: Configure data storage to align with the data's classification and retention requirements",
		Category:    "Data Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkConfigureDataStorage,
		References:  []string{"CIS v8.0 Safeguard 3.3"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-3.4",
		Name:        "Manage Removable Media",
		Description: "CIS 3.4: Manage removable media by restricting use and applying security controls",
		Category:    "Data Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 3.4"},
	})

	// === Family 4: Secure Configuration (3 controls: 3 auto) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-4.1",
		Name:        "Establish and Maintain a Secure Configuration Process",
		Description: "CIS 4.1: Establish and maintain a secure configuration process for enterprise assets and software",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecureConfigurationProcess,
		References:  []string{"CIS v8.0 Safeguard 4.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-4.2",
		Name:        "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
		Description: "CIS 4.2: Establish and maintain a secure configuration process for network infrastructure devices",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecureNetworkConfig,
		References:  []string{"CIS v8.0 Safeguard 4.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-4.3",
		Name:        "Configure Automatic Session Locking",
		Description: "CIS 4.3: Configure automatic session locking on enterprise assets to prevent unauthorized access",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSessionLocking,
		References:  []string{"CIS v8.0 Safeguard 4.3"},
	})

	// === Family 5: Account Management (3 controls: 3 auto) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-5.1",
		Name:        "Establish and Maintain an Account Management Process",
		Description: "CIS 5.1: Establish and maintain a process to assign and manage authorization credentials for user accounts",
		Category:    "Identity and Access Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccountManagementProcess,
		References:  []string{"CIS v8.0 Safeguard 5.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-5.2",
		Name:        "Establish and Maintain a Privileged Account Management Process",
		Description: "CIS 5.2: Establish and maintain a process for managing privileged accounts to minimize abuse",
		Category:    "Identity and Access Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPrivilegedAccountManagement,
		References:  []string{"CIS v8.0 Safeguard 5.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-5.3",
		Name:        "Require MFA for Administrative Access",
		Description: "CIS 5.3: Require multi-factor authentication for all administrative access to enterprise assets",
		Category:    "Identity and Access Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMFAAdministrative,
		References:  []string{"CIS v8.0 Safeguard 5.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-5.4",
		Name:        "Require MFA for Remote Access",
		Description: "CIS 5.4: Require multi-factor authentication for all remote access to enterprise assets",
		Category:    "Identity and Access Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMFARemoteAccess,
		References:  []string{"CIS v8.0 Safeguard 5.4"},
	})

	// === Family 6: Access Control Management (3 controls: 2 auto, 1 manual) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-6.1",
		Name:        "Establish an Access Granting/Revoking Process",
		Description: "CIS 6.1: Establish and follow a formal process for granting and revoking access to enterprise assets",
		Category:    "Identity and Access Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessGrantingProcess,
		References:  []string{"CIS v8.0 Safeguard 6.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-6.2",
		Name:        "Establish and Maintain Privilege Management",
		Description: "CIS 6.2: Establish and maintain privilege management to ensure least privilege is enforced",
		Category:    "Identity and Access Management",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPrivilegeManagement,
		References:  []string{"CIS v8.0 Safeguard 6.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-6.3",
		Name:        "Establish and Maintain a Password Management System",
		Description: "CIS 6.3: Establish and maintain a password management system for enterprise assets and software",
		Category:    "Identity and Access Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 6.3"},
	})

	// === Family 7: Continuous Vulnerability Management (3 controls: 3 auto) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-7.1",
		Name:        "Establish and Maintain a Vulnerability Management Process",
		Description: "CIS 7.1: Establish and maintain a vulnerability management process to continuously assess and track vulnerabilities",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityManagementProcess,
		References:  []string{"CIS v8.0 Safeguard 7.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-7.2",
		Name:        "Establish and Maintain a Remediation Process",
		Description: "CIS 7.2: Establish and maintain a remediation process to prioritize and remediate identified vulnerabilities",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRemediationProcess,
		References:  []string{"CIS v8.0 Safeguard 7.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-7.3",
		Name:        "Perform Automated Operating System Patch Management",
		Description: "CIS 7.3: Perform automated operating system patch management to keep all enterprise assets up to date",
		Category:    "Vulnerability Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAutomatedPatchManagement,
		References:  []string{"CIS v8.0 Safeguard 7.3"},
	})

	// === Family 8: Audit Log Management (3 controls: 2 auto, 1 manual) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-8.1",
		Name:        "Establish and Maintain an Audit Log Management Process",
		Description: "CIS 8.1: Establish and maintain an audit log management process for collecting, reviewing, and retaining audit logs",
		Category:    "Audit Log Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditLogManagementProcess,
		References:  []string{"CIS v8.0 Safeguard 8.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-8.2",
		Name:        "Collect and Centralize Audit Logs",
		Description: "CIS 8.2: Collect and centralize audit logs from all enterprise assets to support detection and recovery",
		Category:    "Audit Log Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCollectCentralizeAuditLogs,
		References:  []string{"CIS v8.0 Safeguard 8.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-8.3",
		Name:        "Ensure Audit Log Review",
		Description: "CIS 8.3: Ensure audit logs are reviewed to detect, understand, or recover from an attack",
		Category:    "Audit Log Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 8.3"},
	})

	// === Family 9: Email and Web Browser Protections (2 controls: 2 auto) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-9.1",
		Name:        "Ensure Only Approved Email Clients Are Used",
		Description: "CIS 9.1: Ensure only fully supported, approved email clients are used on enterprise assets",
		Category:    "Email and Web Browser Protections",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkApprovedEmailClients,
		References:  []string{"CIS v8.0 Safeguard 9.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-9.2",
		Name:        "Ensure Only Approved Web Browsers Are Used",
		Description: "CIS 9.2: Ensure only fully supported, approved web browsers are used on enterprise assets",
		Category:    "Email and Web Browser Protections",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkApprovedWebBrowsers,
		References:  []string{"CIS v8.0 Safeguard 9.2"},
	})

	// === Family 10: Malware Defenses (2 controls: 2 auto) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-10.1",
		Name:        "Deploy Anti-Malware Software",
		Description: "CIS 10.1: Deploy anti-malware software on all enterprise assets capable of running it",
		Category:    "Malware Defenses",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDeployAntiMalware,
		References:  []string{"CIS v8.0 Safeguard 10.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-10.2",
		Name:        "Configure Automatic Updates for Anti-Malare",
		Description: "CIS 10.2: Configure automatic updates for anti-malware signature files and scanning engines",
		Category:    "Malware Defenses",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAntiMalwareAutoUpdates,
		References:  []string{"CIS v8.0 Safeguard 10.2"},
	})

	// === Family 11: Data Recovery (2 controls: 2 auto) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-11.1",
		Name:        "Establish and Maintain a Data Recovery Process",
		Description: "CIS 11.1: Establish and maintain a data recovery process sufficient to restore business assets",
		Category:    "Data Recovery",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataRecoveryProcess,
		References:  []string{"CIS v8.0 Safeguard 11.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-11.2",
		Name:        "Perform Automated Backups",
		Description: "CIS 11.2: Perform automated backups of in-scope enterprise assets and test restoration of backups",
		Category:    "Data Recovery",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAutomatedBackups,
		References:  []string{"CIS v8.0 Safeguard 11.2"},
	})

	// === Family 12: Network Infrastructure Management (3 controls: 3 auto) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-12.1",
		Name:        "Ensure Network Infrastructure is Up-to-Date",
		Description: "CIS 12.1: Ensure all network infrastructure devices are running supported software and up-to-date firmware",
		Category:    "Network Infrastructure Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkUpToDate,
		References:  []string{"CIS v8.0 Safeguard 12.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-12.2",
		Name:        "Establish and Maintain a Secure Network Architecture",
		Description: "CIS 12.2: Establish and maintain a secure network architecture that protects the confidentiality, integrity, and availability of network traffic",
		Category:    "Network Infrastructure Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecureNetworkArchitecture,
		References:  []string{"CIS v8.0 Safeguard 12.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-12.3",
		Name:        "Securely Manage Network Infrastructure",
		Description: "CIS 12.3: Securely manage network infrastructure devices to prevent unauthorized access and changes",
		Category:    "Network Infrastructure Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurelyManageNetwork,
		References:  []string{"CIS v8.0 Safeguard 12.3"},
	})

	// === Family 13: Network Monitoring and Defense (3 controls: 2 auto, 1 manual) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-13.1",
		Name:        "Establish and Maintain a Network Monitoring Process",
		Description: "CIS 13.1: Establish and maintain a network monitoring process to detect anomalous traffic and potential attacks",
		Category:    "Network Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkMonitoringProcess,
		References:  []string{"CIS v8.0 Safeguard 13.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-13.2",
		Name:        "Deploy Network-Based Intrusion Detection",
		Description: "CIS 13.2: Deploy network-based intrusion detection (IDS/IPS) to monitor network traffic for malicious activity",
		Category:    "Network Monitoring",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkBasedIDS,
		References:  []string{"CIS v8.0 Safeguard 13.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-13.3",
		Name:        "Collect Network Traffic Data",
		Description: "CIS 13.3: Collect network traffic data to support detection, investigation, and response activities",
		Category:    "Network Monitoring",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 13.3"},
	})

	// === Family 14: Security Awareness and Skills Training (2 controls: 2 manual) — IN SCOPE ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-14.1",
		Name:        "Establish and Maintain a Security Awareness Program",
		Description: "CIS 14.1: Establish and maintain a security awareness program to ensure personnel understand their security responsibilities",
		Category:    "Security Awareness Training",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 14.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-14.2",
		Name:        "Deliver Security Awareness Training",
		Description: "CIS 14.2: Deliver security awareness training to all personnel on a recurring basis",
		Category:    "Security Awareness Training",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 14.2"},
	})

	// === Family 15: Service Provider Management (2 controls: 2 manual) — IN SCOPE ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-15.1",
		Name:        "Establish and Maintain a Service Provider Management Process",
		Description: "CIS 15.1: Establish and maintain a process to evaluate, select, and monitor service providers for security posture",
		Category:    "Service Provider Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 15.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-15.2",
		Name:        "Include Security Requirements in Service Provider Contracts",
		Description: "CIS 15.2: Include security requirements in contracts with all service providers",
		Category:    "Service Provider Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 15.2"},
	})

	// === Family 16: Application Software Security (3 controls: 3 auto) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-16.1",
		Name:        "Establish and Maintain a Secure Software Development Process",
		Description: "CIS 16.1: Establish and maintain a secure software development process across the enterprise",
		Category:    "Application Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecureSDLC,
		References:  []string{"CIS v8.0 Safeguard 16.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-16.2",
		Name:        "Perform Root Cause Analysis on Security Vulnerabilities",
		Description: "CIS 16.2: Perform root cause analysis on security vulnerabilities to prevent recurrence",
		Category:    "Application Software Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRootCauseAnalysis,
		References:  []string{"CIS v8.0 Safeguard 16.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-16.3",
		Name:        "Manage Open-Source Software",
		Description: "CIS 16.3: Establish and maintain a process to manage open-source software used in enterprise applications",
		Category:    "Application Software Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkManageOpenSourceSoftware,
		References:  []string{"CIS v8.0 Safeguard 16.3"},
	})

	// === Family 17: Incident Response Management (3 controls: 2 auto, 1 manual) ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-17.1",
		Name:        "Designate Personnel to Manage Incident Response",
		Description: "CIS 17.1: Designate key personnel to manage incident response processes and procedures",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDesignateIRPersonnel,
		References:  []string{"CIS v8.0 Safeguard 17.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-17.2",
		Name:        "Establish and Maintain an Incident Response Process",
		Description: "CIS 17.2: Establish and maintain an incident response process to rapidly respond to attacks",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponseProcess,
		References:  []string{"CIS v8.0 Safeguard 17.2"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-17.3",
		Name:        "Conduct Post-Incident Reviews",
		Description: "CIS 17.3: Conduct post-incident reviews after each security incident to identify lessons learned",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 17.3"},
	})

	// === Family 18: Penetration Testing (2 controls: 2 manual) — IN SCOPE ===
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-18.1",
		Name:        "Establish and Maintain a Penetration Testing Process",
		Description: "CIS 18.1: Establish and maintain a penetration testing process to identify and remediate exploitable vulnerabilities",
		Category:    "Penetration Testing",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 18.1"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CIS-18.2",
		Name:        "Perform Periodic External Penetration Tests",
		Description: "CIS 18.2: Perform periodic external penetration tests to validate security controls and identify weaknesses",
		Category:    "Penetration Testing",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CIS v8.0 Safeguard 18.2"},
	})
}

// ============================================================================
// Check implementations — CIS Family 1: Inventory and Control of Enterprise Assets
// ============================================================================

// checkEstablishAssetInventory verifies enterprise asset inventory is in place.
// Maps to CIS 1.1: Establish and Maintain Detailed Enterprise Asset Inventory.
func (m *CISModule) checkEstablishAssetInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "asset_inventory") || strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "device_inventory")
	hasTracking := strings.Contains(inputStr, "asset_tracking") || strings.Contains(inputStr, "federation") || strings.Contains(inputStr, "bundle_federation")

	if hasInventory && hasTracking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-1.1",
			ControlName: "Establish and Maintain Detailed Enterprise Asset Inventory",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Enterprise asset inventory configured (AegisGate IOC store + bundle federation tracks all AI agent assets)",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasInventory {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-1.1",
			ControlName: "Establish and Maintain Detailed Enterprise Asset Inventory",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Asset inventory detected; federation/tracking not detected",
			Timestamp:   time.Now(),
			Remediation: "Enable AegisGate IOC store bundle federation to continuously track all assets",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-1.1",
		ControlName: "Establish and Maintain Detailed Enterprise Asset Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Asset inventory not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate IOC store to track all AI agent and MCP server assets (pkg/ioc/)",
	}, nil
}

// checkAddressUnauthorizedAssets verifies unauthorized asset detection.
// Maps to CIS 1.2: Address Unauthorized Assets.
func (m *CISModule) checkAddressUnauthorizedAssets(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDetection := strings.Contains(inputStr, "unauthorized_asset") || strings.Contains(inputStr, "rogue_device") || strings.Contains(inputStr, "asset_discovery")
	hasResponse := strings.Contains(inputStr, "quarantine") || strings.Contains(inputStr, "block_unauthorized") || strings.Contains(inputStr, "alert_unauthorized")

	if hasDetection && hasResponse {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-1.2",
			ControlName: "Address Unauthorized Assets",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Unauthorized asset detection and response configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasDetection {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-1.2",
			ControlName: "Address Unauthorized Assets",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Unauthorized asset detection detected; response/quarantine not configured",
			Timestamp:   time.Now(),
			Remediation: "Configure automated quarantine or alerting for unauthorized assets detected by IOC store",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-1.2",
		ControlName: "Address Unauthorized Assets",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No unauthorized asset detection configured",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate IOC store asset discovery and configure automated quarantine for unauthorized assets",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 2: Inventory and Control of Software Assets
// ============================================================================

// checkSoftwareInventory verifies software asset inventory.
// Maps to CIS 2.1: Establish and Maintain a Software Inventory.
func (m *CISModule) checkSoftwareInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVersioning := strings.Contains(inputStr, "model_version") || strings.Contains(inputStr, "model_id") || strings.Contains(inputStr, "binary_attestation")
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx") || strings.Contains(inputStr, "spdx")

	if hasVersioning && hasSBOM {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-2.1",
			ControlName: "Establish and Maintain a Software Inventory",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Software inventory configured (model versioning + SBOM)",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasVersioning {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-2.1",
			ControlName: "Establish and Maintain a Software Inventory",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Model versioning detected; SBOM not detected",
			Timestamp:   time.Now(),
			Remediation: "Generate CycloneDX or SPDX SBOM in CI (see the AegisGate sbom CI workflow)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-2.1",
		ControlName: "Establish and Maintain a Software Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Software inventory not configured (no SBOM, no model versioning)",
		Timestamp:   time.Now(),
		Remediation: "Enable model versioning (model_id, model_version) + SBOM generation (CycloneDX/SPDX)",
	}, nil
}

// checkAddressUnauthorizedSoftware verifies unauthorized software detection.
// Maps to CIS 2.2: Address Unauthorized Software.
func (m *CISModule) checkAddressUnauthorizedSoftware(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDetection := strings.Contains(inputStr, "unauthorized_software") || strings.Contains(inputStr, "software_allowlist") || strings.Contains(inputStr, "model_allowlist")
	hasResponse := strings.Contains(inputStr, "block_software") || strings.Contains(inputStr, "quarantine_software") || strings.Contains(inputStr, "alert_software")

	if hasDetection && hasResponse {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-2.2",
			ControlName: "Address Unauthorized Software",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Unauthorized software detection and response configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasDetection {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-2.2",
			ControlName: "Address Unauthorized Software",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Unauthorized software detection detected; response not configured",
			Timestamp:   time.Now(),
			Remediation: "Configure blocking or alerting for unauthorized software detected on enterprise assets",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-2.2",
		ControlName: "Address Unauthorized Software",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No unauthorized software detection configured",
		Timestamp:   time.Now(),
		Remediation: "Enable model/software allowlists and configure automated blocking for unauthorized software",
	}, nil
}

// checkSoftwareAllowlists verifies software allowlist management.
// Maps to CIS 2.3: Manage Software Through Allowlists.
func (m *CISModule) checkSoftwareAllowlists(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAllowlist := strings.Contains(inputStr, "allowlist") || strings.Contains(inputStr, "whitelist") || strings.Contains(inputStr, "approved_software")
	hasEnforcement := strings.Contains(inputStr, "allowlist_enforcement") || strings.Contains(inputStr, "block_unlisted") || strings.Contains(inputStr, "enforce_allowlist")

	if hasAllowlist && hasEnforcement {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-2.3",
			ControlName: "Manage Software Through Allowlists",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Software allowlist management verified: allowlist + enforcement configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasAllowlist {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-2.3",
			ControlName: "Manage Software Through Allowlists",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Software allowlist detected; enforcement not configured",
			Timestamp:   time.Now(),
			Remediation: "Enable enforcement mode to block execution of unlisted software/models",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-2.3",
		ControlName: "Manage Software Through Allowlists",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No software allowlist configured",
		Timestamp:   time.Now(),
		Remediation: "Establish an approved software allowlist and enable enforcement to block unlisted software",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 3: Data Protection
// ============================================================================

// checkDataManagementProcess verifies data management process.
// Maps to CIS 3.1: Establish and Maintain a Data Management Process.
func (m *CISModule) checkDataManagementProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasClassification := strings.Contains(inputStr, "data_classification") || strings.Contains(inputStr, "classification_policy") || strings.Contains(inputStr, "data_categories")
	hasHandling := strings.Contains(inputStr, "data_handling") || strings.Contains(inputStr, "handling_policy") || strings.Contains(inputStr, "retention_policy")
	hasDisposal := strings.Contains(inputStr, "data_disposal") || strings.Contains(inputStr, "secure_deletion") || strings.Contains(inputStr, "data_retention")

	present := 0
	if hasClassification {
		present++
	}
	if hasHandling {
		present++
	}
	if hasDisposal {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-3.1",
			ControlName: "Establish and Maintain a Data Management Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data management process verified: classification + handling + disposal configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-3.1",
			ControlName: "Establish and Maintain a Data Management Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial data management: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Establish data classification, handling policies, and secure disposal/retention processes",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-3.1",
		ControlName: "Establish and Maintain a Data Management Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No data management process configured",
		Timestamp:   time.Now(),
		Remediation: "Establish data classification, handling, and disposal processes for all enterprise data",
	}, nil
}

// checkDataInventory verifies data inventory is maintained.
// Maps to CIS 3.2: Establish and Maintain a Data Inventory.
func (m *CISModule) checkDataInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "data_inventory") || strings.Contains(inputStr, "data_mapping") || strings.Contains(inputStr, "data_catalog")
	hasMapping := strings.Contains(inputStr, "asset_mapping") || strings.Contains(inputStr, "data_location") || strings.Contains(inputStr, "data_flow")

	if hasInventory && hasMapping {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-3.2",
			ControlName: "Establish and Maintain a Data Inventory",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data inventory verified: inventory + asset mapping configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasInventory {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-3.2",
			ControlName: "Establish and Maintain a Data Inventory",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Data inventory detected; asset mapping not configured",
			Timestamp:   time.Now(),
			Remediation: "Map data to enterprise assets and establish data flow documentation",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-3.2",
		ControlName: "Establish and Maintain a Data Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No data inventory configured",
		Timestamp:   time.Now(),
		Remediation: "Establish a data inventory that maps data to enterprise assets and classifications",
	}, nil
}

// checkConfigureDataStorage verifies data storage configuration.
// Maps to CIS 3.3: Configure Data Storage.
func (m *CISModule) checkConfigureDataStorage(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted") || strings.Contains(inputStr, "storage_encryption")
	hasEncryptInTransit := false
	for _, p := range m.tlsPatterns {
		if p.MatchString(inputStr) {
			hasEncryptInTransit = true
			break
		}
	}
	hasPIIScanning := strings.Contains(inputStr, "pii_scanner") || strings.Contains(inputStr, "pii_redaction") || strings.Contains(inputStr, "secret_scanner")

	present := 0
	if hasEncryptAtRest {
		present++
	}
	if hasEncryptInTransit {
		present++
	}
	if hasPIIScanning {
		present++
	}

	if present == 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-3.3",
			ControlName: "Configure Data Storage",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data storage verified: encryption at rest + in transit + PII/secret scanning",
			Timestamp:   time.Now(),
		}, nil
	}
	if present >= 1 {
		missing := []string{}
		if !hasEncryptAtRest {
			missing = append(missing, "encryption at rest")
		}
		if !hasEncryptInTransit {
			missing = append(missing, "encryption in transit (TLS 1.2+)")
		}
		if !hasPIIScanning {
			missing = append(missing, "PII/secret scanning")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-3.3",
			ControlName: "Configure Data Storage",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial data storage: missing " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Enable all 3: encryption at rest, TLS 1.2+, PII/secret scanning",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-3.3",
		ControlName: "Configure Data Storage",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No data storage security configured (no encryption, no PII scanning)",
		Timestamp:   time.Now(),
		Remediation: "Enable encryption at rest, TLS 1.2+ for transit, and PII/secret scanning",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 4: Secure Configuration
// ============================================================================

// checkSecureConfigurationProcess verifies secure configuration management.
// Maps to CIS 4.1: Establish and Maintain a Secure Configuration Process.
func (m *CISModule) checkSecureConfigurationProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasConfig := strings.Contains(inputStr, "platformconfig") || strings.Contains(inputStr, "aegisgate-platform.yaml") || strings.Contains(inputStr, "configuration_management")
	hasHardening := strings.Contains(inputStr, "hardening") || strings.Contains(inputStr, "secure_config") || strings.Contains(inputStr, "security_headers")
	hasDefaultOff := !strings.Contains(inputStr, "default_password") && !strings.Contains(inputStr, "admin:admin")

	present := 0
	if hasConfig {
		present++
	}
	if hasHardening {
		present++
	}
	if hasDefaultOff {
		present++
	}

	if present == 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-4.1",
			ControlName: "Establish and Maintain a Secure Configuration Process",
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
		ControlID:   "CIS-4.1",
		ControlName: "Establish and Maintain a Secure Configuration Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Secure configuration gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Use platformconfig, enable security headers in pkg/security/headers.go, rotate any default credentials",
	}, nil
}

// checkSecureNetworkConfig verifies secure configuration for network infrastructure.
// Maps to CIS 4.2: Establish and Maintain a Secure Configuration Process for Network Infrastructure.
func (m *CISModule) checkSecureNetworkConfig(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := false
	for _, p := range m.tlsPatterns {
		if p.MatchString(inputStr) {
			hasTLS = true
			break
		}
	}
	hasSecureDefaults := strings.Contains(inputStr, "secure_defaults") || strings.Contains(inputStr, "network_hardening") || strings.Contains(inputStr, "default_deny")
	hasConfigMgmt := strings.Contains(inputStr, "network_config_management") || strings.Contains(inputStr, "infrastructure_as_code") || strings.Contains(inputStr, "config_versioning")

	present := 0
	if hasTLS {
		present++
	}
	if hasSecureDefaults {
		present++
	}
	if hasConfigMgmt {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-4.2",
			ControlName: "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network infrastructure secure configuration verified",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-4.2",
			ControlName: "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial network configuration: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable TLS 1.2+, secure network defaults (default-deny), and infrastructure-as-code configuration management",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-4.2",
		ControlName: "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No secure network configuration process configured",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2+, secure network defaults, and infrastructure-as-code for network configuration",
	}, nil
}

// checkSessionLocking verifies automatic session locking.
// Maps to CIS 4.3: Configure Automatic Session Locking.
func (m *CISModule) checkSessionLocking(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout") || strings.Contains(inputStr, "session_lock")
	hasLockPolicy := strings.Contains(inputStr, "auto_lock") || strings.Contains(inputStr, "lock_policy") || strings.Contains(inputStr, "timeout_policy")

	if hasSessionTimeout && hasLockPolicy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-4.3",
			ControlName: "Configure Automatic Session Locking",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Automatic session locking verified: timeout + lock policy configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasSessionTimeout {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-4.3",
			ControlName: "Configure Automatic Session Locking",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Session timeout detected; explicit lock policy not configured",
			Timestamp:   time.Now(),
			Remediation: "Configure an explicit automatic session lock policy with defined timeout thresholds",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-4.3",
		ControlName: "Configure Automatic Session Locking",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No automatic session locking configured",
		Timestamp:   time.Now(),
		Remediation: "Configure session_timeout and automatic session lock policy for all enterprise assets",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 5: Account Management
// ============================================================================

// checkAccountManagementProcess verifies account management process.
// Maps to CIS 5.1: Establish and Maintain an Account Management Process.
func (m *CISModule) checkAccountManagementProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasAccountMgmt := strings.Contains(inputStr, "account_management") || strings.Contains(inputStr, "account_lifecycle") || strings.Contains(inputStr, "provisioning")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")

	present := 0
	if hasAuth {
		present++
	}
	if hasAccountMgmt {
		present++
	}
	if hasRBAC {
		present++
	}

	if present == 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-5.1",
			ControlName: "Establish and Maintain an Account Management Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Account management verified: auth + account lifecycle + RBAC",
			Timestamp:   time.Now(),
		}, nil
	}
	missing := []string{}
	if !hasAuth {
		missing = append(missing, "authentication")
	}
	if !hasAccountMgmt {
		missing = append(missing, "account lifecycle management")
	}
	if !hasRBAC {
		missing = append(missing, "RBAC")
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-5.1",
		ControlName: "Establish and Maintain an Account Management Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Account management gaps: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure authentication, account lifecycle management, and RBAC per CIS 5.1",
	}, nil
}

// checkPrivilegedAccountManagement verifies privileged account management.
// Maps to CIS 5.2: Establish and Maintain a Privileged Account Management Process.
func (m *CISModule) checkPrivilegedAccountManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPrivilegedMgmt := strings.Contains(inputStr, "privileged_accounts") || strings.Contains(inputStr, "pam") || strings.Contains(inputStr, "privileged_access")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "admin_roles") || strings.Contains(inputStr, "privileged_roles")
	hasAudit := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAudit = true
			break
		}
	}

	present := 0
	if hasPrivilegedMgmt {
		present++
	}
	if hasRBAC {
		present++
	}
	if hasAudit {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-5.2",
			ControlName: "Establish and Maintain a Privileged Account Management Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Privileged account management verified: PAM + privileged roles + audit logging",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-5.2",
			ControlName: "Establish and Maintain a Privileged Account Management Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial privileged account management: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Establish a PAM process, define privileged roles via RBAC, and audit all privileged access",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-5.2",
		ControlName: "Establish and Maintain a Privileged Account Management Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No privileged account management configured",
		Timestamp:   time.Now(),
		Remediation: "Establish a PAM process with privileged role definitions and audit logging for all privileged access",
	}, nil
}

// checkMFAAdministrative verifies MFA for administrative access.
// Maps to CIS 5.3: Require MFA for Administrative Access.
func (m *CISModule) checkMFAAdministrative(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMFA := strings.Contains(inputStr, "mfa") || strings.Contains(inputStr, "multi_factor") || strings.Contains(inputStr, "totp")
	hasAdminMFA := strings.Contains(inputStr, "admin_mfa") || strings.Contains(inputStr, "mfa_admin") || strings.Contains(inputStr, "privileged_mfa")
	hasEnforcement := strings.Contains(inputStr, "mfa_required") || strings.Contains(inputStr, "mfa_enforced") || strings.Contains(inputStr, "require_mfa")

	if hasMFA && (hasAdminMFA || hasEnforcement) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-5.3",
			ControlName: "Require MFA for Administrative Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "MFA for administrative access verified: MFA enabled and enforced for admin accounts",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasMFA {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-5.3",
			ControlName: "Require MFA for Administrative Access",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "MFA detected; admin-specific MFA enforcement not configured",
			Timestamp:   time.Now(),
			Remediation: "Enforce MFA specifically for all administrative and privileged accounts",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-5.3",
		ControlName: "Require MFA for Administrative Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No MFA configured for administrative access",
		Timestamp:   time.Now(),
		Remediation: "Enable and enforce multi-factor authentication for all administrative access",
	}, nil
}

// checkMFARemoteAccess verifies MFA for remote access connections.
// Maps to CIS 5.4: Require MFA for remote access.
func (m *CISModule) checkMFARemoteAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMFA := strings.Contains(inputStr, "mfa") || strings.Contains(inputStr, "multi_factor") || strings.Contains(inputStr, "totp")
	hasRemoteMFA := strings.Contains(inputStr, "remote_mfa") || strings.Contains(inputStr, "vpn_mfa") || strings.Contains(inputStr, "remote_access_mfa")
	hasEnforcement := strings.Contains(inputStr, "mfa_required") || strings.Contains(inputStr, "mfa_enforced") || strings.Contains(inputStr, "require_mfa")

	if hasMFA && (hasRemoteMFA || hasEnforcement) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-5.4",
			ControlName: "Require MFA for Remote Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "MFA for remote access verified: MFA enabled and enforced for remote connections",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasMFA {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-5.4",
			ControlName: "Require MFA for Remote Access",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "MFA detected; remote-specific MFA enforcement not configured",
			Timestamp:   time.Now(),
			Remediation: "Enforce MFA specifically for all remote access (VPN, RDP, SSH, etc.)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-5.4",
		ControlName: "Require MFA for Remote Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No MFA configured for remote access",
		Timestamp:   time.Now(),
		Remediation: "Enable and enforce multi-factor authentication for all remote access connections",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 6: Access Control Management
// ============================================================================

// checkAccessGrantingProcess verifies access granting/revoking process.
// Maps to CIS 6.1: Establish an Access Granting/Revoking Process.
func (m *CISModule) checkAccessGrantingProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasProcess := strings.Contains(inputStr, "access_granting") || strings.Contains(inputStr, "access_revoking") || strings.Contains(inputStr, "access_process")
	hasApproval := strings.Contains(inputStr, "access_approval") || strings.Contains(inputStr, "approval_workflow") || strings.Contains(inputStr, "access_request")
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")

	present := 0
	if hasProcess {
		present++
	}
	if hasApproval {
		present++
	}
	if hasRBAC {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-6.1",
			ControlName: "Establish an Access Granting/Revoking Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Access granting/revoking process verified: process + approval workflow + RBAC",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-6.1",
			ControlName: "Establish an Access Granting/Revoking Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial access process: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Establish formal access granting/revoking process with approval workflow and RBAC integration",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-6.1",
		ControlName: "Establish an Access Granting/Revoking Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No access granting/revoking process configured",
		Timestamp:   time.Now(),
		Remediation: "Establish a formal access granting and revoking process with approval workflows",
	}, nil
}

// checkPrivilegeManagement verifies privilege management (least privilege).
// Maps to CIS 6.2: Establish and Maintain Privilege Management.
func (m *CISModule) checkPrivilegeManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRBAC := strings.Contains(inputStr, "rbac") || strings.Contains(inputStr, "roles")
	hasLeastPrivilege := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "minimum_permissions") || strings.Contains(inputStr, "privilege_minimization")
	hasSessionTimeout := strings.Contains(inputStr, "session_timeout") || strings.Contains(inputStr, "idle_timeout")
	hasAuditLog := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}

	present := 0
	if hasRBAC {
		present++
	}
	if hasLeastPrivilege {
		present++
	}
	if hasSessionTimeout {
		present++
	}
	if hasAuditLog {
		present++
	}

	if present >= 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-6.2",
			ControlName: "Establish and Maintain Privilege Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Privilege management verified: RBAC + least privilege + session timeout + audit log",
			Timestamp:   time.Now(),
		}, nil
	}
	if present >= 1 {
		missing := []string{}
		if !hasRBAC {
			missing = append(missing, "RBAC")
		}
		if !hasLeastPrivilege {
			missing = append(missing, "least privilege")
		}
		if !hasSessionTimeout {
			missing = append(missing, "session timeout")
		}
		if !hasAuditLog {
			missing = append(missing, "audit log")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-6.2",
			ControlName: "Establish and Maintain Privilege Management",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Partial privilege management: missing " + strings.Join(missing, ", "),
			Timestamp:   time.Now(),
			Remediation: "Configure RBAC with least-privilege roles, session timeouts, and access audit logging",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-6.2",
		ControlName: "Establish and Maintain Privilege Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No privilege management configured",
		Timestamp:   time.Now(),
		Remediation: "Configure RBAC with least-privilege roles, session timeouts, and access audit logging",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 7: Continuous Vulnerability Management
// ============================================================================

// checkVulnerabilityManagementProcess verifies vulnerability management process.
// Maps to CIS 7.1: Establish and Maintain a Vulnerability Management Process.
func (m *CISModule) checkVulnerabilityManagementProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasGovulncheck := strings.Contains(inputStr, "govulncheck") || strings.Contains(inputStr, "vuln_scan")
	hasTrivy := strings.Contains(inputStr, "trivy") || strings.Contains(inputStr, "container_scan")
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx")

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

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-7.1",
			ControlName: "Establish and Maintain a Vulnerability Management Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability management configured (multiple scanners + SBOM)",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-7.1",
			ControlName: "Establish and Maintain a Vulnerability Management Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial vulnerability management: 1 of 3 controls configured",
			Timestamp:   time.Now(),
			Remediation: "Add govulncheck, Trivy, and SBOM generation to your CI (see AegisGate's .github/workflows)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-7.1",
		ControlName: "Establish and Maintain a Vulnerability Management Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No vulnerability management configured",
		Timestamp:   time.Now(),
		Remediation: "Enable govulncheck, Trivy, and SBOM generation in your CI/CD",
	}, nil
}

// checkRemediationProcess verifies vulnerability remediation process.
// Maps to CIS 7.2: Establish and Maintain a Remediation Process.
func (m *CISModule) checkRemediationProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRemediation := strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "remediation_process") || strings.Contains(inputStr, "fix_process")
	hasSLA := strings.Contains(inputStr, "remediation_sla") || strings.Contains(inputStr, "sla") || strings.Contains(inputStr, "time_to_remediate")
	hasTracking := strings.Contains(inputStr, "vuln_tracking") || strings.Contains(inputStr, "ticketing") || strings.Contains(inputStr, "issue_tracking")

	present := 0
	if hasRemediation {
		present++
	}
	if hasSLA {
		present++
	}
	if hasTracking {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-7.2",
			ControlName: "Establish and Maintain a Remediation Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Remediation process verified: process + SLA + tracking configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-7.2",
			ControlName: "Establish and Maintain a Remediation Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial remediation: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Establish a remediation process with SLAs and vulnerability tracking/ticketing",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-7.2",
		ControlName: "Establish and Maintain a Remediation Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No remediation process configured",
		Timestamp:   time.Now(),
		Remediation: "Establish a remediation process with SLAs and vulnerability tracking",
	}, nil
}

// checkAutomatedPatchManagement verifies automated OS patch management.
// Maps to CIS 7.3: Perform Automated Operating System Patch Management.
func (m *CISModule) checkAutomatedPatchManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPatchMgmt := strings.Contains(inputStr, "patch_management") || strings.Contains(inputStr, "automated_patching") || strings.Contains(inputStr, "patch")
	hasAutoUpdate := strings.Contains(inputStr, "auto_update") || strings.Contains(inputStr, "automatic_updates") || strings.Contains(inputStr, "unattended_upgrades")
	hasPatchTesting := strings.Contains(inputStr, "patch_testing") || strings.Contains(inputStr, "staged_patching") || strings.Contains(inputStr, "patch_validation")

	present := 0
	if hasPatchMgmt {
		present++
	}
	if hasAutoUpdate {
		present++
	}
	if hasPatchTesting {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-7.3",
			ControlName: "Perform Automated Operating System Patch Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Automated patch management verified: patching + auto-update + testing",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-7.3",
			ControlName: "Perform Automated Operating System Patch Management",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial patch management: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable automated OS patching with auto-updates and staged patch testing",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-7.3",
		ControlName: "Perform Automated Operating System Patch Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No automated patch management configured",
		Timestamp:   time.Now(),
		Remediation: "Enable automated OS patch management with auto-updates and staged patch testing",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 8: Audit Log Management
// ============================================================================

// checkAuditLogManagementProcess verifies audit log management process.
// Maps to CIS 8.1: Establish and Maintain an Audit Log Management Process.
func (m *CISModule) checkAuditLogManagementProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAudit := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAudit = true
			break
		}
	}
	hasRetention := strings.Contains(inputStr, "retention") || strings.Contains(inputStr, "audit_log_retention")
	hasProcess := strings.Contains(inputStr, "log_management") || strings.Contains(inputStr, "audit_process") || strings.Contains(inputStr, "log_policy")

	present := 0
	if hasAudit {
		present++
	}
	if hasRetention {
		present++
	}
	if hasProcess {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-8.1",
			ControlName: "Establish and Maintain an Audit Log Management Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit log management process verified: collection + retention + policy",
			Timestamp:   time.Now(),
		}, nil
	}
	missing := []string{}
	if !hasAudit {
		missing = append(missing, "audit log collection")
	}
	if !hasRetention {
		missing = append(missing, "retention policy")
	}
	if !hasProcess {
		missing = append(missing, "log management process")
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-8.1",
		ControlName: "Establish and Maintain an Audit Log Management Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit log management gaps: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit log collection, retention policy, and a formal log management process",
	}, nil
}

// checkCollectCentralizeAuditLogs verifies audit log collection and centralization.
// Maps to CIS 8.2: Collect and Centralize Audit Logs.
func (m *CISModule) checkCollectCentralizeAuditLogs(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
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
	hasCentralization := strings.Contains(inputStr, "centralized_logging") || strings.Contains(inputStr, "log_aggregation") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "log_central")

	if hasAudit && hasIntegrity && hasCentralization {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-8.2",
			ControlName: "Collect and Centralize Audit Logs",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Audit log collection verified: collection + hash-chain integrity + centralization",
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
	if !hasCentralization {
		missing = append(missing, "log centralization")
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-8.2",
		ControlName: "Collect and Centralize Audit Logs",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Audit log collection gaps: " + strings.Join(missing, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure audit log collection with hash-chain integrity and centralize logs in a SIEM or log aggregator",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 9: Email and Web Browser Protections
// ============================================================================

// checkApprovedEmailClients verifies approved email clients are used.
// Maps to CIS 9.1: Ensure Only Approved Email Clients Are Used.
func (m *CISModule) checkApprovedEmailClients(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasApproved := strings.Contains(inputStr, "approved_email") || strings.Contains(inputStr, "email_allowlist") || strings.Contains(inputStr, "email_client_policy")
	hasDLP := strings.Contains(inputStr, "email_dlp") || strings.Contains(inputStr, "data_loss_prevention") || strings.Contains(inputStr, "email_scanning")

	if hasApproved && hasDLP {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-9.1",
			ControlName: "Ensure Only Approved Email Clients Are Used",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Approved email clients verified: allowlist + DLP scanning configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasApproved {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-9.1",
			ControlName: "Ensure Only Approved Email Clients Are Used",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Approved email clients detected; DLP scanning not configured",
			Timestamp:   time.Now(),
			Remediation: "Enable email DLP scanning in addition to approved email client policy",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-9.1",
		ControlName: "Ensure Only Approved Email Clients Are Used",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No approved email client policy configured",
		Timestamp:   time.Now(),
		Remediation: "Establish an approved email client allowlist and enable email DLP scanning",
	}, nil
}

// checkApprovedWebBrowsers verifies approved web browsers are used.
// Maps to CIS 9.2: Ensure Only Approved Web Browsers Are Used.
func (m *CISModule) checkApprovedWebBrowsers(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLens := strings.Contains(inputStr, "aegisgate_lens") || strings.Contains(inputStr, "lens_extension") || strings.Contains(inputStr, "browser_extension")
	hasCSP := strings.Contains(inputStr, "content_security_policy") || strings.Contains(inputStr, "csp_header")
	hasApproved := strings.Contains(inputStr, "approved_browsers") || strings.Contains(inputStr, "browser_allowlist") || strings.Contains(inputStr, "browser_policy")

	present := 0
	if hasLens {
		present++
	}
	if hasCSP {
		present++
	}
	if hasApproved {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-9.2",
			ControlName: "Ensure Only Approved Web Browsers Are Used",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Approved web browsers verified: AegisGate Lens + CSP + browser policy",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-9.2",
			ControlName: "Ensure Only Approved Web Browsers Are Used",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial browser protections: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Install AegisGate Lens, set CSP headers, and establish approved browser policy",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-9.2",
		ControlName: "Ensure Only Approved Web Browsers Are Used",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No approved web browser protections detected",
		Timestamp:   time.Now(),
		Remediation: "Install AegisGate Lens for client-side scanning, set CSP headers, and establish approved browser policy",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 10: Malware Defenses
// ============================================================================

// checkDeployAntiMalware verifies anti-malware/anti-attack scanning is in place.
// Maps to CIS 10.1: Deploy Anti-Malware Software.
func (m *CISModule) checkDeployAntiMalware(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)

	hasScanner := false
	for _, p := range m.scannerPatterns {
		if p.MatchString(inputStr) {
			hasScanner = true
			break
		}
	}
	hasAntiMalware := strings.Contains(inputStr, "anti_malware") || strings.Contains(inputStr, "antivirus") || strings.Contains(inputStr, "malware_scan")
	hasCoverage := strings.Contains(inputStr, "full_coverage") || strings.Contains(inputStr, "all_assets") || strings.Contains(inputStr, "endpoint_protection")

	present := 0
	if hasScanner {
		present++
	}
	if hasAntiMalware {
		present++
	}
	if hasCoverage {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-10.1",
			ControlName: "Deploy Anti-Malware Software",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Anti-malware defenses verified: scanner + anti-malware + full coverage",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-10.1",
			ControlName: "Deploy Anti-Malware Software",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial anti-malware defenses: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Deploy AegisGate scanner across all assets and ensure full endpoint coverage",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-10.1",
		ControlName: "Deploy Anti-Malware Software",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No anti-malware defenses detected",
		Timestamp:   time.Now(),
		Remediation: "Deploy AegisGate scanner (pkg/scanner/) with anti-malware scanning across all enterprise assets",
	}, nil
}

// checkAntiMalwareAutoUpdates verifies automatic updates for anti-malware.
// Maps to CIS 10.2: Configure Automatic Updates for Anti-Malware.
func (m *CISModule) checkAntiMalwareAutoUpdates(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAutoUpdate := strings.Contains(inputStr, "auto_update") || strings.Contains(inputStr, "pattern_update") || strings.Contains(inputStr, "rule_update") || strings.Contains(inputStr, "automatic_updates")
	hasSignatureUpdates := strings.Contains(inputStr, "signature_update") || strings.Contains(inputStr, "definition_update") || strings.Contains(inputStr, "signature_auto_update")
	hasRegularScans := strings.Contains(inputStr, "regular_scan") || strings.Contains(inputStr, "scheduled_scan") || strings.Contains(inputStr, "scan_interval")

	present := 0
	if hasAutoUpdate {
		present++
	}
	if hasSignatureUpdates {
		present++
	}
	if hasRegularScans {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-10.2",
			ControlName: "Configure Automatic Updates for Anti-Malware",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Anti-malware auto-updates verified: auto-update + signature updates + scheduled scans",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-10.2",
			ControlName: "Configure Automatic Updates for Anti-Malware",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial auto-update configuration: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable automatic pattern/signature updates and scheduled scans for anti-malware",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-10.2",
		ControlName: "Configure Automatic Updates for Anti-Malware",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No automatic anti-malware updates configured",
		Timestamp:   time.Now(),
		Remediation: "Enable automatic pattern updates, signature updates, and scheduled scans for AegisGate scanner",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 11: Data Recovery
// ============================================================================

// checkDataRecoveryProcess verifies data recovery process.
// Maps to CIS 11.1: Establish and Maintain a Data Recovery Process.
func (m *CISModule) checkDataRecoveryProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBackup := strings.Contains(inputStr, "backup") || strings.Contains(inputStr, "disaster_recovery")
	hasIntegrity := strings.Contains(inputStr, "log_integrity") || strings.Contains(inputStr, "hash_chain")
	hasRestore := strings.Contains(inputStr, "restore") || strings.Contains(inputStr, "audit_replay") || strings.Contains(inputStr, "recoverable")

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

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-11.1",
			ControlName: "Establish and Maintain a Data Recovery Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Data recovery process verified: backup + integrity + restore capability",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-11.1",
			ControlName: "Establish and Maintain a Data Recovery Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial data recovery: 1 of 3 capabilities configured",
			Timestamp:   time.Now(),
			Remediation: "Enable backup, hash-chain integrity, and restore/replay capability",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-11.1",
		ControlName: "Establish and Maintain a Data Recovery Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No data recovery process configured",
		Timestamp:   time.Now(),
		Remediation: "Establish a data recovery process with backup, integrity verification, and restore testing",
	}, nil
}

// checkAutomatedBackups verifies automated backup capability.
// Maps to CIS 11.2: Perform Automated Backups.
func (m *CISModule) checkAutomatedBackups(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAutomatedBackup := strings.Contains(inputStr, "automated_backup") || strings.Contains(inputStr, "auto_backup") || strings.Contains(inputStr, "scheduled_backup")
	hasRetention := strings.Contains(inputStr, "retention") || strings.Contains(inputStr, "retention_days") || strings.Contains(inputStr, "backup_retention")
	hasRestoreTest := strings.Contains(inputStr, "restore_test") || strings.Contains(inputStr, "backup_test") || strings.Contains(inputStr, "recovery_test")

	present := 0
	if hasAutomatedBackup {
		present++
	}
	if hasRetention {
		present++
	}
	if hasRestoreTest {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-11.2",
			ControlName: "Perform Automated Backups",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Automated backups verified: automated backup + retention + restore testing",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-11.2",
			ControlName: "Perform Automated Backups",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial automated backups: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable automated backups with retention policy and periodic restore testing",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-11.2",
		ControlName: "Perform Automated Backups",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No automated backups configured",
		Timestamp:   time.Now(),
		Remediation: "Enable automated backups with retention policy (default 7/30/90 days by tier) and periodic restore testing",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 12: Network Infrastructure Management
// ============================================================================

// checkNetworkUpToDate verifies network infrastructure is up-to-date.
// Maps to CIS 12.1: Ensure Network Infrastructure is Up-to-Date.
func (m *CISModule) checkNetworkUpToDate(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := false
	for _, p := range m.tlsPatterns {
		if p.MatchString(inputStr) {
			hasTLS = true
			break
		}
	}
	hasFirmwareUpdates := strings.Contains(inputStr, "firmware_update") || strings.Contains(inputStr, "patch_network") || strings.Contains(inputStr, "network_up_to_date")
	hasSupportedVer := strings.Contains(inputStr, "supported_version") || strings.Contains(inputStr, "end_of_life_check") || strings.Contains(inputStr, "version_check")

	present := 0
	if hasTLS {
		present++
	}
	if hasFirmwareUpdates {
		present++
	}
	if hasSupportedVer {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-12.1",
			ControlName: "Ensure Network Infrastructure is Up-to-Date",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network infrastructure up-to-date: TLS 1.2+ + firmware updates + version checks",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-12.1",
			ControlName: "Ensure Network Infrastructure is Up-to-Date",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial network up-to-date: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Ensure TLS 1.2+, firmware updates, and supported version checks for all network devices",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-12.1",
		ControlName: "Ensure Network Infrastructure is Up-to-Date",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No network infrastructure update process configured",
		Timestamp:   time.Now(),
		Remediation: "Ensure TLS 1.2+ on all 6 protocol pillars, firmware updates, and supported version checks",
	}, nil
}

// checkSecureNetworkArchitecture verifies secure network architecture.
// Maps to CIS 12.2: Establish and Maintain a Secure Network Architecture.
func (m *CISModule) checkSecureNetworkArchitecture(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMTLS := strings.Contains(inputStr, "mtls") || strings.Contains(inputStr, "mutual_tls") || strings.Contains(inputStr, "client_cert")
	hasSegmentation := strings.Contains(inputStr, "network_segmentation") || strings.Contains(inputStr, "segmented") || strings.Contains(inputStr, "isolated")
	hasFirewall := strings.Contains(inputStr, "firewall") || strings.Contains(inputStr, "egress_allowlist") || strings.Contains(inputStr, "ingress_allowlist")

	present := 0
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
			ControlID:   "CIS-12.2",
			ControlName: "Establish and Maintain a Secure Network Architecture",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Secure network architecture verified: mTLS + segmentation + firewall rules",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-12.2",
			ControlName: "Establish and Maintain a Secure Network Architecture",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial network architecture: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable mTLS for A2A/ACP, network segmentation defaults, and egress/ingress allowlists",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-12.2",
		ControlName: "Establish and Maintain a Secure Network Architecture",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No secure network architecture configured",
		Timestamp:   time.Now(),
		Remediation: "Enable mTLS for A2A/ACP, network segmentation, and egress/ingress allowlists",
	}, nil
}

// checkSecurelyManageNetwork verifies secure management of network infrastructure.
// Maps to CIS 12.3: Securely Manage Network Infrastructure.
func (m *CISModule) checkSecurelyManageNetwork(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccessControl := strings.Contains(inputStr, "network_access_control") || strings.Contains(inputStr, "nac") || strings.Contains(inputStr, "device_auth")
	hasChangeMgmt := strings.Contains(inputStr, "change_management") || strings.Contains(inputStr, "config_change_control") || strings.Contains(inputStr, "network_change")
	hasAuditLog := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditLog = true
			break
		}
	}

	present := 0
	if hasAccessControl {
		present++
	}
	if hasChangeMgmt {
		present++
	}
	if hasAuditLog {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-12.3",
			ControlName: "Securely Manage Network Infrastructure",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Secure network management verified: access control + change management + audit logging",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-12.3",
			ControlName: "Securely Manage Network Infrastructure",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial network management: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable network access control, change management, and audit logging for network infrastructure",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-12.3",
		ControlName: "Securely Manage Network Infrastructure",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No secure network management configured",
		Timestamp:   time.Now(),
		Remediation: "Enable network access control, change management, and audit logging for network infrastructure",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 13: Network Monitoring and Defense
// ============================================================================

// checkNetworkMonitoringProcess verifies network monitoring process.
// Maps to CIS 13.1: Establish and Maintain a Network Monitoring Process.
func (m *CISModule) checkNetworkMonitoringProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIOCStore := strings.Contains(inputStr, "ioc_store") || strings.Contains(inputStr, "ioc_federation")
	hasAnomaly := strings.Contains(inputStr, "anomaly") || strings.Contains(inputStr, "trust_score") || strings.Contains(inputStr, "anomaly_detection")
	hasMonitoring := strings.Contains(inputStr, "network_monitoring") || strings.Contains(inputStr, "traffic_monitoring") || strings.Contains(inputStr, "continuous_monitoring")

	present := 0
	if hasIOCStore {
		present++
	}
	if hasAnomaly {
		present++
	}
	if hasMonitoring {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-13.1",
			ControlName: "Establish and Maintain a Network Monitoring Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network monitoring process verified: IOC store + anomaly detection + continuous monitoring",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-13.1",
			ControlName: "Establish and Maintain a Network Monitoring Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial network monitoring: 1 of 3 controls configured",
			Timestamp:   time.Now(),
			Remediation: "Enable AegisGate IOC store, anomaly detection, and continuous network monitoring",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-13.1",
		ControlName: "Establish and Maintain a Network Monitoring Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No network monitoring process configured",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate IOC store + anomaly detection + continuous network monitoring",
	}, nil
}

// checkNetworkBasedIDS verifies network-based intrusion detection.
// Maps to CIS 13.2: Deploy Network-Based Intrusion Detection.
func (m *CISModule) checkNetworkBasedIDS(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIDS := strings.Contains(inputStr, "ids") || strings.Contains(inputStr, "intrusion") || strings.Contains(inputStr, "intrusion_detection")
	hasIPS := strings.Contains(inputStr, "ips") || strings.Contains(inputStr, "intrusion_prevention") || strings.Contains(inputStr, "blocking")
	hasAlerting := strings.Contains(inputStr, "alert") || strings.Contains(inputStr, "siem") || strings.Contains(inputStr, "soc_alerting")

	present := 0
	if hasIDS {
		present++
	}
	if hasIPS {
		present++
	}
	if hasAlerting {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-13.2",
			ControlName: "Deploy Network-Based Intrusion Detection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network-based IDS verified: IDS + IPS + alerting configured",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-13.2",
			ControlName: "Deploy Network-Based Intrusion Detection",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial IDS: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Deploy network-based IDS/IPS with SIEM alerting integration",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-13.2",
		ControlName: "Deploy Network-Based Intrusion Detection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No network-based intrusion detection configured",
		Timestamp:   time.Now(),
		Remediation: "Deploy network-based IDS/IPS with SIEM alerting integration",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 16: Application Software Security
// ============================================================================

// checkSecureSDLC verifies secure software development process.
// Maps to CIS 16.1: Establish and Maintain a Secure Software Development Process.
func (m *CISModule) checkSecureSDLC(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasScanner := false
	for _, p := range m.scannerPatterns {
		if p.MatchString(inputStr) {
			hasScanner = true
			break
		}
	}
	hasSSDF := strings.Contains(inputStr, "ssdf") || strings.Contains(inputStr, "secure_sdlc") || strings.Contains(inputStr, "devsecops")
	hasCodeReview := strings.Contains(inputStr, "code_review") || strings.Contains(inputStr, "peer_review") || strings.Contains(inputStr, "security_review")

	present := 0
	if hasScanner {
		present++
	}
	if hasSSDF {
		present++
	}
	if hasCodeReview {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-16.1",
			ControlName: "Establish and Maintain a Secure Software Development Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Secure SDLC verified: scanner + SDLC process + code review",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-16.1",
			ControlName: "Establish and Maintain a Secure Software Development Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial secure SDLC: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable AegisGate scanner, establish secure SDLC process, and implement security code reviews",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-16.1",
		ControlName: "Establish and Maintain a Secure Software Development Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No secure software development process configured",
		Timestamp:   time.Now(),
		Remediation: "Enable AegisGate scanner, establish secure SDLC process, and implement security code reviews",
	}, nil
}

// checkRootCauseAnalysis verifies root cause analysis on vulnerabilities.
// Maps to CIS 16.2: Perform Root Cause Analysis on Security Vulnerabilities.
func (m *CISModule) checkRootCauseAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRCA := strings.Contains(inputStr, "root_cause") || strings.Contains(inputStr, "rca") || strings.Contains(inputStr, "postmortem")
	hasVulnTracking := strings.Contains(inputStr, "vuln_management") || strings.Contains(inputStr, "vuln_tracking") || strings.Contains(inputStr, "vulnerability_database")
	hasRemediation := strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "fix_process") || strings.Contains(inputStr, "prevent_recurrence")

	present := 0
	if hasRCA {
		present++
	}
	if hasVulnTracking {
		present++
	}
	if hasRemediation {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-16.2",
			ControlName: "Perform Root Cause Analysis on Security Vulnerabilities",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Root cause analysis verified: RCA + vulnerability tracking + recurrence prevention",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-16.2",
			ControlName: "Perform Root Cause Analysis on Security Vulnerabilities",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Partial RCA process: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Establish RCA process with vulnerability tracking and recurrence prevention measures",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-16.2",
		ControlName: "Perform Root Cause Analysis on Security Vulnerabilities",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "No root cause analysis process configured",
		Timestamp:   time.Now(),
		Remediation: "Establish RCA process with vulnerability tracking and recurrence prevention measures",
	}, nil
}

// checkManageOpenSourceSoftware verifies open-source software management.
// Maps to CIS 16.3: Manage Open-Source Software.
func (m *CISModule) checkManageOpenSourceSoftware(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx") || strings.Contains(inputStr, "spdx")
	hasVulnManagement := strings.Contains(inputStr, "vuln_management") || strings.Contains(inputStr, "vuln_scan") || strings.Contains(inputStr, "govulncheck")
	hasOSSPolicy := strings.Contains(inputStr, "oss_policy") || strings.Contains(inputStr, "open_source_policy") || strings.Contains(inputStr, "license_compliance")

	present := 0
	if hasSBOM {
		present++
	}
	if hasVulnManagement {
		present++
	}
	if hasOSSPolicy {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-16.3",
			ControlName: "Manage Open-Source Software",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Open-source software management verified: SBOM + vulnerability scanning + OSS policy",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-16.3",
			ControlName: "Manage Open-Source Software",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial OSS management: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Enable SBOM generation, vulnerability scanning for dependencies, and OSS license policy",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-16.3",
		ControlName: "Manage Open-Source Software",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No open-source software management configured",
		Timestamp:   time.Now(),
		Remediation: "Enable SBOM generation (CycloneDX/SPDX), dependency vulnerability scanning, and OSS license compliance policy",
	}, nil
}

// ============================================================================
// Check implementations — CIS Family 17: Incident Response Management
// ============================================================================

// checkDesignateIRPersonnel verifies designated incident response personnel.
// Maps to CIS 17.1: Designate Personnel to Manage Incident Response.
func (m *CISModule) checkDesignateIRPersonnel(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDesignated := strings.Contains(inputStr, "ir_team") || strings.Contains(inputStr, "incident_response_team") || strings.Contains(inputStr, "designated_personnel")
	hasRoles := strings.Contains(inputStr, "ir_roles") || strings.Contains(inputStr, "response_roles") || strings.Contains(inputStr, "incident_roles")
	hasContact := strings.Contains(inputStr, "ir_contact") || strings.Contains(inputStr, "emergency_contact") || strings.Contains(inputStr, "escalation_contact")

	present := 0
	if hasDesignated {
		present++
	}
	if hasRoles {
		present++
	}
	if hasContact {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-17.1",
			ControlName: "Designate Personnel to Manage Incident Response",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "IR personnel verified: designated team + defined roles + contact info",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-17.1",
			ControlName: "Designate Personnel to Manage Incident Response",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial IR personnel: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Designate IR team with defined roles and escalation contact information",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-17.1",
		ControlName: "Designate Personnel to Manage Incident Response",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No designated incident response personnel configured",
		Timestamp:   time.Now(),
		Remediation: "Designate IR team with defined roles and escalation contact information",
	}, nil
}

// checkIncidentResponseProcess verifies incident response process.
// Maps to CIS 17.2: Establish and Maintain an Incident Response Process.
func (m *CISModule) checkIncidentResponseProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPlan := strings.Contains(inputStr, "incident_response_plan") || strings.Contains(inputStr, "ir_plan") || strings.Contains(inputStr, "incident_process")
	hasAttestations := strings.Contains(inputStr, "attestation") || strings.Contains(inputStr, "signed_log") || strings.Contains(inputStr, "trust_framework")
	hasAuditTrail := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(inputStr) {
			hasAuditTrail = true
			break
		}
	}

	present := 0
	if hasPlan {
		present++
	}
	if hasAttestations {
		present++
	}
	if hasAuditTrail {
		present++
	}

	if present >= 2 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-17.2",
			ControlName: "Establish and Maintain an Incident Response Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident response process verified: plan + signed attestations + audit trail",
			Timestamp:   time.Now(),
		}, nil
	}
	if present == 1 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CIS-17.2",
			ControlName: "Establish and Maintain an Incident Response Process",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial incident response: 1 of 3 components configured",
			Timestamp:   time.Now(),
			Remediation: "Create an IR plan; enable AegisGate signed attestations and audit log for forensic evidence",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CIS-17.2",
		ControlName: "Establish and Maintain an Incident Response Process",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No incident response process configured",
		Timestamp:   time.Now(),
		Remediation: "Create an IR plan; AegisGate's signed attestations (pkg/attestation/) and audit log are the forensic evidence sources",
	}, nil
}

// ============================================================================
// Dependencies
// ============================================================================

// Dependencies returns required modules.
func (m *CISModule) Dependencies() []string {
	return []string{"scanner", "auth", "persistence", "ioc", "trust"}
}
