// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CJIS Compliance Module
// =========================================================================
//
// Criminal Justice Information Services (CJIS) Security Policy compliance
// controls as a licensed add-on module. Covers 13 policy areas:
// Information Management, Personnel Security, Access Control, Physical
// Protection, Cryptography, Incident Response, System and Communications
// Protection, System and Information Integrity, Configuration Management,
// Maintenance, Identification and Authentication, Cloud Computing, and
// AI Controls.
//
// Module metadata:
//   - Framework:     "cjis"
//   - Version:       "5.9.1"
//   - Required tier: Professional ($199/mo)
//   - Controls:      64 (47 automated, 17 manual)
//   - Categories:    13
//
// Architecture:
//   - cjis.go:              module wiring, 64 RegisterControl calls,
//                           24 CheckFunc implementations
//   - cjis_test.go:         unit tests
//   - tier_coverage_test.go: tier/framework tests
//
// Reference: CJIS Security Policy v5.9.1
// =========================================================================

// Package cjis provides CJIS Security Policy compliance controls as a licensed add-on module.
package cjis

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// CJISModule implements CJIS Security Policy compliance controls.
type CJISModule struct {
	*compliance.BaseComplianceModule
	cjiPatterns []*regexp.Regexp
}

// NewCJISModule creates a new CJIS compliance module.
func NewCJISModule() *CJISModule {
	m := &CJISModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("cjis", "5.9.1", core.TierProfessional),
	}

	m.initCJIPatterns()
	m.registerControls()

	return m
}

// initCJIPatterns initializes patterns for detecting Criminal Justice Information.
func (m *CJISModule) initCJIPatterns() {
	// CJIS-defined CJI identifiers
	m.cjiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),                 // SSN
		regexp.MustCompile(`(?i)\d{2}-\d{6}`),                   // Case number (YY-XXXXXX)
		regexp.MustCompile(`(?i)fbi\s*\d{8,10}`),                // FBI number
		regexp.MustCompile(`(?i)ncic\s*\d{8,12}`),               // NCIC number
		regexp.MustCompile(`(?i)ori\s*[A-Za-z0-9]{7,9}`),        // ORI number
		regexp.MustCompile(`(?i)\d{2}[/-]\d{2}[/-]\d{4}`),       // Date of birth
		regexp.MustCompile(`(?i)case\s*#\s*\d{2}-\d{6}`),        // Case number with prefix
		regexp.MustCompile(`(?i)arrest\s*#\s*[A-Za-z0-9-]+`),    // Arrest number
		regexp.MustCompile(`(?i)offender\s*id\s*[A-Za-z0-9-]+`), // Offender ID
	}
}

// ============================================================================
// Control Registration — 64 controls
// ============================================================================

// registerControls registers all CJIS Security Policy v5.9.1 controls.
func (m *CJISModule) registerControls() {
	// ── Information Management (IM) — 6 controls, 3 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IM-01",
		Name:        "Information Management Policy",
		Description: "Policies and procedures for managing Criminal Justice Information throughout its lifecycle",
		Category:    "Information Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInformationManagement,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IM-02",
		Name:        "Media Protection",
		Description: "Protect CJI stored on physical and electronic media through encryption and access controls",
		Category:    "Information Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMediaProtection,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.2.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IM-03",
		Name:        "Media Storage",
		Description: "Store CJI media in secure locations with appropriate environmental and access controls",
		Category:    "Information Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.2.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IM-04",
		Name:        "Media Transport",
		Description: "Protect CJI media during transport through encryption and chain-of-custody procedures",
		Category:    "Information Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.2.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IM-05",
		Name:        "Media Sanitization and Disposal",
		Description: "Sanitize and dispose of CJI media using approved methods to prevent data recovery",
		Category:    "Information Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.2.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IM-06",
		Name:        "Record Retention",
		Description: "Implement data retention policies for Criminal Justice Information in compliance with CJIS requirements",
		Category:    "Information Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRecordRetention,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.3"},
	})

	// ── Personnel Security (PS) — 6 controls, 3 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PS-01",
		Name:        "Personnel Security Policy",
		Description: "Ensure all personnel with CJI access undergo background checks and security screening",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPersonnelSecurity,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PS-02",
		Name:        "Security Awareness Training",
		Description: "Provide security awareness training for all personnel accessing CJI",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityAwarenessTraining,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PS-03",
		Name:        "Incident Response Training",
		Description: "Provide incident response training for personnel with CJI access",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponseTraining,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PS-04",
		Name:        "Background Checks",
		Description: "Conduct criminal history record checks and fingerprint-based background checks for all personnel with CJI access",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.1.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PS-05",
		Name:        "Personnel Sanctioning",
		Description: "Implement sanctions for personnel who fail to comply with CJIS Security Policy requirements",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.1.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PS-06",
		Name:        "Termination Procedures",
		Description: "Implement procedures for terminating access to CJI when personnel depart or change roles",
		Category:    "Personnel Security",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.1.3"},
	})

	// ── Access Control (AC) — 8 controls, 4 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-01",
		Name:        "Access Control Policy",
		Description: "Implement role-based access controls to restrict CJI access to authorized personnel",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccessControl,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.4.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-02",
		Name:        "Account Management",
		Description: "Implement procedures for creating, managing, and disabling accounts with CJI access",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccountManagement,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.4.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-03",
		Name:        "Audit and Accountability",
		Description: "Implement audit logging for all access to Criminal Justice Information",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAuditAccountability,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.4.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-04",
		Name:        "Access Enforcement",
		Description: "Enforce access control policies through technical mechanisms on all CJI systems",
		Category:    "Access Control",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAccessEnforcement,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.4.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-05",
		Name:        "Information Flow Enforcement",
		Description: "Enforce information flow control policies between CJI systems and external networks",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInfoFlowEnforcement,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.4.5"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-06",
		Name:        "Separation of Duties",
		Description: "Implement separation of duties to prevent single individuals from compromising CJI security",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCJISSeparationOfDuties,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.4.6"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-07",
		Name:        "Least Privilege",
		Description: "Assign the least privilege necessary for personnel to accomplish their assigned tasks with CJI",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLeastPrivilege,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.4.7"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AC-08",
		Name:        "Remote Access",
		Description: "Implement secure remote access controls including VPN and multi-factor authentication for CJI access",
		Category:    "Access Control",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRemoteAccess,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.4.8"},
	})

	// ── Physical Protection (PP) — 4 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PP-01",
		Name:        "Physical Protection Policy",
		Description: "Implement physical security controls for facilities housing CJI systems (customer responsibility)",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.4.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PP-02",
		Name:        "Mobile Device Security",
		Description: "Implement mobile device management for all devices that access CJI",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMobileDeviceSecurity,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.4.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PP-03",
		Name:        "Facility Security",
		Description: "Implement facility security controls including perimeter protection and access monitoring",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.4.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-PP-04",
		Name:        "Visitor Control",
		Description: "Implement visitor control procedures for facilities housing CJI systems",
		Category:    "Physical Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.4.4"},
	})

	// ── Cryptography (CR) — 5 controls, 3 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CR-01",
		Name:        "Encryption at Rest",
		Description: "Encrypt CJI at rest using FIPS 140-2 validated cryptographic modules (AES-256)",
		Category:    "Cryptography",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionAtRest,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.5.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CR-02",
		Name:        "Encryption in Transit",
		Description: "Encrypt CJI in transit using TLS 1.2 or higher (TLS 1.3 recommended)",
		Category:    "Cryptography",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkEncryptionInTransit,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.5.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CR-03",
		Name:        "Key Management",
		Description: "Implement cryptographic key management procedures including rotation and secure storage",
		Category:    "Cryptography",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkKeyManagement,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.5.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CR-04",
		Name:        "FIPS-Validated Cryptography",
		Description: "Use FIPS 140-2 validated cryptographic modules for all CJI encryption operations",
		Category:    "Cryptography",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkFIPSValidatedCrypto,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.5.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CR-05",
		Name:        "Public Key Infrastructure",
		Description: "Implement PKI infrastructure for CJI systems including certificate management and validation",
		Category:    "Cryptography",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPKI,
		References:  []string{"CJIS Security Policy v5.9.1 Section 4.5.5"},
	})

	// ── Incident Response (IR) — 5 controls, 2 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IR-01",
		Name:        "Incident Response Plan",
		Description: "Implement an incident response plan for CJI security incidents including roles and procedures",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentResponse,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.5.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IR-02",
		Name:        "Incident Response Training",
		Description: "Provide incident response training for personnel involved in CJI incident response",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.5.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IR-03",
		Name:        "Incident Monitoring",
		Description: "Implement monitoring capabilities to detect and respond to CJI security incidents",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentMonitoring,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.5.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IR-04",
		Name:        "Incident Reporting",
		Description: "Implement procedures for reporting CJI security incidents to appropriate authorities",
		Category:    "Incident Response",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIncidentReporting,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.5.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IR-05",
		Name:        "Incident Response Testing",
		Description: "Test incident response plans and procedures on a regular basis for CJI systems",
		Category:    "Incident Response",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.5.5"},
	})

	// ── System and Communications Protection (SC) — 5 controls, 0 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SC-01",
		Name:        "Boundary Protection",
		Description: "Implement boundary protection controls including firewalls and network segmentation for CJI systems",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBoundaryProtection,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.6.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SC-02",
		Name:        "Transmission Confidentiality and Integrity",
		Description: "Protect the confidentiality and integrity of transmitted CJI using cryptographic mechanisms",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTransmissionConfInteg,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.6.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SC-03",
		Name:        "Network Access Control",
		Description: "Implement network access control to restrict access to CJI systems and networks",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkAccessControl,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.6.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SC-04",
		Name:        "Protection of Information at Rest",
		Description: "Protect CJI at rest through encryption, access controls, and data integrity mechanisms",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkProtectionAtRest,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.6.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SC-05",
		Name:        "Security Function Isolation",
		Description: "Isolate security functions from non-security functions in CJI systems",
		Category:    "System and Communications Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityFunctionIsolation,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.6.5"},
	})

	// ── System and Information Integrity (SI) — 5 controls, 2 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SI-01",
		Name:        "Flaw Remediation",
		Description: "Implement flaw remediation procedures including patch management and vulnerability remediation",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFlawRemediation,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.7.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SI-02",
		Name:        "Malicious Code Protection",
		Description: "Implement malicious code protection including antivirus, anti-malware, and EDR solutions",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMaliciousCodeProtection,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.7.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SI-03",
		Name:        "Security Alerts and Advisories",
		Description: "Receive and act on security alerts and advisories relevant to CJI systems",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityAlerts,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.7.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SI-04",
		Name:        "Security Functionality Verification",
		Description: "Verify security functionality of CJI systems on a regular basis",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityFunctionVerification,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.7.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-SI-05",
		Name:        "Software and Information Integrity",
		Description: "Implement controls to verify the integrity of software and information in CJI systems",
		Category:    "System and Information Integrity",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSoftwareIntegrity,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.7.5"},
	})

	// ── Configuration Management (CM) — 5 controls, 1 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CM-01",
		Name:        "Configuration Management Policy",
		Description: "Implement configuration management policies and procedures for CJI systems",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.8.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CM-02",
		Name:        "Configuration Change Control",
		Description: "Implement configuration change control including change approval and documentation",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConfigChangeControl,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.8.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CM-03",
		Name:        "Security Impact Analysis",
		Description: "Perform security impact analysis for configuration changes to CJI systems",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityImpactAnalysis,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.8.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CM-04",
		Name:        "Change Implementation",
		Description: "Implement approved configuration changes through controlled procedures for CJI systems",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkChangeImplementation,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.8.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CM-05",
		Name:        "Software Usage and Restrictions",
		Description: "Implement software usage restrictions and license management for CJI systems",
		Category:    "Configuration Management",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkSoftwareUsage,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.8.5"},
	})

	// ── Maintenance (MA) — 4 controls, 0 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-MA-01",
		Name:        "Maintenance Policy",
		Description: "Implement maintenance policies and procedures for CJI systems",
		Category:    "Maintenance",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.9.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-MA-02",
		Name:        "Controlled Maintenance",
		Description: "Implement controlled maintenance procedures for CJI systems including scheduling and documentation",
		Category:    "Maintenance",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.9.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-MA-03",
		Name:        "Maintenance Tools",
		Description: "Control and monitor maintenance tools used on CJI systems",
		Category:    "Maintenance",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.9.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-MA-04",
		Name:        "Remote Maintenance and Diagnostic Ports",
		Description: "Implement controls for remote maintenance and diagnostic ports on CJI systems (customer responsibility)",
		Category:    "Maintenance",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRemoteMaintenance,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.9.4"},
	})

	// ── Identification and Authentication (IA) — 5 controls, 3 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IA-01",
		Name:        "Identification and Authentication Policy",
		Description: "Implement identification and authentication policies for CJI system access",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIdentificationAuth,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.10.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IA-02",
		Name:        "Identifier Management",
		Description: "Implement identifier management procedures for CJI system accounts",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.10.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IA-03",
		Name:        "Authenticator Management",
		Description: "Implement authenticator management including token and credential lifecycle management",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuthenticatorManagement,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.10.3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IA-04",
		Name:        "Advanced Authentication",
		Description: "Implement advanced authentication including MFA for all CJI system access per CJIS requirements",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAdvancedAuth,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.10.4"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-IA-05",
		Name:        "FICAM Compliance",
		Description: "Implement FICAM-aligned identity, credential, and access management for CJI systems",
		Category:    "Identification and Authentication",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.10.5"},
	})

	// ── Cloud Computing (CC) — 3 controls, 0 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CC-01",
		Name:        "Cloud Service Provider Security",
		Description: "Ensure cloud service providers meet CJIS Security Policy requirements for CJI processing",
		Category:    "Cloud Computing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCloudServiceProviderSecurity,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.11.1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CC-02",
		Name:        "Cloud Access Controls",
		Description: "Implement access controls for cloud-hosted CJI systems including identity federation",
		Category:    "Cloud Computing",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCloudAccessControls,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.11.2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-CC-03",
		Name:        "Cloud Data Protection",
		Description: "Implement data protection controls for CJI stored and processed in cloud environments",
		Category:    "Cloud Computing",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCloudDataProtection,
		References:  []string{"CJIS Security Policy v5.9.1 Section 5.11.3"},
	})

	// ── AI Controls (AI) — 3 controls, 2 automated ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AI-01",
		Name:        "AI Model CJI Protection",
		Description: "Ensure AI models do not retain or expose Criminal Justice Information",
		Category:    "AI Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAIModelCJIProtection,
		References:  []string{"CJIS Security Policy v5.9.1 AI Supplement"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AI-02",
		Name:        "AI Audit Trail",
		Description: "Maintain audit trails for all AI model interactions involving Criminal Justice Information",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIAuditTrail,
		References:  []string{"CJIS Security Policy v5.9.1 AI Supplement"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CJIS-AI-03",
		Name:        "AI Model Governance for CJI Systems",
		Description: "Implement AI model governance for systems processing Criminal Justice Information",
		Category:    "AI Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAIModelGovernanceCJI,
		References:  []string{"CJIS Security Policy v5.9.1 AI Supplement"},
	})
}

// ============================================================================
// Check Function Implementations — 24 automated checks
// ============================================================================

func (m *CJISModule) checkInformationManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInfoPolicy := strings.Contains(inputStr, "information_management_policy") || strings.Contains(inputStr, "data_classification")

	if hasInfoPolicy {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IM-01",
			ControlName: "Information Management Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Information management policy and data classification controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IM-01",
		ControlName: "Information Management Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Information management policy and data classification controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement information management policy with CJI data classification",
	}, nil
}

func (m *CJISModule) checkMediaProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMediaProtection := strings.Contains(inputStr, "media_protection")
	hasEncryptionAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "disk_encrypted")

	if hasMediaProtection && hasEncryptionAtRest {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IM-02",
			ControlName: "Media Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Media protection and encryption at rest detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasMediaProtection || hasEncryptionAtRest {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IM-02",
			ControlName: "Media Protection",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial media protection controls detected",
			Timestamp:   time.Now(),
			Remediation: "Implement both media protection policies and encryption at rest for CJI media",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IM-02",
		ControlName: "Media Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "No media protection controls detected",
		Timestamp:   time.Now(),
		Remediation: "Implement media protection policies and encryption at rest for all CJI storage media",
	}, nil
}

func (m *CJISModule) checkRecordRetention(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRecordRetention := strings.Contains(inputStr, "record_retention") || strings.Contains(inputStr, "data_retention_policy")

	if hasRecordRetention {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IM-06",
			ControlName: "Record Retention",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Record retention policy detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IM-06",
		ControlName: "Record Retention",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Record retention policy not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement CJI record retention policies per CJIS Security Policy requirements",
	}, nil
}

func (m *CJISModule) checkPersonnelSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPersonnelSecurity := strings.Contains(inputStr, "personnel_security") || strings.Contains(inputStr, "background_checks") || strings.Contains(inputStr, "screening")

	if hasPersonnelSecurity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-PS-01",
			ControlName: "Personnel Security Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Personnel security screening and background checks detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-PS-01",
		ControlName: "Personnel Security Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Personnel security controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement background checks and security screening for all personnel with CJI access",
	}, nil
}

func (m *CJISModule) checkSecurityAwarenessTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTraining := strings.Contains(inputStr, "security_training") || strings.Contains(inputStr, "security_awareness")

	if hasTraining {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-PS-02",
			ControlName: "Security Awareness Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Security awareness training program detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-PS-02",
		ControlName: "Security Awareness Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Security awareness training program not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement mandatory security awareness training for all CJI access personnel",
	}, nil
}

func (m *CJISModule) checkIncidentResponseTraining(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRTraining := strings.Contains(inputStr, "incident_response_training") || strings.Contains(inputStr, "ir_training")

	if hasIRTraining {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-PS-03",
			ControlName: "Incident Response Training",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Incident response training program detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-PS-03",
		ControlName: "Incident Response Training",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Incident response training program not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement incident response training for all personnel with CJI access",
	}, nil
}

func (m *CJISModule) checkAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccessControl := strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac")

	if hasAccessControl {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AC-01",
			ControlName: "Access Control Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Access control policy with RBAC detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AC-01",
		ControlName: "Access Control Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Access control policy not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement role-based access control for all CJI systems",
	}, nil
}

func (m *CJISModule) checkAccountManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccountMgmt := strings.Contains(inputStr, "account_management") || strings.Contains(inputStr, "user_provisioning")

	if hasAccountMgmt {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AC-02",
			ControlName: "Account Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Account management and user provisioning controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AC-02",
		ControlName: "Account Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Account management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement account management procedures including user provisioning and deprovisioning",
	}, nil
}

func (m *CJISModule) checkAuditAccountability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := strings.Contains(inputStr, "audit_log") || strings.Contains(inputStr, "audit_enabled") || strings.Contains(inputStr, "logging_enabled")

	if hasAuditLog {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AC-03",
			ControlName: "Audit and Accountability",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Audit logging and accountability controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AC-03",
		ControlName: "Audit and Accountability",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Audit logging controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Enable comprehensive audit logging for all CJI access events",
	}, nil
}

func (m *CJISModule) checkRemoteAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRemoteAccess := strings.Contains(inputStr, "remote_access") ||
		strings.Contains(inputStr, "vpn") ||
		strings.Contains(inputStr, "vpn_required") ||
		strings.Contains(inputStr, "remote_desktop")

	if hasRemoteAccess {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AC-08",
			ControlName: "Remote Access",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Remote access controls including VPN detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AC-08",
		ControlName: "Remote Access",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Remote access controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement secure remote access including VPN and multi-factor authentication for CJI access",
	}, nil
}

func (m *CJISModule) checkMobileDeviceSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMDM := strings.Contains(inputStr, "mobile_device_management") || strings.Contains(inputStr, "mdm") || strings.Contains(inputStr, "device_enrollment")

	if hasMDM {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-PP-02",
			ControlName: "Mobile Device Security",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Mobile device management and enrollment controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-PP-02",
		ControlName: "Mobile Device Security",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Mobile device management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement mobile device management for all devices that access CJI",
	}, nil
}

func (m *CJISModule) checkEncryptionAtRest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryptionAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted") || strings.Contains(inputStr, "aes_256") || strings.Contains(inputStr, "fips")

	if hasEncryptionAtRest {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-CR-01",
			ControlName: "Encryption at Rest",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "CJI encryption at rest with FIPS-validated module detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-CR-01",
		ControlName: "Encryption at Rest",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "CJI encryption at rest not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement AES-256 encryption at rest with FIPS 140-2 validated modules for all CJI storage",
	}, nil
}

func (m *CJISModule) checkEncryptionInTransit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS13 := strings.Contains(inputStr, "tls1.3") || strings.Contains(inputStr, "tls_13")
	hasTLS := strings.Contains(inputStr, "https") || strings.Contains(inputStr, "tls")

	if hasTLS13 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-CR-02",
			ControlName: "Encryption in Transit",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS 1.3 enabled for CJI transmission security",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasTLS {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-CR-02",
			ControlName: "Encryption in Transit",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "TLS detected but not TLS 1.3",
			Timestamp:   time.Now(),
			Remediation: "Upgrade to TLS 1.3 for maximum CJI transmission security per CJIS requirements",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-CR-02",
		ControlName: "Encryption in Transit",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No TLS encryption detected for CJI in transit",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.3 for all CJI data transmission per CJIS Security Policy",
	}, nil
}

func (m *CJISModule) checkKeyManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasKeyManagement := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "kms")

	if hasKeyManagement {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-CR-03",
			ControlName: "Key Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Cryptographic key management and rotation controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-CR-03",
		ControlName: "Key Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Cryptographic key management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement key management procedures including rotation and secure storage per CJIS requirements",
	}, nil
}

func (m *CJISModule) checkIncidentResponse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIRPlan := strings.Contains(inputStr, "incident_response_plan") ||
		strings.Contains(inputStr, "ir_plan") ||
		strings.Contains(inputStr, "incident_response")

	if hasIRPlan {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IR-01",
			ControlName: "Incident Response Plan",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident response plan detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IR-01",
		ControlName: "Incident Response Plan",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident response plan not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement an incident response plan for CJI security incidents",
	}, nil
}

func (m *CJISModule) checkIncidentMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMonitoring := strings.Contains(inputStr, "incident_monitoring") ||
		strings.Contains(inputStr, "siem") ||
		strings.Contains(inputStr, "security_monitoring")

	if hasMonitoring {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IR-03",
			ControlName: "Incident Monitoring",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Incident monitoring and SIEM controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IR-03",
		ControlName: "Incident Monitoring",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Incident monitoring controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement incident monitoring with SIEM for CJI systems",
	}, nil
}

func (m *CJISModule) checkFlawRemediation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFlawRemediation := strings.Contains(inputStr, "flaw_remediation") ||
		strings.Contains(inputStr, "patch_management") ||
		strings.Contains(inputStr, "vulnerability_patch")

	if hasFlawRemediation {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-SI-01",
			ControlName: "Flaw Remediation",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Flaw remediation and patch management controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-SI-01",
		ControlName: "Flaw Remediation",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Flaw remediation controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement flaw remediation including patch management and vulnerability remediation",
	}, nil
}

func (m *CJISModule) checkMaliciousCodeProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMaliciousCodeProtection := strings.Contains(inputStr, "antivirus") ||
		strings.Contains(inputStr, "anti_malware") ||
		strings.Contains(inputStr, "malware_detection") ||
		strings.Contains(inputStr, "edr")

	if hasMaliciousCodeProtection {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-SI-02",
			ControlName: "Malicious Code Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Malicious code protection including antivirus and EDR detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-SI-02",
		ControlName: "Malicious Code Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Malicious code protection controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement malicious code protection including antivirus, anti-malware, and EDR solutions",
	}, nil
}

func (m *CJISModule) checkConfigChangeControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasChangeControl := strings.Contains(inputStr, "change_control") ||
		strings.Contains(inputStr, "change_management") ||
		strings.Contains(inputStr, "cab_approval") ||
		strings.Contains(inputStr, "configuration_change")

	if hasChangeControl {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-CM-02",
			ControlName: "Configuration Change Control",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Configuration change control and management controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-CM-02",
		ControlName: "Configuration Change Control",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Configuration change control not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement configuration change control including change approval and documentation",
	}, nil
}

func (m *CJISModule) checkIdentificationAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIdentAuth := strings.Contains(inputStr, "identification") ||
		strings.Contains(inputStr, "authentication") ||
		strings.Contains(inputStr, "user_identification")

	if hasIdentAuth {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IA-01",
			ControlName: "Identification and Authentication Policy",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Identification and authentication controls detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IA-01",
		ControlName: "Identification and Authentication Policy",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Identification and authentication controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement identification and authentication policies for CJI system access",
	}, nil
}

func (m *CJISModule) checkAuthenticatorManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuthenticatorMgmt := strings.Contains(inputStr, "authenticator_management") ||
		strings.Contains(inputStr, "token_management") ||
		strings.Contains(inputStr, "credential_management")

	if hasAuthenticatorMgmt {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IA-03",
			ControlName: "Authenticator Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Authenticator management including token and credential management detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IA-03",
		ControlName: "Authenticator Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Authenticator management controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement authenticator management including token and credential lifecycle management",
	}, nil
}

func (m *CJISModule) checkAdvancedAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAdvancedAuth := strings.Contains(inputStr, "advanced_authentication") ||
		strings.Contains(inputStr, "mfa") ||
		strings.Contains(inputStr, "multi_factor") ||
		strings.Contains(inputStr, "totp") ||
		strings.Contains(inputStr, "fido")

	if hasAdvancedAuth {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-IA-04",
			ControlName: "Advanced Authentication",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Advanced authentication including MFA detected",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-IA-04",
		ControlName: "Advanced Authentication",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Advanced authentication controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement advanced authentication including MFA for all CJI system access",
	}, nil
}

func (m *CJISModule) checkAIModelCJIProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	cjiFound := m.detectCJI(string(input))

	if len(cjiFound) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AI-01",
			ControlName: "AI Model CJI Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "No Criminal Justice Information detected in AI model data",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AI-01",
		ControlName: "AI Model CJI Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "Criminal Justice Information patterns detected in AI model data",
		Details:     "Detected CJI patterns in input data",
		Timestamp:   time.Now(),
		Remediation: "Implement CJI scrubbing for all AI model inputs and outputs per CJIS Security Policy",
	}, nil
}

func (m *CJISModule) checkAIAuditTrail(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuditLog := strings.Contains(inputStr, "audit_log")
	hasAIAuditTrail := strings.Contains(inputStr, "ai_audit_trail")
	hasModelLogging := strings.Contains(inputStr, "model_logging")

	violations := []string{}
	if !hasAuditLog {
		violations = append(violations, "audit log")
	}
	if !hasAIAuditTrail {
		violations = append(violations, "AI audit trail")
	}
	if !hasModelLogging {
		violations = append(violations, "model logging")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AI-02",
			ControlName: "AI Audit Trail",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "AI audit trail with model logging detected",
			Timestamp:   time.Now(),
		}, nil
	}

	if len(violations) < 3 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CJIS-AI-02",
			ControlName: "AI Audit Trail",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityHigh,
			Message:     "Partial AI audit controls: missing " + strings.Join(violations, ", "),
			Timestamp:   time.Now(),
			Remediation: "Implement comprehensive AI audit trail including audit_log, ai_audit_trail, and model_logging",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CJIS-AI-02",
		ControlName: "AI Audit Trail",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "AI audit trail controls not detected",
		Timestamp:   time.Now(),
		Remediation: "Implement audit logging, AI audit trail, and model logging for all CJI-related AI interactions",
	}, nil
}

// detectCJI scans input for potential Criminal Justice Information patterns.
func (m *CJISModule) detectCJI(input string) []string {
	found := []string{}
	for _, pattern := range m.cjiPatterns {
		if pattern.MatchString(input) {
			found = append(found, pattern.String())
		}
	}
	return found
}

// Dependencies returns required modules.
func (m *CJISModule) Dependencies() []string {
	return []string{"scanner"}
}

// ============================================================================
// Promoted CheckFunc implementations — P4 Compliance Automation Expansion
// ============================================================================

func (m *CJISModule) checkAccessEnforcement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAccess := strings.Contains(inputStr, "access_enforcement") || strings.Contains(inputStr, "access_control") || strings.Contains(inputStr, "rbac")
	hasPolicy := strings.Contains(inputStr, "access_policy") || strings.Contains(inputStr, "enforcement_policy") || strings.Contains(inputStr, "policy_enforcement")
	if hasAccess && hasPolicy {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AC-04", ControlName: "Access Enforcement", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Access enforcement with policy detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasAccess {
		violations = append(violations, "access enforcement not configured")
	}
	if !hasPolicy {
		violations = append(violations, "access policy not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AC-04", ControlName: "Access Enforcement", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Access enforcement gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement access enforcement with policy"}, nil
}

func (m *CJISModule) checkInfoFlowEnforcement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFlow := strings.Contains(inputStr, "information_flow") || strings.Contains(inputStr, "flow_control") || strings.Contains(inputStr, "data_flow_enforcement")
	hasRule := strings.Contains(inputStr, "flow_rule") || strings.Contains(inputStr, "flow_policy") || strings.Contains(inputStr, "flow_filtering")
	if hasFlow && hasRule {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AC-05", ControlName: "Information Flow Enforcement", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Information flow enforcement detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasFlow {
		violations = append(violations, "information flow enforcement not configured")
	}
	if !hasRule {
		violations = append(violations, "flow rules not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AC-05", ControlName: "Information Flow Enforcement", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Flow enforcement gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement information flow enforcement with rules"}, nil
}

func (m *CJISModule) checkCJISSeparationOfDuties(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSOD := strings.Contains(inputStr, "separation_of_duties") || strings.Contains(inputStr, "sod") || strings.Contains(inputStr, "dual_control")
	if hasSOD {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AC-06", ControlName: "Separation of Duties", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Separation of duties detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AC-06", ControlName: "Separation of Duties", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Separation of duties not detected", Timestamp: time.Now(), Remediation: "Implement separation of duties controls"}, nil
}

func (m *CJISModule) checkLeastPrivilege(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasLeastPriv := strings.Contains(inputStr, "least_privilege") || strings.Contains(inputStr, "minimal_access") || strings.Contains(inputStr, "privilege_minimization")
	if hasLeastPriv {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AC-07", ControlName: "Least Privilege", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Least privilege controls detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AC-07", ControlName: "Least Privilege", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Least privilege not detected", Timestamp: time.Now(), Remediation: "Implement least privilege access controls"}, nil
}

func (m *CJISModule) checkFIPSValidatedCrypto(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFIPS := strings.Contains(inputStr, "fips_validated") || strings.Contains(inputStr, "fips_140") || strings.Contains(inputStr, "fips_compliant")
	if hasFIPS {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CR-04", ControlName: "FIPS-Validated Cryptography", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "FIPS-validated cryptography detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CR-04", ControlName: "FIPS-Validated Cryptography", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "FIPS-validated cryptography not detected", Timestamp: time.Now(), Remediation: "Use FIPS-validated cryptographic modules"}, nil
}

func (m *CJISModule) checkPKI(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPKI := strings.Contains(inputStr, "pki") || strings.Contains(inputStr, "public_key_infrastructure") || strings.Contains(inputStr, "certificate_authority")
	hasCertMgmt := strings.Contains(inputStr, "certificate_management") || strings.Contains(inputStr, "cert_management") || strings.Contains(inputStr, "x509")
	if hasPKI && hasCertMgmt {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CR-05", ControlName: "Public Key Infrastructure", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "PKI with certificate management detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasPKI {
		violations = append(violations, "PKI not configured")
	}
	if !hasCertMgmt {
		violations = append(violations, "certificate management not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CR-05", ControlName: "Public Key Infrastructure", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "PKI gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement PKI with certificate management"}, nil
}

func (m *CJISModule) checkBoundaryProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBoundary := strings.Contains(inputStr, "boundary_protection") || strings.Contains(inputStr, "firewall") || strings.Contains(inputStr, "network_boundary")
	if hasBoundary {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-01", ControlName: "Boundary Protection", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Boundary protection detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-01", ControlName: "Boundary Protection", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Boundary protection not detected", Timestamp: time.Now(), Remediation: "Implement boundary protection controls"}, nil
}

func (m *CJISModule) checkTransmissionConfInteg(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "encryption_in_transit") || strings.Contains(inputStr, "https")
	hasIntegrity := strings.Contains(inputStr, "transmission_integrity") || strings.Contains(inputStr, "integrity_check") || strings.Contains(inputStr, "hmac")
	if hasTLS && hasIntegrity {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-02", ControlName: "Transmission Confidentiality and Integrity", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Transmission confidentiality and integrity detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasTLS {
		violations = append(violations, "transmission encryption not configured")
	}
	if !hasIntegrity {
		violations = append(violations, "transmission integrity not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-02", ControlName: "Transmission Confidentiality and Integrity", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Transmission gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement transmission confidentiality and integrity"}, nil
}

func (m *CJISModule) checkNetworkAccessControl(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasNAC := strings.Contains(inputStr, "network_access_control") || strings.Contains(inputStr, "nac") || strings.Contains(inputStr, "network_access")
	if hasNAC {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-03", ControlName: "Network Access Control", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Network access control detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-03", ControlName: "Network Access Control", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Network access control not detected", Timestamp: time.Now(), Remediation: "Implement network access control"}, nil
}

func (m *CJISModule) checkProtectionAtRest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAtRest := strings.Contains(inputStr, "encryption_at_rest") || strings.Contains(inputStr, "data_encrypted") || strings.Contains(inputStr, "aes")
	if hasAtRest {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-04", ControlName: "Protection of Information at Rest", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Protection of information at rest detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-04", ControlName: "Protection of Information at Rest", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Protection at rest not detected", Timestamp: time.Now(), Remediation: "Implement encryption for data at rest"}, nil
}

func (m *CJISModule) checkSecurityFunctionIsolation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIsolation := strings.Contains(inputStr, "security_function_isolation") || strings.Contains(inputStr, "function_isolation") || strings.Contains(inputStr, "sandboxing")
	if hasIsolation {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-05", ControlName: "Security Function Isolation", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Security function isolation detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SC-05", ControlName: "Security Function Isolation", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Security function isolation not detected", Timestamp: time.Now(), Remediation: "Implement security function isolation"}, nil
}

func (m *CJISModule) checkSecurityAlerts(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAlerts := strings.Contains(inputStr, "security_alerts") || strings.Contains(inputStr, "advisory_monitoring") || strings.Contains(inputStr, "threat_alerts")
	if hasAlerts {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SI-03", ControlName: "Security Alerts and Advisories", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Security alerts and advisories detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SI-03", ControlName: "Security Alerts and Advisories", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Security alerts not detected", Timestamp: time.Now(), Remediation: "Implement security alerts and advisory monitoring"}, nil
}

func (m *CJISModule) checkSecurityFunctionVerification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVerification := strings.Contains(inputStr, "security_function_verification") || strings.Contains(inputStr, "function_verification") || strings.Contains(inputStr, "security_verification")
	if hasVerification {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SI-04", ControlName: "Security Functionality Verification", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Security function verification detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SI-04", ControlName: "Security Functionality Verification", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Security function verification not detected", Timestamp: time.Now(), Remediation: "Implement security function verification"}, nil
}

func (m *CJISModule) checkSoftwareIntegrity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasIntegrity := strings.Contains(inputStr, "software_integrity") || strings.Contains(inputStr, "integrity_monitoring") || strings.Contains(inputStr, "file_integrity")
	if hasIntegrity {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SI-05", ControlName: "Software and Information Integrity", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Software and information integrity detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-SI-05", ControlName: "Software and Information Integrity", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Software integrity not detected", Timestamp: time.Now(), Remediation: "Implement software and information integrity monitoring"}, nil
}

func (m *CJISModule) checkSecurityImpactAnalysis(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasImpact := strings.Contains(inputStr, "security_impact_analysis") || strings.Contains(inputStr, "impact_analysis") || strings.Contains(inputStr, "change_impact")
	if hasImpact {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CM-03", ControlName: "Security Impact Analysis", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Security impact analysis detected", Timestamp: time.Now()}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CM-03", ControlName: "Security Impact Analysis", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Security impact analysis not detected", Timestamp: time.Now(), Remediation: "Implement security impact analysis for changes"}, nil
}

func (m *CJISModule) checkChangeImplementation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasImpl := strings.Contains(inputStr, "change_implementation") || strings.Contains(inputStr, "controlled_change") || strings.Contains(inputStr, "change_control")
	hasReview := strings.Contains(inputStr, "implementation_review") || strings.Contains(inputStr, "change_review") || strings.Contains(inputStr, "post_review")
	if hasImpl && hasReview {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CM-04", ControlName: "Change Implementation", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Controlled change implementation with review detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasImpl {
		violations = append(violations, "change implementation not configured")
	}
	if !hasReview {
		violations = append(violations, "implementation review not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CM-04", ControlName: "Change Implementation", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Change implementation gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement controlled change with review"}, nil
}

func (m *CJISModule) checkSoftwareUsage(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasUsage := strings.Contains(inputStr, "software_usage") || strings.Contains(inputStr, "software_restriction") || strings.Contains(inputStr, "license_control")
	hasPolicy := strings.Contains(inputStr, "software_policy") || strings.Contains(inputStr, "usage_policy") || strings.Contains(inputStr, "software_inventory")
	if hasUsage && hasPolicy {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CM-05", ControlName: "Software Usage and Restrictions", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Software usage controls with policy detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasUsage {
		violations = append(violations, "software usage controls not configured")
	}
	if !hasPolicy {
		violations = append(violations, "usage policy not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CM-05", ControlName: "Software Usage and Restrictions", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityMedium, Message: "Software usage gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement software usage and restriction controls"}, nil
}

func (m *CJISModule) checkRemoteMaintenance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRemote := strings.Contains(inputStr, "remote_maintenance") || strings.Contains(inputStr, "remote_access") || strings.Contains(inputStr, "diagnostic_port")
	hasControl := strings.Contains(inputStr, "maintenance_control") || strings.Contains(inputStr, "remote_maintenance_control") || strings.Contains(inputStr, "diagnostic_control")
	if hasRemote && hasControl {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-MA-04", ControlName: "Remote Maintenance and Diagnostic Ports", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Remote maintenance controls detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasRemote {
		violations = append(violations, "remote maintenance not configured")
	}
	if !hasControl {
		violations = append(violations, "maintenance controls not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-MA-04", ControlName: "Remote Maintenance and Diagnostic Ports", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Remote maintenance gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement remote maintenance controls"}, nil
}

func (m *CJISModule) checkCloudServiceProviderSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCSP := strings.Contains(inputStr, "cloud_service_provider") || strings.Contains(inputStr, "csp_security") || strings.Contains(inputStr, "cloud_provider_security")
	hasAssurance := strings.Contains(inputStr, "provider_assurance") || strings.Contains(inputStr, "cloud_assurance") || strings.Contains(inputStr, "fedramp")
	if hasCSP && hasAssurance {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CC-01", ControlName: "Cloud Service Provider Security", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Cloud service provider security detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasCSP {
		violations = append(violations, "CSP security not configured")
	}
	if !hasAssurance {
		violations = append(violations, "cloud assurance not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CC-01", ControlName: "Cloud Service Provider Security", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "CSP security gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement cloud service provider security controls"}, nil
}

func (m *CJISModule) checkCloudAccessControls(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCloudAccess := strings.Contains(inputStr, "cloud_access_control") || strings.Contains(inputStr, "cloud_access") || strings.Contains(inputStr, "cloud_rbac")
	hasAuth := strings.Contains(inputStr, "cloud_authentication") || strings.Contains(inputStr, "cloud_mfa") || strings.Contains(inputStr, "cloud_sso")
	if hasCloudAccess && hasAuth {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CC-02", ControlName: "Cloud Access Controls", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Cloud access controls detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasCloudAccess {
		violations = append(violations, "cloud access controls not configured")
	}
	if !hasAuth {
		violations = append(violations, "cloud authentication not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CC-02", ControlName: "Cloud Access Controls", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Cloud access gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement cloud access controls with authentication"}, nil
}

func (m *CJISModule) checkCloudDataProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEnc := strings.Contains(inputStr, "cloud_data_protection") || strings.Contains(inputStr, "cloud_encryption") || strings.Contains(inputStr, "cloud_data_encryption")
	hasDLP := strings.Contains(inputStr, "cloud_dlp") || strings.Contains(inputStr, "cloud_data_loss_prevention") || strings.Contains(inputStr, "cloud_masking")
	if hasEnc && hasDLP {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CC-03", ControlName: "Cloud Data Protection", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Cloud data protection detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasEnc {
		violations = append(violations, "cloud encryption not configured")
	}
	if !hasDLP {
		violations = append(violations, "cloud DLP not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-CC-03", ControlName: "Cloud Data Protection", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Cloud data protection gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement cloud data protection controls"}, nil
}

func (m *CJISModule) checkAIModelGovernanceCJI(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasGovernance := strings.Contains(inputStr, "ai_model_governance") || strings.Contains(inputStr, "model_governance") || strings.Contains(inputStr, "ai_oversight")
	hasApproval := strings.Contains(inputStr, "model_approval") || strings.Contains(inputStr, "ai_approval") || strings.Contains(inputStr, "model_oversight")
	if hasGovernance && hasApproval {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AI-03", ControlName: "AI Model Governance for CJI Systems", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "AI model governance with oversight detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasGovernance {
		violations = append(violations, "AI model governance not configured")
	}
	if !hasApproval {
		violations = append(violations, "model approval not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-AI-03", ControlName: "AI Model Governance for CJI Systems", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "AI governance gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement AI model governance with oversight for CJI systems"}, nil
}

func (m *CJISModule) checkIncidentReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReporting := strings.Contains(inputStr, "incident_reporting") || strings.Contains(inputStr, "incident_report") || strings.Contains(inputStr, "security_incident_report")
	hasProcedure := strings.Contains(inputStr, "reporting_procedure") || strings.Contains(inputStr, "reporting_process") || strings.Contains(inputStr, "incident_notification")
	if hasReporting && hasProcedure {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-IR-04", ControlName: "Incident Reporting", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Incident reporting controls detected", Timestamp: time.Now()}, nil
	}
	violations := []string{}
	if !hasReporting {
		violations = append(violations, "incident reporting not configured")
	}
	if !hasProcedure {
		violations = append(violations, "reporting procedure not configured")
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "CJIS-IR-04", ControlName: "Incident Reporting", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "Incident reporting gaps: " + strings.Join(violations, ", "), Timestamp: time.Now(), Remediation: "Implement incident reporting procedures"}, nil
}
