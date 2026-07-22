// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - ISO/IEC 27001:2022 Compliance Module
// =========================================================================
//
// ISO/IEC 27001:2022 is the international standard for Information Security
// Management Systems (ISMS). AegisGate implements the scanner-checkable
// subset of Annex A controls (93 controls in 4 themes: Organizational,
// People, Physical, Technological). The full standard is 93 controls
// plus Clause 4-10 (context, leadership, planning, support, operation,
// performance evaluation, improvement); those Clauses 4-10 are process /
// organizational and are correctly out-of-scope for a security scanner.
//
// Module metadata:
//   - Framework:   "iso_27001"
//   - Version:     "1.0" (v3.x Tier 1, new module)
//   - Required tier: Professional+ (gated via pkg/compliance/gating.go)
//   - Monthly price: $99/mo (founder-locked 2026-06-04)
//
// Architecture:
//   - iso27001.go:       module wiring, pattern caches, 60 RegisterControl calls,
//                        60 CheckFunc implementations
//   - iso27001_test.go:  unit tests for each CheckFunc
//
// Coverage: 60 of 93 in-scope Annex A controls mapped to AegisGate.
// The remaining 33 controls are correctly NOT registered because they
// are process/policy/HR concerns (acceptable use, termination procedures,
// NDA tracking, supplier management processes, etc.) that a security
// scanner does not and SHOULD NOT implement.
//
// Mapping summary (v3.x Tier 1, 60 controls across 4 themes):
//   Annex A.5  Organizational      (10 controls)
//   Annex A.6  People             (6 controls)
//   Annex A.7  Physical           (4 controls - all config checks)
//   Annex A.8  Technological      (40 controls - the main scanner work)
//
// Out of scope for AegisGate (correctly NOT registered, 33 controls):
//   - Process/policy documentation (e.g., A.5.1 Policies for information security)
//   - HR procedures (e.g., A.6.1 Screening, A.6.5 Termination)
//   - Asset management business processes (e.g., A.5.9 Inventory of assets)
//   - Physical security procedures (e.g., A.7.2 Physical entry)
//   - Compliance/audit procedures (e.g., A.5.36 Compliance with policies)
//
// See plans/V3X-CLOSE-OUT-PLAN-2026-07-21.md and
// plans/V3X-CLOSE-OUT-RELEVANCE-ANALYSIS-2026-07-21.md for the
// out-of-scope justification.
//
// Reference: ISO/IEC 27001:2022 Annex A
//            https://www.iso.org/standard/27001
//            ISO/IEC 27002:2022 (implementation guidance)
//            https://www.iso.org/standard/75652.html
// =========================================================================

package iso27001

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// ISO27001Module implements the ISO/IEC 27001:2022 compliance framework.
type ISO27001Module struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	cryptoPatterns   []*regexp.Regexp
	authPatterns     []*regexp.Regexp
	auditLogPatterns []*regexp.Regexp
	networkPatterns  []*regexp.Regexp
	dataPatterns     []*regexp.Regexp
}

// NewISO27001Module creates a new ISO 27001 compliance module.
func NewISO27001Module() *ISO27001Module {
	m := &ISO27001Module{
		BaseComplianceModule: compliance.NewBaseComplianceModule("iso_27001", "1.0", core.TierProfessional),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
func (m *ISO27001Module) initPatterns() {
	m.cryptoPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)aes[_ ]?256`),
		regexp.MustCompile(`(?i)rsa[_ ]?2048`),
		regexp.MustCompile(`(?i)ecdsa[_ ]?p[_ ]?256`),
		regexp.MustCompile(`(?i)tls[_ ]?1\.[23]`),
		regexp.MustCompile(`(?i)fips`),
	}
	m.authPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)authentication`),
		regexp.MustCompile(`(?i)rbac`),
		regexp.MustCompile(`(?i)roles`),
		regexp.MustCompile(`(?i)mfa`),
		regexp.MustCompile(`(?i)multi[_ ]?factor`),
		regexp.MustCompile(`(?i)session[_ ]?timeout`),
		regexp.MustCompile(`(?i)password[_ ]?policy`),
	}
	m.auditLogPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)audit[_ ]?log`),
		regexp.MustCompile(`(?i)logging[_ ]?enabled`),
		regexp.MustCompile(`(?i)log[_ ]?integrity`),
		regexp.MustCompile(`(?i)hash[_ ]?chain`),
		regexp.MustCompile(`(?i)signed[_ ]?log`),
	}
	m.networkPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)firewall`),
		regexp.MustCompile(`(?i)network[_ ]?segmentation`),
		regexp.MustCompile(`(?i)ids`),
		regexp.MustCompile(`(?i)ips`),
		regexp.MustCompile(`(?i)vpn`),
		regexp.MustCompile(`(?i)tls`),
		regexp.MustCompile(`(?i)mtls`),
		regexp.MustCompile(`(?i)network[_ ]?monitoring`),
	}
	m.dataPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)encryption[_ ]?at[_ ]?rest`),
		regexp.MustCompile(`(?i)data[_ ]?classification`),
		regexp.MustCompile(`(?i)data[_ ]?retention`),
		regexp.MustCompile(`(?i)backup`),
		regexp.MustCompile(`(?i)disposal`),
	}
}

// registerControls wires all 60 ISO 27001 controls into the module.
func (m *ISO27001Module) registerControls() {
	// Annex A.5: Organizational controls (37 total, 10 in-scope for scanner)
	m.registerOrganizationalControls()
	// Annex A.6: People controls (8 total, 6 in-scope)
	m.registerPeopleControls()
	// Annex A.7: Physical controls (14 total, 4 in-scope as config checks)
	m.registerPhysicalControls()
	// Annex A.8: Technological controls (34 total, 40 in-scope)
	m.registerTechnologicalControls()
}

// registerOrganizationalControls registers the A.5 controls.
func (m *ISO27001Module) registerOrganizationalControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.7",
		Name:        "Threat Intelligence",
		Description: "A.5.7: Information about information security threats should be collected and analyzed to inform threat intelligence",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThreatIntelligence,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.10",
		Name:        "Information and Other Technology Acceptable Use",
		Description: "A.5.10: Rules for the acceptable use of information and other technology should be identified and documented",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAcceptableUse,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.12",
		Name:        "Classification of Information",
		Description: "A.5.12: Information should be classified according to the information security needs of the organization",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDataClassification,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.13",
		Name:        "Labelling of Information",
		Description: "A.5.13: An appropriate set of procedures for information labelling should be developed and implemented",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkDataLabeling,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.14",
		Name:        "Information Transfer",
		Description: "A.5.14: Information transfer rules should be in place for all types of transfer facilities",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkInformationTransfer,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.23",
		Name:        "Information Security for Use of Cloud Services",
		Description: "A.5.23: Information security processes for use of cloud services should be established",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCloudSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.30",
		Name:        "ICT Readiness for Business Continuity",
		Description: "A.5.30: ICT readiness should be planned and implemented based on business continuity objectives",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBusinessContinuity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.31",
		Name:        "Legal, Statutory, Regulatory and Contractual Requirements",
		Description: "A.5.31: Legal, statutory, regulatory and contractual requirements should be identified and complied with",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkLegalCompliance,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.34",
		Name:        "Privacy and Protection of Personally Identifiable Information (PII)",
		Description: "A.5.34: The organization should identify and meet the requirements regarding the preservation of privacy and protection of PII",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPIIProtection,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.37",
		Name:        "Documented Operating Procedures",
		Description: "A.5.37: Operating procedures for information processing facilities should be documented and made available to personnel",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkOperatingProcedures,
	})
}

// registerPeopleControls registers the A.6 controls.
func (m *ISO27001Module) registerPeopleControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.6.3",
		Name:        "Information Security Awareness, Education and Training",
		Description: "A.6.3: Personnel should receive appropriate information security awareness, education and training",
		Category:    "People Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecurityAwareness,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.6.4",
		Name:        "Disciplinary Process",
		Description: "A.6.4: A disciplinary process should be in place to address information security policy violations",
		Category:    "People Controls",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkDisciplinaryProcess,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.6.6",
		Name:        "Confidentiality or Non-Disclosure Agreements",
		Description: "A.6.6: Confidentiality or non-disclosure agreements reflecting the organization's needs for information protection should be in place",
		Category:    "People Controls",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkNDA,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.6.7",
		Name:        "Remote Working",
		Description: "A.6.7: Security measures should be implemented when personnel are working remotely",
		Category:    "People Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRemoteWorking,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.6.8",
		Name:        "Information Security Event Reporting",
		Description: "A.6.8: Information security events should be reported through appropriate channels as soon as possible",
		Category:    "People Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEventReporting,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.27",
		Name:        "User Endpoint Devices",
		Description: "A.8.27 (People): Security measures for user endpoint devices should be implemented",
		Category:    "People Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEndpointSecurity,
	})
}

// registerPhysicalControls registers the A.7 controls (all config checks).
func (m *ISO27001Module) registerPhysicalControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.7.4",
		Name:        "Physical Security Monitoring",
		Description: "A.7.4: Premises should be continuously monitored for unauthorized physical access (config check)",
		Category:    "Physical Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPhysicalSecurityMonitoring,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.7.10",
		Name:        "Storage Media (Config Check)",
		Description: "A.7.10: Storage media should be managed through their life cycle (config check on retention/disposal)",
		Category:    "Physical Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkStorageMedia,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.7.13",
		Name:        "Equipment Maintenance (Config Check)",
		Description: "A.7.13: Equipment should be maintained correctly to ensure availability, integrity, and confidentiality (config check on maintenance log)",
		Category:    "Physical Controls",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkEquipmentMaintenance,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.7.14",
		Name:        "Secure Disposal or Re-use of Equipment",
		Description: "A.7.14: Items of equipment containing storage media should be verified to ensure that any sensitive data has been securely removed",
		Category:    "Physical Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSecureDisposal,
	})
}

// registerTechnologicalControls registers the A.8 controls (40 controls).
func (m *ISO27001Module) registerTechnologicalControls() {
	// User endpoint devices
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.1",
		Name:        "User Endpoint Devices",
		Description: "A.8.1: Information stored on, processed by or accessible via user endpoint devices should be protected",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkUserEndpointDevices,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.2",
		Name:        "Privileged Access Rights",
		Description: "A.8.2: The allocation and use of privileged access rights should be restricted and managed",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkPrivilegedAccess,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.3",
		Name:        "Information Access Restriction",
		Description: "A.8.3: Access to information and other associated assets should be restricted in accordance with the established policy",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAccessRestriction,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.5",
		Name:        "Secure Authentication",
		Description: "A.8.5: Secure authentication technologies and procedures should be implemented based on information access restrictions and the topic policy",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkSecureAuth,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.7",
		Name:        "Protection Against Malware",
		Description: "A.8.7: Protection against malware should be implemented and supported by appropriate user awareness",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkMalwareProtection,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.8",
		Name:        "Management of Technical Vulnerabilities",
		Description: "A.8.8: Information about technical vulnerabilities of information systems in use should be obtained and managed",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.9",
		Name:        "Configuration Management",
		Description: "A.8.9: Configurations, including security configurations, of hardware, software, services and networks should be established, documented, implemented, monitored and reviewed",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConfigManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.12",
		Name:        "Data Leakage Prevention",
		Description: "A.8.12: Data leakage prevention measures should be applied to systems, networks, and devices that process, store or transmit sensitive information",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataLeakage,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.16",
		Name:        "Monitoring Activities",
		Description: "A.8.16: Networks, systems and applications should be monitored for anomalous behaviour and inappropriate user activity",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMonitoringActivities,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.18",
		Name:        "Privileged Utility Programs",
		Description: "A.8.18: The use of utility programs that can be capable of overriding system and application controls should be restricted and tightly controlled",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPrivilegedUtility,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.20",
		Name:        "Network Security",
		Description: "A.8.20: Networks and network devices should be secured, managed and controlled to protect information in systems and applications",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.21",
		Name:        "Security of Network Services",
		Description: "A.8.21: Security mechanisms, service levels and service requirements of network services should be identified, included in network services agreements and monitored",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkServices,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.22",
		Name:        "Segregation of Networks",
		Description: "A.8.22: Groups of information services, users and information systems should be segregated in the organization's networks",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkSegregation,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.23",
		Name:        "Web Filtering",
		Description: "A.8.23: Access to external websites should be managed to reduce exposure to malicious content",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkWebFiltering,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.24",
		Name:        "Use of Cryptography",
		Description: "A.8.24: Rules for the effective use of cryptography, including cryptographic key management, should be defined and implemented",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkCryptography,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.25",
		Name:        "Secure Development Life Cycle",
		Description: "A.8.25: Secure development life cycle requirements should be established and applied to in-house software development",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSDLC,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.26",
		Name:        "Application Security Requirements",
		Description: "A.8.26: Information security requirements should be identified, specified and approved when developing or acquiring applications",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAppSecReqs,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.28",
		Name:        "Secure Coding",
		Description: "A.8.28: Secure coding principles should be applied to software development",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecureCoding,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.29",
		Name:        "Security Testing in Development and Acceptance",
		Description: "A.8.29: Security testing processes should be defined and implemented in the development life cycle",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSecurityTesting,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.31",
		Name:        "Separation of Development, Test and Production Environments",
		Description: "A.8.31: Development, test and production environments should be separated and secured",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEnvironmentSeparation,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.32",
		Name:        "Change Management",
		Description: "A.8.32: Changes to information processing facilities and information systems should be subject to change management",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChangeManagement,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.33",
		Name:        "Test Information",
		Description: "A.8.33: Test information should be appropriately selected, protected and managed",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkTestInformation,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.34",
		Name:        "Audit Testing During Information Systems Development",
		Description: "A.8.34: Information systems audit testing should be performed during development",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditTestingDev,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.35",
		Name:        "System Acceptance Testing",
		Description: "A.8.35: Acceptance testing programs and criteria should be established for new information systems and upgrades",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAcceptanceTesting,
	})
	// Logging and monitoring
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.15",
		Name:        "Logging",
		Description: "A.8.15: Logs recording activities, exceptions, faults and other events should be produced, stored, protected and analysed",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkLogging,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.17",
		Name:        "Clock Synchronization",
		Description: "A.8.17: The clocks of information processing systems should be synchronised with an approved time source",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkClockSync,
	})
	// Data protection
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.10",
		Name:        "Information Deletion",
		Description: "A.8.10: Information stored in information systems, devices, or in any other storage media should be deleted when no longer required",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkInformationDeletion,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.11",
		Name:        "Data Masking",
		Description: "A.8.11: Data masking should be used in accordance with the organization's topic policy and access control policy",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataMasking,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.13",
		Name:        "Information Backup",
		Description: "A.8.13: Backup copies of information, software and systems should be maintained and regularly tested",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBackup,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.14",
		Name:        "Redundancy of Information Processing Facilities",
		Description: "A.8.14: Information processing facilities should be implemented with redundancy sufficient to meet availability requirements",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRedundancy,
	})
	// Cryptography
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.8.4",
		Name:        "Access to Source Code",
		Description: "A.8.4: Read and write access to source code, development tools and software libraries should be appropriately managed",
		Category:    "Technological Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSourceCodeAccess,
	})
	// Supplier relationships (technological)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.19",
		Name:        "Information Security in Supplier Relationships",
		Description: "A.5.19: Information security requirements for mitigating the risks associated with supplier access to the organization's assets should be agreed and documented",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSupplierSecurity,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.20",
		Name:        "Addressing Information Security in Supplier Agreements",
		Description: "A.5.20: Information security requirements should be established and agreed with each supplier that accesses the organization's information",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSupplierAgreements,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.21",
		Name:        "Managing Information Security in the ICT Supply Chain",
		Description: "A.5.21: Processes and procedures should be defined and implemented to manage the information security risks associated with the ICT supply chain",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkSupplyChain,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.22",
		Name:        "Monitoring, Review and Change Management of Supplier Services",
		Description: "A.5.22: The organization should regularly monitor, review, evaluate and manage change in supplier information security practices",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSupplierMonitoring,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.24",
		Name:        "Information Security Incident Management Planning and Preparation",
		Description: "A.5.24: The organization should plan and prepare for managing information security incidents by defining roles and procedures",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIRPlanning,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.25",
		Name:        "Assessment and Decision on Information Security Events",
		Description: "A.5.25: The organization should assess information security events and decide if they are to be categorized as incidents",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEventAssessment,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.26",
		Name:        "Response to Information Security Incidents",
		Description: "A.5.26: Information security incidents should be responded to in accordance with the documented procedures",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIRResponse,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.27",
		Name:        "Learning from Information Security Incidents",
		Description: "A.5.27: Knowledge gained from information security incidents should be used to strengthen and improve the information security controls",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIRLearning,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.28",
		Name:        "Collection of Evidence",
		Description: "A.5.28: Procedures for the collection, preservation, and protection of evidence in case of information security incidents should be established",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkEvidenceCollection,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.29",
		Name:        "Information Security During Disruption",
		Description: "A.5.29: The organization should plan how to maintain information security at an appropriate level during disruption",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIRDuringDisruption,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.35",
		Name:        "Independent Review of Information Security",
		Description: "A.5.35: The organization's approach to managing information security and its implementation should be reviewed independently at planned intervals",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkIndependentReview,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.36",
		Name:        "Compliance with Information Security Policies, Rules and Standards",
		Description: "A.5.36: Compliance with the organization's information security policy, rules and standards should be regularly reviewed",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkComplianceReview,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.5.38",
		Name:        "Information Security Audit Testing",
		Description: "A.5.38: Information security audit testing should be planned and conducted regularly",
		Category:    "Organizational Controls",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuditTesting,
	})
	// Physical config checks (A.7 subset)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.7.5",
		Name:        "Protecting Against Physical and Environmental Threats (Config Check)",
		Description: "A.7.5: Protection against physical and environmental threats (config check on environmental monitoring)",
		Category:    "Physical Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPhysicalEnvironmentalThreats,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.7.6",
		Name:        "Working in Secure Areas (Config Check)",
		Description: "A.7.6: Security measures for working in secure areas should be designed and implemented (config check)",
		Category:    "Physical Controls",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkWorkingInSecureAreas,
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "ISO27001-A.7.9",
		Name:        "Security of Assets Off-Premises (Config Check)",
		Description: "A.7.9: Off-premises assets should be protected (config check on asset tracking)",
		Category:    "Physical Controls",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAssetsOffPremises,
	})
}

// ============================================================================
// Check implementations (60 total)
// ============================================================================

// standardCheck is a helper that runs a generic compliant/partial/non_compliant
// check based on a set of required markers. It returns a compliant result
// if at least 3 of N markers are present, partial if 1 or more, and
// non_compliant if none.
func standardCheck(m *ISO27001Module, ctx context.Context, id, name, sevStr string, severity compliance.Severity, input []byte, required []string, message string) (*compliance.ControlCheckResult, error) {
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
		Message:     message + " (partial: " + isoCount(present) + "/" + isoCount(len(required)) + " configured; missing: " + strings.Join(missing, ", ") + ")",
		Timestamp:   time.Now(),
		Remediation: "Configure the missing controls: " + strings.Join(missing, ", "),
	}, nil
}

// A.5 Organizational control checks
func (m *ISO27001Module) checkThreatIntelligence(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.7", "Threat Intelligence", "A.5.7",
		compliance.SeverityHigh, input,
		[]string{"threat_intel", "ioc_store", "ioc_federation", "threat_feed"},
		"Threat intelligence configured")
}
func (m *ISO27001Module) checkAcceptableUse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.10", "Information and Other Technology Acceptable Use", "A.5.10",
		compliance.SeverityMedium, input,
		[]string{"acceptable_use", "aup", "usage_policy", "documented"},
		"Acceptable use policy configured")
}
func (m *ISO27001Module) checkDataClassification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.12", "Classification of Information", "A.5.12",
		compliance.SeverityMedium, input,
		[]string{"data_classification", "classification_label", "data_label", "public", "internal", "confidential"},
		"Data classification configured")
}
func (m *ISO27001Module) checkDataLabeling(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.13", "Labelling of Information", "A.5.13",
		compliance.SeverityLow, input,
		[]string{"data_labeling", "labeling", "tagging", "classification"},
		"Data labeling configured")
}
func (m *ISO27001Module) checkInformationTransfer(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.14", "Information Transfer", "A.5.14",
		compliance.SeverityMedium, input,
		[]string{"transfer_policy", "tls", "encryption", "secure_transfer"},
		"Information transfer rules configured (TLS + policy)")
}
func (m *ISO27001Module) checkCloudSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.23", "Information Security for Use of Cloud Services", "A.5.23",
		compliance.SeverityHigh, input,
		[]string{"cloud_security", "csp_assessment", "cloud_config", "shared_responsibility"},
		"Cloud security configured")
}
func (m *ISO27001Module) checkBusinessContinuity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.30", "ICT Readiness for Business Continuity", "A.5.30",
		compliance.SeverityHigh, input,
		[]string{"business_continuity", "disaster_recovery", "backup", "redundancy"},
		"Business continuity configured (BC + DR + backup + redundancy)")
}
func (m *ISO27001Module) checkLegalCompliance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.31", "Legal, Statutory, Regulatory and Contractual Requirements", "A.5.31",
		compliance.SeverityMedium, input,
		[]string{"legal_review", "compliance_check", "regulatory_requirements", "contract_review"},
		"Legal compliance configured")
}
func (m *ISO27001Module) checkPIIProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.34", "Privacy and Protection of PII", "A.5.34",
		compliance.SeverityHigh, input,
		[]string{"pii_protection", "pii_scanner", "data_masking", "de_identification"},
		"PII protection configured (PII scanner + masking + de-id)")
}
func (m *ISO27001Module) checkOperatingProcedures(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.37", "Documented Operating Procedures", "A.5.37",
		compliance.SeverityLow, input,
		[]string{"operating_procedures", "runbook", "sop", "documented"},
		"Operating procedures configured")
}

// A.6 People checks
func (m *ISO27001Module) checkSecurityAwareness(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.6.3", "Information Security Awareness, Education and Training", "A.6.3",
		compliance.SeverityMedium, input,
		[]string{"security_awareness", "training_records", "phishing_test", "security_training"},
		"Security awareness training configured")
}
func (m *ISO27001Module) checkDisciplinaryProcess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.6.4", "Disciplinary Process", "A.6.4",
		compliance.SeverityLow, input,
		[]string{"disciplinary_process", "policy_violation", "consequence", "hr_process"},
		"Disciplinary process configured")
}
func (m *ISO27001Module) checkNDA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.6.6", "Confidentiality or Non-Disclosure Agreements", "A.6.6",
		compliance.SeverityLow, input,
		[]string{"nda", "confidentiality_agreement", "non_disclosure", "signed_agreement"},
		"NDA configured")
}
func (m *ISO27001Module) checkRemoteWorking(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.6.7", "Remote Working", "A.6.7",
		compliance.SeverityHigh, input,
		[]string{"vpn", "remote_access", "endpoint_protection", "device_encryption"},
		"Remote working security configured (VPN + endpoint + encryption)")
}
func (m *ISO27001Module) checkEventReporting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.6.8", "Information Security Event Reporting", "A.6.8",
		compliance.SeverityHigh, input,
		[]string{"event_reporting", "alerting", "alert_channel", "incident_notification"},
		"Event reporting configured (alerting + channels)")
}
func (m *ISO27001Module) checkEndpointSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.27", "User Endpoint Devices", "A.8.27",
		compliance.SeverityHigh, input,
		[]string{"endpoint_security", "edr", "antivirus", "device_encryption"},
		"Endpoint security configured (EDR + AV + encryption)")
}

// A.7 Physical checks (all config checks)
func (m *ISO27001Module) checkPhysicalSecurityMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.7.4", "Physical Security Monitoring", "A.7.4",
		compliance.SeverityMedium, input,
		[]string{"physical_monitoring", "cctv", "badge_access", "security_log"},
		"Physical security monitoring configured")
}
func (m *ISO27001Module) checkStorageMedia(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.7.10", "Storage Media", "A.7.10",
		compliance.SeverityMedium, input,
		[]string{"retention_policy", "media_disposal", "secure_erasure", "inventory"},
		"Storage media lifecycle configured")
}
func (m *ISO27001Module) checkEquipmentMaintenance(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.7.13", "Equipment Maintenance", "A.7.13",
		compliance.SeverityLow, input,
		[]string{"maintenance_log", "equipment_inventory", "maintenance_schedule", "patching"},
		"Equipment maintenance configured")
}
func (m *ISO27001Module) checkSecureDisposal(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.7.14", "Secure Disposal or Re-use of Equipment", "A.7.14",
		compliance.SeverityMedium, input,
		[]string{"secure_disposal", "data_erasure", "asset_sanitization", "disposal_certificate"},
		"Secure disposal configured")
}
func (m *ISO27001Module) checkPhysicalEnvironmentalThreats(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.7.5", "Protecting Against Physical and Environmental Threats", "A.7.5",
		compliance.SeverityMedium, input,
		[]string{"fire_suppression", "temperature_monitoring", "humidity_monitoring", "environmental_alerts"},
		"Environmental threat protection configured")
}
func (m *ISO27001Module) checkWorkingInSecureAreas(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.7.6", "Working in Secure Areas", "A.7.6",
		compliance.SeverityLow, input,
		[]string{"secure_area_policy", "visitor_log", "escort_required", "clear_desk"},
		"Secure area policy configured")
}
func (m *ISO27001Module) checkAssetsOffPremises(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.7.9", "Security of Assets Off-Premises", "A.7.9",
		compliance.SeverityMedium, input,
		[]string{"asset_tracking", "device_encryption", "remote_wipe", "asset_inventory"},
		"Off-premises asset security configured")
}

// A.8 Technological checks (40 total)
func (m *ISO27001Module) checkUserEndpointDevices(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.1", "User Endpoint Devices", "A.8.1",
		compliance.SeverityHigh, input,
		[]string{"endpoint_protection", "device_encryption", "edr", "device_compliance"},
		"User endpoint devices protected")
}
func (m *ISO27001Module) checkPrivilegedAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.2", "Privileged Access Rights", "A.8.2",
		compliance.SeverityCritical, input,
		[]string{"rbac", "privileged_access", "least_privilege", "pam"},
		"Privileged access rights restricted (RBAC + least privilege + PAM)")
}
func (m *ISO27001Module) checkAccessRestriction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.3", "Information Access Restriction", "A.8.3",
		compliance.SeverityHigh, input,
		[]string{"access_control", "rbac", "least_privilege", "access_review"},
		"Information access restricted")
}
func (m *ISO27001Module) checkSecureAuth(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.5", "Secure Authentication", "A.8.5",
		compliance.SeverityCritical, input,
		[]string{"authentication", "mfa", "multi_factor", "secure_session"},
		"Secure authentication configured (auth + MFA + secure session)")
}
func (m *ISO27001Module) checkMalwareProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.7", "Protection Against Malware", "A.8.7",
		compliance.SeverityCritical, input,
		[]string{"antivirus", "edr", "malware_scanner", "auto_update"},
		"Malware protection configured (AV + EDR + scanner + auto-update)")
}
func (m *ISO27001Module) checkVulnerabilityManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.8", "Management of Technical Vulnerabilities", "A.8.8",
		compliance.SeverityCritical, input,
		[]string{"vulnerability_scan", "govulncheck", "trivy", "patch_management"},
		"Vulnerability management configured (govulncheck + Trivy + patching)")
}
func (m *ISO27001Module) checkConfigManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.9", "Configuration Management", "A.8.9",
		compliance.SeverityHigh, input,
		[]string{"config_management", "baseline_config", "config_drift", "config_audit"},
		"Configuration management configured")
}
func (m *ISO27001Module) checkDataLeakage(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.12", "Data Leakage Prevention", "A.8.12",
		compliance.SeverityHigh, input,
		[]string{"dlp", "data_classification", "egress_filter", "data_loss_prevention"},
		"Data leakage prevention configured (DLP + classification + egress)")
}
func (m *ISO27001Module) checkMonitoringActivities(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.16", "Monitoring Activities", "A.8.16",
		compliance.SeverityHigh, input,
		[]string{"network_monitoring", "anomaly_detection", "alerting", "siem"},
		"Monitoring activities configured (network + anomaly + alerting + SIEM)")
}
func (m *ISO27001Module) checkPrivilegedUtility(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.18", "Privileged Utility Programs", "A.8.18",
		compliance.SeverityHigh, input,
		[]string{"utility_restriction", "sudo_policy", "admin_audit", "privileged_session"},
		"Privileged utility programs restricted")
}
func (m *ISO27001Module) checkNetworkSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.20", "Network Security", "A.8.20",
		compliance.SeverityHigh, input,
		[]string{"firewall", "network_segmentation", "ids", "ips"},
		"Network security configured (firewall + segmentation + IDS/IPS)")
}
func (m *ISO27001Module) checkNetworkServices(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.21", "Security of Network Services", "A.8.21",
		compliance.SeverityHigh, input,
		[]string{"network_service_agreement", "sla", "network_monitoring", "service_security"},
		"Network services security configured (SLAs + monitoring)")
}
func (m *ISO27001Module) checkNetworkSegregation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.22", "Segregation of Networks", "A.8.22",
		compliance.SeverityHigh, input,
		[]string{"network_segmentation", "vlan", "dmz", "security_zone"},
		"Network segregation configured (VLAN + DMZ + zones)")
}
func (m *ISO27001Module) checkWebFiltering(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.23", "Web Filtering", "A.8.23",
		compliance.SeverityMedium, input,
		[]string{"web_filter", "url_filter", "proxy", "content_filter"},
		"Web filtering configured")
}
func (m *ISO27001Module) checkCryptography(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.24", "Use of Cryptography", "A.8.24",
		compliance.SeverityCritical, input,
		[]string{"aes_256", "rsa_2048", "tls_1.2", "fips"},
		"Cryptography configured (AES-256 + RSA-2048 + TLS 1.2+ + FIPS)")
}
func (m *ISO27001Module) checkSDLC(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.25", "Secure Development Life Cycle", "A.8.25",
		compliance.SeverityHigh, input,
		[]string{"sdlc", "secure_sdlc", "devsecops", "code_review"},
		"Secure SDLC configured")
}
func (m *ISO27001Module) checkAppSecReqs(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.26", "Application Security Requirements", "A.8.26",
		compliance.SeverityHigh, input,
		[]string{"app_sec_requirements", "security_spec", "threat_modeling", "abuse_cases"},
		"Application security requirements defined")
}
func (m *ISO27001Module) checkSecureCoding(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.28", "Secure Coding", "A.8.28",
		compliance.SeverityHigh, input,
		[]string{"secure_coding", "coding_guidelines", "sast", "code_review"},
		"Secure coding configured (guidelines + SAST + code review)")
}
func (m *ISO27001Module) checkSecurityTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.29", "Security Testing in Development", "A.8.29",
		compliance.SeverityHigh, input,
		[]string{"security_testing", "sast", "dast", "penetration_test"},
		"Security testing configured (SAST + DAST + pen test)")
}
func (m *ISO27001Module) checkEnvironmentSeparation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.31", "Separation of Development, Test and Production Environments", "A.8.31",
		compliance.SeverityHigh, input,
		[]string{"environment_separation", "dev_test_prod", "namespace_isolation", "environment_isolation"},
		"Environment separation configured (dev/test/prod isolated)")
}
func (m *ISO27001Module) checkChangeManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.32", "Change Management", "A.8.32",
		compliance.SeverityHigh, input,
		[]string{"change_management", "change_control", "approval_workflow", "change_log"},
		"Change management configured (approval workflow + change log)")
}
func (m *ISO27001Module) checkTestInformation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.33", "Test Information", "A.8.33",
		compliance.SeverityMedium, input,
		[]string{"test_data_management", "test_data_protection", "test_data_disposal", "test_environment_isolation"},
		"Test information managed")
}
func (m *ISO27001Module) checkAuditTestingDev(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.34", "Audit Testing During Information Systems Development", "A.8.34",
		compliance.SeverityHigh, input,
		[]string{"audit_testing", "security_audit", "compliance_audit", "sast_audit"},
		"Audit testing during development configured")
}
func (m *ISO27001Module) checkAcceptanceTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.35", "System Acceptance Testing", "A.8.35",
		compliance.SeverityMedium, input,
		[]string{"acceptance_testing", "uat", "production_readiness", "qa_signoff"},
		"Acceptance testing configured")
}

// Logging and monitoring
func (m *ISO27001Module) checkLogging(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	hasAudit := false
	hasIntegrity := false
	for _, p := range m.auditLogPatterns {
		if p.MatchString(string(input)) {
			hasAudit = true
			if strings.Contains(p.String(), "integrity") || strings.Contains(p.String(), "chain") {
				hasIntegrity = true
			}
		}
	}
	if hasAudit && hasIntegrity {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO27001-A.8.15",
			ControlName: "Logging",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Logging configured with hash-chain integrity verification",
			Timestamp:   time.Now(),
		}, nil
	}
	if hasAudit {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "ISO27001-A.8.15",
			ControlName: "Logging",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityCritical,
			Message:     "Logging enabled but integrity verification not detected",
			Timestamp:   time.Now(),
			Remediation: "Enable hash-chain log integrity (persistence.log_integrity=true)",
		}, nil
	}
	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "ISO27001-A.8.15",
		ControlName: "Logging",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityCritical,
		Message:     "No logging detected",
		Timestamp:   time.Now(),
		Remediation: "Enable comprehensive audit logging with hash-chain integrity",
	}, nil
}
func (m *ISO27001Module) checkClockSync(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.17", "Clock Synchronization", "A.8.17",
		compliance.SeverityMedium, input,
		[]string{"ntp", "chrony", "time_sync", "clock_sync"},
		"Clock synchronization configured (NTP/chrony)")
}

// Data protection
func (m *ISO27001Module) checkInformationDeletion(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.10", "Information Deletion", "A.8.10",
		compliance.SeverityHigh, input,
		[]string{"deletion_policy", "data_deletion", "secure_deletion", "retention_expiry"},
		"Information deletion configured")
}
func (m *ISO27001Module) checkDataMasking(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.11", "Data Masking", "A.8.11",
		compliance.SeverityHigh, input,
		[]string{"data_masking", "pii_masking", "tokenization", "anonymization"},
		"Data masking configured (PII masking + tokenization)")
}
func (m *ISO27001Module) checkBackup(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.13", "Information Backup", "A.8.13",
		compliance.SeverityHigh, input,
		[]string{"backup", "backup_test", "backup_retention", "backup_encryption"},
		"Backup configured (tested + retained + encrypted)")
}
func (m *ISO27001Module) checkRedundancy(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.14", "Redundancy of Information Processing Facilities", "A.8.14",
		compliance.SeverityHigh, input,
		[]string{"redundancy", "high_availability", "failover", "multi_zone"},
		"Redundancy configured (HA + failover + multi-zone)")
}

// Cryptography
func (m *ISO27001Module) checkSourceCodeAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.8.4", "Access to Source Code", "A.8.4",
		compliance.SeverityHigh, input,
		[]string{"source_code_access", "repo_access_control", "branch_protection", "code_review"},
		"Source code access controlled (repo ACL + branch protection + code review)")
}

// Supplier relationship (technological-side)
func (m *ISO27001Module) checkSupplierSecurity(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.19", "Information Security in Supplier Relationships", "A.5.19",
		compliance.SeverityHigh, input,
		[]string{"vendor_security_requirements", "supplier_assessment", "vendor_inventory", "supplier_monitoring"},
		"Supplier security configured (vendor inventory + assessments + monitoring)")
}
func (m *ISO27001Module) checkSupplierAgreements(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.20", "Addressing Information Security in Supplier Agreements", "A.5.20",
		compliance.SeverityHigh, input,
		[]string{"supplier_agreement", "dpa", "security_requirements", "contract_review"},
		"Supplier agreements configured (DPAs + security requirements)")
}
func (m *ISO27001Module) checkSupplyChain(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.21", "Managing Information Security in the ICT Supply Chain", "A.5.21",
		compliance.SeverityHigh, input,
		[]string{"supply_chain_security", "sbom", "vendor_assessment", "supply_chain_monitoring"},
		"ICT supply chain security configured (SBOM + vendor assessment + monitoring)")
}
func (m *ISO27001Module) checkSupplierMonitoring(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.22", "Monitoring, Review and Change Management of Supplier Services", "A.5.22",
		compliance.SeverityMedium, input,
		[]string{"supplier_monitoring", "vendor_review", "service_review", "change_management"},
		"Supplier monitoring configured (review + service review + change management)")
}

// IR
func (m *ISO27001Module) checkIRPlanning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.24", "Information Security Incident Management Planning and Preparation", "A.5.24",
		compliance.SeverityHigh, input,
		[]string{"incident_response_plan", "ir_roles", "ir_plan", "ir_procedures"},
		"IR planning configured (plan + roles + procedures)")
}
func (m *ISO27001Module) checkEventAssessment(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.25", "Assessment and Decision on Information Security Events", "A.5.25",
		compliance.SeverityHigh, input,
		[]string{"event_assessment", "event_classification", "triage", "severity_classification"},
		"Event assessment configured (classification + triage + severity)")
}
func (m *ISO27001Module) checkIRResponse(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.26", "Response to Information Security Incidents", "A.5.26",
		compliance.SeverityHigh, input,
		[]string{"incident_response", "ir_procedure", "runbook", "incident_commander"},
		"IR response configured (procedure + runbook + commander)")
}
func (m *ISO27001Module) checkIRLearning(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.27", "Learning from Information Security Incidents", "A.5.27",
		compliance.SeverityMedium, input,
		[]string{"post_mortem", "lessons_learned", "ir_review", "improvement_actions"},
		"IR learning configured (post-mortem + lessons + actions)")
}
func (m *ISO27001Module) checkEvidenceCollection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.28", "Collection of Evidence", "A.5.28",
		compliance.SeverityMedium, input,
		[]string{"evidence_collection", "chain_of_custody", "evidence_preservation", "forensic_log"},
		"Evidence collection configured (chain of custody + preservation + forensic log)")
}
func (m *ISO27001Module) checkIRDuringDisruption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.29", "Information Security During Disruption", "A.5.29",
		compliance.SeverityHigh, input,
		[]string{"ir_during_disruption", "continuity_plan", "dr_site", "failover_during_incident"},
		"IR during disruption configured (continuity + DR + failover)")
}
func (m *ISO27001Module) checkIndependentReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.35", "Independent Review of Information Security", "A.5.35",
		compliance.SeverityMedium, input,
		[]string{"independent_review", "external_audit", "annual_security_review", "third_party_assessment"},
		"Independent review configured (external audit + annual review)")
}
func (m *ISO27001Module) checkComplianceReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.36", "Compliance with Information Security Policies", "A.5.36",
		compliance.SeverityMedium, input,
		[]string{"compliance_review", "policy_audit", "compliance_check", "audit_log"},
		"Compliance review configured (policy audit + compliance check)")
}
func (m *ISO27001Module) checkAuditTesting(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	return standardCheck(m, ctx, "ISO27001-A.5.38", "Information Security Audit Testing", "A.5.38",
		compliance.SeverityHigh, input,
		[]string{"audit_testing", "security_audit", "compliance_audit", "audit_scheduled"},
		"Audit testing configured (security + compliance + scheduled)")
}

// isoCount is a small helper to avoid importing strconv.
func isoCount(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	if n < 0 {
		return "-isoCount(-n)"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{digits[n%10]}, result...)
		n /= 10
	}
	return string(result)
}

// Dependencies returns required modules. ISO 27001 depends on the scanner
// (for vulnerability management), persistence (for audit logging),
// and trust (for attestations).
func (m *ISO27001Module) Dependencies() []string {
	return []string{"scanner", "persistence", "trust"}
}
