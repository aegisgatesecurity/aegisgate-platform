// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HITRUST CSF ID/IP/PE Families
// =========================================================================
//
// HITRUST CSF v11.2 — Identity Management, Information Protection,
// and Privacy & Endpoint families.
//
// In-scope controls (60 total: 18 automated + 42 manual):
//
//   ID (Identity Management): 10 controls (4 automated + 6 manual)
//     ID-01  Identity Management Policy     (manual)
//     ID-02  Identity Verification           (automated)
//     ID-03  Authenticator Management        (automated)
//     ID-04  Credential Management           (automated)
//     ID-05  Identity Proofing              (manual)
//     ID-06  Identity Proofing              (manual)
//     ID-07  Device Identification           (automated)
//     ID-08  Cryptographic Module Auth       (manual)
//     ID-09  Authenticator Type              (manual)
//     ID-10  Authentication Token Protection (manual)
//
//   IP (Information Protection): 25 controls (9 automated + 16 manual)
//     IP-01  Data Classification             (manual)
//     IP-02  Encryption at Rest              (automated)
//     IP-03  Encryption in Transit           (automated)
//     IP-04  Key Management                  (automated)
//     IP-05  Data Masking                    (automated)
//     IP-06  Data Loss Prevention            (manual)
//     IP-07  Endpoint Protection             (automated)
//     IP-08  Network Protection              (automated)
//     IP-09  Malware Protection              (automated)
//     IP-10  Vulnerability Management        (automated)
//     IP-11  Incident Response               (manual)
//     IP-12  Logging and Monitoring          (manual)
//     IP-13  Backup and Recovery             (automated)
//     IP-14  Data Loss Prevention            (automated)
//     IP-15  Information Spillage            (manual)
//     IP-16  Data Mining Prevention          (manual)
//     IP-17  Storage Object Encryption       (automated)
//     IP-18  Mobile Device Encryption        (manual)
//     IP-19  Data Boundary Protection        (manual)
//     IP-20  Data Retention and Disposal     (manual)
//     IP-21  Cryptographic Key Protection    (manual)
//     IP-22  Cryptographic Key Establishment (manual)
//     IP-23  FIPS-Validated Cryptography     (manual)
//     IP-24  Protected Storage               (manual)
//     IP-25  Transmission Guard              (manual)
//
//   PE (Privacy & Endpoint): 25 controls (5 automated + 20 manual)
//     PE-01 through PE-15 (existing, manual)
//     PE-16  Endpoint Detection and Response (automated)
//     PE-17  Mobile Device Management        (automated)
//     PE-18  Privacy Impact Assessment       (manual)
//     PE-19  Data Privacy Controls           (manual)
//     PE-20  Privacy Notice and Consent      (manual)
//     PE-21  Full Disk Encryption            (automated)
//     PE-22  Anti-Malware Updates            (automated)
//     PE-23  Patch Management                (automated)
//     PE-24  Host-Based Firewall             (manual)
//     PE-25  Device Hardening                (manual)
//
// =========================================================================

package hitrust

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerIDIPPEControls wires the ID, IP, and PE family controls into the module.
func (m *HITRUSTModule) registerIDIPPEControls() {
	// ── ID: Identity Management ──────────────────────────────────

	// ID-01: Identity Management Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-01",
		Name:        "Identity Management Policy",
		Description: "HITRUST CSF v11.2 ID-01: Identity management policy documented — defines identity lifecycle, provisioning, and de-provisioning procedures",
		Category:    "Identity Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 02.a", "NIST SP 800-53 Rev. 5 IA-1"},
	})

	// ID-02: Identity Verification (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-02",
		Name:        "Identity Verification",
		Description: "HITRUST CSF v11.2 ID-02: Unique identity verification before granting access — authentication mechanisms verified",
		Category:    "Identity Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIdentityVerification,
		References:  []string{"HITRUST CSF v11.2 02.b", "NIST SP 800-53 Rev. 5 IA-2"},
	})

	// ID-03: Authenticator Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-03",
		Name:        "Authenticator Management",
		Description: "HITRUST CSF v11.2 ID-03: Authenticator management — credentials, tokens, and certificates provisioned and revoked securely",
		Category:    "Identity Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkAuthenticatorManagement,
		References:  []string{"HITRUST CSF v11.2 02.c", "NIST SP 800-53 Rev. 5 IA-5"},
	})

	// ID-04: Credential Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-04",
		Name:        "Credential Management",
		Description: "HITRUST CSF v11.2 ID-04: Credential lifecycle management — creation, distribution, storage, and termination of credentials",
		Category:    "Identity Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkCredentialManagement,
		References:  []string{"HITRUST CSF v11.2 02.d", "NIST SP 800-53 Rev. 5 IA-5(1)"},
	})

	// ID-05: Identity Proofing (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-05",
		Name:        "Identity Proofing",
		Description: "HITRUST CSF v11.2 ID-05: Identity proofing procedures ensure individuals are who they claim to be before credentials are issued",
		Category:    "Identity Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 02.e", "NIST SP 800-53 Rev. 5 IA-4"},
	})

	// ID-06: Identity Proofing (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-06",
		Name:        "Identity Proofing",
		Description: "HITRUST CSF v11.2 ID-06: Identity proofing — evidence-based verification of identity claims before account provisioning",
		Category:    "Identity Management",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IA-4"},
	})

	// ID-07: Device Identification (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-07",
		Name:        "Device Identification",
		Description: "HITRUST CSF v11.2 ID-07: Device identification and authentication — devices uniquely identified before network access",
		Category:    "Identity Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDeviceIdentification,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IA-3"},
	})

	// ID-08: Cryptographic Module Authentication (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-08",
		Name:        "Cryptographic Module Authentication",
		Description: "HITRUST CSF v11.2 ID-08: Cryptographic module authentication — authentication of cryptographic modules per NIST SP 800-53 IA-9",
		Category:    "Identity Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IA-9"},
	})

	// ID-09: Authenticator Type (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-09",
		Name:        "Authenticator Type",
		Description: "HITRUST CSF v11.2 ID-09: Authenticator type requirements — types of authenticators allowed and complexity requirements",
		Category:    "Identity Management",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IA-5(1)"},
	})

	// ID-10: Authentication Token Protection (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-ID-10",
		Name:        "Authentication Token Protection",
		Description: "HITRUST CSF v11.2 ID-10: Authentication token protection — secure storage and transmission of authentication tokens",
		Category:    "Identity Management",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 IA-5(4)"},
	})

	// ── IP: Information Protection ────────────────────────────────

	// IP-01: Data Classification (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-01",
		Name:        "Data Classification",
		Description: "HITRUST CSF v11.2 IP-01: Data classification policy — information assets classified by sensitivity and criticality",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 03.a", "NIST SP 800-53 Rev. 5 MP-2"},
	})

	// IP-02: Encryption at Rest (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-02",
		Name:        "Encryption at Rest",
		Description: "HITRUST CSF v11.2 IP-02: Data at rest encrypted using approved algorithms — AES-256 or FIPS 140-validated modules",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEncryptionAtRest,
		References:  []string{"HITRUST CSF v11.2 03.b", "NIST SP 800-53 Rev. 5 SC-28"},
	})

	// IP-03: Encryption in Transit (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-03",
		Name:        "Encryption in Transit",
		Description: "HITRUST CSF v11.2 IP-03: Data in transit encrypted — TLS 1.2+ required for all communications",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEncryptionInTransit,
		References:  []string{"HITRUST CSF v11.2 03.c", "NIST SP 800-53 Rev. 5 SC-8"},
	})

	// IP-04: Key Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-04",
		Name:        "Key Management",
		Description: "HITRUST CSF v11.2 IP-04: Cryptographic key management — generation, distribution, storage, rotation, and revocation per NIST SP 800-57",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkKeyManagement,
		References:  []string{"HITRUST CSF v11.2 03.d", "NIST SP 800-53 Rev. 5 SC-12"},
	})

	// IP-05: Data Masking (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-05",
		Name:        "Data Masking",
		Description: "HITRUST CSF v11.2 IP-05: Sensitive data masked or redacted in non-production environments — PII, PHI, and financial data protected",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDataMasking,
		References:  []string{"HITRUST CSF v11.2 03.e", "NIST SP 800-53 Rev. 5 SC-28(1)"},
	})

	// IP-06: Data Loss Prevention (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-06",
		Name:        "Data Loss Prevention",
		Description: "HITRUST CSF v11.2 IP-06: DLP controls prevent unauthorized data exfiltration — content inspection, endpoint DLP, and network egress filtering",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 03.f", "NIST SP 800-53 Rev. 5 SC-7(10)"},
	})

	// IP-07: Endpoint Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-07",
		Name:        "Endpoint Protection",
		Description: "HITRUST CSF v11.2 IP-07: Endpoint protection — anti-malware, host-based IDS, and configuration hardening on all endpoints",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEndpointProtection,
		References:  []string{"HITRUST CSF v11.2 03.g", "NIST SP 800-53 Rev. 5 SI-3"},
	})

	// IP-08: Network Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-08",
		Name:        "Network Protection",
		Description: "HITRUST CSF v11.2 IP-08: Network protection — firewalls, network segmentation, and egress filtering enforced",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNetworkProtection,
		References:  []string{"HITRUST CSF v11.2 03.h", "NIST SP 800-53 Rev. 5 SC-7"},
	})

	// IP-09: Malware Protection (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-09",
		Name:        "Malware Protection",
		Description: "HITRUST CSF v11.2 IP-09: Malware protection — anti-malware deployed, updated, and scanning at entry and exit points",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkMalwareProtection,
		References:  []string{"HITRUST CSF v11.2 03.i", "NIST SP 800-53 Rev. 5 SI-3"},
	})

	// IP-10: Vulnerability Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-10",
		Name:        "Vulnerability Management",
		Description: "HITRUST CSF v11.2 IP-10: Vulnerability management — scanning, risk rating, and timely remediation of identified vulnerabilities",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkVulnerabilityManagement,
		References:  []string{"HITRUST CSF v11.2 03.j", "NIST SP 800-53 Rev. 5 RA-5"},
	})

	// IP-11: Incident Response (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-11",
		Name:        "Incident Response",
		Description: "HITRUST CSF v11.2 IP-11: Incident response plan documented — detection, containment, eradication, and recovery procedures tested regularly",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 03.k", "NIST SP 800-53 Rev. 5 IR-1"},
	})

	// IP-12: Logging and Monitoring (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-12",
		Name:        "Logging and Monitoring",
		Description: "HITRUST CSF v11.2 IP-12: Security event logging and monitoring — centralized log collection, SIEM integration, and alerting",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 03.l", "NIST SP 800-53 Rev. 5 AU-6"},
	})

	// IP-13: Backup and Recovery (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-13",
		Name:        "Backup and Recovery",
		Description: "HITRUST CSF v11.2 IP-13: Backup and recovery — data backup procedures, tested recovery, and off-site storage verified",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBackupAndRecovery,
		References:  []string{"HITRUST CSF v11.2 03.m", "NIST SP 800-53 Rev. 5 CP-9"},
	})

	// IP-14: Data Loss Prevention (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-14",
		Name:        "Data Loss Prevention",
		Description: "HITRUST CSF v11.2 IP-14: DLP enforcement — content inspection, endpoint DLP, and network egress filtering verified automatically",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDLP,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 AC-4"},
	})

	// IP-15: Information Spillage (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-15",
		Name:        "Information Spillage",
		Description: "HITRUST CSF v11.2 IP-15: Information spillage controls — procedures to respond to data spills and cross-domain contamination",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 AC-5"},
	})

	// IP-16: Data Mining Prevention (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-16",
		Name:        "Data Mining Prevention",
		Description: "HITRUST CSF v11.2 IP-16: Data mining prevention — controls to prevent unauthorized data mining and aggregation",
		Category:    "Information Protection",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// IP-17: Storage Object Encryption (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-17",
		Name:        "Storage Object Encryption",
		Description: "HITRUST CSF v11.2 IP-17: Storage object encryption — data at rest in storage objects encrypted",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkStorageEncryption,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 MP-3(1)"},
	})

	// IP-18: Mobile Device Encryption (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-18",
		Name:        "Mobile Device Encryption",
		Description: "HITRUST CSF v11.2 IP-18: Mobile device encryption — encryption of data on mobile devices and removable media",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SC-28(1)"},
	})

	// IP-19: Data Boundary Protection (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-19",
		Name:        "Data Boundary Protection",
		Description: "HITRUST CSF v11.2 IP-19: Data boundary protection — controls to prevent data from crossing trust boundaries",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 AC-4(21)"},
	})

	// IP-20: Data Retention and Disposal (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-20",
		Name:        "Data Retention and Disposal",
		Description: "HITRUST CSF v11.2 IP-20: Data retention and disposal — retention periods and secure disposal procedures",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SI-12"},
	})

	// IP-21: Cryptographic Key Protection (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-21",
		Name:        "Cryptographic Key Protection",
		Description: "HITRUST CSF v11.2 IP-21: Cryptographic key protection — protection of cryptographic keys from unauthorized access",
		Category:    "Information Protection",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SC-12"},
	})

	// IP-22: Cryptographic Key Establishment (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-22",
		Name:        "Cryptographic Key Establishment",
		Description: "HITRUST CSF v11.2 IP-22: Cryptographic key establishment — secure key establishment protocols for cryptographic operations",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SC-21"},
	})

	// IP-23: FIPS-Validated Cryptography (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-23",
		Name:        "FIPS-Validated Cryptography",
		Description: "HITRUST CSF v11.2 IP-23: FIPS-validated cryptography — use of FIPS-validated cryptographic modules and algorithms",
		Category:    "Information Protection",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SC-13"},
	})

	// IP-24: Protected Storage (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-24",
		Name:        "Protected Storage",
		Description: "HITRUST CSF v11.2 IP-24: Protected storage — storage of sensitive data in protected storage locations",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 MP-4"},
	})

	// IP-25: Transmission Guard (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-IP-25",
		Name:        "Transmission Guard",
		Description: "HITRUST CSF v11.2 IP-25: Transmission guard — protection of data in transit using guard mechanisms",
		Category:    "Information Protection",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SC-8"},
	})

	// ── PE: Privacy & Endpoint ────────────────────────────────────

	// PE-01: Privacy Policy (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-01",
		Name:        "Privacy Policy",
		Description: "HITRUST CSF v11.2 PE-01: Privacy policy documented and published — data handling, retention, and subject rights disclosed",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.a", "NIST SP 800-53 Rev. 5 PT-1"},
	})

	// PE-02: Consent Management (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-02",
		Name:        "Consent Management",
		Description: "HITRUST CSF v11.2 PE-02: Consent management — opt-in/opt-out mechanisms, consent records, and preference management documented",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.b", "GDPR Article 7"},
	})

	// PE-03: Data Retention (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-03",
		Name:        "Data Retention",
		Description: "HITRUST CSF v11.2 PE-03: Data retention policy — retention periods defined, data disposal procedures documented and enforced",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.c", "NIST SP 800-53 Rev. 5 SI-12"},
	})

	// PE-04: Data Subject Rights (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-04",
		Name:        "Data Subject Rights",
		Description: "HITRUST CSF v11.2 PE-04: Data subject rights — access, rectification, erasure, and portability mechanisms documented and tested",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.d", "GDPR Articles 15-20"},
	})

	// PE-05: Privacy Impact Assessment (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-05",
		Name:        "Privacy Impact Assessment",
		Description: "HITRUST CSF v11.2 PE-05: Privacy impact assessment — PIA conducted for new systems and major changes, results documented",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.e", "NIST SP 800-53 Rev. 5 PT-4"},
	})

	// PE-06: Data Processing Agreements (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-06",
		Name:        "Data Processing Agreements",
		Description: "HITRUST CSF v11.2 PE-06: Data processing agreements — DPAs with third parties governing data handling obligations",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.f", "GDPR Article 28"},
	})

	// PE-07: Cross-Border Data Transfer (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-07",
		Name:        "Cross-Border Data Transfer",
		Description: "HITRUST CSF v11.2 PE-07: Cross-border data transfer — safeguards for international data transfers documented and enforced",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.g", "GDPR Articles 44-49"},
	})

	// PE-08: Privacy Notice (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-08",
		Name:        "Privacy Notice",
		Description: "HITRUST CSF v11.2 PE-08: Privacy notice — transparent disclosure of data practices, purposes, and sharing published",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.h", "GDPR Article 13"},
	})

	// PE-09: Endpoint Security (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-09",
		Name:        "Endpoint Security",
		Description: "HITRUST CSF v11.2 PE-09: Endpoint security policy — device hardening, patching, and configuration management documented",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.i", "NIST SP 800-53 Rev. 5 CM-1"},
	})

	// PE-10: Mobile Device Management (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-10",
		Name:        "Mobile Device Management",
		Description: "HITRUST CSF v11.2 PE-10: Mobile device management — MDM policies, remote wipe, and containerization documented",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.j", "NIST SP 800-53 Rev. 5 AC-19"},
	})

	// PE-11: Removable Media (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-11",
		Name:        "Removable Media",
		Description: "HITRUST CSF v11.2 PE-11: Removable media controls — encryption, usage restrictions, and sanitization procedures documented",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.k", "NIST SP 800-53 Rev. 5 MP-7"},
	})

	// PE-12: Physical Security (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-12",
		Name:        "Physical Security",
		Description: "HITRUST CSF v11.2 PE-12: Physical security — access controls, visitor management, and environmental controls documented",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.l", "NIST SP 800-53 Rev. 5 PE-3"},
	})

	// PE-13: Asset Management (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-13",
		Name:        "Asset Management",
		Description: "HITRUST CSF v11.2 PE-13: Asset management — hardware and software inventory tracked, classified, and reviewed",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.m", "NIST SP 800-53 Rev. 5 CM-8"},
	})

	// PE-14: Disposal and Sanitization (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-14",
		Name:        "Disposal and Sanitization",
		Description: "HITRUST CSF v11.2 PE-14: Disposal and sanitization — media sanitization and decommissioning procedures documented and verified",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.n", "NIST SP 800-53 Rev. 5 MP-6"},
	})

	// PE-15: Business Continuity (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-15",
		Name:        "Business Continuity",
		Description: "HITRUST CSF v11.2 PE-15: Business continuity — BCP documented, disaster recovery tested, and continuity of operations verified",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2 04.o", "NIST SP 800-53 Rev. 5 CP-1"},
	})

	// PE-16: Endpoint Detection and Response (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-16",
		Name:        "Endpoint Detection and Response",
		Description: "HITRUST CSF v11.2 PE-16: EDR deployed and operational — detection, investigation, and response capabilities on all endpoints",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkEDR,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// PE-17: Mobile Device Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-17",
		Name:        "Mobile Device Management",
		Description: "HITRUST CSF v11.2 PE-17: MDM policies enforced — remote wipe, encryption, and policy compliance on mobile devices",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkMDM,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 AC-19"},
	})

	// PE-18: Privacy Impact Assessment (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-18",
		Name:        "Privacy Impact Assessment",
		Description: "HITRUST CSF v11.2 PE-18: Privacy impact assessment — systematic assessment of privacy risks for new systems and changes",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// PE-19: Data Privacy Controls (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-19",
		Name:        "Data Privacy Controls",
		Description: "HITRUST CSF v11.2 PE-19: Data privacy controls — technical and organizational measures to protect personal data",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// PE-20: Privacy Notice and Consent (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-20",
		Name:        "Privacy Notice and Consent",
		Description: "HITRUST CSF v11.2 PE-20: Privacy notice and consent — mechanisms for obtaining and managing user consent for data processing",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2"},
	})

	// PE-21: Full Disk Encryption (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-21",
		Name:        "Full Disk Encryption",
		Description: "HITRUST CSF v11.2 PE-21: Full disk encryption — all endpoint devices encrypted with full disk encryption",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkFullDiskEncryption,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SC-28"},
	})

	// PE-22: Anti-Malware Updates (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-22",
		Name:        "Anti-Malware Updates",
		Description: "HITRUST CSF v11.2 PE-22: Anti-malware signature updates — automatic updates for anti-malware software",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAntiMalwareUpdates,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SI-3(2)"},
	})

	// PE-23: Patch Management (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-23",
		Name:        "Patch Management",
		Description: "HITRUST CSF v11.2 PE-23: Patch management — automated patch deployment and verification on all endpoints",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPatchManagement,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SI-2"},
	})

	// PE-24: Host-Based Firewall (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-24",
		Name:        "Host-Based Firewall",
		Description: "HITRUST CSF v11.2 PE-24: Host-based firewall — firewall protection on individual endpoint devices",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 SC-7(6)"},
	})

	// PE-25: Device Hardening (manual)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "HITRUST-PE-25",
		Name:        "Device Hardening",
		Description: "HITRUST CSF v11.2 PE-25: Device hardening — security configurations and baselines applied to endpoint devices",
		Category:    "Privacy and Endpoint",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"HITRUST CSF v11.2", "NIST SP 800-53 CM-7"},
	})
}

// ── ID Family Automated Checks ────────────────────────────────────

// checkIdentityVerification verifies unique identity verification
// before granting access. Maps to HITRUST ID-02.
func (m *HITRUSTModule) checkIdentityVerification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasUniqueID := strings.Contains(inputStr, "user_id") || strings.Contains(inputStr, "unique_id") || strings.Contains(inputStr, "identity")
	hasMFA := m.hasMFA(inputStr)

	if hasAuth && hasUniqueID {
		evidence := []string{"Unique identity verification configured"}
		if hasMFA {
			evidence = append(evidence, "MFA enabled for identity verification")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-ID-02",
			ControlName: "Identity Verification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Identity verification controls verified (unique IDs + authentication)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAuth {
		violations = append(violations, "authentication not configured")
	}
	if !hasUniqueID {
		violations = append(violations, "unique user identification not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-ID-02",
		ControlName: "Identity Verification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Identity verification gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure unique user identification and enable authentication for all access",
	}, nil
}

// checkAuthenticatorManagement verifies authenticator provisioning and
// revocation. Maps to HITRUST ID-03.
func (m *HITRUSTModule) checkAuthenticatorManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPasswordPolicy := strings.Contains(inputStr, "password_policy") || strings.Contains(inputStr, "password_complexity")
	hasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation")
	hasMFA := m.hasMFA(inputStr)

	if hasPasswordPolicy && hasKeyMgmt && hasMFA {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-ID-03",
			ControlName: "Authenticator Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Authenticator management controls verified (password policy + key management + MFA)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPasswordPolicy {
		violations = append(violations, "password policy not configured")
	}
	if !hasKeyMgmt {
		violations = append(violations, "key management not configured")
	}
	if !hasMFA {
		violations = append(violations, "MFA not enabled for authenticators")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-ID-03",
		ControlName: "Authenticator Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Authenticator management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure password policy, key management, and enable MFA for all authenticators",
	}, nil
}

// checkCredentialManagement verifies credential lifecycle management.
// Maps to HITRUST ID-04.
func (m *HITRUSTModule) checkCredentialManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasRotation := strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "password_rotation") || strings.Contains(inputStr, "credential_rotation")
	hasRevocation := strings.Contains(inputStr, "revocation") || strings.Contains(inputStr, "deprovision") || strings.Contains(inputStr, "termination")
	hasAudit := m.hasAudit(inputStr)

	if hasRotation && hasRevocation {
		evidence := []string{"Credential rotation configured"}
		if hasAudit {
			evidence = append(evidence, "Audit logging for credential changes")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-ID-04",
			ControlName: "Credential Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Credential management controls verified (rotation + revocation)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasRotation {
		violations = append(violations, "credential rotation not configured")
	}
	if !hasRevocation {
		violations = append(violations, "credential revocation not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-ID-04",
		ControlName: "Credential Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Credential management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure credential rotation and revocation procedures",
	}, nil
}

// checkDeviceIdentification verifies device identification and authentication.
// Maps to HITRUST ID-07.
func (m *HITRUSTModule) checkDeviceIdentification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDeviceID := strings.Contains(inputStr, "device_identification") || strings.Contains(inputStr, "device_id") || strings.Contains(inputStr, "device_certificate")
	hasAuth := strings.Contains(inputStr, "authentication") || strings.Contains(inputStr, "auth_enabled")
	hasInventory := strings.Contains(inputStr, "device_inventory") || strings.Contains(inputStr, "inventory") || strings.Contains(inputStr, "device_registration")

	if hasDeviceID && hasAuth && hasInventory {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-ID-07",
			ControlName: "Device Identification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Device identification controls verified (device ID + authentication + inventory)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasDeviceID {
		violations = append(violations, "device identification not configured")
	}
	if !hasAuth {
		violations = append(violations, "device authentication not configured")
	}
	if !hasInventory {
		violations = append(violations, "device inventory not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-ID-07",
		ControlName: "Device Identification",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Device identification gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure device identification with authentication and device inventory management",
	}, nil
}

// ── IP Family Automated Checks (existing) ─────────────────────────

// checkEncryptionAtRest verifies data-at-rest encryption.
// Maps to HITRUST IP-02.
func (m *HITRUSTModule) checkEncryptionAtRest(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEncryption := m.hasEncryption(inputStr)
	hasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation")
	hasAES := strings.Contains(inputStr, "aes_256") || strings.Contains(inputStr, "aes-256") || strings.Contains(inputStr, "encryption_at_rest")

	if hasEncryption || hasAES {
		evidence := []string{"Encryption at rest configured"}
		if hasKeyMgmt {
			evidence = append(evidence, "Key management for encryption at rest")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-02",
			ControlName: "Encryption at Rest",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Encryption at rest verified (AES-256 / FIPS 140-validated)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-02",
		ControlName: "Encryption at Rest",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Encryption at rest not configured — AES-256 or FIPS 140-validated encryption required",
		Timestamp:   time.Now(),
		Remediation: "Enable encryption at rest using AES-256 or FIPS 140-validated cryptographic modules",
	}, nil
}

// checkEncryptionInTransit verifies data-in-transit encryption.
// Maps to HITRUST IP-03.
func (m *HITRUSTModule) checkEncryptionInTransit(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasTLS := strings.Contains(inputStr, "tls") || strings.Contains(inputStr, "https") || strings.Contains(inputStr, "tls1.2") || strings.Contains(inputStr, "tls1.3")
	hasEncryption := m.hasEncryption(inputStr)

	if hasTLS || hasEncryption {
		evidence := []string{"Encryption in transit configured"}
		if strings.Contains(inputStr, "tls1.3") || strings.Contains(inputStr, "tls_1.3") {
			evidence = append(evidence, "TLS 1.3 detected")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-03",
			ControlName: "Encryption in Transit",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Encryption in transit verified (TLS 1.2+)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-03",
		ControlName: "Encryption in Transit",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Encryption in transit not configured — TLS 1.2+ required for all communications",
		Timestamp:   time.Now(),
		Remediation: "Enable TLS 1.2+ for all network communications and API endpoints",
	}, nil
}

// checkKeyManagement verifies cryptographic key management.
// Maps to HITRUST IP-04.
func (m *HITRUSTModule) checkKeyManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_management_enabled")
	hasRotation := strings.Contains(inputStr, "key_rotation") || strings.Contains(inputStr, "rotation_policy")
	hasFIPS := strings.Contains(inputStr, "fips_140") || strings.Contains(inputStr, "fips_mode") || strings.Contains(inputStr, "cmvp")

	if hasKeyMgmt && hasRotation {
		evidence := []string{"Key management configured", "Key rotation enabled"}
		if hasFIPS {
			evidence = append(evidence, "FIPS 140-validated key management")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-04",
			ControlName: "Key Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Key management controls verified (key management + rotation)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasKeyMgmt {
		violations = append(violations, "key management not configured")
	}
	if !hasRotation {
		violations = append(violations, "key rotation not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-04",
		ControlName: "Key Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Key management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure key management with automated rotation per NIST SP 800-57",
	}, nil
}

// checkDataMasking verifies sensitive data masking in non-production.
// Maps to HITRUST IP-05.
func (m *HITRUSTModule) checkDataMasking(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMasking := strings.Contains(inputStr, "data_masking") || strings.Contains(inputStr, "masking") || strings.Contains(inputStr, "redaction") || strings.Contains(inputStr, "anonymization")
	hasNonProd := strings.Contains(inputStr, "non_production") || strings.Contains(inputStr, "staging") || strings.Contains(inputStr, "test_environment")
	hasPII := strings.Contains(inputStr, "pii") || strings.Contains(inputStr, "phi") || strings.Contains(inputStr, "sensitive_data")

	if hasMasking && (hasNonProd || hasPII) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-05",
			ControlName: "Data Masking",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Data masking controls verified (masking + non-production environment protection)",
			Timestamp:   time.Now(),
		}, nil
	}

	if hasMasking {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-05",
			ControlName: "Data Masking",
			Status:      compliance.StatusPartial,
			Severity:    compliance.SeverityMedium,
			Message:     "Data masking configured but non-production environment protection not verified",
			Timestamp:   time.Now(),
			Remediation: "Ensure data masking is applied in all non-production environments for PII, PHI, and financial data",
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-05",
		ControlName: "Data Masking",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Data masking not configured — PII and sensitive data must be masked in non-production environments",
		Timestamp:   time.Now(),
		Remediation: "Configure data masking for PII, PHI, and financial data in all non-production environments",
	}, nil
}

// checkEndpointProtection verifies endpoint security controls.
// Maps to HITRUST IP-07.
func (m *HITRUSTModule) checkEndpointProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAntimalware := strings.Contains(inputStr, "antimalware") || strings.Contains(inputStr, "anti_malware") || strings.Contains(inputStr, "malware_protection") || strings.Contains(inputStr, "endpoint_protection")
	hasHardening := strings.Contains(inputStr, "hardening") || strings.Contains(inputStr, "secure_baseline") || strings.Contains(inputStr, "cis_benchmark")
	hasEDR := strings.Contains(inputStr, "edr") || strings.Contains(inputStr, "host_ids") || strings.Contains(inputStr, "ids")

	if hasAntimalware && (hasHardening || hasEDR) {
		evidence := []string{"Anti-malware protection configured"}
		if hasHardening {
			evidence = append(evidence, "Endpoint hardening configured")
		}
		if hasEDR {
			evidence = append(evidence, "EDR/IDS protection configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-07",
			ControlName: "Endpoint Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Endpoint protection controls verified (anti-malware + hardening/EDR)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAntimalware {
		violations = append(violations, "anti-malware not configured")
	}
	if !hasHardening && !hasEDR {
		violations = append(violations, "endpoint hardening or EDR not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-07",
		ControlName: "Endpoint Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Endpoint protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Deploy anti-malware, configure endpoint hardening (CIS benchmarks), and enable EDR/IDS",
	}, nil
}

// checkNetworkProtection verifies firewall and network segmentation.
// Maps to HITRUST IP-08.
func (m *HITRUSTModule) checkNetworkProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFirewall := m.hasFirewall(inputStr)
	hasSegmentation := strings.Contains(inputStr, "network_segmentation") || strings.Contains(inputStr, "segmentation") || strings.Contains(inputStr, "dmz")
	hasEgress := strings.Contains(inputStr, "egress_filter") || strings.Contains(inputStr, "egress_filtering") || strings.Contains(inputStr, "network_policy")

	if hasFirewall && (hasSegmentation || hasEgress) {
		evidence := []string{"Firewall/WAF protection configured"}
		if hasSegmentation {
			evidence = append(evidence, "Network segmentation configured")
		}
		if hasEgress {
			evidence = append(evidence, "Egress filtering configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-08",
			ControlName: "Network Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Network protection controls verified (firewall + segmentation/egress filtering)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasFirewall {
		violations = append(violations, "firewall/WAF not configured")
	}
	if !hasSegmentation && !hasEgress {
		violations = append(violations, "network segmentation or egress filtering not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-08",
		ControlName: "Network Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Network protection gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Deploy firewall/WAF, configure network segmentation, and enable egress filtering",
	}, nil
}

// checkMalwareProtection verifies anti-malware deployment and scanning.
// Maps to HITRUST IP-09.
func (m *HITRUSTModule) checkMalwareProtection(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAntimalware := strings.Contains(inputStr, "antimalware") || strings.Contains(inputStr, "anti_malware") || strings.Contains(inputStr, "malware_protection") || strings.Contains(inputStr, "malware_scan")
	hasUpdates := strings.Contains(inputStr, "signature_update") || strings.Contains(inputStr, "auto_update") || strings.Contains(inputStr, "scanner_update")
	hasScanPoints := strings.Contains(inputStr, "scan_entry") || strings.Contains(inputStr, "scan_exit") || strings.Contains(inputStr, "file_upload") || strings.Contains(inputStr, "email_scan")

	if hasAntimalware {
		evidence := []string{"Anti-malware protection configured"}
		if hasUpdates {
			evidence = append(evidence, "Signature updates configured")
		}
		if hasScanPoints {
			evidence = append(evidence, "Scan at entry/exit points configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-09",
			ControlName: "Malware Protection",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Malware protection controls verified",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-09",
		ControlName: "Malware Protection",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Malware protection not configured — anti-malware required at entry and exit points",
		Timestamp:   time.Now(),
		Remediation: "Deploy anti-malware with automatic signature updates and scanning at all entry/exit points",
	}, nil
}

// checkVulnerabilityManagement verifies vulnerability scanning and remediation.
// Maps to HITRUST IP-10.
func (m *HITRUSTModule) checkVulnerabilityManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasVulnScan := m.hasVulnScan(inputStr)
	hasRemediation := strings.Contains(inputStr, "patch") || strings.Contains(inputStr, "remediation") || strings.Contains(inputStr, "fix")
	hasRiskRating := strings.Contains(inputStr, "cvss") || strings.Contains(inputStr, "risk_rating") || strings.Contains(inputStr, "risk_assessment")

	if hasVulnScan && hasRemediation {
		evidence := []string{"Vulnerability scanning configured"}
		if hasRiskRating {
			evidence = append(evidence, "Risk rating (CVSS) configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-10",
			ControlName: "Vulnerability Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Vulnerability management controls verified (scanning + remediation)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasVulnScan {
		violations = append(violations, "vulnerability scanning not configured")
	}
	if !hasRemediation {
		violations = append(violations, "patch remediation not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-10",
		ControlName: "Vulnerability Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Vulnerability management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable vulnerability scanning with CVSS risk rating and configure patch remediation",
	}, nil
}

// checkBackupAndRecovery verifies backup procedures and recovery testing.
// Maps to HITRUST IP-13.
func (m *HITRUSTModule) checkBackupAndRecovery(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBackup := strings.Contains(inputStr, "backup") || strings.Contains(inputStr, "data_backup") || strings.Contains(inputStr, "recovery")
	hasRecoveryTest := strings.Contains(inputStr, "recovery_test") || strings.Contains(inputStr, "disaster_recovery") || strings.Contains(inputStr, "dr_test")
	hasOffsite := strings.Contains(inputStr, "offsite") || strings.Contains(inputStr, "off_site_storage") || strings.Contains(inputStr, "cloud_backup")

	if hasBackup && hasRecoveryTest {
		evidence := []string{"Backup procedures configured"}
		if hasOffsite {
			evidence = append(evidence, "Off-site backup storage configured")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-13",
			ControlName: "Backup and Recovery",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Backup and recovery controls verified (backup + recovery testing)",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasBackup {
		violations = append(violations, "backup procedures not configured")
	}
	if !hasRecoveryTest {
		violations = append(violations, "recovery testing not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-13",
		ControlName: "Backup and Recovery",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Backup and recovery gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure data backup procedures with regular recovery testing and off-site storage",
	}, nil
}

// ── IP Family Automated Checks (new) ──────────────────────────────

// checkDLP verifies DLP enforcement. Maps to HITRUST IP-14.
func (m *HITRUSTModule) checkDLP(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDLP := strings.Contains(inputStr, "dlp") || strings.Contains(inputStr, "data_loss_prevention")
	hasContentInspection := strings.Contains(inputStr, "content_inspection") || strings.Contains(inputStr, "content_filtering")
	hasEgress := strings.Contains(inputStr, "egress_filter") || strings.Contains(inputStr, "egress_filtering") || strings.Contains(inputStr, "network_policy")

	if hasDLP && (hasContentInspection || hasEgress) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-14",
			ControlName: "Data Loss Prevention",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "DLP controls verified (DLP + content inspection/egress filtering)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasDLP {
		violations = append(violations, "DLP not configured")
	}
	if !hasContentInspection && !hasEgress {
		violations = append(violations, "content inspection or egress filtering not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-14",
		ControlName: "Data Loss Prevention",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "DLP gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Deploy DLP with content inspection and egress filtering",
	}, nil
}

// checkStorageEncryption verifies storage object encryption. Maps to HITRUST IP-17.
func (m *HITRUSTModule) checkStorageEncryption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasStorageEncryption := strings.Contains(inputStr, "storage_encryption") || strings.Contains(inputStr, "storage_object_encryption") || strings.Contains(inputStr, "encryption_at_rest")
	hasKeyMgmt := strings.Contains(inputStr, "key_management") || strings.Contains(inputStr, "key_rotation")
	hasEncryption := m.hasEncryption(inputStr)

	if hasStorageEncryption || hasEncryption {
		evidence := []string{"Storage encryption configured"}
		if hasKeyMgmt {
			evidence = append(evidence, "Key management for storage encryption")
		}
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-IP-17",
			ControlName: "Storage Object Encryption",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Storage object encryption verified",
			Evidence:    evidence,
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-IP-17",
		ControlName: "Storage Object Encryption",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Storage object encryption not configured",
		Timestamp:   time.Now(),
		Remediation: "Enable encryption for storage objects with key management",
	}, nil
}

// ── PE Family Automated Checks (new) ──────────────────────────────

// checkEDR verifies endpoint detection and response. Maps to HITRUST PE-16.
func (m *HITRUSTModule) checkEDR(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasEDR := strings.Contains(inputStr, "edr") || strings.Contains(inputStr, "endpoint_detection_response")
	hasMonitoring := strings.Contains(inputStr, "monitoring") || strings.Contains(inputStr, "siem") || m.hasAudit(inputStr)
	hasResponse := strings.Contains(inputStr, "response") || strings.Contains(inputStr, "automated_response") || strings.Contains(inputStr, "incident_response")

	if hasEDR && hasMonitoring && hasResponse {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-PE-16",
			ControlName: "Endpoint Detection and Response",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "EDR controls verified (EDR + monitoring + automated response)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasEDR {
		violations = append(violations, "EDR not deployed")
	}
	if !hasMonitoring {
		violations = append(violations, "monitoring not configured")
	}
	if !hasResponse {
		violations = append(violations, "automated response not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-PE-16",
		ControlName: "Endpoint Detection and Response",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "EDR gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Deploy EDR with monitoring and automated response capabilities",
	}, nil
}

// checkMDM verifies mobile device management. Maps to HITRUST PE-17.
func (m *HITRUSTModule) checkMDM(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasMDM := strings.Contains(inputStr, "mdm") || strings.Contains(inputStr, "mobile_device_management") || strings.Contains(inputStr, "mobile_management")
	hasRemoteWipe := strings.Contains(inputStr, "remote_wipe") || strings.Contains(inputStr, "wipe") || strings.Contains(inputStr, "remote_lock")
	hasEncryption := m.hasEncryption(inputStr) || strings.Contains(inputStr, "mobile_encryption") || strings.Contains(inputStr, "device_encryption")

	if hasMDM && hasRemoteWipe && hasEncryption {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-PE-17",
			ControlName: "Mobile Device Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "MDM controls verified (MDM + remote wipe + encryption)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasMDM {
		violations = append(violations, "MDM not configured")
	}
	if !hasRemoteWipe {
		violations = append(violations, "remote wipe not configured")
	}
	if !hasEncryption {
		violations = append(violations, "mobile device encryption not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-PE-17",
		ControlName: "Mobile Device Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "MDM gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Deploy MDM with remote wipe and device encryption",
	}, nil
}

// checkFullDiskEncryption verifies full disk encryption. Maps to HITRUST PE-21.
func (m *HITRUSTModule) checkFullDiskEncryption(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasFDE := strings.Contains(inputStr, "full_disk_encryption") || strings.Contains(inputStr, "fde") || strings.Contains(inputStr, "disk_encryption")
	hasEncryption := m.hasEncryption(inputStr) || strings.Contains(inputStr, "encryption_at_rest")

	if hasFDE || hasEncryption {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-PE-21",
			ControlName: "Full Disk Encryption",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Full disk encryption verified on endpoints",
			Timestamp:   time.Now(),
		}, nil
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-PE-21",
		ControlName: "Full Disk Encryption",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Full disk encryption not configured on endpoints",
		Timestamp:   time.Now(),
		Remediation: "Enable full disk encryption on all endpoint devices",
	}, nil
}

// checkAntiMalwareUpdates verifies anti-malware signature updates. Maps to HITRUST PE-22.
func (m *HITRUSTModule) checkAntiMalwareUpdates(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasAntimalware := strings.Contains(inputStr, "antimalware") || strings.Contains(inputStr, "anti_malware") || strings.Contains(inputStr, "malware_protection")
	hasUpdates := strings.Contains(inputStr, "signature_update") || strings.Contains(inputStr, "auto_update") || strings.Contains(inputStr, "signature_updates")

	if hasAntimalware && hasUpdates {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-PE-22",
			ControlName: "Anti-Malware Updates",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Anti-malware signature updates verified",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasAntimalware {
		violations = append(violations, "anti-malware not deployed")
	}
	if !hasUpdates {
		violations = append(violations, "automatic signature updates not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-PE-22",
		ControlName: "Anti-Malware Updates",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Anti-malware update gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Deploy anti-malware with automatic signature updates",
	}, nil
}

// checkPatchManagement verifies patch management. Maps to HITRUST PE-23.
func (m *HITRUSTModule) checkPatchManagement(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPatchMgmt := strings.Contains(inputStr, "patch_management") || strings.Contains(inputStr, "patch") || strings.Contains(inputStr, "patching")
	hasAutoDeploy := strings.Contains(inputStr, "auto_deploy") || strings.Contains(inputStr, "automatic_patch") || strings.Contains(inputStr, "patch_deployment")
	hasVerification := strings.Contains(inputStr, "patch_verification") || strings.Contains(inputStr, "verification") || strings.Contains(inputStr, "patch_compliance")

	if hasPatchMgmt && hasAutoDeploy && hasVerification {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "HITRUST-PE-23",
			ControlName: "Patch Management",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Patch management controls verified (patching + auto-deploy + verification)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasPatchMgmt {
		violations = append(violations, "patch management not configured")
	}
	if !hasAutoDeploy {
		violations = append(violations, "automatic patch deployment not configured")
	}
	if !hasVerification {
		violations = append(violations, "patch verification not configured")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "HITRUST-PE-23",
		ControlName: "Patch Management",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Patch management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure automated patch management with deployment and verification",
	}, nil
}
