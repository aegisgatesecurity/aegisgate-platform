// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Cross-Framework Control Mapping
// =========================================================================
//
// The Cross-Framework Control Mapping is the GRC-platform secret sauce:
// one AegisGate control (e.g., RBAC enforced with MFA) maps to many
// framework controls (SOC 2 CC6.1, ISO 27001 A.9.2, HIPAA §164.312(a),
// PCI 7.1, NIST CSF PR.AC-4, CIS 5, OWASP Web A01, etc.). Instead of
// writing 8 different evidence packages, the customer writes ONE and
// AegisGate fans it out to all 8 framework reports.
//
// This is the difference between "I spent 3 weeks preparing for SOC 2
// Type II" and "I clicked the AegisGate Compliance Report button and
// got a 47-page PDF in 12 seconds covering all 11 frameworks."
//
// Architecture:
//   - mapping.go:     the cross-framework mapping table + query API
//   - mapping_test.go: tests
//
// The mapping table has 3 layers:
//   1. AegisGate internal control name (e.g., "RBAC with MFA")
//   2. AegisGate CheckFunc control IDs (CC6.1, PR.AC-4, etc.)
//   3. External framework control IDs (SOC 2 CC6.1, ISO 27001 A.9.2, etc.)
//
// Query API:
//   - MapByControlID(aegisgateID)   -> external framework control IDs
//   - MapByFramework(framework, extID) -> AegisGate control IDs
//   - CrossReference(framework, controlID) -> equivalent controls in ALL frameworks
//   - CrossReferenceAll() -> full N×N traceability matrix
//   - GetRelatedControls(framework, controlID) -> all AegisGate + framework controls
//   - GenerateReport(framework, config) -> the framework-specific report
//
// The GRC user flow is:
//   1. Run /api/v1/compliance/scan (existing endpoint)
//   2. For each compliant AegisGate control, fan out to all framework
//      controls that share evidence
//   3. Generate a single PDF/Markdown report with all frameworks
//   4. Auditor sees one set of evidence cited across many framework controls
//
// Reference: This pattern is called "control harmonization" in the
// GRC industry. Commercial tools (Drata, Vanta, Secureframe) do this
// at the data-collection level; AegisGate does it at the evidence
// generation level (deeper integration = less manual work).
// =========================================================================

package mapping

import (
	"fmt"
	"sort"
	"strings"
)

// AegisGateControl is a single AegisGate internal control.
// Each AegisGate control maps to N external framework controls.
type AegisGateControl struct {
	ID          string // AegisGate internal ID (e.g., "AG-AUTH-RBAC-MFA")
	Name        string // Human-readable name
	Description string // One-sentence description
	Category    string // AegisGate category (e.g., "Access Control")
	// ExternalControls is the list of external framework control IDs
	// that this AegisGate control satisfies.
	ExternalControls []ExternalControlRef
}

// ExternalControlRef is a reference to a single external framework control.
type ExternalControlRef struct {
	Framework string // "soc2", "iso27001", "hipaa", "pci", "nist_ai_rmf", "nist_csf", "fedramp", "fips_140", "iso_42001", "cis", "owasp_web", "owasp_llm", "atlas", "eu_ai_act", "gdpr"
	ControlID string // e.g., "CC6.1", "A.9.2", "§164.312(a)", "7.1", "PR.AC-4"
	Title     string // human-readable title of the external control
}

// Mapping is the cross-framework mapping table.
// Keyed by AegisGate internal control ID.
var Mapping = map[string]AegisGateControl{
	// ================================================================
	// Data Protection and Privacy family
	// ================================================================
	"AG-DATA-PROTECTION-PRIVACY": {
		ID:          "AG-DATA-PROTECTION-PRIVACY",
		Name:        "Data Protection and Privacy Controls",
		Description: "Data classification, PII detection, data loss prevention, retention and disposal",
		Category:    "Data Protection",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.5", Title: "Data Classification and Handling"},
			{Framework: "iso27001", ControlID: "A.5.12", Title: "Classification of information"},
			{Framework: "iso27001", ControlID: "A.5.13", Title: "Labelling of information"},
			{Framework: "iso27001", ControlID: "A.5.14", Title: "Information transfer"},
			{Framework: "iso27001", ControlID: "A.8.10", Title: "Storage media"},
			{Framework: "iso27001", ControlID: "A.8.11", Title: "Data masking"},
			{Framework: "iso27001", ControlID: "A.8.12", Title: "Data leakage prevention"},
			{Framework: "hipaa", ControlID: "§164.312(a)(1)", Title: "Access Control"},
			{Framework: "hipaa", ControlID: "§164.312(c)(1)", Title: "Integrity Controls"},
			{Framework: "hipaa", ControlID: "§164.312(e)(1)", Title: "Transmission Security"},
			{Framework: "pci", ControlID: "3.1", Title: "Data retention and disposal"},
			{Framework: "pci", ControlID: "3.3", Title: "Sensitive authentication data protection"},
			{Framework: "pci", ControlID: "3.5", Title: "Protection of cryptographic keys"},
			{Framework: "pci", ControlID: "4.1", Title: "Strong cryptography for transmission"},
			{Framework: "pci", ControlID: "PCI-AI-001", Title: "AI data protection requirements"},
			{Framework: "nist_csf", ControlID: "PR.DS-1", Title: "Data-at-rest protection"},
			{Framework: "nist_csf", ControlID: "PR.DS-2", Title: "Data-in-transit protection"},
			{Framework: "nist_csf", ControlID: "PR.DS-5", Title: "Data integrity protection"},
			{Framework: "cis", ControlID: "CIS-3", Title: "Data Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-8", Title: "Transmission Confidentiality and Integrity"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-12", Title: "Cryptographic Key Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-28", Title: "Protection of Information at Rest"},
			{Framework: "fips_140", ControlID: "FIPS-140-004", Title: "Approved hashes"},
			{Framework: "fips_140", ControlID: "FIPS-140-005", Title: "Key sizes"},
			{Framework: "fips_140", ControlID: "FIPS-140-006", Title: "Minimum Cryptographic Key Sizes"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A02", Title: "Cryptographic Failures"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art10-001", Title: "Data governance requirements"},
			{Framework: "gdpr", ControlID: "GDPR-5", Title: "Data minimization"},
			{Framework: "fedramp", ControlID: "FedRAMP-MP-1", Title: "Media Protection Policy"},
			{Framework: "cjis", ControlID: "CJIS-IM-001", Title: "Information Management Policy"},
			{Framework: "ferpa", ControlID: "FERPA-ER-003", Title: "Record Destruction Policy"},
			{Framework: "ferpa", ControlID: "FERPA-DI-001", Title: "Directory Information Classification"},
			{Framework: "ferpa", ControlID: "FERPA-AI-002", Title: "AI Training Data Consent"},
			{Framework: "sox", ControlID: "SOX-DP-001", Title: "Records Retention (Section 802)"},
			{Framework: "sox", ControlID: "SOX-DP-002", Title: "Data Integrity Controls"},
			{Framework: "glba", ControlID: "GLBA-FP-001", Title: "Privacy Notice"},
			{Framework: "glba", ControlID: "GLBA-FP-003", Title: "Information Sharing Safeguards"},
			{Framework: "glba", ControlID: "GLBA-DP-003", Title: "Data Retention and Disposal"},
		},
	},

	// ================================================================
	// Security Awareness and Training family
	// ================================================================
	"AG-SECURITY-AWARENESS": {
		ID:          "AG-SECURITY-AWARENESS",
		Name:        "Security Awareness and Training Program",
		Description: "Security awareness training, phishing simulation, role-based training tracking",
		Category:    "Human Security",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC1.4", Title: "Demonstrates Commitment to Integrity"},
			{Framework: "iso27001", ControlID: "A.6.3", Title: "Information security awareness, education and training"},
			{Framework: "iso27001", ControlID: "A.5.7", Title: "Threat intelligence"},
			{Framework: "hipaa", ControlID: "§164.308(a)(5)(i)", Title: "Security Awareness and Training"},
			{Framework: "pci", ControlID: "12.2", Title: "Acceptable use policies for technologies"},
			{Framework: "pci", ControlID: "12.4", Title: "Security awareness training"},
			{Framework: "nist_csf", ControlID: "PR.AT-1", Title: "Understanding threats"},
			{Framework: "nist_csf", ControlID: "PR.AT-2", Title: "Role-based training"},
			{Framework: "cis", ControlID: "CIS-14", Title: "Security Awareness and Skills Training"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-2", Title: "Account Management"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-7.5", Title: "AI system documentation"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art14-001", Title: "Human oversight measures"},
			{Framework: "gdpr", ControlID: "GDPR-13", Title: "Information to data subjects"},
			{Framework: "cjis", ControlID: "CJIS-PS-002", Title: "Security Awareness Training"},
			{Framework: "ferpa", ControlID: "FERPA-ER-001", Title: "Education Records Access"},
		},
	},

	// ================================================================
	// Asset Management and Inventory family
	// ================================================================
	"AG-ASSET-INVENTORY": {
		ID:          "AG-ASSET-INVENTORY",
		Name:        "Asset Management and Inventory Controls",
		Description: "Asset inventory, classification, lifecycle management, and acceptable use",
		Category:    "Asset Management",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "iso27001", ControlID: "A.5.9", Title: "Inventory of information and other associated assets"},
			{Framework: "iso27001", ControlID: "A.5.10", Title: "Acceptable use of information and other associated assets"},
			{Framework: "iso27001", ControlID: "A.5.11", Title: "Return of assets"},
			{Framework: "iso27001", ControlID: "A.8.9", Title: "Configuration management"},
			{Framework: "iso27001", ControlID: "A.8.19", Title: "Installation of software on operational systems"},
			{Framework: "hipaa", ControlID: "§164.310(d)(1)", Title: "Device and Media Controls"},
			{Framework: "pci", ControlID: "2.4", Title: "Configuration management for system components"},
			{Framework: "pci", ControlID: "12.5", Title: "Inventory of system components"},
			{Framework: "nist_csf", ControlID: "ID.AM-1", Title: "Physical devices inventory"},
			{Framework: "nist_csf", ControlID: "ID.AM-2", Title: "Software platforms inventory"},
			{Framework: "cis", ControlID: "CIS-1", Title: "Enterprise Assets"},
			{Framework: "cis", ControlID: "CIS-2", Title: "Data Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-2", Title: "Baseline Configuration"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-8", Title: "System Component Inventory"},
			{Framework: "iso_42001", ControlID: "ISO42001-8.1", Title: "AI operational planning"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art11-001", Title: "Technical documentation"},
		},
	},

	// ================================================================
	// Third-Party and Supply Chain Risk family
	// ================================================================
	"AG-SUPPLY-CHAIN-RISK": {
		ID:          "AG-SUPPLY-CHAIN-RISK",
		Name:        "Third-Party and Supply Chain Risk Management",
		Description: "Vendor risk assessment, supply chain integrity, third-party monitoring",
		Category:    "Supply Chain",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC9.2", Title: "Risk Assessment of Third-Party Providers"},
			{Framework: "iso27001", ControlID: "A.5.19", Title: "Information security in supplier agreements"},
			{Framework: "iso27001", ControlID: "A.5.20", Title: "Addressing information security within supplier agreements"},
			{Framework: "iso27001", ControlID: "A.5.21", Title: "Managing information security in the ICT supply chain"},
			{Framework: "iso27001", ControlID: "A.5.22", Title: "Monitoring, review and change management of supplier services"},
			{Framework: "iso27001", ControlID: "A.5.23", Title: "Information security for use of cloud services"},
			{Framework: "iso27001", ControlID: "A.5.24", Title: "Information security incident management by suppliers"},
			{Framework: "hipaa", ControlID: "§164.308(b)(1)", Title: "Business Associate Contracts"},
			{Framework: "pci", ControlID: "12.8", Title: "Third-party service provider management"},
			{Framework: "pci", ControlID: "12.9", Title: "Third-party service provider agreements"},
			{Framework: "nist_csf", ControlID: "ID.SC-1", Title: "Cybersecurity supply chain risk management"},
			{Framework: "nist_csf", ControlID: "ID.SC-2", Title: "Third-party risk management"},
			{Framework: "cis", ControlID: "CIS-15", Title: "Service Provider Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-9", Title: "System and Services Acquisition"},
			{Framework: "fedramp", ControlID: "FedRAMP-SR-3", Title: "Supply Chain Controls and Processes"},
			{Framework: "fedramp", ControlID: "FedRAMP-SR-4", Title: "Provenance"},
			{Framework: "fedramp", ControlID: "FedRAMP-SR-12", Title: "Software and Firmware Integrity Verification"},
			{Framework: "fedramp", ControlID: "FedRAMP-SR-1", Title: "Supply Chain Risk Management Policy"},
			{Framework: "iso_42001", ControlID: "ISO42001-8.3", Title: "AI system supply chain management"},
			{Framework: "owasp_llm", ControlID: "LLM05", Title: "Supply Chain Vulnerabilities"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk management system"},
		},
	},

	// ================================================================
	// Business Continuity and Availability family
	// ================================================================
	"AG-BUSINESS-CONTINUITY": {
		ID:          "AG-BUSINESS-CONTINUITY",
		Name:        "Business Continuity and Availability Controls",
		Description: "Backup, disaster recovery, redundancy, and service availability management",
		Category:    "Availability",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "A1.1", Title: "System Availability"},
			{Framework: "soc2", ControlID: "A1.2", Title: "Backup and Recovery"},
			{Framework: "soc2", ControlID: "A1.3", Title: "Environmental Controls"},
			{Framework: "iso27001", ControlID: "A.5.29", Title: "Information security during disruption"},
			{Framework: "iso27001", ControlID: "A.5.30", Title: "ICT readiness for business continuity"},
			{Framework: "iso27001", ControlID: "A.8.14", Title: "Redundancy of information processing facilities"},
			{Framework: "hipaa", ControlID: "§164.308(a)(7)", Title: "Contingency Plan"},
			{Framework: "hipaa", ControlID: "§164.312(b)", Title: "Audit Controls"},
			{Framework: "pci", ControlID: "12.10", Title: "Incident response plan"},
			{Framework: "nist_csf", ControlID: "PR.IP-4", Title: "Backups and recovery"},
			{Framework: "nist_csf", ControlID: "PR.IP-9", Title: "Response and recovery plans"},
			{Framework: "cis", ControlID: "CIS-11", Title: "Data Recovery"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-10", Title: "Audit Record Retention"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-4", Title: "Incident Handling"},
			{Framework: "fips_140", ControlID: "FIPS-140-002", Title: "Approved ciphers"},
			{Framework: "fips_140", ControlID: "FIPS-140-011", Title: "Mitigation of Other Attacks"},
			{Framework: "fips_140", ControlID: "FIPS-140-012", Title: "HSM Integration"},
			{Framework: "iso_42001", ControlID: "ISO42001-9.2", Title: "AI system monitoring and measurement"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art15-001", Title: "Accuracy and robustness"},
		},
	},

	// ================================================================
	// Identity and Lifecycle Management family
	// ================================================================
	"AG-IDENTITY-LIFECYCLE": {
		ID:          "AG-IDENTITY-LIFECYCLE",
		Name:        "Identity and Access Lifecycle Management",
		Description: "User provisioning, deprovisioning, session management, and periodic access review",
		Category:    "Identity Management",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.2", Title: "User Provisioning and De-provisioning"},
			{Framework: "soc2", ControlID: "CC6.3", Title: "Role-based Access Controls"},
			{Framework: "iso27001", ControlID: "A.5.15", Title: "Access control"},
			{Framework: "iso27001", ControlID: "A.5.16", Title: "Identity management"},
			{Framework: "iso27001", ControlID: "A.5.17", Title: "Authentication information"},
			{Framework: "iso27001", ControlID: "A.5.18", Title: "Access rights"},
			{Framework: "iso27001", ControlID: "A.8.2", Title: "Privileged access rights"},
			{Framework: "hipaa", ControlID: "§164.312(a)(2)(i)", Title: "Unique User Identification"},
			{Framework: "hipaa", ControlID: "§164.312(a)(2)(ii)", Title: "Emergency Access"},
			{Framework: "pci", ControlID: "7.1", Title: "Restrict access on need-to-know basis"},
			{Framework: "pci", ControlID: "7.2", Title: "Role-based access control"},
			{Framework: "pci", ControlID: "8.1", Title: "User identification"},
			{Framework: "pci", ControlID: "8.2", Title: "Authentication"},
			{Framework: "pci", ControlID: "8.3", Title: "MFA for access"},
			{Framework: "pci", ControlID: "8.4", Title: "MFA for administrators"},
			{Framework: "nist_csf", ControlID: "PR.AC-1", Title: "Identity management and access control"},
			{Framework: "nist_csf", ControlID: "PR.AC-2", Title: "Access control"},
			{Framework: "nist_csf", ControlID: "PR.AC-3", Title: "Least privilege"},
			{Framework: "cis", ControlID: "CIS-5", Title: "Account Management"},
			{Framework: "cis", ControlID: "CIS-16", Title: "Application Software Security"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-2", Title: "Account Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-2", Title: "Identification and Authentication"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-5", Title: "Authenticator Management"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-5.2", Title: "AI policy"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A01", Title: "Broken Access Control"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A07", Title: "Identification and Authentication Failures"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art13-001", Title: "Transparency and provision of information"},
			{Framework: "gdpr", ControlID: "GDPR-25", Title: "Data protection by design"},
			{Framework: "cjis", ControlID: "CJIS-AC-002", Title: "Account Management"},
			{Framework: "ferpa", ControlID: "FERPA-DS-001", Title: "Administrative Data Safeguards"},
		},
	},

	// ================================================================
	// Network and Communication Security family
	// ================================================================
	"AG-NETWORK-SECURITY": {
		ID:          "AG-NETWORK-SECURITY",
		Name:        "Network and Communication Security Controls",
		Description: "Network segmentation, firewall management, traffic filtering, and secure protocols",
		Category:    "Network Security",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.6", Title: "System Operations - Audit Logging"},
			{Framework: "iso27001", ControlID: "A.8.20", Title: "Networks security"},
			{Framework: "iso27001", ControlID: "A.8.21", Title: "Security of network services"},
			{Framework: "iso27001", ControlID: "A.8.22", Title: "Segregation of networks"},
			{Framework: "iso27001", ControlID: "A.8.23", Title: "Web filtering"},
			{Framework: "hipaa", ControlID: "§164.312(e)(1)", Title: "Transmission Security"},
			{Framework: "pci", ControlID: "1.1", Title: "Firewall and router configuration"},
			{Framework: "pci", ControlID: "1.2", Title: "Network security controls"},
			{Framework: "pci", ControlID: "1.3", Title: "Network segmentation"},
			{Framework: "pci", ControlID: "1.4", Title: "Network connection controls"},
			{Framework: "nist_csf", ControlID: "PR.AC-5", Title: "Network integrity"},
			{Framework: "nist_csf", ControlID: "PR.PT-4", Title: "Communications security"},
			{Framework: "cis", ControlID: "CIS-13", Title: "Network Monitoring and Defense"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-7", Title: "Boundary Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-17", Title: "Remote Access"},
			{Framework: "iso_42001", ControlID: "ISO42001-8.2", Title: "AI risk implementation"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A05", Title: "Security Misconfiguration"},
		},
	},

	// ================================================================
	// Risk Assessment and Governance family
	// ================================================================
	"AG-RISK-GOVERNANCE": {
		ID:          "AG-RISK-GOVERNANCE",
		Name:        "Risk Assessment and Governance Controls",
		Description: "Risk assessment methodology, security governance, policy management, and compliance tracking",
		Category:    "Governance",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC3.1", Title: "Risk Assessment"},
			{Framework: "soc2", ControlID: "CC3.2", Title: "Risk Management"},
			{Framework: "soc2", ControlID: "CC3.3", Title: "Internal Control"},
			{Framework: "iso27001", ControlID: "A.5.1", Title: "Policies for information security"},
			{Framework: "iso27001", ControlID: "A.5.2", Title: "Information security roles and responsibilities"},
			{Framework: "iso27001", ControlID: "A.5.3", Title: "Segregation of duties"},
			{Framework: "iso27001", ControlID: "A.5.4", Title: "Management responsibilities"},
			{Framework: "iso27001", ControlID: "A.5.5", Title: "Contact with authorities"},
			{Framework: "iso27001", ControlID: "A.5.8", Title: "Information security in project management"},
			{Framework: "hipaa", ControlID: "§164.308(a)(1)", Title: "Security Management Process"},
			{Framework: "hipaa", ControlID: "§164.308(a)(8)", Title: "Evaluation"},
			{Framework: "pci", ControlID: "5.1", Title: "Vulnerability scanning"},
			{Framework: "pci", ControlID: "5.2", Title: "Vulnerability management"},
			{Framework: "pci", ControlID: "5.3", Title: "Risk assessment"},
			{Framework: "pci", ControlID: "12.1", Title: "Information security policy"},
			{Framework: "pci", ControlID: "12.3", Title: "Security policies and operational procedures"},
			{Framework: "nist_csf", ControlID: "ID.RA-1", Title: "Asset vulnerability"},
			{Framework: "nist_csf", ControlID: "ID.RA-2", Title: "Cyber threat intelligence"},
			{Framework: "nist_csf", ControlID: "ID.RA-3", Title: "Vulnerability identification"},
			{Framework: "nist_csf", ControlID: "GV1", Title: "Organizational Context"},
			{Framework: "cis", ControlID: "CIS-7", Title: "Continuous Vulnerability Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-3", Title: "Risk Assessment"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-5", Title: "Vulnerability Monitoring and Scanning"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-7", Title: "Continuous Monitoring"},
			{Framework: "fips_140", ControlID: "FIPS-140-007", Title: "Audit logging"},
			{Framework: "fips_140", ControlID: "FIPS-140-008", Title: "Cryptographic Audit Logging"},
			{Framework: "iso_42001", ControlID: "ISO42001-9.1", Title: "AI performance monitoring"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-AI-001", Title: "Prohibited AI practices detection"},
			{Framework: "gdpr", ControlID: "GDPR-35", Title: "Data protection impact assessment"},
		},
	},

	// ================================================================
	// Physical and Environmental Security family
	// ================================================================
	"AG-PHYSICAL-SECURITY": {
		ID:          "AG-PHYSICAL-SECURITY",
		Name:        "Physical and Environmental Security Controls",
		Description: "Physical access controls, environmental monitoring, secure disposal, and clear desk/screen",
		Category:    "Physical Security",
		ExternalControls: []ExternalControlRef{
			{Framework: "iso27001", ControlID: "A.7.1", Title: "Physical security perimeters"},
			{Framework: "iso27001", ControlID: "A.7.2", Title: "Physical entry"},
			{Framework: "iso27001", ControlID: "A.7.3", Title: "Securing offices, rooms and facilities"},
			{Framework: "iso27001", ControlID: "A.7.4", Title: "Physical security monitoring"},
			{Framework: "iso27001", ControlID: "A.7.5", Title: "Environmental controls"},
			{Framework: "iso27001", ControlID: "A.7.7", Title: "Clear desk and clear screen"},
			{Framework: "iso27001", ControlID: "A.7.8", Title: "Asset disposal"},
			{Framework: "iso27001", ControlID: "A.8.13", Title: "Information backup"},
			{Framework: "hipaa", ControlID: "§164.310(a)(1)", Title: "Facility Access Controls"},
			{Framework: "hipaa", ControlID: "§164.310(b)", Title: "Workstation Use"},
			{Framework: "hipaa", ControlID: "§164.310(c)", Title: "Workstation Security"},
			{Framework: "pci", ControlID: "9.1", Title: "Physical access restrictions"},
			{Framework: "pci", ControlID: "9.2", Title: "Physical media controls"},
			{Framework: "nist_csf", ControlID: "PR.AC-2", Title: "Physical access control"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-14", Title: "Permitted Actions Without Identification"},
			{Framework: "fedramp", ControlID: "FedRAMP-PE-1", Title: "Physical and Environmental Protection Policy"},
			{Framework: "cjis", ControlID: "CJIS-PP-001", Title: "Physical Protection Policy"},
			{Framework: "ferpa", ControlID: "FERPA-DS-002", Title: "Physical Data Safeguards"},
		},
	},

	// ================================================================
	// AI-Specific Safety and Quality family
	// ================================================================
	"AG-AI-SAFETY-QUALITY": {
		ID:          "AG-AI-SAFETY-QUALITY",
		Name:        "AI Safety, Quality, and Transparency Controls",
		Description: "AI model validation, bias detection, explainability, prompt injection defense, and AI output quality",
		Category:    "AI Safety",
		ExternalControls: []ExternalControlRef{
			{Framework: "iso27001", ControlID: "A.5.36", Title: "Compliance with policies, rules and standards"},
			{Framework: "iso27001", ControlID: "A.5.37", Title: "Documentation of information security"},
			{Framework: "iso27001", ControlID: "A.5.38", Title: "Privacy protection"},
			{Framework: "pci", ControlID: "PCI-AI-002", Title: "AI model security requirements"},
			{Framework: "nist_csf", ControlID: "GV2", Title: "Risk Management Strategy"},
			{Framework: "nist_csf", ControlID: "MP1", Title: "Mapping: System Context"},
			{Framework: "nist_csf", ControlID: "ME1", Title: "Measuring: Performance Monitoring"},
			{Framework: "cis", ControlID: "CIS-4", Title: "Secure Configuration"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-11", Title: "Developer Security Testing"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-22", Title: "Unsupported System Components"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "iso_42001", ControlID: "ISO42001-9.3", Title: "AI system audit"},
			{Framework: "owasp_llm", ControlID: "LLM01", Title: "Prompt Injection"},
			{Framework: "owasp_llm", ControlID: "LLM06", Title: "Sensitive Information Disclosure"},
			{Framework: "owasp_llm", ControlID: "LLM07", Title: "Insecure Plugin Design"},
			{Framework: "owasp_llm", ControlID: "LLM09", Title: "Overreliance"},
			{Framework: "atlas", ControlID: "ATLAS-T1535", Title: "ML Model Stealing"},
			{Framework: "atlas", ControlID: "ATLAS-T1484", Title: "Adversarial Examples"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-AI-002", Title: "Social scoring prohibition"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-AI-003", Title: "Real-time remote biometric identification"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art12-001", Title: "Record-keeping requirements"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art15-007", Title: "Cybersecurity requirements"},
			{Framework: "ferpa", ControlID: "FERPA-AI-001", Title: "AI Model Student Data Protection"},
			{Framework: "ferpa", ControlID: "FERPA-AI-002", Title: "AI Training Data Consent"},
			{Framework: "ferpa", ControlID: "FERPA-AI-004", Title: "AI Bias Detection in Education"},
			{Framework: "sox", ControlID: "SOX-AI-001", Title: "AI Model Financial Data Protection"},
			{Framework: "sox", ControlID: "SOX-AI-002", Title: "AI Audit Trail for Financial Reports"},
			{Framework: "glba", ControlID: "GLBA-AI-001", Title: "AI Model NPI Protection"},
			{Framework: "glba", ControlID: "GLBA-AI-002", Title: "AI Audit Trail for Financial Privacy"},
		},
	},

	// ================================================================
	// Access Control family"
	// ================================================================
	"AG-AUTH-RBAC-MFA": {
		ID:          "AG-AUTH-RBAC-MFA",
		Name:        "Role-Based Access Control with Multi-Factor Authentication",
		Description: "All users are uniquely identified, assigned roles, and required to authenticate with MFA",
		Category:    "Access Control",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "soc2", ControlID: "CC6.6", Title: "System Operations - Audit Logging"},
			{Framework: "iso27001", ControlID: "A.9.2.1", Title: "User registration and de-registration"},
			{Framework: "iso27001", ControlID: "A.9.2.3", Title: "Management of privileged access rights"},
			{Framework: "iso27001", ControlID: "A.9.4.2", Title: "Secure log-on procedures"},
			{Framework: "hipaa", ControlID: "§164.312(a)(1)", Title: "Access Control - Unique User Identification"},
			{Framework: "hipaa", ControlID: "§164.312(a)(2)(i)", Title: "Unique user identification"},
			{Framework: "hipaa", ControlID: "§164.312(d)", Title: "Person or Entity Authentication"},
			{Framework: "pci", ControlID: "7.1", Title: "Restrict access to system components and cardholder data"},
			{Framework: "pci", ControlID: "7.2", Title: "Restrict access to system components and cardholder data by business need to know"},
			{Framework: "pci", ControlID: "8.3", Title: "Secure all individual non-console administrative access to the CDE using multi-factor authentication"},
			{Framework: "nist_csf", ControlID: "PR.AC-1", Title: "Identities and credentials are managed for authorized devices and users"},
			{Framework: "nist_csf", ControlID: "PR.AC-4", Title: "Access permissions are managed"},
			{Framework: "nist_csf", ControlID: "PR.AC-7", Title: "Users, devices, and assets are authenticated"},
			{Framework: "cis", ControlID: "CIS-5", Title: "Account Management"},
			{Framework: "cis", ControlID: "CIS-6", Title: "Access Control Management"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A01", Title: "Broken Access Control"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A07", Title: "Identification and Authentication Failures"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-2", Title: "Account Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-3", Title: "Access Enforcement"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-6", Title: "Least Privilege"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-14", Title: "Permitted Actions Without Identification"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-17", Title: "Remote Access"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-24", Title: "Access Control Policy Support"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-2", Title: "Identification and Authentication"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-3", Title: "Device Identification and Authentication"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-5", Title: "Authenticator Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-6", Title: "Authenticator Feedback"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-8", Title: "Non-Organizational Users"},
			{Framework: "cjis", ControlID: "CJIS-AC-001", Title: "Access Control Policy"},
			{Framework: "ferpa", ControlID: "FERPA-ER-001", Title: "Education Records Access"},
			{Framework: "ferpa", ControlID: "FERPA-DI-002", Title: "Opt-Out Mechanism"},
			{Framework: "ferpa", ControlID: "FERPA-DI-003", Title: "Disclosure Consent"},
			{Framework: "ferpa", ControlID: "FERPA-CD-001", Title: "Authorized Disclosure"},
		},
	},

	// ================================================================
	// Audit Logging family
	// ================================================================
	"AG-AUDIT-LOG-HASH-CHAIN": {
		ID:          "AG-AUDIT-LOG-HASH-CHAIN",
		Name:        "Hash-Chained Tamper-Evident Audit Logging",
		Description: "Every audit log entry is hash-chained to the previous, providing tamper-evident evidence of all system activity",
		Category:    "Audit Logging",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.6", Title: "System Operations - Audit Logging"},
			{Framework: "soc2", ControlID: "CC6.7", Title: "Data Transmission Security"},
			{Framework: "iso27001", ControlID: "A.12.4.1", Title: "Event logging"},
			{Framework: "iso27001", ControlID: "A.12.4.3", Title: "Administrator and operator logs"},
			{Framework: "iso_42001", ControlID: "8.2", Title: "AI risk treatment implementation"},
			{Framework: "hipaa", ControlID: "§164.312(b)", Title: "Audit Controls"},
			{Framework: "pci", ControlID: "10.1", Title: "Implement audit trails to link all access to system components to each individual user"},
			{Framework: "pci", ControlID: "10.2", Title: "Implement automated audit trails for all system components"},
			{Framework: "pci", ControlID: "10.5", Title: "Secure audit trails so they cannot be altered"},
			{Framework: "nist_csf", ControlID: "DE.CM-1", Title: "The network is monitored to detect potential cybersecurity events"},
			{Framework: "nist_csf", ControlID: "PR.PT-1", Title: "Audit log records are determined, documented, implemented, and reviewed"},
			{Framework: "cis", ControlID: "CIS-8", Title: "Audit Log Management"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A09", Title: "Security Logging and Monitoring Failures"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-2", Title: "Audit Events"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-3", Title: "Content of Audit Records"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-6", Title: "Audit Review, Analysis, and Reporting"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-9", Title: "Protection of Audit Information"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-10", Title: "Audit Record Retention"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-12", Title: "Audit Generation"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-16", Title: "Cross-Organization Audit Logging"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art12-001", Title: "Automatic Logging"},
			{Framework: "cjis", ControlID: "CJIS-IM-003", Title: "Record Retention"},
			{Framework: "ferpa", ControlID: "FERPA-CD-003", Title: "Law Enforcement Unit Records"},
			{Framework: "ferpa", ControlID: "FERPA-CD-001", Title: "Authorized Disclosure"},
			{Framework: "ferpa", ControlID: "FERPA-DS-003", Title: "Technical Data Safeguards"},
			{Framework: "ferpa", ControlID: "FERPA-AI-003", Title: "AI Audit Trail for Education Records"},
			{Framework: "ferpa", ControlID: "FERPA-DI-003", Title: "Disclosure Consent"},
			{Framework: "sox", ControlID: "SOX-IC-001", Title: "Internal Control Assessment"},
			{Framework: "sox", ControlID: "SOX-FR-002", Title: "Real-Time Disclosure (Section 409)"},
			{Framework: "sox", ControlID: "SOX-DP-002", Title: "Data Integrity Controls"},
			{Framework: "sox", ControlID: "SOX-IT-003", Title: "Backup and Recovery"},
			{Framework: "glba", ControlID: "GLBA-PP-001", Title: "Pretexting Prevention"},
			{Framework: "glba", ControlID: "GLBA-SG-001", Title: "Information Security Program"},
			{Framework: "glba", ControlID: "GLBA-DP-003", Title: "Data Retention and Disposal"},
		},
	},

	// ================================================================
	// Encryption family
	// ================================================================
	"AG-CRYPTO-TLS-FIPS": {
		ID:          "AG-CRYPTO-TLS-FIPS",
		Name:        "TLS 1.2+ with FIPS-Approved Cryptography",
		Description: "All data in transit is protected with TLS 1.2 or higher, using FIPS-approved cipher suites (ECDHE+AES-GCM+SHA-384)",
		Category:    "Cryptography",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.7", Title: "Data Transmission Security"},
			{Framework: "iso27001", ControlID: "A.10.1.1", Title: "Policy on the use of cryptographic controls"},
			{Framework: "iso27001", ControlID: "A.13.1.1", Title: "Network controls"},
			{Framework: "iso27001", ControlID: "A.14.1.2", Title: "Securing application services on public networks"},
			{Framework: "iso27001", ControlID: "A.14.1.3", Title: "Protecting application services transactions"},
			{Framework: "hipaa", ControlID: "§164.312(e)(1)", Title: "Transmission Security"},
			{Framework: "hipaa", ControlID: "§164.312(e)(2)(i)", Title: "Integrity controls"},
			{Framework: "hipaa", ControlID: "§164.312(e)(2)(ii)", Title: "Encryption"},
			{Framework: "pci", ControlID: "4.1", Title: "Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission over open, public networks"},
			{Framework: "nist_csf", ControlID: "PR.DS-2", Title: "Data-in-transit is protected"},
			{Framework: "cis", ControlID: "CIS-12", Title: "Network Infrastructure Management"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS Mode Enabled"},
			{Framework: "fips_140", ControlID: "FIPS-140-003", Title: "Approved TLS Cipher Suites"},
			{Framework: "fips_140", ControlID: "FIPS-140-004", Title: "Minimum TLS Version 1.2"},
			{Framework: "fips_140", ControlID: "FIPS-140-009", Title: "CMVP Validation Status"},
			{Framework: "fips_140", ControlID: "FIPS-140-010", Title: "Design Assurance"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-4", Title: "Information in Shared Resources"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-7", Title: "Boundary Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-8", Title: "Transmission Confidentiality and Integrity"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-12", Title: "Cryptographic Key Establishment and Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-13", Title: "Cryptographic Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-23", Title: "Session Authenticity"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-28", Title: "Protection of Information at Rest"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-7", Title: "Cryptographic Module Authentication"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A02", Title: "Cryptographic Failures"},
			{Framework: "cjis", ControlID: "CJIS-IM-002", Title: "Media Protection"},
			{Framework: "cjis", ControlID: "CJIS-CR-001", Title: "Encryption at Rest"},
			{Framework: "cjis", ControlID: "CJIS-CR-002", Title: "Encryption in Transit"},
			{Framework: "cjis", ControlID: "CJIS-CR-003", Title: "Key Management"},
			{Framework: "ferpa", ControlID: "FERPA-DS-003", Title: "Technical Data Safeguards"},
			{Framework: "glba", ControlID: "GLBA-DP-001", Title: "Encryption at Rest"},
			{Framework: "glba", ControlID: "GLBA-DP-002", Title: "Encryption in Transit"},
		},
	},

	// ================================================================
	// Vulnerability Management" family
	// ================================================================
	"AG-VULN-CI-SCANNING": {
		ID:          "AG-VULN-CI-SCANNING",
		Name:        "Continuous Vulnerability Scanning in CI",
		Description: "Every commit triggers govulncheck, Trivy, and SBOM generation; high-severity findings block the build",
		Category:    "Vulnerability Management",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC7.1", Title: "Detection of Vulnerabilities"},
			{Framework: "iso27001", ControlID: "A.12.6.1", Title: "Management of technical vulnerabilities"},
			{Framework: "pci", ControlID: "6.3", Title: "Identify and assign risk rankings to newly discovered security vulnerabilities"},
			{Framework: "pci", ControlID: "11.2", Title: "Run internal and external network vulnerability scans at least quarterly"},
			{Framework: "nist_csf", ControlID: "ID.RA-1", Title: "Vulnerabilities in assets are identified, validated, and recorded"},
			{Framework: "nist_csf", ControlID: "DE.CM-8", Title: "Vulnerability scans are performed"},
			{Framework: "cis", ControlID: "CIS-7", Title: "Continuous Vulnerability Management"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A06", Title: "Vulnerable and Outdated Components"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-3", Title: "Risk Assessment"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-5", Title: "Vulnerability Monitoring and Scanning (evidence-mapped)"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-6", Title: "Technical Surveillance and Countermeasures"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-7", Title: "Supply Chain Risk Assessment"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-2", Title: "Flaw Remediation"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-3", Title: "Malicious Code Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-7", Title: "Software and Information Integrity"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-8", Title: "Spam Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-10", Title: "Information Input Validation"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-2", Title: "Security Assessments"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-7", Title: "Continuous Monitoring"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-11", Title: "Developer Security Testing"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-8", Title: "System Component Information"},
		},
	},

	// ================================================================
	// Detection / Anomaly family
	// ================================================================
	"AG-DETECT-SCANNER": {
		ID:          "AG-DETECT-SCANNER",
		Name:        "AI-Powered Detection Scanner with IOC Federation",
		Description: "AegisGate's scanner detects prompt injection, PII leaks, secrets, and adversarial patterns; IOCs federate across instances",
		Category:    "Detection",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC7.2", Title: "System Operations - Monitoring"},
			{Framework: "iso27001", ControlID: "A.16.1.1", Title: "Responsibilities and procedures for incident response"},
			{Framework: "iso_42001", ControlID: "9.1", Title: "Monitoring, measurement, analysis and evaluation"},
			{Framework: "nist_ai_rmf", ControlID: "MEASURE 2.5", Title: "AI system performance is monitored"},
			{Framework: "nist_ai_rmf", ControlID: "MANAGE 2.4", Title: "Mechanisms are in place to address AI risks"},
			{Framework: "nist_csf", ControlID: "DE.AE-2", Title: "Detected events are analyzed to understand attack targets and methods"},
			{Framework: "nist_csf", ControlID: "DE.CM-1", Title: "The network is monitored to detect potential cybersecurity events"},
			{Framework: "nist_csf", ControlID: "RS.AN-1", Title: "Notifications from detection systems are investigated"},
			{Framework: "owasp_llm", ControlID: "LLM01", Title: "Prompt Injection"},
			{Framework: "owasp_llm", ControlID: "LLM02", Title: "Sensitive Information Disclosure"},
			{Framework: "owasp_llm", ControlID: "LLM06", Title: "Excessive Agency"},
			{Framework: "atlas", ControlID: "AML.T0051", Title: "LLM Prompt Injection"},
			{Framework: "atlas", ControlID: "AML.T0024", Title: "Exfiltration via Cyber Means"},
			{Framework: "cis", ControlID: "CIS-13", Title: "Network Monitoring and Defense"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art15-001", Title: "Accuracy Level Appropriate"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art15-007", Title: "Data Poisoning Mitigation"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-6", Title: "Audit Review, Analysis, and Reporting"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-4", Title: "Incident Handling"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-5", Title: "Incident Monitoring"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-6", Title: "Incident Reporting"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-7", Title: "Incident Response Assistance"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-8", Title: "Incident Response Plan"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-4", Title: "Information System Monitoring (evidence-mapped)"},
		},
	},

	// ================================================================
	// Trust Framework / Agent Attestation family
	// ================================================================
	"AG-TRUST-AGENT-ATTESTATION": {
		ID:          "AG-TRUST-AGENT-ATTESTATION",
		Name:        "AI Agent Identity, Capability Contracts, and Cryptographic Attestations",
		Description: "Every AI agent has cryptographic identity, signed capability contracts, and signed behavioral attestations",
		Category:    "Trust Framework",
		ExternalControls: []ExternalControlRef{
			{Framework: "iso_42001", ControlID: "6.1.2", Title: "AI risk identification and analysis"},
			{Framework: "iso_42001", ControlID: "A.6.2.5", Title: "AI system lifecycle requirements"},
			{Framework: "iso_42001", ControlID: "5.2", Title: "AI policy"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk Management System"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-AI-006", Title: "AI Agent Capability Attestation"},
			{Framework: "nist_ai_rmf", ControlID: "GOVERN 2.2", Title: "Roles, responsibilities, and lines of communication related to AI risks are documented and clear"},
			{Framework: "nist_ai_rmf", ControlID: "MANAGE 2.3", Title: "Resources are provided to manage AI risks"},
			{Framework: "atlas", ControlID: "AML.T0019", Title: "Publish or Derive AI Model APIs"},
			{Framework: "atlas", ControlID: "AML.T0040", Title: "AI Supply Chain Compromise"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-4", Title: "Acquisition Process"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-5", Title: "Information System Processing and Storage"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-9", Title: "External System Services"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-22", Title: "Unsupported System Components"},
			{Framework: "fedramp", ControlID: "FedRAMP-SR-3", Title: "Supply Chain Controls and Processes"},
			{Framework: "fedramp", ControlID: "FedRAMP-SR-4", Title: "Provenance"},
			{Framework: "fedramp", ControlID: "FedRAMP-SR-6", Title: "Supplier Diversity"},
			{Framework: "fedramp", ControlID: "FedRAMP-SR-8", Title: "Supply Chain Risk Assessment"},
			{Framework: "fedramp", ControlID: "FedRAMP-SR-12", Title: "Supply Chain Software and Firmware Integrity Verification"},
		},
	},

	// ================================================================
	// Output Filtering family
	// ================================================================
	"AG-OUTPUT-PII-SECRET-FILTER": {
		ID:          "AG-OUTPUT-PII-SECRET-FILTER",
		Name:        "AI Output Filtering for PII, Secrets, and Toxicity",
		Description: "Every AI response is scanned for PII, secrets, and toxicity before being returned to the user; matches are redacted or blocked",
		Category:    "Data Protection",
		ExternalControls: []ExternalControlRef{
			{Framework: "hipaa", ControlID: "§164.514(a)", Title: "De-identification of PHI"},
			{Framework: "hipaa", ControlID: "§164.514(b)", Title: "Safe harbor method for de-identification"},
			{Framework: "pci", ControlID: "3.4", Title: "Render PAN unreadable anywhere it is stored"},
			{Framework: "iso_42001", ControlID: "7.5", Title: "Documented information"},
			{Framework: "gdpr", ControlID: "Art. 5(1)(c)", Title: "Data minimization"},
			{Framework: "gdpr", ControlID: "Art. 25", Title: "Data protection by design and by default"},
			{Framework: "gdpr", ControlID: "Art. 32", Title: "Security of processing"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-AI-002", Title: "Training Data Sanitization"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-AI-003", Title: "AI System Output Filtering"},
			{Framework: "nist_ai_rmf", ControlID: "MANAGE 2.1", Title: "AI risks are identified, recorded, and managed"},
			{Framework: "iso27001", ControlID: "A.18.1.4", Title: "Privacy and protection of personally identifiable information"},
			{Framework: "owasp_llm", ControlID: "LLM02", Title: "Sensitive Information Disclosure"},
			{Framework: "nist_csf", ControlID: "PR.DS-1", Title: "Data-at-rest is protected"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-8", Title: "Spam Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-28", Title: "Protection of Information at Rest"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-3", Title: "Malicious Code Protection"},
			{Framework: "ferpa", ControlID: "FERPA-AI-001", Title: "AI Model Student Data Protection"},
			{Framework: "sox", ControlID: "SOX-AI-001", Title: "AI Model Financial Data Protection"},
			{Framework: "glba", ControlID: "GLBA-AI-001", Title: "AI Model NPI Protection"},
		},
	},

	// ================================================================
	// Configuration Management / Baseline family"
	// ================================================================
	"AG-CM-BASELINE-CONFIG": {
		ID:          "AG-CM-BASELINE-CONFIG",
		Name:        "Configuration Baseline Management and Change Control",
		Description: "All system configurations are baseline-controlled, changes require approval, and component inventories are maintained",
		Category:    "Configuration Management",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC8.1", Title: "Change Management"},
			{Framework: "iso27001", ControlID: "A.12.1.2", Title: "Change management"},
			{Framework: "iso27001", ControlID: "A.12.5.1", Title: "Installation of software on operational systems"},
			{Framework: "hipaa", ControlID: "§164.312(a)(2)(iv)", Title: "Encryption and decryption"},
			{Framework: "pci", ControlID: "1.1", Title: "Install and maintain network security controls"},
			{Framework: "pci", ControlID: "2.2", Title: "Develop configuration standards for all system components"},
			{Framework: "nist_csf", ControlID: "PR.IP-1", Title: "A baseline configuration of information technology/industrial control systems is created and maintained"},
			{Framework: "nist_csf", ControlID: "PR.IP-3", Title: "Configuration change control processes are in place"},
			{Framework: "cis", ControlID: "CIS-4", Title: "Secure Configuration of Hardware and Software"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A05", Title: "Security Misconfiguration"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-2", Title: "Baseline Configuration"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-3", Title: "Configuration Change Control"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-5", Title: "Access Restrictions for Change"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-6", Title: "Configuration Settings"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-8", Title: "System Component Information"},
			{Framework: "cjis", ControlID: "CJIS-IM-001", Title: "Information Management Policy"},
			{Framework: "ferpa", ControlID: "FERPA-ER-003", Title: "Record Destruction Policy"},
			{Framework: "ferpa", ControlID: "FERPA-DI-001", Title: "Directory Information Classification"},
			{Framework: "ferpa", ControlID: "FERPA-AI-002", Title: "AI Training Data Consent"},
			{Framework: "sox", ControlID: "SOX-DP-001", Title: "Records Retention (Section 802)"},
			{Framework: "sox", ControlID: "SOX-DP-002", Title: "Data Integrity Controls"},
			{Framework: "glba", ControlID: "GLBA-FP-001", Title: "Privacy Notice"},
			{Framework: "glba", ControlID: "GLBA-FP-003", Title: "Information Sharing Safeguards"},
			{Framework: "glba", ControlID: "GLBA-DP-003", Title: "Data Retention and Disposal"},
		},
	},

	// ================================================================
	// Continuous Monitoring / Risk Assessment family
	// ================================================================
	"AG-CA-CONTINUOUS-MONITORING": {
		ID:          "AG-CA-CONTINUOUS-MONITORING",
		Name:        "Continuous Monitoring and Security Assessment",
		Description: "Ongoing security assessments, continuous monitoring dashboards, and independent 3PAO-level assessments",
		Category:    "Assessment and Monitoring",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC4.1", Title: "Monitoring Activities"},
			{Framework: "iso27001", ControlID: "A.18.2.1", Title: "Independent review of information security"},
			{Framework: "iso27001", ControlID: "A.18.2.2", Title: "Compliance with security policies and standards"},
			{Framework: "hipaa", ControlID: "§164.308(a)(8)", Title: "Evaluation"},
			{Framework: "pci", ControlID: "11.3", Title: "Implement a methodology for penetration testing"},
			{Framework: "nist_csf", ControlID: "ID.RA-1", Title: "Vulnerabilities in assets are identified"},
			{Framework: "nist_csf", ControlID: "DE.CM-1", Title: "The network is monitored to detect events"},
			{Framework: "cis", ControlID: "CIS-7", Title: "Continuous Vulnerability Management"},
			{Framework: "fips_140", ControlID: "FIPS-140-005", Title: "Continuous Monitoring of Cryptographic Module Integrity"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-2", Title: "Security Assessments"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-7", Title: "Continuous Monitoring"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-8", Title: "Penetration Testing"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-9", Title: "Internal System Connections"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-3", Title: "Risk Assessment"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-5", Title: "Vulnerability Monitoring and Scanning"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-6", Title: "Technical Surveillance and Countermeasures"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-7", Title: "Supply Chain Risk Assessment"},
		},
	},

	// ================================================================
	// Incident Response family
	// ================================================================
	"AG-IR-INCIDENT-RESPONSE": {
		ID:          "AG-IR-INCIDENT-RESPONSE",
		Name:        "Incident Response and Reporting Automation",
		Description: "Automated incident detection, classification, response playbooks, and regulatory reporting with IOC federation",
		Category:    "Incident Response",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC7.3", Title: "Incident Management"},
			{Framework: "soc2", ControlID: "CC7.4", Title: "Security Breach Notification"},
			{Framework: "iso27001", ControlID: "A.16.1.1", Title: "Responsibilities and procedures"},
			{Framework: "iso27001", ControlID: "A.16.1.4", Title: "Information security event assessment"},
			{Framework: "iso27001", ControlID: "A.16.1.5", Title: "Information security event collection"},
			{Framework: "hipaa", ControlID: "§164.308(a)(6)", Title: "Security incident procedures"},
			{Framework: "pci", ControlID: "12.10", Title: "Implement an incident response plan"},
			{Framework: "nist_csf", ControlID: "RS.AN-1", Title: "Notifications from detection systems are investigated"},
			{Framework: "nist_csf", ControlID: "RS.CO-2", Title: "Incident information is shared with authorized stakeholders"},
			{Framework: "cis", ControlID: "CIS-17", Title: "Incident Response Management"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art18-001", Title: "Reporting of Serious Incidents"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-4", Title: "Incident Handling"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-5", Title: "Incident Monitoring"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-6", Title: "Incident Reporting"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-7", Title: "Incident Response Assistance"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-8", Title: "Incident Response Plan"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-6", Title: "Audit Review, Analysis, and Reporting"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-4", Title: "Information System Monitoring"},
			{Framework: "cjis", ControlID: "CJIS-PS-003", Title: "Incident Response Training"},
			{Framework: "ferpa", ControlID: "FERPA-CD-002", Title: "Health/Safety Exception"},
		},
	},

	// ================================================================
	// Boundary Protection / Network Security family
	// ================================================================
	"AG-SC-BOUNDARY-PROTECTION": {
		ID:          "AG-SC-BOUNDARY-PROTECTION",
		Name:        "Boundary Protection, Session Management, and Cryptographic Key Management",
		Description: "Network boundary protection, session authenticity enforcement, and cryptographic key management for data at rest and in transit",
		Category:    "System and Communications Protection",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "soc2", ControlID: "CC6.6", Title: "System Operations - Audit Logging"},
			{Framework: "iso27001", ControlID: "A.13.1.1", Title: "Network controls"},
			{Framework: "iso27001", ControlID: "A.13.1.3", Title: "Securing application services transactions"},
			{Framework: "hipaa", ControlID: "§164.312(e)(1)", Title: "Transmission Security"},
			{Framework: "pci", ControlID: "1.1", Title: "Install and maintain network security controls"},
			{Framework: "pci", ControlID: "4.1", Title: "Use strong cryptography for cardholder data transmission"},
			{Framework: "nist_csf", ControlID: "PR.AC-5", Title: "Network integrity is protected"},
			{Framework: "nist_csf", ControlID: "PR.DS-2", Title: "Data-in-transit is protected"},
			{Framework: "cis", ControlID: "CIS-12", Title: "Network Infrastructure Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-4", Title: "Information in Shared Resources"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-7", Title: "Boundary Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-12", Title: "Cryptographic Key Establishment and Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-13", Title: "Cryptographic Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-23", Title: "Session Authenticity"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-28", Title: "Protection of Information at Rest"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS Mode Enabled"},
			// v3.6.0 M3: CMMC L2, NIST 800-171, HITRUST, TISAX, CCPA cross-framework mappings
			{Framework: "cmmcl2", ControlID: "CMMCL2-AC-02", Title: "Access Control Policy"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-AC-03", Title: "Role Based Access Control"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-AC-04", Title: "Remote Access Control"},
			{Framework: "nist800171", ControlID: "NIST800171-AC-2", Title: "Account Management"},
			{Framework: "nist800171", ControlID: "NIST800171-AC-3", Title: "Access Enforcement"},
			{Framework: "nist800171", ControlID: "NIST800171-AC-6", Title: "Least Privilege"},
			{Framework: "nist800171", ControlID: "NIST800171-AC-17", Title: "Remote Access"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-02", Title: "User Authentication"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-03", Title: "Logical Access Control"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-04", Title: "MFA Enforcement"},
			{Framework: "tisax", ControlID: "TISAX-IS-03", Title: "Asset Management"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "tisax", ControlID: "TISAX-IS-05", Title: "Cryptography"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
			{Framework: "sox", ControlID: "SOX-IC-003", Title: "Risk Assessment Framework"},
			{Framework: "glba", ControlID: "GLBA-SG-002", Title: "Risk Assessment"},
			{Framework: "glba", ControlID: "GLBA-SG-004", Title: "Vendor Management"},
			{Framework: "cjis", ControlID: "CJIS-PP-002", Title: "Mobile Device Security"},
		},
	},

	// ================================================================
	// P0: Newly-promoted FedRAMP controls (AC-10, IA-10, IR-10,
	//     SC-6, SC-22, CM-9, CM-11) mapped to all frameworks.
	// ================================================================

	"AG-AC-CONCURRENT-SESSIONS": {
		ID:          "AG-AC-CONCURRENT-SESSIONS",
		Name:        "Concurrent Session Control and Session Management",
		Description: "Limiting concurrent sessions, session lock, session termination, and session enforcement to prevent unauthorized access",
		Category:    "Access Control",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "iso27001", ControlID: "A.9.4.2", Title: "Secure log-on procedures"},
			{Framework: "iso27001", ControlID: "A.9.2.6", Title: "Removal of access rights"},
			{Framework: "hipaa", ControlID: "§164.312(a)(1)", Title: "Access Control"},
			{Framework: "pci", ControlID: "8.1", Title: "Define and implement user identification policies"},
			{Framework: "nist_csf", ControlID: "PR.AC-1", Title: "Identities and credentials are managed"},
			{Framework: "nist_csf", ControlID: "PR.AC-7", Title: "Users, devices, and other assets are authenticated"},
			{Framework: "cis", ControlID: "CIS-6", Title: "Access Control Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-10", Title: "Concurrent Session Control"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-12", Title: "Session Termination"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-11", Title: "Session Lock"},
			{Framework: "fips_140", ControlID: "FIPS-140-003", Title: "Authentication mechanisms"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A07", Title: "Identification and Authentication Failures"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk management system"},
			{Framework: "gdpr", ControlID: "GDPR-32", Title: "Security of processing"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-AC-02", Title: "Access Control Policy"},
			{Framework: "nist800171", ControlID: "NIST800171-AC-2", Title: "Account Management"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-02", Title: "User Authentication"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-IA-ADVERSARY-DETECTION": {
		ID:          "AG-IA-ADVERSARY-DETECTION",
		Name:        "Adversary Detection and Identification Assurance",
		Description: "Adversary identification, authenticator assurance, and non-organizational user authentication to prevent credential-based attacks",
		Category:    "Identification and Authentication",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "iso27001", ControlID: "A.9.2.1", Title: "User registration and de-registration"},
			{Framework: "iso27001", ControlID: "A.9.4.2", Title: "Secure log-on procedures"},
			{Framework: "hipaa", ControlID: "§164.312(d)", Title: "Person or Entity Authentication"},
			{Framework: "pci", ControlID: "8.2", Title: "Authenticate users with unique ID and strong authentication"},
			{Framework: "nist_csf", ControlID: "PR.AC-1", Title: "Identities and credentials are managed"},
			{Framework: "nist_csf", ControlID: "PR.AC-7", Title: "Users, devices, and other assets are authenticated"},
			{Framework: "cis", ControlID: "CIS-6", Title: "Access Control Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-10", Title: "Adversary Detection and Identification"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-1", Title: "Identification and Authentication Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-4", Title: "Identifier Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-9", Title: "Non-Organizational Users"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-11", Title: "Authenticator Assurance"},
			{Framework: "fips_140", ControlID: "FIPS-140-003", Title: "Authentication mechanisms"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A07", Title: "Identification and Authentication Failures"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk management system"},
			{Framework: "gdpr", ControlID: "GDPR-32", Title: "Security of processing"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-IA-01", Title: "Identification and Authentication"},
			{Framework: "nist800171", ControlID: "NIST800171-IA-2", Title: "User Identification and Authentication"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-02", Title: "User Authentication"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-IR-INTEGRATION": {
		ID:          "AG-IR-INTEGRATION",
		Name:        "Incident Response Integration and Coordination",
		Description: "IR integration, incident response assistance, incident monitoring, and coordinated incident handling across organizational boundaries",
		Category:    "Incident Response",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC7.4", Title: "Security Breach Notification"},
			{Framework: "iso27001", ControlID: "A.16.1.1", Title: "Responsibilities and procedures"},
			{Framework: "iso27001", ControlID: "A.16.1.4", Title: "Information security event assessment"},
			{Framework: "hipaa", ControlID: "§164.308(a)(6)", Title: "Security incident procedures"},
			{Framework: "pci", ControlID: "12.10", Title: "Implement an incident response plan"},
			{Framework: "nist_csf", ControlID: "RS.AN-1", Title: "Notifications from detection systems are investigated"},
			{Framework: "nist_csf", ControlID: "RS.CO-2", Title: "Incident information is shared with authorized stakeholders"},
			{Framework: "cis", ControlID: "CIS-17", Title: "Incident Response Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-10", Title: "IR Integration"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-9", Title: "Incident Response Assistance"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-7", Title: "Incident Response Assistance"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-5", Title: "Incident Monitoring"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A10", Title: "Server-Side Request Forgery"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art18-001", Title: "Reporting of Serious Incidents"},
			{Framework: "gdpr", ControlID: "GDPR-33", Title: "Notification of data breach"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-IR-01", Title: "Incident Response"},
			{Framework: "nist800171", ControlID: "NIST800171-IR-4", Title: "Incident Handling"},
			{Framework: "hitrust", ControlID: "HITRUST-IM-01", Title: "Incident Management"},
			{Framework: "tisax", ControlID: "TISAX-DP-07", Title: "Incident Handling"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-SC-RESOURCE-AVAILABILITY": {
		ID:          "AG-SC-RESOURCE-AVAILABILITY",
		Name:        "Resource Availability, Fail-Safe Networks, and Boundary Defense",
		Description: "System resource availability, fail-safe network configurations, denial-of-service protection, and boundary protection enforcement",
		Category:    "System and Communications Protection",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "soc2", ControlID: "A1.2", Title: "System Availability"},
			{Framework: "iso27001", ControlID: "A.12.3", Title: "Separation of networks"},
			{Framework: "iso27001", ControlID: "A.17.1", Title: "Information security continuity"},
			{Framework: "hipaa", ControlID: "§164.312(b)", Title: "Audit Controls"},
			{Framework: "hipaa", ControlID: "§164.308(a)(7)", Title: "Contingency Plan"},
			{Framework: "pci", ControlID: "1.1", Title: "Install and maintain network security controls"},
			{Framework: "pci", ControlID: "11.4", Title: "Use network intrusion detection and prevention"},
			{Framework: "nist_csf", ControlID: "PR.AC-5", Title: "Network integrity is protected"},
			{Framework: "nist_csf", ControlID: "PR.PT-3", Title: "Access is managed"},
			{Framework: "cis", ControlID: "CIS-12", Title: "Network Infrastructure Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-6", Title: "Resource Availability"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-22", Title: "Fail-Safe Network"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-5", Title: "Denial-of-Service Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-3", Title: "Security Function Isolation"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-7", Title: "Boundary Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-39", Title: "Information Process Isolation"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A05", Title: "Security Misconfiguration"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk management system"},
			{Framework: "gdpr", ControlID: "GDPR-32", Title: "Security of processing"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-SC-01", Title: "System and Communications Protection"},
			{Framework: "nist800171", ControlID: "NIST800171-SC-5", Title: "Denial-of-Service Protection"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-03", Title: "Logical Access Control"},
			{Framework: "tisax", ControlID: "TISAX-IS-05", Title: "Cryptography"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-CM-CONFIGURATION-PLANNING": {
		ID:          "AG-CM-CONFIGURATION-PLANNING",
		Name:        "Configuration Management Planning and Software Restrictions",
		Description: "Configuration management planning, software installation restrictions, change control, and baseline enforcement across the system lifecycle",
		Category:    "Configuration Management",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC8.1", Title: "Change Management"},
			{Framework: "iso27001", ControlID: "A.12.1.2", Title: "Change management"},
			{Framework: "iso27001", ControlID: "A.12.5.1", Title: "Installation of software on operational systems"},
			{Framework: "hipaa", ControlID: "§164.308(a)(8)", Title: "Evaluation"},
			{Framework: "pci", ControlID: "6.4", Title: "Public-facing web application changes follow change control processes"},
			{Framework: "nist_csf", ControlID: "PR.IP-3", Title: "Configurations are established and maintained"},
			{Framework: "nist_csf", ControlID: "PR.IP-1", Title: "A baseline configuration is maintained"},
			{Framework: "cis", ControlID: "CIS-10", Title: "Security Assessment and Penetration Testing"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-1", Title: "Configuration Management Policy"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-9", Title: "Configuration Management Plan"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-11", Title: "Software Installation Restrictions"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-4", Title: "Security Impact Analysis"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-7", Title: "Least Functionality"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-10", Title: "Software Usage Restrictions"},
			{Framework: "fedramp", ControlID: "FedRAMP-CM-12", Title: "Information Location"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-7.5", Title: "AI system documentation"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A05", Title: "Security Misconfiguration"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk management system"},
			{Framework: "gdpr", ControlID: "GDPR-25", Title: "Data protection by design and by default"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-CM-01", Title: "Configuration Management"},
			{Framework: "nist800171", ControlID: "NIST800171-CM-3", Title: "Configuration Change Control"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-03", Title: "Logical Access Control"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	// ================================================================
	// P1: Missing NIST 800-53 families (AT, CP, MA, MP, PE, PL, PM, PS)
	// and P2: remaining controls from partially-mapped families.
	// ================================================================

	"AG-AT-AWARENESS-TRAINING": {
		ID:          "AG-AT-AWARENESS-TRAINING",
		Name:        "Awareness and Training Program",
		Description: "Security awareness training, role-based training, insider threat training, and training records management",
		Category:    "Awareness and Training",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC1.4", Title: "Demonstrates Commitment to Integrity"},
			{Framework: "iso27001", ControlID: "A.6.3", Title: "Information security awareness, education and training"},
			{Framework: "hipaa", ControlID: "§164.308(a)(5)(i)", Title: "Security Awareness and Training"},
			{Framework: "pci", ControlID: "12.4", Title: "Security awareness training"},
			{Framework: "nist_csf", ControlID: "PR.AT-1", Title: "Understanding threats"},
			{Framework: "nist_csf", ControlID: "PR.AT-2", Title: "Role-based training"},
			{Framework: "cis", ControlID: "CIS-14", Title: "Security Awareness and Skills Training"},
			{Framework: "fedramp", ControlID: "FedRAMP-AT-1", Title: "Security Awareness and Training Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-AT-2", Title: "Security Awareness Training"},
			{Framework: "fedramp", ControlID: "FedRAMP-AT-3", Title: "Role-Based Training"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-7.5", Title: "AI system documentation"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A10", Title: "Server-Side Request Forgery"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art14-001", Title: "Human oversight measures"},
			{Framework: "gdpr", ControlID: "GDPR-13", Title: "Information to data subjects"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-AT-01", Title: "Awareness and Training"},
			{Framework: "nist800171", ControlID: "NIST800171-AT-1", Title: "Security Awareness and Training"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-02", Title: "User Authentication"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
			{Framework: "cjis", ControlID: "CJIS-PS-002", Title: "Security Awareness Training"},
			{Framework: "ferpa", ControlID: "FERPA-ER-001", Title: "Education Records Access"},
			{Framework: "sox", ControlID: "SOX-IC-002", Title: "Control Environment"},
			{Framework: "sox", ControlID: "SOX-WP-002", Title: "Anonymous Reporting Mechanism"},
		},
	},

	"AG-CP-CONTINGENCY": {
		ID:          "AG-CP-CONTINGENCY",
		Name:        "Contingency Planning and Business Continuity",
		Description: "Contingency planning, contingency training, system backup, recovery, and alternate processing sites for operational resilience",
		Category:    "Contingency Planning",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "A1.2", Title: "System Availability"},
			{Framework: "soc2", ControlID: "A1.3", Title: "System Backup and Recovery"},
			{Framework: "iso27001", ControlID: "A.17.1", Title: "Information security continuity"},
			{Framework: "iso27001", ControlID: "A.17.2", Title: "Redundancies"},
			{Framework: "hipaa", ControlID: "§164.308(a)(7)", Title: "Contingency Plan"},
			{Framework: "pci", ControlID: "12.10", Title: "Implement an incident response plan"},
			{Framework: "nist_csf", ControlID: "PR.IP-9", Title: "Response and recovery plans are tested"},
			{Framework: "nist_csf", ControlID: "RC.RP-1", Title: "Recovery plan is executed"},
			{Framework: "cis", ControlID: "CIS-11", Title: "Data Recovery"},
			{Framework: "fedramp", ControlID: "FedRAMP-CP-1", Title: "Contingency Planning Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-CP-2", Title: "Contingency Plan"},
			{Framework: "fedramp", ControlID: "FedRAMP-CP-3", Title: "Contingency Training"},
			{Framework: "fedramp", ControlID: "FedRAMP-CP-4", Title: "Contingency Plan Testing"},
			{Framework: "fedramp", ControlID: "FedRAMP-CP-6", Title: "Alternate Storage Site"},
			{Framework: "fedramp", ControlID: "FedRAMP-CP-7", Title: "Alternate Processing Site"},
			{Framework: "fedramp", ControlID: "FedRAMP-CP-8", Title: "Telecommunications Services"},
			{Framework: "fedramp", ControlID: "FedRAMP-CP-9", Title: "System Backup"},
			{Framework: "fedramp", ControlID: "FedRAMP-CP-10", Title: "System Recovery and Reconstitution"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A10", Title: "Server-Side Request Forgery"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk management system"},
			{Framework: "gdpr", ControlID: "GDPR-32", Title: "Security of processing"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-CM-01", Title: "Configuration Management"},
			{Framework: "nist800171", ControlID: "NIST800171-CP-1", Title: "Contingency Planning"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-03", Title: "Logical Access Control"},
			{Framework: "tisax", ControlID: "TISAX-IS-05", Title: "Cryptography"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-CA-SECURITY-ASSESSMENT": {
		ID:          "AG-CA-SECURITY-ASSESSMENT",
		Name:        "Security Assessment, Authorization, and Risk Assessment",
		Description: "Security assessments, independent assessments, penetration testing, risk assessment, and internal system connections evaluation",
		Category:    "Security Assessment and Authorization",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC4.1", Title: "Risk Assessment"},
			{Framework: "iso27001", ControlID: "A.18.2.1", Title: "Independent review of information security"},
			{Framework: "hipaa", ControlID: "§164.308(a)(8)", Title: "Evaluation"},
			{Framework: "pci", ControlID: "11.3", Title: "Penetration testing methodology"},
			{Framework: "nist_csf", ControlID: "ID.RA-1", Title: "Asset vulnerabilities are identified"},
			{Framework: "nist_csf", ControlID: "ID.RA-5", Title: "Threat and vulnerability information is identified"},
			{Framework: "cis", ControlID: "CIS-10", Title: "Security Assessment and Penetration Testing"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-1", Title: "Security Assessment Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-3", Title: "System Interconnections"},
			{Framework: "fedramp", ControlID: "FedRAMP-CA-5", Title: "Plan of Action and Milestones"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-1", Title: "Risk Assessment Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-4", Title: "Vulnerability Scanning"},
			{Framework: "fedramp", ControlID: "FedRAMP-RA-9", Title: "Threat Hunting"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A09", Title: "Security Logging and Monitoring Failures"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk management system"},
			{Framework: "gdpr", ControlID: "GDPR-35", Title: "Data protection impact assessment"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-CA-01", Title: "Security Assessment and Authorization"},
			{Framework: "nist800171", ControlID: "NIST800171-CA-2", Title: "Security Assessments"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-02", Title: "User Authentication"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
			{Framework: "sox", ControlID: "SOX-FR-001", Title: "Financial Statement Integrity"},
			{Framework: "sox", ControlID: "SOX-FR-003", Title: "Audit Committee Oversight"},
		},
	},

	"AG-AC-ACCESS-ENFORCEMENT": {
		ID:          "AG-AC-ACCESS-ENFORCEMENT",
		Name:        "Access Enforcement, Information Sharing, and Public Content",
		Description: "Access enforcement, information sharing controls, publicly accessible content management, data mining protection, and policy support",
		Category:    "Access Control",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "soc2", ControlID: "CC6.3", Title: "Logical Access Security"},
			{Framework: "iso27001", ControlID: "A.9.4.1", Title: "Information access restriction"},
			{Framework: "iso27001", ControlID: "A.8.10", Title: "Storage media"},
			{Framework: "hipaa", ControlID: "§164.312(a)(1)", Title: "Access Control"},
			{Framework: "pci", ControlID: "7.1", Title: "Restrict access to need-to-know basis"},
			{Framework: "nist_csf", ControlID: "PR.AC-1", Title: "Identities and credentials are managed"},
			{Framework: "nist_csf", ControlID: "PR.AC-4", Title: "Access permissions are managed"},
			{Framework: "cis", ControlID: "CIS-6", Title: "Access Control Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-1", Title: "Access Control Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-4", Title: "Information Flow Enforcement"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-5", Title: "Separation of Duties"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-7", Title: "Unsuccessful Login Attempts"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-8", Title: "System Use Notification"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-20", Title: "Use of External Systems"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-21", Title: "Information Sharing"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-22", Title: "Publicly Accessible Content"},
			{Framework: "fedramp", ControlID: "FedRAMP-AC-23", Title: "Data Mining Protection"},
			{Framework: "fips_140", ControlID: "FIPS-140-003", Title: "Authentication mechanisms"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A01", Title: "Broken Access Control"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk management system"},
			{Framework: "gdpr", ControlID: "GDPR-5", Title: "Data minimization"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-AC-02", Title: "Access Control Policy"},
			{Framework: "nist800171", ControlID: "NIST800171-AC-3", Title: "Access Enforcement"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-03", Title: "Logical Access Control"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
			{Framework: "cjis", ControlID: "CJIS-AC-001", Title: "Access Control Policy"},
			{Framework: "ferpa", ControlID: "FERPA-ER-001", Title: "Education Records Access"},
			{Framework: "ferpa", ControlID: "FERPA-DI-002", Title: "Opt-Out Mechanism"},
			{Framework: "ferpa", ControlID: "FERPA-DI-003", Title: "Disclosure Consent"},
			{Framework: "ferpa", ControlID: "FERPA-CD-001", Title: "Authorized Disclosure"},
			{Framework: "ferpa", ControlID: "FERPA-ER-002", Title: "Record Amendment Rights"},
			{Framework: "sox", ControlID: "SOX-DP-003", Title: "Access Controls for Financial Systems"},
			{Framework: "sox", ControlID: "SOX-IT-002", Title: "IT Security Controls"},
			{Framework: "sox", ControlID: "SOX-IT-001", Title: "Change Management"},
			{Framework: "glba", ControlID: "GLBA-SG-003", Title: "Access Controls"},
			{Framework: "glba", ControlID: "GLBA-PP-002", Title: "Customer Authentication"},
			{Framework: "glba", ControlID: "GLBA-FP-002", Title: "Opt-Out Rights"},
		},
	},

	"AG-AU-AUDIT-MONITORING": {
		ID:          "AG-AU-AUDIT-MONITORING",
		Name:        "Audit Monitoring, Analysis, and Retention",
		Description: "Audit monitoring, event analysis, record retention, audit reduction, and evidence preservation for compliance verification",
		Category:    "Audit and Accountability",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC4.1", Title: "Risk Assessment"},
			{Framework: "soc2", ControlID: "CC7.2", Title: "Monitoring Activities"},
			{Framework: "iso27001", ControlID: "A.12.4.1", Title: "Event logging"},
			{Framework: "iso27001", ControlID: "A.12.4.3", Title: "Administrator and operator logs"},
			{Framework: "hipaa", ControlID: "§164.312(b)", Title: "Audit Controls"},
			{Framework: "hipaa", ControlID: "§164.530(j)", Title: "Retention of documentation"},
			{Framework: "pci", ControlID: "10.1", Title: "Implement audit trails"},
			{Framework: "pci", ControlID: "10.7", Title: "Retain audit trail history"},
			{Framework: "nist_csf", ControlID: "DE.AE-2", Title: "Events are analyzed"},
			{Framework: "nist_csf", ControlID: "DE.AE-4", Title: "Impact of events is determined"},
			{Framework: "cis", ControlID: "CIS-8", Title: "Audit Log Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-1", Title: "Audit and Accountability Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-4", Title: "Audit Storage Capacity"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-5", Title: "Response to Audit Processing Failures"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-7", Title: "Audit Reduction and Report Generation"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-11", Title: "Audit Record Retention"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-13", Title: "Audit Monitoring and Analysis"},
			{Framework: "fedramp", ControlID: "FedRAMP-AU-14", Title: "Session Audit"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A09", Title: "Security Logging and Monitoring Failures"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art12-001", Title: "Transparency obligations"},
			{Framework: "gdpr", ControlID: "GDPR-30", Title: "Records of processing activities"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-AU-01", Title: "Audit and Accountability"},
			{Framework: "nist800171", ControlID: "NIST800171-AU-2", Title: "Audit Events"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-02", Title: "User Authentication"},
			{Framework: "tisax", ControlID: "TISAX-DP-07", Title: "Incident Handling"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
			{Framework: "cjis", ControlID: "CJIS-AC-003", Title: "Audit and Accountability"},
		},
	},

	"AG-PL-PLANNING": {
		ID:          "AG-PL-PLANNING",
		Name:        "Security Planning and Program Management",
		Description: "Security planning, program management, and policy oversight for organizational security posture",
		Category:    "Planning and Program Management",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC2.1", Title: "Communication of Quality Objectives"},
			{Framework: "iso27001", ControlID: "A.5.1", Title: "Policies for information security"},
			{Framework: "hipaa", ControlID: "§164.308(a)(1)", Title: "Security Management Process"},
			{Framework: "pci", ControlID: "12.1", Title: "Establish security policies and procedures"},
			{Framework: "nist_csf", ControlID: "ID.GV-1", Title: "Organizational context is understood"},
			{Framework: "nist_csf", ControlID: "ID.GV-2", Title: "Risk management strategy is established"},
			{Framework: "cis", ControlID: "CIS-1", Title: "Inventory and Control of Enterprise Assets"},
			{Framework: "fedramp", ControlID: "FedRAMP-PL-1", Title: "Security Planning Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-PL-2", Title: "System Security Plan"},
			{Framework: "fedramp", ControlID: "FedRAMP-PM-1", Title: "Information Security Program Plan"},
			{Framework: "fedramp", ControlID: "FedRAMP-PM-14", Title: "Testing and Assessment"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-5.2", Title: "AI policy"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A05", Title: "Security Misconfiguration"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art9-001", Title: "Risk management system"},
			{Framework: "gdpr", ControlID: "GDPR-24", Title: "Responsibility of the controller"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-CA-01", Title: "Security Assessment and Authorization"},
			{Framework: "nist800171", ControlID: "NIST800171-RA-3", Title: "Risk Assessment"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-01", Title: "Access Management Policy"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-MA-MAINTENANCE": {
		ID:          "AG-MA-MAINTENANCE",
		Name:        "System Maintenance and Media Protection",
		Description: "System maintenance, maintenance personnel controls, media sanitization, and media protection for operational security",
		Category:    "Maintenance and Media Protection",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "soc2", ControlID: "CC7.1", Title: "Logical Access Security over System Assets"},
			{Framework: "iso27001", ControlID: "A.11.2.4", Title: "Equipment maintenance"},
			{Framework: "iso27001", ControlID: "A.8.10", Title: "Storage media"},
			{Framework: "hipaa", ControlID: "§164.310(d)(1)", Title: "Physical Safeguards for Workstations"},
			{Framework: "pci", ControlID: "9.7", Title: "Maintain strict physical control over media"},
			{Framework: "nist_csf", ControlID: "PR.MA-1", Title: "Maintenance and repair of assets"},
			{Framework: "nist_csf", ControlID: "PR.DS-3", Title: "Assets are formally managed"},
			{Framework: "cis", ControlID: "CIS-3", Title: "Data Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-MA-1", Title: "Maintenance Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-MA-4", Title: "Nonlocal Maintenance"},
			{Framework: "fedramp", ControlID: "FedRAMP-MP-5", Title: "Media Transport"},
			{Framework: "fedramp", ControlID: "FedRAMP-MP-6", Title: "Media Sanitization"},
			{Framework: "fedramp", ControlID: "FedRAMP-PE-3", Title: "Physical Access Control"},
			{Framework: "fedramp", ControlID: "FedRAMP-PE-20", Title: "Asset Tracking"},
			{Framework: "fips_140", ControlID: "FIPS-140-003", Title: "Authentication mechanisms"},
			{Framework: "iso_42001", ControlID: "ISO42001-7.5", Title: "AI system documentation"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A05", Title: "Security Misconfiguration"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art11-001", Title: "Technical documentation"},
			{Framework: "gdpr", ControlID: "GDPR-32", Title: "Security of processing"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-CM-01", Title: "Configuration Management"},
			{Framework: "nist800171", ControlID: "NIST800171-MA-2", Title: "Controlled Maintenance"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-02", Title: "User Authentication"},
			{Framework: "tisax", ControlID: "TISAX-IS-05", Title: "Cryptography"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-PS-PERSONNEL-SECURITY": {
		ID:          "AG-PS-PERSONNEL-SECURITY",
		Name:        "Personnel Security and Acceptable Use",
		Description: "Personnel security, acceptable use policies, and user sanctions for workforce security management",
		Category:    "Personnel Security",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC1.4", Title: "Demonstrates Commitment to Integrity"},
			{Framework: "iso27001", ControlID: "A.7.1", Title: "Pre-employment verification"},
			{Framework: "iso27001", ControlID: "A.7.2", Title: "Terms and conditions of employment"},
			{Framework: "hipaa", ControlID: "§164.308(a)(3)(i)", Title: "Workforce Security"},
			{Framework: "pci", ControlID: "12.2", Title: "Acceptable use policies for technologies"},
			{Framework: "nist_csf", ControlID: "PR.IP-11", Title: "Cybersecurity is included in human resources practices"},
			{Framework: "cis", ControlID: "CIS-14", Title: "Security Awareness and Skills Training"},
			{Framework: "fedramp", ControlID: "FedRAMP-PS-1", Title: "Personnel Security Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-PS-2", Title: "Position Risk Designation"},
			{Framework: "fedramp", ControlID: "FedRAMP-PS-3", Title: "Personnel Screening"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-7.3", Title: "Awareness"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A10", Title: "Server-Side Request Forgery"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art14-001", Title: "Human oversight measures"},
			{Framework: "gdpr", ControlID: "GDPR-13", Title: "Information to data subjects"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-AT-01", Title: "Awareness and Training"},
			{Framework: "nist800171", ControlID: "NIST800171-PS-1", Title: "Personnel Security"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-01", Title: "Access Management Policy"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
			{Framework: "cjis", ControlID: "CJIS-PS-001", Title: "Personnel Security Policy"},
			{Framework: "ferpa", ControlID: "FERPA-DS-001", Title: "Administrative Data Safeguards"},
			{Framework: "sox", ControlID: "SOX-IC-002", Title: "Control Environment"},
			{Framework: "sox", ControlID: "SOX-WP-001", Title: "Whistleblower Protection (Section 806)"},
		},
	},

	"AG-IR-IR-POLICY-PLANNING": {
		ID:          "AG-IR-IR-POLICY-PLANNING",
		Name:        "Incident Response Policy, Planning, and Coordination",
		Description: "IR policy and procedures, incident response planning, and incident coordination for organizational resilience",
		Category:    "Incident Response",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC7.4", Title: "Security Breach Notification"},
			{Framework: "iso27001", ControlID: "A.16.1.1", Title: "Responsibilities and procedures"},
			{Framework: "hipaa", ControlID: "§164.308(a)(6)", Title: "Security incident procedures"},
			{Framework: "pci", ControlID: "12.10", Title: "Implement an incident response plan"},
			{Framework: "nist_csf", ControlID: "RS.RP-1", Title: "Response plan is executed"},
			{Framework: "nist_csf", ControlID: "RS.CO-2", Title: "Incident information is shared"},
			{Framework: "cis", ControlID: "CIS-17", Title: "Incident Response Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-1", Title: "Incident Response Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-2", Title: "Incident Response Training"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-3", Title: "Incident Response Testing"},
			{Framework: "fedramp", ControlID: "FedRAMP-IR-9", Title: "Incident Response Assistance"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A09", Title: "Security Logging and Monitoring Failures"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art18-001", Title: "Reporting of Serious Incidents"},
			{Framework: "gdpr", ControlID: "GDPR-33", Title: "Notification of data breach"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-IR-01", Title: "Incident Response"},
			{Framework: "nist800171", ControlID: "NIST800171-IR-1", Title: "Incident Response Policy"},
			{Framework: "hitrust", ControlID: "HITRUST-IM-01", Title: "Incident Management"},
			{Framework: "tisax", ControlID: "TISAX-DP-07", Title: "Incident Handling"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-SC-COMM-PROTECTION": {
		ID:          "AG-SC-COMM-PROTECTION",
		Name:        "System and Communications Protection — Extended Controls",
		Description: "Mobile code policy, DNS architecture, fail-safe communication, mobile code, system partitioning, cryptographic module authentication, and information hiding",
		Category:    "System and Communications Protection",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "iso27001", ControlID: "A.13.1.1", Title: "Network controls"},
			{Framework: "iso27001", ControlID: "A.13.1.3", Title: "Securing application services transactions"},
			{Framework: "hipaa", ControlID: "§164.312(e)(1)", Title: "Transmission Security"},
			{Framework: "pci", ControlID: "1.1", Title: "Install and maintain network security controls"},
			{Framework: "nist_csf", ControlID: "PR.AC-5", Title: "Network integrity is protected"},
			{Framework: "nist_csf", ControlID: "PR.DS-2", Title: "Data-in-transit is protected"},
			{Framework: "cis", ControlID: "CIS-12", Title: "Network Infrastructure Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-1", Title: "System and Communications Protection Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-2", Title: "Access Control Policy for Mobile Code"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-21", Title: "Architecture and Provisioning for DNS"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-24", Title: "Fail-Safe Communication"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-25", Title: "Thin Nodes"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-26", Title: "Mobile Code"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-15", Title: "Collaborative Computing Devices"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-34", Title: "Leaving the System"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-40", Title: "Information Hiding"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-44", Title: "Detonate and Analyze"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A05", Title: "Security Misconfiguration"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art15-001", Title: "Accuracy and robustness"},
			{Framework: "gdpr", ControlID: "GDPR-32", Title: "Security of processing"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-SC-01", Title: "System and Communications Protection"},
			{Framework: "nist800171", ControlID: "NIST800171-SC-7", Title: "Boundary Protection"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-03", Title: "Logical Access Control"},
			{Framework: "tisax", ControlID: "TISAX-IS-05", Title: "Cryptography"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-SI-SYSTEM-INTEGRITY": {
		ID:          "AG-SI-SYSTEM-INTEGRITY",
		Name:        "System and Information Integrity — Extended Controls",
		Description: "System integrity, spam protection, error handling, software integrity verification, and information input validation",
		Category:    "System and Information Integrity",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "soc2", ControlID: "CC7.1", Title: "Logical Access Security over System Assets"},
			{Framework: "iso27001", ControlID: "A.12.2.1", Title: "Controls against malware"},
			{Framework: "iso27001", ControlID: "A.14.2.1", Title: "Secure development policies"},
			{Framework: "hipaa", ControlID: "§164.312(c)(1)", Title: "Integrity Controls"},
			{Framework: "pci", ControlID: "5.1", Title: "Antivirus software"},
			{Framework: "pci", ControlID: "6.5", Title: "Address common coding vulnerabilities"},
			{Framework: "nist_csf", ControlID: "DE.CM-1", Title: "Network is managed"},
			{Framework: "nist_csf", ControlID: "PR.DS-6", Title: "Integrity checking"},
			{Framework: "cis", ControlID: "CIS-10", Title: "Security Assessment and Penetration Testing"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-1", Title: "System and Information Integrity Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-11", Title: "Error Handling"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-12", Title: "Information Handling and Retention"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-14", Title: "Non-Repudiation"},
			{Framework: "fedramp", ControlID: "FedRAMP-SI-16", Title: "Memory Protection"},
			{Framework: "fips_140", ControlID: "FIPS-140-001", Title: "FIPS mode enabled"},
			{Framework: "iso_42001", ControlID: "ISO42001-6.1", Title: "AI risk assessment"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A03", Title: "Injection"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art15-001", Title: "Accuracy and robustness"},
			{Framework: "gdpr", ControlID: "GDPR-32", Title: "Security of processing"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-SC-01", Title: "System and Communications Protection"},
			{Framework: "nist800171", ControlID: "NIST800171-SI-2", Title: "Flaw Remediation"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-03", Title: "Logical Access Control"},
			{Framework: "tisax", ControlID: "TISAX-IS-05", Title: "Cryptography"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},

	"AG-SA-SYSTEM-ACQUISITION": {
		ID:          "AG-SA-SYSTEM-ACQUISITION",
		Name:        "System Acquisition and Software Integrity",
		Description: "System acquisition, software integrity verification, developer security testing, and supply chain security for procurement assurance",
		Category:    "System and Services Acquisition",
		ExternalControls: []ExternalControlRef{
			{Framework: "soc2", ControlID: "CC6.1", Title: "Logical and Physical Access Controls"},
			{Framework: "iso27001", ControlID: "A.15.1", Title: "Information security in supplier relationships"},
			{Framework: "hipaa", ControlID: "§164.308(a)(8)", Title: "Evaluation"},
			{Framework: "pci", ControlID: "6.3", Title: "Develop secure software"},
			{Framework: "nist_csf", ControlID: "PR.IP-2", Title: "Software and hardware inventory"},
			{Framework: "nist_csf", ControlID: "PR.DS-6", Title: "Integrity checking"},
			{Framework: "cis", ControlID: "CIS-10", Title: "Security Assessment and Penetration Testing"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-1", Title: "System and Services Acquisition Policy and Procedures"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-8", Title: "Security Engineering Principles"},
			{Framework: "fedramp", ControlID: "FedRAMP-SA-10", Title: "Developer Configuration Management"},
			{Framework: "fips_140", ControlID: "FIPS-140-004", Title: "Approved hashes"},
			{Framework: "iso_42001", ControlID: "ISO42001-7.5", Title: "AI system documentation"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A06", Title: "Vulnerable and Outdated Components"},
			{Framework: "eu_ai_act", ControlID: "EUAIAct-Art11-001", Title: "Technical documentation"},
			{Framework: "gdpr", ControlID: "GDPR-25", Title: "Data protection by design and by default"},
			{Framework: "cmmcl2", ControlID: "CMMCL2-SA-01", Title: "System and Services Acquisition"},
			{Framework: "nist800171", ControlID: "NIST800171-SA-3", Title: "System Development and Acquisition"},
			{Framework: "hitrust", ControlID: "HITRUST-AM-02", Title: "User Authentication"},
			{Framework: "tisax", ControlID: "TISAX-IS-04", Title: "Access Control"},
			{Framework: "ccpa", ControlID: "CCPA-OS-01", Title: "Right to Opt-Out"},
		},
	},
}

// FrameworkName maps the framework key to a human-readable name.
var FrameworkName = map[string]string{
	"soc2":        "SOC 2 Type II",
	"iso27001":    "ISO 27001:2022",
	"hipaa":       "HIPAA Security Rule",
	"pci":         "PCI-DSS v4.0",
	"nist_ai_rmf": "NIST AI RMF 1.0",
	"nist_csf":    "NIST CSF 2.0",
	"cis":         "CIS Critical Security Controls v8",
	"owasp_web":   "OWASP Top 10 Web (2021)",
	"owasp_llm":   "OWASP Top 10 LLM (2025)",
	"fedramp":     "FedRAMP Moderate (NIST 800-53)",
	"fips_140":    "FIPS 140-2/140-3",
	"iso_42001":   "ISO/IEC 42001:2023",
	"atlas":       "MITRE ATLAS",
	"eu_ai_act":   "EU AI Act (Regulation 2024/1689)",
	"gdpr":        "GDPR (Regulation 2016/679)",
	// v3.6.0 M3 additions:
	"cmmcl2":     "CMMC Level 2",
	"nist800171": "NIST SP 800-171 Rev. 2",
	"hitrust":    "HITRUST CSF v11.2",
	"tisax":      "TISAX AL2",
	"ccpa":       "CCPA/CPRA",
	// v3.7.0 additions:
	"cjis": "CJIS Security Policy v5.9.1",
	"ferpa": "FERPA (34 CFR Part 99)",
	"sox":    "Sarbanes-Oxley Act (2002)",
	"glba":   "Gramm-Leach-Bliley Act (1999)",
}

// MapByControlID returns all external framework controls that the
// given AegisGate control ID satisfies.
func MapByControlID(aegisgateID string) ([]ExternalControlRef, error) {
	ctrl, ok := Mapping[aegisgateID]
	if !ok {
		return nil, fmt.Errorf("unknown AegisGate control ID: %s", aegisgateID)
	}
	return ctrl.ExternalControls, nil
}

// MapByFramework returns all AegisGate control IDs that satisfy the
// given external framework control. Results are sorted alphabetically
// for determinism.
func MapByFramework(framework, extControlID string) []string {
	results := []string{}
	for agID, ctrl := range Mapping {
		for _, ext := range ctrl.ExternalControls {
			if ext.Framework == framework && ext.ControlID == extControlID {
				results = append(results, agID)
				break
			}
		}
	}
	sort.Strings(results)
	return results
}

// ListFrameworks returns the list of supported frameworks.
func ListFrameworks() []string {
	keys := make([]string, 0, len(FrameworkName))
	for k := range FrameworkName {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ListControls returns the list of all AegisGate control IDs.
func ListControls() []string {
	ids := make([]string, 0, len(Mapping))
	for id := range Mapping {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// CoverageMatrix returns a matrix: framework -> external control ID ->
// AegisGate control IDs that satisfy it. This is the GRC user's
// "single view" — for any framework, see which AegisGate controls
// cover it.
func CoverageMatrix() map[string]map[string][]string {
	matrix := make(map[string]map[string][]string)
	// Pre-populate the outer map with all known frameworks so that
	// CoverageMatrix() always returns a non-nil inner map for any
	// known framework (avoids nil map panics in callers).
	for framework := range FrameworkName {
		matrix[framework] = make(map[string][]string)
	}
	for agID, ctrl := range Mapping {
		for _, ext := range ctrl.ExternalControls {
			// Ensure the inner map exists (defensive, in case ext.Framework
			// is a key not in FrameworkName).
			if matrix[ext.Framework] == nil {
				matrix[ext.Framework] = make(map[string][]string)
			}
			matrix[ext.Framework][ext.ControlID] = append(matrix[ext.Framework][ext.ControlID], agID)
		}
	}
	return matrix
}

// CoverageReport summarizes the cross-framework coverage of all
// AegisGate controls. This is the GRC dashboard's "summary card".
type CoverageReport struct {
	TotalAegisGateControls int
	TotalFrameworkMappings int
	FrameworksCovered      []string
	FrameworkControlCount  map[string]int // framework -> number of controls covered
	AegisGateCoverage      map[string]int // aegisgateID -> number of frameworks it covers
}

// GenerateCoverageReport builds the CoverageReport.
func GenerateCoverageReport() CoverageReport {
	report := CoverageReport{
		TotalAegisGateControls: len(Mapping),
		FrameworksCovered:      ListFrameworks(),
		FrameworkControlCount:  make(map[string]int),
		AegisGateCoverage:      make(map[string]int),
	}
	for _, ctrl := range Mapping {
		report.TotalFrameworkMappings += len(ctrl.ExternalControls)
		report.AegisGateCoverage[ctrl.ID] = len(ctrl.ExternalControls)
		for _, ext := range ctrl.ExternalControls {
			report.FrameworkControlCount[ext.Framework]++
		}
	}
	return report
}

// FormatReport renders a CoverageReport as a human-readable string.
// This is the GRC user-facing output (rendered in the dashboard or
// the CLI report command).
func (c CoverageReport) FormatReport() string {
	var b strings.Builder
	b.WriteString("# AegisGate Cross-Framework Coverage Report\n\n")
	fmt.Fprintf(&b, "**%d AegisGate controls** mapping to **%d external framework controls** across **%d frameworks**\n\n",
		c.TotalAegisGateControls, c.TotalFrameworkMappings, len(c.FrameworksCovered))
	b.WriteString("## Framework Coverage\n\n")
	// Sort frameworks by display name for deterministic output (so the
	// test can reliably check for specific framework names).
	sortedFrameworks := make([]string, len(c.FrameworksCovered))
	copy(sortedFrameworks, c.FrameworksCovered)
	sort.Slice(sortedFrameworks, func(i, j int) bool {
		return FrameworkName[sortedFrameworks[i]] < FrameworkName[sortedFrameworks[j]]
	})
	for _, fw := range sortedFrameworks {
		count := c.FrameworkControlCount[fw]
		name := FrameworkName[fw]
		fmt.Fprintf(&b, "- **%s** (%s): %d controls covered\n", name, fw, count)
	}
	b.WriteString("\n## AegisGate Control Coverage (top 10 by framework breadth)\n\n")
	type kv struct {
		ID    string
		Count int
	}
	pairs := make([]kv, 0, len(c.AegisGateCoverage))
	for id, count := range c.AegisGateCoverage {
		pairs = append(pairs, kv{id, count})
	}
	// Sort by count desc, with ID asc as tie-breaker for full
	// determinism (Go map iteration is random; without the
	// tie-breaker, ties produce different outputs on different runs)
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count != pairs[j].Count {
			return pairs[i].Count > pairs[j].Count
		}
		return pairs[i].ID < pairs[j].ID
	})
	for i, p := range pairs {
		if i >= 10 {
			break
		}
		ctrl := Mapping[p.ID]
		fmt.Fprintf(&b, "- **%s** (%s): %d framework controls\n", p.ID, ctrl.Name, p.Count)
	}
	return b.String()
}

// =========================================================================
// Cross-Framework Traceability API
// =========================================================================
//
// The functions below provide the "full web of traceability" — when a
// FedRAMP control fires, the operator instantly sees every equivalent
// control across all 15 frameworks. This is the detection-to-compliance
// fan-out: one alarm → all relevant frameworks.
//
// CrossReference("fedramp", "FedRAMP-AC-2") returns:
//   SOC 2 CC6.1, ISO 27001 A.9.2.1, HIPAA §164.312(a), PCI 7.1,
//   NIST CSF PR.AC-4, CIS 5, OWASP Web A01, etc.
//
// The hub-and-spoke model makes this O(Frameworks × Controls) instead
// of O(N²) manual pairwise mappings.

// CrossReferenceResult is a single equivalent control in another framework.
type CrossReferenceResult struct {
	SourceFramework  string // e.g., "fedramp"
	SourceControlID  string // e.g., "FedRAMP-AC-2"
	SourceTitle      string // e.g., "Account Management"
	AegisGateControl string // e.g., "AG-AUTH-RBAC-MFA"
	TargetFramework  string // e.g., "soc2"
	TargetControlID  string // e.g., "CC6.1"
	TargetTitle      string // e.g., "Logical and Physical Access Controls"
}

// CrossReference finds all equivalent controls across ALL frameworks for
// a given framework control. When FedRAMP AC-2 fires, this returns every
// SOC 2, ISO 27001, HIPAA, PCI, NIST CSF, CIS, OWASP, etc. control that
// addresses the same underlying security concern.
func CrossReference(framework, controlID string) []CrossReferenceResult {
	// Step 1: Find which AegisGate controls map to this framework control.
	agControls := MapByFramework(framework, controlID)
	if len(agControls) == 0 {
		return nil
	}
	var results []CrossReferenceResult
	for _, agID := range agControls {
		// Step 2: For each AegisGate control, get ALL external controls.
		ctrl, exists := Mapping[agID]
		if !exists {
			continue
		}
		// Find the source control's title
		sourceTitle := ""
		for _, ext := range ctrl.ExternalControls {
			if ext.Framework == framework && ext.ControlID == controlID {
				sourceTitle = ext.Title
				break
			}
		}
		// Step 3: Fan out to all other frameworks
		for _, ext := range ctrl.ExternalControls {
			// Skip same-framework controls (we already know about those)
			if ext.Framework == framework {
				continue
			}
			results = append(results, CrossReferenceResult{
				SourceFramework:  framework,
				SourceControlID:  controlID,
				SourceTitle:      sourceTitle,
				AegisGateControl: agID,
				TargetFramework:  ext.Framework,
				TargetControlID:  ext.ControlID,
				TargetTitle:      ext.Title,
			})
		}
	}
	return results
}

// FullTraceabilityMatrix returns the complete N×N cross-reference:
// every framework control mapped to every equivalent control in every
// other framework. This is the "full web" — the definitive
// traceability graph for GRC evidence packages.
//
// The result is keyed by "framework:controlID" → []CrossReferenceResult.
func FullTraceabilityMatrix() map[string][]CrossReferenceResult {
	matrix := make(map[string][]CrossReferenceResult)
	for fw := range FrameworkName {
		for _, ctrl := range Mapping {
			for _, ext := range ctrl.ExternalControls {
				if ext.Framework != fw {
					continue
				}
				key := fw + ":" + ext.ControlID
				refs := CrossReference(fw, ext.ControlID)
				if len(refs) > 0 {
					matrix[key] = refs
				}
			}
		}
	}
	return matrix
}

// RelatedControlGroup bundles an AegisGate control with all its
// framework equivalents — the full picture for a detection event.
type RelatedControlGroup struct {
	AegisGateControl  string
	AegisGateName     string
	FrameworkControls []ExternalControlRef
}

// GetRelatedControls returns the full control group for a given framework
// control: the AegisGate internal control + all equivalent framework
// controls. This is what surfaces when a detection alarm fires.
func GetRelatedControls(framework, controlID string) []RelatedControlGroup {
	agControls := MapByFramework(framework, controlID)
	if len(agControls) == 0 {
		return nil
	}
	var groups []RelatedControlGroup
	for _, agID := range agControls {
		ctrl, exists := Mapping[agID]
		if !exists {
			continue
		}
		groups = append(groups, RelatedControlGroup{
			AegisGateControl:  agID,
			AegisGateName:     ctrl.Name,
			FrameworkControls: ctrl.ExternalControls,
		})
	}
	return groups
}
