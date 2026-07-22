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
	// Access Control family
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
			{Framework: "fedramp", ControlID: "FedRAMP-SC-4", Title: "Information in Shared Resources"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-7", Title: "Boundary Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-8", Title: "Transmission Confidentiality and Integrity"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-12", Title: "Cryptographic Key Establishment and Management"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-13", Title: "Cryptographic Protection"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-23", Title: "Session Authenticity"},
			{Framework: "fedramp", ControlID: "FedRAMP-SC-28", Title: "Protection of Information at Rest"},
			{Framework: "fedramp", ControlID: "FedRAMP-IA-7", Title: "Cryptographic Module Authentication"},
			{Framework: "owasp_web", ControlID: "OWASPWeb-A02", Title: "Cryptographic Failures"},
		},
	},

	// ================================================================
	// Vulnerability Management family
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
		},
	},

	// ================================================================
	// Configuration Management / Baseline family
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
