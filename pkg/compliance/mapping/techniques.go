// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - AI Technique-Level Cross-Mapping
// =========================================================================
//
// The control-level mapping in mapping.go answers the GRC question:
// "Which AegisGate controls satisfy SOC 2 CC6.1?" (control -> control).
//
// This file (techniques.go) answers the security-engineer question:
// "Which MITRE ATLAS techniques does AegisGate detect?" (technique -> control).
//
// These are complementary views:
//   - mapping.go:        GRC-facing (control -> framework control)
//   - techniques.go:     Engineer-facing (framework technique -> AegisGate control)
//
// The data in this file was adapted from the legacy
// pkg/compliance/framework_mapping.go (38K LOC, v3.2.0) but
// re-expressed in the new mapping package's API so the GRC user
// can query either view from the same place.
//
// Reference: MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
//            https://atlas.mitre.org/
//            NIST AI RMF 1.0
//            https://www.nist.gov/itl/ai-risk-management-framework
//            OWASP Top 10 for LLM Applications
//            https://owasp.org/www-project-top-10-for-large-language-model-applications/
// =========================================================================

package mapping

// TechniqueMapping is a single mapping from a framework technique
// (e.g., MITRE ATLAS T1535) to an AegisGate internal control that
// detects or mitigates it. The AegisGateControl references the
// same control IDs used in the AegisGateControl.ExternalControls
// list in mapping.go.
//
// This is the "evidence view" — for each technique, which AegisGate
// control produces the evidence (or the mitigation)?
type TechniqueMapping struct {
	TechniqueID      string  // e.g., "T1535" (MITRE ATLAS), "LLM01" (OWASP LLM), "GV1" (NIST AI RMF)
	TechniqueName    string  // Human-readable name
	Framework        string  // "atlas", "owasp_llm", "nist_ai_rmf"
	AegisGateControl string  // AegisGate control that detects/mitigates
	Relationship     string  // "detects" | "mitigates" | "supports" | "addresses" | "equivalent" | "relates"
	Confidence       float64 // 0.0 to 1.0
	Description      string
}

// TechniqueMappings is the canonical mapping table.
// Sourced from the legacy framework_mapping.go (v3.2.0) but
// keyed to the new AegisGate control IDs (AG-AUTH-RBAC-MFA, etc.)
// rather than to the legacy source-control IDs.
//
// Note: the legacy mapping used NIST AI RMF's "Functions + Categories"
// nomenclature (GOVERN, MAP, MEASURE, MANAGE) with subcategories
// (GV.OC, GV.RM, etc.). For simplicity, the new mapping uses the
// higher-level NIST AI RMF control IDs (GOVERN 2.2, MEASURE 2.5,
// MANAGE 2.3, etc.) which match the IDs in mapping.go.
var TechniqueMappings = []TechniqueMapping{
	// ================================================================
	// MITRE ATLAS -> AegisGate controls (AegisGate's scanner detects)
	// ================================================================
	{TechniqueID: "T1535", TechniqueName: "Unsecured Credentials", Framework: "atlas", AegisGateControl: "AG-AUTH-RBAC-MFA", Relationship: "mitigates", Confidence: 0.95, Description: "RBAC with MFA prevents adversary from obtaining credentials through exploitation"},
	{TechniqueID: "T1484", TechniqueName: "Jailbreak (LLM)", Framework: "atlas", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.95, Description: "AegisGate's prompt injection scanner detects LLM jailbreak attempts"},
	{TechniqueID: "T1632", TechniqueName: "Training Data Extraction", Framework: "atlas", AegisGateControl: "AG-OUTPUT-PII-SECRET-FILTER", Relationship: "mitigates", Confidence: 0.9, Description: "PII/secret filter prevents training data exfiltration"},
	{TechniqueID: "T1589", TechniqueName: "Gather Victim Network Information", Framework: "atlas", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.85, Description: "Scanner detects reconnaissance patterns"},
	{TechniqueID: "T1584", TechniqueName: "Access Token Manipulation", Framework: "atlas", AegisGateControl: "AG-AUTH-RBAC-MFA", Relationship: "mitigates", Confidence: 0.9, Description: "RBAC with MFA + signed attestations prevents token manipulation"},
	{TechniqueID: "T1658", TechniqueName: "Exploitable Prompt Injection", Framework: "atlas", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.95, Description: "Scanner detects prompt injection patterns"},
	{TechniqueID: "T1648", TechniqueName: "Serverless Function Exploitation", Framework: "atlas", AegisGateControl: "AG-VULN-CI-SCANNING", Relationship: "mitigates", Confidence: 0.85, Description: "CI vulnerability scanning detects serverless vulnerabilities"},
	{TechniqueID: "T1590", TechniqueName: "Gather Victim Network Info (Cloud)", Framework: "atlas", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.8, Description: "Scanner detects cloud reconnaissance"},
	{TechniqueID: "T1592", TechniqueName: "Gather Victim Host Info", Framework: "atlas", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.8, Description: "Scanner detects host reconnaissance"},
	{TechniqueID: "T1556", TechniqueName: "Modify Authentication Process", Framework: "atlas", AegisGateControl: "AG-AUTH-RBAC-MFA", Relationship: "mitigates", Confidence: 0.9, Description: "MFA enforcement prevents authentication bypass"},
	{TechniqueID: "T1552", TechniqueName: "Unsecured Credentials (Files)", Framework: "atlas", AegisGateControl: "AG-OUTPUT-PII-SECRET-FILTER", Relationship: "mitigates", Confidence: 0.9, Description: "Secret scanner detects credential leakage in AI outputs"},
	{TechniqueID: "T1566", TechniqueName: "Phishing", Framework: "atlas", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.8, Description: "Scanner detects phishing in AI tool calls"},
	{TechniqueID: "T1486", TechniqueName: "Data Encrypted for Impact", Framework: "atlas", AegisGateControl: "AG-CRYPTO-TLS-FIPS", Relationship: "mitigates", Confidence: 0.9, Description: "FIPS-approved encryption prevents data at rest attacks"},
	{TechniqueID: "T1611", TechniqueName: "Exploitation of Remote Services", Framework: "atlas", AegisGateControl: "AG-VULN-CI-SCANNING", Relationship: "mitigates", Confidence: 0.85, Description: "CI vulnerability scanning detects remote service exploits"},
	{TechniqueID: "T1621", TechniqueName: "Forge Web Credentials", Framework: "atlas", AegisGateControl: "AG-AUTH-RBAC-MFA", Relationship: "mitigates", Confidence: 0.85, Description: "RBAC + signed attestations prevent credential forgery"},
	{TechniqueID: "T1599", TechniqueName: "Exploit Public-Facing Application", Framework: "atlas", AegisGateControl: "AG-VULN-CI-SCANNING", Relationship: "mitigates", Confidence: 0.85, Description: "CI scanning detects public-facing app vulnerabilities"},
	{TechniqueID: "T1110", TechniqueName: "Brute Force", Framework: "atlas", AegisGateControl: "AG-AUTH-RBAC-MFA", Relationship: "mitigates", Confidence: 0.9, Description: "MFA + rate limiting prevents brute force"},
	{TechniqueID: "T1041", TechniqueName: "Exfiltration Over C2 Channel", Framework: "atlas", AegisGateControl: "AG-OUTPUT-PII-SECRET-FILTER", Relationship: "mitigates", Confidence: 0.85, Description: "PII/secret filter prevents data exfiltration"},

	// ================================================================
	// OWASP LLM Top 10 -> AegisGate controls
	// ================================================================
	{TechniqueID: "LLM01", TechniqueName: "Prompt Injection", Framework: "owasp_llm", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.95, Description: "Scanner detects prompt injection (T1535, T1484 equivalents in ATLAS)"},
	{TechniqueID: "LLM02", TechniqueName: "Sensitive Information Disclosure", Framework: "owasp_llm", AegisGateControl: "AG-OUTPUT-PII-SECRET-FILTER", Relationship: "mitigates", Confidence: 0.95, Description: "PII/secret filter prevents sensitive info disclosure"},
	{TechniqueID: "LLM03", TechniqueName: "Training Data Poisoning", Framework: "owasp_llm", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.9, Description: "Scanner detects data poisoning patterns (T1590, T1592)"},
	{TechniqueID: "LLM04", TechniqueName: "Model Denial of Service", Framework: "owasp_llm", AegisGateControl: "AG-CRYPTO-TLS-FIPS", Relationship: "mitigates", Confidence: 0.8, Description: "Rate limiting via AegisGate proxy prevents resource exhaustion (T1486, T1611)"},
	{TechniqueID: "LLM05", TechniqueName: "Supply Chain Vulnerabilities", Framework: "owasp_llm", AegisGateControl: "AG-VULN-CI-SCANNING", Relationship: "mitigates", Confidence: 0.9, Description: "CI scanning detects supply chain vulns (T1556, T1552, T1566)"},
	{TechniqueID: "LLM06", TechniqueName: "Excessive Agency", Framework: "owasp_llm", AegisGateControl: "AG-TRUST-AGENT-ATTESTATION", Relationship: "mitigates", Confidence: 0.85, Description: "Capability contracts limit agent scope (T1484, T1621)"},
	{TechniqueID: "LLM07", TechniqueName: "System Prompt Leakage", Framework: "owasp_llm", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.85, Description: "Scanner detects system prompt extraction (T1648, T1110, T1041)"},
	{TechniqueID: "LLM08", TechniqueName: "Vector and Embedding Weaknesses", Framework: "owasp_llm", AegisGateControl: "AG-VULN-CI-SCANNING", Relationship: "mitigates", Confidence: 0.8, Description: "CI scanning covers RAG/embedding vulns (T1484, T1621)"},
	{TechniqueID: "LLM09", TechniqueName: "Misinformation", Framework: "owasp_llm", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.85, Description: "Hallucination detector flags misinformation (T1535, T1484, T1658)"},
	{TechniqueID: "LLM10", TechniqueName: "Unbounded Consumption", Framework: "owasp_llm", AegisGateControl: "AG-CRYPTO-TLS-FIPS", Relationship: "mitigates", Confidence: 0.85, Description: "Rate limiting + token limiter (T1648, T1599, T1611)"},

	// ================================================================
	// NIST AI RMF -> AegisGate controls (the high-level mapping)
	// ================================================================
	{TechniqueID: "GOVERN 2.2", TechniqueName: "Roles and responsibilities", Framework: "nist_ai_rmf", AegisGateControl: "AG-TRUST-AGENT-ATTESTATION", Relationship: "supports", Confidence: 0.9, Description: "Trust Framework tracks AI agent identities and roles"},
	{TechniqueID: "MEASURE 2.5", TechniqueName: "AI system performance monitored", Framework: "nist_ai_rmf", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "supports", Confidence: 0.9, Description: "Scanner monitors AI system behavior continuously"},
	{TechniqueID: "MANAGE 2.3", TechniqueName: "Resources for AI risk management", Framework: "nist_ai_rmf", AegisGateControl: "AG-TRUST-AGENT-ATTESTATION", Relationship: "supports", Confidence: 0.85, Description: "Trust Framework provides attestation infrastructure for AI risk management"},
	{TechniqueID: "MANAGE 2.4", TechniqueName: "Mechanisms for AI risks", Framework: "nist_ai_rmf", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "supports", Confidence: 0.85, Description: "Scanner is the primary risk mitigation mechanism"},

	// ================================================================
	// Audit log mappings (T-codes that involve modifying or evading logs)
	// ================================================================
	{TechniqueID: "T1070", TechniqueName: "Indicator Removal (Log Tampering)", Framework: "atlas", AegisGateControl: "AG-AUDIT-LOG-HASH-CHAIN", Relationship: "mitigates", Confidence: 0.95, Description: "Hash-chain audit log prevents post-hoc tampering"},
	{TechniqueID: "T1070.002", TechniqueName: "Clear Linux/Mac Logs", Framework: "atlas", AegisGateControl: "AG-AUDIT-LOG-HASH-CHAIN", Relationship: "detects", Confidence: 0.9, Description: "Tamper-evident audit log detects log deletion attempts"},
	{TechniqueID: "T1562", TechniqueName: "Impair Defenses", Framework: "atlas", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.85, Description: "Scanner detects defense-evasion attempts (T1562.x sub-techniques)"},
	{TechniqueID: "T1090", TechniqueName: "Proxy/Command & Control", Framework: "atlas", AegisGateControl: "AG-DETECT-SCANNER", Relationship: "detects", Confidence: 0.85, Description: "Scanner detects C2 traffic patterns in AI tool calls"},

	// ================================================================
	// VULN-CI-SCANNING: explicit technique mappings (vulnerability-related)
	// ================================================================
	{TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing Application", Framework: "atlas", AegisGateControl: "AG-VULN-CI-SCANNING", Relationship: "mitigates", Confidence: 0.95, Description: "govulncheck + Trivy + SBOM in CI detects public-facing app vulns before deploy"},
	{TechniqueID: "T1059", TechniqueName: "Command and Scripting Interpreter", Framework: "atlas", AegisGateControl: "AG-VULN-CI-SCANNING", Relationship: "mitigates", Confidence: 0.85, Description: "CI vulnerability scanning catches command injection vulns in dependencies"},

	// ================================================================
	// CRYPTO-TLS-FIPS: cryptographic attack technique mappings
	// ================================================================
	{TechniqueID: "T1557", TechniqueName: "Adversary-in-the-Middle", Framework: "atlas", AegisGateControl: "AG-CRYPTO-TLS-FIPS", Relationship: "mitigates", Confidence: 0.95, Description: "TLS 1.2+ with FIPS-approved ciphers prevents AiTM attacks"},
	{TechniqueID: "T1573", TechniqueName: "Encrypted Channel", Framework: "atlas", AegisGateControl: "AG-CRYPTO-TLS-FIPS", Relationship: "mitigates", Confidence: 0.9, Description: "FIPS-approved crypto enforces strong encryption"},

	// ================================================================
	// AG-CM-BASELINE-CONFIG: Configuration and change management techniques
	// ================================================================
	{TechniqueID: "T1070.004", TechniqueName: "File Deletion (Configuration Tampering)", Framework: "atlas", AegisGateControl: "AG-CM-BASELINE-CONFIG", Relationship: "mitigates", Confidence: 0.9, Description: "Baseline configuration management detects unauthorized configuration changes"},
	{TechniqueID: "T1529", TechniqueName: "System Shutdown/Reboot (Config Drift)", Framework: "atlas", AegisGateControl: "AG-CM-BASELINE-CONFIG", Relationship: "detects", Confidence: 0.85, Description: "Configuration change control detects unauthorized system changes"},
	{TechniqueID: "GOVERN 1.1", TechniqueName: "AI policies and procedures", Framework: "nist_ai_rmf", AegisGateControl: "AG-CM-BASELINE-CONFIG", Relationship: "supports", Confidence: 0.85, Description: "Configuration baselines support AI system governance policies"},
	{TechniqueID: "OWASPDev-05", TechniqueName: "Security Misconfiguration", Framework: "owasp_llm", AegisGateControl: "AG-CM-BASELINE-CONFIG", Relationship: "mitigates", Confidence: 0.85, Description: "Baseline configuration prevents security misconfigurations"},

	// ================================================================
	// AG-CA-CONTINUOUS-MONITORING: Assessment and monitoring techniques
	// ================================================================
	{TechniqueID: "T1595", TechniqueName: "Active Scanning", Framework: "atlas", AegisGateControl: "AG-CA-CONTINUOUS-MONITORING", Relationship: "mitigates", Confidence: 0.9, Description: "Continuous monitoring detects active scanning reconnaissance"},
	{TechniqueID: "T1595.001", TechniqueName: "Scanning IP Blocks", Framework: "atlas", AegisGateControl: "AG-CA-CONTINUOUS-MONITORING", Relationship: "detects", Confidence: 0.85, Description: "Continuous monitoring detects IP block scanning patterns"},
	{TechniqueID: "MEASURE 1.1", TechniqueName: "AI performance metrics identified", Framework: "nist_ai_rmf", AegisGateControl: "AG-CA-CONTINUOUS-MONITORING", Relationship: "supports", Confidence: 0.85, Description: "Continuous monitoring supports AI performance metrics measurement"},
	{TechniqueID: "LLM05", TechniqueName: "Supply Chain Vulnerabilities", Framework: "owasp_llm", AegisGateControl: "AG-CA-CONTINUOUS-MONITORING", Relationship: "mitigates", Confidence: 0.8, Description: "Continuous vulnerability scanning detects supply chain threats"},

	// ================================================================
	// AG-IR-INCIDENT-RESPONSE: Incident response techniques
	// ================================================================
	{TechniqueID: "T1070.001", TechniqueName: "Log Tampering (Incident Evidence)", Framework: "atlas", AegisGateControl: "AG-IR-INCIDENT-RESPONSE", Relationship: "detects", Confidence: 0.9, Description: "Incident response detects and correlates log tampering events"},
	{TechniqueID: "T1562.001", TechniqueName: "Impair Defenses: Disable Security Tools", Framework: "atlas", AegisGateControl: "AG-IR-INCIDENT-RESPONSE", Relationship: "detects", Confidence: 0.85, Description: "Incident response detects defense impairment and triggers automated playbooks"},
	{TechniqueID: "GOVERN 2.3", TechniqueName: "AI risk management responsibilities", Framework: "nist_ai_rmf", AegisGateControl: "AG-IR-INCIDENT-RESPONSE", Relationship: "supports", Confidence: 0.85, Description: "Incident response automation supports AI risk management responsibilities"},
	{TechniqueID: "OWASPDev-09", TechniqueName: "Security Logging and Monitoring Failures", Framework: "owasp_llm", AegisGateControl: "AG-IR-INCIDENT-RESPONSE", Relationship: "mitigates", Confidence: 0.85, Description: "Automated incident response mitigates logging and monitoring gaps"},

	// ================================================================
	// AG-SC-BOUNDARY-PROTECTION: Network and cryptographic boundary techniques
	// ================================================================
	{TechniqueID: "T1136", TechniqueName: "Create Account (Boundary Violation)", Framework: "atlas", AegisGateControl: "AG-SC-BOUNDARY-PROTECTION", Relationship: "mitigates", Confidence: 0.85, Description: "Boundary protection prevents unauthorized account creation across network segments"},
	{TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing Application (Boundary)", Framework: "atlas", AegisGateControl: "AG-SC-BOUNDARY-PROTECTION", Relationship: "mitigates", Confidence: 0.85, Description: "Boundary protection limits attack surface of public-facing applications"},
	{TechniqueID: "PR.AC-5", TechniqueName: "Network Integrity Protected", Framework: "nist_ai_rmf", AegisGateControl: "AG-SC-BOUNDARY-PROTECTION", Relationship: "supports", Confidence: 0.9, Description: "Boundary protection implements network integrity controls"},
	{TechniqueID: "OWASPDev-07", TechniqueName: "Identification and Authentication Failures", Framework: "owasp_llm", AegisGateControl: "AG-SC-BOUNDARY-PROTECTION", Relationship: "mitigates", Confidence: 0.85, Description: "Session authenticity and key management prevent auth failures"},

	// ================================================================
	// AG-DATA-PROTECTION-PRIVACY — Data Protection and Privacy Controls
	// ================================================================
	{TechniqueID: "T1189", TechniqueName: "Drive-by Compromise", Framework: "atlas", AegisGateControl: "AG-DATA-PROTECTION-PRIVACY", Relationship: "mitigates", Confidence: 0.8, Description: "Data masking and DLP prevent drive-by compromise data exfiltration"},
	{TechniqueID: "T1567", TechniqueName: "Exfiltration Over Web Service", Framework: "atlas", AegisGateControl: "AG-DATA-PROTECTION-PRIVACY", Relationship: "mitigates", Confidence: 0.85, Description: "DLP prevents data exfiltration via web services"},
	{TechniqueID: "ME1", TechniqueName: "Measuring: Performance Monitoring", Framework: "nist_ai_rmf", AegisGateControl: "AG-DATA-PROTECTION-PRIVACY", Relationship: "supports", Confidence: 0.8, Description: "Data protection monitoring supports AI RMF performance measurement"},
	{TechniqueID: "LLM06", TechniqueName: "Sensitive Information Disclosure", Framework: "owasp_llm", AegisGateControl: "AG-DATA-PROTECTION-PRIVACY", Relationship: "mitigates", Confidence: 0.9, Description: "Data masking and PII filtering prevent sensitive information disclosure from LLMs"},

	// ================================================================
	// AG-SECURITY-AWARENESS — Security Awareness and Training
	// ================================================================
	{TechniqueID: "T1535", TechniqueName: "Unsecured Credentials", Framework: "atlas", AegisGateControl: "AG-SECURITY-AWARENESS", Relationship: "supports", Confidence: 0.7, Description: "Security awareness training reduces credential exposure risk"},
	{TechniqueID: "T1566", TechniqueName: "Phishing", Framework: "atlas", AegisGateControl: "AG-SECURITY-AWARENESS", Relationship: "mitigates", Confidence: 0.85, Description: "Security awareness training is primary defense against phishing"},
	{TechniqueID: "GV1", TechniqueName: "Govern: Organizational Context", Framework: "nist_ai_rmf", AegisGateControl: "AG-SECURITY-AWARENESS", Relationship: "supports", Confidence: 0.75, Description: "Security awareness training supports organizational governance"},
	{TechniqueID: "OWASPDev-06", TechniqueName: "Vulnerable and Outdated Components", Framework: "owasp_llm", AegisGateControl: "AG-SECURITY-AWARENESS", Relationship: "supports", Confidence: 0.7, Description: "Training helps teams identify and remediate vulnerable components"},

	// ================================================================
	// AG-ASSET-INVENTORY — Asset Management and Inventory Controls
	// ================================================================
	{TechniqueID: "T1590", TechniqueName: "Gather Victim Network Information", Framework: "atlas", AegisGateControl: "AG-ASSET-INVENTORY", Relationship: "mitigates", Confidence: 0.8, Description: "Asset inventory reduces reconnaissance attack surface"},
	{TechniqueID: "T1595", TechniqueName: "Active Scanning", Framework: "atlas", AegisGateControl: "AG-ASSET-INVENTORY", Relationship: "detects", Confidence: 0.85, Description: "Asset inventory enables detection of unauthorized scanning"},
	{TechniqueID: "ID.AM-1", TechniqueName: "Identify: Asset Management", Framework: "nist_ai_rmf", AegisGateControl: "AG-ASSET-INVENTORY", Relationship: "supports", Confidence: 0.9, Description: "Asset inventory is foundational to NIST CSF Identify function"},
	{TechniqueID: "LLM05", TechniqueName: "Supply Chain Vulnerabilities", Framework: "owasp_llm", AegisGateControl: "AG-ASSET-INVENTORY", Relationship: "mitigates", Confidence: 0.8, Description: "Software inventory enables supply chain vulnerability detection"},

	// ================================================================
	// AG-SUPPLY-CHAIN-RISK — Third-Party and Supply Chain Risk Management
	// ================================================================
	{TechniqueID: "T0043", TechniqueName: "ML Supply Chain Compromise", Framework: "atlas", AegisGateControl: "AG-SUPPLY-CHAIN-RISK", Relationship: "mitigates", Confidence: 0.9, Description: "Supply chain risk management addresses ML model and data compromise"},
	{TechniqueID: "T0044", TechniqueName: "AI Red Team Evasion", Framework: "atlas", AegisGateControl: "AG-SUPPLY-CHAIN-RISK", Relationship: "mitigates", Confidence: 0.85, Description: "Third-party risk assessment covers adversarial supply chain attacks"},
	{TechniqueID: "GV3", TechniqueName: "Govern: Risk Management", Framework: "nist_ai_rmf", AegisGateControl: "AG-SUPPLY-CHAIN-RISK", Relationship: "supports", Confidence: 0.85, Description: "Supply chain risk supports AI governance risk management"},
	{TechniqueID: "LLM05", TechniqueName: "Supply Chain Vulnerabilities", Framework: "owasp_llm", AegisGateControl: "AG-SUPPLY-CHAIN-RISK", Relationship: "mitigates", Confidence: 0.9, Description: "Supply chain risk management directly addresses LLM supply chain vulnerabilities"},

	// ================================================================
	// AG-BUSINESS-CONTINUITY — Business Continuity and Availability
	// ================================================================
	{TechniqueID: "T1486", TechniqueName: "Data Encrypted for Impact", Framework: "atlas", AegisGateControl: "AG-BUSINESS-CONTINUITY", Relationship: "mitigates", Confidence: 0.8, Description: "Backup and recovery procedures mitigate ransomware impact"},
	{TechniqueID: "T1490", TechniqueName: "Inhibit System Recovery", Framework: "atlas", AegisGateControl: "AG-BUSINESS-CONTINUITY", Relationship: "mitigates", Confidence: 0.85, Description: "Business continuity planning addresses recovery inhibition"},
	{TechniqueID: "PR.IP-4", TechniqueName: "Protect: Backups", Framework: "nist_ai_rmf", AegisGateControl: "AG-BUSINESS-CONTINUITY", Relationship: "supports", Confidence: 0.9, Description: "Business continuity planning supports NIST CSF backup requirements"},

	// ================================================================
	// AG-IDENTITY-LIFECYCLE — Identity and Access Lifecycle Management
	// ================================================================
	{TechniqueID: "T1078", TechniqueName: "Valid Accounts", Framework: "atlas", AegisGateControl: "AG-IDENTITY-LIFECYCLE", Relationship: "mitigates", Confidence: 0.9, Description: "Identity lifecycle management prevents valid account abuse"},
	{TechniqueID: "T1556", TechniqueName: "Modify Authentication Process", Framework: "atlas", AegisGateControl: "AG-IDENTITY-LIFECYCLE", Relationship: "mitigates", Confidence: 0.85, Description: "Provisioning and deprovisioning prevents auth modification attacks"},
	{TechniqueID: "PR.AC-1", TechniqueName: "Protect: Identity Management", Framework: "nist_ai_rmf", AegisGateControl: "AG-IDENTITY-LIFECYCLE", Relationship: "supports", Confidence: 0.9, Description: "Identity lifecycle management directly supports identity controls"},
	{TechniqueID: "OWASPDev-01", TechniqueName: "Broken Access Control", Framework: "owasp_llm", AegisGateControl: "AG-IDENTITY-LIFECYCLE", Relationship: "mitigates", Confidence: 0.85, Description: "Identity lifecycle management prevents broken access control"},

	// ================================================================
	// AG-NETWORK-SECURITY — Network and Communication Security
	// ================================================================
	{TechniqueID: "T1136", TechniqueName: "Create Account", Framework: "atlas", AegisGateControl: "AG-NETWORK-SECURITY", Relationship: "detects", Confidence: 0.8, Description: "Network security controls detect unauthorized account creation"},
	{TechniqueID: "T1090", TechniqueName: "Proxy: Multi-hop Proxy", Framework: "atlas", AegisGateControl: "AG-NETWORK-SECURITY", Relationship: "mitigates", Confidence: 0.85, Description: "Network segmentation and firewall management prevents proxy-based C2"},
	{TechniqueID: "PR.AC-5", TechniqueName: "Protect: Network Integrity", Framework: "nist_ai_rmf", AegisGateControl: "AG-NETWORK-SECURITY", Relationship: "supports", Confidence: 0.9, Description: "Network security controls implement network integrity requirements"},
	{TechniqueID: "OWASPDev-05", TechniqueName: "Security Misconfiguration", Framework: "owasp_llm", AegisGateControl: "AG-NETWORK-SECURITY", Relationship: "mitigates", Confidence: 0.85, Description: "Network security controls prevent misconfiguration-based attacks"},

	// ================================================================
	// AG-RISK-GOVERNANCE — Risk Assessment and Governance
	// ================================================================
	{TechniqueID: "T1590", TechniqueName: "Gather Victim Network Information", Framework: "atlas", AegisGateControl: "AG-RISK-GOVERNANCE", Relationship: "detects", Confidence: 0.8, Description: "Risk assessment identifies reconnaissance threats"},
	{TechniqueID: "T1592", TechniqueName: "Gather Victim Host Information", Framework: "atlas", AegisGateControl: "AG-RISK-GOVERNANCE", Relationship: "detects", Confidence: 0.8, Description: "Risk governance processes address host-level reconnaissance"},
	{TechniqueID: "GV4", TechniqueName: "Govern: Risk Management", Framework: "nist_ai_rmf", AegisGateControl: "AG-RISK-GOVERNANCE", Relationship: "supports", Confidence: 0.9, Description: "Risk governance directly supports AI RMF governance function"},
	{TechniqueID: "OWASPDev-09", TechniqueName: "Security Logging and Monitoring Failures", Framework: "owasp_llm", AegisGateControl: "AG-RISK-GOVERNANCE", Relationship: "supports", Confidence: 0.8, Description: "Risk governance requires comprehensive logging and monitoring"},

	// ================================================================
	// AG-PHYSICAL-SECURITY — Physical and Environmental Security
	// ================================================================
	{TechniqueID: "T1366", TechniqueName: "Physical Access", Framework: "atlas", AegisGateControl: "AG-PHYSICAL-SECURITY", Relationship: "mitigates", Confidence: 0.75, Description: "Physical security controls prevent physical access attacks"},

	// ================================================================
	// AG-AI-SAFETY-QUALITY — AI Safety, Quality, and Transparency
	// ================================================================
	{TechniqueID: "T1484", TechniqueName: "Adversarial Examples", Framework: "atlas", AegisGateControl: "AG-AI-SAFETY-QUALITY", Relationship: "mitigates", Confidence: 0.9, Description: "AI safety controls detect and mitigate adversarial examples"},
	{TechniqueID: "T1535", TechniqueName: "ML Model Stealing", Framework: "atlas", AegisGateControl: "AG-AI-SAFETY-QUALITY", Relationship: "mitigates", Confidence: 0.85, Description: "AI quality controls protect against model extraction and theft"},
	{TechniqueID: "T1658", TechniqueName: "Jailbreak", Framework: "atlas", AegisGateControl: "AG-AI-SAFETY-QUALITY", Relationship: "mitigates", Confidence: 0.9, Description: "AI safety controls defend against jailbreak and prompt injection"},
	{TechniqueID: "GV1", TechniqueName: "Govern: Organizational Context", Framework: "nist_ai_rmf", AegisGateControl: "AG-AI-SAFETY-QUALITY", Relationship: "supports", Confidence: 0.85, Description: "AI safety governance supports organizational risk management"},
	{TechniqueID: "MP4", TechniqueName: "Map: Adversarial Profiling", Framework: "nist_ai_rmf", AegisGateControl: "AG-AI-SAFETY-QUALITY", Relationship: "supports", Confidence: 0.9, Description: "AI safety measurement supports adversarial threat profiling"},
	{TechniqueID: "LLM01", TechniqueName: "Prompt Injection", Framework: "owasp_llm", AegisGateControl: "AG-AI-SAFETY-QUALITY", Relationship: "mitigates", Confidence: 0.95, Description: "AI safety controls are primary defense against prompt injection"},
	{TechniqueID: "LLM09", TechniqueName: "Overreliance", Framework: "owasp_llm", AegisGateControl: "AG-AI-SAFETY-QUALITY", Relationship: "mitigates", Confidence: 0.85, Description: "AI quality controls prevent overreliance on LLM outputs"},

	// ================================================================
	// P0/P1/P2: New cross-framework AG controls — technique mappings
	// ================================================================

	// AG-AC-CONCURRENT-SESSIONS — Session management
	{TechniqueID: "T1535", TechniqueName: "Unsecured Credentials", Framework: "atlas", AegisGateControl: "AG-AC-CONCURRENT-SESSIONS", Relationship: "mitigates", Confidence: 0.85, Description: "Concurrent session limits prevent credential reuse attacks"},
	{TechniqueID: "T1110", TechniqueName: "Brute Force", Framework: "atlas", AegisGateControl: "AG-AC-CONCURRENT-SESSIONS", Relationship: "mitigates", Confidence: 0.9, Description: "Session limits prevent brute-force credential attacks"},
	{TechniqueID: "GV2", TechniqueName: "Govern: Accountability", Framework: "nist_ai_rmf", AegisGateControl: "AG-AC-CONCURRENT-SESSIONS", Relationship: "supports", Confidence: 0.8, Description: "Session management supports accountability governance"},

	// AG-IA-ADVERSARY-DETECTION — Adversary detection and identification
	{TechniqueID: "T1556", TechniqueName: "Modify Authentication Process", Framework: "atlas", AegisGateControl: "AG-IA-ADVERSARY-DETECTION", Relationship: "detects", Confidence: 0.9, Description: "Adversary detection identifies authentication manipulation attempts"},
	{TechniqueID: "T1584", TechniqueName: "Access Token Manipulation", Framework: "atlas", AegisGateControl: "AG-IA-ADVERSARY-DETECTION", Relationship: "detects", Confidence: 0.9, Description: "Adversary detection identifies token manipulation"},
	{TechniqueID: "MP4", TechniqueName: "Map: Adversarial Profiling", Framework: "nist_ai_rmf", AegisGateControl: "AG-IA-ADVERSARY-DETECTION", Relationship: "supports", Confidence: 0.85, Description: "Adversary detection supports adversarial threat profiling"},
	{TechniqueID: "LLM06", TechniqueName: "Sensitive Data Disclosure", Framework: "owasp_llm", AegisGateControl: "AG-IA-ADVERSARY-DETECTION", Relationship: "detects", Confidence: 0.85, Description: "Adversary detection identifies unauthorized data access attempts"},

	// AG-IR-INTEGRATION — Incident response integration
	{TechniqueID: "T1484", TechniqueName: "Jailbreak", Framework: "atlas", AegisGateControl: "AG-IR-INTEGRATION", Relationship: "supports", Confidence: 0.85, Description: "IR integration provides coordinated response to jailbreak events"},
	{TechniqueID: "GV1", TechniqueName: "Govern: Organizational Context", Framework: "nist_ai_rmf", AegisGateControl: "AG-IR-INTEGRATION", Relationship: "supports", Confidence: 0.8, Description: "IR integration supports organizational incident governance"},
	{TechniqueID: "LLM09", TechniqueName: "Overreliance", Framework: "owasp_llm", AegisGateControl: "AG-IR-INTEGRATION", Relationship: "supports", Confidence: 0.8, Description: "IR integration handles incidents from AI overreliance"},

	// AG-SC-RESOURCE-AVAILABILITY — DoS protection, fail-safe networks
	{TechniqueID: "T1498", TechniqueName: "Network DoS", Framework: "atlas", AegisGateControl: "AG-SC-RESOURCE-AVAILABILITY", Relationship: "mitigates", Confidence: 0.9, Description: "Resource availability controls prevent denial-of-service"},
	{TechniqueID: "T1486", TechniqueName: "Data Encrypted for Impact", Framework: "atlas", AegisGateControl: "AG-SC-RESOURCE-AVAILABILITY", Relationship: "mitigates", Confidence: 0.85, Description: "Fail-safe networks prevent data impact from DoS"},
	{TechniqueID: "GV2", TechniqueName: "Govern: Accountability", Framework: "nist_ai_rmf", AegisGateControl: "AG-SC-RESOURCE-AVAILABILITY", Relationship: "supports", Confidence: 0.8, Description: "Resource availability supports system accountability governance"},

	// AG-CM-CONFIGURATION-PLANNING — Configuration management
	{TechniqueID: "T1648", TechniqueName: "Serverless Function Exploitation", Framework: "atlas", AegisGateControl: "AG-CM-CONFIGURATION-PLANNING", Relationship: "mitigates", Confidence: 0.85, Description: "Configuration management prevents unauthorized software installation"},
	{TechniqueID: "T1599", TechniqueName: "Exploit Public-Facing Application", Framework: "atlas", AegisGateControl: "AG-CM-CONFIGURATION-PLANNING", Relationship: "mitigates", Confidence: 0.85, Description: "Configuration planning ensures secure application configurations"},
	{TechniqueID: "GV1", TechniqueName: "Govern: Organizational Context", Framework: "nist_ai_rmf", AegisGateControl: "AG-CM-CONFIGURATION-PLANNING", Relationship: "supports", Confidence: 0.8, Description: "Configuration management supports organizational governance"},

	// AG-AT-AWARENESS-TRAINING — Security awareness
	{TechniqueID: "T1566", TechniqueName: "Phishing", Framework: "atlas", AegisGateControl: "AG-AT-AWARENESS-TRAINING", Relationship: "mitigates", Confidence: 0.85, Description: "Security awareness training reduces phishing susceptibility"},
	{TechniqueID: "T1535", TechniqueName: "Unsecured Credentials", Framework: "atlas", AegisGateControl: "AG-AT-AWARENESS-TRAINING", Relationship: "mitigates", Confidence: 0.8, Description: "Training reduces credential exposure"},
	{TechniqueID: "GV1", TechniqueName: "Govern: Organizational Context", Framework: "nist_ai_rmf", AegisGateControl: "AG-AT-AWARENESS-TRAINING", Relationship: "supports", Confidence: 0.85, Description: "Awareness training supports organizational risk governance"},

	// AG-CP-CONTINGENCY — Business continuity and contingency
	{TechniqueID: "T1498", TechniqueName: "Network DoS", Framework: "atlas", AegisGateControl: "AG-CP-CONTINGENCY", Relationship: "mitigates", Confidence: 0.85, Description: "Contingency planning provides recovery from DoS attacks"},
	{TechniqueID: "T1486", TechniqueName: "Data Encrypted for Impact", Framework: "atlas", AegisGateControl: "AG-CP-CONTINGENCY", Relationship: "mitigates", Confidence: 0.85, Description: "Business continuity planning provides recovery from ransomware"},
	{TechniqueID: "GV2", TechniqueName: "Govern: Accountability", Framework: "nist_ai_rmf", AegisGateControl: "AG-CP-CONTINGENCY", Relationship: "supports", Confidence: 0.8, Description: "Contingency planning supports accountability governance"},

	// AG-CA-SECURITY-ASSESSMENT — Security assessments
	{TechniqueID: "T1590", TechniqueName: "Gather Victim Network Info", Framework: "atlas", AegisGateControl: "AG-CA-SECURITY-ASSESSMENT", Relationship: "detects", Confidence: 0.85, Description: "Security assessments identify network reconnaissance"},
	{TechniqueID: "T1592", TechniqueName: "Gather Victim Host Info", Framework: "atlas", AegisGateControl: "AG-CA-SECURITY-ASSESSMENT", Relationship: "detects", Confidence: 0.85, Description: "Security assessments identify host reconnaissance"},
	{TechniqueID: "MP5", TechniqueName: "Measure: Risk Tracking", Framework: "nist_ai_rmf", AegisGateControl: "AG-CA-SECURITY-ASSESSMENT", Relationship: "supports", Confidence: 0.85, Description: "Security assessments support AI risk tracking"},

	// AG-AC-ACCESS-ENFORCEMENT — Access enforcement and info sharing
	{TechniqueID: "T1556", TechniqueName: "Modify Authentication Process", Framework: "atlas", AegisGateControl: "AG-AC-ACCESS-ENFORCEMENT", Relationship: "mitigates", Confidence: 0.9, Description: "Access enforcement prevents authentication manipulation"},
	{TechniqueID: "T1584", TechniqueName: "Access Token Manipulation", Framework: "atlas", AegisGateControl: "AG-AC-ACCESS-ENFORCEMENT", Relationship: "mitigates", Confidence: 0.85, Description: "Information flow enforcement prevents token manipulation"},
	{TechniqueID: "LLM06", TechniqueName: "Sensitive Data Disclosure", Framework: "owasp_llm", AegisGateControl: "AG-AC-ACCESS-ENFORCEMENT", Relationship: "mitigates", Confidence: 0.85, Description: "Access enforcement prevents unauthorized data disclosure"},

	// AG-AU-AUDIT-MONITORING — Audit monitoring and analysis
	{TechniqueID: "T1535", TechniqueName: "Unsecured Credentials", Framework: "atlas", AegisGateControl: "AG-AU-AUDIT-MONITORING", Relationship: "detects", Confidence: 0.85, Description: "Audit monitoring detects credential exposure events"},
	{TechniqueID: "T1589", TechniqueName: "Gather Victim Network Info", Framework: "atlas", AegisGateControl: "AG-AU-AUDIT-MONITORING", Relationship: "detects", Confidence: 0.85, Description: "Audit monitoring detects network reconnaissance patterns"},
	{TechniqueID: "MS2", TechniqueName: "Measure: AI System Risk Assessment", Framework: "nist_ai_rmf", AegisGateControl: "AG-AU-AUDIT-MONITORING", Relationship: "supports", Confidence: 0.85, Description: "Audit monitoring supports AI system risk measurement"},

	// AG-PL-PLANNING — Security planning
	{TechniqueID: "GV1", TechniqueName: "Govern: Organizational Context", Framework: "nist_ai_rmf", AegisGateControl: "AG-PL-PLANNING", Relationship: "supports", Confidence: 0.9, Description: "Security planning supports organizational risk governance"},
	{TechniqueID: "GV2", TechniqueName: "Govern: Accountability", Framework: "nist_ai_rmf", AegisGateControl: "AG-PL-PLANNING", Relationship: "supports", Confidence: 0.85, Description: "Security planning supports accountability governance"},
	{TechniqueID: "T1566", TechniqueName: "Phishing", Framework: "atlas", AegisGateControl: "AG-PL-PLANNING", Relationship: "mitigates", Confidence: 0.8, Description: "Security planning reduces phishing impact through policy"},

	// AG-MA-MAINTENANCE — System maintenance and media protection
	{TechniqueID: "T1648", TechniqueName: "Serverless Function Exploitation", Framework: "atlas", AegisGateControl: "AG-MA-MAINTENANCE", Relationship: "mitigates", Confidence: 0.8, Description: "Proper maintenance reduces serverless exploitation risk"},
	{TechniqueID: "T1599", TechniqueName: "Exploit Public-Facing Application", Framework: "atlas", AegisGateControl: "AG-MA-MAINTENANCE", Relationship: "mitigates", Confidence: 0.8, Description: "Maintenance reduces public-facing application vulnerabilities"},
	{TechniqueID: "GV1", TechniqueName: "Govern: Organizational Context", Framework: "nist_ai_rmf", AegisGateControl: "AG-MA-MAINTENANCE", Relationship: "supports", Confidence: 0.8, Description: "Maintenance supports organizational governance"},

	// AG-PS-PERSONNEL-SECURITY — Personnel security
	{TechniqueID: "T1535", TechniqueName: "Unsecured Credentials", Framework: "atlas", AegisGateControl: "AG-PS-PERSONNEL-SECURITY", Relationship: "mitigates", Confidence: 0.8, Description: "Personnel security reduces insider credential threats"},
	{TechniqueID: "T1566", TechniqueName: "Phishing", Framework: "atlas", AegisGateControl: "AG-PS-PERSONNEL-SECURITY", Relationship: "mitigates", Confidence: 0.85, Description: "Personnel security screening reduces phishing susceptibility"},
	{TechniqueID: "GV1", TechniqueName: "Govern: Organizational Context", Framework: "nist_ai_rmf", AegisGateControl: "AG-PS-PERSONNEL-SECURITY", Relationship: "supports", Confidence: 0.8, Description: "Personnel security supports organizational risk governance"},

	// AG-IR-IR-POLICY-PLANNING — IR policy and coordination
	{TechniqueID: "T1484", TechniqueName: "Jailbreak", Framework: "atlas", AegisGateControl: "AG-IR-IR-POLICY-PLANNING", Relationship: "supports", Confidence: 0.8, Description: "IR policy provides structured response to jailbreak incidents"},
	{TechniqueID: "GV2", TechniqueName: "Govern: Accountability", Framework: "nist_ai_rmf", AegisGateControl: "AG-IR-IR-POLICY-PLANNING", Relationship: "supports", Confidence: 0.85, Description: "IR policy supports accountability governance"},
	{TechniqueID: "LLM02", TechniqueName: "Sensitive Information Leakage", Framework: "owasp_llm", AegisGateControl: "AG-IR-IR-POLICY-PLANNING", Relationship: "supports", Confidence: 0.8, Description: "IR policy coordinates response to sensitive information leakage"},

	// AG-SC-COMM-PROTECTION — Extended SC controls
	{TechniqueID: "T1498", TechniqueName: "Network DoS", Framework: "atlas", AegisGateControl: "AG-SC-COMM-PROTECTION", Relationship: "mitigates", Confidence: 0.85, Description: "Communication protection controls prevent network DoS"},
	{TechniqueID: "T1590", TechniqueName: "Gather Victim Network Info", Framework: "atlas", AegisGateControl: "AG-SC-COMM-PROTECTION", Relationship: "mitigates", Confidence: 0.85, Description: "DNS and mobile code controls prevent network reconnaissance"},
	{TechniqueID: "MP4", TechniqueName: "Map: Adversarial Profiling", Framework: "nist_ai_rmf", AegisGateControl: "AG-SC-COMM-PROTECTION", Relationship: "supports", Confidence: 0.8, Description: "Communication protection supports adversarial profiling defense"},

	// AG-SI-SYSTEM-INTEGRITY — Extended SI controls
	{TechniqueID: "T1484", TechniqueName: "Jailbreak", Framework: "atlas", AegisGateControl: "AG-SI-SYSTEM-INTEGRITY", Relationship: "detects", Confidence: 0.85, Description: "System integrity controls detect jailbreak-related anomalies"},
	{TechniqueID: "T1658", TechniqueName: "Exploitable Prompt Injection", Framework: "atlas", AegisGateControl: "AG-SI-SYSTEM-INTEGRITY", Relationship: "detects", Confidence: 0.85, Description: "Integrity validation detects prompt injection exploits"},
	{TechniqueID: "MS2", TechniqueName: "Measure: AI System Risk Assessment", Framework: "nist_ai_rmf", AegisGateControl: "AG-SI-SYSTEM-INTEGRITY", Relationship: "supports", Confidence: 0.8, Description: "System integrity supports AI risk measurement"},

	// AG-SA-SYSTEM-ACQUISITION — System acquisition
	{TechniqueID: "T1599", TechniqueName: "Exploit Public-Facing Application", Framework: "atlas", AegisGateControl: "AG-SA-SYSTEM-ACQUISITION", Relationship: "mitigates", Confidence: 0.85, Description: "Secure acquisition processes reduce exploitable software risk"},
	{TechniqueID: "T1648", TechniqueName: "Serverless Function Exploitation", Framework: "atlas", AegisGateControl: "AG-SA-SYSTEM-ACQUISITION", Relationship: "mitigates", Confidence: 0.85, Description: "Acquisition security requirements prevent serverless exploits"},
	{TechniqueID: "GV1", TechniqueName: "Govern: Organizational Context", Framework: "nist_ai_rmf", AegisGateControl: "AG-SA-SYSTEM-ACQUISITION", Relationship: "supports", Confidence: 0.8, Description: "Secure acquisition supports organizational risk governance"},
}

// TechniquesForControl returns all technique mappings that target
// the given AegisGate control. The opposite-direction query to
// MapByControlID.
func TechniquesForControl(aegisgateID string) []TechniqueMapping {
	results := []TechniqueMapping{}
	for _, m := range TechniqueMappings {
		if m.AegisGateControl == aegisgateID {
			results = append(results, m)
		}
	}
	return results
}

// AegisGateControlsForTechnique returns the AegisGate controls that
// detect/mitigate a given technique (e.g., "T1535").
func AegisGateControlsForTechnique(framework, techniqueID string) []TechniqueMapping {
	results := []TechniqueMapping{}
	for _, m := range TechniqueMappings {
		if m.Framework == framework && m.TechniqueID == techniqueID {
			results = append(results, m)
		}
	}
	return results
}

// AegisGateCoverageByTechnique returns the count of techniques
// each AegisGate control detects/mitigates. This is the "engineer
// view" complement to the GRC report's "framework coverage" view.
func AegisGateCoverageByTechnique() map[string]int {
	coverage := make(map[string]int)
	for _, m := range TechniqueMappings {
		coverage[m.AegisGateControl]++
	}
	return coverage
}
