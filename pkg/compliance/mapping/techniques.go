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
