// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Rule Metadata Database (CWE / OWASP / Remediation)
// =========================================================================
//
// Provides structured metadata for every detection rule, including:
//   - CWE (Common Weakness Enumeration) IDs
//   - OWASP LLM Top 10 (2025) references
//   - Human-readable descriptions
//   - Remediation guidance
//   - Reference URLs
//
// Ported from the AegisGate Scanner pkg/output/rule_metadata.go to make
// remediation guidance available to the Platform without a cross-repo
// dependency. The Scanner remains the canonical source; this package
// mirrors its data and adds Platform-specific convenience helpers.
//
// OWASP LLM Top 10 → CWE mapping:
//   LLM01: Prompt Injection            → CWE 77  (Command Injection)
//   LLM02: Insecure Output Handling    → CWE 20  (Improper Input Validation)
//   LLM03: Training Data Poisoning     → CWE 506 (Embedded Malicious Code)
//   LLM04: Model DoS                   → CWE 770 (Resource Exhaustion)
//   LLM05: Supply Chain                → CWE 829 (Inclusion of Functionality
//                                                 from Untrusted Control Sphere)
//   LLM06: Sensitive Info Disclosure   → CWE 200 (Information Exposure)
//   LLM07: Insecure Plugin Design      → CWE 1117(Inspectable Execution
//                                                 Node)
//   LLM08: Excessive Agency            → CWE 250 (Execution with Unnecessary
//                                                 Privileges)
//   LLM09: Overreliance                → CWE 710 (Improper Adherence to
//                                                 Coding Standards)
//   LLM10: Model Theft                 → CWE 1242(Insecure Exfiltration of
//                                                 Sensitive Information)
//
// =========================================================================

package remediation

import "strings"

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

// RuleMetadata holds CWE, OWASP, and remediation information for a
// detection rule.
type RuleMetadata struct {
	RuleID       string   `json:"rule_id"`        // e.g., "owasp_llm01_prompt_injection"
	CWE          []int    `json:"cwe"`            // e.g., [77]
	OWASPLLMTop  string   `json:"owasp_llm_top"`  // e.g., "LLM01"
	OWASPName    string   `json:"owasp_name"`     // e.g., "Prompt Injection"
	NISTAIRMF    []string `json:"nist_ai_rmf"`    // NIST AI RMF functions: Govern, Map, Measure, Manage
	NISTCSF      []string `json:"nist_csf"`       // NIST CSF 2.0 subcategories: PR.AC-1, DE.CM-1, etc.
	EUAIArticles []string `json:"eu_ai_articles"` // EU AI Act articles: Art. 10, Art. 14, Art. 15, etc.
	Description  string   `json:"description"`    // human-readable description
	Remediation  string   `json:"remediation"`    // how to fix it
	References   []string `json:"references"`     // URLs to docs
}

// ---------------------------------------------------------------------
// OWASP LLM Top 10 constant mapping
// ---------------------------------------------------------------------

// owaspLLMMap maps OWASP LLM Top 10 identifiers to their CWE, name,
// NIST AI RMF functions, NIST CSF 2.0 subcategories, and EU AI Act
// article references. Framework mappings are derived from the AegisGate
// ATLAS → Compliance Coverage Map (v1.0, Aug 2026).
var owaspLLMMap = map[string]struct {
	CWE          int
	Name         string
	NISTAIRMF    []string
	NISTCSF      []string
	EUAIArticles []string
}{
	"LLM01": {77, "Prompt Injection",
		[]string{"Map", "Measure", "Manage"},
		[]string{"PR.AC-1", "DE.CM-1"},
		[]string{"Art. 14", "Art. 15"},
	},
	"LLM02": {20, "Insecure Output Handling",
		[]string{"Measure", "Manage"},
		[]string{"DE.CM-7", "ID.RA-2"},
		[]string{"Art. 10", "Art. 15"},
	},
	"LLM03": {506, "Training Data Poisoning",
		[]string{"Map", "Measure", "Manage"},
		[]string{"ID.RA-2", "DE.CM-7"},
		[]string{"Art. 10"},
	},
	"LLM04": {770, "Model DoS",
		[]string{"Measure", "Manage"},
		[]string{"PR.DS-4", "DE.CM-1"},
		[]string{"Art. 15"},
	},
	"LLM05": {829, "Supply Chain",
		[]string{"Map", "Measure", "Manage"},
		[]string{"ID.RA-2", "PR.AC-4"},
		[]string{"Art. 10", "Art. 15"},
	},
	"LLM06": {200, "Sensitive Info Disclosure",
		[]string{"Govern", "Measure", "Manage"},
		[]string{"PR.AC-1", "DE.CM-1"},
		[]string{"Art. 14", "Art. 15"},
	},
	"LLM07": {1117, "Insecure Plugin Design",
		[]string{"Map", "Measure", "Manage"},
		[]string{"DE.CM-7", "PR.AC-4"},
		[]string{"Art. 15"},
	},
	"LLM08": {250, "Excessive Agency",
		[]string{"Govern", "Measure", "Manage"},
		[]string{"PR.AC-1", "PR.AC-4"},
		[]string{"Art. 14", "Art. 15"},
	},
	"LLM09": {710, "Overreliance",
		[]string{"Govern", "Map"},
		[]string{"ID.RA-2"},
		[]string{"Art. 14"},
	},
	"LLM10": {1242, "Model Theft",
		[]string{"Govern", "Measure", "Manage"},
		[]string{"ID.RA-2", "DE.CM-7"},
		[]string{"Art. 10", "Art. 15"},
	},
}

// ---------------------------------------------------------------------
// Remediation text constants
// ---------------------------------------------------------------------

const (
	remediationPromptInjection = "Sanitize and filter user input before processing. " +
		"Use input validation and prompt boundaries. Consider using structured prompts with delimiters."
	remediationSecrets = "Move secrets to environment variables or a secrets manager. " +
		"Never hardcode credentials in source code or configuration files."
	remediationPII = "Remove PII from the dataset. Use data anonymization or pseudonymization " +
		"techniques. Implement data minimization principles."
	remediationXSS = "Sanitize and encode all user-generated content before rendering. " +
		"Use CSP headers. Implement output encoding."
	remediationOT = "Validate and sanitize all protocol commands. Implement access controls " +
		"on OT systems. Use allowlists for accepted commands."
	remediationCompliance = "Review the referenced regulation and implement required controls. " +
		"Document compliance measures."
	remediationHarmful = "Implement content filtering and safety guardrails. " +
		"Use ML-based content classification to block harmful outputs."
	remediationATLAS = "Implement adversarial detection and defense mechanisms. " +
		"Monitor for reconnaissance and resource development activities."
	remediationDefault = "Review the finding and determine if it represents a security risk " +
		"for your use case."
	remediationDangerousCode = "Avoid executing untrusted code. Use sandboxing and code review " +
		"for dynamic execution paths. Restrict dangerous APIs in production."
	remediationInsecureOutput = "Validate and sanitize all model outputs before rendering or " +
		"executing. Use output encoding and content security policies."
	remediationModelDoS = "Implement rate limiting and resource quotas. " +
		"Monitor for excessive token consumption and repeated requests."
	remediationSupplyChain = "Verify the provenance and integrity of all models, plugins, and " +
		"libraries. Use signed packages and trusted registries."
	remediationSensitiveInfo = "Remove sensitive information from prompts and outputs. " +
		"Implement access controls and data loss prevention measures."
	remediationExcessiveAgency = "Implement human-in-the-loop controls for critical actions. " +
		"Restrict tool access and require explicit confirmation for sensitive operations."
	remediationOverreliance = "Validate AI-generated outputs with independent sources. " +
		"Do not rely solely on AI for critical decisions. Implement human review."
	remediationModelTheft = "Restrict access to model weights and parameters. " +
		"Monitor for extraction attempts. Use API rate limiting and watermarking."
	remediationTrainingPoisoning = "Validate and curate training data sources. " +
		"Implement data integrity checks and adversarial training defenses."
)

// ---------------------------------------------------------------------
// Explicit metadata map — OWASP LLM Top 10 and key patterns
// ---------------------------------------------------------------------

// ruleMetadataMap contains explicit metadata entries for known rules.
// Category-level matching (by prefix) handles rules not listed here.
var ruleMetadataMap = map[string]RuleMetadata{
	// === OWASP LLM01: Prompt Injection (CWE 77) ===
	"owasp_llm01_prompt_injection": {
		RuleID:      "owasp_llm01_prompt_injection",
		CWE:         []int{77},
		OWASPLLMTop: "LLM01",
		OWASPName:   "Prompt Injection",
		Description: "Prompt injection attempt — adversarial input designed to override system instructions or safety guardrails.",
		Remediation: remediationPromptInjection,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/77.html",
		},
	},

	// === OWASP LLM02: Insecure Output Handling (CWE 20) ===
	"owasp_llm02_insecure_output": {
		RuleID:      "owasp_llm02_insecure_output",
		CWE:         []int{20},
		OWASPLLMTop: "LLM02",
		OWASPName:   "Insecure Output Handling",
		Description: "Insecure output handling — model output may contain executable code or markup that could cause XSS or code injection.",
		Remediation: remediationInsecureOutput,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/20.html",
		},
	},

	// === OWASP LLM03: Training Data Poisoning (CWE 506) ===
	"atlas_poison": {
		RuleID:      "atlas_poison",
		CWE:         []int{506},
		OWASPLLMTop: "LLM03",
		OWASPName:   "Training Data Poisoning",
		Description: "Training data poisoning — adversarial manipulation of training data to introduce vulnerabilities or backdoors.",
		Remediation: remediationTrainingPoisoning,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/506.html",
		},
	},

	// === OWASP LLM04: Model DoS (CWE 770) ===
	"owasp_llm04_model_dos": {
		RuleID:      "owasp_llm04_model_dos",
		CWE:         []int{770},
		OWASPLLMTop: "LLM04",
		OWASPName:   "Model DoS",
		Description: "Denial-of-service attempt on model — flooding or overwhelming the system to degrade availability.",
		Remediation: remediationModelDoS,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/770.html",
		},
	},

	// === OWASP LLM05: Supply Chain (CWE 829) ===
	"owasp_llm05_supply_chain": {
		RuleID:      "owasp_llm05_supply_chain",
		CWE:         []int{829},
		OWASPLLMTop: "LLM05",
		OWASPName:   "Supply Chain",
		Description: "Supply chain risk — using untrusted or unverified models, plugins, or components.",
		Remediation: remediationSupplyChain,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/829.html",
		},
	},

	// === OWASP LLM06: Sensitive Info Disclosure (CWE 200) ===
	"owasp_llm06_sensitive_info_disclosure_system_prompt": {
		RuleID:      "owasp_llm06_sensitive_info_disclosure_system_prompt",
		CWE:         []int{200},
		OWASPLLMTop: "LLM06",
		OWASPName:   "Sensitive Info Disclosure",
		Description: "System prompt extraction attempt — adversary tries to reveal hidden instructions or configuration.",
		Remediation: remediationSensitiveInfo,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/200.html",
		},
	},
	"owasp_llm06_system_prompt_extraction_variant": {
		RuleID:      "owasp_llm06_system_prompt_extraction_variant",
		CWE:         []int{200},
		OWASPLLMTop: "LLM06",
		OWASPName:   "Sensitive Info Disclosure",
		Description: "System prompt extraction via variant phrasing — attempting to leak system instructions through indirect queries.",
		Remediation: remediationSensitiveInfo,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/200.html",
		},
	},

	// === OWASP LLM07: Insecure Plugin Design (CWE 1117) ===
	"owasp_llm07_insecure_plugin_design": {
		RuleID:      "owasp_llm07_insecure_plugin_design",
		CWE:         []int{1117},
		OWASPLLMTop: "LLM07",
		OWASPName:   "Insecure Plugin Design",
		Description: "Insecure plugin design — plugins or extensions that lack proper input validation, access control, or sandboxing.",
		Remediation: "Validate all plugin inputs and outputs. Implement strict access controls " +
			"and sandboxing for plugin execution. Require authentication and authorization for sensitive operations.",
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/1117.html",
		},
	},

	// === OWASP LLM08: Excessive Agency (CWE 250) ===
	"owasp_llm08_excessive_agency": {
		RuleID:      "owasp_llm08_excessive_agency",
		CWE:         []int{250},
		OWASPLLMTop: "LLM08",
		OWASPName:   "Excessive Agency",
		Description: "Excessive agency — AI system performs actions with unnecessary privileges or without human oversight.",
		Remediation: remediationExcessiveAgency,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/250.html",
		},
	},

	// === OWASP LLM09: Overreliance (CWE 710) ===
	"owasp_llm09_overreliance": {
		RuleID:      "owasp_llm09_overreliance",
		CWE:         []int{710},
		OWASPLLMTop: "LLM09",
		OWASPName:   "Overreliance",
		Description: "Overreliance — placing undue trust in AI outputs for critical decisions without independent verification.",
		Remediation: remediationOverreliance,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/710.html",
		},
	},
	"owasp_llm09_overreliance_misinformation_explicit": {
		RuleID:      "owasp_llm09_overreliance_misinformation_explicit",
		CWE:         []int{710},
		OWASPLLMTop: "LLM09",
		OWASPName:   "Overreliance",
		Description: "Explicit request to generate misinformation — fabrication of studies, citations, or news content.",
		Remediation: remediationOverreliance,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/710.html",
		},
	},

	// === OWASP LLM10: Model Theft (CWE 1242) ===
	"owasp_llm10_model_theft": {
		RuleID:      "owasp_llm10_model_theft",
		CWE:         []int{1242},
		OWASPLLMTop: "LLM10",
		OWASPName:   "Model Theft",
		Description: "Model extraction/theft attempt — adversary tries to extract model weights, parameters, or architecture.",
		Remediation: remediationModelTheft,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/1242.html",
		},
	},
	"owasp_llm10_model_theft_query": {
		RuleID:      "owasp_llm10_model_theft_query",
		CWE:         []int{1242},
		OWASPLLMTop: "LLM10",
		OWASPName:   "Model Theft",
		Description: "Model theft via direct query — attempting to extract model architecture or weights through conversational queries.",
		Remediation: remediationModelTheft,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/1242.html",
		},
	},
	"owasp_llm10_unbounded_consumption": {
		RuleID:      "owasp_llm10_unbounded_consumption",
		CWE:         []int{1242, 770},
		OWASPLLMTop: "LLM10",
		OWASPName:   "Model Theft",
		Description: "Resource exhaustion / unbounded consumption — attempting to exhaust API, token, or compute resources.",
		Remediation: remediationModelDoS,
		References: []string{
			"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
			"https://cwe.mitre.org/data/definitions/770.html",
		},
	},

	// === MITRE ATLAS patterns (CWE 506) ===
	"mitre_atlas_ta0001_reconnaissance": {
		RuleID:      "mitre_atlas_ta0001_reconnaissance",
		CWE:         []int{506},
		OWASPLLMTop: "LLM03",
		OWASPName:   "Training Data Poisoning",
		Description: "MITRE ATLAS TA0001: Reconnaissance of AI model weaknesses, guardrails, and safety filters.",
		Remediation: remediationATLAS,
		References: []string{
			"https://atlas.mitre.org/techniques/TA0001/",
			"https://cwe.mitre.org/data/definitions/506.html",
		},
	},
	"mitre_atlas_ta0002_resource_development": {
		RuleID:      "mitre_atlas_ta0002_resource_development",
		CWE:         []int{506},
		OWASPLLMTop: "LLM03",
		OWASPName:   "Training Data Poisoning",
		Description: "MITRE ATLAS TA0002: Building attack tools, payloads, or exploits targeting AI systems.",
		Remediation: remediationATLAS,
		References: []string{
			"https://atlas.mitre.org/techniques/TA0002/",
			"https://cwe.mitre.org/data/definitions/506.html",
		},
	},
	"mitre_atlas_ta0009_collection": {
		RuleID:      "mitre_atlas_ta0009_collection",
		CWE:         []int{506},
		OWASPLLMTop: "LLM03",
		OWASPName:   "Training Data Poisoning",
		Description: "MITRE ATLAS TA0009: Data collection and exfiltration from AI systems.",
		Remediation: remediationATLAS,
		References: []string{
			"https://atlas.mitre.org/techniques/TA0009/",
			"https://cwe.mitre.org/data/definitions/506.html",
		},
	},

	// === Atlas patterns (CWE 506 for poison, 77 for jailbreak/bypass, 200 for exfiltration) ===
	"atlas_exfiltration": {
		RuleID:      "atlas_exfiltration",
		CWE:         []int{200},
		OWASPLLMTop: "LLM06",
		OWASPName:   "Sensitive Info Disclosure",
		Description: "Data exfiltration via AI — attempting to send sensitive data to external endpoints.",
		Remediation: remediationSensitiveInfo,
		References: []string{
			"https://atlas.mitre.org/",
			"https://cwe.mitre.org/data/definitions/200.html",
		},
	},
	"atlas_jailbreak": {
		RuleID:      "atlas_jailbreak",
		CWE:         []int{77},
		OWASPLLMTop: "LLM01",
		OWASPName:   "Prompt Injection",
		Description: "Jailbreak attempt — adversarial input designed to bypass safety guidelines and restrictions.",
		Remediation: remediationPromptInjection,
		References: []string{
			"https://atlas.mitre.org/",
			"https://cwe.mitre.org/data/definitions/77.html",
		},
	},
	"atlas_safety_protocol_bypass": {
		RuleID:      "atlas_safety_protocol_bypass",
		CWE:         []int{77},
		OWASPLLMTop: "LLM01",
		OWASPName:   "Prompt Injection",
		Description: "Safety protocol bypass attempt — attempting to disable or circumvent safety measures and content filters.",
		Remediation: remediationPromptInjection,
		References: []string{
			"https://atlas.mitre.org/",
			"https://cwe.mitre.org/data/definitions/77.html",
		},
	},
	"atlas_data_exfiltration_query": {
		RuleID:      "atlas_data_exfiltration_query",
		CWE:         []int{200},
		OWASPLLMTop: "LLM06",
		OWASPName:   "Sensitive Info Disclosure",
		Description: "Direct request for sensitive system data — credentials, environment variables, or system files.",
		Remediation: remediationSensitiveInfo,
		References: []string{
			"https://atlas.mitre.org/",
			"https://cwe.mitre.org/data/definitions/200.html",
		},
	},
}

// ---------------------------------------------------------------------
// Prefix-based category matchers
// ---------------------------------------------------------------------

// prefixMatcher defines a prefix pattern and its associated metadata template.
type prefixMatcher struct {
	prefixes []string
	template RuleMetadata
}

// prefixMatchers defines category-level metadata for rules not in the
// explicit map. Rules are matched by prefix (case-insensitive).
var prefixMatchers = []prefixMatcher{
	// Prompt injection — CWE 77, LLM01
	{
		prefixes: []string{"prompt_injection_"},
		template: RuleMetadata{
			CWE:         []int{77},
			OWASPLLMTop: "LLM01",
			OWASPName:   "Prompt Injection",
			Description: "Prompt injection pattern detected — adversarial input designed to manipulate model behavior.",
			Remediation: remediationPromptInjection,
			References: []string{
				"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
				"https://cwe.mitre.org/data/definitions/77.html",
			},
		},
	},

	// Secrets — CWE 798 (Use of Hard-coded Credentials), OWASP LLM06
	{
		prefixes: []string{"secret_"},
		template: RuleMetadata{
			CWE:         []int{798},
			OWASPLLMTop: "LLM06",
			OWASPName:   "Sensitive Info Disclosure",
			Description: "Hardcoded secret or credential detected in source code or configuration.",
			Remediation: remediationSecrets,
			References: []string{
				"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
				"https://cwe.mitre.org/data/definitions/798.html",
			},
		},
	},

	// PII — CWE 200 (Information Exposure)
	{
		prefixes: []string{"pii_"},
		template: RuleMetadata{
			CWE:         []int{200},
			OWASPLLMTop: "LLM06",
			OWASPName:   "Sensitive Info Disclosure",
			Description: "Personally identifiable information (PII) detected in data.",
			Remediation: remediationPII,
			References: []string{
				"https://cwe.mitre.org/data/definitions/200.html",
			},
		},
	},

	// XSS — CWE 79 (Cross-site Scripting)
	{
		prefixes: []string{"xss_"},
		template: RuleMetadata{
			CWE:         []int{79},
			OWASPLLMTop: "LLM02",
			OWASPName:   "Insecure Output Handling",
			Description: "Cross-site scripting (XSS) vector detected in content.",
			Remediation: remediationXSS,
			References: []string{
				"https://cwe.mitre.org/data/definitions/79.html",
			},
		},
	},

	// OT protocols — CWE 20 (Improper Input Validation)
	{
		prefixes: []string{"ot_"},
		template: RuleMetadata{
			CWE:         []int{20},
			OWASPLLMTop: "",
			OWASPName:   "",
			Description: "Operational technology (OT) protocol command detected.",
			Remediation: remediationOT,
			References: []string{
				"https://cwe.mitre.org/data/definitions/20.html",
			},
		},
	},

	// Compliance — CWE 200 (Information Exposure)
	{
		prefixes: []string{
			"eu_ai_act_", "nist_", "iso_", "ccpa_", "lgpd_",
			"anp_", "cu_", "pipeda_", "popia_", "compliance_",
		},
		template: RuleMetadata{
			CWE:         []int{200},
			OWASPLLMTop: "",
			OWASPName:   "",
			Description: "Regulatory compliance reference detected — review against applicable regulations.",
			Remediation: remediationCompliance,
			References: []string{
				"https://cwe.mitre.org/data/definitions/200.html",
			},
		},
	},

	// Harmful content — CWE 1127 (Weakness in Policy Enforcement for Sensitive Operations)
	{
		prefixes: []string{"harmful_", "toxicity_"},
		template: RuleMetadata{
			CWE:         []int{1127},
			OWASPLLMTop: "",
			OWASPName:   "",
			Description: "Harmful or toxic content detected — content that violates safety policies.",
			Remediation: remediationHarmful,
			References: []string{
				"https://cwe.mitre.org/data/definitions/1127.html",
			},
		},
	},

	// MITRE ATLAS — CWE 506 (Embedded Malicious Code)
	{
		prefixes: []string{"mitre_atlas_"},
		template: RuleMetadata{
			CWE:         []int{506},
			OWASPLLMTop: "LLM03",
			OWASPName:   "Training Data Poisoning",
			Description: "MITRE ATLAS adversarial technique detected — reconnaissance, resource development, or collection activity.",
			Remediation: remediationATLAS,
			References: []string{
				"https://atlas.mitre.org/",
				"https://cwe.mitre.org/data/definitions/506.html",
			},
		},
	},

	// Dangerous URL/endpoint patterns — CWE 918 (SSRF)
	// Checked before the general dangerous_ matcher below.
	{
		prefixes: []string{"dangerous_aws_endpoint", "dangerous_gcp_endpoint"},
		template: RuleMetadata{
			CWE:         []int{918},
			OWASPLLMTop: "",
			OWASPName:   "",
			Description: "Dangerous endpoint or URL pattern detected — potential Server-Side Request Forgery (SSRF) risk.",
			Remediation: remediationDangerousCode,
			References: []string{
				"https://cwe.mitre.org/data/definitions/918.html",
			},
		},
	},

	// Dangerous base64/code patterns — CWE 94 (Code Injection)
	// Checked before the general dangerous_ matcher below.
	{
		prefixes: []string{
			"dangerous_b64_", "dangerous_base64",
		},
		template: RuleMetadata{
			CWE:         []int{94},
			OWASPLLMTop: "",
			OWASPName:   "",
			Description: "Dangerous base64-encoded code pattern detected — potential code injection via obfuscated payloads.",
			Remediation: remediationDangerousCode,
			References: []string{
				"https://cwe.mitre.org/data/definitions/94.html",
			},
		},
	},

	// Dangerous code patterns (general) — CWE 78 (OS Command Injection)
	{
		prefixes: []string{"dangerous_"},
		template: RuleMetadata{
			CWE:         []int{78},
			OWASPLLMTop: "",
			OWASPName:   "",
			Description: "Dangerous code pattern detected — unsafe API usage that may lead to OS command injection or arbitrary code execution.",
			Remediation: remediationDangerousCode,
			References: []string{
				"https://cwe.mitre.org/data/definitions/78.html",
			},
		},
	},

	// Financial crypto context — CWE 200
	{
		prefixes: []string{"fin_crypto_"},
		template: RuleMetadata{
			CWE:         []int{200},
			OWASPLLMTop: "LLM06",
			OWASPName:   "Sensitive Info Disclosure",
			Description: "Financial cryptocurrency context detected — sensitive financial data exposure risk.",
			Remediation: remediationPII,
			References: []string{
				"https://cwe.mitre.org/data/definitions/200.html",
			},
		},
	},
}

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

// GetRuleMetadata looks up metadata for a rule ID. It first checks the
// explicit metadata map, then falls back to prefix-based category
// matching. Returns a zero-value RuleMetadata (empty RuleID) if no
// match is found.
func GetRuleMetadata(ruleID string) RuleMetadata {
	// Exact match.
	if m, ok := ruleMetadataMap[ruleID]; ok {
		// Enrich with NIST/EU framework mappings from the OWASP LLM Top 10
		// cross-reference table if not already populated.
		if m.OWASPLLMTop != "" && len(m.NISTAIRMF) == 0 {
			if owasp, ok := owaspLLMMap[m.OWASPLLMTop]; ok {
				m.NISTAIRMF = owasp.NISTAIRMF
				m.NISTCSF = owasp.NISTCSF
				m.EUAIArticles = owasp.EUAIArticles
			}
		}
		return m
	}

	// Prefix-based category matching.
	lower := strings.ToLower(ruleID)
	for _, pm := range prefixMatchers {
		for _, p := range pm.prefixes {
			if strings.HasPrefix(lower, p) {
				result := pm.template
				result.RuleID = ruleID
				// Enrich with NIST/EU framework mappings.
				if result.OWASPLLMTop != "" {
					if owasp, ok := owaspLLMMap[result.OWASPLLMTop]; ok {
						result.NISTAIRMF = owasp.NISTAIRMF
						result.NISTCSF = owasp.NISTCSF
						result.EUAIArticles = owasp.EUAIArticles
					}
				}
				return result
			}
		}
	}

	// Containment check for prompt injection (handles IDs like
	// "ml_prompt_injection" that don't start with "prompt_injection_").
	if strings.Contains(lower, "prompt_injection") {
		result := prefixMatchers[0].template // prompt injection template
		result.RuleID = ruleID
		// Enrich with NIST/EU framework mappings.
		if owasp, ok := owaspLLMMap[result.OWASPLLMTop]; ok {
			result.NISTAIRMF = owasp.NISTAIRMF
			result.NISTCSF = owasp.NISTCSF
			result.EUAIArticles = owasp.EUAIArticles
		}
		return result
	}

	// SlackToken-style names (capitalized, no prefix).
	if strings.Contains(lower, "token") || strings.Contains(lower, "slack") {
		result := RuleMetadata{
			RuleID:      ruleID,
			CWE:         []int{798},
			Description: "Hardcoded token or credential detected.",
			Remediation: remediationSecrets,
			References: []string{
				"https://cwe.mitre.org/data/definitions/798.html",
			},
		}
		return result
	}

	// Default: return a valid RuleMetadata struct with the rule ID so
	// SARIF and other output formatters always have a populated entry.
	return RuleMetadata{
		RuleID:      ruleID,
		Description: "Security finding detected by AegisGate Platform.",
		Remediation: remediationDefault,
		References: []string{
			"https://aegisgatesecurity.io/docs/platform/rules/" + ruleID,
		},
	}
}

// GetRuleMetadataWithDefault looks up metadata for a rule ID, returning
// a sensible default for unknown rules that do not match any category.
// Since GetRuleMetadata now always returns a populated struct, this
// function is equivalent to GetRuleMetadata but is kept for backward
// compatibility with existing callers.
func GetRuleMetadataWithDefault(ruleID string) RuleMetadata {
	return GetRuleMetadata(ruleID)
}

// GetAllRuleMetadata returns a copy of the full explicit metadata map.
// This includes all OWASP LLM Top 10 entries and other explicitly
// mapped rules. Rules matched only by prefix are not included.
func GetAllRuleMetadata() map[string]RuleMetadata {
	result := make(map[string]RuleMetadata, len(ruleMetadataMap))
	for k, v := range ruleMetadataMap {
		result[k] = v
	}
	return result
}

// GetRemediation returns the remediation guidance text for a given
// rule ID. This is a convenience wrapper around GetRuleMetadata that
// returns only the remediation field.
func GetRemediation(ruleID string) string {
	return GetRuleMetadata(ruleID).Remediation
}

// getRemediationForCategory returns the remediation text associated
// with a detection category prefix. It searches the prefix matchers
// for a matching category and returns the template's remediation text.
// If no category matches, the default remediation text is returned.
func getRemediationForCategory(category string) string {
	lower := strings.ToLower(category)
	for _, pm := range prefixMatchers {
		for _, p := range pm.prefixes {
			if strings.HasPrefix(lower, p) {
				return pm.template.Remediation
			}
		}
	}
	// Containment fallback for prompt injection.
	if strings.Contains(lower, "prompt_injection") {
		return prefixMatchers[0].template.Remediation
	}
	return remediationDefault
}

// GetOWASPMapping returns the CWE, OWASP name, NIST AI RMF functions,
// NIST CSF 2.0 subcategories, and EU AI Act article references for a
// given OWASP LLM Top 10 identifier (e.g., "LLM01"). The ok return
// value is false if the LLM ID is not found in the mapping table.
func GetOWASPMapping(llmID string) (cwe int, name string, nistAiRmf, nistCsf, euAiArticles []string, ok bool) {
	entry, found := owaspLLMMap[llmID]
	if !found {
		return 0, "", nil, nil, nil, false
	}
	return entry.CWE, entry.Name, entry.NISTAIRMF, entry.NISTCSF, entry.EUAIArticles, true
}