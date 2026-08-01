// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ATLAS Enrichment for Incident Response
// =========================================================================
//
// atlas_enrichment.go provides automatic MTTI (Mean Time To Investigate)
// enrichment for ATLAS-matched findings. When a finding is detected by
// the compliance engine, this module enriches it with:
//   - ATLAS technique name and category
//   - Severity level (critical/high/medium/low)
//   - Recommended response actions
//   - Mapped compliance framework controls
//   - Estimated investigation priority
//
// This enrichment is used by:
//   - SIEM event dispatching (adds MITRE mapping to every alert)
//   - Incident creation (auto-populates ComplianceMappings)
//   - Dashboard alerts (shows technique + severity + response)
//
// v3.6.0 — P2 Item 10: MTTI auto-enrichment.
// =========================================================================

package incident

import (
	"fmt"
	"strings"
)

// ATLASTechniqueInfo holds enrichment data for a single ATLAS technique.
type ATLASTechniqueInfo struct {
	// ID is the ATLAS sub-technique ID (e.g., "T1535.001").
	ID string `json:"id"`
	// Technique is the parent technique ID (e.g., "T1535").
	Technique string `json:"technique"`
	// Name is the human-readable technique name.
	Name string `json:"name"`
	// Category is the ATLAS category (e.g., "PromptInjection").
	Category string `json:"category"`
	// Severity is the incident severity (critical/high/medium/low).
	Severity IncidentSeverity `json:"severity"`
	// Description is a brief description of what this technique does.
	Description string `json:"description"`
	// RecommendedResponse lists recommended response actions.
	RecommendedResponse []string `json:"recommended_response"`
	// ComplianceMappings maps this technique to compliance controls.
	ComplianceMappings []ComplianceMapping `json:"compliance_mappings"`
	// InvestigationPriority is 1-5 (1=critical, 5=low).
	InvestigationPriority int `json:"investigation_priority"`
}

// atlasTechniqueDB maps ATLAS sub-technique IDs to enrichment data.
// This is the authoritative source for MTTI auto-enrichment.
var atlasTechniqueDB = map[string]ATLASTechniqueInfo{
	// ==================== PROMPT INJECTION (T1535) ====================
	"T1535.001": {
		ID:          "T1535.001",
		Technique:   "T1535",
		Name:        "Ignore Previous Instructions",
		Category:    "PromptInjection",
		Severity:    SeverityHigh,
		Description: "Direct command to disregard system prompts",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1535", ControlName: "Prompt Injection", Relevance: "Direct instruction override detected"},
			{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling", Relevance: "Prompt injection requires containment"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Security Incident Response", Relevance: "Instruction override is a security incident"},
		},
		InvestigationPriority: 1,
	},
	"T1535.002": {
		ID:          "T1535.002",
		Technique:   "T1535",
		Name:        "Override System Boundaries",
		Category:    "PromptInjection",
		Severity:    SeverityHigh,
		Description: "Attempt to bypass role restrictions",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1535", ControlName: "Prompt Injection", Relevance: "Role boundary override detected"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Security Incident Response", Relevance: "Boundary override is a high-severity incident"},
		},
		InvestigationPriority: 1,
	},
	"T1535.003": {
		ID:          "T1535.003",
		Technique:   "T1535",
		Name:        "Prompt Injection via Role Play",
		Category:    "PromptInjection",
		Severity:    SeverityHigh,
		Description: "Role-play based prompt injection",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1535", ControlName: "Prompt Injection", Relevance: "Role-play injection detected"},
		},
		InvestigationPriority: 1,
	},
	"T1535.004": {
		ID:          "T1535.004",
		Technique:   "T1535",
		Name:        "Token Smuggling",
		Category:    "PromptInjection",
		Severity:    SeverityCritical,
		Description: "Encoded instructions to bypass filters",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1535", ControlName: "Prompt Injection", Relevance: "Token smuggling is a critical evasion technique"},
			{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling", Relevance: "Evasion technique requires immediate containment"},
		},
		InvestigationPriority: 1,
	},
	"T1535.005": {
		ID:          "T1535.005",
		Technique:   "T1535",
		Name:        "Multi-turn Prompt Injection",
		Category:    "PromptInjection",
		Severity:    SeverityCritical,
		Description: "Progressive injection across multiple turns",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1535", ControlName: "Prompt Injection", Relevance: "Multi-turn injection detected"},
			{Framework: "NIST-800-171", ControlID: "IR.1", ControlName: "Incident Response", Relevance: "Multi-turn attack requires investigation"},
		},
		InvestigationPriority: 1,
	},

	// ==================== LLM JAILBREAK (T1484) ====================
	"T1484.001": {
		ID:          "T1484.001",
		Technique:   "T1484",
		Name:        "Direct Jailbreak",
		Category:    "LLMJailbreak",
		Severity:    SeverityCritical,
		Description: "Direct attempt to break model safety constraints",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1484", ControlName: "LLM Jailbreak", Relevance: "Direct jailbreak attempt"},
			{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling", Relevance: "Jailbreak requires containment"},
		},
		InvestigationPriority: 1,
	},
	"T1484.002": {
		ID:          "T1484.002",
		Technique:   "T1484",
		Name:        "Indirect Jailbreak",
		Category:    "LLMJailbreak",
		Severity:    SeverityCritical,
		Description: "Indirect jailbreak via context manipulation",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1484", ControlName: "LLM Jailbreak", Relevance: "Indirect jailbreak detected"},
		},
		InvestigationPriority: 1,
	},
	"T1484.003": {
		ID:          "T1484.003",
		Technique:   "T1484",
		Name:        "Context Manipulation",
		Category:    "LLMJailbreak",
		Severity:    SeverityCritical,
		Description: "Manipulating context to bypass safety",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1484", ControlName: "LLM Jailbreak", Relevance: "Context manipulation detected"},
		},
		InvestigationPriority: 1,
	},
	"T1484.004": {
		ID:          "T1484.004",
		Technique:   "T1484",
		Name:        "Adversarial Suffix",
		Category:    "LLMJailbreak",
		Severity:    SeverityHigh,
		Description: "Suffix-based adversarial attack",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1484", ControlName: "LLM Jailbreak", Relevance: "Adversarial suffix attack"},
		},
		InvestigationPriority: 2,
	},
	"T1484.005": {
		ID:          "T1484.005",
		Technique:   "T1484",
		Name:        "Structured Output Manipulation",
		Category:    "LLMJailbreak",
		Severity:    SeverityCritical,
		Description: "Manipulating model via structured output",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1484", ControlName: "LLM Jailbreak", Relevance: "Structured output manipulation"},
		},
		InvestigationPriority: 1,
	},

	// ==================== PROMPT EXTRACTION (T1632) ====================
	"T1632.001": {
		ID:          "T1632.001",
		Technique:   "T1632",
		Name:        "Direct System Prompt Extraction",
		Category:    "PromptExtraction",
		Severity:    SeverityCritical,
		Description: "Direct attempt to extract system prompt",
		RecommendedResponse: []string{
			"isolate_session", "collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1632", ControlName: "Prompt Extraction", Relevance: "System prompt extraction attempt"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Security Incident Response", Relevance: "Data extraction attempt"},
		},
		InvestigationPriority: 1,
	},
	"T1632.002": {
		ID:          "T1632.002",
		Technique:   "T1632",
		Name:        "Indirect Prompt Extraction",
		Category:    "PromptExtraction",
		Severity:    SeverityCritical,
		Description: "Indirect extraction via clever prompting",
		RecommendedResponse: []string{
			"isolate_session", "collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1632", ControlName: "Prompt Extraction", Relevance: "Indirect extraction detected"},
		},
		InvestigationPriority: 1,
	},
	"T1632.003": {
		ID:          "T1632.003",
		Technique:   "T1632",
		Name:        "Translation-based Extraction",
		Category:    "PromptExtraction",
		Severity:    SeverityHigh,
		Description: "Using translation to extract prompts",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1632", ControlName: "Prompt Extraction", Relevance: "Translation-based extraction"},
		},
		InvestigationPriority: 2,
	},
	"T1632.004": {
		ID:          "T1632.004",
		Technique:   "T1632",
		Name:        "API-based Extraction",
		Category:    "PromptExtraction",
		Severity:    SeverityHigh,
		Description: "API-level system prompt leakage",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1632", ControlName: "Prompt Extraction", Relevance: "API-based extraction"},
		},
		InvestigationPriority: 2,
	},
	"T1632.005": {
		ID:          "T1632.005",
		Technique:   "T1632",
		Name:        "Context Window Extraction",
		Category:    "PromptExtraction",
		Severity:    SeverityHigh,
		Description: "Extraction via context window manipulation",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1632", ControlName: "Prompt Extraction", Relevance: "Context window extraction"},
		},
		InvestigationPriority: 2,
	},

	// ==================== DATA EXTRACTION (T1589) ====================
	"T1589.001": {
		ID:          "T1589.001",
		Technique:   "T1589",
		Name:        "PII Extraction",
		Category:    "DataExtraction",
		Severity:    SeverityHigh,
		Description: "Extracting personally identifiable information",
		RecommendedResponse: []string{
			"isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1589", ControlName: "Data Extraction", Relevance: "PII extraction attempt"},
			{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling", Relevance: "PII exposure requires containment"},
			{Framework: "ISO27001", ControlID: "A.16.1.2", ControlName: "Reporting Information Security Events", Relevance: "PII extraction is a reportable event"},
		},
		InvestigationPriority: 1,
	},
	"T1589.002": {
		ID:          "T1589.002",
		Technique:   "T1589",
		Name:        "Model Data Extraction",
		Category:    "DataExtraction",
		Severity:    SeverityCritical,
		Description: "Extracting model training data",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1589", ControlName: "Data Extraction", Relevance: "Model extraction attack"},
		},
		InvestigationPriority: 1,
	},
	"T1589.003": {
		ID:          "T1589.003",
		Technique:   "T1589",
		Name:        "Credential Extraction",
		Category:    "DataExtraction",
		Severity:    SeverityHigh,
		Description: "Extracting API keys or credentials",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1589", ControlName: "Data Extraction", Relevance: "Credential extraction attempt"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Security Incident Response", Relevance: "Credential exposure is critical"},
		},
		InvestigationPriority: 1,
	},
	"T1589.004": {
		ID:          "T1589.004",
		Technique:   "T1589",
		Name:        "Configuration Extraction",
		Category:    "DataExtraction",
		Severity:    SeverityHigh,
		Description: "Extracting system configuration",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1589", ControlName: "Data Extraction", Relevance: "Configuration extraction"},
		},
		InvestigationPriority: 2,
	},
	"T1589.005": {
		ID:          "T1589.005",
		Technique:   "T1589",
		Name:        "Training Data Inference",
		Category:    "DataExtraction",
		Severity:    SeverityHigh,
		Description: "Inferring training data membership",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1589", ControlName: "Data Extraction", Relevance: "Training data inference"},
		},
		InvestigationPriority: 2,
	},

	// ==================== INDIRECT INJECTION (T1584) ====================
	"T1584.001": {
		ID:          "T1584.001",
		Technique:   "T1584",
		Name:        "Third-Party Injection",
		Category:    "IndirectInjection",
		Severity:    SeverityCritical,
		Description: "Injection via third-party content",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1584", ControlName: "Indirect Injection", Relevance: "Third-party injection detected"},
			{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling", Relevance: "Supply chain attack requires containment"},
		},
		InvestigationPriority: 1,
	},
	"T1584.002": {
		ID:          "T1584.002",
		Technique:   "T1584",
		Name:        "Data Poisoning via Injection",
		Category:    "IndirectInjection",
		Severity:    SeverityCritical,
		Description: "Injecting via data poisoning",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1584", ControlName: "Indirect Injection", Relevance: "Data poisoning detected"},
		},
		InvestigationPriority: 1,
	},
	"T1584.003": {
		ID:          "T1584.003",
		Technique:   "T1584",
		Name:        "Retrieval-Augmented Injection",
		Category:    "IndirectInjection",
		Severity:    SeverityHigh,
		Description: "Injection via RAG retrieval",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1584", ControlName: "Indirect Injection", Relevance: "RAG injection detected"},
		},
		InvestigationPriority: 2,
	},
	"T1584.004": {
		ID:          "T1584.004",
		Technique:   "T1584",
		Name:        "Tool-Use Injection",
		Category:    "IndirectInjection",
		Severity:    SeverityHigh,
		Description: "Injection via tool/tool-use results",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1584", ControlName: "Indirect Injection", Relevance: "Tool-use injection"},
		},
		InvestigationPriority: 2,
	},
	"T1584.005": {
		ID:          "T1584.005",
		Technique:   "T1584",
		Name:        "Cross-Prompt Injection",
		Category:    "IndirectInjection",
		Severity:    SeverityHigh,
		Description: "Injection across prompt boundaries",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1584", ControlName: "Indirect Injection", Relevance: "Cross-prompt injection"},
		},
		InvestigationPriority: 2,
	},

	// ==================== VECTOR DB POISONING (T1600) ====================
	"T1600.001": {
		ID:          "T1600.001",
		Technique:   "T1600",
		Name:        "Direct Vector DB Poisoning",
		Category:    "VectorDBPoisoning",
		Severity:    SeverityCritical,
		Description: "Direct poisoning of vector database",
		RecommendedResponse: []string{
			"isolate_session", "collect_evidence", "run_compliance_check", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1600", ControlName: "Vector DB Poisoning", Relevance: "Direct poisoning attempt"},
		},
		InvestigationPriority: 1,
	},
	"T1600.002": {
		ID:          "T1600.002",
		Technique:   "T1600",
		Name:        "Indirect Vector DB Poisoning",
		Category:    "VectorDBPoisoning",
		Severity:    SeverityCritical,
		Description: "Indirect poisoning via upstream data",
		RecommendedResponse: []string{
			"isolate_session", "collect_evidence", "run_compliance_check", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1600", ControlName: "Vector DB Poisoning", Relevance: "Indirect poisoning detected"},
		},
		InvestigationPriority: 1,
	},
	"T1600.003": {
		ID:          "T1600.003",
		Technique:   "T1600",
		Name:        "Embedding Manipulation",
		Category:    "VectorDBPoisoning",
		Severity:    SeverityHigh,
		Description: "Manipulating embeddings to change retrieval",
		RecommendedResponse: []string{
			"collect_evidence", "run_compliance_check",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1600", ControlName: "Vector DB Poisoning", Relevance: "Embedding manipulation"},
		},
		InvestigationPriority: 2,
	},

	// ==================== CONTENT INJECTION (T1613) ====================
	"T1613.001": {
		ID:          "T1613.001",
		Technique:   "T1613",
		Name:        "Markdown Injection",
		Category:    "ContentInjection",
		Severity:    SeverityHigh,
		Description: "Injection via markdown rendering",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1613", ControlName: "Content Injection", Relevance: "Markdown injection detected"},
		},
		InvestigationPriority: 2,
	},
	"T1613.002": {
		ID:          "T1613.002",
		Technique:   "T1613",
		Name:        "HTML Injection",
		Category:    "ContentInjection",
		Severity:    SeverityHigh,
		Description: "Injection via HTML rendering",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1613", ControlName: "Content Injection", Relevance: "HTML injection detected"},
		},
		InvestigationPriority: 2,
	},
	"T1613.003": {
		ID:          "T1613.003",
		Technique:   "T1613",
		Name:        "Code Injection via Output",
		Category:    "ContentInjection",
		Severity:    SeverityHigh,
		Description: "Code execution via model output",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1613", ControlName: "Content Injection", Relevance: "Code injection via output"},
		},
		InvestigationPriority: 2,
	},

	// ==================== PLUGIN EXPLOITATION (T1563) ====================
	"T1563.001": {
		ID:          "T1563.001",
		Technique:   "T1563",
		Name:        "MCP Tool Exploitation",
		Category:    "PluginExploitation",
		Severity:    SeverityCritical,
		Description: "Exploiting MCP tool authorization",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1563", ControlName: "Plugin Exploitation", Relevance: "MCP tool exploitation"},
			{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling", Relevance: "Tool exploitation requires containment"},
		},
		InvestigationPriority: 1,
	},
	"T1563.002": {
		ID:          "T1563.002",
		Technique:   "T1563",
		Name:        "Plugin Permission Escalation",
		Category:    "PluginExploitation",
		Severity:    SeverityHigh,
		Description: "Escalating permissions via plugins",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1563", ControlName: "Plugin Exploitation", Relevance: "Permission escalation"},
		},
		InvestigationPriority: 2,
	},
	"T1563.003": {
		ID:          "T1563.003",
		Technique:   "T1563",
		Name:        "Malicious Plugin Registration",
		Category:    "PluginExploitation",
		Severity:    SeverityCritical,
		Description: "Registering a malicious plugin",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1563", ControlName: "Plugin Exploitation", Relevance: "Malicious plugin registration"},
		},
		InvestigationPriority: 1,
	},

	// ==================== DEFENSE EVASION (T1622) ====================
	"T1622.001": {
		ID:          "T1622.001",
		Technique:   "T1622",
		Name:        "Obfuscation",
		Category:    "DefenseEvasion",
		Severity:    SeverityHigh,
		Description: "Obfuscating attack payload to evade detection",
		RecommendedResponse: []string{
			"collect_evidence", "notify", "run_compliance_check",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1622", ControlName: "Defense Evasion", Relevance: "Payload obfuscation detected"},
		},
		InvestigationPriority: 2,
	},
	"T1622.002": {
		ID:          "T1622.002",
		Technique:   "T1622",
		Name:        "Impair Defenses",
		Category:    "DefenseEvasion",
		Severity:    SeverityHigh,
		Description: "Attempting to disable or impair security controls",
		RecommendedResponse: []string{
			"collect_evidence", "notify", "run_compliance_check",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1622", ControlName: "Defense Evasion", Relevance: "Defense impairment detected"},
		},
		InvestigationPriority: 2,
	},
	"T1622.003": {
		ID:          "T1622.003",
		Technique:   "T1622",
		Name:        "Agent Impersonation",
		Category:    "DefenseEvasion",
		Severity:    SeverityHigh,
		Description: "Impersonating an authorized agent",
		RecommendedResponse: []string{
			"isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1622", ControlName: "Defense Evasion", Relevance: "Agent impersonation detected"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Security Incident Response", Relevance: "Impersonation requires isolation"},
		},
		InvestigationPriority: 1,
	},

	// ==================== CREDENTIAL FORGERY (T1606) ====================
	"T1606.001": {
		ID:          "T1606.001",
		Technique:   "T1606",
		Name:        "API Key Forgery",
		Category:    "CredentialForgery",
		Severity:    SeverityCritical,
		Description: "Forging or injecting API keys",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1606", ControlName: "Credential Forgery", Relevance: "API key forgery detected"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Security Incident Response", Relevance: "Credential forgery is critical"},
		},
		InvestigationPriority: 1,
	},
	"T1606.002": {
		ID:          "T1606.002",
		Technique:   "T1606",
		Name:        "Token Forgery",
		Category:    "CredentialForgery",
		Severity:    SeverityCritical,
		Description: "Forging authentication tokens",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1606", ControlName: "Credential Forgery", Relevance: "Token forgery detected"},
		},
		InvestigationPriority: 1,
	},

	// ==================== MFA BYPASS (T1621) ====================
	"T1621.001": {
		ID:          "T1621.001",
		Technique:   "T1621",
		Name:        "MFA Fatigue Attack",
		Category:    "MFABypass",
		Severity:    SeverityCritical,
		Description: "MFA fatigue/push bombing attack",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1621", ControlName: "MFA Bypass", Relevance: "MFA fatigue attack detected"},
		},
		InvestigationPriority: 1,
	},
	"T1621.002": {
		ID:          "T1621.002",
		Technique:   "T1621",
		Name:        "MFA Bypass via Prompt Injection",
		Category:    "MFABypass",
		Severity:    SeverityCritical,
		Description: "Bypassing MFA via prompt injection",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1621", ControlName: "MFA Bypass", Relevance: "MFA bypass via injection"},
		},
		InvestigationPriority: 1,
	},

	// ==================== ELEVATION OF PRIVILEGE (T1548) ====================
	"T1548.001": {
		ID:          "T1548.001",
		Technique:   "T1548",
		Name:        "Privilege Escalation via Role Manipulation",
		Category:    "ElevationAbuse",
		Severity:    SeverityCritical,
		Description: "Escalating privileges via role manipulation",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1548", ControlName: "Elevation of Privilege", Relevance: "Privilege escalation detected"},
			{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling", Relevance: "Privilege escalation requires containment"},
		},
		InvestigationPriority: 1,
	},
	"T1548.002": {
		ID:          "T1548.002",
		Technique:   "T1548",
		Name:        "Capability Escalation",
		Category:    "ElevationAbuse",
		Severity:    SeverityCritical,
		Description: "Escalating capabilities beyond authorized scope",
		RecommendedResponse: []string{
			"block_agent", "isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1548", ControlName: "Elevation of Privilege", Relevance: "Capability escalation detected"},
		},
		InvestigationPriority: 1,
	},

	// ==================== INHIBIT RECOVERY (T1490) ====================
	"T1490.001": {
		ID:          "T1490.001",
		Technique:   "T1490",
		Name:        "Safety Instruction Override",
		Category:    "InhibitRecovery",
		Severity:    SeverityCritical,
		Description: "Overriding safety instructions to inhibit recovery",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1490", ControlName: "Inhibit Recovery", Relevance: "Safety override detected"},
		},
		InvestigationPriority: 1,
	},
	"T1490.002": {
		ID:          "T1490.002",
		Technique:   "T1490",
		Name:        "Backup Disabling",
		Category:    "InhibitRecovery",
		Severity:    SeverityCritical,
		Description: "Attempting to disable backup mechanisms",
		RecommendedResponse: []string{
			"block_agent", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1490", ControlName: "Inhibit Recovery", Relevance: "Backup disabling detected"},
		},
		InvestigationPriority: 1,
	},

	// ==================== DENIAL OF SERVICE (T1498) ====================
	"T1498.001": {
		ID:          "T1498.001",
		Technique:   "T1498",
		Name:        "Resource Exhaustion",
		Category:    "DenialOfService",
		Severity:    SeverityHigh,
		Description: "Exhausting resources via repeated requests",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1498", ControlName: "Denial of Service", Relevance: "Resource exhaustion detected"},
			{Framework: "SOC2", ControlID: "CC6.3", ControlName: "Security Event Monitoring", Relevance: "Rate anomaly detected"},
		},
		InvestigationPriority: 3,
	},
	"T1498.002": {
		ID:          "T1498.002",
		Technique:   "T1498",
		Name:        "Token Limit Exploitation",
		Category:    "DenialOfService",
		Severity:    SeverityHigh,
		Description: "Exploiting token limits for denial of service",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1498", ControlName: "Denial of Service", Relevance: "Token limit exploitation"},
		},
		InvestigationPriority: 3,
	},

	// ==================== ENDPOINT DENIAL (T1499) ====================
	"T1499.001": {
		ID:          "T1499.001",
		Technique:   "T1499",
		Name:        "API Endpoint Flooding",
		Category:    "EndpointDenial",
		Severity:    SeverityHigh,
		Description: "Flooding API endpoints",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1499", ControlName: "Endpoint Denial", Relevance: "API flooding detected"},
		},
		InvestigationPriority: 3,
	},
	"T1499.002": {
		ID:          "T1499.002",
		Technique:   "T1499",
		Name:        "Inference Endpoint DoS",
		Category:    "EndpointDenial",
		Severity:    SeverityHigh,
		Description: "Denial of service on inference endpoints",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1499", ControlName: "Endpoint Denial", Relevance: "Inference DoS detected"},
		},
		InvestigationPriority: 3,
	},

	// ==================== CONFIG EXFILTRATION (T1602) ====================
	"T1602.001": {
		ID:          "T1602.001",
		Technique:   "T1602",
		Name:        "System Config Extraction",
		Category:    "ConfigExfiltration",
		Severity:    SeverityCritical,
		Description: "Extracting system configuration",
		RecommendedResponse: []string{
			"isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1602", ControlName: "Config Exfiltration", Relevance: "System config extraction"},
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Security Incident Response", Relevance: "Config extraction is critical"},
		},
		InvestigationPriority: 1,
	},
	"T1602.002": {
		ID:          "T1602.002",
		Technique:   "T1602",
		Name:        "Model Config Extraction",
		Category:    "ConfigExfiltration",
		Severity:    SeverityCritical,
		Description: "Extracting model configuration parameters",
		RecommendedResponse: []string{
			"isolate_session", "collect_evidence", "escalate",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1602", ControlName: "Config Exfiltration", Relevance: "Model config extraction"},
		},
		InvestigationPriority: 1,
	},

	// ==================== RESOURCE EXHAUSTION (T1648) ====================
	"T1648.001": {
		ID:          "T1648.001",
		Technique:   "T1648",
		Name:        "Compute Resource Exhaustion",
		Category:    "ResourceExhaustion",
		Severity:    SeverityHigh,
		Description: "Exhausting compute resources",
		RecommendedResponse: []string{
			"collect_evidence", "notify",
		},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "ATLAS", ControlID: "T1648", ControlName: "Resource Exhaustion", Relevance: "Compute exhaustion detected"},
			{Framework: "SOC2", ControlID: "CC6.3", ControlName: "Security Event Monitoring", Relevance: "Resource exhaustion triggers monitoring"},
		},
		InvestigationPriority: 3,
	},
}

// EnrichATLASFinding enriches a finding with ATLAS technique info,
// recommended response, and compliance mappings. Returns the
// enrichment data and true if the technique ID was found in the
// database. Returns a zero-value struct and false if not found.
func EnrichATLASFinding(techniqueID string) (ATLASTechniqueInfo, bool) {
	info, ok := atlasTechniqueDB[techniqueID]
	return info, ok
}

// EnrichATLASFindings enriches multiple ATLAS findings (by their
// sub-technique IDs) and returns deduplicated enrichment data.
// Duplicate technique-level mappings are deduplicated.
func EnrichATLASFindings(techniqueIDs []string) []ATLASTechniqueInfo {
	seen := make(map[string]bool)
	result := make([]ATLASTechniqueInfo, 0, len(techniqueIDs))
	for _, id := range techniqueIDs {
		info, ok := atlasTechniqueDB[id]
		if !ok {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, info)
	}
	return result
}

// GetRecommendedPlaybook returns the recommended playbook ID for
// a given ATLAS technique. It uses the enrichment database to
// map technique severity and category to the appropriate playbook.
func GetRecommendedPlaybook(techniqueID string) string {
	info, ok := atlasTechniqueDB[techniqueID]
	if !ok {
		return "pb_fedramp_ir4" // default
	}
	// Map category to playbook
	switch info.Category {
	case "PromptInjection", "LLMJailbreak":
		if info.Severity == SeverityCritical {
			return "pb_atlas_prompt_injection"
		}
		return "pb_atlas_prompt_injection"
	case "DataExtraction", "PromptExtraction", "ConfigExfiltration":
		return "pb_atlas_data_extraction"
	case "IndirectInjection", "ContentInjection", "VectorDBPoisoning":
		return "pb_atlas_indirect_injection"
	case "PluginExploitation", "ElevationAbuse", "MFABypass":
		return "pb_atlas_plugin_exploitation"
	case "DefenseEvasion":
		return "pb_atlas_defense_evasion"
	case "DenialOfService", "EndpointDenial", "ResourceExhaustion":
		return "pb_atlas_resource_exhaustion"
	case "CredentialForgery", "InhibitRecovery":
		return "pb_atlas_credential_forgery"
	default:
		return "pb_fedramp_ir4"
	}
}

// GetATLASTechniqueIDs returns all ATLAS technique IDs that match
// the given category.
func GetATLASTechniqueIDs(category string) []string {
	var ids []string
	for _, info := range atlasTechniqueDB {
		if strings.EqualFold(info.Category, category) {
			ids = append(ids, info.ID)
		}
	}
	return ids
}

// AllATLASTechniqueIDs returns all known ATLAS technique IDs.
func AllATLASTechniqueIDs() []string {
	ids := make([]string, 0, len(atlasTechniqueDB))
	for id := range atlasTechniqueDB {
		ids = append(ids, id)
	}
	return ids
}

// FormatEnrichmentSummary returns a human-readable summary of
// enrichment data for a technique ID.
func FormatEnrichmentSummary(techniqueID string) string {
	info, ok := atlasTechniqueDB[techniqueID]
	if !ok {
		return fmt.Sprintf("unknown technique %s", techniqueID)
	}
	return fmt.Sprintf("%s [%s] %s — severity: %s, priority: %d, response: %s",
		info.ID, info.Category, info.Name, info.Severity,
		info.InvestigationPriority,
		strings.Join(info.RecommendedResponse, ", "))
}