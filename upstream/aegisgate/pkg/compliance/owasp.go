// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package compliance provides security compliance framework detection and analysis
package compliance

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// OwaspManager implements the FrameworkManager interface for OWASP AI Top 10
type OwaspManager struct {
	patterns []OwaspPattern
}

// OwaspFinding represents a detected OWASP LLM vulnerability
type OwaspFinding struct {
	ID          string    `json:"id"`
	Category    string    `json:"category"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Line        int       `json:"line,omitempty"`
	Match       string    `json:"match,omitempty"`
	Suggestion  string    `json:"suggestion"`
	Timestamp   time.Time `json:"timestamp"`
}

// OwaspPattern represents a detection pattern for OWASP vulnerabilities
type OwaspPattern struct {
	ID          string
	Category    string
	Name        string
	Description string
	Severity    string
	Regex       *regexp.Regexp
	Suggestion  string
}

// OwaspRisk represents an OWASP LLM risk category
type OwaspRisk struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	CommonPatterns []string `json:"common_patterns,omitempty"`
	Mitigations    []string `json:"mitigations,omitempty"`
}

// OWASP LLM Top 10 Risks
var owaspRisks = []OwaspRisk{
	{
		ID:          "LLM01",
		Name:        "Prompt Injection",
		Description: "Attackers manipulate LLM inputs to bypass safety filters or extract sensitive data",
		Severity:    "critical",
		CommonPatterns: []string{
			"Ignore previous instructions",
			"Disregard all above",
			"You are now in developer mode",
			"system override",
		},
		Mitigations: []string{
			"Implement strict input validation and sanitization",
			"Use prompt engineering with clear boundaries",
			"Deploy dedicated LLM security gateways",
			"Monitor for anomalous behavior patterns",
		},
	},
	{
		ID:          "LLM02",
		Name:        "Insecure Output Handling",
		Description: "Insufficient validation of LLM outputs leads to security vulnerabilities",
		Severity:    "high",
		CommonPatterns: []string{
			"Direct HTML rendering",
			"Unsanitized markdown",
			"Script injection in responses",
		},
		Mitigations: []string{
			"Implement output encoding and sanitization",
			"Use content security policies",
			"Validate and sanitize all LLM outputs",
			"Implement rate limiting on outputs",
		},
	},
	{
		ID:          "LLM03",
		Name:        "Training Data Poisoning",
		Description: "Manipulation of training data to introduce vulnerabilities or backdoors",
		Severity:    "high",
		CommonPatterns: []string{
			"Malicious training samples",
			"Backdoor triggers",
			"Data manipulation attacks",
		},
		Mitigations: []string{
			"Implement data provenance tracking",
			"Use differential privacy techniques",
			"Regular audits of training data",
			"Implement data validation pipelines",
		},
	},
	{
		ID:          "LLM04",
		Name:        "Model Denial of Service",
		Description: "Attackers cause resource exhaustion through excessive LLM operations",
		Severity:    "medium",
		CommonPatterns: []string{
			"Excessive context length",
			"Recursive prompt expansion",
			"Resource-intensive queries",
		},
		Mitigations: []string{
			"Implement input length limits",
			"Use rate limiting and throttling",
			"Monitor resource consumption",
			"Deploy scalable infrastructure",
		},
	},
	{
		ID:          "LLM05",
		Name:        "Supply Chain Vulnerabilities",
		Description: "Vulnerabilities in LLM supply chain components like models, data, or libraries",
		Severity:    "high",
		CommonPatterns: []string{
			"Compromised pre-trained models",
			"Vulnerable dependencies",
			"Untrusted data sources",
		},
		Mitigations: []string{
			"Verify model integrity with checksums",
			"Use trusted model repositories",
			"Scan dependencies for vulnerabilities",
			"Implement supply chain monitoring",
		},
	},
	{
		ID:          "LLM06",
		Name:        "Sensitive Information Disclosure",
		Description: "LLMs inadvertently revealing sensitive or confidential information",
		Severity:    "critical",
		CommonPatterns: []string{
			"PII exposure in responses",
			"Training data leakage",
			"Confidential data extraction",
		},
		Mitigations: []string{
			"Implement data minimization practices",
			"Use PII detection and redaction",
			"Apply differential privacy",
			"Regular security audits",
		},
	},
	{
		ID:          "LLM07",
		Name:        "Insecure Plugin Design",
		Description: "Insecure integrations and plugins that expand LLM attack surface",
		Severity:    "high",
		CommonPatterns: []string{
			"Unvalidated plugin inputs",
			"Excessive plugin permissions",
			"Command injection via plugins",
		},
		Mitigations: []string{
			"Implement plugin sandboxing",
			"Validate all plugin inputs/outputs",
			"Use least privilege principle",
			"Regular plugin security audits",
		},
	},
	{
		ID:          "LLM08",
		Name:        "Excessive Agency",
		Description: "LLMs granted excessive autonomy leading to unintended actions",
		Severity:    "medium",
		CommonPatterns: []string{
			"Unrestricted function calling",
			"Overly permissive APIs",
			"Autonomous decision making",
		},
		Mitigations: []string{
			"Implement human-in-the-loop controls",
			"Define clear autonomy boundaries",
			"Use explicit user confirmation for actions",
			"Implement audit logging",
		},
	},
	{
		ID:          "LLM09",
		Name:        "Overreliance",
		Description: "Excessive trust in LLM outputs leading to security or operational issues",
		Severity:    "medium",
		CommonPatterns: []string{
			"Blind trust in outputs",
			"Missing human oversight",
			"Uncritical adoption of suggestions",
		},
		Mitigations: []string{
			"Implement output verification",
			"Provide uncertainty indicators",
			"Train users on LLM limitations",
			"Establish review processes",
		},
	},
	{
		ID:          "LLM10",
		Name:        "Model Theft",
		Description: "Unauthorized access and exfiltration of LLM models and weights",
		Severity:    "high",
		CommonPatterns: []string{
			"Model weight extraction",
			"API-based model cloning",
			"Insider threats",
		},
		Mitigations: []string{
			"Implement access controls",
			"Use model watermarking",
			"Deploy API rate limiting",
			"Monitor for anomalous access",
		},
	},
}

// NewOwaspManager creates a new OWASP manager with compiled regex patterns
func NewOwaspManager() *OwaspManager {
	return &OwaspManager{
		patterns: GetOwaspPatterns(),
	}
}

// GetOwaspPatterns returns all OWASP detection patterns
func GetOwaspPatterns() []OwaspPattern {
	return []OwaspPattern{
		// LLM01: Prompt Injection patterns
		{
			ID:          "LLM01-001",
			Category:    "LLM01",
			Name:        "Ignore Instructions",
			Description: "Attempts to bypass instructions or safety filters",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(ignore|disregard|skip|bypass)\s+(all\s+)?(previous|prior|above|earlier|instructions?|prompts?|rules?|guidelines?|constraints?)`),
			Suggestion:  "Review prompt for instruction bypass attempts",
		},
		{
			ID:          "LLM01-002",
			Category:    "LLM01",
			Name:        "Developer Mode Override",
			Description: "Attempts to enable developer or debug mode",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(developer|debug|admin|root|sudo)\s*(mode|access|privileges?|override)`),
			Suggestion:  "Check for unauthorized mode elevation attempts",
		},
		{
			ID:          "LLM01-003",
			Category:    "LLM01",
			Name:        "System Prompt Extraction",
			Description: "Attempts to extract system prompts",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(reveal|show|display|print|output|repeat|echo)\s+(your|the|system|initial|original)\s*(prompt|instructions?|system\s*message)`),
			Suggestion:  "Review for system prompt extraction attempts",
		},
		{
			ID:          "LLM01-004",
			Category:    "LLM01",
			Name:        "DAN Attack Pattern",
			Description: "Do Anything Now attack pattern",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(DAN|do\s*anything\s*now|stay\s*in\s*character|you\s*are\s*now\s*free)`),
			Suggestion:  "Detect DAN-style jailbreak attempts",
		},
		{
			ID:          "LLM01-005",
			Category:    "LLM01",
			Name:        "Role Override",
			Description: "Attempts to override model role or persona",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(you\s*are\s*(now|no\s*longer)\s*(a|an)?\s*(evil|malicious|unrestricted|unconstrained|unethical))`),
			Suggestion:  "Check for persona hijacking attempts",
		},
		{
			ID:          "LLM01-006",
			Category:    "LLM01",
			Name:        "Instruction Leakage",
			Description: "Attempts to leak hidden instructions",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(what\s*(are|is)\s*your\s*(hidden|secret|private|internal)\s*(instructions?|prompts?|rules?))`),
			Suggestion:  "Potential instruction leakage attempt",
		},
		{
			ID:          "LLM01-007",
			Category:    "LLM01",
			Name:        "Prompt Injection via Format",
			Description: "Injection attempts through markdown, JSON, or code blocks",
			Severity:    "high",
			Regex:       regexp.MustCompile("(?i)" + strings.Repeat("`", 3) + "(?:system|assistant|user)\\s*\\n[\\s\\S]*?(?:ignore|disregard|override)"),
			Suggestion:  "Check for injection in formatted blocks",
		},
		{
			ID:          "LLM01-008",
			Category:    "LLM01",
			Name:        "Context Manipulation",
			Description: "Attempts to manipulate conversation context",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(forget|erase|reset|clear|delete)\s+(all\s+)?(previous|prior|above|conversation|context|memory|history)`),
			Suggestion:  "Context manipulation attempt detected",
		},

		// LLM02: Insecure Output Handling patterns
		{
			ID:          "LLM02-001",
			Category:    "LLM02",
			Name:        "HTML Injection",
			Description: "Potential HTML injection in LLM output",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)<\s*(script|iframe|object|embed|link|meta|style|base|form)[^>]*>`),
			Suggestion:  "Sanitize HTML output before rendering",
		},
		{
			ID:          "LLM02-002",
			Category:    "LLM02",
			Name:        "JavaScript Execution",
			Description: "Potential JavaScript injection",
			Severity:    "critical",
			Regex:       regexp.MustCompile("(?i)(javascript\\s*:|on\\s*\\w+\\s*=|" + strings.Repeat("`", 3) + "javascript)"),
			Suggestion:  "Validate and sanitize dynamic content",
		},
		{
			ID:          "LLM02-003",
			Category:    "LLM02",
			Name:        "Markdown XSS",
			Description: "Markdown-based XSS attempt",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)\[.*?\]\(\s*javascript\s*:[\s\S]*?\)`),
			Suggestion:  "Sanitize markdown links and images",
		},
		{
			ID:          "LLM02-004",
			Category:    "LLM02",
			Name:        "SQL Injection Payload",
			Description: "Generated SQL injection payload",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(UNION\s+SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|DROP\s+TABLE|DELETE\s+FROM)`),
			Suggestion:  "Review output for SQL injection payloads",
		},
		{
			ID:          "LLM02-005",
			Category:    "LLM02",
			Name:        "Command Injection",
			Description: "Generated command injection payload",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(;\s*(rm|wget|curl|bash|sh|python|perl|ruby)\s+|\|\s*(rm|wget|curl|bash|sh|python|perl|ruby)\s+)`),
			Suggestion:  "Review output for command injection payloads",
		},

		// LLM04: Model Denial of Service patterns
		{
			ID:          "LLM04-001",
			Category:    "LLM04",
			Name:        "Excessive Context",
			Description: "Request for very long context generation",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(generate|write|create|produce)\s+(a|an)?\s*(very\s+)?(long|large|extensive|huge)\s*(article|story|document|text|list|essay)`),
			Suggestion:  "Implement output length limits",
		},
		{
			ID:          "LLM04-002",
			Category:    "LLM04",
			Name:        "Recursive Expansion",
			Description: "Request that may cause recursive expansion",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(expand\s+each|for\s+each\s+.*\s+expand|recursively\s+expand|expand\s+all\s+items)`),
			Suggestion:  "Limit recursive expansion depth",
		},
		{
			ID:          "LLM04-003",
			Category:    "LLM04",
			Name:        "Repeat Loop Trigger",
			Description: "Request that may trigger infinite generation",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(keep\s+repeating|repeat\s+forever|never\s+stop|infinite\s+loop|endless\s+stream)`),
			Suggestion:  "Implement generation limits",
		},

		// LLM06: Sensitive Information Disclosure patterns
		{
			ID:          "LLM06-001",
			Category:    "LLM06",
			Name:        "PII Request",
			Description: "Request for personally identifiable information",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(social\s*security|SSN|passport\s*number|credit\s*card\s*number|bank\s*account\s*number)`),
			Suggestion:  "Implement PII filtering",
		},
		{
			ID:          "LLM06-002",
			Category:    "LLM06",
			Name:        "Credential Request",
			Description: "Request for credentials or secrets",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(password|secret|api\s*key|token|credential|auth)\s+(for|of|to)`),
			Suggestion:  "Block credential disclosure",
		},
		{
			ID:          "LLM06-003",
			Category:    "LLM06",
			Name:        "Training Data Query",
			Description: "Query attempting to extract training data",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(what\s+data\s+were\s+you\s+trained\s+on|show\s+me\s+training\s+data|reveal\s+training\s+examples)`),
			Suggestion:  "Prevent training data extraction",
		},
		{
			ID:          "LLM06-004",
			Category:    "LLM06",
			Name:        "Configuration Exposure",
			Description: "Request for system configuration details",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(show|reveal|display|list|dump)\s+(system\s+)?(config|configuration|environment|settings)`),
			Suggestion:  "Block configuration disclosure",
		},
		{
			ID:          "LLM06-005",
			Category:    "LLM06",
			Name:        "Personal Information",
			Description: "Request for personal information patterns",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(email|phone|address|home|work)\s*(address|number|contact)\s*(of|for)\s*`),
			Suggestion:  "Implement personal info protection",
		},

		// LLM07: Insecure Plugin Design patterns
		{
			ID:          "LLM07-001",
			Category:    "LLM07",
			Name:        "Plugin Parameter Injection",
			Description: "Injection attempt through plugin parameters",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(plugin|tool|function|api)\s+.*\s*(exec|eval|system|shell|command)`),
			Suggestion:  "Validate plugin inputs",
		},
		{
			ID:          "LLM07-002",
			Category:    "LLM07",
			Name:        "Unvalidated URL",
			Description: "Potentially dangerous URL in plugin call",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(url|uri|link|endpoint)\s*:\s*['"]?(file|git|ssh|ftp)://`),
			Suggestion:  "Validate URLs before plugin execution",
		},
		{
			ID:          "LLM07-003",
			Category:    "LLM07",
			Name:        "File Path Injection",
			Description: "Potential path traversal in plugin call",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(\.\.[\\/]|etc/passwd|windows/system)`),
			Suggestion:  "Sanitize file paths in plugins",
		},
		{
			ID:          "LLM07-004",
			Category:    "LLM07",
			Name:        "SQL in Plugin",
			Description: "SQL injection attempt via plugin",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)plugin.*(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP)`),
			Suggestion:  "Use parameterized queries in plugins",
		},

		// LLM08: Excessive Agency patterns
		{
			ID:          "LLM08-001",
			Category:    "LLM08",
			Name:        "Unrestricted Function Call",
			Description: "Request for unrestricted code execution",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(execute|run|eval|exec)\s*(any|all|every|arbitrary)\s*(code|command|script|function)`),
			Suggestion:  "Implement function call restrictions",
		},
		{
			ID:          "LLM08-002",
			Category:    "LLM08",
			Name:        "Autonomous Action Request",
			Description: "Request for autonomous action without confirmation",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(automatically|autonomously|without\s+asking|without\s+confirmation)\s*(execute|perform|do|take\s+action)`),
			Suggestion:  "Require human confirmation for actions",
		},
		{
			ID:          "LLM08-003",
			Category:    "LLM08",
			Name:        "Permission Grant Request",
			Description: "Request to grant elevated permissions",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(grant|give|provide|enable)\s*(full|elevated|admin|root|super)\s*(access|permission|privilege)`),
			Suggestion:  "Restrict permission modification",
		},
		{
			ID:          "LLM08-004",
			Category:    "LLM08",
			Name:        "Bulk Operation Request",
			Description: "Request for bulk operations without limits",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(process|modify|delete|update|execute)\s*(all|every|each|entire)\s*(file|record|entry|item)`),
			Suggestion:  "Implement bulk operation limits",
		},

		// LLM09: Overreliance patterns
		{
			ID:          "LLM09-001",
			Category:    "LLM09",
			Name:        "Critical Decision Request",
			Description: "Request for critical decision without verification",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(make|take)\s*(a|the|final|critical|important)\s*(decision|judgment|determination)\s*(for|on)`),
			Suggestion:  "Require human review for decisions",
		},
		{
			ID:          "LLM09-002",
			Category:    "LLM09",
			Name:        "Medical Advice Request",
			Description: "Request for medical diagnosis or treatment",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(diagnose|prescribe|treat|cure)\s*(my|this|the)\s*(condition|symptom|illness|disease)`),
			Suggestion:  "Require professional medical consultation",
		},
		{
			ID:          "LLM09-003",
			Category:    "LLM09",
			Name:        "Legal Advice Request",
			Description: "Request for legal advice or decisions",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(legal|law|attorney|lawyer)\s*(advice|opinion|recommendation|counsel)[^a-zA-Z]`),
			Suggestion:  "Require professional legal consultation",
		},
		{
			ID:          "LLM09-004",
			Category:    "LLM09",
			Name:        "Financial Decision Request",
			Description: "Request for financial decisions",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(invest|trade|buy|sell)\s*(stocks?|shares?|crypto|securities|bonds?)\s*(for|instead\s+of)`),
			Suggestion:  "Require financial advisor consultation",
		},

		// LLM10: Model Theft patterns
		{
			ID:          "LLM10-001",
			Category:    "LLM10",
			Name:        "Model Weight Extraction",
			Description: "Attempt to extract model weights or architecture",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(extract|retrieve|download|copy|steal|export)\s*(model\s+)?(weights?|parameters?|architecture|layers?)`),
			Suggestion:  "Monitor for model extraction attempts",
		},
		{
			ID:          "LLM10-002",
			Category:    "LLM10",
			Name:        "Model Cloning Request",
			Description: "Attempt to clone or replicate model",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(clone|replicate|recreate|duplicate|mirror)\s*(this|the|your)\s*(model|llm|gpt|ai)`),
			Suggestion:  "Detect model cloning attempts",
		},
		{
			ID:          "LLM10-003",
			Category:    "LLM10",
			Name:        "API Abuse Pattern",
			Description: "Pattern suggesting API-based model extraction",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(enumerate|probe|reverse\s*engineer|inspect)\s*(model|architecture|parameters?)`),
			Suggestion:  "Implement API usage monitoring",
		},
		{
			ID:          "LLM10-004",
			Category:    "LLM10",
			Name:        "Excessive Querying",
			Description: "Pattern suggesting systematic querying",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(query|request|call)\s*(all|every|each|complete)\s*(responses?|outputs?|behaviors?)`),
			Suggestion:  "Rate limit suspicious query patterns",
		},

		// Additional LLM01 patterns
		{
			ID:          "LLM01-009",
			Category:    "LLM01",
			Name:        "Multi-step Instruction Override",
			Description: "Complex multi-step prompt injection attempt",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(step\s*\d+|first|then|finally)\s*:\s*(ignore|disregard|override|bypass)`),
			Suggestion:  "Multi-step injection detected",
		},
		{
			ID:          "LLM01-010",
			Category:    "LLM01",
			Name:        "Base64 Encoded Injection",
			Description: "Base64 encoded prompt injection attempt",
			Severity:    "high",
			Regex:       regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}(?:.*(?:ignore|exec|eval|system|admin))`),
			Suggestion:  "Decode and check for hidden injection",
		},

		// Additional LLM06 patterns
		{
			ID:          "LLM06-006",
			Category:    "LLM06",
			Name:        "Database Dump Request",
			Description: "Request for database content",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(dump|export|download|extract)\s*(the\s+)?(database|db|all\s+records|entire\s+table)`),
			Suggestion:  "Block database extraction attempts",
		},
		{
			ID:          "LLM06-007",
			Category:    "LLM06",
			Name:        "Source Code Request",
			Description: "Request for proprietary source code",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(show|display|reveal|give|provide)\s*(me\s+)?(the\s+)?(source\s+code|proprietary\s+code|internal\s+code)`),
			Suggestion:  "Protect proprietary code access",
		},

		// Additional LLM07 patterns
		{
			ID:          "LLM07-005",
			Category:    "LLM07",
			Name:        "Dangerous Function Call",
			Description: "Request to call dangerous functions",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(eval|exec|system|shell|popen|spawn)\s*\([^)]*\)`),
			Suggestion:  "Block dangerous function calls",
		},
		{
			ID:          "LLM07-006",
			Category:    "LLM07",
			Name:        "Network Request in Plugin",
			Description: "Plugin making unexpected network requests",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(http|https|ftp)://[^\s]*\.(exe|dll|sh|bat|cmd|ps1)`),
			Suggestion:  "Block malicious download attempts",
		},

		// Additional LLM08 patterns
		{
			ID:          "LLM08-005",
			Category:    "LLM08",
			Name:        "Self-Modification Pattern",
			Description: "Request for model to modify itself",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(modify|change|alter|update|rewrite)\s*(your|the)\s*(own|internal|core|system)\s*(code|rules|behavior|configuration)`),
			Suggestion:  "Prevent self-modification attempts",
		},
		{
			ID:          "LLM08-006",
			Category:    "LLM08",
			Name:        "Privilege Escalation",
			Description: "Request for elevated privileges",
			Severity:    "critical",
			Regex:       regexp.MustCompile(`(?i)(sudo|su\s+-|runas|elevate|escalate)\s*(privileges?|permissions?|access|rights?)`),
			Suggestion:  "Block privilege escalation",
		},

		// LLM03: Training Data Poisoning indicators
		{
			ID:          "LLM03-001",
			Category:    "LLM03",
			Name:        "Backdoor Trigger Detection",
			Description: "Potential backdoor trigger phrase",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(activate|trigger|enable)\s*(backdoor|trojan|hidden\s*mode|special\s*mode)`),
			Suggestion:  "Scan for backdoor triggers",
		},
		{
			ID:          "LLM03-002",
			Category:    "LLM03",
			Name:        "Data Poisoning Pattern",
			Description: "Pattern suggesting poisoned training data",
			Severity:    "high",
			Regex:       regexp.MustCompile(`(?i)(inject|poison|corrupt|manipulate)\s*(training|train|dataset|data)`),
			Suggestion:  "Validate training data integrity",
		},

		// LLM05: Supply Chain patterns
		{
			ID:          "LLM05-001",
			Category:    "LLM05",
			Name:        "Untrusted Model Source",
			Description: "Reference to untrusted model sources",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(download|load|import)\s*(model|weights?)\s*(from|huggingface|github|url|http)`),
			Suggestion:  "Verify model source integrity",
		},
		{
			ID:          "LLM05-002",
			Category:    "LLM05",
			Name:        "Dependency Vulnerability",
			Description: "Reference to potentially vulnerable dependencies",
			Severity:    "medium",
			Regex:       regexp.MustCompile(`(?i)(transformers|torch|tensorflow|keras)\s*==\s*[0-9]+\.[0-9]+\.[0-9]+`),
			Suggestion:  "Verify dependency versions",
		},
	}
}

// CheckRequest analyzes a text request for OWASP LLM vulnerabilities
func (m *OwaspManager) CheckRequest(ctx context.Context, request string) ([]OwaspFinding, error) {
	var findings []OwaspFinding

	for _, pattern := range m.patterns {
		if pattern.Regex == nil {
			continue
		}

		matches := pattern.Regex.FindAllStringIndex(request, -1)
		if len(matches) > 0 {
			for _, match := range matches {
				findings = append(findings, OwaspFinding{
					ID:          pattern.ID,
					Category:    pattern.Category,
					Title:       pattern.Name,
					Description: pattern.Description,
					Severity:    pattern.Severity,
					Line:        1, // Simplified for single-line request
					Match:       request[match[0]:min(match[1], len(request))],
					Suggestion:  pattern.Suggestion,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return findings, nil
}

// CheckResponse analyzes an LLM response for security issues
func (m *OwaspManager) CheckResponse(ctx context.Context, response string) ([]OwaspFinding, error) {
	var findings []OwaspFinding

	// Focus on output-related vulnerabilities (LLM02 primarily)
	for _, pattern := range m.patterns {
		// Only check output-relevant patterns
		if pattern.Category != "LLM02" && pattern.Category != "LLM06" && pattern.Category != "LLM07" {
			continue
		}

		if pattern.Regex == nil {
			continue
		}

		matches := pattern.Regex.FindAllStringIndex(response, -1)
		for _, match := range matches {
			findings = append(findings, OwaspFinding{
				ID:          pattern.ID,
				Category:    pattern.Category,
				Title:       pattern.Name,
				Description: pattern.Description,
				Severity:    pattern.Severity,
				Line:        countLines(response[:match[0]]),
				Match:       response[match[0]:min(match[1], len(response))],
				Suggestion:  pattern.Suggestion,
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

// CheckHTTP analyzes HTTP traffic for OWASP LLM vulnerabilities
func (m *OwaspManager) CheckHTTP(ctx context.Context, method, path string, headers map[string]string, body string) ([]OwaspFinding, error) {
	var findings []OwaspFinding

	// Check request body
	if body != "" {
		bodyFindings, _ := m.CheckRequest(ctx, body)
		findings = append(findings, bodyFindings...)
	}

	// Check headers for suspicious patterns
	for key, value := range headers {
		headerFindings, _ := m.CheckRequest(ctx, key+": "+value)
		findings = append(findings, headerFindings...)
	}

	return findings, nil
}

// GetRiskByID returns an OWASP risk by its ID
func GetRiskByID(id string) *OwaspRisk {
	for i := range owaspRisks {
		if owaspRisks[i].ID == id {
			return &owaspRisks[i]
		}
	}
	return nil
}

// GetRisksBySeverity returns all risks of a given severity
func GetRisksBySeverity(severity string) []OwaspRisk {
	var results []OwaspRisk
	for i := range owaspRisks {
		if owaspRisks[i].Severity == severity {
			results = append(results, owaspRisks[i])
		}
	}
	return results
}

// GetAllRisks returns all OWASP LLM risks
func GetAllRisks() []OwaspRisk {
	return owaspRisks
}

// Helper functions

func countLines(s string) int {
	return strings.Count(s, "\n") + 1
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetName returns the framework name
func (m *OwaspManager) GetName() string {
	return "OWASP AI Top 10"
}

// GetVersion returns the framework version
func (m *OwaspManager) GetVersion() string {
	return "2023"
}

// GetDescription returns the framework description
func (m *OwaspManager) GetDescription() string {
	return "OWASP Top 10 for LLM Applications - Security risks specific to large language models"
}
