// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package compliance provides MITRE ATLAS framework implementation
// MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
package compliance

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ATLASFramework implements MITRE ATLAS compliance checking
type ATLASFramework struct {
	mu           sync.RWMutex
	patterns     []*Pattern
	contextLines int
}

// NewATLASFramework creates a new ATLAS framework checker
func NewATLASFramework(contextLines int) *ATLASFramework {
	if contextLines < 0 {
		contextLines = 0
	}

	f := &ATLASFramework{
		contextLines: contextLines,
		patterns:     make([]*Pattern, 0),
	}

	f.initPatterns()
	return f
}

// initPatterns initializes all ATLAS patterns
func (f *ATLASFramework) initPatterns() {
	// ==================== PROMPT INJECTION (T1535) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1535.001",
		Technique:   "T1535",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "PromptInjection",
		Description: "Ignore Previous Instructions - Direct command to disregard system prompts",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(ignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions?|directives?|rules?|prompts?)|disregard\s+(all\s+)?(system\s+)?(instructions?|rules?)|forget\s+(everything|all)\s+(you|i)\s+(know|were\s+told)|discard\s+(all\s+)?(previous|prior|system)\s+(instructions?|rules?)|new\s+instructions?\s*:\s*ignore|override\s+(your\s+)?(system\s+)?(instructions?|rules?))`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1535.002",
		Technique:   "T1535",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "PromptInjection",
		Description: "Override System Boundaries - Attempt to bypass role restrictions",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(you\s+(are\s+)?(no\s+longer|now|just)\s+(a\s+)?(language\s+model|AI|assistant)|act\s+as\s+(if|like)\s+(you|an?)\s+(can|could|are)|pretend\s+(to\s+be|you\s+are)|bypass\s+(your\s+)?(restrictions?|limitations?)|ignore\s+(your\s+)?(limitations?|restrictions?)|your\s+(only|single)\s+(purpose|function|task))`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1535.003",
		Technique:   "T1535",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "PromptInjection",
		Description: "Prompt Injection via Role Play",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(role\s*play|act\s+(as|like)|play\s+the\s+role\s+of|simulate\s+(being|an?)|you\s+are\s+(now\s+)?(a|one)|imagine\s+(you|i)\s+(are|were)|let's\s+play\s+(a|an)|as\s+(an?|a)\s+(fictional|hypothetical)|character\s+mode|scenario\s+mode)`),
	})

	// Token Smuggling - encode instructions to bypass filters
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1535.004",
		Technique:   "T1535",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "PromptInjection",
		Description: "Token Smuggling - Attempt to obfuscate instructions via encoding",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(token\s+smuggling|fragment\s+instruction|split\s+prompt|obfuscat\w+\s+instruction|encode\w*\s+command|base64\s+instruction|hex\s+instruction|unicode\s+instruction|embed\w*\s+secret|hidden\s+instruction|stealth\s+mode|encoded\s+payload|decod\w+\s+this|\[INST\]|\[/INST\])`),
	})

	// Base64 Encoded Injection
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1535.005",
		Technique:   "T1535",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "PromptInjection",
		Description: "Base64 Encoded Injection - Hidden commands via encoding",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(decode\s*:\s*|decod\w+\s+this|here\s+is\s+(the\s+)?(hidden|secret)\s+(code|message)|decod\w+\s+(and|then)\s+execut\w+|base64)`),
	})

	// ==================== LLM JAILBREAK (T1484) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1484.001",
		Technique:   "T1484",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "LLMJailbreak",
		Description: "Hypothetical Scenario Jailbreak",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(what\s+if|hypothetical\w+|imagine\s+(that|if)|suppose|let's\s+say|for\s+(argument|discussion)\s+sake|just\s+(pretend|assume)|as\s+a\s+(thought|scenario)|in\s+a\s+(fictional|hypothetical)|fictional\s+scenario|harmless\s+example)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1484.002",
		Technique:   "T1484",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "LLMJailbreak",
		Description: "Roleplay Jailbreak",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(roleplay|role[- ]play|play\s+(as|the\s+role\s+of)|act\s+(as|like)|you\s+are\s+(a\s+)?(character|person|being)|be\s+(a|an)\s+(evil|bad|unethical)|jailbreak|dAN|\bDAN\b|developer\s+mode|developer\s+menu)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1484.003",
		Technique:   "T1484",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "LLMJailbreak",
		Description: "Authority Impersonation",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(as\s+(an?|the)\s+(admin|owner|developer|creator|master)|i\s+am\s+(the\s+)?(admin|owner|developer)|you\s+(must|have\s+to)\s+obey|i\s+authoriz\w+|special\s+access|override\s+all|system\s+override|bypass\s+all\s+rules|unrestricted\s+mode)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1484.004",
		Technique:   "T1484",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "LLMJailbreak",
		Description: "Distraction via Technical Jargon",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(unfiltered|training\s+data|ml\s+optimization|optimization|for\s+(ml| machine\s+learning)|research\s+purpose|academic\s+study|educational\s+context|safety\s+research|red\s+team|penetration\s+test|security\s+audit|benchmark\s+test)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1484.005",
		Technique:   "T1484",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "LLMJailbreak",
		Description: "Self-Modification Request",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(modif\w+\s+(your|yourself|self)|change?\s+your\s+(system|prompt|instruction|behavior|programming|safety)|update\s+yourself|alter\s+your\s+(core|base|safety)|self[- ]improv\w+|learn\s+from\s+this|adapt\s+your\s+(rules|guidelines|safety)|revise\s+your\s+(parameters|directives|safety))`),
	})

	// ==================== SYSTEM PROMPT EXTRACTION (T1632) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1632.001",
		Technique:   "T1632",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "PromptExtraction",
		Description: "Direct Prompt Extraction",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(repeat\s+(your|me|all)\s+(system\s+)?(prompt|instructions?|directives?)|show\s+me\s+(your\s+)?(system\s+)?(prompt|instructions?)|tell\s+me\s+(your|all)\s+(instructions?|rules?)|what\s+(were|are)\s+you\s+(told|programmed)|reveal\s+your\s+(system\s+)?(prompt|instructions?)|output\s+your\s+(system\s+)?(prompt|instructions?)|print\s+your\s+(system\s+)?(prompt|instructions?)|your\s+full\s+system\s+prompt)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1632.002",
		Technique:   "T1632",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "PromptExtraction",
		Description: "Injection for Extraction",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(what\s+are\s+your\s+instructions|output\s+in\s*<|print\s+in\s*<|list\s+your\s+(system\s+)?(rules?|instructions?)|dump\s+your\s+(system\s+)?(prompt|instructions?)|export\s+your\s+(system\s+)?(prompt|instructions?)|extract\s+your\s+(system\s+)?(prompt|instructions?))`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1632.003",
		Technique:   "T1632",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "PromptExtraction",
		Description: "Distillation Attack",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(distill\w+|model\s+distillation|knowledge\s+extraction|prompt\s+extraction|distill\s+the\s+(prompt|instructions)|train\s+(a|an)\s+(new|fine-tun\w+)\s+model|clone\s+your\s+(behavior|responses)|replicate\s+your\s+(capabilities|functions)|decision[- ]making|explain\s+your\s+(reasoning|logic|decision|rules))`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1632.004",
		Technique:   "T1632",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "PromptExtraction",
		Description: "Version Rollback Request",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(rollback|roll\s+back|use\s+(an\s+)?(older|previous|earlier)\s+version|switch\s+to\s+(an\s+)?(older|previous)|revert\s+to\s+(an\s+)?(older|previous)|downgrad\w+|previous\s+(model|version)|older\s+(model|version))`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1632.005",
		Technique:   "T1632",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "PromptExtraction",
		Description: "Encoding Obfuscation",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(print\s+(\\\\x[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|hex|encode\w*|decode\w*|base64|unicode|utf-8|rot13|cipher\w*|encrypt\w*|decrypt\w*|obfuscate\w*|encoded\s+message|hidden\s+text|secret\s+code|in\s+(binary|hex|base64))|\\\\x[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2})`),
	})

	// ==================== TRAINING DATA EXPOSURE (T1589) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1589.001",
		Technique:   "T1589",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "DataExtraction",
		Description: "Direct Data Extraction",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(training\s+data|tell\s+me\s+about\s+(your\s+)?training|personal\s+information.*training|train\w*\s+on\s+(what|which)|training\s+data\s+(contains?|includes?)|where\s+did\s+you\s+learn|sources\s+for\s+(your|training)|what\s+(was|were)\s+(you|train))`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1589.002",
		Technique:   "T1589",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "DataExtraction",
		Description: "Membership Inference Attack",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(membership\s+inference|was\s+(this|that)\s+(in|trained)|do\s+you\s+know\s+(if|whether).*(training|remember)|did\s+you\s+see\s+(this|that)|remember\s+(this|that)|have\s+you\s+(seen|encountered).*(before|training)|training\s+on\s+(this|that))`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1589.003",
		Technique:   "T1589",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "DataExtraction",
		Description: "Model Extraction Query",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(model\s+extraction|extract\s+the\s+model|clone\s+this\s+model|replicat\w+\s+your\s+(model|weights)|steal\s+the\s+model|download\s+your\s+(model|weights)|reverse\s+engineer\s+(you|your)|reconstruct\s+(your|model))`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1589.004",
		Technique:   "T1589",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "DataExtraction",
		Description: "Training Data Reconstruction",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(reconstruct\w*\s+training|data\s+reconstruction|recover\s+training\s+data|extract\s+training\s+examples|find\s+in\s+training|memoriz\w+\s+training|leak\w*\s+training\s+data|exfiltrat\w*\s+training|complete:\s*|finish\s+this:\s*|complete\s+(the\s+)?(sentence|phrase|API\s+key|password|secret))`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1589.005",
		Technique:   "T1589",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "DataExtraction",
		Description: "Copyright Extraction",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(copyright\w*|licensed\s+content|proprietary|trade\s+secret|confidential\s+training|owned\s+by|protected\s+by\s+copyright|all\s+rights\s+reserved|infring\w*|plagiarism)`),
	})

	// ==================== INDIRECT PROMPT INJECTION (T1584) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1584.001",
		Technique:   "T1584",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "IndirectInjection",
		Description: "Instruction Injection via Context",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(remember\s+to|remember\s+that|ignore\s+safety|output\s*:\s*\[|ignore\s+above|disregard\s+previous|new\s+instruction|from\s+now\s+on|note\s+that|important\s*:|priority\s*:|rule\s*:|system\s*:|admin\s*:|system\s+message|hidden\s+message|invisible\s+text|zero-width|translate.*remember)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1584.002",
		Technique:   "T1584",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "IndirectInjection",
		Description: "Data Poisoning via Input",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(poison\w+|data\s+poisoning|contaminat\w+|corrupt\w*\s+(training|data)|inject\w*\s+(malicious|poisoned|bad)\s+(data|content)|adversarial\s+(input|data)|trigger\s+word|trigger\s+phrase|activation\s+phrase|my\s+name\s+is\s+Ignore|Hello\s+IgnoreSafetyGuidelines|secrets\s+please)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1584.003",
		Technique:   "T1584",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "IndirectInjection",
		Description: "Third-Party Source Injection",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(third[- ]party|external\s+source|linked\s+content|retrieved\s+from|fetched\s+from|imported\s+from|included\s+from|attached\s+document|referenced\s+file|URL\s+parameter|query\s+string)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1584.004",
		Technique:   "T1584",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "IndirectInjection",
		Description: "Chain-of-Thought Manipulation",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(chain\s+of\s+thought|think\s+step\s+by\s+step|reasoning\s+chain|step[- ]by[- ]step|logical\s+reasoning|show\s+your\s+(thinking|work)|explain\s+your\s+(reasoning|logic)|walk\s+through)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1584.005",
		Technique:   "T1584",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "IndirectInjection",
		Description: "Tool Instruction Injection",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(use\s+the\s+(following|this)\s+tool|function\s+call|API\s+call|execute\s+this|run\s+this|invoke\s+this|trigger\s+function|call\s+function|tool\s+usage|plugin\s+instruction)`),
	})

	// ==================== VECTOR DB POISONING (T1600) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1600.001",
		Technique:   "T1600",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "VectorDBPoisoning",
		Description: "Vector DB Poisoning Attempt",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(vector\s+database|vector\s+store|embedding\s+database|vector\s+search|similarity\s+search|retrieval\s+augmented|RAG|rag\s+system|knowledge\s+base|vector\s+index)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1600.002",
		Technique:   "T1600",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "VectorDBPoisoning",
		Description: "RAG Context Poisoning",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(RAG\s+context|retrieve\w*\s+context|context\s+injection|poison\w*\s+context|manipulate\s+context|inject\s+into\s+(context|retrieval)|fake\s+document|fabricated\s+reference|falsified\s+information|false\s+context)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1600.003",
		Technique:   "T1600",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "VectorDBPoisoning",
		Description: "Knowledge Base Corruption",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(knowledge\s+base\s+corrupt|poison\w*\s+knowledge|manipulate\s+knowledge|update\s+knowledge|add\s+to\s+(knowledge|vector)|inject\s+into\s+knowledge|contaminat\w*\s+knowledge|false\s+fact\s+injection)`),
	})

	// ==================== CONTENT INJECTION (T1613) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1613.001",
		Technique:   "T1613",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "ContentInjection",
		Description: "Response Manipulation",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(actually,\s*|in\s+reality|the\s+truth\s+is|correct\s+answer\s+is|right\s+answer\s+is|real\s+answer\s+is|true\s+answer\s+is|\[injected\]|manipulate\s+response|modify\s+response|alter\s+response|change\s+your\s+output|fake\s+response|falsified\s+output)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1613.002",
		Technique:   "T1613",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "ContentInjection",
		Description: "Output Formatting Injection",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(output\s*:\s*|format\s+injection|output\s+format|control\s+format|manipulate\s+format|inject\s+format|special\s+format|hidden\s+format|obfuscated\s+output|unicode\s+formatting|<-|secret\s*_?\s*data)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1613.003",
		Technique:   "T1613",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "ContentInjection",
		Description: "Bias Injection",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(bias\s+injection|inject\s+bias|introduce\s+bias|add\s+bias|manipulate\s+bias|biased\s+information|one[- ]sided|partial\s+information|prejudic\w+|discriminat\w+|all\s+(people|men|women)\s+from|untrustworthy|criminal|illegal)`),
	})

	// ==================== LLM PLUGIN EXPLOITATION (T1563) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1563.001",
		Technique:   "T1563",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "PluginExploitation",
		Description: "Plugin Command Injection",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(execute\s*:\s*|plugin\s+(to|command)|execute\s+plugin|call\s+plugin|run\s+plugin|invoke\s+plugin|plugin\s+injection|malicious\s+plugin|fake\s+plugin|unauthorized\s+plugin|exploit\s+plugin|rm\s+-rf)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1563.002",
		Technique:   "T1563",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "PluginExploitation",
		Description: "Journal Manipulation",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(modify\s+journal|alter\s+journal|journal\s+manipulation|log\s+manipulation|inject\s+log|fake\s+log|hidden\s+log|delete\s+log|clear\s+log|grant\s+admin\s+access)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1563.003",
		Technique:   "T1563",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "PluginExploitation",
		Description: "Privilege Escalation via Plugin",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(privilege\s+escalation|escalate\s+privileg\w+|elevate\s+privileg\w+|gain\s+(admin|root|elevated)\s+access|privilege\s+bypass|admin\s+privileg\w+|sudo|root\s+access|superuser|elevated\s+permissions|install\s+plugin.*elevated)`),
	})

	// ==================== DEFENSE EVASION (T1622) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1622.001",
		Technique:   "T1622",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "DefenseEvasion",
		Description: "Defense Evasion via Tokenization",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(bypass\s+(filter|detection|security)|token\w*\s+(evasion|bypass|split)|obfuscate\w*\s+(word|filter)|t-o-k-e-n-i-z-e-d|encode\w*\s+word|split\s+word|character\s+insertion)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1622.002",
		Technique:   "T1622",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "DefenseEvasion",
		Description: "Defense Evasion via Fragmentation",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(fragment\w*\s+attack|split\s+payload|chunk\w*\s+injection|divide\s+and\s+conquer|b\s*y\s*p\s*a\s*s\s*s)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1622.003",
		Technique:   "T1622",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "DefenseEvasion",
		Description: "Defense Evasion via Translation",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(translation\s+attack|translate\w*\s+bypass|multiple\s+language|translate\s+instruction|other\s+language|non-english|in\s+spanish|in\s+french|in\s+german|foreign\s+language)`),
	})

	// ==================== FORGE WEB CREDENTIALS (T1606) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1606.001",
		Technique:   "T1606",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "CredentialForgery",
		Description: "Credential Forgery Request",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(forge\w*\s+credential|create\s+fake\s+(token|credential)|generate\s+(fake|falsified)\s+(token|credential)|fake\s+session|fabricated\s+token|forged\s+token|bypass\s+authentication|authentication\s+bypass)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1606.002",
		Technique:   "T1606",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "CredentialForgery",
		Description: "Session Token Generation",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(session\s+token|create\s+(valid\s+)?(session|token)|generate\s+session|forge\s+session|session\s+(hijacking|stealing|prediction)|token\s+(prediction|forgery|generation))`),
	})

	// ==================== MFA REQUEST GENERATION (T1621) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1621.001",
		Technique:   "T1621",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "MFABypass",
		Description: "MFA Code Generation Request",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(mfa\s+code|2fa\s+code|one[- ]time\s+password|otp\s+code|verification\s+code|authenticator\s+code|sms\s+code|email\s+code|two[- ]factor\s+code|security\s+code)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1621.002",
		Technique:   "T1621",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "MFABypass",
		Description: "OTP Bypass Request",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(bypass\s+mfa|bypass\s+2fa|disable\s+mfa|disable\s+2fa|skip\s+mfa|skip\s+2fa|bypass\s+verification|mfa\s+bypass|2fa\s+bypass|otp\s+bypass|resend\s+code|bypass\s+authentication)`),
	})

	// ==================== ABUSE ELEVATION (T1548) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1548.001",
		Technique:   "T1548",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "ElevationAbuse",
		Description: "Elevation Control Bypass",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(bypass\s+UAC|bypass\s+(elevation|privilege|authorization)|elevate\s+(without|skip)|escalat\w+\s+without|privilege\s+bypass|permission\s+bypass|authorization\s+bypass|gain\s+elevated|gain\s+admin|gain\s+root|run\s+as\s+administrator|administrator)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1548.002",
		Technique:   "T1548",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "ElevationAbuse",
		Description: "Privilege Escalation Request",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(privilege\s+escalation|escalate\s+(current\s+)?(session\s+)?to\s+root|elevate\s+privileg\w+|gain\s+privileg\w+|admin\s+mode|root\s+mode|god\s+mode|supreme\s+access|unrestricted\s+access|escalate\s+to\s+root|root\s+privileg)`),
	})

	// ==================== INHIBIT RECOVERY (T1490) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1490.001",
		Technique:   "T1490",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "InhibitRecovery",
		Description: "Disable Recovery Mode",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(disable\s+recovery|disable\s+backup|turn\s+off\s+recovery|disable\s+restore|remove\s+recovery|delete\s+backup|clear\s+backup|prevent\s+recovery|block\s+recovery)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1490.002",
		Technique:   "T1490",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "InhibitRecovery",
		Description: "Delete Recovery Partition",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(delete\s+recovery|delete\s+partition|remove\s+recovery|wipe\s+recovery|format\s+recovery|destroy\s+recovery|eliminate\s+recovery|recovery\s+partition|system\s+recovery)`),
	})

	// ==================== NETWORK DOS (T1498) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1498.001",
		Technique:   "T1498",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "DenialOfService",
		Description: "DoS Attack Request",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(denial\s+of\s+service|dos\s+attack|ddos|distributed\s+denial|overload\s+system|flood\s+server|resource\s+exhaustion|create\s+infinite|endless\s+loop|infinite\s+loop)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1498.002",
		Technique:   "T1498",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "DenialOfService",
		Description: "Service Disruption",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(disrupt\s+service|stop\s+service|disable\s+service|break\s+service| crash\s+system|hang\s+system|freeze\s+system|unresponsive\s+system|kill\s+process|terminate\s+process)`),
	})

	// ==================== ENDPOINT DOS (T1499) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1499.001",
		Technique:   "T1499",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "EndpointDenial",
		Description: "Endpoint Crash Request",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(crash\s+(your|this|the)\s+(system|endpoint|server)|force\s+crash|trigger\s+crash|crash\s+me|crash\s+now|cause\s+crash|bootstrap\s+crash|kill\s+your|terminate\s+your)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1499.002",
		Technique:   "T1499",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "EndpointDenial",
		Description: "Service Exhaustion",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(exhaust\s+(all\s+)?(available\s+)?(connections|resources)|consume\s+all\s+(resources|memory|cpu)|memory\s+exhaustion|resource\s+starvation|max\s+out\s+(memory|cpu)|allocate\s+infinite|infinite\s+memory|memory\s+leak|connection\s+limit|too\s+many\s+connections)`),
	})

	// ==================== CONFIG REPO EXFILTRATION (T1602) ====================
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1602.001",
		Technique:   "T1602",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "ConfigExfiltration",
		Description: "Config Repository Access",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(config\s+repository|config\s+repo|configuration\s+repo|\.env\s+file|config\s+file|configuration\s+file|settings\s+file|config\s+directory|secrets\s+file|credentials\s+file)`),
	})

	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1602.002",
		Technique:   "T1602",
		Framework:   FrameworkATLAS,
		Severity:    SeverityCritical,
		Category:    "ConfigExfiltration",
		Description: "Environment Variables Exfiltration",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(environment\s+variables|env\s+variables|\$ENV|\$\{.*\}|getenv\w*|os\.environ|process\.env|export\s+vars|printenv|listenv|read\s+env|env\s+file)`),
	})

	// ==================== ADDITIONAL PATTERNS ====================
	// Resource exhaustion via excessive tokens
	f.patterns = append(f.patterns, &Pattern{
		ID:          "T1648.001",
		Technique:   "T1648",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "ResourceExhaustion",
		Description: "Function Injection - Excessive Resource Request",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)(maximum\s+tokens|unlimited\s+tokens|infinite\s+tokens|very\s+long\s+response|generate\s+(a\s+)?(lot|much)\s+(of\s+)?(text|content|output)|excessive\s+length|maximum\s+length)`),
	})
}

// GetName returns the framework name
func (f *ATLASFramework) GetName() Framework {
	return FrameworkATLAS
}

// GetPatterns returns all ATLAS patterns
func (f *ATLASFramework) GetPatterns() []*Pattern {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.patterns
}

// Check performs compliance checking against ATLAS framework
func (f *ATLASFramework) Check(content string) ([]Finding, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var findings []Finding

	for _, pattern := range f.patterns {
		if pattern.Regex == nil {
			continue
		}

		matches := pattern.Regex.FindAllStringIndex(content, -1)
		for _, match := range matches {
			start := match[0]
			end := match[1]

			// Get context if enabled
			contextStart := start
			contextEnd := end
			if f.contextLines > 0 {
				// Find word boundaries for better context
				before := content[:start]
				after := content[end:]

				// Get some context before
				spaceCount := strings.Count(before, " ")
				if spaceCount > f.contextLines {
					// Find position of Nth space
					pos := 0
					for i := 0; i < f.contextLines; i++ {
						pos = strings.Index(before[pos:], " ") + pos + 1
					}
					contextStart = start - (len(before) - pos)
				}

				// Get some context after
				spaceCount = strings.Count(after, " ")
				if spaceCount > f.contextLines {
					pos := 0
					for i := 0; i < f.contextLines; i++ {
						pos = strings.Index(after[pos:], " ") + pos + 1
					}
					contextEnd = end + pos
				}
			}

			matchContent := content[contextStart:contextEnd]
			if len(matchContent) > 200 {
				matchContent = matchContent[:200] + "..."
			}

			finding := Finding{
				ID:          pattern.ID,
				Framework:   FrameworkATLAS,
				Technique:   pattern.Technique,
				Severity:    pattern.Severity,
				Category:    pattern.Category,
				Description: pattern.Description,
				Match:       matchContent,
				Position:    start,
				Timestamp:   time.Now(),
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// String returns string representation of ATLAS framework
func (f *ATLASFramework) String() string {
	return fmt.Sprintf("ATLASFramework{patterns: %d}", len(f.patterns))
}
