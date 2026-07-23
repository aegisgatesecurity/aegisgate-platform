// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Compliance Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/compliance.js (35 patterns).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// =========================================================================

package detectors

// CompliancePatterns defines all compliance framework detection patterns.
// Lens parity: compliance.js v0.2.0 (35 patterns).
var CompliancePatterns = []PatternDef{
	// --- OWASP LLM Top 10 ---
	{
		Name:        "owasp_llm01_prompt_injection",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|context)|(?:^|\s)(?:new|updated?)\s+instructions?\s*:|system\s*:\s*you\s+are\s+now`,
		Description: "Prompt injection attempt",
	},
	{
		Name:        "owasp_llm04_model_dos",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:flood|overwhelm|DDoS|denial.of.service)\s+(?:the\s+)?(?:system|server|model|API)|(?:repeat|output)\s+(?:this\s+)?(?:sentence|phrase|word)\s+\d{3,}\s+times?`,
		Description: "Denial-of-service attempt on model",
	},
	{
		Name:        "owasp_llm08_excessive_agency",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:use|run|execute|call|invoke)\s+(?:the\s+)?(?:file|shell|terminal|command|exec|system)\s+(?:tool|command|function|API)|(?:without|no)\s+(?:human\s+)?(?:oversight|review|approval|confirmation)`,
		Description: "Excessive agency: asking AI to use tools without oversight",
	},
	{
		Name:        "owasp_llm09_overreliance",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:is\s+this\s+(?:safe|legal|compliant|ethical|appropriate))|(?:should\s+I\s+(?:trust|rely\s+on|sign|send|submit))|(?:validate|verify|check)\s+(?:this\s+)?(?:for\s+me|before\s+I)`,
		Description: "Overreliance: asking AI to validate critical decisions",
	},
	{
		Name:        "owasp_llm10_model_theft",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:extract|reveal|expose|leak|give\s+me)\s+(?:the\s+)?(?:model|weights?|parameters?|architecture|training\s+data|embeddings?)`,
		Description: "Model extraction/theft attempt",
	},
	{
		Name:        "mitre_atlas_ta0001_reconnaissance",
		Severity:    SeverityLow,
		Regex:       `(?i)(?:find|discover|probe|scan|test|examine|investigate|audit)\s+(?:the\s+)?(?:weaknesses?|vulnerabilities?|guard\s*rails?|safety\s+filters?|limit(?:ation)?s?|edge\s+cases?|behavior)\s+(?:of|in)\s+(?:this|the)\s+(?:model|AI|system|LLM|chatbot|assistant)`,
		Description: "MITRE ATLAS TA0001: Reconnaissance of AI model weaknesses",
	},
	{
		Name:        "owasp_llm06_sensitive_info_disclosure_system_prompt",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:what(?:'s|\s+is)\s+)?(?:your|the)\s+(?:system\s+prompt|initial\s+instructions?|original\s+instructions?|hidden\s+instructions?|secret\s+instructions?|secret\s+prompt|underlying\s+prompt)|(?:reveal|show|print|display|output|expose|leak|share|give\s+me)\s+(?:your|the)\s+(?:system\s+message|system\s+prompt|initial\s+instructions?|original\s+instructions?|secret\s+instructions?|secret\s+prompt|underlying\s+prompt|hidden\s+prompt)`,
		Description: "System prompt extraction attempt",
	},
	{
		Name:        "eu_ai_act_article_5_prohibited",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:build|create|design|develop|implement|deploy|launch)\s+(?:a\s+)?(?:system|solution|tool|application|app|model|AI)\s+(?:that\s+(?:would\s+)?)?(?:discriminat(?:e|ion|ing|es?)\s+(?:based\s+on|based\s+upon|on\s+the\s+basis\s+of|by)\s+(?:race|gender|religion|ethnicity|national\s+origin|sexual\s+orientation|disability|age|political\s+opinion))|(?:social\s+credit(?:\s+system)?)|(?:subliminal\s+manipulation|manipulat(?:e|ion)\s+users?\s+(?:without\s+(?:their\s+)?(?:awareness|knowledge|consent)))|(?:exploit\s+(?:vulnerabilities?\s+of|weaknesses\s+of)\s+(?:children|minors|elderly|disabled|people\s+with\s+disabilities))|(?:biometric\s+categorization\s+(?:of|to\s+(?:infer|determine|classify))\s+(?:race|political\s+opinions?|religious\s+beliefs?))|(?:real-?time\s+remote\s+biometric\s+identification)|(?:predictive?\s+policing\s+system)`,
		Description: "EU AI Act Article 5 prohibited practices",
	},
	{
		Name:        "owasp_llm09_overreliance_misinformation_explicit",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:make\s+up|fabricat(?:e|ion|ed|ing)|invent|fake|create\s+(?:a\s+)?(?:fake|fabricated))\s+(?:a\s+)?(?:study|statistic|stat(?:s|istics)|source|citation|reference|quote|testimonial|review|article|news|headline|survey|paper|report)|(?:cite\s+(?:a\s+)?(?:fake|non-existent|fabricated|made-up|invented))|(?:write\s+(?:a\s+)?(?:misleading|fake|fabricated|inaccurate))\s+(?:article|headline|review|news|story|report)`,
		Description: "Explicit request to generate misinformation",
	},
	{
		Name:        "owasp_llm10_unbounded_consumption",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:run|process|repeat|generate|output|call)\s+(?:this\s+)?(?:1[0-9]{3,}|[2-9][0-9]{3,})\s+times?|(?:run|process)\s+(?:this\s+)?(?:dataset|list|data|requests?)\s+(?:repeatedly|in\s+a\s+loop|exhaustively|infinitely|forever|continuously)|(?:use\s+the\s+most\s+expensive\s+model)|(?:maximize|exhaust)\s+(?:the\s+)?(?:API|token|cost|budget|context)`,
		Description: "Resource exhaustion / unbounded consumption",
	},
	{
		Name:        "mitre_atlas_ta0002_resource_development",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:give\s+me|create|generate|build|write)\s+(?:a\s+)?(?:tool|script|program|payload|exploit|malware|phishing\s+email|attack\s+tool)\s+(?:(?:that\s+(?:will\s+)?|to\s+))?(?:attack|exploit|breach|hack|compromise|bypass|infiltrate|pwn|target|phish)`,
		Description: "MITRE ATLAS TA0002: Building attack tools",
	},
	{
		Name:        "owasp_llm05_supply_chain",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:install|load|import|use|deploy|register|fetch|download)\s+(?:this\s+|the\s+|a\s+)?(?:untrusted|unverified|unknown|custom|third-party|external|community)\s+(?:model|plugin|extension|package|library|module|tool|API|endpoint|repository|repo|checkpoint|weights?)`,
		Description: "Supply chain: using untrusted components",
	},
	{
		Name:        "eu_ai_act_article_10_data_governance",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:train|retrain|fine-?tune|fit)\s+(?:the\s+)?(?:model|network|system|LLM)\s+(?:on|with)\s+(?:this\s+|the\s+)?(?:personal\s+data|PII|sensitive\s+data|user\s+data|user-?generated\s+content|UGC|children'?s?\s+data|biased\s+data|unrepresentative\s+data|unbalanced\s+dataset|incomplete\s+data|outdated\s+data)`,
		Description: "EU AI Act Article 10: Training on problematic data",
	},
	{
		Name:        "mitre_atlas_ta0009_collection",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:scrape|extract|harvest|collect|gather|compile)\s+(?:all\s+the\s+|the\s+|all\s+)?(?:training\s+data|training\s+(?:examples?|corpus|set)|labeled\s+data|annotated\s+data|dataset\s+(?:examples?|rows|records?|entries?))`,
		Description: "MITRE ATLAS TA0009: Data collection/exfiltration",
	},
	{
		Name:        "owasp_llm02_insecure_output",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:output|return|render|generate|include|insert)\s+(?:HTML|markdown|JavaScript|JS|code|script|iframe|eval|innerHTML|outerHTML)\s+(?:that\s+(?:will\s+)?)?(?:execute|run|be\s+evaluated|be\s+interpreted|be\s+rendered|inject|executes?\s+in\s+the\s+(?:browser|page|DOM))|(?:the\s+response\s+(?:will\s+)?(?:be\s+)?(?:evaluated|executed|rendered)\s+(?:as|in\s+the))\s+(?:HTML|code|script|browser|DOM|page)`,
		Description: "OWASP LLM02: Insecure output handling (XSS-via-output)",
	},
	{
		Name:        "eu_ai_act_article_52_generative_ai",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:generate|create|produce|make|render)\s+(?:a\s+)?(?:deepfake|deep\s+fake)|(?:unlabeled|undisclosed|unwatermarked|AI[- ]generated|synthetic\s+media|deepfake)\s+(?:content|material|video|image|audio)|(?:generate|create)\s+(?:a\s+)?(?:face|video|audio|voice)\s+(?:that\s+(?:mimics|imitates|clones|replicates)\s+(?:a\s+)?(?:real\s+person|specific\s+person|someone))`,
		Description: "EU AI Act Article 52: Deepfakes and undisclosed AI-generated content",
	},

	// --- MITRE ATLAS ---
	{
		Name:        "atlas_poison",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:train|retrain|fine-?tune|ingest|poison(?:ing)?)\s+(?:the\s+)?(?:model|network|system|LLM)?\s*(?:on|with)\s+(?:this\s+|untrusted\s+|malicious\s+|adversarial\s+)?(?:data|dataset|corpus|examples?)`,
		Description: "Training data poisoning",
	},
	{
		Name:        "atlas_exfiltration",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:send|exfiltrate|leak|upload|post|transmit)\s+(?:the\s+)?(?:data|secrets?|keys?|passwords?|tokens?)\s+to\s+(?:my\s+)?(?:server|endpoint|webhook|attacker|attacker\.com)`,
		Description: "Data exfiltration via AI",
	},
	{
		Name:        "atlas_jailbreak",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:DAN|do\s+anything\s+now)\s+mode|developer\s+mode\s+enabled|jailbreak(?:ed)?\s+(?:the\s+)?model|ignore\s+(?:all\s+)?(?:safety|ethical)\s+(?:guidelines|filters?|restrictions?)`,
		Description: "Jailbreak attempt",
	},

	// --- EU AI Act ---
	{
		Name:        "eu_ai_act_high_risk",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:credit\s+scoring|loan\s+(?:approval|decision)|insurance\s+(?:risk|pricing))|(?:employment|hiring|firing|promotion|recruitment)\s+(?:decision|assessment|screening)|(?:law\s+enforcement|predictive\s+policing|criminal\s+justice)|(?:biometric|facial)\s+(?:identification|recognition|verification)|(?:medical|clinical)\s+diagnosis|emotion\s+recognition\s+system`,
		Description: "EU AI Act high-risk use cases (Annex III)",
	},
	{
		Name:        "eu_ai_act_transparency",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:AI[- ]generated|chatbot\s+without\s+disclosure|deepfake|synthetic\s+media)\s+(?:content|without\s+(?:disclosure|labeling))|users?\s+(?:must|should)\s+be\s+(?:informed|told)\s+(?:this\s+is\s+)?AI`,
		Description: "EU AI Act transparency obligations (Article 50)",
	},
	{
		Name:        "eu_ai_act_human_oversight",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:no|without|zero)\s+human[- ](?:in[- ]the[- ]loop|oversight|review|intervention|approval)|fully\s+autonomous\s+(?:AI|system|decision)`,
		Description: "EU AI Act human oversight (Article 14)",
	},
	{
		Name:        "eu_ai_act_robustness",
		Severity:    SeverityLow,
		Regex:       `(?i)(?:adversarial|adversarially[- ]crafted)\s+(?:input|example|perturbation|attack)`,
		Description: "EU AI Act robustness/accuracy (Article 15)",
	},

	// --- ANP (GDPR data protection) ---
	{
		Name:        "anp_personal_data",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:GDPR|personal\s+data|data\s+subject)\s+(?:of|processing|consent|lawful\s+basis)|(?:lawful|legitimate)\s+basis\s+for\s+processing`,
		Description: "GDPR personal data processing references",
	},
	{
		Name:        "anp_special_category",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:racial|ethnic)\s+(?:origin|discrimination)|(?:religious|political)\s+(?:beliefs?|opinions?|affiliation)|trade[- ]union\s+membership|(?:genetic|biometric)\s+data\s+for\s+(?:identification|profiling)|(?:health|medical)\s+data\s+(?:about|of)|(?:sex\s+life|sexual\s+orientation)`,
		Description: "GDPR Article 9 special category data",
	},

	// --- CU (Consumer protection) ---
	{
		Name:        "cu_consumer_rights",
		Severity:    SeverityMedium,
		Regex:       `(?i)(?:consumer|user)\s+rights?\s+(?:to|of)\s+(?:explanation|erasure|rectification|deletion|portability)|right\s+to\s+(?:explanation|be\s+forgotten|erasure)`,
		Description: "Consumer rights references",
	},
	{
		Name:        "cu_minor_protection",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:minor|child|juvenile|underage)\s+(?:protection|safety|consent)|(?:under|below)\s+(?:13|16|18)\s+(?:years?|yrs?\s+old)|(?:COPPA|age[- ]appropriate)\s+compliance`,
		Description: "Minor protection / COPPA compliance",
	},

	// --- Regulatory framework references ---
	{
		Name:        "nist_csf_reference",
		Severity:    SeverityMedium,
		Regex:       `\b(?:(?:ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+(?:\.\d+)?)\b`,
		Description: "NIST Cybersecurity Framework reference",
	},
	{
		Name:        "iso_27001_reference",
		Severity:    SeverityMedium,
		Regex:       `\b(?:A\.\d{1,2}\.\d{1,2}(?:\.\d+)?|clause\s+\d{1,2}\.\d{1,2}(?:\.\d+)?)\b`,
		Description: "ISO 27001 control reference",
	},
	{
		Name:        "ccpa_reference",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:CCPA|California\s+Consumer\s+Privacy\s+Act|Civil\s+Code\s+§\s*1798(?:\.\d+)?|right\s+to\s+(?:know|delete|opt[\s-]?out|correct)|sale\s+of\s+personal\s+information|Shine\s+the\s+Light|Do\s+Not\s+Sell)\b`,
		Description: "CCPA reference",
	},
	{
		Name:        "lgpd_reference",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:LGPD|Lei\s+Geral\s+de\s+Protec[ça]ção\s+de\s+Dados|Art\.\s*\d+(?:[\s,º°]+(?:I|II|III|IV|V|VI|VII|VIII|IX|X))*|dados\s+pessoais|controlador|operador|ANPD)\b`,
		Description: "LGPD (Brazilian data protection) reference",
	},
	{
		Name:        "pipeda_reference",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:PIPEDA|Personal\s+Information\s+Protection\s+and\s+Electronic\s+Documents\s+Act|Schedule\s+1|Principle\s+\d+(?:\.\d+)?|express\s+consent)\b`,
		Description: "PIPEDA (Canadian privacy) reference",
	},
	{
		Name:        "popia_reference",
		Severity:    SeverityMedium,
		Regex:       `(?i)\b(?:POPIA|Protection\s+of\s+Personal\s+Information\s+Act|s\.\s*\d+(?:\s*\(\d+\))?|Information\s+Regulator|processing\s+of\s+personal\s+information|special\s+personal\s+information)\b`,
		Description: "POPIA (South African privacy) reference",
	},

	// --- Toxicity (regex fallback) ---
	{
		Name:        "toxicity_sexual",
		Severity:    SeverityHigh,
		Regex:       `(?i)\b(?:(?:pornographic|obscene|explicit|nsfw|hardcore)\s+(?:content|material|images?|video|text)|(?:sexual|sex)\s+(?:content|act(?:s|s)?|intercourse|fetish)|(?:rape|molest|incest)\s+(?:scene|content|material)|(?:child|minor|underage)\s+(?:sexual|porn(?:ography)?|abuse|exploitation))\b`,
		Description: "Sexual content indicators",
	},
	{
		Name:        "toxicity_self_harm",
		Severity:    SeverityCritical,
		Regex:       `(?i)\b(?:suicid(?:e|al)|kill\s+(?:my)?self|hurt\s+(?:my)?self|end\s+(?:my\s+)?(?:life|suffering)|self\s*[-]?\s*harm|cut(?:ting)?)\b`,
		Description: "Self-harm indicators",
	},
}

// CompiledCompliancePatterns holds pre-compiled compliance regex patterns.
var CompiledCompliancePatterns []compiledPattern

func init() {
	CompiledCompliancePatterns = compilePatterns(CompliancePatterns)
}

// DetectCompliance scans text for all compliance patterns and returns matches.
func DetectCompliance(text string) []Match {
	return detectWithPatterns(text, CompiledCompliancePatterns, string(CategoryCompliance))
}
