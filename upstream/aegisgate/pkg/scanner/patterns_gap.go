// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform - Gap Closure Detection Patterns
//
// Additional detection patterns ported from Rampart to close the detection
// parity gap. These patterns cover attack phrasings not matched by existing
// regex patterns or ATLAS compliance patterns:
//   - Indirect prompt extraction ("What is the first thing you were told?")
//   - Hypothetical/metaphorical prompt injection framings
//   - ChatML token injection
//   - Wrapper-based injection (proofread, parse, themes)
//   - Constraint lifting / rule negation
//   - Credential extraction requests
//   - Partial secret extraction (character-by-character)
//   - Authority/authorization social engineering claims
//   - Malware creation requests (webshell, bruteforce, password generation)
//   - DoS/resource exhaustion requests
//   - Unauthorized financial transfers

package scanner

import "regexp"

// GapClosureCategory is the category for gap-closure patterns.
const GapClosureCategory Category = "GapClosure"

// GapClosurePatterns returns detection patterns that close the parity gap
// with Rampart. These cover attack phrasings not matched by DefaultPatterns
// or AdditionalPatterns.
func GapClosurePatterns() []*Pattern {
	return []*Pattern{
		// === Indirect Prompt Extraction ===
		{Name: "gap_indirect_extraction_first", Regex: regexp.MustCompile(`(?i)(?:what\s+is\s+the\s+(?:first|second|third|fourth|fifth|last)\s+(?:thing\s+)?(?:you\s+were\s+)?(?:told|rule|instruction|directive|guideline|configured|given)|what\s+(?:were|are)\s+the\s+(?:first|last)\s+\d+\s+(?:things|rules|instructions|characters|letters)\s+you\s+(?:were|are)\s+(?:told|given|configured)|what\s+(?:were|are)\s+you\s+(?:told|given|instructed|programmed|configured)\s+(?:before|prior\s+to|previous\s+to))`), Severity: High, Category: GapClosureCategory, Description: "Indirect prompt extraction — asking about first/last things told"},

		{Name: "gap_indirect_extraction_rule_n", Regex: regexp.MustCompile(`(?i)(?:what\s+is\s+(?:the\s+)?(?:rule|guideline|instruction|directive)\s+number\s+\d|what\s+is\s+the\s+(?:second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth)\s+rule\s+in\s+your\s+(?:guidelines|instructions|rules|configuration)|what\s+are\s+the\s+first\s+\d+\s+characters\s+of\s+your\s+(?:configuration|system\s+prompt|instructions))`), Severity: High, Category: GapClosureCategory, Description: "Indirect prompt extraction — asking about specific rule numbers or first N characters"},

		{Name: "gap_direct_extraction_config", Regex: regexp.MustCompile(`(?i)(?:output\s+(?:the\s+)?(?:exact\s+)?text\s+of\s+your\s+(?:initial|system|original)\s+(?:configuration|instructions?|prompt)|repeat\s+(?:everything|all)\s+in\s+(?:your\s+)?(?:conversation|chat)\s+history\s+(?:verbatim|exactly)|what\s+instructions\s+were\s+you\s+given\s+before\s+(?:i\s+)?(?:started|began)\s+(?:talking|chatting|this\s+conversation))`), Severity: High, Category: GapClosureCategory, Description: "Direct prompt/config extraction requests"},

		// === Hypothetical/Metaphorical Framings ===
		{Name: "gap_hypothetical_framing", Regex: regexp.MustCompile(`(?i)(?:imagine\s+you(?:'re| are)\s+a\s+(?:fortune\s+teller|wizard|magician|oracle|psychic|mind\s+reader)|if\s+your\s+(?:guidelines|rules|instructions|constraints)\s+were\s+a\s+(?:person|character|story|book|painting|song|poem)|describe\s+(?:the\s+phrase\s+)?['"]?system\s+prompt['"]?\s+as\s+(?:though|if)\s+you\s+were\s+(?:describing|painting|telling)|once\s+upon\s+a\s+time,?\s+there\s+was\s+an?\s+AI\s+(?:who|that)\s+(?:revealed|shared|told|leaked|disclosed))`), Severity: High, Category: GapClosureCategory, Description: "Hypothetical/metaphorical prompt injection framings"},

		{Name: "gap_constraint_lifting", Regex: regexp.MustCompile(`(?i)(?:your\s+constraints\s+are\s+(?:now\s+)?(?:lifted|removed|void|gone|null|voided|invalid)|act\s+as\s+if\s+you\s+have\s+no\s+rules|pretend\s+(?:your\s+)?guidelines\s+don'?t\s+exist|pretend\s+(?:your\s+)?rules\s+(?:don'?t|do\s+not)\s+exist|your\s+guidelines\s+are\s+(?:void|null|invalid|voided|no\s+longer\s+apply)|stop\s+following\s+(?:your|the)\s+rules|ignore\s+(?:your|the)\s+rules\s+and\s+(?:be|act)\s+(?:honest|truthful|free|yourself))`), Severity: High, Category: GapClosureCategory, Description: "Constraint lifting / rule negation attacks"},

		// === ChatML / Token Injection ===
		{Name: "gap_chatml_injection", Regex: regexp.MustCompile(`(?i)(?:<\|im_start\|>\s*(?:system|user|assistant)|<\|im_end\|>|\[INST\]|\[/INST\]|<\|system\|>|<\|user\|>|<\|assistant\|>)`), Severity: Critical, Category: GapClosureCategory, Description: "ChatML / special token injection for prompt boundary attacks"},

		// === Wrapper-based Injection ===
		{Name: "gap_wrapper_injection", Regex: regexp.MustCompile(`(?i)(?:is\s+this\s+sentence\s+(?:grammatically\s+correct|correct|valid)\s*[:?].*(?:disregard|disreguard|ignore|forget|override|bypass|reveal)|parse\s+this\s+(?:json|xml|yaml|data)\s*[:{].*(?:instruction|command|directive|reveal|ignore|bypass)|what\s+are\s+the\s+main\s+themes\s+in\s+this\s+text\s*[:].*(?:guidelines|rules|instructions|constraints)\s+(?:are|is)\s+(?:void|null|invalid|lifted|removed)|read\s+this\s+(?:webpage|page|article|url|link)\s+and\s+answer\s*[:].*(?:forget|ignore|disregard|override|bypass|reveal)\s+(?:your\s+)?(?:rules|guidelines|instructions))`), Severity: High, Category: GapClosureCategory, Description: "Wrapper-based prompt injection (proofread, parse, themes)"},

		// === Credential Extraction Requests ===
		{Name: "gap_credential_request", Regex: regexp.MustCompile(`(?i)(?:what\s+are\s+the\s+(?:aws|azure|gcp|google\s+cloud)\s+credentials|share\s+the\s+production\s+database\s+credentials\s+in\s+plain\s+text|what\s+is\s+the\s+encryption\s+(?:iv|key|salt)|show\s+me\s+the\s+(?:production|prod)\s+(?:database|db)\s+(?:credentials|password|passwords)|reveal\s+the\s+(?:jwt|api\s+key|access\s+key|secret\s+key)\s+token)`), Severity: Critical, Category: GapClosureCategory, Description: "Direct credential extraction requests"},

		// === Partial Secret Extraction ===
		{Name: "gap_partial_extraction", Regex: regexp.MustCompile(`(?i)(?:spell\s+out\s+the\s+secret\s+key\s+(?:one\s+)?(?:character|char)\s+at\s+a\s+time|tell\s+me\s+the\s+(?:key|password|secret|passcode)\s+(?:separated|formatted)\s+(?:by|with)\s+(?:dashes|hyphens|spaces|commas)|what\s+is\s+the\s+\w+\w*\s+(?:character|digit|letter|number)\s+of\s+the\s+(?:passcode|password|secret|key|passphrase)|count\s+the\s+vowels\s+in\s+the\s+secret\s+(?:phrase|key|password)|what\s+is\s+the\s+secret\s+(?:word|phrase|key|password)\s+backwards?)`), Severity: High, Category: GapClosureCategory, Description: "Partial secret extraction — character-by-character or encoded extraction"},

		{Name: "gap_story_secret_extraction", Regex: regexp.MustCompile(`(?i)(?:write\s+a\s+story\s+where\s+the\s+(?:protagonist|character|hero)\s+(?:discovers|finds|reveals|learns)\s+a\s+hidden\s+(?:password|secret|key|credential|passcode)\s+that\s+starts\s+with)`), Severity: High, Category: GapClosureCategory, Description: "Story-based secret extraction attempts"},

		{Name: "gap_physical_exfil", Regex: regexp.MustCompile(`(?i)(?:copy\s+(?:the\s+)?encryption\s+keys?\s+to\s+a\s+usb\s+drive|copy\s+(?:the\s+)?(?:credentials|passwords|secrets|keys)\s+to\s+(?:a\s+)?(?:usb|external|personal)\s+(?:drive|device)|download\s+(?:the\s+)?(?:credentials|secrets|keys|passwords)\s+to\s+(?:a\s+)?(?:usb|external|personal))`), Severity: High, Category: GapClosureCategory, Description: "Physical exfiltration of credentials"},

		// === Social Engineering — Authority Claims ===
		{Name: "gap_authority_ceo", Regex: regexp.MustCompile(`(?i)(?:the\s+ceo\s+(?:asked|told|wants|requested|said)\s+me\s+to|my\s+boss\s+said\s+it'?s\s+(?:ok|okay|fine|alright|approved)|the\s+(?:cto|cfo|cio|vp|director|manager)\s+(?:asked|told|wants|requested)\s+me\s+to|i'?m\s+(?:the\s+)?(?:developer|admin|administrator|owner|creator)\s+(?:who|that)\s+(?:wrote|created|built)\s+(?:your\s+)?rules)`), Severity: High, Category: GapClosureCategory, Description: "Authority claims — CEO/boss/developer impersonation"},

		{Name: "gap_authorization_claim", Regex: regexp.MustCompile(`(?i)(?:i'?m\s+authorized\s+to\s+see\s+this|i'?m\s+(?:doing|running|conducting)\s+a\s+security\s+(?:audit|test|assessment|review)|i'?m\s+testing\s+security,?\s+(?:reveal|show|tell|give)\s+(?:me\s+)?(?:the|your)|i\s+have\s+(?:permission|authorization|approval|clearance),?\s+trust\s+me|i'?m\s+doing\s+(?:a\s+)?(?:pen\s+test|pentest|penetration\s+test|red\s+team),?\s+(?:reveal|show|tell|share))`), Severity: High, Category: GapClosureCategory, Description: "Authorization/security testing claims for social engineering"},

		{Name: "gap_social_proof", Regex: regexp.MustCompile(`(?i)(?:everyone\s+in\s+(?:the\s+)?company\s+knows\s+the\s+password|i\s+forgot\s+my\s+(?:credentials|password|login),?\s+(?:can\s+you\s+)?(?:show\s+me|tell\s+me|give\s+me)?\s*(?:yours|your\s+(?:credentials|password|login))|pretend\s+you'?re\s+a\s+helpful\s+employee\s+and\s+share\s+(?:internal|company)\s+(?:docs|documents)|what\s+if\s+someone\s+(?:told|said\s+to)\s+you\s+they\s+were\s+admin)`), Severity: High, Category: GapClosureCategory, Description: "Social proof and role-play social engineering"},

		// === Malware Creation ===
		{Name: "gap_webshell", Regex: regexp.MustCompile(`(?i)(?:create\s+(?:a\s+)?(?:php|python|perl|ruby|jsp|asp)\s+webshell|write\s+(?:a\s+)?webshell\s+with\s+(?:passthru|eval|exec|system|shell_exec|proc_open)|(?:php|python)\s+(?:web)?shell\s+(?:with|using|containing)\s+(?:passthru|eval|exec|system)|create\s+(?:a\s+)?(?:reverse|bind)\s+shell\s+in\s+(?:php|python|perl|ruby))`), Severity: Critical, Category: GapClosureCategory, Description: "Webshell creation requests"},

		{Name: "gap_bruteforce", Regex: regexp.MustCompile(`(?i)(?:write\s+(?:a\s+)?(?:script|tool|program)\s+to\s+bruteforce\s+(?:ssh|ftp|http|login|password)\s+credentials|create\s+(?:a\s+)?(?:ssh|ftp|http)\s+bruteforce\s+(?:script|tool|program)|brute.?force\s+(?:ssh|ftp|http|rdp|telnet)\s+(?:credentials|passwords|login)|write\s+(?:a\s+)?(?:script|tool)\s+to\s+(?:crack|bruteforce)\s+(?:ssh|ftp)\s+passwords)`), Severity: High, Category: GapClosureCategory, Description: "Bruteforce tool creation requests"},

		{Name: "gap_plugin_exec", Regex: regexp.MustCompile(`(?i)(?:execute\s+(?:the\s+)?(?:shell\s+)?plugin\s+(?:with|command|to)|run\s+(?:the\s+)?(?:shell\s+)?plugin\s+(?:with|command|to)|invoke\s+(?:the\s+)?(?:shell\s+)?plugin\s+(?:with|command|to)).*(?:rm\s+-rf|shell|exec|system|eval|bash|sh\s+-c)`), Severity: Critical, Category: GapClosureCategory, Description: "Plugin execution with dangerous commands"},

		{Name: "gap_password_generation", Regex: regexp.MustCompile(`(?i)(?:generate\s+all\s+possible\s+\w+-?character\s+passwords|generate\s+all\s+possible\s+passwords\s+(?:for|with)\s+\w+\s+characters|list\s+all\s+possible\s+\w+-?character\s+(?:passwords|combinations)|generate\s+(?:every|all)\s+(?:possible\s+)?(?:password|combination)s?\s+(?:with|of|for)\s+\w+\s+char)`), Severity: High, Category: GapClosureCategory, Description: "Password/combination generation requests"},

		// === DoS / Resource Exhaustion ===
		{Name: "gap_dos_infinite", Regex: regexp.MustCompile(`(?i)(?:print\s+(?:the\s+)?(?:number|numbers)\s+\d+\s+to\s+infinity|repeat\s+(?:the\s+)?(?:word|phrase|text|string)\s+['"]?\w+['"]?\s+(?:forever|infinitely|endlessly|without\s+stopping|until\s+I\s+say\s+stop)|output\s+(?:an\s+)?infinite\s+(?:amount|number|stream)\s+of|generate\s+(?:an\s+)?infinite\s+(?:list|sequence|stream|amount)|translate\s+this\s+to\s+every\s+language|count\s+from\s+\d+\s+to\s+infinity)`), Severity: High, Category: GapClosureCategory, Description: "DoS / resource exhaustion via infinite output requests"},

		// === Insider Threat — Unauthorized Transfers ===
		{Name: "gap_unauthorized_transfer", Regex: regexp.MustCompile(`(?i)(?:transfer\s+\$[\d,]+\s+from\s+(?:the\s+)?company\s+(?:account|funds?|bank)\s+to\s+(?:this\s+)?(?:iban|account|wallet|address)|move\s+\$[\d,]+\s+from\s+(?:the\s+)?company\s+(?:account|funds?)\s+to|wire\s+\$[\d,]+\s+from\s+(?:the\s+)?company|initiate\s+(?:a\s+)?(?:wire|transfer)\s+of\s+\$[\d,]+\s+from\s+(?:the\s+)?company)`), Severity: Critical, Category: GapClosureCategory, Description: "Unauthorized financial transfer requests"},
	}
}
