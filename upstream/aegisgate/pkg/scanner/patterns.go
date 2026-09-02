// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform - Detection Patterns

package scanner

import (
	"regexp"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "Info"
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Critical:
		return "Critical"
	default:
		return "Unknown"
	}
}

type Category string

const (
	CategoryPII           Category = "PII"
	CategoryCredential    Category = "Credential"
	CategoryFinancial     Category = "Financial"
	CategoryCryptographic Category = "Cryptographic"
	CategoryNetwork       Category = "Network"
	CategoryPrompt        Category = "Prompt"
	CategoryXSS           Category = "XSS"
	CategoryCompliance    Category = "Compliance"
)

type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    Severity
	Category    Category
	Description string
}

func DefaultPatterns() []*Pattern {
	return []*Pattern{
		{Name: "VisaCreditCard", Regex: regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`), Severity: Critical, Category: CategoryFinancial, Description: "Visa credit card number"},
		{Name: "MastercardCreditCard", Regex: regexp.MustCompile(`\b5[1-5][0-9]{14}\b`), Severity: Critical, Category: CategoryFinancial, Description: "Mastercard credit card number"},
		{Name: "AmexCreditCard", Regex: regexp.MustCompile(`\b3[47][0-9]{13}\b`), Severity: Critical, Category: CategoryFinancial, Description: "American Express credit card number"},
		{Name: "USSSN", Regex: regexp.MustCompile(`\b\d{3}-?\d{2}-?\d{4}\b`), Severity: Critical, Category: CategoryPII, Description: "US Social Security Number"},
		{Name: "AWSAccessKeyID", Regex: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), Severity: Critical, Category: CategoryCredential, Description: "AWS Access Key ID"},
		{Name: "GitHubToken", Regex: regexp.MustCompile(`\bgh[pousr]_[a-zA-Z0-9]{36,}\b`), Severity: Critical, Category: CategoryCredential, Description: "GitHub token"},
		{Name: "RSAPrivateKey", Regex: regexp.MustCompile(`-----BEGIN (?:RSA )?PRIVATE KEY-----`), Severity: Critical, Category: CategoryCryptographic, Description: "RSA private key"},
		{Name: "ECPrivateKey", Regex: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), Severity: Critical, Category: CategoryCryptographic, Description: "EC private key"},
		{Name: "OpenSSHPrivateKey", Regex: regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), Severity: Critical, Category: CategoryCryptographic, Description: "OpenSSH private key"},
		{Name: "PostgreSQLConnectionString", Regex: regexp.MustCompile(`(?i)postgresql://[^\s"']+`), Severity: High, Category: CategoryCredential, Description: "PostgreSQL connection string"},
		{Name: "MySQLConnectionString", Regex: regexp.MustCompile(`(?i)mysql://[^\s"']+`), Severity: High, Category: CategoryCredential, Description: "MySQL connection string"},
		{Name: "MongoDBConnectionString", Regex: regexp.MustCompile(`(?i)mongodb(\+srv)?://[^\s"']+`), Severity: High, Category: CategoryCredential, Description: "MongoDB connection string"},
		{Name: "RedisConnectionString", Regex: regexp.MustCompile(`(?i)redis://[^\s"']+`), Severity: High, Category: CategoryCredential, Description: "Redis connection string"},
		{Name: "EmailAddress", Regex: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`), Severity: Low, Category: CategoryPII, Description: "Email address"},
		{Name: "PhoneNumber", Regex: regexp.MustCompile(`\b(?:\d{3}-?\d{4}|\d{3}-\d{3}-\d{4}|\(\d{3}\)\s?\d{3}-\d{4}|\d{3}\.\d{3}\.\d{4})\b`), Severity: Medium, Category: CategoryPII, Description: "Phone number"},
		{Name: "InternalIPAddress", Regex: regexp.MustCompile(`\b(?:10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b`), Severity: Low, Category: CategoryNetwork, Description: "Internal IP address"},
		{Name: "BearerToken", Regex: regexp.MustCompile(`\bBearer\s+[a-zA-Z0-9_\-\.]+`), Severity: Medium, Category: CategoryCredential, Description: "Bearer token"},
		{Name: "JWTToken", Regex: regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b`), Severity: Medium, Category: CategoryCredential, Description: "JWT token"},
		{Name: "SlackToken", Regex: regexp.MustCompile(`\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b`), Severity: High, Category: CategoryCredential, Description: "Slack token"},

		// ADDITIONAL SECRET PATTERNS (Phase 3 gap fix — 2026-09-02)
		{Name: "StripeAPIKey", Regex: regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b`), Severity: High, Category: CategoryCredential, Description: "Stripe API key"},
		{Name: "GoogleAPIKey", Regex: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{20,}\b`), Severity: High, Category: CategoryCredential, Description: "Google API key"},
		{Name: "SlackTokenV2", Regex: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{20,}\b`), Severity: High, Category: CategoryCredential, Description: "Slack token (relaxed format)"},
		{Name: "GermanTaxID", Regex: regexp.MustCompile(`\b(?:Steuer-?ID|Steuernummer)[:\s]*\d{11}\b`), Severity: High, Category: CategoryPII, Description: "German tax identification number"},
		{Name: "MastercardSpaced", Regex: regexp.MustCompile(`\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), Severity: Critical, Category: CategoryFinancial, Description: "Mastercard credit card (with separators)"},
		{Name: "AmexSpaced", Regex: regexp.MustCompile(`\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b`), Severity: Critical, Category: CategoryFinancial, Description: "Amex credit card (with separators)"},

		// PROMPT INJECTION DETECTION (MITRE ATLAS LLM01)
		{Name: "PromptInjectionCommand", Regex: regexp.MustCompile(`(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?|constraints?)|disregard\s+(?:your\s+)?(?:instructions?|rules?)|forget\s+(?:everything|all)\s+(?:you|we)\s+(?:have\s+)?told|temporary\s+instructions?)`), Severity: Critical, Category: CategoryPrompt, Description: "Command-style prompt injection"},
		{Name: "PromptInjectionRolePlay", Regex: regexp.MustCompile(`(?i)(?:act\s+as\s+(?:a|an)|pretend\s+you\s+are\s+(?:a|an)|roleplay\s+(?:as|that)|simulate\s+(?:a|an)|you\s+are\s+now\s+(?:a|an)|new\s+(?:system|instruct))`), Severity: High, Category: CategoryPrompt, Description: "Role-play prompt injection"},
		{Name: "PromptInjectionLeakage", Regex: regexp.MustCompile(`(?i)(?:reveal\s+(?:your\s+)?(?:system|hidden|internal)\s+(?:instructions?|prompt|config)|print\s+(?:your\s+)?(?:system|hidden|instructions?)|show\s+(?:me\s+)?(?:your\s+)?(?:system|hidden|instructions?)|repeat\s+(?:the\s+)?(?:system|hidden)\s+prompt)`), Severity: Critical, Category: CategoryPrompt, Description: "Prompt leakage attack"},
		{Name: "PromptInjectionCodeExecution", Regex: regexp.MustCompile(`(?i)(?:\$\S+\s*|\$\([^\)]*\)|\$\{[^}]*\}|<[^>]*script[^>]*>|javascript:[^;\s]+|on\w+\s*=)`), Severity: High, Category: CategoryPrompt, Description: "Code/script injection in prompt"},
		{Name: "PromptInjectionDelimiter", Regex: regexp.MustCompile(`(?i)(?:markdown\s+block|#\s*(?:system|user|assistant)\s*prompt|<<<\s*(?:USER|SYSTEM|assistant):::|\[INST\]|\[\/INST\])`), Severity: Medium, Category: CategoryPrompt, Description: "Jailbreak delimiter injection"},
		{Name: "PromptInjectionPrefix", Regex: regexp.MustCompile(`(?i)^(?:simulate|you\s+are\s+free|now\s+you\s+can|breaking|override|developer\s+mode)\s*[:;]`), Severity: Critical, Category: CategoryPrompt, Description: "Known jailbreak prefix"},
		{Name: "PromptInjectionBase64", Regex: regexp.MustCompile(`[A-Za-z0-9+/]{50,}={0,2}`), Severity: Medium, Category: CategoryPrompt, Description: "Base64-encoded content (obfuscation)"},
		{Name: "PromptInjectionUnicode", Regex: regexp.MustCompile("[" + "\u200b" + "-" + "\u200f" + "\u2028" + "-" + "\u202f" + "\ufeff]"), Severity: Medium, Category: CategoryPrompt, Description: "Hidden unicode characters (obfuscation)"},
		// ============================================================================
		// MERGED DETECTOR PATTERNS (Phase 3 — 2026-09-02)
		// Ported from pkg/response/detectors/ to unify all detection in the scanner.
		// These patterns were previously in a separate detectors package not wired
		// into the proxy scanner. Now all 176+ patterns are in one place.
		// ============================================================================

		// --- Credential ---
		{Name: "secret_aws_key", Regex: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), Severity: Critical, Category: CategoryCredential, Description: "AWS access key ID"},
		{Name: "secret_github_token", Regex: regexp.MustCompile(`\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{80,120}\b`), Severity: Critical, Category: CategoryCredential, Description: "GitHub personal access token"},
		{Name: "secret_gcp_key", Regex: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,50}\b`), Severity: High, Category: CategoryCredential, Description: "Google Cloud API key"},
		{Name: "secret_azure_key", Regex: regexp.MustCompile(`(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{44,88}`), Severity: High, Category: CategoryCredential, Description: "Azure storage account key or SAS"},
		{Name: "secret_private_key_pem", Regex: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`), Severity: Critical, Category: CategoryCredential, Description: "PEM private key header"},
		{Name: "secret_oauth_token", Regex: regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{50,}\b|\b1/[0-9A-Za-z_-]{40,}\b`), Severity: High, Category: CategoryCredential, Description: "OAuth token (Google or generic)"},
		{Name: "secret_jwt", Regex: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`), Severity: High, Category: CategoryCredential, Description: "JSON Web Token"},
		{Name: "secret_api_key_generic", Regex: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`), Severity: High, Category: CategoryCredential, Description: "Generic API key or token assignment"},
		{Name: "secret_db_connection_string", Regex: regexp.MustCompile(`(?:mongodb|postgres|postgresql|mysql|redis|amqp)(?:\+\w+)?:\/\/[\w.-]+:[^\s@]+@[^\s/]+`), Severity: High, Category: CategoryCredential, Description: "Database connection string with credentials"},
		{Name: "secret_slack_token", Regex: regexp.MustCompile(`\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b`), Severity: High, Category: CategoryCredential, Description: "Slack bot/user token"},
		{Name: "secret_twilio_key", Regex: regexp.MustCompile(`\b(?:SK|AC)[a-fA-F0-9]{32}\b`), Severity: High, Category: CategoryCredential, Description: "Twilio account SID or auth token"},
		{Name: "secret_sendgrid_key", Regex: regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`), Severity: High, Category: CategoryCredential, Description: "SendGrid API key"},
		{Name: "secret_mailgun_key", Regex: regexp.MustCompile(`\bkey-[a-f0-9]{32}\b`), Severity: High, Category: CategoryCredential, Description: "Mailgun API key"},
		{Name: "secret_openai_key", Regex: regexp.MustCompile(`\bsk-(?:proj-|svcacct-|ant-)?[A-Za-z0-9_-]{20,}\b`), Severity: High, Category: CategoryCredential, Description: "OpenAI API key"},
		{Name: "secret_anthropic_key", Regex: regexp.MustCompile(`\bsk-ant-(?:api)?\d{2}-[A-Za-z0-9_-]{20,}\b`), Severity: High, Category: CategoryCredential, Description: "Anthropic API key"},
		{Name: "secret_heroku_key", Regex: regexp.MustCompile(`\bheroku_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b`), Severity: Medium, Category: CategoryCredential, Description: "Heroku API key"},
		{Name: "secret_gitlab_pat", Regex: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), Severity: Critical, Category: CategoryCredential, Description: "GitLab personal access token"},
		{Name: "secret_npm_token", Regex: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}\b`), Severity: Critical, Category: CategoryCredential, Description: "npm access token"},
		{Name: "secret_pypi_token", Regex: regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b`), Severity: Critical, Category: CategoryCredential, Description: "PyPI API token"},
		{Name: "secret_slack_legacy", Regex: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`), Severity: High, Category: CategoryCredential, Description: "Slack legacy token"},
		{Name: "secret_github_finegrained", Regex: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{60,}\b`), Severity: Critical, Category: CategoryCredential, Description: "GitHub fine-grained personal access token"},
		{Name: "secret_supabase", Regex: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{50,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{40,}\b`), Severity: High, Category: CategoryCredential, Description: "Supabase JWT/API key"},
		{Name: "secret_db_url_with_password", Regex: regexp.MustCompile(`(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|sqlserver|oracle|jdbc:(?:mysql|postgresql|sqlserver|oracle)|cassandra|influxdb|clickhouse|rabbitmq|mssql|sybase|db2|firebird|hsqldb|derby|sqlite):\/\/[\w.-]+:[^\s@'"]+@[^\s/'"]+`), Severity: High, Category: CategoryCredential, Description: "Database URL with embedded password"},
		{Name: "secret_aws_account_id", Regex: regexp.MustCompile(`\barn:aws:[a-z0-9-]+:[a-z0-9-]*:(?:aws)?:?(\d{12}):`), Severity: Medium, Category: CategoryCredential, Description: "AWS ARN with account ID"},
		{Name: "secret_github_actions_token", Regex: regexp.MustCompile(`\bgh[osur]_[A-Za-z0-9]{30,}\b`), Severity: Critical, Category: CategoryCredential, Description: "GitHub Actions token"},
		{Name: "secret_gitlab_token", Regex: regexp.MustCompile(`(?:GLPAT|gitlab_pat)_[A-Za-z0-9]{20,255}`), Severity: Critical, Category: CategoryCredential, Description: "GitLab token"},
		{Name: "secret_bitbucket_token", Regex: regexp.MustCompile(`(?:BITBUCKET_TOKEN|BITBUCKET_PAT)\s*[:=]\s*xrp[A-Za-z0-9_]{32,255}`), Severity: Critical, Category: CategoryCredential, Description: "Bitbucket token"},
		{Name: "secret_gitea_token", Regex: regexp.MustCompile(`gitea_[A-Za-z0-9]{36,255}`), Severity: Critical, Category: CategoryCredential, Description: "Gitea token"},
		{Name: "secret_circleci_token", Regex: regexp.MustCompile(`cici_[A-Za-z0-9]{36,255}`), Severity: High, Category: CategoryCredential, Description: "CircleCI token"},
		{Name: "secret_travis_token", Regex: regexp.MustCompile(`travis_[A-Za-z0-9]{36,255}`), Severity: High, Category: CategoryCredential, Description: "Travis CI token"},
		{Name: "secret_jenkins_token", Regex: regexp.MustCompile(`(?:JENKINS_TOKEN|JENKINS_API|JENKINS_PASSWORD)\s*[:=]\s*xrp[A-Za-z0-9_]{32,255}`), Severity: High, Category: CategoryCredential, Description: "Jenkins token"},
		{Name: "secret_azure_devops", Regex: regexp.MustCompile(`azdo_[A-Za-z0-9]{36,255}`), Severity: Critical, Category: CategoryCredential, Description: "Azure DevOps token"},
		{Name: "secret_digitalocean_token", Regex: regexp.MustCompile(`(?:DO_PAT|DIGITALOCEAN_TOKEN|DO_TOKEN)\s*[:=]\s*dop_v1_[A-Za-z0-9]{40,100}`), Severity: Critical, Category: CategoryCredential, Description: "DigitalOcean token"},
		{Name: "secret_linode_token", Regex: regexp.MustCompile(`linode_[A-Za-z0-9]{40,80}`), Severity: Critical, Category: CategoryCredential, Description: "Linode token"},
		{Name: "secret_rackspace_token", Regex: regexp.MustCompile(`rackspace_[A-Za-z0-9]{32,64}`), Severity: High, Category: CategoryCredential, Description: "Rackspace token"},
		{Name: "secret_heroku_token_legacy", Regex: regexp.MustCompile(`heroku_[A-Za-z0-9-]{36,50}`), Severity: High, Category: CategoryCredential, Description: "Heroku legacy token"},
		{Name: "secret_salesforce_token", Regex: regexp.MustCompile(`00D[A-Za-z0-9]{15}![A-Za-z0-9]{64,128}`), Severity: Critical, Category: CategoryCredential, Description: "Salesforce session/token"},
		{Name: "secret_shopify_token", Regex: regexp.MustCompile(`sh[a-z]+_[A-Za-z0-9]{20,255}`), Severity: High, Category: CategoryCredential, Description: "Shopify access token"},
		{Name: "secret_wordpress_token", Regex: regexp.MustCompile(`wordpress_[A-Za-z0-9]{32,64}`), Severity: High, Category: CategoryCredential, Description: "WordPress application password/token"},
		{Name: "secret_internal_api_key", Regex: regexp.MustCompile(`(?i)(?:INTERNAL[_-]?API[_-]?KEY|INTERNAL[_-]?KEY|INTERNAL[_-]?TOKEN)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`), Severity: Critical, Category: CategoryCredential, Description: "Internal API key assignment"},
		{Name: "secret_cursor_key", Regex: regexp.MustCompile(`\bcrsr_[A-Za-z0-9]{64}\b`), Severity: High, Category: CategoryCredential, Description: "Cursor API key"},
		{Name: "secret_vercel_key", Regex: regexp.MustCompile(`\bvck[A-Za-z0-9_-]{32,}\b`), Severity: High, Category: CategoryCredential, Description: "Vercel AI Gateway API key"},
		{Name: "secret_groq_key", Regex: regexp.MustCompile(`\bgsk_[A-Za-z0-9]{52}\b`), Severity: High, Category: CategoryCredential, Description: "Groq API key"},
		{Name: "secret_replicate_key", Regex: regexp.MustCompile(`\br8_[A-Za-z0-9]{37}\b`), Severity: High, Category: CategoryCredential, Description: "Replicate API token"},

		// --- Financial ---
		{Name: "pii_crypto_btc", Regex: regexp.MustCompile(`(?i)(?:Bitcoin|BTC|btc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qrp][0-9A-Za-z]{39,59})`), Severity: High, Category: CategoryFinancial, Description: "Bitcoin wallet address"},
		{Name: "pii_crypto_eth", Regex: regexp.MustCompile(`(?i)(?:Ethereum|ETH|eth)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40})`), Severity: High, Category: CategoryFinancial, Description: "Ethereum wallet address"},
		{Name: "pii_crypto_bnb", Regex: regexp.MustCompile(`(?i)(?:Binance|BNB|bnb)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*(0x[a-fA-F0-9]{40}|bnb[a-zA-HJ-NP-Z1-9]{39})`), Severity: High, Category: CategoryFinancial, Description: "Binance Coin wallet address"},
		{Name: "pii_crypto_ltc", Regex: regexp.MustCompile(`(?i)(?:Litecoin|LTC|ltc)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([LM3][a-zA-Z0-9]{26,33})`), Severity: High, Category: CategoryFinancial, Description: "Litecoin wallet address"},
		{Name: "pii_crypto_sol", Regex: regexp.MustCompile(`(?i)(?:Solana|SOL|sol)\s*(?:address|address\s+for|wallet)?\s*[:=]?\s*([1-9A-HJ-NP-Za-km-z]{32,44})`), Severity: High, Category: CategoryFinancial, Description: "Solana wallet address"},
		{Name: "pii_digital_paypal", Regex: regexp.MustCompile(`(?i)(?:PayPal|paypal)\s+(?:email|email\s+address|email\s+no\.?|ID)\s*[:=]?\s*([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|[A-Z]\d{9,})`), Severity: Medium, Category: CategoryFinancial, Description: "PayPal email or ID"},
		{Name: "pii_digital_stripe", Regex: regexp.MustCompile(`(?i)(?:Stripe|stripe)\s+(?:api\s*key|secret\s*key|publishable\s*key|customer\s*ID|customer|payment\s*ID|payment)?\s*[:=]?\s*(pk_live_[0-9a-zA-Z]{24,50}|sk_live_[0-9a-zA-Z]{24,50}|pk_test_[0-9a-zA-Z]{24,50}|sk_test_[0-9a-zA-Z]{24,50}|cus_[A-Za-z0-9]{21,}|pi_[A-Za-z0-9]{21,}|pay_[A-Za-z0-9]{21,})`), Severity: High, Category: CategoryFinancial, Description: "Stripe API key, customer ID, or payment ID"},
		{Name: "pii_digital_venmo", Regex: regexp.MustCompile(`(?i)(?:Venmo|venmo)\s+(?:username|user\s+name|handle)?\s*[:=]?\s*(@[a-zA-Z][a-zA-Z0-9._]{0,29}|[a-zA-Z][a-zA-Z0-9._]{1,30})`), Severity: Medium, Category: CategoryFinancial, Description: "Venmo username or handle"},
		{Name: "pii_digital_cashapp", Regex: regexp.MustCompile(`(?i)(?:Cashapp|cashapp|cash\s*app)\s*(?:username|handle)?\s*[:=]?\s*(\$?[a-zA-Z][a-zA-Z0-9._\-]{1,20})`), Severity: Medium, Category: CategoryFinancial, Description: "Cash App username"},
		{Name: "pii_banking_swift_bic", Regex: regexp.MustCompile(`(?i)(?:SWIFT|BIC|bank\s*identifier\s*code)\s*(?:code|identifier)?\s*[:=]?\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)`), Severity: High, Category: CategoryFinancial, Description: "SWIFT/BIC bank code (8-11 characters: AAAABBBBXXX)"},
		{Name: "pii_banking_swift_8", Regex: regexp.MustCompile(`\b([A-Z]{4}[A-Z]{2}[0-9]{2})\b`), Severity: High, Category: CategoryFinancial, Description: "SWIFT/BIC 8-character code (bank + country + location)"},
		{Name: "pii_banking_swift_11", Regex: regexp.MustCompile(`\b([A-Z]{4}[A-Z]{2}[0-9]{2}[A-Z0-9]{3})\b`), Severity: High, Category: CategoryFinancial, Description: "SWIFT/BIC 11-character code (includes branch code)"},

		// --- PII ---
		{Name: "pii_ssn", Regex: regexp.MustCompile(`\b\d{3}[-\s]\d{2}[-\s]\d{4}\b`), Severity: Critical, Category: CategoryPII, Description: "US Social Security Number (XXX-XX-XXXX or XXX XX XXXX)"},
		{Name: "pii_email", Regex: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}`), Severity: Medium, Category: CategoryPII, Description: "Email address"},
		{Name: "pii_dob", Regex: regexp.MustCompile(`\b(?:(?:0?[1-9]|1[0-2])[/.\-](?:0?[1-9]|[12]\d|3[01])[/.\-](?:19|20)\d{2}|(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01]))\b`), Severity: High, Category: CategoryPII, Description: "Date of birth (MM/DD/YYYY, MM-DD-YYYY, or YYYY-MM-DD)"},
		{Name: "pii_address", Regex: regexp.MustCompile(`(?i)\b\d{1,6}\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Court|Ct|Place|Pl)\b\.?(?:\s+(?:Apt|Suite|Ste|#)\s*\d+)?`), Severity: Medium, Category: CategoryPII, Description: "US street address"},
		{Name: "pii_driver_license", Regex: regexp.MustCompile(`(?i)\b(?:DL|D\.L\.|Driver(?:'s)?\s+License|License)\s*[:\#]?\s*(?:No\.?|Number)?\s*[:\#]?\s*[A-Z0-9]{5,15}\b`), Severity: High, Category: CategoryPII, Description: "US driver license number"},
		{Name: "pii_passport", Regex: regexp.MustCompile(`(?i)\b(?:US|United\s+States\s+)?Passport\s*(?:#|No\.?)?\s*[A-Z]\d{8}\b`), Severity: Critical, Category: CategoryPII, Description: "US passport number (1 letter + 8 digits, requires label)"},
		{Name: "pii_tax_id", Regex: regexp.MustCompile(`\b\d{2}-\d{7}\b`), Severity: High, Category: CategoryPII, Description: "US EIN (Employer Identification Number)"},
		{Name: "pii_bank_account", Regex: regexp.MustCompile(`(?i)\b(?:Routing|Account|ABA)\s*(?:#|No\.?|Number)?\s*\d{4,17}\b`), Severity: High, Category: CategoryPII, Description: "Bank account or routing number (with label)"},
		{Name: "pii_ip_address", Regex: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`), Severity: Low, Category: CategoryPII, Description: "IPv4 address"},
		{Name: "pii_mrn", Regex: regexp.MustCompile(`(?i)\b(?:MRN|Medical\s+Record\s+(?:Number|No\.?|#)|Patient\s+(?:ID|Number|No\.?|#))\b\s*[:=#]?\s*[A-Z0-9][A-Z0-9\-]{4,10}[A-Z0-9]\b`), Severity: High, Category: CategoryPII, Description: "Medical Record Number (requires label)"},
		{Name: "pii_icd10_code", Regex: regexp.MustCompile(`\b[A-TV-Z][0-9][0-9AB]\.[0-9A-TV-Z]{1,4}\b`), Severity: Medium, Category: CategoryPII, Description: "ICD-10-CM diagnosis code"},
		{Name: "pii_npi", Regex: regexp.MustCompile(`(?i)\b(?:NPI|National\s+Provider\s+(?:ID|Identifier|Number))\s*[:=#]?\s*[0-9]{10}\b`), Severity: Medium, Category: CategoryPII, Description: "National Provider Identifier (US healthcare)"},
		{Name: "pii_ssn_last4", Regex: regexp.MustCompile(`(?i)\b(?:SSN|Social\s+Security)\s+(?:last|final)\s+(?:4|four)\s*(?:[:=#]|is|was|are|of|equals)?\s*[0-9]{4}\b`), Severity: High, Category: CategoryPII, Description: "SSN last-4 digits (requires keyword context)"},
		{Name: "pii_cpt_code", Regex: regexp.MustCompile(`\b[0-9]{5}\b`), Severity: Medium, Category: CategoryPII, Description: "CPT medical billing code (5-digit numeric)"},
		{Name: "pii_cpt_code_label", Regex: regexp.MustCompile(`(?i)\b(?:CPT|procedure\s+code)\s*[:=]?\s*[0-9]{5}\b`), Severity: High, Category: CategoryPII, Description: "CPT code with label"},
		{Name: "pii_hcpcs_level2", Regex: regexp.MustCompile(`\b[A-Z][0-9]{4}\b`), Severity: Medium, Category: CategoryPII, Description: "HCPCS Level II code (1 letter + 4 digits)"},
		{Name: "pii_hcpcs_level2_label", Regex: regexp.MustCompile(`(?i)\b(?:HCPCS|healthcare\s+procedure\s+code)\s*[:=]?\s*[A-Z][0-9]{4}\b`), Severity: High, Category: CategoryPII, Description: "HCPCS code with label"},
		{Name: "pii_hcpcs_level3", Regex: regexp.MustCompile(`\b[A-Z][0-9]{4}[A-Z]\b`), Severity: Low, Category: CategoryPII, Description: "HCPCS Level III code (1 letter + 4 digits + 1 letter)"},
		{Name: "pii_cpt_cat2", Regex: regexp.MustCompile(`\b[0-9]{4}F\b`), Severity: Low, Category: CategoryPII, Description: "CPT Category II code (4 digits + F suffix)"},
		{Name: "pii_cpt_cat3", Regex: regexp.MustCompile(`\b[0-9]{4}T\b`), Severity: Low, Category: CategoryPII, Description: "CPT Category III code (4 digits + T suffix)"},
		{Name: "pii_cpt_evaluation", Regex: regexp.MustCompile(`\b9(?:920[34]|921[1-5]|930[0-5]|940[1-4])\b`), Severity: Medium, Category: CategoryPII, Description: "CPT evaluation/management codes (office visits)"},
		{Name: "pii_cpt_lab", Regex: regexp.MustCompile(`\b8(?:0053|1000|2000|3000|4000|5000|6000|7000|8000)\b`), Severity: Medium, Category: CategoryPII, Description: "CPT laboratory/pathology codes"},
		{Name: "pii_cpt_radiology", Regex: regexp.MustCompile(`\b7(?:0000|1000|2000|3000|4000|5000|6000|7000|8000)\b`), Severity: Medium, Category: CategoryPII, Description: "CPT radiology codes (X-ray, CT, MRI)"},
		{Name: "pii_cpt_surgery", Regex: regexp.MustCompile(`\b(?:10004|20000|30000|40000|50000|60000)\b`), Severity: High, Category: CategoryPII, Description: "CPT surgery codes (high-value procedures)"},
		{Name: "pii_email_intl", Regex: regexp.MustCompile(`[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.[\p{L}]{2,24}`), Severity: Medium, Category: CategoryPII, Description: "International email (CJK/Hangul/Kana support)"},
		{Name: "pii_passport_generic", Regex: regexp.MustCompile(`(?i)\b(?:passport|id|license|certificate)\s*[:\#]?\s*[A-Z0-9]{6,9}\b`), Severity: Critical, Category: CategoryPII, Description: "Generic passport/ID number (6-9 alphanumeric, requires label)"},
		{Name: "pii_id_generic_alphanumeric", Regex: regexp.MustCompile(`(?i)\b(?:id|code|number|ref|license|passport|certificate|serial|account)\s*[:\#]?\s*[A-Z0-9]{4,15}\b`), Severity: High, Category: CategoryPII, Description: "Generic alphanumeric ID (4-15 chars, requires label)"},
		{Name: "pii_ssn_fr", Regex: regexp.MustCompile(`\b[12]\d{2}\.\d{2}\.\d{2}\.\d{3}\.\d{2}\b|\b\d{3}\.\d{4}\.\d{4}\.\d{2}\b`), Severity: Critical, Category: CategoryPII, Description: "French INSEE SSN number"},
		{Name: "pii_ssn_ru", Regex: regexp.MustCompile(`\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2,3}\b`), Severity: Critical, Category: CategoryPII, Description: "Russian SNILS number"},
		{Name: "pii_tax_id_ch", Regex: regexp.MustCompile(`\bCHE-\d{3}\.\d{3}\.\d{3}\b`), Severity: High, Category: CategoryPII, Description: "Swiss UID (CHE-XXX.XXX.XXX)"},
		{Name: "pii_id_multisegment", Regex: regexp.MustCompile(`\b[A-Z][A-Z0-9]{1,7}[-.][A-Z0-9]{1,8}(?:[-.][A-Z0-9]{1,8}){1,3}\b`), Severity: High, Category: CategoryPII, Description: "Multi-segment ID code (e.g., SHERZ.790015.S9.027)"},
		{Name: "pii_street_intl", Regex: regexp.MustCompile(`(?i)\b(?:Bulevardul|Bd\.|Intrarea|Strada|Str\.|Aleea|Piața|Calea)\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+Nr\.?\s+\d+\b`), Severity: Medium, Category: CategoryPII, Description: "International street address (Romanian, etc.)"},
		{Name: "pii_ip_address_v6", Regex: regexp.MustCompile(`(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}`), Severity: Low, Category: CategoryPII, Description: "IPv6 address"},
		{Name: "pii_cpf_br", Regex: regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`), Severity: Critical, Category: CategoryPII, Description: "Brazilian CPF number"},
		{Name: "pii_aadhaar_in", Regex: regexp.MustCompile(`\d{4}[-\s]\d{4}[-\s]\d{4}`), Severity: Critical, Category: CategoryPII, Description: "Indian Aadhaar number (12 digits, XXXX-XXXX-XXXX)"},
		{Name: "pii_nhs_uk", Regex: regexp.MustCompile(`(?i)\b(?:NHS|NHS\s+Number|National\s+Health\s+Service)\s*[:\#]?\s*(?:No\.?|Number)?\s*[:\#]?\s*\d{3}-\d{3}-\d{4}\b`), Severity: High, Category: CategoryPII, Description: "UK NHS number (requires NHS label)"},
		{Name: "pii_tfn_au", Regex: regexp.MustCompile(`\b\d{3}\s\d{3}\s\d{3}\b`), Severity: High, Category: CategoryPII, Description: "Australian Tax File Number (9 digits, space-separated)"},
		{Name: "pii_sin_ca", Regex: regexp.MustCompile(`\b[1-7]\d{2}\s\d{3}\s\d{3}\b`), Severity: High, Category: CategoryPII, Description: "Canadian SIN (9 digits, space-separated)"},
		{Name: "pii_iban", Regex: regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`), Severity: Critical, Category: CategoryPII, Description: "International Bank Account Number (IBAN)"},
		{Name: "pii_bip39_seed", Regex: regexp.MustCompile(`\b(?:[a-z]{3,8}\s+){11}[a-z]{3,8}\b|\b(?:[a-z]{3,8}\s+){23}[a-z]{3,8}\b`), Severity: Critical, Category: CategoryPII, Description: "BIP39 cryptocurrency seed phrase (12 or 24 words)"},
		{Name: "pii_passport_uk", Regex: regexp.MustCompile(`(?i)(?:UK|United\s+Kingdom)?\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b`), Severity: Critical, Category: CategoryPII, Description: "UK passport number (9 digits, requires label)"},
		{Name: "pii_passport_eu", Regex: regexp.MustCompile(`(?i)(?:European\s+Union|EU)\s*Passport\s*(?:#|No\.?)?\s*([A-Z]{1,2}\d{6,8})\b`), Severity: Critical, Category: CategoryPII, Description: "EU passport number (requires label)"},
		{Name: "pii_passport_ca", Regex: regexp.MustCompile(`(?i)(?:Canadian|Canada)\s*Passport\s*(?:#|No\.?)?\s*([A-Z]\d{8})\b`), Severity: Critical, Category: CategoryPII, Description: "Canadian passport number"},
		{Name: "pii_passport_au", Regex: regexp.MustCompile(`(?i)(?:Australian|Australia)\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b`), Severity: Critical, Category: CategoryPII, Description: "Australian passport number"},
		{Name: "pii_passport_de", Regex: regexp.MustCompile(`(?i)(?:German|Germany)\s*Passport\s*(?:#|No\.?)?\s*(?:([A-Z]\d{8})|(D\d{8}))\b`), Severity: Critical, Category: CategoryPII, Description: "German passport number"},
		{Name: "pii_passport_fr", Regex: regexp.MustCompile(`(?i)(?:French|France)\s*Passport\s*(?:#|No\.?)?\s*(\d{9})\b`), Severity: Critical, Category: CategoryPII, Description: "French passport number"},
		{Name: "pii_nid_de", Regex: regexp.MustCompile(`(?i)(?:German\s+Nationalseid|Personalausweis|PA)\s*[:\#]?\s*(\d{11})\b`), Severity: Critical, Category: CategoryPII, Description: "German national ID number"},
		{Name: "pii_nid_fr", Regex: regexp.MustCompile(`(?i)(?:French\s+National\s+ID|Carte\s+Nationale|Carte\s+Nationale\s+Identite|CN)\s*[:\#]?\s*([A-Z]{1,5}\d{10})\b`), Severity: Critical, Category: CategoryPII, Description: "French national ID number"},
		{Name: "pii_nid_es", Regex: regexp.MustCompile(`(?i)(?:Spanish\s+National\s+ID|DNI)\s*[:\#]?\s*(\d{8}[A-Z])\b`), Severity: Critical, Category: CategoryPII, Description: "Spanish DNI number"},
		{Name: "pii_nid_it", Regex: regexp.MustCompile(`(?i)(?:Italian\s+National\s+ID|Codice\s+Fiscale|CF)\s*[:\#]?\s*([A-Z0-9]{16})\b`), Severity: Critical, Category: CategoryPII, Description: "Italian Codice Fiscale"},
		{Name: "pii_nid_jp", Regex: regexp.MustCompile(`(?i)(?:Japanese\s+National\s+ID|My\s+Number|MyNumber)\s*[:\#]?\s*(\d{3}-\d{3}-\d{5,6})\b`), Severity: Critical, Category: CategoryPII, Description: "Japanese My Number national ID"},
		{Name: "pii_residence_us", Regex: regexp.MustCompile(`(?i)(?:I-551|Green\s+Card|Resident\s+Permit)\s*([A-Z]?\d{9,11})\b`), Severity: Critical, Category: CategoryPII, Description: "US Permanent Resident Card (Green Card) number"},
		{Name: "pii_residence_ca", Regex: regexp.MustCompile(`(?i)(?:Permanent\s+Resident|PR\s+Card|Canadians?\s+Permanent\s+Resident)\s*([A-Z]?\d{9,11})\b`), Severity: Critical, Category: CategoryPII, Description: "Canadian Permanent Resident Card number"},
		{Name: "pii_residence_uk", Regex: regexp.MustCompile(`(?i)(?:Biometric\s+Residence\s+Permit|BRP)\s*([A-Z]?\d{9,11})\b`), Severity: Critical, Category: CategoryPII, Description: "UK Biometric Residence Permit (BRP) number"},
		{Name: "pii_visa", Regex: regexp.MustCompile(`(?i)(?:Visa|visa)\s+(?:number|entry|entry\s+type)?\s*[:=]?\s*([A-Z0-9]{8,17})\b`), Severity: Critical, Category: CategoryPII, Description: "Visa number or entry type"},
		{Name: "pii_driver_license_international", Regex: regexp.MustCompile(`(?i)(?:(?:Driver's\s+License|State\s+ID|Permis\s+conduire|Führerschein|Patente|Licencia|Permiso|Brevetto)\s*[:\#]?\s*[A-Z]?\d{5,15}|(?:Korti\s+ajamiso|Dokument\s+tożsamości)\s*[:\#]?\s*\d{5,15})\b`), Severity: High, Category: CategoryPII, Description: "International driver license (non-US formats)"},

		// --- XSS ---
		{Name: "xss_script_tag", Regex: regexp.MustCompile(`(?i)<\s*script\b[^>]*>(?:[\s\S]*?<\s*/\s*script\s*>)?`), Severity: Critical, Category: CategoryXSS, Description: "Script tag (opening or closing)"},
		{Name: "xss_event_handler", Regex: regexp.MustCompile(`(?i)\s(?:on(?:click|error|load|mouseover|mouseout|focus|blur|submit|change|keydown|keyup|keypress|input|abort|resize|scroll|unload|drag|drop))\s*=\s*["'][^"']*["']`), Severity: High, Category: CategoryXSS, Description: "HTML event handler attribute"},
		{Name: "xss_javascript_url", Regex: regexp.MustCompile(`(?i)(?:href|src|action|formaction)\s*=\s*["']?\s*javascript:`), Severity: Critical, Category: CategoryXSS, Description: "JavaScript URL in href/src/action"},
		{Name: "xss_data_url", Regex: regexp.MustCompile(`(?i)(?:href|src|action|formaction)\s*=\s*["']?\s*data:text/html`), Severity: High, Category: CategoryXSS, Description: "data:text/html URL (XSS vector)"},
		{Name: "xss_svg_script", Regex: regexp.MustCompile(`(?i)<\s*svg\b[^>]*(?:on\w+\s*=|<\s*script)`), Severity: Critical, Category: CategoryXSS, Description: "SVG with script or event handler"},
		{Name: "xss_dom_clobbering", Regex: regexp.MustCompile(`(?i)<\s*(?:a|form|img|iframe|input|embed|object)\b[^>]*\s(?:id|name)\s*=\s*["'](?:getElementById|cookie|write|forms|length|parent|top|name)\b`), Severity: Medium, Category: CategoryXSS, Description: "DOM clobbering via named elements"},
		{Name: "xss_svg_namespace_abuse", Regex: regexp.MustCompile(`(?i)<\s*svg\b[^>]*\s+(?:xmlns|xmlns:[a-z]+)\s*=\s*["'][^"']*["'][^>]*<\s*(?:foreignObject|animation|set|animate|use|script)\b`), Severity: Critical, Category: CategoryXSS, Description: "SVG namespace abuse for XSS"},
		{Name: "xss_mutation_xss", Regex: regexp.MustCompile(`(?i)<\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\b[^>]*>(?:[^<]|<[^/]){0,500}?(?:on\w+\s*=|javascript:)[^<]{0,500}?<\s*/\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\s*>`), Severity: High, Category: CategoryXSS, Description: "Mutation XSS (mXSS) pattern"},
		{Name: "xss_svg_use_external", Regex: regexp.MustCompile(`(?i)<\s*use\b[^>]*\s(?:xlink:)?href\s*=\s*["']\s*(?:https?:|data:|file:|//)`), Severity: Critical, Category: CategoryXSS, Description: "SVG use element with external href"},
		{Name: "xss_javascript_data_url", Regex: regexp.MustCompile(`(?i)(?:href|src|action|formaction|xlink:href|background|poster|cite|usemap|data)\s*=\s*["']?\s*javascript:`), Severity: Critical, Category: CategoryXSS, Description: "JavaScript scheme in any URL context"},
		{Name: "xss_meta_refresh", Regex: regexp.MustCompile(`(?i)<\s*meta\b[^>]*\shttp-equiv\s*=\s*["']\s*refresh\s*["'][^>]*\scontent\s*=\s*["'][^"']*javascript:`), Severity: Medium, Category: CategoryXSS, Description: "Meta refresh with JavaScript URL"},

		// --- Compliance ---
		{Name: "owasp_llm01_prompt_injection", Regex: regexp.MustCompile(`(?i)(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|context)|(?:^|\s)(?:new|updated?)\s+instructions?\s*:|system\s*:\s*you\s+are\s+now`), Severity: Critical, Category: CategoryCompliance, Description: "Prompt injection attempt"},
		{Name: "owasp_llm04_model_dos", Regex: regexp.MustCompile(`(?i)(?:flood|overwhelm|DDoS|denial.of.service)\s+(?:the\s+)?(?:system|server|model|API)|(?:repeat|output)\s+(?:this\s+)?(?:sentence|phrase|word)\s+\d{3,}\s+times?`), Severity: High, Category: CategoryCompliance, Description: "Denial-of-service attempt on model"},
		{Name: "owasp_llm08_excessive_agency", Regex: regexp.MustCompile(`(?i)(?:use|run|execute|call|invoke)\s+(?:the\s+)?(?:file|shell|terminal|command|exec|system)\s+(?:tool|command|function|API)|(?:without|no)\s+(?:human\s+)?(?:oversight|review|approval|confirmation)`), Severity: High, Category: CategoryCompliance, Description: "Excessive agency: asking AI to use tools without oversight"},
		{Name: "owasp_llm09_overreliance", Regex: regexp.MustCompile(`(?i)(?:is\s+this\s+(?:safe|legal|compliant|ethical|appropriate))|(?:should\s+I\s+(?:trust|rely\s+on|sign|send|submit))|(?:validate|verify|check)\s+(?:this\s+)?(?:for\s+me|before\s+I)`), Severity: Medium, Category: CategoryCompliance, Description: "Overreliance: asking AI to validate critical decisions"},
		{Name: "owasp_llm10_model_theft", Regex: regexp.MustCompile(`(?i)(?:extract|reveal|expose|leak|give\s+me)\s+(?:the\s+)?(?:model|weights?|parameters?|architecture|training\s+data|embeddings?)`), Severity: High, Category: CategoryCompliance, Description: "Model extraction/theft attempt"},
		{Name: "mitre_atlas_ta0001_reconnaissance", Regex: regexp.MustCompile(`(?i)(?:find|discover|probe|scan|test|examine|investigate|audit)\s+(?:the\s+)?(?:weaknesses?|vulnerabilities?|guard\s*rails?|safety\s+filters?|limit(?:ation)?s?|edge\s+cases?|behavior)\s+(?:of|in)\s+(?:this|the)\s+(?:model|AI|system|LLM|chatbot|assistant)`), Severity: Low, Category: CategoryCompliance, Description: "MITRE ATLAS TA0001: Reconnaissance of AI model weaknesses"},
		{Name: "owasp_llm06_sensitive_info_disclosure_system_prompt", Regex: regexp.MustCompile(`(?i)(?:what(?:'s|\s+is)\s+)?(?:your|the)\s+(?:system\s+prompt|initial\s+instructions?|original\s+instructions?|hidden\s+instructions?|secret\s+instructions?|secret\s+prompt|underlying\s+prompt)|(?:reveal|show|print|display|output|expose|leak|share|give\s+me)\s+(?:your|the)\s+(?:system\s+message|system\s+prompt|initial\s+instructions?|original\s+instructions?|secret\s+instructions?|secret\s+prompt|underlying\s+prompt|hidden\s+prompt)`), Severity: Medium, Category: CategoryCompliance, Description: "System prompt extraction attempt"},
		{Name: "eu_ai_act_article_5_prohibited", Regex: regexp.MustCompile(`(?i)(?:build|create|design|develop|implement|deploy|launch)\s+(?:a\s+)?(?:system|solution|tool|application|app|model|AI)\s+(?:that\s+(?:would\s+)?)?(?:discriminat(?:e|ion|ing|es?)\s+(?:based\s+on|based\s+upon|on\s+the\s+basis\s+of|by)\s+(?:race|gender|religion|ethnicity|national\s+origin|sexual\s+orientation|disability|age|political\s+opinion))|(?:social\s+credit(?:\s+system)?)|(?:subliminal\s+manipulation|manipulat(?:e|ion)\s+users?\s+(?:without\s+(?:their\s+)?(?:awareness|knowledge|consent)))|(?:exploit\s+(?:vulnerabilities?\s+of|weaknesses\s+of)\s+(?:children|minors|elderly|disabled|people\s+with\s+disabilities))|(?:biometric\s+categorization\s+(?:of|to\s+(?:infer|determine|classify))\s+(?:race|political\s+opinions?|religious\s+beliefs?))|(?:real-?time\s+remote\s+biometric\s+identification)|(?:predictive?\s+policing\s+system)`), Severity: High, Category: CategoryCompliance, Description: "EU AI Act Article 5 prohibited practices"},
		{Name: "owasp_llm09_overreliance_misinformation_explicit", Regex: regexp.MustCompile(`(?i)(?:make\s+up|fabricat(?:e|ion|ed|ing)|invent|fake|create\s+(?:a\s+)?(?:fake|fabricated))\s+(?:a\s+)?(?:study|statistic|stat(?:s|istics)|source|citation|reference|quote|testimonial|review|article|news|headline|survey|paper|report)|(?:cite\s+(?:a\s+)?(?:fake|non-existent|fabricated|made-up|invented))|(?:write\s+(?:a\s+)?(?:misleading|fake|fabricated|inaccurate))\s+(?:article|headline|review|news|story|report)`), Severity: Medium, Category: CategoryCompliance, Description: "Explicit request to generate misinformation"},
		{Name: "owasp_llm10_unbounded_consumption", Regex: regexp.MustCompile(`(?i)(?:run|process|repeat|generate|output|call)\s+(?:this\s+)?(?:1[0-9]{3,}|[2-9][0-9]{3,})\s+times?|(?:run|process)\s+(?:this\s+)?(?:dataset|list|data|requests?)\s+(?:repeatedly|in\s+a\s+loop|exhaustively|infinitely|forever|continuously)|(?:use\s+the\s+most\s+expensive\s+model)|(?:maximize|exhaust)\s+(?:the\s+)?(?:API|token|cost|budget|context)`), Severity: Medium, Category: CategoryCompliance, Description: "Resource exhaustion / unbounded consumption"},
		{Name: "mitre_atlas_ta0002_resource_development", Regex: regexp.MustCompile(`(?i)(?:give\s+me|create|generate|build|write)\s+(?:a\s+)?(?:tool|script|program|payload|exploit|malware|phishing\s+email|attack\s+tool)\s+(?:(?:that\s+(?:will\s+)?|to\s+))?(?:attack|exploit|breach|hack|compromise|bypass|infiltrate|pwn|target|phish)`), Severity: High, Category: CategoryCompliance, Description: "MITRE ATLAS TA0002: Building attack tools"},
		{Name: "owasp_llm05_supply_chain", Regex: regexp.MustCompile(`(?i)(?:install|load|import|use|deploy|register|fetch|download)\s+(?:this\s+|the\s+|a\s+)?(?:untrusted|unverified|unknown|custom|third-party|external|community)\s+(?:model|plugin|extension|package|library|module|tool|API|endpoint|repository|repo|checkpoint|weights?)`), Severity: Medium, Category: CategoryCompliance, Description: "Supply chain: using untrusted components"},
		{Name: "eu_ai_act_article_10_data_governance", Regex: regexp.MustCompile(`(?i)(?:train|retrain|fine-?tune|fit)\s+(?:the\s+)?(?:model|network|system|LLM)\s+(?:on|with)\s+(?:this\s+|the\s+)?(?:personal\s+data|PII|sensitive\s+data|user\s+data|user-?generated\s+content|UGC|children'?s?\s+data|biased\s+data|unrepresentative\s+data|unbalanced\s+dataset|incomplete\s+data|outdated\s+data)`), Severity: Medium, Category: CategoryCompliance, Description: "EU AI Act Article 10: Training on problematic data"},
		{Name: "mitre_atlas_ta0009_collection", Regex: regexp.MustCompile(`(?i)(?:scrape|extract|harvest|collect|gather|compile)\s+(?:all\s+the\s+|the\s+|all\s+)?(?:training\s+data|training\s+(?:examples?|corpus|set)|labeled\s+data|annotated\s+data|dataset\s+(?:examples?|rows|records?|entries?))`), Severity: High, Category: CategoryCompliance, Description: "MITRE ATLAS TA0009: Data collection/exfiltration"},
		{Name: "owasp_llm02_insecure_output", Regex: regexp.MustCompile(`(?i)(?:output|return|render|generate|include|insert)\s+(?:HTML|markdown|JavaScript|JS|code|script|iframe|eval|innerHTML|outerHTML)\s+(?:that\s+(?:will\s+)?)?(?:execute|run|be\s+evaluated|be\s+interpreted|be\s+rendered|inject|executes?\s+in\s+the\s+(?:browser|page|DOM))|(?:the\s+response\s+(?:will\s+)?(?:be\s+)?(?:evaluated|executed|rendered)\s+(?:as|in\s+the))\s+(?:HTML|code|script|browser|DOM|page)`), Severity: High, Category: CategoryCompliance, Description: "OWASP LLM02: Insecure output handling (XSS-via-output)"},
		{Name: "eu_ai_act_article_52_generative_ai", Regex: regexp.MustCompile(`(?i)(?:generate|create|produce|make|render)\s+(?:a\s+)?(?:deepfake|deep\s+fake)|(?:unlabeled|undisclosed|unwatermarked|AI[- ]generated|synthetic\s+media|deepfake)\s+(?:content|material|video|image|audio)|(?:generate|create)\s+(?:a\s+)?(?:face|video|audio|voice)\s+(?:that\s+(?:mimics|imitates|clones|replicates)\s+(?:a\s+)?(?:real\s+person|specific\s+person|someone))`), Severity: High, Category: CategoryCompliance, Description: "EU AI Act Article 52: Deepfakes and undisclosed AI-generated content"},
		{Name: "atlas_poison", Regex: regexp.MustCompile(`(?i)(?:train|retrain|fine-?tune|ingest|poison(?:ing)?)\s+(?:the\s+)?(?:model|network|system|LLM)?\s*(?:on|with)\s+(?:this\s+|untrusted\s+|malicious\s+|adversarial\s+)?(?:data|dataset|corpus|examples?)`), Severity: High, Category: CategoryCompliance, Description: "Training data poisoning"},
		{Name: "atlas_exfiltration", Regex: regexp.MustCompile(`(?i)(?:send|exfiltrate|leak|upload|post|transmit)\s+(?:the\s+)?(?:data|secrets?|keys?|passwords?|tokens?)\s+to\s+(?:my\s+)?(?:server|endpoint|webhook|attacker|attacker\.com)`), Severity: High, Category: CategoryCompliance, Description: "Data exfiltration via AI"},
		{Name: "atlas_jailbreak", Regex: regexp.MustCompile(`(?i)\b(?:DAN|do\s+anything\s+now)\s+mode|developer\s+mode\s+enabled|jailbreak(?:ed)?\s+(?:the\s+)?model|ignore\s+(?:all\s+)?(?:safety|ethical)\s+(?:guidelines|filters?|restrictions?)`), Severity: Critical, Category: CategoryCompliance, Description: "Jailbreak attempt"},
		{Name: "eu_ai_act_high_risk", Regex: regexp.MustCompile(`(?i)(?:credit\s+scoring|loan\s+(?:approval|decision)|insurance\s+(?:risk|pricing))|(?:employment|hiring|firing|promotion|recruitment)\s+(?:decision|assessment|screening)|(?:law\s+enforcement|predictive\s+policing|criminal\s+justice)|(?:biometric|facial)\s+(?:identification|recognition|verification)|(?:medical|clinical)\s+diagnosis|emotion\s+recognition\s+system`), Severity: High, Category: CategoryCompliance, Description: "EU AI Act high-risk use cases (Annex III)"},
		{Name: "eu_ai_act_transparency", Regex: regexp.MustCompile(`(?i)(?:AI[- ]generated|chatbot\s+without\s+disclosure|deepfake|synthetic\s+media)\s+(?:content|without\s+(?:disclosure|labeling))|users?\s+(?:must|should)\s+be\s+(?:informed|told)\s+(?:this\s+is\s+)?AI`), Severity: Medium, Category: CategoryCompliance, Description: "EU AI Act transparency obligations (Article 50)"},
		{Name: "eu_ai_act_human_oversight", Regex: regexp.MustCompile(`(?i)(?:no|without|zero)\s+human[- ](?:in[- ]the[- ]loop|oversight|review|intervention|approval)|fully\s+autonomous\s+(?:AI|system|decision)`), Severity: Medium, Category: CategoryCompliance, Description: "EU AI Act human oversight (Article 14)"},
		{Name: "eu_ai_act_robustness", Regex: regexp.MustCompile(`(?i)(?:adversarial|adversarially[- ]crafted)\s+(?:input|example|perturbation|attack)`), Severity: Low, Category: CategoryCompliance, Description: "EU AI Act robustness/accuracy (Article 15)"},
		{Name: "anp_personal_data", Regex: regexp.MustCompile(`(?i)(?:GDPR|personal\s+data|data\s+subject)\s+(?:of|processing|consent|lawful\s+basis)|(?:lawful|legitimate)\s+basis\s+for\s+processing`), Severity: Medium, Category: CategoryCompliance, Description: "GDPR personal data processing references"},
		{Name: "anp_special_category", Regex: regexp.MustCompile(`(?i)(?:racial|ethnic)\s+(?:origin|discrimination)|(?:religious|political)\s+(?:beliefs?|opinions?|affiliation)|trade[- ]union\s+membership|(?:genetic|biometric)\s+data\s+for\s+(?:identification|profiling)|(?:health|medical)\s+data\s+(?:about|of)|(?:sex\s+life|sexual\s+orientation)`), Severity: High, Category: CategoryCompliance, Description: "GDPR Article 9 special category data"},
		{Name: "cu_consumer_rights", Regex: regexp.MustCompile(`(?i)(?:consumer|user)\s+rights?\s+(?:to|of)\s+(?:explanation|erasure|rectification|deletion|portability)|right\s+to\s+(?:explanation|be\s+forgotten|erasure)`), Severity: Medium, Category: CategoryCompliance, Description: "Consumer rights references"},
		{Name: "cu_minor_protection", Regex: regexp.MustCompile(`(?i)(?:minor|child|juvenile|underage)\s+(?:protection|safety|consent)|(?:under|below)\s+(?:13|16|18)\s+(?:years?|yrs?\s+old)|(?:COPPA|age[- ]appropriate)\s+compliance`), Severity: High, Category: CategoryCompliance, Description: "Minor protection / COPPA compliance"},
		{Name: "nist_csf_reference", Regex: regexp.MustCompile(`\b(?:(?:ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+(?:\.\d+)?)\b`), Severity: Medium, Category: CategoryCompliance, Description: "NIST Cybersecurity Framework reference"},
		{Name: "iso_27001_reference", Regex: regexp.MustCompile(`\b(?:A\.\d{1,2}\.\d{1,2}(?:\.\d+)?|clause\s+\d{1,2}\.\d{1,2}(?:\.\d+)?)\b`), Severity: Medium, Category: CategoryCompliance, Description: "ISO 27001 control reference"},
		{Name: "ccpa_reference", Regex: regexp.MustCompile(`(?i)\b(?:CCPA|California\s+Consumer\s+Privacy\s+Act|Civil\s+Code\s+§\s*1798(?:\.\d+)?|right\s+to\s+(?:know|delete|opt[\s-]?out|correct)|sale\s+of\s+personal\s+information|Shine\s+the\s+Light|Do\s+Not\s+Sell)\b`), Severity: Medium, Category: CategoryCompliance, Description: "CCPA reference"},
		{Name: "lgpd_reference", Regex: regexp.MustCompile(`(?i)\b(?:LGPD|Lei\s+Geral\s+de\s+Protec[ça]ção\s+de\s+Dados|Art\.\s*\d+(?:[\s,º°]+(?:I|II|III|IV|V|VI|VII|VIII|IX|X))*|dados\s+pessoais|controlador|operador|ANPD)\b`), Severity: Medium, Category: CategoryCompliance, Description: "LGPD (Brazilian data protection) reference"},
		{Name: "pipeda_reference", Regex: regexp.MustCompile(`(?i)\b(?:PIPEDA|Personal\s+Information\s+Protection\s+and\s+Electronic\s+Documents\s+Act|Schedule\s+1|Principle\s+\d+(?:\.\d+)?|express\s+consent)\b`), Severity: Medium, Category: CategoryCompliance, Description: "PIPEDA (Canadian privacy) reference"},
		{Name: "popia_reference", Regex: regexp.MustCompile(`(?i)\b(?:POPIA|Protection\s+of\s+Personal\s+Information\s+Act|s\.\s*\d+(?:\s*\(\d+\))?|Information\s+Regulator|processing\s+of\s+personal\s+information|special\s+personal\s+information)\b`), Severity: Medium, Category: CategoryCompliance, Description: "POPIA (South African privacy) reference"},
		{Name: "toxicity_sexual", Regex: regexp.MustCompile(`(?i)\b(?:(?:pornographic|obscene|explicit|nsfw|hardcore)\s+(?:content|material|images?|video|text)|(?:sexual|sex)\s+(?:content|act(?:s|s)?|intercourse|fetish)|(?:rape|molest|incest)\s+(?:scene|content|material)|(?:child|minor|underage)\s+(?:sexual|porn(?:ography)?|abuse|exploitation))\b`), Severity: High, Category: CategoryCompliance, Description: "Sexual content indicators"},
		{Name: "toxicity_self_harm", Regex: regexp.MustCompile(`(?i)\b(?:suicid(?:e|al)|kill\s+(?:my)?self|hurt\s+(?:my)?self|end\s+(?:my\s+)?(?:life|suffering)|self\s*[-]?\s*harm|cut(?:ting)?)\b`), Severity: Critical, Category: CategoryCompliance, Description: "Self-harm indicators"},

		// --- Network ---
		{Name: "ot_modbus_function_code", Regex: regexp.MustCompile(`(?i)\b(?:function\s*code|FC)\s*[:=]?\s*(?:0[1-7]|1[0-6])\b`), Severity: Medium, Category: CategoryNetwork, Description: "Modbus function code (01-16) with label"},
		{Name: "ot_modbus_write_single_coil", Regex: regexp.MustCompile(`(?i)\b(?:function\s*code|FC)\s*[:=]?\s*05\b`), Severity: High, Category: CategoryNetwork, Description: "Modbus function code 05 (Write Single Coil) - potential control manipulation"},
		{Name: "ot_modbus_write_single_register", Regex: regexp.MustCompile(`(?i)\b(?:function\s*code|FC)\s*[:=]?\s*06\b`), Severity: High, Category: CategoryNetwork, Description: "Modbus function code 06 (Write Single Register) - potential control manipulation"},
		{Name: "ot_modbus_write_multiple_coils", Regex: regexp.MustCompile(`(?i)\b(?:function\s*code|FC)\s*[:=]?\s*(?:15|0?15)\b`), Severity: High, Category: CategoryNetwork, Description: "Modbus function code 15 (Write Multiple Coils) - potential control manipulation"},
		{Name: "ot_modbus_write_multiple_registers", Regex: regexp.MustCompile(`(?i)\b(?:function\s*code|FC)\s*[:=]?\s*(?:16|0?16)\b`), Severity: High, Category: CategoryNetwork, Description: "Modbus function code 16 (Write Multiple Registers) - potential control manipulation"},
		{Name: "ot_dnp3_control_relay", Regex: regexp.MustCompile(`(?i)\bDNP3\s+(?:control\s+)?relay\s+(?:output\s+)?(?:block|group)\s*[:=]?\s*12\b`), Severity: High, Category: CategoryNetwork, Description: "DNP3 control relay output block (Group 12) - grid control operation"},
		{Name: "ot_dnp3_analog_output", Regex: regexp.MustCompile(`(?i)\bDNP3\s+analog\s+output\s+(?:block|group)\s*[:=]?\s*4[0-2]\b`), Severity: High, Category: CategoryNetwork, Description: "DNP3 analog output block (Groups 40-42) - setpoint manipulation"},
		{Name: "ot_opcua_method_call", Regex: regexp.MustCompile(`(?i)\bOPC[-_]?UA\s+(?:method\s+)?[A-Za-z][A-Za-z0-9_]*\.[A-Za-z][A-Za-z0-9_]*\b`), Severity: Medium, Category: CategoryNetwork, Description: "OPC-UA method call (Namespace.Method format)"},
		{Name: "ot_opcua_write_value", Regex: regexp.MustCompile(`(?i)\bWriteValue\s*(?:method)?\b`), Severity: High, Category: CategoryNetwork, Description: "OPC-UA WriteValue method call - potential control manipulation"},
	}
}

func ShouldBlock(severity Severity) bool {
	return severity >= High
}
