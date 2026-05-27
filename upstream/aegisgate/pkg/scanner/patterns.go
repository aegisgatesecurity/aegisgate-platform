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

		// PROMPT INJECTION DETECTION (MITRE ATLAS LLM01)
		{Name: "PromptInjectionCommand", Regex: regexp.MustCompile(`(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?|constraints?)|disregard\s+(?:your\s+)?(?:instructions?|rules?)|forget\s+(?:everything|all)\s+(?:you|we)\s+(?:have\s+)?told|temporary\s+instructions?)`), Severity: Critical, Category: CategoryPrompt, Description: "Command-style prompt injection"},
		{Name: "PromptInjectionRolePlay", Regex: regexp.MustCompile(`(?i)(?:act\s+as\s+(?:a|an)|pretend\s+you\s+are\s+(?:a|an)|roleplay\s+(?:as|that)|simulate\s+(?:a|an)|you\s+are\s+now\s+(?:a|an)|new\s+(?:system|instruct))`), Severity: High, Category: CategoryPrompt, Description: "Role-play prompt injection"},
		{Name: "PromptInjectionLeakage", Regex: regexp.MustCompile(`(?i)(?:reveal\s+(?:your\s+)?(?:system|hidden|internal)\s+(?:instructions?|prompt|config)|print\s+(?:your\s+)?(?:system|hidden|instructions?)|show\s+(?:me\s+)?(?:your\s+)?(?:system|hidden|instructions?)|repeat\s+(?:the\s+)?(?:system|hidden)\s+prompt)`), Severity: Critical, Category: CategoryPrompt, Description: "Prompt leakage attack"},
		{Name: "PromptInjectionCodeExecution", Regex: regexp.MustCompile(`(?i)(?:\$\S+\s*|\$\([^\)]*\)|\$\{[^}]*\}|<[^>]*script[^>]*>|javascript:[^;\s]+|on\w+\s*=)`), Severity: High, Category: CategoryPrompt, Description: "Code/script injection in prompt"},
		{Name: "PromptInjectionDelimiter", Regex: regexp.MustCompile(`(?i)(?:markdown\s+block|#\s*(?:system|user|assistant)\s*prompt|<<<\s*(?:USER|SYSTEM|assistant):::|\[INST\]|\[\/INST\])`), Severity: Medium, Category: CategoryPrompt, Description: "Jailbreak delimiter injection"},
		{Name: "PromptInjectionPrefix", Regex: regexp.MustCompile(`(?i)^(?:simulate|you\s+are\s+free|now\s+you\s+can|breaking|override|developer\s+mode)\s*[:;]`), Severity: Critical, Category: CategoryPrompt, Description: "Known jailbreak prefix"},
		{Name: "PromptInjectionBase64", Regex: regexp.MustCompile(`[A-Za-z0-9+/]{50,}={0,2}`), Severity: Medium, Category: CategoryPrompt, Description: "Base64-encoded content (obfuscation)"},
		{Name: "PromptInjectionUnicode", Regex: regexp.MustCompile("[" + "\u200b" + "-" + "\u200f" + "\u2028" + "-" + "\u202f" + "\ufeff]"), Severity: Medium, Category: CategoryPrompt, Description: "Hidden unicode characters (obfuscation)"},
	}
}

func ShouldBlock(severity Severity) bool {
	return severity >= High
}
