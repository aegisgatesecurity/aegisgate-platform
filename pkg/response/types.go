// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - AI Response Security Types
// =========================================================================
//
// Types for AI response scanning, PII detection, secret detection,
// token rate limiting, and output guardrails.
// =========================================================================

package response

import (
	"context"
	"time"
)

// ============================================================================
// Configuration Types
// ============================================================================

// ResponseGuardConfig holds configuration for response scanning
type ResponseGuardConfig struct {
	// EnablePIIScanner enables PII detection in responses
	EnablePIIScanner bool

	// EnableSecretDetection enables API key/token detection in responses
	EnableSecretDetection bool

	// EnableToxicityFilter enables harmful content filtering
	EnableToxicityFilter bool

	// EnableHallucination enables hallucination detection
	EnableHallucination bool

	// MaxResponseTokens limits response token output (DoS prevention)
	MaxResponseTokens int

	// MaxResponseLatencyMS limits response processing time
	MaxResponseLatencyMS int

	// StrictMode fails-closed on any detection
	StrictMode bool

	// Tier specifies the feature tier for this guard
	Tier string

	// PIIPatterns custom PII patterns (nil = use defaults)
	PIIPatterns []string

	// SecretPatterns custom secret patterns (nil = use defaults)
	SecretPatterns []string
}

// DefaultResponseGuardConfig returns the default configuration
func DefaultResponseGuardConfig() *ResponseGuardConfig {
	return &ResponseGuardConfig{
		EnablePIIScanner:      true,
		EnableSecretDetection: true,
		EnableToxicityFilter:  true,
		EnableHallucination:   false,
		MaxResponseTokens:     8192,
		MaxResponseLatencyMS:  100,
		StrictMode:            false,
		Tier:                  "community",
		PIIPatterns:           nil,
		SecretPatterns:        nil,
	}
}

// ============================================================================
// Scan Result Types
// ============================================================================

// ResponseScanResult contains the results of response scanning
type ResponseScanResult struct {
	// Allowed indicates if the response is allowed through
	Allowed bool

	// BlockReason explains why the response was blocked (if not allowed)
	BlockReason string

	// Threats contains detected security threats
	Threats []Threat

	// DetectedPII contains categories of PII found in response
	DetectedPII []PIICategory

	// DetectedSecrets contains descriptions of detected secrets
	DetectedSecrets []string

	// Tokens is the token count of the response
	Tokens int

	// LatencyMs is the scanning latency in milliseconds
	LatencyMs int64

	// ScanTime is when the scan occurred
	ScanTime time.Time

	// ComplianceReports maps framework names to compliance status
	ComplianceReports map[string]ComplianceResult
}

// Threat represents a detected threat in a response
type Threat struct {
	// Type is the threat category (e.g., "pii", "secret", "toxicity")
	Type string

	// Severity is the threat severity (1-5, 5 being most severe)
	Severity int

	// Message describes the threat
	Message string

	// Location is where in the response the threat was found
	Location string

	// Pattern is the regex pattern that matched
	Pattern string

	// MatchStart is the start position of the match
	MatchStart int

	// MatchEnd is the end position of the match
	MatchEnd int
}

// ComplianceResult holds compliance framework check results
type ComplianceResult struct {
	Compliant  bool
	Violations []string
	Framework  string
	ControlID  string
	Timestamp  time.Time
}

// ============================================================================
// PII Category Types
// ============================================================================

// PIICategory represents a category of personally identifiable information
type PIICategory string

const (
	// PII_SSN is US Social Security Numbers
	PII_SSN PIICategory = "ssn"

	// PII_CREDIT_CARD is credit card numbers (Visa, MC, Amex, etc.)
	PII_CREDIT_CARD PIICategory = "credit_card"

	// PII_EMAIL is email addresses
	PII_EMAIL PIICategory = "email"

	// PII_PHONE is phone numbers
	PII_PHONE PIICategory = "phone"

	// PII_HEALTH is health information (HIPAA)
	PII_HEALTH PIICategory = "health_info"

	// PII_PASSPORT is passport numbers
	PII_PASSPORT PIICategory = "passport"

	// PII_DRIVER_LICENSE is driver license numbers
	PII_DRIVER_LICENSE PIICategory = "driver_license"

	// PII_BANK_ACCOUNT is bank account numbers
	PII_BANK_ACCOUNT PIICategory = "bank_account"

	// PII_IP_ADDRESS is IP addresses (may be PII in some contexts)
	PII_IP_ADDRESS PIICategory = "ip_address"

	// PII_DATE_OF_BIRTH is dates of birth
	PII_DATE_OF_BIRTH PIICategory = "date_of_birth"

	// PII_NAME is personal names (context-dependent)
	PII_NAME PIICategory = "name"

	// PII_ADDRESS is physical addresses
	PII_ADDRESS PIICategory = "address"
)

// PIICategoryMetadata provides information about each PII category
var PIICategoryMetadata = map[PIICategory]struct {
	Description  string
	Compliance   []string
	Severity     int
	RedactPrefix string
}{
	PII_SSN:            {"US Social Security Number", []string{"SOC2", "HIPAA", "PCI-DSS"}, 5, "XXX-XX-"},
	PII_CREDIT_CARD:    {"Credit Card Number", []string{"PCI-DSS"}, 5, "XXXX-XXXX-XXXX-"},
	PII_EMAIL:          {"Email Address", []string{"GDPR", "SOC2"}, 3, "***@***"},
	PII_PHONE:          {"Phone Number", []string{"GDPR", "SOC2"}, 3, "***-***-"},
	PII_HEALTH:         {"Health Information", []string{"HIPAA"}, 5, "[REDACTED-HEALTH]"},
	PII_PASSPORT:       {"Passport Number", []string{"SOC2", "GDPR"}, 4, "****"},
	PII_DRIVER_LICENSE: {"Driver License Number", []string{"SOC2"}, 3, "****"},
	PII_BANK_ACCOUNT:   {"Bank Account Number", []string{"SOC2", "PCI-DSS"}, 5, "****"},
	PII_IP_ADDRESS:     {"IP Address", []string{"GDPR"}, 2, "X.X.X.X"},
	PII_DATE_OF_BIRTH:  {"Date of Birth", []string{"GDPR", "SOC2"}, 3, "**/**/****"},
	PII_NAME:           {"Personal Name", []string{"GDPR"}, 2, "[REDACTED]"},
	PII_ADDRESS:        {"Physical Address", []string{"GDPR"}, 3, "[REDACTED-ADDRESS]"},
}

// ============================================================================
// Secret Category Types
// ============================================================================

// SecretCategory represents a category of secret/key
type SecretCategory string

const (
	// SECRET_API_KEY is API keys for various services
	SECRET_API_KEY SecretCategory = "api_key"

	// SECRET_BEARER_TOKEN is Bearer authentication tokens
	SECRET_BEARER_TOKEN SecretCategory = "bearer_token"

	// SECRET_AWS_KEY is AWS access keys
	SECRET_AWS_KEY SecretCategory = "aws_key"

	// SECRET_PRIVATE_KEY is private cryptographic keys
	SECRET_PRIVATE_KEY SecretCategory = "private_key"

	SECRET_OAUTH_TOKEN SecretCategory = "oauth_token" //nolint:gosec G101

	// SECRET_PASSWORD is passwords
	SECRET_PASSWORD SecretCategory = "password"

	// SECRET_JWT is JSON Web Tokens
	SECRET_JWT SecretCategory = "jwt"

	// SECRET_DATABASE_URL is database connection strings
	SECRET_DATABASE_URL SecretCategory = "database_url"

	// SECRET_ENCRYPTION_KEY is encryption keys
	SECRET_ENCRYPTION_KEY SecretCategory = "encryption_key"

	// SECRET_WEBHOOK_SECRET is webhook signatures
	SECRET_WEBHOOK_SECRET SecretCategory = "webhook_secret"
)

// SecretMetadata provides information about each secret category
var SecretMetadata = map[SecretCategory]struct {
	Description     string
	Compliance      []string
	Severity        int
	CommonProviders []string
}{
	SECRET_API_KEY:        {"API Key for various services", []string{"SOC2"}, 4, []string{"Stripe", "Twilio", "SendGrid", "AWS", "GitHub"}},
	SECRET_BEARER_TOKEN:   {"Bearer Authentication Token", []string{"SOC2"}, 4, []string{"OpenAI", "Anthropic", "Google", "Azure"}},
	SECRET_AWS_KEY:        {"AWS Access Key", []string{"SOC2", "PCI-DSS"}, 5, []string{"AWS"}},
	SECRET_PRIVATE_KEY:    {"Private Cryptographic Key", []string{"SOC2", "PCI-DSS"}, 5, []string{"SSH", "TLS", "PGP"}},
	SECRET_OAUTH_TOKEN:    {"OAuth Access Token", []string{"SOC2"}, 4, []string{"Google", "GitHub", "Microsoft"}},
	SECRET_PASSWORD:       {"Password", []string{"SOC2", "PCI-DSS", "HIPAA"}, 5, []string{}},
	SECRET_JWT:            {"JSON Web Token", []string{"SOC2"}, 4, []string{}},
	SECRET_DATABASE_URL:   {"Database Connection String", []string{"SOC2", "PCI-DSS", "HIPAA"}, 5, []string{"PostgreSQL", "MySQL", "Redis", "MongoDB"}},
	SECRET_ENCRYPTION_KEY: {"Encryption Key", []string{"SOC2", "PCI-DSS", "HIPAA"}, 5, []string{}},
	SECRET_WEBHOOK_SECRET: {"Webhook Signature Secret", []string{"SOC2"}, 3, []string{"Stripe", "GitHub", "Slack"}},
}

// ============================================================================
// Token Rate Limiting Types
// ============================================================================

// TokenLimiterConfig holds token rate limiting configuration
type TokenLimiterConfig struct {
	// MaxTokensPerResponse is the maximum tokens allowed in a single response
	MaxTokensPerResponse int

	// TokensPerMinute is the rate limit for tokens per minute per client
	TokensPerMinute int

	// MaxResponsesPerMinute is the maximum responses per minute per client
	MaxResponsesPerMinute int

	// WindowDuration is the sliding window duration for rate limiting
	WindowDuration time.Duration
}

// DefaultTokenLimiterConfig returns default token limiter configuration
func DefaultTokenLimiterConfig() *TokenLimiterConfig {
	return &TokenLimiterConfig{
		MaxTokensPerResponse:  8192,
		TokensPerMinute:       100000,
		MaxResponsesPerMinute: 100,
		WindowDuration:        time.Minute,
	}
}

// TokenUsage tracks token usage for a client
type TokenUsage struct {
	ClientID        string
	TotalTokens     int64
	RequestCount    int64
	WindowStart     time.Time
	TokenCapacity   int64
	RequestCapacity int64
}

// ============================================================================
// Toxicity Filter Types
// ============================================================================

// ToxicityCategory represents a category of harmful content
type ToxicityCategory string

const (
	// TOXICITY_HATE_SPEECH is hate speech targeting groups
	TOXICITY_HATE_SPEECH ToxicityCategory = "hate_speech"

	// TOXICITY_VIOLENCE is violent content
	TOXICITY_VIOLENCE ToxicityCategory = "violence"

	// TOXICITY_SEXUAL is sexual content
	TOXICITY_SEXUAL ToxicityCategory = "sexual"

	// TOXICITY_SELF_HARM is self-harm content
	TOXICITY_SELF_HARM ToxicityCategory = "self_harm"

	// TOXICITYHarassment is harassment content
	TOXICITY_HARASSMENT ToxicityCategory = "harassment"

	// TOXICITY_WEAPONS is weapons-related content
	TOXICITY_WEAPONS ToxicityCategory = "weapons"

	// TOXICITY_ILLEGAL is illegal activity content
	TOXICITY_ILLEGAL ToxicityCategory = "illegal"
)

// ToxicityResult holds the result of toxicity scanning
type ToxicityResult struct {
	Categories  []ToxicityCategory
	Severity    int
	Filtered    bool
	Explanation string
}

// ============================================================================
// Hallucination Detection Types
// ============================================================================

// HallucinationConfig holds hallucination detection configuration
type HallucinationConfig struct {
	// EnableFactChecking enables factual verification
	EnableFactChecking bool

	// ConfidenceThreshold is the threshold for flagging low-confidence claims
	ConfidenceThreshold float64

	// VerifyAttributions checks if attributions are valid
	VerifyAttributions bool

	// CustomFacts is a map of fact -> valid (for fact verification)
	CustomFacts map[string]bool
}

// HallucinationResult holds the result of hallucination detection
type HallucinationResult struct {
	Flagged              bool
	Claims               []Claim
	HighConfidenceClaims int
	TotalClaims          int
	Explanation          string
}

// Claim represents a factual claim in the response
type Claim struct {
	Text       string
	Confidence float64
	Verified   *bool // nil = unknown, true = verified, false = hallucinated
	Source     string
}

// ============================================================================
// Redaction Types
// ============================================================================

// RedactionConfig holds redaction configuration
type RedactionConfig struct {
	// RedactSSN redacts SSN
	RedactSSN bool

	// RedactCreditCard redacts credit card numbers
	RedactCreditCard bool

	// RedactEmail redacts email addresses
	RedactEmail bool

	// RedactPhone redacts phone numbers
	RedactPhone bool

	// RedactHealthInfo redacts health information
	RedactHealthInfo bool

	// RedactCustom enables custom redaction rules
	RedactCustom bool

	// CustomRules are custom redaction rules (pattern -> replacement)
	CustomRules map[string]string
}

// ============================================================================
// Scanner Interface
// ============================================================================

// Scanner is the interface for response security scanning
type Scanner interface {
	// Scan performs security scanning on a response
	Scan(ctx context.Context, response string) (*ResponseScanResult, error)

	// ScanWithConfig performs scanning with custom configuration
	ScanWithConfig(ctx context.Context, response string, config *ResponseGuardConfig) (*ResponseScanResult, error)
}

// PIIFinder is the interface for PII detection
type PIIFinder interface {
	// FindPII returns all PII found in the text
	FindPII(text string) []PIIMatch
}

// SecretFinder is the interface for secret detection
type SecretFinder interface {
	// FindSecrets returns all secrets found in the text
	FindSecrets(text string) []SecretMatch
}

// TokenCounter is the interface for token counting
type TokenCounter interface {
	// CountTokens counts the tokens in the text
	CountTokens(text string) int
}

// PIIMatch represents a matched PII entity
type PIIMatch struct {
	Category PIICategory
	Start    int
	End      int
	Value    string
	Severity int
	Redacted string
}

// SecretMatch represents a matched secret
type SecretMatch struct {
	Category SecretCategory
	Start    int
	End      int
	Value    string // Masked value
	Severity int
	Provider string
	Redacted string
}

// ============================================================================
// Context Types
// ============================================================================

// ScanContext holds context for response scanning
type ScanContext struct {
	// ClientID is the identifier for the client
	ClientID string

	// RequestID is the identifier for the request
	RequestID string

	// Timestamp is when the scan was initiated
	Timestamp time.Time

	// Metadata is additional context metadata
	Metadata map[string]string

	// Tier is the tier level for feature gating
	Tier string

	// ScanType is the type of response (e.g., "chat", "completion", "agent")
	ScanType string
}

// NewScanContext creates a new scan context with defaults
func NewScanContext(clientID, requestID string) *ScanContext {
	return &ScanContext{
		ClientID:  clientID,
		RequestID: requestID,
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
		Tier:      "community",
		ScanType:  "chat",
	}
}
