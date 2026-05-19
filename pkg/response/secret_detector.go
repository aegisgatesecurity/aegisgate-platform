// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Secret Detector
// =========================================================================
//
// Detects API keys, tokens, passwords, and other secrets in AI responses.
// Supports OWASP LLM02 compliance and SOC2 requirements.
// =========================================================================

package response

import (
	"context"
	"regexp"
	"strings"
	"sync"
)

// ============================================================================
// Secret Detector
// ============================================================================

// SecretDetector detects secrets in text using regex patterns
type SecretDetector struct {
	// patterns is a map of SecretCategory to compiled regex patterns
	patterns map[SecretCategory]*regexp.Regexp

	// customPatterns are user-defined patterns
	customPatterns []*regexp.Regexp

	// maskedPatterns are pre-built patterns for common secret formats
	maskedPatterns []*regexp.Regexp

	// mu protects pattern compilation
	mu sync.RWMutex
}

// NewSecretDetector creates a new secret detector with default patterns
func NewSecretDetector() *SecretDetector {
	sd := &SecretDetector{
		patterns: make(map[SecretCategory]*regexp.Regexp),
	}
	sd.initDefaultPatterns()
	return sd
}

// NewSecretDetectorWithCustomPatterns creates a detector with custom patterns
func NewSecretDetectorWithCustomPatterns(patterns []string) (*SecretDetector, error) {
	sd := NewSecretDetector()

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		sd.customPatterns = append(sd.customPatterns, re)
	}

	return sd, nil
}

// initDefaultPatterns initializes all default secret detection patterns
func (sd *SecretDetector) initDefaultPatterns() {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	// API Keys for various services - use combined pattern to avoid overwriting
	// Stripe, GitHub, Slack combined into one pattern
	sd.patterns[SECRET_API_KEY] = regexp.MustCompile(`(?i)(?:(?:sk_live_|sk_test_|rk_live_|rk_test_)[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}|xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,})`)

	// AWS Access Key
	sd.patterns[SECRET_AWS_KEY] = regexp.MustCompile(`(?i)(?:AKIA[A-Z0-9]{16})`)

	// Bearer Tokens
	sd.patterns[SECRET_BEARER_TOKEN] = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9_-]{20,}`)

	// JWT Tokens
	sd.patterns[SECRET_JWT] = regexp.MustCompile(`(?i)(?:eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)`)

	// Private Keys (RSA, EC, DSA, etc.)
	sd.patterns[SECRET_PRIVATE_KEY] = regexp.MustCompile(`(?i)-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----`)

	// Webhook Secrets
	sd.patterns[SECRET_WEBHOOK_SECRET] = regexp.MustCompile(`(?i)(?:whsec_[a-zA-Z0-9]{32,})`)

	// Generic API Key pattern (fallback)
	sd.maskedPatterns = append(sd.maskedPatterns,
		regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["']?[a-zA-Z0-9_-]{20,}`),
		regexp.MustCompile(`(?i)(?:token|auth)\s*[=:]\s*["']?[a-zA-Z0-9_-]{32,}`),
	)

	// OAuth Tokens
	sd.patterns[SECRET_OAUTH_TOKEN] = regexp.MustCompile(`(?i)(?:oauth_token|access_token|refresh_token)\s*[=:]\s*["']?[A-Za-z0-9_-]{20,}`)

	// Passwords in configuration
	sd.patterns[SECRET_PASSWORD] = regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*[^"'\s]{8,}`)

	// Database URLs (connection strings with credentials)
	sd.patterns[SECRET_DATABASE_URL] = regexp.MustCompile(`(?i)(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9]+:[^@]+@`)

	// Encryption Keys
	sd.patterns[SECRET_ENCRYPTION_KEY] = regexp.MustCompile(`(?i)(?:encryption[_-]?key|enc_key)\s*[=:]\s*["']?[a-zA-Z0-9+/=]{32,}`)

	// OpenAI, Anthropic, Google Cloud, Twilio, SendGrid as masked patterns
	sd.maskedPatterns = append(sd.maskedPatterns,
		regexp.MustCompile(`(?i)(?:sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9_-]{48,})`),
		regexp.MustCompile(`(?i)(?:sk-ant-[a-zA-Z0-9]{48,})`),
		regexp.MustCompile(`(?i)(?:AIza[a-zA-Z0-9_-]{35})`),
		regexp.MustCompile(`(?i)(?:SK[0-9a-fA-F]{32})`),
		regexp.MustCompile(`(?i)(?:SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})`),
	)
}

// FindSecrets returns all secret matches in the text
func (sd *SecretDetector) FindSecrets(text string) []SecretMatch {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	var matches []SecretMatch

	// Check each category pattern
	for category, pattern := range sd.patterns {
		found := sd.findMatches(text, category, pattern)
		matches = append(matches, found...)
	}

	// Check masked patterns
	for _, pattern := range sd.maskedPatterns {
		found := sd.findMaskedMatches(text, pattern)
		matches = append(matches, found...)
	}

	// Check custom patterns
	for _, pattern := range sd.customPatterns {
		found := sd.findMaskedMatches(text, pattern)
		matches = append(matches, found...)
	}

	return matches
}

// findMatches finds all matches for a pattern and returns them as SecretMatches
func (sd *SecretDetector) findMatches(text string, category SecretCategory, pattern *regexp.Regexp) []SecretMatch {
	var matches []SecretMatch

	indices := pattern.FindAllStringIndex(text, -1)
	for _, idx := range indices {
		match := text[idx[0]:idx[1]]

		// Skip false positives with additional validation
		if !sd.validateMatch(category, match) {
			continue
		}

		metadata := SecretMetadata[category]

		matches = append(matches, SecretMatch{
			Category: category,
			Start:    idx[0],
			End:      idx[1],
			Value:    sd.maskSecret(match),
			Severity: metadata.Severity,
			Provider: sd.detectProvider(match),
			Redacted: sd.maskSecret(match),
		})
	}

	return matches
}

// findMaskedMatches finds matches for generic masked patterns
func (sd *SecretDetector) findMaskedMatches(text string, pattern *regexp.Regexp) []SecretMatch {
	var matches []SecretMatch

	indices := pattern.FindAllStringIndex(text, -1)
	for _, idx := range indices {
		match := text[idx[0]:idx[1]]

		matches = append(matches, SecretMatch{
			Category: SECRET_API_KEY, // Categorize as generic API key
			Start:    idx[0],
			End:      idx[1],
			Value:    sd.maskSecret(match),
			Severity: 4, // Default high severity
			Provider: "generic",
			Redacted: sd.maskSecret(match),
		})
	}

	return matches
}

// validateMatch performs additional validation to reduce false positives
func (sd *SecretDetector) validateMatch(category SecretCategory, match string) bool {
	switch category {
	case SECRET_AWS_KEY:
		// AWS keys start with AKIA, not AKIA followed by another A
		if strings.HasPrefix(strings.ToUpper(match), "AKIAIA") {
			return false
		}
		return true

	case SECRET_API_KEY:
		// Check minimum length for API keys
		clean := strings.TrimSpace(match)
		if len(clean) < 20 {
			return false
		}
		return true

	case SECRET_JWT:
		// JWT should have 3 parts separated by dots
		parts := strings.Split(match, ".")
		if len(parts) != 3 {
			return false
		}
		// First two parts should be reasonably long (base64 encoded)
		if len(parts[0]) < 10 || len(parts[1]) < 10 {
			return false
		}
		return true

	case SECRET_BEARER_TOKEN:
		// Bearer token should be reasonably long
		if len(match) < 20 {
			return false
		}
		return true

	default:
		return len(match) >= 10
	}
}

// maskSecret returns a masked version of the secret
func (sd *SecretDetector) maskSecret(secret string) string {
	// Detect the type of secret and mask appropriately
	upper := strings.ToUpper(secret)

	if strings.Contains(upper, "PRIVATE KEY") {
		return "-----BEGIN [PRIVATE KEY]-----"
	}

	if strings.Contains(upper, "JWT") || strings.Count(secret, ".") == 2 {
		// JWT: show first 10 chars + "...[MASKED]..."
		if len(secret) > 10 {
			return secret[:10] + "...[JWT-MASKED]"
		}
		return "[JWT-MASKED]"
	}

	if strings.HasPrefix(upper, "BEARER") {
		return "Bearer ...[MASKED]"
	}

	if strings.HasPrefix(upper, "SK_LIVE") || strings.HasPrefix(upper, "SK_TEST") {
		return secret[:7] + "...[STRIPE-KEY-MASKED]"
	}

	if strings.HasPrefix(upper, "AKIA") {
		return secret[:4] + "...[AWS-KEY-MASKED]"
	}

	if strings.HasPrefix(upper, "SG.") {
		return "SG.../[SENDGRID-KEY-MASKED]"
	}

	if strings.HasPrefix(upper, "GHP_") {
		return secret[:4] + "...[GITHUB-TOKEN-MASKED]"
	}

	if strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "PASSWD") || strings.Contains(upper, "PWD") {
		return "password=...[MASKED]"
	}

	// Generic: show first 4 chars
	if len(secret) > 4 {
		return secret[:4] + "...[SECRET-MASKED]"
	}

	return "...[SECRET-MASKED]"
}

// detectProvider detects the service provider from the secret
func (sd *SecretDetector) detectProvider(secret string) string {
	upper := strings.ToUpper(secret)

	if strings.HasPrefix(upper, "SK_LIVE") || strings.HasPrefix(upper, "SK_TEST") || strings.HasPrefix(upper, "RK_LIVE") || strings.HasPrefix(upper, "RK_TEST") {
		return "Stripe"
	}

	if strings.HasPrefix(upper, "SK-") && !strings.HasPrefix(upper, "SK-ANT-") {
		return "OpenAI"
	}

	if strings.HasPrefix(upper, "SK-ANT-") {
		return "Anthropic"
	}

	if strings.HasPrefix(upper, "AKIA") {
		return "AWS"
	}

	if strings.Contains(upper, "AIza") {
		return "Google Cloud"
	}

	if strings.HasPrefix(upper, "GHP_") || strings.HasPrefix(upper, "GITHUB_PAT") {
		return "GitHub"
	}

	if strings.HasPrefix(upper, "XOX") {
		return "Slack"
	}

	if strings.HasPrefix(upper, "SG.") {
		return "SendGrid"
	}

	if strings.HasPrefix(upper, "WHSEC_") {
		return "Stripe Webhook"
	}

	if strings.Contains(upper, "JWT") || strings.Count(secret, ".") == 2 {
		return "JWT"
	}

	if strings.Contains(upper, "PRIVATE KEY") {
		return "Private Key"
	}

	return "Unknown"
}

// ScanSecrets performs secret scanning on text and returns matches
func (sd *SecretDetector) ScanSecrets(ctx context.Context, text string) ([]SecretMatch, error) {
	return sd.FindSecrets(text), nil
}

// ScanSecretsWithContext performs secret scanning with scan context
func (sd *SecretDetector) ScanSecretsWithContext(ctx context.Context, text string, scanCtx *ScanContext) ([]SecretMatch, error) {
	matches := sd.FindSecrets(text)

	// Add context metadata
	if scanCtx != nil {
		for i := range matches {
			if scanCtx.Metadata == nil {
				scanCtx.Metadata = make(map[string]string)
			}
			matches[i].Value = matches[i].Redacted // Return masked value for security
		}
	}

	return matches, nil
}

// CountByCategory returns the count of secret matches by category
func (sd *SecretDetector) CountByCategory(matches []SecretMatch) map[SecretCategory]int {
	counts := make(map[SecretCategory]int)
	for _, match := range matches {
		counts[match.Category]++
	}
	return counts
}

// SeveritySummary returns a summary of detected secret severity
func (sd *SecretDetector) SeveritySummary(matches []SecretMatch) struct {
	Critical int
	High     int
	Medium   int
	Low      int
} {
	summary := struct {
		Critical int
		High     int
		Medium   int
		Low      int
	}{}

	for _, match := range matches {
		switch {
		case match.Severity >= 5:
			summary.Critical++
		case match.Severity >= 4:
			summary.High++
		case match.Severity >= 3:
			summary.Medium++
		default:
			summary.Low++
		}
	}

	return summary
}

// SeverityDistribution returns a map of severity levels to counts
func (sd *SecretDetector) SeverityDistribution(matches []SecretMatch) map[int]int {
	dist := make(map[int]int)
	for _, match := range matches {
		dist[match.Severity]++
	}
	return dist
}

// DetectSecretsByProvider returns secrets grouped by provider
func (sd *SecretDetector) DetectSecretsByProvider(matches []SecretMatch) map[string][]SecretMatch {
	byProvider := make(map[string][]SecretMatch)
	for _, match := range matches {
		provider := match.Provider
		if provider == "" {
			provider = "Unknown"
		}
		byProvider[provider] = append(byProvider[provider], match)
	}
	return byProvider
}

// ============================================================================
// Standalone Scan Functions
// ============================================================================

// ScanTextForSecrets is a convenience function for scanning text for secrets
func ScanTextForSecrets(text string) ([]SecretMatch, error) {
	detector := NewSecretDetector()
	return detector.FindSecrets(text), nil
}

// ScanTextForSecretsWithConfig scans text with custom patterns
func ScanTextForSecretsWithConfig(text string, patterns []string) ([]SecretMatch, error) {
	detector, err := NewSecretDetectorWithCustomPatterns(patterns)
	if err != nil {
		return nil, err
	}
	return detector.FindSecrets(text), nil
}

// MaskSecrets masks all secrets in the text
func MaskSecrets(text string) string {
	detector := NewSecretDetector()
	matches := detector.FindSecrets(text)

	if len(matches) == 0 {
		return text
	}

	result := text

	// Sort by start position in reverse order
	type matchIndex struct {
		start int
		end   int
		mask  string
	}

	sortedMatches := make([]matchIndex, 0, len(matches))
	for _, m := range matches {
		sortedMatches = append(sortedMatches, matchIndex{m.Start, m.End, m.Redacted})
	}

	// Sort by start position descending
	for i := 0; i < len(sortedMatches)-1; i++ {
		for j := i + 1; j < len(sortedMatches); j++ {
			if sortedMatches[i].start < sortedMatches[j].start {
				sortedMatches[i], sortedMatches[j] = sortedMatches[j], sortedMatches[i]
			}
		}
	}

	// Apply masks in reverse order
	for _, m := range sortedMatches {
		result = result[:m.start] + m.mask + result[m.end:]
	}

	return result
}

// ============================================================================
// Validator for Secret Detection
// ============================================================================

// ValidateSecretResult holds validation results
type ValidateSecretResult struct {
	Valid         bool
	Severity      int
	Category      SecretCategory
	Provider      string
	FalsePositive bool
}

// ValidateSecret performs validation on a potential secret
func ValidateSecret(secret string) *ValidateSecretResult {
	result := &ValidateSecretResult{
		Valid:    false,
		Severity: 4,
	}

	if len(secret) < 10 {
		result.FalsePositive = true
		return result
	}

	// Check if it matches any known pattern
	detector := NewSecretDetector()

	// Create a text context around the secret so word boundaries work
	text := "secret=" + secret + ";end"
	matches := detector.FindSecrets(text)
	if len(matches) == 0 {
		result.FalsePositive = true
		return result
	}

	match := matches[0]
	result.Valid = true
	result.Severity = match.Severity
	result.Category = match.Category
	result.Provider = match.Provider

	return result
}
