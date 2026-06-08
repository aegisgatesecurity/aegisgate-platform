package anomaly

import (
	"regexp"
	"strings"
	"unicode"
)

// TokenType classifies common secret/token formats.
type TokenType int

const (
	TokenTypeUnknown TokenType = iota
	TokenTypeAPIKey
	TokenTypeOAuthToken
	TokenTypeJWT
	TokenTypeAWSKey
	TokenTypeGitHubToken
	TokenTypeStripeKey
	TokenTypeOpenAIKey
	TokenTypeSlackToken
	TokenTypeGenericSecret
	TokenTypePassword
	TokenTypeSessionID
	TokenTypeBase64Encoded
	TokenTypeHexEncoded
	TokenTypeUUID
	TokenTypeTimestamp
)

// String returns human-readable token type name.
func (t TokenType) String() string {
	switch t {
	case TokenTypeUnknown:
		return "unknown"
	case TokenTypeAPIKey:
		return "api_key"
	case TokenTypeOAuthToken:
		return "oauth_token"
	case TokenTypeJWT:
		return "jwt"
	case TokenTypeAWSKey:
		return "aws_key"
	case TokenTypeGitHubToken:
		return "github_token"
	case TokenTypeStripeKey:
		return "stripe_key"
	case TokenTypeOpenAIKey:
		return "openai_key"
	case TokenTypeSlackToken:
		return "slack_token"
	case TokenTypeGenericSecret:
		return "generic_secret"
	case TokenTypePassword:
		return "password"
	case TokenTypeSessionID:
		return "session_id"
	case TokenTypeBase64Encoded:
		return "base64_encoded"
	case TokenTypeHexEncoded:
		return "hex_encoded"
	case TokenTypeUUID:
		return "uuid"
	case TokenTypeTimestamp:
		return "timestamp"
	default:
		return "unknown"
	}
}

// TokenStructure represents analysis of a token's structure.
type TokenStructure struct {
	Type          TokenType
	Length        int
	Prefix        string   // e.g., "sk-" for OpenAI
	Suffix        string   // e.g., "-live" for production keys
	Segments      []string // Delimiter-separated parts
	HasTimestamps bool     // Contains epoch timestamps
	HasUUID       bool     // Contains UUID patterns
	IsProduction  bool     // Likely production vs test key
	IsEncoded     bool     // Base64 or hex encoded
	Entropy       float64  // Entropy score
	Base64Score   float64  // Base64 likelihood
	HexScore      float64  // Hex likelihood
	Flags         []string // Detection flags for logging
}

// Classify analyzes a token and returns its structure.
func Classify(value string) TokenStructure {
	if value == "" {
		return TokenStructure{Type: TokenTypeUnknown}
	}

	ts := TokenStructure{
		Length:  len(value),
		Entropy: ShannonEntropyString(value),
	}

	// Detect encoding
	ts.Base64Score = Base64Likeness([]byte(value))
	ts.HexScore = HexLikeness([]byte(value))
	ts.IsEncoded = ts.Base64Score > 0.9 || ts.HexScore > 0.9

	// Extract prefix (first segment before common delimiters)
	ts.Prefix = extractPrefix(value)

	// Extract suffix
	ts.Suffix = extractSuffix(value)

	// Split into segments
	ts.Segments = splitIntoSegments(value)

	// Detect specific token types
	ts.Type = detectTokenType(value, ts)

	// Detect special properties
	ts.HasUUID = isUUID(value)
	ts.HasTimestamps = containsTimestamp(value)
	ts.IsProduction = isProductionKey(value, ts)

	// Set flags for logging
	ts.Flags = buildFlags(ts)

	return ts
}

// Known prefixes for common services
var knownPrefixes = map[string]TokenType{
	"sk-":         TokenTypeOpenAIKey,
	"sk-prod-":    TokenTypeOpenAIKey,
	"sk-test-":    TokenTypeOpenAIKey,
	"ghp_":        TokenTypeGitHubToken,
	"github_pat_": TokenTypeGitHubToken,
	"xoxb-":       TokenTypeSlackToken,
	"xoxp-":       TokenTypeSlackToken,
	"sk_live_":    TokenTypeStripeKey,
	"sk_test_":    TokenTypeStripeKey,
	"rk_live_":    TokenTypeStripeKey,
	"AKIA":        TokenTypeAWSKey,
	"ASIA":        TokenTypeAWSKey,
	"eyJ":         TokenTypeJWT,
	"eyJh":        TokenTypeJWT,
	"gho_":        TokenTypeGitHubToken,
	"glpat-":      TokenTypeGitHubToken,
	"glft-":       TokenTypeGitHubToken,
	"sq0atp-":     TokenTypeStripeKey,
	"sq0csp-":     TokenTypeStripeKey,
}

// Known production suffixes
var productionSuffixes = []string{"-live", "_live", "/live", ":live"}

// detectTokenType identifies the specific token type.
func detectTokenType(value string, ts TokenStructure) TokenType {
	upper := strings.ToUpper(value)
	lower := strings.ToLower(value)

	// Check known prefixes (most reliable)
	for prefix, tokenType := range knownPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return tokenType
		}
	}

	// Check for JWT (starts with eyJ, contains two more base64 segments)
	if strings.HasPrefix(value, "eyJ") && len(ts.Segments) >= 3 {
		return TokenTypeJWT
	}

	// Check for AWS keys (16 chars, uppercase alphanumeric)
	if len(value) == 20 && isUpperAlphaNumeric(value) && strings.HasPrefix(upper, "AKIA") {
		return TokenTypeAWSKey
	}

	// Check for AWS secret key (40 chars, base64-like)
	if len(value) == 40 && isBase64Like(value) {
		return TokenTypeAWSKey
	}

	// Check for UUID
	if ts.HasUUID {
		return TokenTypeUUID
	}

	// Check for Base64 encoded content (high base64 score + high entropy)
	if ts.Base64Score > 0.9 && ts.Entropy > 4.5 {
		return TokenTypeBase64Encoded
	}

	// Check for hex encoded content
	if ts.HexScore > 0.9 && ts.Entropy > 3.5 {
		return TokenTypeHexEncoded
	}

	// Check for generic API key patterns
	if isLikelyAPIKey(value, ts) {
		return TokenTypeAPIKey
	}

	// Check for session ID (moderate length, alphanumeric)
	if isLikelySessionID(value, ts) {
		return TokenTypeSessionID
	}

	return TokenTypeUnknown
}

// extractPrefix extracts the prefix before common delimiters.
func extractPrefix(value string) string {
	delimiters := []string{"-", "_", "/", ":"}

	for _, d := range delimiters {
		if idx := strings.Index(value, d); idx > 0 && idx < 10 {
			return value[:idx]
		}
	}

	// Check first 10 chars for prefix pattern
	if len(value) > 10 {
		return value[:min(10, len(value))]
	}

	return value
}

// extractSuffix extracts the suffix after common delimiters.
func extractSuffix(value string) string {
	// Look for production indicators
	for _, suffix := range productionSuffixes {
		if strings.Contains(value, suffix) {
			parts := strings.Split(value, suffix)
			return suffix + parts[len(parts)-1]
		}
	}

	// Look for last delimiter segment
	delimiters := []string{"-", "_", "/", ":"}
	longest := ""

	for _, d := range delimiters {
		if idx := strings.LastIndex(value, d); idx > 0 && idx < len(value)-1 {
			candidate := value[idx+1:]
			if len(candidate) > len(longest) && len(candidate) < 20 {
				longest = candidate
			}
		}
	}

	return longest
}

// splitIntoSegments splits token by common delimiters.
func splitIntoSegments(value string) []string {
	// Split by multiple delimiters
	re := regexp.MustCompile(`[-_/:.]+`)
	parts := re.Split(value, -1)

	// Filter empty segments
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}

	return result
}

// isUUID checks if value matches UUID pattern.
func isUUID(value string) bool {
	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	return uuidPattern.MatchString(strings.ToLower(value))
}

// containsTimestamp checks for Unix epoch timestamps.
func containsTimestamp(value string) bool {
	// Pattern for Unix timestamps (10-13 digits)
	timestampPattern := regexp.MustCompile(`\b1[0-9]{9,12}\b`)
	return timestampPattern.MatchString(value)
}

// isProductionKey determines if key is likely production vs test.
func isProductionKey(value string, ts TokenStructure) bool {
	lower := strings.ToLower(value)

	// Check for test indicators
	testIndicators := []string{"test", "dev", "staging", "sandbox", "mock", "fake", "sample"}
	for _, indicator := range testIndicators {
		if strings.Contains(lower, indicator) {
			return false
		}
	}

	// Check for production indicators
	prodIndicators := []string{"-live", "_live", "/live", "prod", "production", "real"}
	for _, indicator := range prodIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}

	// Check common production prefixes
	prodPrefixes := []string{"sk_live_", "rk_live_", "sk-prod-"}
	for _, prefix := range prodPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	return false // Assume test by default (safer)
}

// isLikelyAPIKey heuristic for generic API key detection.
func isLikelyAPIKey(value string, ts TokenStructure) bool {
	// Length between 16 and 128 chars
	if len(value) < 16 || len(value) > 128 {
		return false
	}

	// High entropy indicates randomness
	if ts.Entropy < 3.5 {
		return false
	}

	// Should be alphanumeric dominant
	alphanum := 0
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			alphanum++
		}
	}

	return float64(alphanum)/float64(len(value)) > 0.8
}

// isLikelySessionID heuristic for session ID detection.
func isLikelySessionID(value string, ts TokenStructure) bool {
	// Session IDs are typically 20-64 chars
	if len(value) < 20 || len(value) > 64 {
		return false
	}

	// Should be alphanumeric
	alphanum := 0
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			alphanum++
		}
	}

	return float64(alphanum)/float64(len(value)) > 0.9
}

// isUpperAlphaNumeric checks if all chars are uppercase letters or digits.
func isUpperAlphaNumeric(value string) bool {
	for _, r := range value {
		if r < 'A' || r > 'Z' {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// isBase64Like checks if string could be Base64.
func isBase64Like(value string) bool {
	if len(value) < 20 {
		return false
	}

	score := Base64Likeness([]byte(value))
	return score > 0.9
}

// buildFlags creates a list of detection flags.
func buildFlags(ts TokenStructure) []string {
	var flags []string

	if ts.IsProduction {
		flags = append(flags, "production_key")
	} else {
		flags = append(flags, "test_key")
	}

	if ts.IsEncoded {
		if ts.Base64Score > ts.HexScore {
			flags = append(flags, "base64_encoded")
		} else {
			flags = append(flags, "hex_encoded")
		}
	}

	if ts.HasUUID {
		flags = append(flags, "contains_uuid")
	}

	if ts.HasTimestamps {
		flags = append(flags, "contains_timestamp")
	}

	if len(ts.Segments) > 1 {
		flags = append(flags, "segmented")
	}

	if ts.Entropy > 6.0 {
		flags = append(flags, "high_entropy")
	}

	return flags
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
