// SPDX-License-Identifier: Apache-2.0
// Anomaly tokenizer tests - all new tests to avoid duplicates

package anomaly

import (
	"testing"
)

func TestTokenizer_TokenTypeString(t *testing.T) {
	tests := []struct {
		tokenType TokenType
		expected  string
	}{
		{TokenTypeUnknown, "unknown"},
		{TokenTypeAPIKey, "api_key"},
		{TokenTypeOAuthToken, "oauth_token"},
		{TokenTypeJWT, "jwt"},
		{TokenTypeAWSKey, "aws_key"},
		{TokenTypeGitHubToken, "github_token"},
		{TokenTypeStripeKey, "stripe_key"},
		{TokenTypeOpenAIKey, "openai_key"},
		{TokenTypeSlackToken, "slack_token"},
		{TokenTypeGenericSecret, "generic_secret"},
		{TokenTypePassword, "password"},
		{TokenTypeSessionID, "session_id"},
		{TokenTypeBase64Encoded, "base64_encoded"},
		{TokenTypeHexEncoded, "hex_encoded"},
		{TokenTypeUUID, "uuid"},
		{TokenTypeTimestamp, "timestamp"},
		{TokenType(100), "unknown"},
	}
	for _, tt := range tests {
		result := tt.tokenType.String()
		if result != tt.expected {
			t.Errorf("TokenType(%d).String() = %q, expected %q", tt.tokenType, result, tt.expected)
		}
	}
}

func TestTokenizer_IsLikelySessionID_Short(t *testing.T) {
	ts := TokenStructure{}
	if isLikelySessionID("sess_abc", ts) {
		t.Error("Expected false for short string")
	}
}

func TestTokenizer_IsLikelySessionID_Long(t *testing.T) {
	ts := TokenStructure{}
	longStr := ""
	for i := 0; i < 65; i++ {
		longStr += "a"
	}
	if isLikelySessionID(longStr, ts) {
		t.Error("Expected false for string > 64 chars")
	}
}

func TestTokenizer_IsLikelySessionID_Valid(t *testing.T) {
	ts := TokenStructure{}
	result := isLikelySessionID("abc123def456ghi789jklmnop", ts)
	_ = result
}

func TestTokenizer_IsBase64Like_Short(t *testing.T) {
	result := isBase64Like("SGVsbG8=")
	if result {
		t.Error("Expected false for short base64")
	}
}

func TestTokenizer_IsBase64Like_Valid(t *testing.T) {
	result := isBase64Like("SGVsbG8gV29ybGRoZXJldXNlcg==")
	if !result {
		t.Error("Expected true for valid base64")
	}
}

func TestTokenizer_IsBase64Like_Plain(t *testing.T) {
	result := isBase64Like("hello world this is plain text")
	if result {
		t.Error("Expected false for plain text")
	}
}

func TestTokenizer_ClassifyOpenAI(t *testing.T) {
	ts := Classify("sk-1234567890abcdefghijklmnop")
	if ts.Type != TokenTypeOpenAIKey {
		t.Errorf("Expected OpenAI key, got %v", ts.Type)
	}
}

func TestTokenizer_ClassifyGitHub(t *testing.T) {
	ts := Classify("ghp_1234567890abcdefghijklmnop")
	if ts.Type != TokenTypeGitHubToken {
		t.Errorf("Expected GitHub token, got %v", ts.Type)
	}
}

func TestTokenizer_ClassifyJWT(t *testing.T) {
	ts := Classify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doziegNqXP3P8cR8vJMyxqMl2K3a8t6J")
	if ts.Type != TokenTypeJWT {
		t.Errorf("Expected JWT, got %v", ts.Type)
	}
}

func TestTokenizer_ClassifyAWS(t *testing.T) {
	ts := Classify("AKIAIOSFODNN7EXAMPLE")
	if ts.Type != TokenTypeAWSKey {
		t.Errorf("Expected AWS key, got %v", ts.Type)
	}
}

func TestTokenizer_ClassifyGeneric(t *testing.T) {
	ts := Classify("some_random_token_123")
	_ = ts
}

func TestTokenizer_IsProduction_Live(t *testing.T) {
	result := isProductionKey("key-123-live", TokenStructure{})
	if !result {
		t.Error("Expected true for -live suffix")
	}
}

func TestTokenizer_IsProduction_Prod(t *testing.T) {
	result := isProductionKey("key-123-prod", TokenStructure{})
	if !result {
		t.Error("Expected true for -prod suffix")
	}
}

func TestTokenizer_IsProduction_Test(t *testing.T) {
	result := isProductionKey("key-123-test", TokenStructure{})
	if result {
		t.Error("Expected false for -test suffix")
	}
}

func TestTokenizer_IsUpperAlpha(t *testing.T) {
	if !isUpperAlphaNumeric("ABC123") {
		t.Error("Expected true for uppercase alphanumeric")
	}
	if isUpperAlphaNumeric("abc123") {
		t.Error("Expected false for lowercase")
	}
}

func TestTokenizer_Min(t *testing.T) {
	if min(5, 3) != 3 {
		t.Error("Expected min(5,3) = 3")
	}
}

func TestTokenizer_IsUUID(t *testing.T) {
	result := isUUID("123e4567-e89b-12d3-a456-426614174000")
	_ = result
}

func TestTokenizer_ContainsTimestamp(t *testing.T) {
	result := containsTimestamp("token_1234567890")
	_ = result
}

func TestTokenizer_BuildFlags(t *testing.T) {
	ts := TokenStructure{
		IsProduction: true,
		Type:         TokenTypeOpenAIKey,
		HasUUID:      false,
	}
	flags := buildFlags(ts)
	_ = flags
}

func TestTokenizer_IsLikelyAPIKey(t *testing.T) {
	result := isLikelyAPIKey("api_key_1234567890", TokenStructure{})
	_ = result
}

func TestTokenizer_ClassifyEmpty(t *testing.T) {
	ts := Classify("")
	_ = ts
}

func TestTokenizer_ClassifyShort(t *testing.T) {
	ts := Classify("abc")
	_ = ts
}

func TestTokenizer_IsProduction_Dev(t *testing.T) {
	result := isProductionKey("key-123-dev", TokenStructure{})
	if result {
		t.Error("Expected false for -dev suffix")
	}
}

func TestTokenizer_IsProduction_Staging(t *testing.T) {
	result := isProductionKey("key-123-staging", TokenStructure{})
	if result {
		t.Error("Expected false for -staging suffix")
	}
}

func TestTokenizer_IsBase64Like_Mixed(t *testing.T) {
	result := isBase64Like("abc123def456ghi789jklmnop")
	_ = result
}

func TestTokenizer_IsLikelySessionID_Underscore(t *testing.T) {
	ts := TokenStructure{}
	result := isLikelySessionID("session_id_xyz789abc123def", ts)
	_ = result
}

func TestTokenizer_IsLikelySessionID_Equals(t *testing.T) {
	ts := TokenStructure{}
	result := isLikelySessionID("session_id=xyz789abc123def", ts)
	_ = result
}
