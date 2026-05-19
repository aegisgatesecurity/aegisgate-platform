// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Secret Detector Tests
// =========================================================================

package response

import (
	"context"
	"testing"
)

func TestNewSecretDetector(t *testing.T) {
	detector := NewSecretDetector()
	if detector == nil {
		t.Fatal("NewSecretDetector() returned nil")
	}
	if detector.patterns == nil {
		t.Error("patterns map not initialized")
	}
}

func TestNewSecretDetectorWithCustomPatterns(t *testing.T) {
	patterns := []string{
		`(?i)CUSTOM-\w{32}`,
	}

	detector, err := NewSecretDetectorWithCustomPatterns(patterns)
	if err != nil {
		t.Fatalf("NewSecretDetectorWithCustomPatterns() error: %v", err)
	}
	if detector == nil {
		t.Fatal("detector is nil")
	}
	if len(detector.customPatterns) != 1 {
		t.Errorf("expected 1 custom pattern, got %d", len(detector.customPatterns))
	}
}

func TestNewSecretDetectorWithInvalidPattern(t *testing.T) {
	patterns := []string{
		`[invalid(regex`,
	}

	_, err := NewSecretDetectorWithCustomPatterns(patterns)
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

func TestFindStripeKeys(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"sk_live key", "sk_live_1234567890abcdefghij", 1},
		{"sk_test key", "sk_test_abcdefghij1234567890", 1},
		{"no key", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			stripeCount := 0
			for _, m := range matches {
				if m.Provider == "Stripe" {
					stripeCount++
				}
			}
			if stripeCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d Stripe keys, want %d", tt.input, stripeCount, tt.expected)
			}
		})
	}
}

func TestFindAWSKeys(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"AKIA key", "AKIAIOSFODNN7EXAMPLE", 1},
		{"AKIA in text", "aws_access_key_id=AKIAIOSFODNN7EXAMPLE", 1},
		{"no key", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			awsCount := 0
			for _, m := range matches {
				if m.Provider == "AWS" {
					awsCount++
				}
			}
			if awsCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d AWS keys, want %d", tt.input, awsCount, tt.expected)
			}
		})
	}
}

func TestFindGitHubTokens(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"ghp_ token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz", 1},
		{"no token", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			githubCount := 0
			for _, m := range matches {
				if m.Provider == "GitHub" {
					githubCount++
				}
			}
			if githubCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d GitHub tokens, want %d", tt.input, githubCount, tt.expected)
			}
		})
	}
}

func TestFindBearerTokens(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Bearer token", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", 1},
		{"Bearer short", "Bearer abc", 0},
		{"no token", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			bearerCount := 0
			for _, m := range matches {
				if m.Category == SECRET_BEARER_TOKEN {
					bearerCount++
				}
			}
			if bearerCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d bearer tokens, want %d", tt.input, bearerCount, tt.expected)
			}
		})
	}
}

func TestFindJWTs(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"JWT token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", 1},
		{"no JWT", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			jwtCount := 0
			for _, m := range matches {
				if m.Category == SECRET_JWT {
					jwtCount++
				}
			}
			if jwtCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d JWTs, want %d", tt.input, jwtCount, tt.expected)
			}
		})
	}
}

func TestFindPrivateKeys(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"RSA private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAMY3UsdY...\n-----END RSA PRIVATE KEY-----", 1},
		{"OPENSSH private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA...\n-----END OPENSSH PRIVATE KEY-----", 1},
		{"EC private key", "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----", 1},
		{"no key", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			privateKeyCount := 0
			for _, m := range matches {
				if m.Category == SECRET_PRIVATE_KEY {
					privateKeyCount++
				}
			}
			if privateKeyCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d private keys, want %d", tt.input, privateKeyCount, tt.expected)
			}
		})
	}
}

func TestFindPasswords(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"password=", "password=supersecret123", 1},
		{"passwd=", "passwd=mysecretpass", 1},
		{"pwd:", "pwd: secret123", 1},
		{"no password", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			passwordCount := 0
			for _, m := range matches {
				if m.Category == SECRET_PASSWORD {
					passwordCount++
				}
			}
			if passwordCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d passwords, want %d", tt.input, passwordCount, tt.expected)
			}
		})
	}
}

func TestFindDatabaseURLs(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"postgres URL", "postgres://user:password@localhost:5432/db", 1},
		{"mysql URL", "mysql://admin:secretpass@localhost:3306/mydb", 1},
		{"mongodb URL", "mongodb://myuser:mypass@server.com:27017/mydb", 1},
		{"no URL", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			dbCount := 0
			for _, m := range matches {
				if m.Category == SECRET_DATABASE_URL {
					dbCount++
				}
			}
			if dbCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d database URLs, want %d", tt.input, dbCount, tt.expected)
			}
		})
	}
}

func TestFindWebhookSecrets(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"whsec_ key", "whsec_1234567890abcdefghijklmnopqrstuv", 1},
		{"no key", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			webhookCount := 0
			for _, m := range matches {
				if m.Category == SECRET_WEBHOOK_SECRET {
					webhookCount++
				}
			}
			if webhookCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d webhook secrets, want %d", tt.input, webhookCount, tt.expected)
			}
		})
	}
}

func TestFindOAuthTokens(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"oauth_token=", "oauth_token=my-oauth-token-value-here", 1},
		{"access_token:", "access_token: \"my-access-token-value\"", 1},
		{"refresh_token=", "refresh_token=my-refresh-token-value-here", 1},
		{"no token", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			oauthCount := 0
			for _, m := range matches {
				if m.Category == SECRET_OAUTH_TOKEN {
					oauthCount++
				}
			}
			if oauthCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d OAuth tokens, want %d", tt.input, oauthCount, tt.expected)
			}
		})
	}
}

func TestFindEncryptionKeys(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"encryption_key=", "encryption_key=aGVsbG93b3JsZHRoaXNpc2F0ZXN0c2VjcmV0", 1},
		{"enc_key:", "enc_key: \"base64encodedencryptionkey12345678901234567890\"", 1},
		{"no key", "This is just a normal text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := detector.FindSecrets(tt.input)
			encCount := 0
			for _, m := range matches {
				if m.Category == SECRET_ENCRYPTION_KEY {
					encCount++
				}
			}
			if encCount != tt.expected {
				t.Errorf("FindSecrets(%q) = %d encryption keys, want %d", tt.input, encCount, tt.expected)
			}
		})
	}
}

func TestFindMultipleSecrets(t *testing.T) {
	detector := NewSecretDetector()

	text := "Stripe key: sk_live_1234567890abcdefghij, AWS key: AKIAIOSFODNN7EXAMPLE, JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"

	matches := detector.FindSecrets(text)

	if len(matches) < 3 {
		t.Errorf("expected at least 3 secrets, got %d", len(matches))
	}
}

func TestMaskSecret(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		name   string
		secret string
	}{
		{"Stripe key", "sk_live_1234567890abcdefghij"},
		{"AWS key", "AKIAIOSFODNN7EXAMPLE"},
		{"JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"},
		{"Bearer", "Bearer mytoken1234567890"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := detector.maskSecret(tt.secret)
			if masked == tt.secret {
				t.Errorf("maskSecret(%q) returned original, expected masked", tt.secret)
			}
		})
	}
}

func TestDetectProvider(t *testing.T) {
	detector := NewSecretDetector()

	tests := []struct {
		secret   string
		expected string
	}{
		{"sk_live_1234567890abcdefghij", "Stripe"},
		{"sk_test_abcdefghij1234567890", "Stripe"},
		{"AKIAIOSFODNN7EXAMPLE", "AWS"},
		{"ghp_1234567890abcdefghijklmnopqrstuvwxyz", "GitHub"},
	}

	for _, tt := range tests {
		t.Run(tt.secret[:20], func(t *testing.T) {
			provider := detector.detectProvider(tt.secret)
			if provider != tt.expected {
				t.Errorf("detectProvider(%q) = %q, want %q", tt.secret, provider, tt.expected)
			}
		})
	}
}

func TestSecretValidateMatch(t *testing.T) {
	detector := NewSecretDetector()

	// Valid AWS key
	if !detector.validateMatch(SECRET_AWS_KEY, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("expected valid AWS key to pass validation")
	}

	// Invalid: AWS key starting with AKIAIA
	if detector.validateMatch(SECRET_AWS_KEY, "AKIAIA12345678901234") {
		t.Error("expected invalid AWS key (AKIAIA) to fail validation")
	}

	// Valid API key (long enough)
	if !detector.validateMatch(SECRET_API_KEY, "sk_live_1234567890abcdefghij") {
		t.Error("expected valid API key to pass validation")
	}

	// Invalid: API key too short
	if detector.validateMatch(SECRET_API_KEY, "sk_123") {
		t.Error("expected short API key to fail validation")
	}

	// Valid JWT
	if !detector.validateMatch(SECRET_JWT, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") {
		t.Error("expected valid JWT to pass validation")
	}
}

func TestScanSecrets(t *testing.T) {
	detector := NewSecretDetector()
	ctx := context.Background()

	text := "API key: sk_live_1234567890abcdefghij"
	matches, err := detector.ScanSecrets(ctx, text)

	if err != nil {
		t.Fatalf("ScanSecrets() error: %v", err)
	}
	if len(matches) < 1 {
		t.Errorf("expected at least 1 match, got %d", len(matches))
	}
}

func TestScanSecretsWithContext(t *testing.T) {
	detector := NewSecretDetector()
	ctx := context.Background()
	scanCtx := NewScanContext("client-123", "req-456")

	text := "API key: sk_live_1234567890abcdefghij"
	matches, err := detector.ScanSecretsWithContext(ctx, text, scanCtx)

	if err != nil {
		t.Fatalf("ScanSecretsWithContext() error: %v", err)
	}
	if len(matches) < 1 {
		t.Fatalf("expected at least 1 match, got %d", len(matches))
	}

	// Should return masked value
	if matches[0].Value == "sk_live_1234567890abcdefghij" {
		t.Error("expected masked value, got original")
	}
}

func TestSecretCountByCategory(t *testing.T) {
	detector := NewSecretDetector()

	text := "Stripe: sk_live_1234567890abcdefghij, AWS: AKIAIOSFODNN7EXAMPLE, Stripe: sk_test_abcdefghij1234567890"
	matches := detector.FindSecrets(text)

	counts := detector.CountByCategory(matches)

	// Should have at least 2 API keys (Stripe)
	apiKeyCount := counts[SECRET_API_KEY]
	if apiKeyCount < 2 {
		t.Errorf("expected at least 2 API keys, got %d", apiKeyCount)
	}

	// Should have at least 1 AWS key
	awsKeyCount := counts[SECRET_AWS_KEY]
	if awsKeyCount < 1 {
		t.Errorf("expected at least 1 AWS key, got %d", awsKeyCount)
	}
}

func TestSecretSeveritySummary(t *testing.T) {
	detector := NewSecretDetector()

	text := "Stripe: sk_live_1234567890abcdefghij, AWS: AKIAIOSFODNN7EXAMPLE, Private Key: -----BEGIN RSA PRIVATE KEY-----"
	matches := detector.FindSecrets(text)

	summary := detector.SeveritySummary(matches)

	if summary.High < 1 {
		t.Errorf("expected at least 1 high severity, got %d", summary.High)
	}
	if summary.Critical < 1 {
		t.Errorf("expected at least 1 critical severity, got %d", summary.Critical)
	}
}

func TestSeverityDistribution(t *testing.T) {
	detector := NewSecretDetector()

	text := "Stripe: sk_live_1234567890abcdefghij, AWS: AKIAIOSFODNN7EXAMPLE"
	matches := detector.FindSecrets(text)

	dist := detector.SeverityDistribution(matches)

	if len(dist) == 0 {
		t.Error("expected non-empty severity distribution")
	}
}

func TestDetectSecretsByProvider(t *testing.T) {
	detector := NewSecretDetector()

	text := "Stripe: sk_live_1234567890abcdefghij, AWS: AKIAIOSFODNN7EXAMPLE, Stripe: sk_test_abcdefghij1234567890"
	matches := detector.FindSecrets(text)

	byProvider := detector.DetectSecretsByProvider(matches)

	if byProvider["Stripe"] == nil {
		t.Error("expected Stripe secrets")
	}
	if len(byProvider["Stripe"]) < 2 {
		t.Errorf("expected at least 2 Stripe secrets, got %d", len(byProvider["Stripe"]))
	}
	if byProvider["AWS"] == nil {
		t.Error("expected AWS secrets")
	}
}

func TestScanTextForSecrets(t *testing.T) {
	text := "API key: sk_live_1234567890abcdefghij"
	matches, err := ScanTextForSecrets(text)

	if err != nil {
		t.Fatalf("ScanTextForSecrets() error: %v", err)
	}
	if len(matches) < 1 {
		t.Errorf("expected at least 1 match, got %d", len(matches))
	}
}

func TestMaskSecrets(t *testing.T) {
	text := "Stripe key: sk_live_1234567890abcdefghij, AWS: AKIAIOSFODNN7EXAMPLE"

	masked := MaskSecrets(text)

	// Original secrets should not be present
	if containsStr(masked, "sk_live_1234567890abcdefghij") {
		t.Error("Stripe key not properly masked")
	}
	if containsStr(masked, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("AWS key not properly masked")
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestValidateSecret(t *testing.T) {
	tests := []struct {
		secret   string
		expected bool
	}{
		{"sk_live_1234567890abcdefghij", true},
		{"AKIAIOSFODNN7EXAMPLE", true},
		{"ghp_1234567890abcdefghijklmnopqrstuvwxyz", true},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true},
		{"-----BEGIN RSA PRIVATE KEY-----test", true},
		{"not a secret", false},
	}

	for _, tt := range tests {
		name := tt.secret
		if len(name) > 20 {
			name = name[:20]
		}
		t.Run(name, func(t *testing.T) {
			result := ValidateSecret(tt.secret)
			if result.Valid != tt.expected {
				t.Errorf("ValidateSecret(%q) = %v, want %v", tt.secret, result.Valid, tt.expected)
			}
		})
	}
}

func TestSecretEmptyText(t *testing.T) {
	detector := NewSecretDetector()

	matches := detector.FindSecrets("")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty text, got %d", len(matches))
	}
}

func TestNoSecrets(t *testing.T) {
	detector := NewSecretDetector()

	text := "This is a normal text without any secrets or API keys"
	matches := detector.FindSecrets(text)

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestSecretCustomPatterns(t *testing.T) {
	detector, _ := NewSecretDetectorWithCustomPatterns([]string{`(?i)MYCUSTOM-\w{20}`})

	text := "ID: MYCUSTOM-abcdefghijklmnopqrst"
	matches := detector.FindSecrets(text)

	// Should find custom pattern
	if len(matches) < 1 {
		t.Error("expected to find custom pattern")
	}
}

func TestSecretMatchPositions(t *testing.T) {
	detector := NewSecretDetector()

	text := "API key is: sk_live_1234567890abcdefghij for testing"
	matches := detector.FindSecrets(text)

	if len(matches) < 1 {
		t.Fatalf("expected at least 1 match, got %d", len(matches))
	}

	// Verify the match is in the expected range
	if matches[0].Start < 10 || matches[0].End > len(text) {
		t.Errorf("unexpected match position: start=%d, end=%d, textLen=%d", matches[0].Start, matches[0].End, len(text))
	}
}

func TestSecretLargeText(t *testing.T) {
	detector := NewSecretDetector()

	// Create a large text with multiple secrets
	baseText := "API key: sk_live_1234567890abcdefghij, AWS: AKIAIOSFODNN7EXAMPLE, "
	largeText := ""
	for i := 0; i < 50; i++ {
		largeText += baseText
	}

	matches := detector.FindSecrets(largeText)

	expected := 50 // 50 * 2 (Stripe + AWS)
	if len(matches) < expected/2 {
		t.Errorf("expected at least %d matches in large text, got %d", expected/2, len(matches))
	}
}

func TestSecretConcurrency(t *testing.T) {
	detector := NewSecretDetector()
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				text := "API key: sk_live_1234567890abcdefghij, AWS: AKIAIOSFODNN7EXAMPLE"
				detector.FindSecrets(text)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func BenchmarkFindSecrets(b *testing.B) {
	detector := NewSecretDetector()
	text := "Stripe: sk_live_1234567890abcdefghij, AWS: AKIAIOSFODNN7EXAMPLE, JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.FindSecrets(text)
	}
}

func BenchmarkMaskSecrets(b *testing.B) {
	text := "Stripe: sk_live_1234567890abcdefghij, AWS: AKIAIOSFODNN7EXAMPLE"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MaskSecrets(text)
	}
}

func TestScanTextForSecretsWithConfig(t *testing.T) {
	patterns := []string{
		`(?i)MYTOKEN-\w{20}`,
	}

	matches, err := ScanTextForSecretsWithConfig("Token: MYTOKEN-abcdefghijklmnopqrstuv", patterns)
	if err != nil {
		t.Fatalf("ScanTextForSecretsWithConfig() error: %v", err)
	}
	// Custom pattern should be found
	if len(matches) < 1 {
		t.Error("expected at least 1 match")
	}
}

func TestScanTextForSecretsWithConfigInvalid(t *testing.T) {
	patterns := []string{
		`[invalid(regex`,
	}

	_, err := ScanTextForSecretsWithConfig("text", patterns)
	if err == nil {
		t.Error("expected error for invalid pattern")
	}
}

func TestValidateSecretValid(t *testing.T) {
	result := ValidateSecret("sk_live_1234567890abcdefghij")
	if !result.Valid {
		t.Error("expected valid Stripe key")
	}
	if result.Severity != 4 {
		t.Errorf("expected severity 4, got %d", result.Severity)
	}
	if result.Provider != "Stripe" {
		t.Errorf("expected provider Stripe, got %s", result.Provider)
	}
}

func TestValidateSecretInvalid(t *testing.T) {
	result := ValidateSecret("not-a-secret")
	if result.Valid {
		t.Error("expected invalid for non-secret")
	}
	if !result.FalsePositive {
		t.Error("expected false positive")
	}
}

func TestValidateSecretEmpty(t *testing.T) {
	result := ValidateSecret("")
	if result.Valid {
		t.Error("expected empty string to be invalid")
	}
}

func TestValidateSecretTooShort(t *testing.T) {
	result := ValidateSecret("short")
	if result.Valid {
		t.Error("expected short string to be invalid")
	}
}

func TestValidateSecretJWTStruct(t *testing.T) {
	result := ValidateSecret("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	if !result.Valid {
		t.Error("expected valid JWT")
	}
	if result.Category != SECRET_JWT {
		t.Errorf("expected JWT category, got %v", result.Category)
	}
}

func TestValidateSecretPrivateKey(t *testing.T) {
	result := ValidateSecret("-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----")
	if !result.Valid {
		t.Error("expected valid private key")
	}
	if result.Category != SECRET_PRIVATE_KEY {
		t.Errorf("expected private key category, got %v", result.Category)
	}
}

func TestValidateSecretAWSKey(t *testing.T) {
	result := ValidateSecret("AKIAIOSFODNN7EXAMPLE")
	if !result.Valid {
		t.Error("expected valid AWS key")
	}
	if result.Provider != "AWS" {
		t.Errorf("expected provider AWS, got %s", result.Provider)
	}
}

func TestValidateSecretGitHubToken(t *testing.T) {
	result := ValidateSecret("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
	if !result.Valid {
		t.Error("expected valid GitHub token")
	}
	if result.Provider != "GitHub" {
		t.Errorf("expected provider GitHub, got %s", result.Provider)
	}
}

func TestValidateSecretUnknown(t *testing.T) {
	// A long random string that doesn't match any pattern
	result := ValidateSecret("this_is_a_long_random_string_without_any_meaning_12345")
	if result.Valid {
		t.Error("expected random string to be invalid")
	}
}

func TestSeverityDistributionEmpty(t *testing.T) {
	detector := NewSecretDetector()
	dist := detector.SeverityDistribution([]SecretMatch{})
	if len(dist) != 0 {
		t.Error("expected empty distribution for empty matches")
	}
}

func TestSeverityDistributionPopulated(t *testing.T) {
	detector := NewSecretDetector()
	
	// Create some matches
	matches := []SecretMatch{
		{Severity: 5},
		{Severity: 4},
		{Severity: 4},
		{Severity: 3},
	}
	
	dist := detector.SeverityDistribution(matches)
	if dist[5] != 1 {
		t.Errorf("expected 1 match with severity 5, got %d", dist[5])
	}
	if dist[4] != 2 {
		t.Errorf("expected 2 matches with severity 4, got %d", dist[4])
	}
	if dist[3] != 1 {
		t.Errorf("expected 1 match with severity 3, got %d", dist[3])
	}
}
