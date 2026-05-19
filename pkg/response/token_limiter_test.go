// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Token Limiter Tests
// =========================================================================

package response

import (
	"testing"
	"time"
)

func TestNewTokenLimiter(t *testing.T) {
	limiter := NewTokenLimiter(nil)
	if limiter == nil {
		t.Fatal("NewTokenLimiter() returned nil")
	}
	if limiter.config == nil {
		t.Error("config should have default value")
	}
}

func TestNewTokenLimiterWithConfig(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.MaxTokensPerResponse = 4096
	config.TokensPerMinute = 50000

	limiter := NewTokenLimiter(config)
	if limiter == nil {
		t.Fatal("NewTokenLimiterWithConfig() returned nil")
	}

	if limiter.config.MaxTokensPerResponse != 4096 {
		t.Errorf("expected MaxTokensPerResponse=4096, got %d", limiter.config.MaxTokensPerResponse)
	}
}

func TestCountTokens(t *testing.T) {
	limiter := NewTokenLimiter(nil)

	tests := []struct {
		text     string
		expected int
	}{
		{"single word", 1},             // 1 word ≈ 1.33 tokens, floor to 1
		{"two words", 2},               // 2 words ≈ 2.67 tokens, floor to 2
		{"hello world", 2},             // 2 words
		{"", 0},                        // empty
		{"one", 1},                     // 1 word
		{"This is a test sentence", 4}, // 5 words
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			count := limiter.CountTokens(tt.text)
			if count < tt.expected {
				t.Errorf("CountTokens(%q) = %d, want >= %d", tt.text, count, tt.expected)
			}
		})
	}
}

func TestCountTokensLongText(t *testing.T) {
	limiter := NewTokenLimiter(nil)

	// 1000 word text
	word := "testword "
	text := ""
	for i := 0; i < 1000; i++ {
		text += word
	}

	count := limiter.CountTokens(text)
	expectedMin := 1000

	if count < expectedMin {
		t.Errorf("CountTokens(long_text) = %d, want >= %d", count, expectedMin)
	}
}

func TestAllowToken(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.TokensPerMinute = 10000
	config.MaxResponsesPerMinute = 10
	config.MaxTokensPerResponse = 2000
	config.WindowDuration = time.Minute

	limiter := NewTokenLimiter(config)

	// First request should be allowed
	allowed, reason := limiter.AllowToken("client-1", 100)
	if !allowed {
		t.Errorf("first request should be allowed, got: %s", reason)
	}

	// Second request should also be allowed
	allowed, reason = limiter.AllowToken("client-1", 100)
	if !allowed {
		t.Errorf("second request should be allowed, got: %s", reason)
	}
}

func TestAllowTokenExceedsMaxPerResponse(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.MaxTokensPerResponse = 1000
	config.TokensPerMinute = 100000
	config.MaxResponsesPerMinute = 100

	limiter := NewTokenLimiter(config)

	// Request with too many tokens
	allowed, reason := limiter.AllowToken("client-1", 2000)
	if allowed {
		t.Error("expected request to be rejected for exceeding max tokens per response")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestAllowTokenExceedsRateLimit(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.TokensPerMinute = 100000 // High enough that request limit hits first
	config.MaxResponsesPerMinute = 5
	config.MaxTokensPerResponse = 2000
	config.WindowDuration = time.Minute

	limiter := NewTokenLimiter(config)

	// Use up the request rate limit
	for i := 0; i < 5; i++ {
		allowed, _ := limiter.AllowToken("client-1", 100)
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be rejected due to request rate limit
	allowed, reason := limiter.AllowToken("client-1", 100)
	if allowed {
		t.Error("expected 6th request to be rejected")
	}
	if reason != "Request rate limit exceeded" {
		t.Errorf("expected 'Request rate limit exceeded', got: %s", reason)
	}
}

func TestAllowTokenExceedsTokenLimit(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.TokensPerMinute = 1000
	config.MaxResponsesPerMinute = 100
	config.MaxTokensPerResponse = 2000
	config.WindowDuration = time.Minute

	limiter := NewTokenLimiter(config)

	// Use up tokens
	for i := 0; i < 5; i++ {
		allowed, _ := limiter.AllowToken("client-1", 200)
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be rejected (1000 tokens used, trying to add 200)
	allowed, reason := limiter.AllowToken("client-1", 200)
	if allowed {
		t.Error("expected request to be rejected for exceeding token limit")
	}
	if reason != "Token rate limit exceeded" {
		t.Errorf("expected 'Token rate limit exceeded', got: %s", reason)
	}
}

func TestAllowTokenDifferentClients(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.TokensPerMinute = 500
	config.MaxResponsesPerMinute = 2
	config.MaxTokensPerResponse = 2000

	limiter := NewTokenLimiter(config)

	// Client 1 uses up their limit
	limiter.AllowToken("client-1", 300)
	limiter.AllowToken("client-1", 300)

	// Client 2 should still be allowed
	allowed, _ := limiter.AllowToken("client-2", 300)
	if !allowed {
		t.Error("client-2 should still have quota")
	}
}

func TestGetUsage(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.TokensPerMinute = 10000
	config.WindowDuration = time.Minute

	limiter := NewTokenLimiter(config)

	// Initially no usage
	tokens, requests := limiter.GetUsage("new-client")
	if tokens != 0 || requests != 0 {
		t.Errorf("expected 0 tokens, 0 requests for new client, got %d, %d", tokens, requests)
	}

	// Add some usage
	limiter.AllowToken("test-client", 100)
	limiter.AllowToken("test-client", 200)

	// Check usage
	tokens, requests = limiter.GetUsage("test-client")
	if tokens != 300 {
		t.Errorf("expected 300 tokens, got %d", tokens)
	}
	if requests != 2 {
		t.Errorf("expected 2 requests, got %d", requests)
	}
}

func TestGetUsageExpired(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.WindowDuration = 100 * time.Millisecond

	limiter := NewTokenLimiter(config)

	// Add usage
	limiter.AllowToken("test-client", 100)

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Usage should be expired
	tokens, requests := limiter.GetUsage("test-client")
	if tokens != 0 || requests != 0 {
		t.Errorf("expected 0 tokens, 0 requests after expiry, got %d, %d", tokens, requests)
	}
}

func TestTokenLimiterResetUsage(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.TokensPerMinute = 10000

	limiter := NewTokenLimiter(config)

	// Add usage
	limiter.AllowToken("test-client", 100)
	limiter.AllowToken("test-client", 200)

	// Reset
	limiter.ResetUsage("test-client")

	// Check usage is reset
	tokens, requests := limiter.GetUsage("test-client")
	if tokens != 0 || requests != 0 {
		t.Errorf("expected 0 tokens, 0 requests after reset, got %d, %d", tokens, requests)
	}
}

func TestTokenLimiterResetUsageNonExistent(t *testing.T) {
	limiter := NewTokenLimiter(nil)

	// Should not panic
	limiter.ResetUsage("non-existent-client")
}

func TestTokenLimiterResetAll(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.TokensPerMinute = 10000

	limiter := NewTokenLimiter(config)

	// Add usage for multiple clients
	limiter.AllowToken("client-1", 100)
	limiter.AllowToken("client-2", 200)
	limiter.AllowToken("client-3", 300)

	// Reset all
	limiter.ResetAll()

	// Check all are reset
	for _, client := range []string{"client-1", "client-2", "client-3"} {
		tokens, requests := limiter.GetUsage(client)
		if tokens != 0 || requests != 0 {
			t.Errorf("expected 0 tokens, 0 requests for %s, got %d, %d", client, tokens, requests)
		}
	}
}

func TestTokenLimiterConcurrency(t *testing.T) {
	config := DefaultTokenLimiterConfig()
	config.TokensPerMinute = 100000
	config.MaxResponsesPerMinute = 10000
	config.WindowDuration = time.Minute

	limiter := NewTokenLimiter(config)
	done := make(chan bool, 10)

	// Run concurrent requests
	for i := 0; i < 10; i++ {
		go func(clientID string) {
			for j := 0; j < 100; j++ {
				limiter.AllowToken(clientID, 10)
				limiter.GetUsage(clientID)
			}
			done <- true
		}("client-" + string('0'+byte(i)))
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestTokenLimiterEdgeCases(t *testing.T) {
	limiter := NewTokenLimiter(nil)

	// Empty client ID
	allowed, _ := limiter.AllowToken("", 100)
	if !allowed {
		t.Error("empty client ID should be allowed")
	}

	// Zero tokens
	allowed, _ = limiter.AllowToken("test-client", 0)
	if !allowed {
		t.Error("zero tokens should be allowed")
	}
}

func BenchmarkCountTokens(b *testing.B) {
	limiter := NewTokenLimiter(nil)
	text := "This is a sample text for benchmarking token counting in the response guard."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.CountTokens(text)
	}
}

func BenchmarkAllowToken(b *testing.B) {
	config := DefaultTokenLimiterConfig()
	limiter := NewTokenLimiter(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.AllowToken("bench-client", 100)
		limiter.ResetUsage("bench-client")
	}
}
