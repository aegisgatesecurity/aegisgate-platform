// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - ACP Guard Tests

package acp

import (
	"context"
	"testing"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

func TestNewACPResponseScanner(t *testing.T) {
	scanner := NewACPResponseScanner()
	if scanner == nil || scanner.guard == nil {
		t.Fatal("Expected non-nil scanner and guard")
	}
}

func TestNewACPResponseScannerWithNilConfig(t *testing.T) {
	scanner := NewACPResponseScannerWithConfig(nil)
	if scanner == nil {
		t.Fatal("Expected non-nil scanner even with nil config")
	}
}

func TestDefaultACPGuardConfig(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config")
	}
	if !cfg.EnableHMAC || !cfg.EnableRateLimiting {
		t.Error("Expected HMAC and rate limiting enabled by default")
	}
}

func TestDefaultACPGuardConfigRateLimit(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	if cfg.RateLimitBurst != 10 || cfg.RateLimitPerMinute != 60 {
		t.Error("Expected default rate limits of 10 burst, 60 RPM")
	}
}

func TestValidateACPMessageNil(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner.ValidateACPMessage(nil) != ErrNilMessage {
		t.Error("Expected ErrNilMessage")
	}
}

func TestValidateACPMessageEmptyMethod(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner.ValidateACPMessage(&ACPMessage{}) != ErrInvalidMethod {
		t.Error("Expected ErrInvalidMethod")
	}
}

func TestValidateACPMessageValid(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner.ValidateACPMessage(&ACPMessage{Method: "test"}) != nil {
		t.Error("Expected nil error")
	}
}

func TestValidateACPMessageBlocked(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.BlockMethod("blocked")
	if scanner.ValidateACPMessage(&ACPMessage{Method: "blocked"}) != ErrMethodBlocked {
		t.Error("Expected ErrMethodBlocked")
	}
}

func TestUnblockMethod(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.BlockMethod("test.method")
	scanner.UnblockMethod("test.method")
	if scanner.ValidateACPMessage(&ACPMessage{Method: "test.method"}) != nil {
		t.Error("Expected no error after unblock")
	}
}

func TestIsMethodBlocked(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.BlockMethod("test.blocked")
	if !scanner.IsMethodBlocked("test.blocked") {
		t.Error("Expected method to be blocked")
	}
	if scanner.IsMethodBlocked("test.unblocked") {
		t.Error("Expected method to not be blocked")
	}
}

func TestCheckRateLimit(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 10
	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner.CheckRateLimit("test-session") != nil {
		t.Error("First request should succeed")
	}
}

func TestCheckRateLimitMultiple(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 5
	scanner := NewACPResponseScannerWithConfig(cfg)
	for i := 0; i < 5; i++ {
		if scanner.CheckRateLimit("multi-test") != nil {
			t.Errorf("Request %d should succeed", i+1)
		}
	}
}

func TestCheckRateLimitExceeded(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 1
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.CheckRateLimit("exceeded")
	if scanner.CheckRateLimit("exceeded") != ErrRateLimited {
		t.Error("Expected ErrRateLimited")
	}
}

func TestCheckRateLimitDisabled(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = false
	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner.CheckRateLimit("disabled") != nil {
		t.Error("Rate limit disabled - should not error")
	}
}

func TestGetRateLimitRemaining(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 5
	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner.GetRateLimitRemaining("test") != 5 {
		t.Error("Expected 5 remaining")
	}
}

func TestGetRateLimitRemainingExhausted(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 1
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.CheckRateLimit("exhausted")
	if scanner.GetRateLimitRemaining("exhausted") != 0 {
		t.Error("Expected 0 remaining after exhaustion")
	}
}

func TestGetRateLimitRemainingNonexistent(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 5
	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner.GetRateLimitRemaining("nonexistent") != 5 {
		t.Error("Expected full tokens for nonexistent session")
	}
}

func TestScanResponse(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	rgCfg := responseguard.DefaultResponseGuardConfig()
	cfg.ResponseGuardConfig = rgCfg
	scanner := NewACPResponseScannerWithConfig(cfg)
	result, err := scanner.ScanResponse(context.Background(), "Hello world!", "test")
	if err != nil || result == nil || !result.Allowed {
		t.Error("Expected clean response to be allowed")
	}
}

func TestScanResponseWithPII(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.EnablePIIScanner = true
	cfg.ResponseGuardConfig = rgCfg
	scanner := NewACPResponseScannerWithConfig(cfg)
	result, err := scanner.ScanResponse(context.Background(), "Email: test@example.com", "pii-test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	t.Logf("PII scan: Allowed=%v, PII=%d", result.Allowed, len(result.DetectedPII))
}

func TestScanResponseStrict(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.StrictMode = true
	rgCfg.EnableSecretDetection = true
	cfg.ResponseGuardConfig = rgCfg
	scanner := NewACPResponseScannerWithConfig(cfg)
	result, err := scanner.ScanResponse(context.Background(), "Token: sk-1234567890", "strict")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	t.Logf("Strict scan: Allowed=%v", result.Allowed)
}

func TestScanResponseNilContext(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	result, err := scanner.ScanResponse(nil, "test content", "nil-ctx")
	if err != nil || result == nil {
		t.Error("Expected non-nil result for nil context")
	}
}

func TestScanACPMessage(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	result, err := scanner.ScanACPMessage(context.Background(), &ACPMessage{Method: "test", Result: "result"}, "msg")
	if err != nil || result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestScanACPMessageStringResult(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	msg := &ACPMessage{Method: "test.method", Result: "string result"}
	result, err := scanner.ScanACPMessage(context.Background(), msg, "str-msg")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	t.Logf("String result scan: Allowed=%v", result.Allowed)
}

func TestClearAllStats(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 10
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.CheckRateLimit("clear-test")
	scanner.ClearAllStats()
	// After clear, session should have full tokens again
	if scanner.GetRateLimitRemaining("clear-test") != 10 {
		t.Error("Expected stats to be cleared (full tokens)")
	}
}

func TestClearAllStatsOnEmptyScanner(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.ClearAllStats()
}

func TestEnsureLogger(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.cfg.Logger = nil
	scanner.EnsureLogger()
	if scanner.cfg.Logger == nil {
		t.Error("Expected logger to be set")
	}
}

func TestEnsureLoggerAlreadySet(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	originalLogger := scanner.cfg.Logger
	scanner.EnsureLogger()
	if scanner.cfg.Logger != originalLogger {
		t.Error("Logger should not change if already set")
	}
}

func TestSetGuardEnabled(t *testing.T) {
	SetGuardEnabled(true)
	SetGuardEnabled(false)
}

func TestSetActiveSessions(t *testing.T) {
	SetActiveSessions(0)
	SetActiveSessions(5)
}

func TestNewACPResponseScannerWithConfigAllFeatures(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 100
	cfg.RateLimitPerMinute = 6000
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.StrictMode = true
	rgCfg.EnablePIIScanner = true
	rgCfg.EnableSecretDetection = true
	cfg.ResponseGuardConfig = rgCfg

	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner == nil {
		t.Fatal("Expected non-nil scanner")
	}

	err := scanner.CheckRateLimit("feature-test")
	if err != nil {
		t.Errorf("First request should succeed: %v", err)
	}
}

// ============================================================================
// Additional Tests for Full Coverage
// ============================================================================

func TestScanAgentResponse(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.EnablePIIScanner = true
	rgCfg.EnableSecretDetection = true
	cfg.ResponseGuardConfig = rgCfg

	scanner := NewACPResponseScannerWithConfig(cfg)

	resp := &AgentResponse{ID: "test-1", Result: "Hello, how can I help you?"}
	result, err := scanner.ScanAgentResponse(context.Background(), resp, "agent-test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestScanAgentResponseWithPII(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	rgCfg := responseguard.DefaultResponseGuardConfig()
	rgCfg.StrictMode = true
	rgCfg.EnablePIIScanner = true
	cfg.ResponseGuardConfig = rgCfg

	scanner := NewACPResponseScannerWithConfig(cfg)

	resp := &AgentResponse{ID: "pii-1", Result: "User email: john@doe.com"}
	result, err := scanner.ScanAgentResponse(context.Background(), resp, "pii-agent-test")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	t.Logf("Agent PII scan: Allowed=%v, PII=%d", result.Allowed, len(result.DetectedPII))
}

func TestUpdateRateLimitStats(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 10
	scanner := NewACPResponseScannerWithConfig(cfg)

	sessionID := "rate-limit-stats"

	// First request
	err := scanner.CheckRateLimit(sessionID)
	if err != nil {
		t.Errorf("First request should succeed: %v", err)
	}

	// Second request
	err = scanner.CheckRateLimit(sessionID)
	if err != nil {
		t.Errorf("Second request should succeed: %v", err)
	}

	// Verify remaining
	remaining := scanner.GetRateLimitRemaining(sessionID)
	if remaining >= 10 {
		t.Errorf("Expected tokens consumed, remaining=%d", remaining)
	}
}

func TestUpdateRateLimitStatsBurst(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 3
	scanner := NewACPResponseScannerWithConfig(cfg)

	sessionID := "burst-stats"

	// Exhaust burst
	for i := 0; i < 3; i++ {
		err := scanner.CheckRateLimit(sessionID)
		if err != nil {
			t.Errorf("Request %d should succeed: %v", i+1, err)
		}
	}

	// Verify exhausted
	remaining := scanner.GetRateLimitRemaining(sessionID)
	if remaining != 0 {
		t.Errorf("Expected 0 remaining after burst, got %d", remaining)
	}
}

func TestNewACPResponseScannerWithNilResponseGuard(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.ResponseGuardConfig = nil

	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner == nil {
		t.Fatal("Expected non-nil scanner")
	}
	if scanner.guard == nil {
		t.Error("Expected guard to be initialized even with nil config")
	}
}

func TestGetSessionStatsNonExistent(t *testing.T) {
	scanner := NewACPResponseScanner()
	stats := scanner.GetSessionStats("non-existent")
	if stats != nil {
		t.Error("Expected nil for non-existent session")
	}
}

func TestCheckRateLimitBurst(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 3
	scanner := NewACPResponseScannerWithConfig(cfg)
	for i := 0; i < 3; i++ {
		err := scanner.CheckRateLimit("burst-test")
		if err != nil {
			t.Errorf("Request %d should succeed, got %v", i+1, err)
		}
	}
	err := scanner.CheckRateLimit("burst-test")
	if err == nil {
		t.Error("Expected rate limit error on 4th request")
	}
}

func TestResetAllSessionStatsMultiple(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 5
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.CheckRateLimit("s1")
	scanner.CheckRateLimit("s2")
	scanner.CheckRateLimit("s3")
	stats := scanner.ResetAllSessionStats()
	if len(stats) != 3 {
		t.Errorf("Expected 3 stats, got %d", len(stats))
	}
}

func TestClearSessionStats(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 5
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.CheckRateLimit("clear-me")
	scanner.ClearSessionStats("clear-me")
	// Should not panic
}

func TestClearAllStats(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableRateLimiting = true
	cfg.RateLimitBurst = 5
	scanner := NewACPResponseScannerWithConfig(cfg)
	scanner.CheckRateLimit("all")
	scanner.ClearAllStats()
	// Should not panic
}

func TestScanResponseWithPII(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnablePIIScanner = true
	scanner := NewACPResponseScannerWithConfig(cfg)
	result, err := scanner.ScanResponse(context.Background(), "Contact: john@example.com", "session-test")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestScanResponseWithSecret(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnableSecretDetection = true
	scanner := NewACPResponseScannerWithConfig(cfg)
	result, err := scanner.ScanResponse(context.Background(), "Password: secret123", "session-test")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestScanResponseStrictMode(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	cfg.EnablePIIScanner = true
	cfg.ResponseGuardConfig.StrictMode = true
	scanner := NewACPResponseScannerWithConfig(cfg)
	result, err := scanner.ScanResponse(context.Background(), "Email: test@test.com", "session-test")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}
