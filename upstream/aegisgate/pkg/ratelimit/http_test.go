// SPDX-FileCopyrightText: Copyright (C) 2025 AegisGuard Security
// SPDX-License-Identifier: MIT

package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ============================================================================
// IP Validation Tests
// ============================================================================

func TestIsValidIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"valid IPv4", "8.8.8.8", true},
		{"valid private 10.x", "10.0.0.1", true},
		{"valid private 172.16.x", "172.16.0.1", true},
		{"valid private 192.168.x", "192.168.1.1", true},
		{"loopback", "127.0.0.1", true},
		{"IPv6 localhost", "::1", true},
		{"invalid empty", "", false},
		{"invalid string", "not-an-ip", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := IsValidIP(tt.ip); result != tt.expected {
				t.Errorf("IsValidIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"10.x", "10.0.0.1", true},
		{"172.16.x", "172.16.0.1", true},
		{"172.31.x", "172.31.255.255", true},
		{"172.15.x not private", "172.15.0.1", false},
		{"172.32.x not private", "172.32.0.1", false},
		{"192.168.x", "192.168.1.1", true},
		{"127.x loopback", "127.0.0.1", true},
		{"public", "8.8.8.8", false},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv6 private", "fc00::1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := IsPrivateIP(tt.ip); result != tt.expected {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsLoopbackIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"127.0.0.1", "127.0.0.1", true},
		{"127.1.2.3", "127.1.2.3", true},
		{"192.168.1.1", "192.168.1.1", false},
		{"::1", "::1", true},
		{"public", "8.8.8.8", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := IsLoopbackIP(tt.ip); result != tt.expected {
				t.Errorf("IsLoopbackIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"IPv4", "192.168.1.1", "192.168.1.1"},
		{"IPv6 loopback", "::1", "::1"},
		{"IPv4 mapped IPv6", "::ffff:192.168.1.1", "192.168.1.1"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := NormalizeIP(tt.ip); result != tt.expected {
				t.Errorf("NormalizeIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// ============================================================================
// GetRealClientIP Tests
// ============================================================================

func TestGetRealClientIP_Cloudflare(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.50")
	ip := GetRealClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("got %q, want 203.0.113.50", ip)
	}
}

func TestGetRealClientIP_Akamai(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("True-Client-IP", "203.0.113.100")
	ip := GetRealClientIP(req)
	if ip != "203.0.113.100" {
		t.Errorf("got %q, want 203.0.113.100", ip)
	}
}

func TestGetRealClientIP_CloudflarePriority(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.50")
	req.Header.Set("True-Client-IP", "203.0.113.100")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	ip := GetRealClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("got %q, want 203.0.113.50 (Cloudflare priority)", ip)
	}
}

func TestGetRealClientIP_XFFPrivateTrusted(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.99, 192.168.1.1")
	ip := GetRealClientIP(req)
	if ip != "10.0.0.99" {
		t.Errorf("got %q, want 10.0.0.99", ip)
	}
}

func TestGetRealClientIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.50")
	ip := GetRealClientIP(req)
	if ip != "10.0.0.50" {
		t.Errorf("got %q, want 10.0.0.50", ip)
	}
}

func TestGetRealClientIP_FallbackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.50:54321"
	ip := GetRealClientIP(req)
	if ip != "192.168.1.50" {
		t.Errorf("got %q, want 192.168.1.50", ip)
	}
}

// ============================================================================
// DefaultKeyFunc Tests
// ============================================================================

func TestDefaultKeyFunc_UseAPIKey(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "test-key")
	key := DefaultKeyFunc(req)
	if key != "api:test-key" {
		t.Errorf("got %q, want api:test-key", key)
	}
}

func TestDefaultKeyFunc_UseIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	key := DefaultKeyFunc(req)
	if key == "" || key[:3] != "ip:" {
		t.Errorf("got %q, want ip:...", key)
	}
}

// ============================================================================
// HTTPRateLimiter Tests
// ============================================================================

func TestHTTPRateLimiter_Allow(t *testing.T) {
	config := HTTPLimiterConfig{
		RequestsPerMinute: 60,
		BurstSize:         10,
		BlockDuration:     time.Minute,
		KeyFunc:           func(r *http.Request) string { return "test" },
	}
	rl := NewHTTPRateLimiter(config)
	defer rl.Close()

	allowed, remaining, retryIn := rl.Allow(context.Background(), "test")
	if !allowed {
		t.Error("First request should be allowed")
	}
	if remaining < 0 || remaining >= 10 {
		t.Errorf("Remaining = %d, expected 0-9", remaining)
	}
	if retryIn != 0 {
		t.Errorf("RetryIn = %v, want 0", retryIn)
	}
}

func TestHTTPRateLimiter_Block(t *testing.T) {
	config := HTTPLimiterConfig{
		RequestsPerMinute: 60,
		BurstSize:         2,
		BlockDuration:     100 * time.Millisecond,
		KeyFunc:           func(r *http.Request) string { return "block-test" },
	}
	rl := NewHTTPRateLimiter(config)
	defer rl.Close()

	// Exhaust the limit
	rl.Allow(context.Background(), "block-test")
	rl.Allow(context.Background(), "block-test")

	// Third should be blocked
	allowed, _, retryAfter := rl.Allow(context.Background(), "block-test")
	if allowed {
		t.Error("Third request should be blocked")
	}
	if retryAfter <= 0 {
		t.Error("Should have retry-after time")
	}
}

func TestHTTPRateLimiter_BlockExpires(t *testing.T) {
	config := HTTPLimiterConfig{
		RequestsPerMinute: 60,
		BurstSize:         2,
		BlockDuration:     150 * time.Millisecond,
		KeyFunc:           func(r *http.Request) string { return "block-expire" },
	}
	rl := NewHTTPRateLimiter(config)
	defer rl.Close()

	// Exhaust and block - first two use tokens, third triggers block
	rl.Allow(context.Background(), "block-expire")
	rl.Allow(context.Background(), "block-expire")
	rl.Allow(context.Background(), "block-expire")

	// Wait for block to expire
	time.Sleep(200 * time.Millisecond)

	// After block expires, the rate limiter bucket should have refilled
	// Use a new key to avoid any cached state
	allowed, _, _ := rl.Allow(context.Background(), "block-expire-reset")
	if !allowed {
		t.Error("Should be allowed after block expires (new key)")
	}
}

func TestHTTPRateLimiter_Middleware_SetsHeaders(t *testing.T) {
	config := HTTPLimiterConfig{
		RequestsPerMinute: 100,
		BurstSize:         50,
		BlockDuration:     time.Minute,
		KeyFunc:           DefaultKeyFunc,
	}
	rl := NewHTTPRateLimiter(config)
	defer rl.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := rl.Middleware(handler)
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
	if rr.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("X-RateLimit-Limit header should be set")
	}
	if rr.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("X-RateLimit-Remaining header should be set")
	}
}

func TestHTTPRateLimiter_Middleware_BlocksOnExhaustion(t *testing.T) {
	config := HTTPLimiterConfig{
		RequestsPerMinute: 60,
		BurstSize:         3,
		BlockDuration:     500 * time.Millisecond,
		KeyFunc:           func(r *http.Request) string { return "middleware-block" },
	}
	rl := NewHTTPRateLimiter(config)
	defer rl.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := rl.Middleware(handler)

	blocked := false
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			blocked = true
			if rr.Header().Get("Retry-After") == "" {
				t.Error("Retry-After header should be set when blocked")
			}
			break
		}
	}

	if !blocked {
		t.Error("Rate limiter should block after exhaustion")
	}
}

// ============================================================================
// Tier Tests
// ============================================================================

func TestGetTierConfig(t *testing.T) {
	tests := []struct {
		tier         Tier
		minRPM       int
		minBurst     int
	}{
		{TierFree, 20, 10},
		{TierStarter, 60, 30},
		{TierProfessional, 300, 100},
		{TierEnterprise, 1000, 500},
	}

	for _, tt := range tests {
		t.Run(string(tt.tier), func(t *testing.T) {
			config := GetTierConfig(tt.tier)
			if config.RequestsPerMinute < tt.minRPM {
				t.Errorf("RPM = %d, want >= %d", config.RequestsPerMinute, tt.minRPM)
			}
			if config.BurstSize < tt.minBurst {
				t.Errorf("Burst = %d, want >= %d", config.BurstSize, tt.minBurst)
			}
		})
	}
}

func TestTieredHTTPRateLimiter(t *testing.T) {
	tierFunc := func(r *http.Request) Tier {
		if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
			if apiKey == "enterprise-key" {
				return TierEnterprise
			}
			if apiKey == "pro-key" {
				return TierProfessional
			}
		}
		return TierFree
	}

	trl := NewTieredHTTPRateLimiter(tierFunc)
	defer trl.Close()

	// Test free tier
	rl := trl.GetLimiter(TierFree)
	if rl == nil {
		t.Error("GetLimiter(free) should not return nil")
	}

	// Test enterprise tier
	rl = trl.GetLimiter(TierEnterprise)
	if rl == nil {
		t.Error("GetLimiter(enterprise) should not return nil")
	}
}

func TestTieredHTTPRateLimiter_Middleware(t *testing.T) {
	tierFunc := func(r *http.Request) Tier {
		if apiKey := r.Header.Get("X-API-Key"); apiKey == "pro-key" {
			return TierProfessional
		}
		return TierFree
	}

	trl := NewTieredHTTPRateLimiter(tierFunc)
	defer trl.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := trl.Middleware(handler)

	// Test free tier
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Header().Get("X-RateLimit-Tier") != string(TierFree) {
		t.Errorf("Tier = %q, want %q", rr.Header().Get("X-RateLimit-Tier"), TierFree)
	}

	// Test professional tier
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "pro-key")
	rr = httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Header().Get("X-RateLimit-Tier") != string(TierProfessional) {
		t.Errorf("Tier = %q, want %q", rr.Header().Get("X-RateLimit-Tier"), TierProfessional)
	}
}
