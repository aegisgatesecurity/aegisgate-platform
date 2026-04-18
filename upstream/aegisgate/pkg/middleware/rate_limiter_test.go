package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

func createTestRequest(xForwardedFor, cfConnectingIP, trueClientIP string) *http.Request {
	req := httptest.NewRequest("GET", "/test", nil)
	if xForwardedFor != "" {
		req.Header.Set("X-Forwarded-For", xForwardedFor)
	}
	if cfConnectingIP != "" {
		req.Header.Set("cf-connecting-ip", cfConnectingIP)
	}
	if trueClientIP != "" {
		req.Header.Set("True-Client-IP", trueClientIP)
	}
	return req
}

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
			if result := isValidIP(tt.ip); result != tt.expected {
				t.Errorf("isValidIP(%q) = %v, want %v", tt.ip, result, tt.expected)
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
			if result := isPrivateIP(tt.ip); result != tt.expected {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestGetRealClientIP_Cloudflare(t *testing.T) {
	req := createTestRequest("", "203.0.113.50", "")
	ip := getRealClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("got %q, want 203.0.113.50", ip)
	}
}

func TestGetRealClientIP_XForwardedFor_NotTrusted(t *testing.T) {
	req := createTestRequest("203.0.113.99", "", "")
	ip := getRealClientIP(req)
	if ip == "203.0.113.99" {
		t.Error("Should not trust public IP in X-Forwarded-For")
	}
}

func TestGetRealClientIP_XForwardedFor_TrustedIfPrivate(t *testing.T) {
	req := createTestRequest("10.0.0.50, 192.168.1.1", "", "")
	ip := getRealClientIP(req)
	if ip != "10.0.0.50" {
		t.Errorf("got %q, want 10.0.0.50", ip)
	}
}

func TestDefaultKeyFunc_UseAPIKey(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "test-key")
	key := DefaultKeyFunc(req)
	if key != "api:test-key" {
		t.Errorf("got %q, want api:test-key", key)
	}
}

func TestDefaultKeyFunc_UseIP(t *testing.T) {
	req := createTestRequest("10.0.0.1", "", "")
	key := DefaultKeyFunc(req)
	if key == "" || key[:3] != "ip:" {
		t.Errorf("got %q, want ip:...", key)
	}
}

func TestRateLimiter_AllowsFirstRequests(t *testing.T) {
	config := DefaultRateLimitConfig(core.TierCommunity)
	rl := NewRateLimiter(config)

	allowed, remaining, _ := rl.Allow("test-key")
	if !allowed {
		t.Error("First request should be allowed")
	}
	if remaining >= 50 {
		t.Errorf("Remaining should be less than 50, got %d", remaining)
	}
}

func TestRateLimiter_DifferentClientsHaveSeparateLimits(t *testing.T) {
	config := DefaultRateLimitConfig(core.TierCommunity)
	rl := NewRateLimiter(config)

	for i := 0; i < 55; i++ {
		rl.Allow("client1")
	}

	allowed, _, _ := rl.Allow("client2")
	if !allowed {
		t.Error("Different clients should have separate rate limit buckets")
	}
}

func BenchmarkIsValidIP(b *testing.B) {
	ips := []string{"8.8.8.8", "10.0.0.1", "192.168.1.1"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ip := range ips {
			isValidIP(ip)
		}
	}
}

func BenchmarkIsPrivateIP(b *testing.B) {
	ips := []string{"8.8.8.8", "10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ip := range ips {
			isPrivateIP(ip)
		}
	}
}
