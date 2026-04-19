// Copyright 2024 AegisGate Security. All rights reserved.

package metrics

import (
	"testing"
)

// ---------------------------------------------------------------------------
// SanitizeEndpoint tests
// ---------------------------------------------------------------------------

func TestSanitizeEndpoint_EmptyPath(t *testing.T) {
	s := NewSanitizer()
	result := s.SanitizeEndpoint("")
	if result != "/" {
		t.Errorf("SanitizeEndpoint('') = %q, want %q", result, "/")
	}
}

func TestSanitizeEndpoint_RootPath(t *testing.T) {
	s := NewSanitizer()
	result := s.SanitizeEndpoint("/")
	if result != "/" {
		t.Errorf("SanitizeEndpoint('/') = %q, want %q", result, "/")
	}
}

func TestSanitizeEndpoint_KnownPaths(t *testing.T) {
	s := NewSanitizer()
	tests := []struct {
		input    string
		expected string
	}{
		// Health and metrics should collapse to their root
		{"/health", "/health"},
		{"/health/live", "/health"},
		{"/health/ready", "/health"},
		{"/metrics", "/metrics"},
		{"/metrics/prometheus", "/metrics"},
		// Versioned API paths should preserve the /api/vN prefix
		{"/api/v1/users", "/api/vN/users"},
		{"/api/v2/tokens", "/api/vN/tokens"},
		// MCP paths
		{"/mcp/tools/invoke", "/mcp/:operation"},
		{"/mcp/sessions/list", "/mcp/:operation"},
		// Admin paths
		{"/admin/settings/general", "/admin/:action"},
		// Static paths
		{"/static/js/app.bundle.js", "/static/:file"},
		{"/static/css/styles.css", "/static/:file"},
		// Proxy paths
		{"/proxy/config/reload", "/proxy/:action"},
	}

	for _, tc := range tests {
		result := s.SanitizeEndpoint(tc.input)
		if result != tc.expected {
			t.Errorf("SanitizeEndpoint(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestSanitizeEndpoint_UUIDsCollapsed(t *testing.T) {
	s := NewSanitizer()
	tests := []struct {
		input    string
		contains string // Check that the result contains these substrings
	}{
		{"/api/v1/users/550e8400-e29b-41d4-a716-446655440000", ":uuid"},
		{"/users/550e8400-e29b-41d4-a716-446655440000/profile", ":uuid"},
	}

	for _, tc := range tests {
		result := s.SanitizeEndpoint(tc.input)
		if !contains(result, tc.contains) {
			t.Errorf("SanitizeEndpoint(%q) = %q, want it to contain %q", tc.input, result, tc.contains)
		}
	}
}

func TestSanitizeEndpoint_NumericIDsCollapsed(t *testing.T) {
	s := NewSanitizer()
	result := s.SanitizeEndpoint("/users/12345/profile")
	if !contains(result, ":id") {
		t.Errorf("SanitizeEndpoint('/users/12345/profile') = %q, want it to contain :id", result)
	}
}

func TestSanitizeEndpoint_MongoDBObjectIDsCollapsed(t *testing.T) {
	s := NewSanitizer()
	result := s.SanitizeEndpoint("/documents/507f1f77bcf86cd799439011")
	if !contains(result, ":objid") {
		t.Errorf("SanitizeEndpoint('/documents/507f1f77bcf86cd799439011') = %q, want it to contain :objid", result)
	}
}

func TestSanitizeEndpoint_QueryParamsStripped(t *testing.T) {
	s := NewSanitizer()
	result := s.SanitizeEndpoint("/api/v1/users?limit=10&offset=20")
	if contains(result, "?") || contains(result, "limit") {
		t.Errorf("SanitizeEndpoint should strip query params, got %q", result)
	}
}

func TestSanitizeEndpoint_FragmentStripped(t *testing.T) {
	s := NewSanitizer()
	result := s.SanitizeEndpoint("/api/v1/users#section")
	if contains(result, "#") || contains(result, "section") {
		t.Errorf("SanitizeEndpoint should strip fragments, got %q", result)
	}
}

func TestSanitizeEndpoint_CacheHit(t *testing.T) {
	s := NewSanitizer()
	// First call populates the cache
	result1 := s.SanitizeEndpoint("/api/v1/users/123")
	// Second call should hit cache
	result2 := s.SanitizeEndpoint("/api/v1/users/123")
	if result1 != result2 {
		t.Errorf("Cache miss: second call returned different result: %q vs %q", result1, result2)
	}
}

func TestPackageLevelSanitizeEndpoint(t *testing.T) {
	// Package-level convenience functions should work
	result := SanitizeEndpoint("/health")
	if result != "/health" {
		t.Errorf("Package-level SanitizeEndpoint('/health') = %q, want '/health'", result)
	}
}

// ---------------------------------------------------------------------------
// SanitizeToolName tests
// ---------------------------------------------------------------------------

func TestSanitizeToolName_Whitelisted(t *testing.T) {
	allowed := []string{"scan_content", "list_tools", "invoke_method"}
	result := SanitizeToolName("scan_content", allowed)
	if result != "scan_content" {
		t.Errorf("SanitizeToolName('scan_content', allowed) = %q, want 'scan_content'", result)
	}
}

func TestSanitizeToolName_UnknownBucketedAsOther(t *testing.T) {
	allowed := []string{"scan_content", "list_tools"}
	result := SanitizeToolName("malicious_tool", allowed)
	if result != "unknown" {
		t.Errorf("SanitizeToolName('malicious_tool', allowed) = %q, want 'unknown'", result)
	}
}

func TestSanitizeToolName_EmptyAllowed(t *testing.T) {
	result := SanitizeToolName("any_tool", nil)
	if result != "unknown" {
		t.Errorf("SanitizeToolName with nil allowed = %q, want 'unknown'", result)
	}
}

func TestSanitizeToolName_EmptyName(t *testing.T) {
	result := SanitizeToolName("", nil)
	if result != "unknown" {
		t.Errorf("SanitizeToolName('', nil) = %q, want 'unknown'", result)
	}
}

// ---------------------------------------------------------------------------
// SanitizeClientID tests
// ---------------------------------------------------------------------------

func TestSanitizeClientID_Empty(t *testing.T) {
	result := SanitizeClientID("")
	if result != "anonymous" {
		t.Errorf("SanitizeClientID('') = %q, want 'anonymous'", result)
	}
}

func TestSanitizeClientID_IPv4(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.100", "192.168.x.x"},
		{"10.0.0.1", "10.0.x.x"},
		{"172.16.0.50", "172.16.x.x"},
	}

	for _, tc := range tests {
		result := SanitizeClientID(tc.input)
		if result != tc.expected {
			t.Errorf("SanitizeClientID(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestSanitizeClientID_IPv6(t *testing.T) {
	result := SanitizeClientID("2001:db8::1")
	if !contains(result, "2001") || !contains(result, "::/") {
		t.Errorf("SanitizeClientID('2001:db8::1') = %q, want IPv6 prefix bucketing", result)
	}
}

func TestSanitizeClientID_NonIP(t *testing.T) {
	result := SanitizeClientID("service-account-abc")
	if result != "service-account-abc" {
		t.Errorf("SanitizeClientID('service-account-abc') = %q, want 'service-account-abc'", result)
	}
}

func TestSanitizeClientID_LongIdentifier(t *testing.T) {
	longID := "very_long_service_account_identifier_that_exceeds_the_maximum_allowed_length_limit_sixty_four"
	result := SanitizeClientID(longID)
	if len(result) > 64 {
		t.Errorf("SanitizeClientID should truncate long identifiers, got len=%d", len(result))
	}
}

// ---------------------------------------------------------------------------
// ValidateLabelValue tests
// ---------------------------------------------------------------------------

func TestValidateLabelValue_Empty(t *testing.T) {
	result := ValidateLabelValue("", 128)
	if result != "empty" {
		t.Errorf("ValidateLabelValue('', 128) = %q, want 'empty'", result)
	}
}

func TestValidateLabelValue_SafeChars(t *testing.T) {
	result := ValidateLabelValue("proxy_service-1", 128)
	if result != "proxy_service-1" {
		t.Errorf("ValidateLabelValue('proxy_service-1', 128) = %q, want 'proxy_service-1'", result)
	}
}

func TestValidateLabelValue_UnsafeChars(t *testing.T) {
	result := ValidateLabelValue("hello world!@#$%", 128)
	if contains(result, " ") {
		t.Errorf("ValidateLabelValue should replace unsafe chars, got %q", result)
	}
}

func TestValidateLabelValue_Truncation(t *testing.T) {
	longValue := "short"
	result := ValidateLabelValue(longValue, 3)
	if len(result) > 3 {
		t.Errorf("ValidateLabelValue should truncate to maxLen, got len=%d", len(result))
	}
}

// ---------------------------------------------------------------------------
// CardinalityTier tests
// ---------------------------------------------------------------------------

func TestCardinalityTier_Values(t *testing.T) {
	if CardinalityLow >= CardinalityMedium {
		t.Errorf("CardinalityLow (%d) should be less than CardinalityMedium (%d)", CardinalityLow, CardinalityMedium)
	}
	if CardinalityMedium >= CardinalityHigh {
		t.Errorf("CardinalityMedium (%d) should be less than CardinalityHigh (%d)", CardinalityMedium, CardinalityHigh)
	}
	if CardinalityHigh >= CardinalityUnbounded {
		t.Errorf("CardinalityHigh (%d) should be less than CardinalityUnbounded (%d)", CardinalityHigh, CardinalityUnbounded)
	}
}

func TestCardinalityLimit(t *testing.T) {
	if CardinalityLimit != 1000 {
		t.Errorf("CardinalityLimit = %d, want 1000", CardinalityLimit)
	}
}

// ---------------------------------------------------------------------------
// Sanitizer concurrency test
// ---------------------------------------------------------------------------

func TestSanitizer_ConcurrentAccess(t *testing.T) {
	s := NewSanitizer()
	done := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		go func(id int) {
			path := "/api/v1/users/"
			if id%2 == 0 {
				path += "123"
			} else {
				path += "456"
			}
			s.SanitizeEndpoint(path)
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
	// If we get here without panicking, the concurrent access is safe
}

// helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr || len(s) > len(substr) && containsInMiddle(s, substr)
}

func containsInMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
