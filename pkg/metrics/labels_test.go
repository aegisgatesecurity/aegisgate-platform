// Copyright 2024 AegisGate Security. All rights reserved.

package metrics

import (
	"testing"
)

// ---------------------------------------------------------------------------
// StatusClass tests
// ---------------------------------------------------------------------------

func TestStatusClass(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		// 2xx Success
		{200, "2xx"},
		{201, "2xx"},
		{204, "2xx"},
		{299, "2xx"},
		// 3xx Redirection
		{301, "3xx"},
		{302, "3xx"},
		{304, "3xx"},
		{399, "3xx"},
		// 4xx Client error
		{400, "4xx"},
		{401, "4xx"},
		{403, "4xx"},
		{404, "4xx"},
		{429, "4xx"},
		{499, "4xx"},
		// 5xx Server error
		{500, "5xx"},
		{502, "5xx"},
		{503, "5xx"},
		{599, "5xx"},
		// Edge cases — codes outside standard ranges
		{100, "unknown"},
		{0, "unknown"},
		{99, "unknown"},
		{600, "unknown"},
		{-1, "unknown"},
	}

	for _, tc := range tests {
		result := StatusClass(tc.code)
		if result != tc.expected {
			t.Errorf("StatusClass(%d) = %q, want %q", tc.code, result, tc.expected)
		}
	}
}

func TestStatusClass_Constants(t *testing.T) {
	// Verify the constants match StatusClass output
	tests := []struct {
		code     int
		constant string
	}{
		{200, Status2xx},
		{301, Status3xx},
		{400, Status4xx},
		{500, Status5xx},
		{0, StatusUnknown},
	}

	for _, tc := range tests {
		result := StatusClass(tc.code)
		if result != tc.constant {
			t.Errorf("StatusClass(%d) = %q, want constant %q", tc.code, result, tc.constant)
		}
	}
}

// ---------------------------------------------------------------------------
// Label name constants tests
// ---------------------------------------------------------------------------

func TestLabelNameConstants(t *testing.T) {
	// Verify all label names follow Prometheus conventions (lowercase, underscores)
	labels := map[string]string{
		"method":    LabelMethod,
		"endpoint":  LabelEndpoint,
		"status":    LabelStatus,
		"service":   LabelService,
		"client":    LabelClient,
		"tool":      LabelTool,
		"tier":      LabelTier,
		"result":    LabelResult,
		"scan_type": LabelScanType,
		"direction": LabelDirection,
		"protocol":  LabelProtocol,
		"version":   LabelVersion,
		"guardrail": LabelGuardrail,
		"action":    LabelAction,
		"cache":     LabelCache,
	}

	for expected, actual := range labels {
		if actual != expected {
			t.Errorf("Label constant mismatch: expected %q, got %q", expected, actual)
		}
	}
}

// ---------------------------------------------------------------------------
// Value constants tests
// ---------------------------------------------------------------------------

func TestHTTPMethodConstants(t *testing.T) {
	methods := map[string]string{
		"GET":     MethodGET,
		"POST":    MethodPOST,
		"PUT":     MethodPUT,
		"DELETE":  MethodDelete,
		"PATCH":   MethodPatch,
		"HEAD":    MethodHead,
		"OPTIONS": MethodOptions,
		"CONNECT": MethodConnect,
	}

	for expected, actual := range methods {
		if actual != expected {
			t.Errorf("HTTP method constant: expected %q, got %q", expected, actual)
		}
	}
}

func TestResultConstants(t *testing.T) {
	results := map[string]string{
		"success":      ResultSuccess,
		"failure":      ResultFailure,
		"blocked":      ResultBlocked,
		"error":        ResultError,
		"timeout":      ResultTimeout,
		"rate_limited": ResultRateLimited,
	}

	for expected, actual := range results {
		if actual != expected {
			t.Errorf("Result constant: expected %q, got %q", expected, actual)
		}
	}
}

func TestServiceConstants(t *testing.T) {
	services := map[string]string{
		"proxy":       ServiceProxy,
		"mcp":         ServiceMCP,
		"dashboard":   ServiceDashboard,
		"persistence": ServicePersistence,
	}

	for expected, actual := range services {
		if actual != expected {
			t.Errorf("Service constant: expected %q, got %q", expected, actual)
		}
	}
}

func TestTierConstants(t *testing.T) {
	tiers := map[string]string{
		"community":    TierCommunity,
		"professional": TierProfessional,
		"enterprise":   TierEnterprise,
	}

	for expected, actual := range tiers {
		if actual != expected {
			t.Errorf("Tier constant: expected %q, got %q", expected, actual)
		}
	}
}

// ---------------------------------------------------------------------------
// LabelSet builder tests
// ---------------------------------------------------------------------------

func TestLabelSet_NewLabelSet(t *testing.T) {
	ls := NewLabelSet()
	if ls == nil {
		t.Fatal("NewLabelSet() returned nil")
	}
	if ls.labels == nil {
		t.Error("NewLabelSet() labels map is nil")
	}
}

func TestLabelSet_With(t *testing.T) {
	ls := NewLabelSet().With("custom_key", "custom_value")
	result := ls.Build()
	if result["custom_key"] != "custom_value" {
		t.Errorf("LabelSet.With() = %v, want custom_key=custom_value", result)
	}
}

func TestLabelSet_WithMethod(t *testing.T) {
	ls := NewLabelSet().WithMethod("get")
	result := ls.Build()
	if result[LabelMethod] != "GET" {
		t.Errorf("LabelSet.WithMethod('get') = %v, want method=GET", result)
	}
}

func TestLabelSet_WithEndpoint(t *testing.T) {
	ls := NewLabelSet().WithEndpoint("/api/v1/users/123")
	result := ls.Build()
	// Endpoint should be sanitized
	if result[LabelEndpoint] == "/api/v1/users/123" {
		t.Errorf("LabelSet.WithEndpoint() should sanitize, got unsanitized path")
	}
}

func TestLabelSet_WithStatus(t *testing.T) {
	ls := NewLabelSet().WithStatus(200)
	result := ls.Build()
	if result[LabelStatus] != Status2xx {
		t.Errorf("LabelSet.WithStatus(200) = %v, want status=2xx", result)
	}
}

func TestLabelSet_WithStatusCode(t *testing.T) {
	ls := NewLabelSet().WithStatusCode(404)
	result := ls.Build()
	if result[LabelStatusCode] != "404" {
		t.Errorf("LabelSet.WithStatusCode(404) = %v, want status_code=404", result)
	}
}

func TestLabelSet_WithService(t *testing.T) {
	ls := NewLabelSet().WithService(ServiceProxy)
	result := ls.Build()
	if result[LabelService] != ServiceProxy {
		t.Errorf("LabelSet.WithService(proxy) = %v, want service=proxy", result)
	}
}

func TestLabelSet_WithClient(t *testing.T) {
	ls := NewLabelSet().WithClient("192.168.1.100")
	result := ls.Build()
	if result[LabelClient] != "192.168.x.x" {
		t.Errorf("LabelSet.WithClient('192.168.1.100') = %v, want client bucketed to '192.168.x.x'", result)
	}
}

func TestLabelSet_WithTool(t *testing.T) {
	ls := NewLabelSet().WithTool("scan_content", []string{"scan_content"})
	result := ls.Build()
	if result[LabelTool] != "scan_content" {
		t.Errorf("LabelSet.WithTool('scan_content') = %v, want tool=scan_content", result)
	}
}

func TestLabelSet_WithTool_Unknown(t *testing.T) {
	ls := NewLabelSet().WithTool("unknown_tool", []string{"scan_content"})
	result := ls.Build()
	if result[LabelTool] != "unknown" {
		t.Errorf("LabelSet.WithTool('unknown_tool') = %v, want tool=unknown", result)
	}
}

func TestLabelSet_WithTier(t *testing.T) {
	ls := NewLabelSet().WithTier(TierCommunity)
	result := ls.Build()
	if result[LabelTier] != TierCommunity {
		t.Errorf("LabelSet.WithTier(community) = %v, want tier=community", result)
	}
}

func TestLabelSet_WithResult(t *testing.T) {
	ls := NewLabelSet().WithResult(ResultSuccess)
	result := ls.Build()
	if result[LabelResult] != ResultSuccess {
		t.Errorf("LabelSet.WithResult(success) = %v, want result=success", result)
	}
}

func TestLabelSet_Chained(t *testing.T) {
	ls := NewLabelSet().
		WithMethod("POST").
		WithEndpoint("/api/v1/tokens").
		WithStatus(200).
		WithService(ServiceProxy)

	result := ls.Build()
	if result[LabelMethod] != "POST" {
		t.Errorf("Chained WithMethod: got %q, want POST", result[LabelMethod])
	}
	if result[LabelStatus] != Status2xx {
		t.Errorf("Chained WithStatus: got %q, want 2xx", result[LabelStatus])
	}
	if result[LabelService] != ServiceProxy {
		t.Errorf("Chained WithService: got %q, want proxy", result[LabelService])
	}
}

func TestLabelSet_BuildSlice(t *testing.T) {
	ls := NewLabelSet().
		WithMethod("GET").
		WithStatus(200)

	slice := ls.BuildSlice()
	if len(slice) < 4 {
		t.Errorf("BuildSlice() returned %d elements, want at least 4", len(slice))
	}

	// BuildSlice returns alternating keys and values
	found := false
	for i := 0; i < len(slice)-1; i += 2 {
		if slice[i] == LabelMethod && slice[i+1] == "GET" {
			found = true
		}
	}
	if !found {
		t.Errorf("BuildSlice() should contain method=GET, got %v", slice)
	}
}

func TestLabelSet_ValidateLabel(t *testing.T) {
	result := ValidateLabel("test-label_123")
	if result != "test-label_123" {
		t.Errorf("ValidateLabel('test-label_123') = %q, want 'test-label_123'", result)
	}
}

func TestLabelSet_EmptyLabelValue(t *testing.T) {
	ls := NewLabelSet().With("test", "")
	result := ls.Build()
	// Empty values should become "empty" via ValidateLabelValue
	if result["test"] != "empty" {
		t.Errorf("Empty label value should become 'empty', got %q", result["test"])
	}
}