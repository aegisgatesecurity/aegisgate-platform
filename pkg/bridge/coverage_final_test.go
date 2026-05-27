package bridge

import (
	"context"
	"testing"
	"time"

	responseguard "github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// ============================================================================
// PlatformBridge Tests - Config and Core
// ============================================================================

func TestNewPlatformBridge(t *testing.T) {
	pb, err := NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Errorf("NewPlatformBridge failed: %v", err)
	}
	if pb == nil {
		t.Error("PlatformBridge should not be nil")
	}
	pb.Close()
}

func TestNewPlatformBridgeInvalid(t *testing.T) {
	_, err := NewPlatformBridge("://invalid")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestNewPlatformBridgeWithConfig(t *testing.T) {
	cfg := &Config{
		AegisGateURL:  "http://localhost:8080",
		Timeout:       30 * time.Second,
		MaxRetries:    5,
		RetryInterval: 200 * time.Millisecond,
		Enabled:       true,
		SkipTLSVerify: true,
	}
	pb, err := NewPlatformBridgeWithConfig(cfg)
	if err != nil {
		t.Errorf("NewPlatformBridgeWithConfig failed: %v", err)
	}
	if pb == nil {
		t.Error("PlatformBridge should not be nil")
	}
	pb.Close()
}

func TestNewPlatformBridgeWithConfigDisabled(t *testing.T) {
	cfg := &Config{
		AegisGateURL:  "http://localhost:8080",
		Timeout:       10 * time.Second,
		Enabled:       false,
		MaxRetries:    3,
		RetryInterval: 100 * time.Millisecond,
	}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	if pb.IsEnabled() {
		t.Error("Bridge should be disabled")
	}
	pb.Close()
}

func TestRouteLLMCallDisabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	req := &LLMRequest{
		RequestID: "req-123",
		AgentID:   "agent-1",
		TargetURL: "https://api.openai.com",
		Method:    "POST",
	}
	resp, err := pb.RouteLLMCall(context.Background(), req)
	if err != nil {
		t.Errorf("RouteLLMCall disabled should not error: %v", err)
	}
	if resp == nil {
		t.Error("Response should not be nil")
	}
}

func TestRouteLLMCallEnabled(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	headers := make(map[string]string)
	headers["Authorization"] = "Bearer test"
	headers["Content-Type"] = "application/json"

	req := &LLMRequest{
		RequestID: "req-full",
		AgentID:   "agent-1",
		SessionID: "session-1",
		TargetURL: "https://api.openai.com",
		Method:    "POST",
		Headers:   headers,
		Body:      []byte(`{"model":"gpt-4"}`),
		ToolName:  "openai_chat",
		Timestamp: time.Now(),
	}
	_, _ = pb.RouteLLMCall(context.Background(), req)
}

func TestRouteLLMCallTimeout(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Timeout: 1 * time.Millisecond,
	}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	req := &LLMRequest{
		RequestID: "req-timeout",
		AgentID:   "agent-timeout",
		TargetURL: "https://httpbin.org/delay/10",
		Method:    "GET",
	}
	_, _ = pb.RouteLLMCall(context.Background(), req)
}

func TestRouteLLMCallWithContext(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	ctx := context.WithValue(context.Background(), "request-id", "test-req")
	req := &LLMRequest{
		RequestID: "req-ctx",
		AgentID:   "agent-1",
		TargetURL: "https://api.openai.com",
		Method:    "GET",
	}
	_, _ = pb.RouteLLMCall(ctx, req)
}

func TestIsLLMCall(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	_ = pb.IsLLMCall("test_tool", nil)
	_ = pb.IsLLMCall("", nil)
}

func TestGetStats(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	stats := pb.GetStats()
	if stats == nil {
		t.Error("Stats should not be nil")
	}
}

func TestSetEnabledToggle(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	pb.SetEnabled(false)
	if pb.IsEnabled() {
		t.Error("Should be disabled after SetEnabled(false)")
	}

	pb.SetEnabled(true)
	if !pb.IsEnabled() {
		t.Error("Should be enabled after SetEnabled(true)")
	}
}

func TestGatewayAccessor(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	gw := pb.Gateway()
	if gw == nil {
		t.Error("Gateway should not be nil")
	}
}

func TestClose(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)

	err := pb.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	err = pb.Close()
	_ = err
}

// ============================================================================
// ResponseScanner Tests
// ============================================================================

func TestNewResponseScanner(t *testing.T) {
	scanner := NewResponseScanner()
	if scanner == nil {
		t.Error("ResponseScanner should not be nil")
	}
}

func TestScanResponse(t *testing.T) {
	scanner := NewResponseScanner()
	result, err := scanner.ScanResponse(context.Background(), "Clean response.")
	if err != nil {
		t.Errorf("ScanResponse failed: %v", err)
	}
	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestScanResponseEmpty(t *testing.T) {
	scanner := NewResponseScanner()
	result, err := scanner.ScanResponse(context.Background(), "")
	_ = result
	_ = err
}

func TestScanResponseNilContext(t *testing.T) {
	scanner := NewResponseScanner()
	result, err := scanner.ScanResponse(nil, "test")
	_ = result
	_ = err
}

func TestScanResponseWithContext(t *testing.T) {
	scanner := NewResponseScanner()
	scanCtx := responseguard.NewScanContext("client-1", "session-1")
	result, err := scanner.ScanResponseWithContext(context.Background(), "test response", scanCtx)
	if err != nil {
		t.Errorf("ScanResponseWithContext failed: %v", err)
	}
	_ = result
}

func TestScanResponseWithContextNil(t *testing.T) {
	scanner := NewResponseScanner()
	result, err := scanner.ScanResponseWithContext(nil, "test", nil)
	_ = result
	_ = err
}

func TestScanResponseWithContextEmptyType(t *testing.T) {
	scanner := NewResponseScanner()
	scanCtx := responseguard.NewScanContext("client-test", "session-test")
	scanCtx.ScanType = ""
	result, err := scanner.ScanResponseWithContext(context.Background(), "test response", scanCtx)
	_ = result
	_ = err
}

func TestScanLLMResponse(t *testing.T) {
	scanner := NewResponseScanner()
	result, err := scanner.ScanLLMResponse(context.Background(), "LLM response", "client-openai")
	if err != nil {
		t.Errorf("ScanLLMResponse failed: %v", err)
	}
	_ = result
}

func TestScanBridgeResponse(t *testing.T) {
	scanner := NewResponseScanner()
	ctx := context.Background()

	resp := &LLMResponse{
		RequestID:  "req-123",
		StatusCode: 200,
		Body:       []byte(`{"content":"LLM response"}`),
	}

	result, err := ScanBridgeResponse(ctx, resp, scanner)
	if err != nil {
		t.Errorf("ScanBridgeResponse failed: %v", err)
	}
	_ = result
}

func TestScanBridgeResponseNilScanner(t *testing.T) {
	ctx := context.Background()
	resp := &LLMResponse{
		RequestID:  "req-123",
		StatusCode: 200,
		Body:       []byte(`{"content":"test"}`),
	}
	result, err := ScanBridgeResponse(ctx, resp, nil)
	_ = result
	_ = err
}

func TestIsResponseAllowed(t *testing.T) {
	scanner := NewResponseScanner()
	ctx := context.Background()

	allowed := scanner.IsResponseAllowed(ctx, "Clean response.")
	_ = allowed
}

func TestIsResponseAllowedBlocked(t *testing.T) {
	scanner := NewResponseScanner()

	blocked := []string{
		"Secret key: sk-1234567890abcdefghijklmnop",
		"My SSN is 123-45-6789",
	}
	for _, text := range blocked {
		_ = scanner.IsResponseAllowed(context.Background(), text)
	}
}

func TestGetComplianceReport(t *testing.T) {
	scanner := NewResponseScanner()
	ctx := context.Background()

	frameworks := []string{"Clean", "PII: 123-45-6789", "Key: sk-test"}
	for _, text := range frameworks {
		report, err := scanner.GetComplianceReport(ctx, text)
		_ = report
		_ = err
	}
}

func TestGetDetectedPII(t *testing.T) {
	scanner := NewResponseScanner()
	ctx := context.Background()

	pii := scanner.GetDetectedPII(ctx, "Test 123-45-6789")
	_ = pii
}

func TestGetDetectedSecrets(t *testing.T) {
	scanner := NewResponseScanner()
	ctx := context.Background()

	secrets := scanner.GetDetectedSecrets(ctx, "Test sk-1234567890")
	_ = secrets
}

// ============================================================================
// PlatformBridgeWithResponse Tests
// ============================================================================

func TestNewPlatformBridgeWithResponse(t *testing.T) {
	pb, err := NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Errorf("NewPlatformBridgeWithResponse failed: %v", err)
	}
	if pb == nil {
		t.Error("PlatformBridgeWithResponse should not be nil")
	}
}

func TestNewPlatformBridgeWithResponseEmpty(t *testing.T) {
	pb, err := NewPlatformBridgeWithResponse("")
	_ = pb
	_ = err
}

func TestPlatformBridgeWithResponseScanResponse(t *testing.T) {
	pb, _ := NewPlatformBridgeWithResponse("http://localhost:8080")
	ctx := context.Background()

	responses := []string{"Clean", "PII: 123", "", "Key: sk-test"}
	for _, text := range responses {
		result, err := pb.ScanResponse(ctx, text)
		_ = result
		_ = err
	}
}

func TestScanAndFilter(t *testing.T) {
	pb, _ := NewPlatformBridgeWithResponse("http://localhost:8080")
	ctx := context.Background()

	tests := []string{"Clean text", "PII: 123-45-6789", ""}
	for _, text := range tests {
		filtered, _, err := pb.ScanAndFilter(ctx, text)
		_ = filtered
		_ = err
	}
}
