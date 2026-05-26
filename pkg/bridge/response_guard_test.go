// SPDX-License-Identifier: Apache-2.0
// Response Guard Tests for bridge package

package bridge_test

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge"
)

func TestScanResponseWithContext_ErrorPath(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()
	result, err := rs.ScanResponseWithContext(ctx, "", nil)
	if err != nil {
		t.Errorf("Empty response should not error: %v", err)
	}
	if result == nil {
		t.Error("Expected result, got nil")
	}
}

func TestScanResponseWithContext_CleanResponse(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()
	cleanResponse := "This is a perfectly safe response."
	result, err := rs.ScanResponseWithContext(ctx, cleanResponse, nil)
	if err != nil {
		t.Fatalf("Clean response should not error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result")
	}
}

func TestScanResponseWithContext_WithContext(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := rs.ScanResponseWithContext(ctx, "test response", nil)
	if err != nil {
		t.Fatalf("Should not error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result")
	}
}

func TestIsResponseAllowed_Clean(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()
	allowed := rs.IsResponseAllowed(ctx, "clean response")
	_ = allowed
}

func TestIsResponseAllowed_WithSecret(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()
	allowed := rs.IsResponseAllowed(ctx, "response with sk-1234567890abcdef")
	_ = allowed
}

func TestGetComplianceReport(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()
	report, err := rs.GetComplianceReport(ctx, "test response")
	if err != nil {
		t.Fatalf("GetComplianceReport failed: %v", err)
	}
	if report == nil {
		t.Error("Expected report, got nil")
	}
}

func TestGetDetectedPII(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()
	pii := rs.GetDetectedPII(ctx, "test response")
	_ = pii
}

func TestGetDetectedSecrets(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()
	secrets := rs.GetDetectedSecrets(ctx, "test response")
	_ = secrets
}

func TestNewResponseScanner(t *testing.T) {
	rs := bridge.NewResponseScanner()
	if rs == nil {
		t.Error("Expected non-nil scanner")
	}
}

func TestScanLLMResponse(t *testing.T) {
	rs := bridge.NewResponseScanner()
	ctx := context.Background()
	result, err := rs.ScanLLMResponse(ctx, "test response", "client-123")
	if err != nil {
		t.Fatalf("ScanLLMResponse failed: %v", err)
	}
	if result == nil {
		t.Fatal("Expected result")
	}
}

func TestScanBridgeResponse(t *testing.T) {
	pb, _ := bridge.NewPlatformBridge("http://localhost:8080")
	defer pb.Close()

	ctx := context.Background()
	resp := &bridge.LLMResponse{
		RequestID: "test-123",
	}
	result, err := bridge.ScanBridgeResponse(ctx, resp, &bridge.ResponseScanner{})
	if err != nil {
		t.Fatalf("ScanBridgeResponse failed: %v", err)
	}
	if result == nil {
		t.Error("Expected result")
	}
}

func TestScanAndFilter_Clean(t *testing.T) {
	pb, err := bridge.NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithResponse failed: %v", err)
	}
	defer pb.Close()

	ctx := context.Background()
	response := "clean response with no issues"
	filteredResponse, result, err := pb.ScanAndFilter(ctx, response)
	if err != nil {
		t.Fatalf("ScanAndFilter failed: %v", err)
	}
	if result == nil {
		t.Error("Expected result")
	}
	if filteredResponse != response {
		t.Error("Clean response should pass through unchanged")
	}
}

func TestScanAndFilter_WithContent(t *testing.T) {
	pb, err := bridge.NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithResponse failed: %v", err)
	}
	defer pb.Close()

	ctx := context.Background()
	response := "test response content"
	filteredResponse, result, err := pb.ScanAndFilter(ctx, response)
	if err != nil {
		t.Fatalf("ScanAndFilter failed: %v", err)
	}
	if result != nil {
		_ = result.Allowed
	}
	_ = filteredResponse
}

func TestNewPlatformBridgeWithResponse(t *testing.T) {
	pb, err := bridge.NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridgeWithResponse failed: %v", err)
	}
	defer pb.Close()
	if !pb.IsEnabled() {
		t.Error("Expected enabled bridge")
	}
}
