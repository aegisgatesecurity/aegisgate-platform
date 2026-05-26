package bridge

import (
	"context"
	"testing"
)

var testCtx = context.Background()

func TestResponseScanner_ScanResponse(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanResponse(testCtx, "clean response content")
	if err != nil {
		t.Fatalf("ScanResponse failed: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestResponseScanner_IsResponseAllowed(t *testing.T) {
	rs := NewResponseScanner()
	allowed := rs.IsResponseAllowed(testCtx, "clean content")
	if !allowed {
		t.Error("Expected allowed for clean content")
	}
}

func TestResponseScanner_GetComplianceReport(t *testing.T) {
	rs := NewResponseScanner()
	reports, err := rs.GetComplianceReport(testCtx, "test content")
	if err != nil {
		t.Fatalf("GetComplianceReport failed: %v", err)
	}
	if reports == nil {
		t.Error("Expected non-nil reports")
	}
}

func TestResponseScanner_GetDetectedPII(t *testing.T) {
	rs := NewResponseScanner()
	pii := rs.GetDetectedPII(testCtx, "test content")
	if pii == nil {
		t.Error("Expected non-nil PII list")
	}
}

func TestResponseScanner_GetDetectedSecrets(t *testing.T) {
	rs := NewResponseScanner()
	secrets := rs.GetDetectedSecrets(testCtx, "test content")
	if secrets == nil {
		t.Error("Expected non-nil secrets list")
	}
}

func TestResponseScanner_ScanResponseWithContext(t *testing.T) {
	rs := NewResponseScanner()
	result, err := rs.ScanResponseWithContext(testCtx, "clean content", nil)
	if err != nil {
		t.Fatalf("ScanResponseWithContext failed: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestPlatformBridgeWithResponse_ScanAndFilter(t *testing.T) {
	pb, err := NewPlatformBridgeWithResponse("http://localhost:8080")
	if err != nil {
		t.Skip("Bridge init failed, skipping")
	}
	filtered, result, err := pb.ScanAndFilter(testCtx, "clean response")
	if err != nil {
		t.Fatalf("ScanAndFilter failed: %v", err)
	}
	if filtered == "" {
		t.Error("Expected non-empty filtered response")
	}
	_ = result
	pb.Close()
}
