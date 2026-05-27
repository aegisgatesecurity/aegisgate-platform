package bridge_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge"
)

func skipIfNoLab(t *testing.T) {
	if os.Getenv("LAB_ENABLED") != "1" {
		t.Skip("Skipping lab test - set LAB_ENABLED=1 to run")
	}
}

func TestNewPlatformBridge_LabEnabled(t *testing.T) {
	skipIfNoLab(t)

	pb, err := bridge.NewPlatformBridge("http://aegisgate-test:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge with lab URL failed: %v", err)
	}
	defer pb.Close()

	if !pb.IsEnabled() {
		t.Error("expected bridge to be enabled")
	}
}

func TestRouteLLMCall_LabIntegration(t *testing.T) {
	skipIfNoLab(t)

	pb, err := bridge.NewPlatformBridge("http://aegisgate-test:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	req := bridge.LLMRequest{
		RequestID: "lab-test-001",
		AgentID:   "test-agent",
		SessionID: "test-session",
		TargetURL: "https://api.anthropic.com/v1/messages",
		Method:    "POST",
		Headers:   map[string]string{"Content-Type": "application/json"},
		Body:      []byte(`{"model":"claude-3-5-sonnet","max_tokens":100}`),
		Timestamp: time.Now(),
	}

	resp, err := pb.RouteLLMCall(context.Background(), &req)
	if err != nil {
		t.Logf("RouteLLMCall error: %v", err)
		return
	}

	if resp != nil && resp.RequestID != req.RequestID {
		t.Errorf("RequestID mismatch")
	}
}

func TestBridgeStats_LabIntegration(t *testing.T) {
	skipIfNoLab(t)

	pb, err := bridge.NewPlatformBridge("http://aegisgate-test:8080")
	if err != nil {
		t.Fatalf("NewPlatformBridge failed: %v", err)
	}
	defer pb.Close()

	stats := pb.GetStats()
	if stats == nil {
		t.Fatal("GetStats returned nil")
	}

	t.Logf("Bridge stats: Total=%d, Blocked=%d", stats.TotalRequests, stats.BlockedRequests)
}

func TestBridgeWithResponseScanner_Lab(t *testing.T) {
	skipIfNoLab(t)

	rs := bridge.NewResponseScanner()
	result, err := rs.ScanResponse(context.Background(), "clean response")
	if err != nil {
		t.Fatalf("ScanResponse failed: %v", err)
	}

	if result == nil {
		t.Fatal("ScanResult is nil")
	}

	t.Logf("ScanResult: Allowed=%v", result.Allowed)
}

func TestBridgeComplianceReport_Lab(t *testing.T) {
	skipIfNoLab(t)

	rs := bridge.NewResponseScanner()
	report, err := rs.GetComplianceReport(context.Background(), "compliant response")
	if err != nil {
		t.Fatalf("GetComplianceReport failed: %v", err)
	}

	if report == nil {
		t.Fatal("Compliance report is nil")
	}

	t.Logf("Compliance report entries: %d", len(report))
}
