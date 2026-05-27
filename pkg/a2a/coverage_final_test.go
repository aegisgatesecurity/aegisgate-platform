package a2a

import (
	"context"
	"testing"
)

func TestA2ANewRespScanner(t *testing.T) {
	scanner := NewA2AResponseScanner()
	if scanner == nil {
		t.Error("Scanner should not be nil")
	}
}

func TestA2ARespScannerScanResponse(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanResponse(context.Background(), "clean response", "agent-1")
	if err != nil {
		t.Errorf("ScanResponse failed: %v", err)
	}
	if result == nil {
		t.Error("ScanResponse returned nil")
	}
}

func TestA2ARespScannerScanA2AMsg(t *testing.T) {
	scanner := NewA2AResponseScanner()
	result, err := scanner.ScanA2AMessage(context.Background(), map[string]string{"content": "test"}, "agent-1")
	if err != nil {
		t.Errorf("ScanA2AMessage failed: %v", err)
	}
	if result == nil {
		t.Error("ScanA2AMessage returned nil")
	}
}

func TestA2ANewRespGuardMiddleware(t *testing.T) {
	mw := NewResponseGuardMiddleware()
	if mw == nil {
		t.Error("Middleware should not be nil")
	}
}

func TestA2ARespGuardMiddlewareEnabled(t *testing.T) {
	mw := NewResponseGuardMiddleware()
	if !mw.IsEnabled() {
		t.Error("Should be enabled by default")
	}
}

func TestA2ARespGuardMiddlewareSetEnabled(t *testing.T) {
	mw := NewResponseGuardMiddleware()
	mw.SetEnabled(false)
	if mw.IsEnabled() {
		t.Error("Should be disabled after SetEnabled(false)")
	}
}

func TestA2ANewRespHandler(t *testing.T) {
	handler := NewA2AResponseHandler()
	if handler == nil {
		t.Error("Handler should not be nil")
	}
}

func TestA2ARespHandlerHandleResponse(t *testing.T) {
	handler := NewA2AResponseHandler()
	_, result, err := handler.HandleResponse(context.Background(), "clean response", "agent-1")
	if err != nil {
		t.Errorf("HandleResponse failed: %v", err)
	}
	if result == nil {
		t.Error("HandleResponse returned nil result")
	}
}

func TestA2ALoadCaps(t *testing.T) {
	caps, err := LoadCaps("/nonexistent/path/caps.yaml")
	if err == nil {
		t.Error("Should error for nonexistent file")
	}
	if caps != nil {
		t.Error("Should return nil for nonexistent file")
	}
}
