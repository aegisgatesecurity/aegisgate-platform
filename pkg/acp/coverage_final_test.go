package acp

import (
	"context"
	"testing"
)

func TestCapEnforcerAllow(t *testing.T) {
	ce := NewCapabilityEnforcer()
	ce.Allow("agent-1", "file:read")
	if !ce.Check("agent-1", "file:read") {
		t.Error("Should allow after Allow()")
	}
}

func TestCapEnforcerDisallow(t *testing.T) {
	ce := NewCapabilityEnforcer()
	ce.Allow("agent-1", "file:read")
	ce.Disallow("agent-1", "file:read")
	if ce.Check("agent-1", "file:read") {
		t.Error("Should not allow after Disallow()")
	}
}

func TestCapEnforcerGetCaps(t *testing.T) {
	ce := NewCapabilityEnforcer()
	ce.Allow("agent-1", "file:read")
	ce.Allow("agent-1", "file:write")
	caps := ce.GetCapabilities("agent-1")
	if len(caps) != 2 {
		t.Errorf("Expected 2 capabilities, got %d", len(caps))
	}
}

func TestCapEnforcerClear(t *testing.T) {
	ce := NewCapabilityEnforcer()
	ce.Allow("agent-1", "file:read")
	ce.Clear("agent-1")
	caps := ce.GetCapabilities("agent-1")
	if len(caps) != 0 {
		t.Error("Should have no capabilities after Clear()")
	}
}

func TestACPGuardConfigDefaults(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	if cfg == nil {
		t.Fatal("Default config should not be nil")
	}
}

func TestConfigLoaderLoadConfig(t *testing.T) {
	cl := NewConfigLoader()
	_, err := cl.LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Should error for nonexistent file")
	}
}

func TestACPScanStats(t *testing.T) {
	stats := NewACPScanStats()
	if stats == nil {
		t.Error("NewACPScanStats should not return nil")
	}
}

func TestACPRespScannerScanResponse(t *testing.T) {
	scanner := NewACPResponseScanner()
	result, err := scanner.ScanResponse(context.Background(), "clean response", "session-1")
	if err != nil {
		t.Errorf("ScanResponse failed: %v", err)
	}
	if result == nil {
		t.Error("ScanResponse returned nil")
	}
}

func TestACPRespScannerWithConfig(t *testing.T) {
	cfg := DefaultACPGuardConfig()
	scanner := NewACPResponseScannerWithConfig(cfg)
	if scanner == nil {
		t.Error("NewACPResponseScannerWithConfig returned nil")
	}
}

func TestACPRespScannerScanACPMessage(t *testing.T) {
	scanner := NewACPResponseScanner()
	msg := &ACPMessage{Method: "task.create", Params: map[string]interface{}{"task": "test"}}
	result, err := scanner.ScanACPMessage(context.Background(), msg, "session-1")
	if err != nil {
		t.Errorf("ScanACPMessage failed: %v", err)
	}
	if result == nil {
		t.Error("ScanACPMessage returned nil")
	}
}
