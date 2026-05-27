package bridge

import (
	"testing"
	"time"
)

// Tests that match actual implementation behavior

func TestNewPlatformBridgeDefault(t *testing.T) {
	pb, err := NewPlatformBridge("http://localhost:8080")
	if err != nil {
		t.Errorf("NewPlatformBridge failed: %v", err)
	}
	if pb == nil {
		t.Error("Bridge should not be nil")
	}
	pb.Close()
}

func TestNewPlatformBridgeWithTimeout(t *testing.T) {
	cfg := &Config{
		AegisGateURL: "http://localhost:9090",
		Timeout:      5 * time.Second,
		Enabled:      true,
	}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	if !pb.IsEnabled() {
		t.Error("Bridge should be enabled")
	}
}

func TestNewPlatformBridgeWithConfigDisabled(t *testing.T) {
	cfg := &Config{
		AegisGateURL: "http://localhost:9090",
		Timeout:      10 * time.Second,
		Enabled:      false,
	}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	if pb.IsEnabled() {
		t.Error("Bridge should be disabled")
	}
}

func TestCloseMultiple(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)

	// Multiple closes should not panic
	pb.Close()
	pb.Close()
	pb.Close()
}

func TestSetEnabled(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	pb.SetEnabled(false)
	if pb.IsEnabled() {
		t.Error("Should be disabled")
	}

	pb.SetEnabled(true)
	if !pb.IsEnabled() {
		t.Error("Should be enabled")
	}
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

func TestGatewayAccessor(t *testing.T) {
	cfg := &Config{Enabled: true}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	gw := pb.Gateway()
	if gw == nil {
		t.Error("Gateway should not be nil")
	}
}

func TestNewPlatformBridgeWithRetry(t *testing.T) {
	cfg := &Config{
		AegisGateURL:  "http://localhost:9090",
		Timeout:       10 * time.Second,
		Enabled:       true,
		MaxRetries:    3,
		RetryInterval: 100 * time.Millisecond,
	}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	if pb == nil {
		t.Error("Bridge should not be nil")
	}
}

func TestNewPlatformBridgeWithSkipTLS(t *testing.T) {
	cfg := &Config{
		AegisGateURL:  "https://localhost:9090",
		Timeout:       10 * time.Second,
		Enabled:       true,
		SkipTLSVerify: true,
	}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	if pb == nil {
		t.Error("Bridge should not be nil")
	}
}

func TestPlatformBridgeDefaultTarget(t *testing.T) {
	cfg := &Config{
		AegisGateURL:  "http://localhost:9090",
		DefaultTarget: "https://api.openai.com",
		Enabled:       true,
	}
	pb, _ := NewPlatformBridgeWithConfig(cfg)
	defer pb.Close()

	if pb == nil {
		t.Error("Bridge should not be nil")
	}
}
