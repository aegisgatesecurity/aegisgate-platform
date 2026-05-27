package mcpserver

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

func TestMCPDefaultGuardrailConfig(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	if cfg.PlatformTier != tier.TierCommunity {
		t.Error("PlatformTier should be Community")
	}
}

func TestMCPNewGuardrailMiddleware(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	mw := NewGuardrailMiddleware(cfg, "test-server")
	if mw == nil {
		t.Fatal("Middleware should not be nil")
	}
	mw.Close()
}

func TestMCPGuardrailMiddlewareOnSessionCreate(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	mw := NewGuardrailMiddleware(cfg, "test-server")
	err := mw.OnSessionCreate("session-1", "agent-1", "127.0.0.1")
	if err != nil {
		t.Errorf("OnSessionCreate failed: %v", err)
	}
	mw.Close()
}

func TestMCPGuardrailMiddlewareOnToolCall(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	mw := NewGuardrailMiddleware(cfg, "test-server")
	mw.OnSessionCreate("session-1", "agent-1", "127.0.0.1")
	err := mw.OnToolCall("session-1", "web_search")
	if err != nil {
		t.Errorf("OnToolCall failed: %v", err)
	}
	mw.Close()
}

func TestMCPGuardrailMiddlewareRateLimitCleanup(t *testing.T) {
	cfg := DefaultGuardrailConfig(tier.TierCommunity)
	mw := NewGuardrailMiddleware(cfg, "test-server")
	mw.RateLimitCleanup()
	mw.Close()
}
