package computeruse

import (
	"context"
	"testing"
)

// ============================================================================
// COMPUTERUSE COVERAGE TESTS - Additional edge cases
// ============================================================================

func TestBrowserAction_AllActionTypes(t *testing.T) {
	actions := []string{ActionClick, ActionType, ActionNavigate, ActionScreenshot, ActionScroll, ActionHover}
	for _, a := range actions {
		action := NewBrowserAction(a, "https://example.com", "agent-1", "session-1")
		if action.Type != a {
			t.Errorf("Action type mismatch: expected %s, got %s", a, action.Type)
		}
	}
}

func TestBrowserAction_WithMetadata(t *testing.T) {
	action := NewBrowserAction(ActionClick, "https://example.com", "agent-1", "session-1")
	action.Metadata["x"] = "100"
	action.Metadata["y"] = "200"
	action.Metadata["element"] = "#btn"
	if action.Metadata["x"] != "100" {
		t.Error("X metadata not set")
	}
}

func TestFormField_WithPosition(t *testing.T) {
	field := &FormField{
		Name:        "card",
		Type:        "text",
		IsSensitive: true,
		Label:       "Credit Card",
		X:           50,
		Y:           100,
	}
	if field.X != 50 || field.Y != 100 {
		t.Error("Position not set correctly")
	}
}

func TestGuardResult_WithMetadata(t *testing.T) {
	result := NewGuardResult(DecisionBlock, "blocked", "test-rule", "high")
	result.Metadata["blocked_url"] = "https://evil.com"
	result.Metadata["blocked_reason"] = "denylist match"
	if result.Metadata["blocked_url"] != "https://evil.com" {
		t.Error("Metadata not set correctly")
	}
}

func TestGuardResult_MultipleDecisions(t *testing.T) {
	results := []*GuardResult{
		NewGuardResult(DecisionAllow, "allowed", "rule1", "low"),
		NewGuardResult(DecisionBlock, "blocked", "rule2", "high"),
		NewGuardResult(DecisionMask, "masked", "rule3", "medium"),
		NewGuardResult(DecisionRequireApproval, "needs approval", "rule4", "medium"),
		NewGuardResult(DecisionLogOnly, "logged", "rule5", "low"),
	}
	for _, r := range results {
		if r.Decision == "" {
			t.Error("Decision should not be empty")
		}
	}
}

func TestGuardConfig_AllFields(t *testing.T) {
	cfg := &Config{
		MaxClicksPerMinute:        15,
		MaxScreenshotsPerMinute:   5,
		MaxKeystrokesPerMinute:    200,
		ScreenshotCooldownSeconds: 30,
		ClickRateThreshold:        8,
		BlockCreditCards:          false,
		BlockSSN:                  false,
		BlockPasswords:            false,
		MaskSessionTokens:         false,
		BlockSensitiveFields:      false,
		AllowByDefault:            true,
		URLDenylist:               []string{"evil.com", "malware.net"},
		URLAllowlist:              []string{"trusted.com"},
	}
	if cfg.MaxClicksPerMinute != 15 {
		t.Error("MaxClicksPerMinute not set")
	}
	if len(cfg.URLDenylist) != 2 {
		t.Error("URLDenylist not set correctly")
	}
}

func TestSecurityContext_WithMetadata(t *testing.T) {
	ctx := NewSecurityContext("agent-1", "session-1")
	ctx.Metadata["ip"] = "192.168.1.100"
	ctx.Metadata["region"] = "us-west-2"
	ctx.Metadata["tier"] = "premium"
	if ctx.Metadata["region"] != "us-west-2" {
		t.Error("Metadata not set correctly")
	}
}

func TestSecurityContext_WithCapabilities(t *testing.T) {
	ctx := NewSecurityContext("agent-1", "session-1")
	ctx.Capabilities = []string{"read", "write", "execute", "admin"}
	if len(ctx.Capabilities) != 4 {
		t.Error("Capabilities not set correctly")
	}
}

func TestGuard_WithCustomDenylist(t *testing.T) {
	cfg := &Config{
		URLDenylist:    []string{"blocked1.com", "blocked2.com"},
		AllowByDefault: true,
	}
	g := NewGuardWithConfig(cfg)

	tests := []struct {
		url     string
		blocked bool
	}{
		{"https://blocked1.com/page", true},
		{"https://blocked2.com/page", true},
		{"https://allowed.com/page", false},
	}

	for _, tt := range tests {
		result, _ := g.GuardURL(context.Background(), tt.url, NewSecurityContext("agent", "session"))
		if tt.blocked && result.Allow() {
			t.Errorf("URL %s should be blocked", tt.url)
		}
		if !tt.blocked && !result.Allow() {
			t.Errorf("URL %s should be allowed", tt.url)
		}
	}
}

func TestGuard_WithCustomAllowlist(t *testing.T) {
	cfg := &Config{
		URLAllowlist:   []string{"allowed.com"},
		AllowByDefault: true,
	}
	g := NewGuardWithConfig(cfg)

	tests := []struct {
		url     string
		allowed bool
	}{
		{"https://allowed.com/page", true},
		{"https://other.com/page", false},
	}

	for _, tt := range tests {
		result, _ := g.GuardURL(context.Background(), tt.url, NewSecurityContext("agent", "session"))
		if tt.allowed && !result.Allow() {
			t.Errorf("URL %s should be allowed", tt.url)
		}
		if !tt.allowed && result.Allow() {
			t.Errorf("URL %s should be blocked", tt.url)
		}
	}
}

func TestGuard_EmptyURL(t *testing.T) {
	g := NewGuard()
	_, err := g.GuardURL(context.Background(), "", NewSecurityContext("agent", "session"))
	if err == nil {
		t.Error("Empty URL should return error")
	}
}

func TestGuard_NilSecurityContext(t *testing.T) {
	g := NewGuard()
	result, err := g.GuardURL(context.Background(), "https://example.com", nil)
	if err != nil {
		t.Errorf("Nil secCtx should not error: %v", err)
	}
	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestGuard_ClickNilAction(t *testing.T) {
	g := NewGuard()
	_, err := g.GuardClick(context.Background(), nil, NewSecurityContext("agent", "session"))
	if err == nil {
		t.Error("Nil action should return error")
	}
}

func TestGuard_ScreenshotNilAction(t *testing.T) {
	g := NewGuard()
	_, err := g.GuardScreenshot(context.Background(), nil, NewSecurityContext("agent", "session"))
	if err == nil {
		t.Error("Nil action should return error")
	}
}

func TestSensitiveFieldTypes(t *testing.T) {
	// Test that all sensitive types are detected
	sensitiveTypes := []string{"password", "credit_card", "ssn", "cvv", "pin", "secret", "api_key", "private_key"}
	for _, st := range sensitiveTypes {
		if !IsSensitiveField(st) {
			t.Errorf("%s should be detected as sensitive", st)
		}
	}

	// Test non-sensitive types
	nonSensitiveTypes := []string{"text", "email", "name", "address", "phone", "date", "number", "search"}
	for _, nst := range nonSensitiveTypes {
		if IsSensitiveField(nst) {
			t.Errorf("%s should not be detected as sensitive", nst)
		}
	}
}
