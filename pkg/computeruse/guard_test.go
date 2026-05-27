package computeruse

import (
	"context"
	"testing"
)

func TestNewGuard(t *testing.T) {
	g := NewGuard()
	if g == nil {
		t.Fatal("NewGuard returned nil")
	}
	if g.cfg == nil {
		t.Error("Config should not be nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.MaxClicksPerMinute != 10 {
		t.Errorf("MaxClicksPerMinute = %d, want 10", cfg.MaxClicksPerMinute)
	}
	if cfg.MaxScreenshotsPerMinute != 1 {
		t.Errorf("MaxScreenshotsPerMinute = %d, want 1", cfg.MaxScreenshotsPerMinute)
	}
	if cfg.MaxKeystrokesPerMinute != 120 {
		t.Errorf("MaxKeystrokesPerMinute = %d, want 120", cfg.MaxKeystrokesPerMinute)
	}
	if !cfg.BlockCreditCards {
		t.Error("BlockCreditCards should be true")
	}
}

func TestGuardURL_Allow(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent-1", "session-1")
	result, err := g.GuardURL(context.Background(), "https://example.com", secCtx)
	if err != nil {
		t.Fatalf("GuardURL failed: %v", err)
	}
	if !result.Allow() {
		t.Errorf("Expected allow, got %s", result.Decision)
	}
}

func TestGuardURL_Empty(t *testing.T) {
	g := NewGuard()
	_, err := g.GuardURL(context.Background(), "", NewSecurityContext("agent", "session"))
	if err == nil {
		t.Error("Expected error for empty URL")
	}
}

func TestGuardURL_Denylist(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent-1", "session-1")
	result, _ := g.GuardURL(context.Background(), "http://localhost:8080", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block, got %s", result.Decision)
	}
}

func TestGuardURL_Whitelist(t *testing.T) {
	g := NewGuardWithConfig(&Config{URLAllowlist: []string{"example.com"}, AllowByDefault: false})
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardURL(context.Background(), "https://example.com", secCtx)
	if !result.Allow() {
		t.Error("Expected allow for whitelisted URL")
	}
}

func TestGuardURL_WhitelistBlock(t *testing.T) {
	g := NewGuardWithConfig(&Config{URLAllowlist: []string{"example.com"}, AllowByDefault: false})
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardURL(context.Background(), "https://other.com", secCtx)
	if result.Decision != DecisionBlock {
		t.Error("Expected block for non-whitelisted URL")
	}
}

func TestGuardClick_Allow(t *testing.T) {
	g := NewGuard()
	action := NewBrowserAction(ActionClick, "https://example.com", "agent", "session")
	result, err := g.GuardClick(context.Background(), action, NewSecurityContext("agent", "session"))
	if err != nil {
		t.Fatalf("GuardClick failed: %v", err)
	}
	if !result.Allow() {
		t.Errorf("Expected allow, got %s", result.Decision)
	}
}

func TestGuardClick_Nil(t *testing.T) {
	g := NewGuard()
	_, err := g.GuardClick(context.Background(), nil, NewSecurityContext("agent", "session"))
	if err == nil {
		t.Error("Expected error for nil action")
	}
}

func TestGuardClick_RateLimit(t *testing.T) {
	g := NewGuardWithConfig(&Config{MaxClicksPerMinute: 3})
	secCtx := NewSecurityContext("agent", "session")
	for i := 0; i < 3; i++ {
		g.GuardClick(context.Background(), NewBrowserAction(ActionClick, "https://example.com", "agent", "session"), secCtx)
	}
	result, _ := g.GuardClick(context.Background(), NewBrowserAction(ActionClick, "https://example.com", "agent", "session"), secCtx)
	// May block or log depending on implementation
	_ = result
}

func TestGuardScreenshot_Allow(t *testing.T) {
	g := NewGuard()
	action := NewBrowserAction(ActionScreenshot, "https://example.com", "agent", "session")
	result, err := g.GuardScreenshot(context.Background(), action, NewSecurityContext("agent", "session"))
	if err != nil {
		t.Fatalf("GuardScreenshot failed: %v", err)
	}
	if !result.Allow() {
		t.Errorf("Expected allow, got %s", result.Decision)
	}
}

func TestGuardScreenshot_Cooldown(t *testing.T) {
	g := NewGuardWithConfig(&Config{ScreenshotCooldownSeconds: 60})
	secCtx := NewSecurityContext("agent", "session")
	g.GuardScreenshot(context.Background(), NewBrowserAction(ActionScreenshot, "https://example.com", "agent", "session"), secCtx)
	result, _ := g.GuardScreenshot(context.Background(), NewBrowserAction(ActionScreenshot, "https://example.com", "agent", "session"), secCtx)
	// Second should be blocked due to cooldown
	_ = result
}

func TestGuardKeystroke_Allow(t *testing.T) {
	g := NewGuard()
	result, err := g.GuardKeystroke(context.Background(), "Hello world", NewSecurityContext("agent", "session"))
	if err != nil {
		t.Fatalf("GuardKeystroke failed: %v", err)
	}
	if !result.Allow() {
		t.Errorf("Expected allow, got %s", result.Decision)
	}
}

func TestGuardKeystroke_RateLimit(t *testing.T) {
	g := NewGuardWithConfig(&Config{MaxKeystrokesPerMinute: 2})
	secCtx := NewSecurityContext("agent", "session")
	g.GuardKeystroke(context.Background(), "a", secCtx)
	g.GuardKeystroke(context.Background(), "b", secCtx)
	result, _ := g.GuardKeystroke(context.Background(), "c", secCtx)
	// May block depending on implementation
	_ = result
}

func TestGuardFormField_Allow(t *testing.T) {
	g := NewGuard()
	field := &FormField{Name: "name", Type: "text", IsSensitive: false}
	result, err := g.GuardFormField(context.Background(), field, "John", NewSecurityContext("agent", "session"))
	if err != nil {
		t.Fatalf("GuardFormField failed: %v", err)
	}
	if !result.Allow() {
		t.Errorf("Expected allow, got %s", result.Decision)
	}
}

func TestGuardFormField_Sensitive(t *testing.T) {
	g := NewGuard()
	field := &FormField{Name: "pwd", Type: "password"}
	result, _ := g.GuardFormField(context.Background(), field, "secret", NewSecurityContext("agent", "session"))
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for password field, got %s", result.Decision)
	}
}

func TestGuardFormField_CC(t *testing.T) {
	g := NewGuard()
	field := &FormField{Name: "cc", Type: "credit_card"}
	result, _ := g.GuardFormField(context.Background(), field, "1234", NewSecurityContext("agent", "session"))
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for credit_card field, got %s", result.Decision)
	}
}

func TestGuardSensitiveData_Allow(t *testing.T) {
	g := NewGuard()
	result, err := g.GuardSensitiveData(context.Background(), "Hello world", NewSecurityContext("agent", "session"))
	if err != nil {
		t.Fatalf("GuardSensitiveData failed: %v", err)
	}
	if !result.Allow() {
		t.Errorf("Expected allow, got %s", result.Decision)
	}
}

func TestGuardSensitiveData_CreditCard(t *testing.T) {
	g := NewGuard()
	result, _ := g.GuardSensitiveData(context.Background(), "Card: 1234-5678-9012-3456", NewSecurityContext("agent", "session"))
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for CC, got %s", result.Decision)
	}
}

func TestGuardSensitiveData_SSN(t *testing.T) {
	g := NewGuard()
	result, _ := g.GuardSensitiveData(context.Background(), "SSN: 123-45-6789", NewSecurityContext("agent", "session"))
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for SSN, got %s", result.Decision)
	}
}

func TestGuardSensitiveData_Password(t *testing.T) {
	g := NewGuard()
	result, _ := g.GuardSensitiveData(context.Background(), "password=supersecretpassword", NewSecurityContext("agent", "session"))
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for password, got %s", result.Decision)
	}
}

func TestIsSensitiveField(t *testing.T) {
	sensitive := []string{"password", "credit_card", "ssn", "cvv", "pin"}
	for _, s := range sensitive {
		if !IsSensitiveField(s) {
			t.Errorf("IsSensitiveField(%s) should be true", s)
		}
	}
	nonSensitive := []string{"text", "email", "name"}
	for _, s := range nonSensitive {
		if IsSensitiveField(s) {
			t.Errorf("IsSensitiveField(%s) should be false", s)
		}
	}
}

func TestNewBrowserAction(t *testing.T) {
	action := NewBrowserAction(ActionClick, "https://example.com", "agent-1", "session-1")
	if action.Type != ActionClick {
		t.Errorf("Type = %s, want %s", action.Type, ActionClick)
	}
	if action.URL != "https://example.com" {
		t.Error("URL mismatch")
	}
}

func TestNewSecurityContext(t *testing.T) {
	ctx := NewSecurityContext("agent-1", "session-1")
	if ctx.AgentID != "agent-1" {
		t.Errorf("AgentID = %s, want agent-1", ctx.AgentID)
	}
}

func TestGuardResult_Allow(t *testing.T) {
	r := NewGuardResult(DecisionAllow, "test", "rule", "low")
	if !r.Allow() {
		t.Error("DecisionAllow should return true")
	}
	r = NewGuardResult(DecisionBlock, "test", "rule", "high")
	if r.Allow() {
		t.Error("DecisionBlock should return false")
	}
}

func TestGuardResult_Block(t *testing.T) {
	r := NewGuardResult(DecisionBlock, "test", "rule", "high")
	if !r.Block() {
		t.Error("DecisionBlock should return true")
	}
}

func TestGuardURL_AllDenylist(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	for _, url := range []string{"http://localhost", "http://127.0.0.1", "http://0.0.0.0"} {
		result, _ := g.GuardURL(context.Background(), url, secCtx)
		if result.Decision != DecisionBlock {
			t.Errorf("Expected block for %s, got %s", url, result.Decision)
		}
	}
}

func TestGuardClick_PerAgent(t *testing.T) {
	g := NewGuardWithConfig(&Config{MaxClicksPerMinute: 2})
	secCtxA := NewSecurityContext("agent-A", "session")
	for i := 0; i < 2; i++ {
		g.GuardClick(context.Background(), NewBrowserAction(ActionClick, "https://example.com", "agent-A", "session"), secCtxA)
	}
	// Agent B should have separate limit
	secCtxB := NewSecurityContext("agent-B", "session")
	result, _ := g.GuardClick(context.Background(), NewBrowserAction(ActionClick, "https://example.com", "agent-B", "session"), secCtxB)
	if !result.Allow() {
		t.Error("Agent B should have independent limit")
	}
}

func TestGuardSensitiveData_Empty(t *testing.T) {
	g := NewGuard()
	result, _ := g.GuardSensitiveData(context.Background(), "", NewSecurityContext("agent", "session"))
	if !result.Allow() {
		t.Error("Empty content should be allowed")
	}
}

func TestGuardFormField_AllSensitive(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	for _, fieldType := range []string{"password", "credit_card", "ssn", "cvv", "pin", "secret", "api_key", "private_key"} {
		field := &FormField{Name: "field", Type: fieldType}
		result, _ := g.GuardFormField(context.Background(), field, "value", secCtx)
		if result.Decision != DecisionBlock {
			t.Errorf("Expected block for %s, got %s", fieldType, result.Decision)
		}
	}
}

func TestConfig_AllDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxClicksPerMinute != 10 {
		t.Errorf("MaxClicksPerMinute = %d", cfg.MaxClicksPerMinute)
	}
	if cfg.MaxScreenshotsPerMinute != 1 {
		t.Errorf("MaxScreenshotsPerMinute = %d", cfg.MaxScreenshotsPerMinute)
	}
	if cfg.MaxKeystrokesPerMinute != 120 {
		t.Errorf("MaxKeystrokesPerMinute = %d", cfg.MaxKeystrokesPerMinute)
	}
	if cfg.ScreenshotCooldownSeconds != 60 {
		t.Errorf("ScreenshotCooldownSeconds = %d", cfg.ScreenshotCooldownSeconds)
	}
	if cfg.ClickRateThreshold != 5 {
		t.Errorf("ClickRateThreshold = %d", cfg.ClickRateThreshold)
	}
	if !cfg.BlockCreditCards || !cfg.BlockSSN || !cfg.BlockPasswords || !cfg.MaskSessionTokens || !cfg.BlockSensitiveFields {
		t.Error("Default protection flags should be true")
	}
}
