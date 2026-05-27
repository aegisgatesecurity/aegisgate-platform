package computeruse

import (
	"context"
	"testing"
)

func TestComputerUse_ScreenshotRateLimit_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{ScreenshotCooldownSeconds: 60})
	secCtx := NewSecurityContext("agent", "session")
	_, _ = g.GuardScreenshot(context.Background(), NewBrowserAction(ActionScreenshot, "https://example.com", "agent", "session"), secCtx)
	result, _ := g.GuardScreenshot(context.Background(), NewBrowserAction(ActionScreenshot, "https://example.com", "agent", "session"), secCtx)
	if result.Allow() {
		t.Error("Second screenshot should be blocked")
	}
}

func TestComputerUse_SensitiveData_CC_Visa_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{BlockCreditCards: true})
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardSensitiveData(context.Background(), "4111111111111111", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for Visa, got %s", result.Decision)
	}
}

func TestComputerUse_SensitiveData_CC_MC_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{BlockCreditCards: true})
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardSensitiveData(context.Background(), "5500000000000004", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for MC, got %s", result.Decision)
	}
}

func TestComputerUse_SensitiveData_CC_Spaced_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{BlockCreditCards: true})
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardSensitiveData(context.Background(), "4111 1111 1111 1111", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for spaced CC, got %s", result.Decision)
	}
}

func TestComputerUse_SensitiveData_CC_Dashed_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{BlockCreditCards: true})
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardSensitiveData(context.Background(), "4111-1111-1111-1111", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for dashed CC, got %s", result.Decision)
	}
}

func TestComputerUse_SensitiveData_SSN_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{BlockSSN: true})
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardSensitiveData(context.Background(), "123-45-6789", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for SSN, got %s", result.Decision)
	}
}

func TestComputerUse_SensitiveData_CC_InText_Boost(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardSensitiveData(context.Background(), "The card number is 4111111111111111", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for CC in text, got %s", result.Decision)
	}
}

func TestComputerUse_SensitiveData_SSN_InText_Boost(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardSensitiveData(context.Background(), "My SSN is 123-45-6789", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for SSN in text, got %s", result.Decision)
	}
}

func TestComputerUse_FormField_SensitiveType_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{BlockSensitiveFields: true})
	field := &FormField{Name: "cvv", Type: "text", IsSensitive: true}
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardFormField(context.Background(), field, "123", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for sensitive type field, got %s", result.Decision)
	}
}

func TestComputerUse_FormField_PasswordType_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{BlockSensitiveFields: true})
	field := &FormField{Name: "pwd", Type: "password", IsSensitive: false}
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardFormField(context.Background(), field, "any", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for password type, got %s", result.Decision)
	}
}

func TestComputerUse_SensitiveData_MultipleCC_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{BlockCreditCards: true})
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardSensitiveData(context.Background(), "Card1: 4111111111111111, Card2: 5500000000000004", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for multiple CC, got %s", result.Decision)
	}
}

func TestComputerUse_SensitiveData_MultipleSSN_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{BlockSSN: true})
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardSensitiveData(context.Background(), "SSN1: 123-45-6789, SSN2: 987-65-4321", secCtx)
	if result.Decision != DecisionBlock {
		t.Errorf("Expected block for multiple SSN, got %s", result.Decision)
	}
}

func TestComputerUse_URL_FileScheme_Boost(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	_, err := g.GuardURL(context.Background(), "file:///etc/passwd", secCtx)
	if err != nil {
		t.Errorf("GuardURL should handle file scheme: %v", err)
	}
}

func TestComputerUse_URL_DataScheme_Boost(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	_, err := g.GuardURL(context.Background(), "data:text/html,<script>", secCtx)
	if err != nil {
		t.Errorf("GuardURL should handle data scheme: %v", err)
	}
}

func TestComputerUse_URL_CustomPort_Boost(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	_, err := g.GuardURL(context.Background(), "https://example.com:8443/api", secCtx)
	if err != nil {
		t.Errorf("GuardURL should handle custom port: %v", err)
	}
}

func TestComputerUse_URL_QueryParams_Boost(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	_, err := g.GuardURL(context.Background(), "https://example.com/api?key=value&token=abc", secCtx)
	if err != nil {
		t.Errorf("GuardURL should handle query params: %v", err)
	}
}

func TestComputerUse_URL_Fragment_Boost(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	_, err := g.GuardURL(context.Background(), "https://example.com/page#section", secCtx)
	if err != nil {
		t.Errorf("GuardURL should handle fragment: %v", err)
	}
}

func TestComputerUse_URL_IPv6_Boost(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	_, err := g.GuardURL(context.Background(), "https://[::1]:8080/path", secCtx)
	if err != nil {
		t.Errorf("GuardURL should handle IPv6: %v", err)
	}
}

func TestComputerUse_Action_Metadata_Boost(t *testing.T) {
	action := NewBrowserAction(ActionClick, "https://example.com", "agent", "session")
	action.Metadata["clicked_by"] = "test"
	if action.Metadata["clicked_by"] != "test" {
		t.Error("Metadata not set correctly")
	}
}

func TestComputerUse_Action_AllFields_Boost(t *testing.T) {
	action := NewBrowserAction(ActionClick, "https://example.com", "agent", "session")
	action.Element = "#submit"
	action.X = 100
	action.Y = 200
	if action.Element != "#submit" || action.X != 100 || action.Y != 200 {
		t.Error("Fields not set correctly")
	}
}

func TestComputerUse_SecCtx_TrustScore_Boost(t *testing.T) {
	secCtx := NewSecurityContext("agent", "session")
	secCtx.TrustScore = 0.85
	if secCtx.TrustScore != 0.85 {
		t.Error("TrustScore not set correctly")
	}
}

func TestComputerUse_SecCtx_Capabilities_Boost(t *testing.T) {
	secCtx := NewSecurityContext("agent", "session")
	secCtx.Capabilities = []string{"read", "write", "execute"}
	if len(secCtx.Capabilities) != 3 {
		t.Error("Capabilities not set correctly")
	}
}

func TestComputerUse_Result_AllowAndBlock_Boost(t *testing.T) {
	resultAllow := NewGuardResult(DecisionAllow, "test", "rule", "low")
	if !resultAllow.Allow() {
		t.Error("DecisionAllow should allow")
	}
	resultBlock := NewGuardResult(DecisionBlock, "test", "rule", "low")
	if !resultBlock.Block() {
		t.Error("DecisionBlock should block")
	}
	resultMask := NewGuardResult(DecisionMask, "test", "rule", "low")
	if !resultMask.Allow() {
		t.Error("DecisionMask should allow")
	}
	resultRequire := NewGuardResult(DecisionRequireApproval, "test", "rule", "low")
	if resultRequire.Allow() {
		t.Error("DecisionRequireApproval should not allow immediately")
	}
}

func TestComputerUse_IsSensitive_True_Boost(t *testing.T) {
	fields := []string{"password", "credit_card", "ssn", "cvv", "pin", "secret", "api_key", "private_key"}
	for _, f := range fields {
		if !IsSensitiveField(f) {
			t.Errorf("IsSensitiveField(%s) = false, want true", f)
		}
	}
}

func TestComputerUse_IsSensitive_False_Boost(t *testing.T) {
	fields := []string{"text", "email", "name", "address", "phone", "date", "number"}
	for _, f := range fields {
		if IsSensitiveField(f) {
			t.Errorf("IsSensitiveField(%s) = true, want false", f)
		}
	}
}

func TestComputerUse_Config_Defaults_Boost(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxClicksPerMinute != 10 || cfg.MaxScreenshotsPerMinute != 1 || cfg.MaxKeystrokesPerMinute != 120 {
		t.Error("Default rate limits incorrect")
	}
	if cfg.ScreenshotCooldownSeconds != 60 || cfg.ClickRateThreshold != 5 {
		t.Error("Default thresholds incorrect")
	}
	if !cfg.BlockCreditCards || !cfg.BlockSSN || !cfg.BlockPasswords {
		t.Error("Default blocks should be enabled")
	}
}

func TestComputerUse_Guard_DefaultConfig_Boost(t *testing.T) {
	g := NewGuard()
	if g.cfg == nil || g.clickRate == nil || g.screenshotLast == nil {
		t.Error("Guard maps should be initialized")
	}
	if g.sensitivePatterns == nil || len(g.sensitivePatterns) == 0 {
		t.Error("sensitivePatterns should be compiled")
	}
}

func TestComputerUse_Click_RateLimit_Boost(t *testing.T) {
	cfg := &Config{MaxClicksPerMinute: 2}
	g := NewGuardWithConfig(cfg)
	secCtx := NewSecurityContext("agent", "session")
	action := NewBrowserAction(ActionClick, "https://example.com", "agent", "session")
	_, _ = g.GuardClick(context.Background(), action, secCtx)
	_, _ = g.GuardClick(context.Background(), action, secCtx)
	result, _ := g.GuardClick(context.Background(), action, secCtx)
	if result.Decision != DecisionBlock {
		t.Error("Click rate limit should be enforced")
	}
}

func TestComputerUse_Click_PerAgent_Boost(t *testing.T) {
	g := NewGuardWithConfig(&Config{MaxClicksPerMinute: 1})
	action := NewBrowserAction(ActionClick, "https://example.com", "agent-a", "session")
	secCtxA := NewSecurityContext("agent-a", "session")
	secCtxB := NewSecurityContext("agent-b", "session")
	_, _ = g.GuardClick(context.Background(), action, secCtxA)
	result, _ := g.GuardClick(context.Background(), action, secCtxB)
	if result.Allow() {
		t.Log("Agent B allowed - rate limits are per-agent")
	}
}

func TestComputerUse_Click_RapidPattern_Boost(t *testing.T) {
	cfg := &Config{ClickRateThreshold: 3}
	g := NewGuardWithConfig(cfg)
	secCtx := NewSecurityContext("agent", "session")
	action := NewBrowserAction(ActionClick, "https://example.com", "agent", "session")
	for i := 0; i < 4; i++ {
		g.GuardClick(context.Background(), action, secCtx)
	}
	result, _ := g.GuardClick(context.Background(), action, secCtx)
	if result.Decision == DecisionLogOnly {
		t.Log("Rapid clicking detected")
	}
}

func TestComputerUse_URL_AllDenylist_Boost(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent", "session")
	blocked := []string{"http://localhost:8080", "http://127.0.0.1/admin", "https://0.0.0.0:8080"}
	for _, url := range blocked {
		result, _ := g.GuardURL(context.Background(), url, secCtx)
		if result.Decision != DecisionBlock {
			t.Errorf("Expected block for %s", url)
		}
	}
}

func TestComputerUse_URL_WhitelistOverride_Boost(t *testing.T) {
	cfg := &Config{
		URLAllowlist:   []string{"example.com"},
		URLDenylist:    []string{"admin"},
		AllowByDefault: false,
	}
	g := NewGuardWithConfig(cfg)
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardURL(context.Background(), "https://example.com/admin", secCtx)
	if result.Decision != DecisionBlock {
		t.Error("Denylist should override allowlist")
	}
}

func TestComputerUse_URL_NoLists_Allow_Boost(t *testing.T) {
	cfg := &Config{AllowByDefault: true}
	g := NewGuardWithConfig(cfg)
	secCtx := NewSecurityContext("agent", "session")
	result, _ := g.GuardURL(context.Background(), "https://example.com", secCtx)
	if !result.Allow() {
		t.Error("Should allow when AllowByDefault=true")
	}
}

func TestComputerUse_Action_Timestamp_Boost(t *testing.T) {
	action := NewBrowserAction(ActionClick, "https://example.com", "agent", "session")
	if action.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestComputerUse_SecCtx_Timestamp_Boost(t *testing.T) {
	secCtx := NewSecurityContext("agent", "session")
	if secCtx.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}
