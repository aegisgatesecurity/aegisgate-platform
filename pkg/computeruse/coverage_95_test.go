package computeruse

import (
	"context"
	"testing"
)

func TestGuardNilConfig(t *testing.T) {
	g := NewGuardWithConfig(nil)
	if g == nil {
		t.Error("Guard should not be nil")
	}
}

func TestGuardDefault(t *testing.T) {
	g := NewGuard()
	if g == nil {
		t.Error("Guard should not be nil")
	}
}

func TestGuardURL(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent-1", "session-1")

	result, err := g.GuardURL(context.Background(), "https://example.com", secCtx)
	if err != nil {
		t.Errorf("GuardURL failed: %v", err)
	}
	_ = result
}

func TestGuardURLEmpty(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent-1", "session-1")

	_, err := g.GuardURL(context.Background(), "", secCtx)
	if err == nil {
		t.Error("GuardURL with empty URL should error")
	}
}

func TestGuardClick(t *testing.T) {
	g := NewGuard()
	action := NewBrowserAction("click", "https://example.com", "agent-1", "session-1")
	secCtx := NewSecurityContext("agent-1", "session-1")

	result, err := g.GuardClick(context.Background(), action, secCtx)
	if err != nil {
		t.Errorf("GuardClick failed: %v", err)
	}
	_ = result
}

func TestGuardClickNilAction(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent-1", "session-1")

	_, err := g.GuardClick(context.Background(), nil, secCtx)
	if err == nil {
		t.Error("GuardClick with nil action should error")
	}
}

func TestGuardScreenshot(t *testing.T) {
	g := NewGuard()
	action := NewBrowserAction("screenshot", "https://example.com", "agent-1", "session-1")
	secCtx := NewSecurityContext("agent-1", "session-1")

	result, err := g.GuardScreenshot(context.Background(), action, secCtx)
	if err != nil {
		t.Errorf("GuardScreenshot failed: %v", err)
	}
	_ = result
}

func TestGuardScreenshotNilAction(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent-1", "session-1")

	_, err := g.GuardScreenshot(context.Background(), nil, secCtx)
	if err == nil {
		t.Error("GuardScreenshot with nil action should error")
	}
}

func TestGuardKeystroke(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent-1", "session-1")

	result, err := g.GuardKeystroke(context.Background(), "hello", secCtx)
	if err != nil {
		t.Errorf("GuardKeystroke failed: %v", err)
	}
	_ = result
}

func TestGuardFormField(t *testing.T) {
	g := NewGuard()
	field := &FormField{Name: "name", Type: "text", IsSensitive: false}
	secCtx := NewSecurityContext("agent-1", "session-1")

	result, err := g.GuardFormField(context.Background(), field, "test value", secCtx)
	if err != nil {
		t.Errorf("GuardFormField failed: %v", err)
	}
	_ = result
}

func TestGuardSensitiveData(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent-1", "session-1")

	result, err := g.GuardSensitiveData(context.Background(), "clean text", secCtx)
	if err != nil {
		t.Errorf("GuardSensitiveData failed: %v", err)
	}
	_ = result
}

func TestGuardSensitiveDataEmpty(t *testing.T) {
	g := NewGuard()
	secCtx := NewSecurityContext("agent-1", "session-1")

	result, err := g.GuardSensitiveData(context.Background(), "", secCtx)
	if err != nil {
		t.Errorf("GuardSensitiveData(empty) failed: %v", err)
	}
	_ = result
}

func TestGuardResultAllow(t *testing.T) {
	result := NewGuardResult(DecisionAllow, "allowed", "rule", "low")
	if !result.Allow() {
		t.Error("Should allow")
	}
	if result.Block() {
		t.Error("Should not block")
	}
}

func TestGuardResultBlock(t *testing.T) {
	result := NewGuardResult(DecisionBlock, "blocked", "rule", "high")
	if result.Allow() {
		t.Error("Should not allow")
	}
	if !result.Block() {
		t.Error("Should block")
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Error("DefaultConfig should not return nil")
	}
	if cfg.MaxClicksPerMinute != 10 {
		t.Error("MaxClicksPerMinute should be 10")
	}
	if cfg.MaxScreenshotsPerMinute != 1 {
		t.Error("MaxScreenshotsPerMinute should be 1")
	}
}

func TestGuardDecisionConstants(t *testing.T) {
	decisions := []GuardDecision{DecisionAllow, DecisionBlock, DecisionMask, DecisionRequireApproval, DecisionLogOnly}
	for _, d := range decisions {
		if d == "" {
			t.Error("GuardDecision should not be empty")
		}
	}
}

func TestActionTypeConstants(t *testing.T) {
	types := []string{ActionClick, ActionType, ActionNavigate, ActionScreenshot, ActionScroll, ActionHover}
	for _, a := range types {
		if a == "" {
			t.Error("ActionType should not be empty")
		}
	}
}
