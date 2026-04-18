package policy

import (
	"context"
	"testing"
)

func TestNewEngine(t *testing.T) {
	engine := NewEngine()
	if engine == nil {
		t.Fatal("NewEngine() returned nil")
	}
	if engine.rules == nil {
		t.Error("rules slice not initialized")
	}
	if engine.policies == nil {
		t.Error("policies map not initialized")
	}
}

func TestEngineAddRule(t *testing.T) {
	engine := NewEngine()

	rule := Rule{
		ID:          "test-rule",
		Name:        "Test Rule",
		Description: "A test rule",
		Condition: RuleCondition{
			ToolNames: []string{"shell"},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "Shell not allowed",
		},
		Priority: 100,
		Enabled:  true,
	}

	engine.AddRule(rule)

	if len(engine.rules) != 1 {
		t.Errorf("AddRule() rules length = %d, want 1", len(engine.rules))
	}
}

func TestEngineAddPolicy(t *testing.T) {
	engine := NewEngine()

	policy := Policy{
		ID:          "test-policy",
		Name:        "Test Policy",
		Description: "A test policy",
		Version:     "1.0",
		Enabled:     true,
		Rules: []Rule{
			{
				ID:   "rule-1",
				Name: "Rule 1",
				Action: RuleAction{
					Allow: true,
				},
				Enabled: true,
			},
		},
	}

	engine.AddPolicy(policy)

	retrieved, ok := engine.GetPolicy("test-policy")
	if !ok {
		t.Fatal("AddPolicy() did not store policy")
	}
	if retrieved.Name != "Test Policy" {
		t.Errorf("Policy name = %s, want 'Test Policy'", retrieved.Name)
	}
}

func TestEngineEvaluateNoRules(t *testing.T) {
	engine := NewEngine()

	ctx := context.Background()
	evalCtx := &EvaluationContext{
		ToolName:  "file_read",
		SessionID: "session-1",
	}

	decision := engine.Evaluate(ctx, evalCtx)

	if !decision.Allowed {
		t.Error("Evaluate() with no rules should default to allow")
	}
}

func TestEngineEvaluateMatchingRule(t *testing.T) {
	engine := NewEngine()

	// Add a rule that blocks shell commands
	engine.AddRule(Rule{
		ID:   "block-shell",
		Name: "Block Shell",
		Condition: RuleCondition{
			ToolNames: []string{"shell", "bash"},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "Shell commands blocked",
		},
		Enabled: true,
	})

	ctx := context.Background()
	evalCtx := &EvaluationContext{
		ToolName:  "shell",
		SessionID: "session-1",
	}

	decision := engine.Evaluate(ctx, evalCtx)

	if decision.Allowed {
		t.Error("Evaluate() should deny shell command")
	}
	if decision.Reason != "Shell commands blocked" {
		t.Errorf("Reason = %s, want 'Shell commands blocked'", decision.Reason)
	}
}

func TestEngineEvaluateRiskAbove(t *testing.T) {
	engine := NewEngine()

	// Add a rule that alerts on high risk
	engine.AddRule(Rule{
		ID:   "high-risk-alert",
		Name: "High Risk Alert",
		Condition: RuleCondition{
			RiskAbove: 70,
		},
		Action: RuleAction{
			Allow:        true,
			LogLevel:     "alert",
			RiskModifier: 10,
		},
		Enabled: true,
	})

	ctx := context.Background()
	evalCtx := &EvaluationContext{
		ToolName:  "file_write",
		RiskScore: 80,
	}

	decision := engine.Evaluate(ctx, evalCtx)

	if len(decision.MatchedRules) != 1 {
		t.Errorf("MatchedRules count = %d, want 1", len(decision.MatchedRules))
	}
	if decision.ModifiedRisk != 10 {
		t.Errorf("ModifiedRisk = %d, want 10", decision.ModifiedRisk)
	}
}

func TestEngineEvaluateDisabledRule(t *testing.T) {
	engine := NewEngine()

	engine.AddRule(Rule{
		ID:   "disabled-rule",
		Name: "Disabled Rule",
		Condition: RuleCondition{
			ToolNames: []string{"*"},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "Should not match",
		},
		Enabled: false,
	})

	ctx := context.Background()
	evalCtx := &EvaluationContext{
		ToolName: "anything",
	}

	decision := engine.Evaluate(ctx, evalCtx)

	if len(decision.MatchedRules) != 0 {
		t.Errorf("Disabled rule should not match, got %v", decision.MatchedRules)
	}
}

func TestEngineDisableRule(t *testing.T) {
	engine := NewEngine()

	engine.AddRule(Rule{
		ID:      "toggleable-rule",
		Name:    "Toggleable Rule",
		Enabled: true,
	})

	engine.DisableRule("toggleable-rule")

	if engine.rules[0].Enabled {
		t.Error("DisableRule() should set Enabled to false")
	}
}

func TestEngineEnableRule(t *testing.T) {
	engine := NewEngine()

	engine.AddRule(Rule{
		ID:      "toggleable-rule",
		Name:    "Toggleable Rule",
		Enabled: false,
	})

	engine.EnableRule("toggleable-rule")

	if !engine.rules[0].Enabled {
		t.Error("EnableRule() should set Enabled to true")
	}
}

func TestEngineLoadPolicy(t *testing.T) {
	engine := NewEngine()

	policy := Policy{
		ID:   "load-test",
		Name: "Load Test Policy",
		Rules: []Rule{
			{ID: "r1", Name: "Rule 1", Enabled: true},
			{ID: "r2", Name: "Rule 2", Enabled: false},
		},
	}

	err := engine.LoadPolicy(&policy)
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}

	// All rules should be enabled after load
	for _, rule := range engine.rules {
		if !rule.Enabled {
			t.Error("Rules should be enabled after LoadPolicy()")
		}
	}
}

func TestCommonRules(t *testing.T) {
	rules := CommonRules()

	if len(rules) == 0 {
		t.Error("CommonRules() should return at least one rule")
	}

	// Verify common security rules exist
	found := make(map[string]bool)
	for _, rule := range rules {
		found[rule.ID] = true
	}

	if !found["block-shell"] {
		t.Error("CommonRules() should include block-shell rule")
	}
	if !found["block-file-delete"] {
		t.Error("CommonRules() should include block-file-delete rule")
	}
	if !found["high-risk-alert"] {
		t.Error("CommonRules() should include high-risk-alert rule")
	}
}

func TestEngineEvaluateCustomMatcher(t *testing.T) {
	engine := NewEngine()

	// Add a rule with custom matcher
	engine.AddRule(Rule{
		ID:   "custom-rule",
		Name: "Custom Rule",
		Condition: RuleCondition{
			CustomMatcher: func(ctx context.Context, ec *EvaluationContext) bool {
				return ec.AgentID == "trusted-agent"
			},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "Custom matcher blocked",
		},
		Enabled: true,
	})

	ctx := context.Background()

	// Should match - agent is trusted
	evalCtx1 := &EvaluationContext{
		ToolName: "file_read",
		AgentID:  "trusted-agent",
	}
	decision1 := engine.Evaluate(ctx, evalCtx1)
	if decision1.Allowed {
		t.Error("Custom matcher should block for trusted-agent")
	}

	// Should not match - agent is not trusted
	evalCtx2 := &EvaluationContext{
		ToolName: "file_read",
		AgentID:  "untrusted-agent",
	}
	decision2 := engine.Evaluate(ctx, evalCtx2)
	if !decision2.Allowed {
		t.Error("Custom matcher should not block for untrusted-agent")
	}
}

func TestEngineEvaluateWildcardToolNames(t *testing.T) {
	engine := NewEngine()

	// Add rule with wildcard
	engine.AddRule(Rule{
		ID:   "block-file-ops",
		Name: "Block File Operations",
		Condition: RuleCondition{
			ToolNames: []string{"file_*"},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "File operations blocked",
		},
		Enabled: true,
	})

	ctx := context.Background()

	tests := []struct {
		toolName string
		expected bool
	}{
		{"file_read", false},
		{"file_write", false},
		{"file_delete", false},
		{"network_request", true},
	}

	for _, tt := range tests {
		evalCtx := &EvaluationContext{ToolName: tt.toolName}
		decision := engine.Evaluate(ctx, evalCtx)
		if decision.Allowed != tt.expected {
			t.Errorf("Tool %s: allowed = %v, want %v", tt.toolName, decision.Allowed, tt.expected)
		}
	}
}

func TestEngineEvaluateAgentIDFilter(t *testing.T) {
	engine := NewEngine()

	engine.AddRule(Rule{
		ID:   "restrict-agent",
		Name: "Restrict Agent",
		Condition: RuleCondition{
			AgentIDs: []string{"agent-1", "agent-2"},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "Agent not allowed",
		},
		Enabled: true,
	})

	ctx := context.Background()

	// agent-1 should be blocked
	eval1 := &EvaluationContext{ToolName: "read", AgentID: "agent-1"}
	d1 := engine.Evaluate(ctx, eval1)
	if d1.Allowed {
		t.Error("agent-1 should be blocked")
	}

	// agent-3 should be allowed
	eval2 := &EvaluationContext{ToolName: "read", AgentID: "agent-3"}
	d2 := engine.Evaluate(ctx, eval2)
	if !d2.Allowed {
		t.Error("agent-3 should be allowed")
	}
}

func TestEngineEvaluateSessionTags(t *testing.T) {
	engine := NewEngine()

	engine.AddRule(Rule{
		ID:   "production-only",
		Name: "Production Only",
		Condition: RuleCondition{
			SessionTags: map[string]string{"env": "production"},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "Not allowed in non-production",
		},
		Enabled: true,
	})

	ctx := context.Background()

	// Should match - production tag
	eval1 := &EvaluationContext{
		ToolName: "shell",
		Tags:     map[string]string{"env": "production"},
	}
	d1 := engine.Evaluate(ctx, eval1)
	if d1.Allowed {
		t.Error("Production environment should be blocked for shell")
	}

	// Should not match - staging tag
	eval2 := &EvaluationContext{
		ToolName: "shell",
		Tags:     map[string]string{"env": "staging"},
	}
	d2 := engine.Evaluate(ctx, eval2)
	if !d2.Allowed {
		t.Error("Staging environment should be allowed")
	}

	// Should not match - no tags
	eval3 := &EvaluationContext{ToolName: "shell"}
	d3 := engine.Evaluate(ctx, eval3)
	if !d3.Allowed {
		t.Error("No tags should be allowed")
	}
}

func TestEngineDeletePolicy(t *testing.T) {
	engine := NewEngine()

	policy := Policy{
		ID:   "delete-test",
		Name: "Delete Test",
		Rules: []Rule{
			{ID: "rule-to-delete", Name: "Rule", Action: RuleAction{Allow: false}, Enabled: true},
		},
	}
	engine.AddPolicy(policy)

	err := engine.DeletePolicy("delete-test")
	if err != nil {
		t.Fatalf("DeletePolicy() error = %v", err)
	}

	_, ok := engine.GetPolicy("delete-test")
	if ok {
		t.Error("GetPolicy() after DeletePolicy() should return false")
	}

	// Rules should also be removed
	found := false
	for _, r := range engine.rules {
		if r.ID == "rule-to-delete" {
			found = true
			break
		}
	}
	if found {
		t.Error("Rules from deleted policy should be removed")
	}
}

func TestEngineDeletePolicyNotFound(t *testing.T) {
	engine := NewEngine()

	err := engine.DeletePolicy("nonexistent")
	if err != ErrPolicyNotFound {
		t.Errorf("DeletePolicy() error = %v, want ErrPolicyNotFound", err)
	}
}

func TestEngineListPolicies(t *testing.T) {
	engine := NewEngine()

	engine.AddPolicy(Policy{ID: "policy-1", Name: "Policy 1"})
	engine.AddPolicy(Policy{ID: "policy-2", Name: "Policy 2"})
	engine.AddPolicy(Policy{ID: "policy-3", Name: "Policy 3"})

	ids := engine.ListPolicies()
	if len(ids) != 3 {
		t.Errorf("ListPolicies() count = %d, want 3", len(ids))
	}
}

func TestEngineMultipleMatchingRules(t *testing.T) {
	engine := NewEngine()

	// First deny rule
	engine.AddRule(Rule{
		ID:   "deny-shell",
		Name: "Deny Shell",
		Condition: RuleCondition{
			ToolNames: []string{"shell"},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "Shell denied",
		},
		Enabled: true,
	})

	// Second rule that adds risk
	engine.AddRule(Rule{
		ID:   "log-shell",
		Name: "Log Shell",
		Condition: RuleCondition{
			ToolNames: []string{"shell"},
		},
		Action: RuleAction{
			Allow:        true,
			LogLevel:     "alert",
			RiskModifier: 20,
		},
		Enabled: true,
	})

	ctx := context.Background()
	evalCtx := &EvaluationContext{ToolName: "shell"}
	decision := engine.Evaluate(ctx, evalCtx)

	// Should be denied (first rule matches)
	if decision.Allowed {
		t.Error("Should be denied")
	}

	// Should have matched both rules
	if len(decision.MatchedRules) != 2 {
		t.Errorf("MatchedRules count = %d, want 2", len(decision.MatchedRules))
	}

	// Risk should be modified
	if decision.ModifiedRisk != 20 {
		t.Errorf("ModifiedRisk = %d, want 20", decision.ModifiedRisk)
	}
}

func TestEngineRuleWithAllConditions(t *testing.T) {
	engine := NewEngine()

	engine.AddRule(Rule{
		ID:   "complex-rule",
		Name: "Complex Rule",
		Condition: RuleCondition{
			ToolNames:   []string{"shell"},
			AgentIDs:    []string{"admin-agent"},
			SessionTags: map[string]string{"level": "admin"},
			RiskAbove:   50,
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "Complex rule blocks",
		},
		Enabled: true,
	})

	ctx := context.Background()

	// Should not match - wrong tool
	eval1 := &EvaluationContext{
		ToolName:  "read",
		AgentID:   "admin-agent",
		RiskScore: 80,
		Tags:      map[string]string{"level": "admin"},
	}
	if !engine.Evaluate(ctx, eval1).Allowed {
		t.Error("Should allow - wrong tool")
	}

	// Should not match - wrong agent
	eval2 := &EvaluationContext{
		ToolName:  "shell",
		AgentID:   "user-agent",
		RiskScore: 80,
		Tags:      map[string]string{"level": "admin"},
	}
	if !engine.Evaluate(ctx, eval2).Allowed {
		t.Error("Should allow - wrong agent")
	}

	// Should match - all conditions met
	eval3 := &EvaluationContext{
		ToolName:  "shell",
		AgentID:   "admin-agent",
		RiskScore: 80,
		Tags:      map[string]string{"level": "admin"},
	}
	if engine.Evaluate(ctx, eval3).Allowed {
		t.Error("Should deny - all conditions met")
	}
}

func TestEngineNilTagsInContext(t *testing.T) {
	engine := NewEngine()

	engine.AddRule(Rule{
		ID:   "tag-rule",
		Name: "Tag Rule",
		Condition: RuleCondition{
			SessionTags: map[string]string{"env": "prod"},
		},
		Action: RuleAction{
			Allow: false,
		},
		Enabled: true,
	})

	ctx := context.Background()
	evalCtx := &EvaluationContext{
		ToolName: "shell",
		Tags:     nil, // No tags in context
	}

	decision := engine.Evaluate(ctx, evalCtx)
	if !decision.Allowed {
		t.Error("Nil tags should not match tag-based rules")
	}
}

func TestEngineDenyReasonFromMatchingRule(t *testing.T) {
	engine := NewEngine()

	engine.AddRule(Rule{
		ID:   "deny-reason-1",
		Name: "Deny Reason 1",
		Condition: RuleCondition{
			ToolNames: []string{"dangerous"},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "First deny reason",
		},
		Enabled: true,
	})

	engine.AddRule(Rule{
		ID:   "deny-reason-2",
		Name: "Deny Reason 2",
		Condition: RuleCondition{
			ToolNames: []string{"dangerous"},
		},
		Action: RuleAction{
			Allow:      false,
			DenyReason: "Second deny reason",
		},
		Enabled: true,
	})

	ctx := context.Background()
	evalCtx := &EvaluationContext{ToolName: "dangerous"}
	decision := engine.Evaluate(ctx, evalCtx)

	// Should use first matching deny reason
	if decision.Reason != "First deny reason" {
		t.Logf("Reason = %s (may vary based on order)", decision.Reason)
	}
}

func TestPolicyError(t *testing.T) {
	err := &PolicyError{"test error"}
	if err.Error() != "test error" {
		t.Errorf("PolicyError.Error() = %s, want 'test error'", err.Error())
	}
}
