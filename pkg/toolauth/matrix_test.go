// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Tool Authorizer Matrix Tests

package toolauth

import (
	"context"
	"testing"
)

// ============================================================================
// RISKLEVEL TESTS
// ============================================================================

func TestRiskLevel_String(t *testing.T) {
	tests := []struct {
		level RiskLevel
		want  string
	}{
		{RiskLevelNone, "none"},
		{RiskLevelLow, "low"},
		{RiskLevelMedium, "medium"},
		{RiskLevelHigh, "high"},
		{RiskLevelCritical, "critical"},
		{99, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.level.String(); got != tt.want {
				t.Errorf("RiskLevel.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// RISKSCORER TESTS
// ============================================================================

func TestRiskScorer_Score(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		wantScore int
		wantRange string
	}{
		{"shell_command max", "shell_command", 100, "95-100"},
		{"bash max", "bash", 100, "95-100"},
		{"code_execute high", "code_execute", 100, "90-100"},
		{"database medium-high", "database", 100, "70-100"},
		{"file_write medium", "file_write", 100, "80-100"},
		{"file_read low", "file_read", 80, "30-80"},
		{"network_call medium", "network_call", 100, "60-100"},
		{"unknown tool base", "unknown_tool", 50, "50"},
	}

	sc := newRiskScorer()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &ToolCall{Name: tt.toolName}
			got := sc.Score(call)

			if got < 50 || got > 100 {
				t.Errorf("RiskScorer.Score() = %d, expected range 50-100", got)
			}

			if tt.toolName == "shell_command" && got != 100 {
				t.Errorf("shell_command should score 100, got %d", got)
			}
			if tt.toolName == "bash" && got != 100 {
				t.Errorf("bash should score 100, got %d", got)
			}
			if tt.toolName == "unknown_tool" && got != 50 {
				t.Errorf("unknown tool should score 50 (base), got %d", got)
			}
		})
	}
}

func TestRiskScorer_ScoreCaps(t *testing.T) {
	sc := newRiskScorer()

	call := &ToolCall{Name: "shell_command"}
	score := sc.Score(call)

	if score > 100 {
		t.Errorf("RiskScorer.Score() should cap at 100, got %d", score)
	}
	if score < 50 {
		t.Errorf("RiskScorer.Score() should be at least 50, got %d", score)
	}
}

// ============================================================================
// MATRIX TESTS
// ============================================================================

func TestNewMatrix(t *testing.T) {
	m := NewMatrix()

	if m == nil {
		t.Fatal("NewMatrix() returned nil")
	}
	if m.policies == nil {
		t.Error("NewMatrix() policies should be initialized")
	}
	if m.riskScorer == nil {
		t.Error("NewMatrix() riskScorer should be initialized")
	}
}

func TestMatrix_AddPolicy(t *testing.T) {
	m := NewMatrix()

	policy := ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	}

	m.AddPolicy("test_tool", policy)

	if len(m.policies) != 1 {
		t.Errorf("AddPolicy() should add 1 policy, got %d", len(m.policies))
	}

	got, ok := m.policies["test_tool"]
	if !ok {
		t.Fatal("AddPolicy() policy not found")
	}
	if got.Allow != true {
		t.Error("AddPolicy() Allow should be true")
	}
	if got.RiskLevel != RiskLevelLow {
		t.Errorf("AddPolicy() RiskLevel = %v, want %v", got.RiskLevel, RiskLevelLow)
	}
}

func TestMatrix_AddRule(t *testing.T) {
	m := NewMatrix()

	rule := AuthorizationRule{
		Name:      "test_rule",
		MatchTool: "test_tool",
		Decision:  Decision{Allow: true, Reason: "test"},
	}

	m.AddRule(rule)

	if len(m.rules) != 1 {
		t.Errorf("AddRule() should add 1 rule, got %d", len(m.rules))
	}
	if m.rules[0].Name != "test_rule" {
		t.Errorf("AddRule() name = %v, want test_rule", m.rules[0].Name)
	}
}

func TestMatrix_GetRiskLevel(t *testing.T) {
	m := NewMatrix()

	m.AddPolicy("test_tool", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelHigh,
	})

	got := m.GetRiskLevel("test_tool")
	if got != RiskLevelHigh {
		t.Errorf("GetRiskLevel() = %v, want %v", got, RiskLevelHigh)
	}

	gotNone := m.GetRiskLevel("unknown_tool")
	if gotNone != RiskLevelNone {
		t.Errorf("GetRiskLevel(unknown) = %v, want %v", gotNone, RiskLevelNone)
	}
}

// ============================================================================
// MATRIX AUTHORIZE TESTS
// ============================================================================

func TestMatrix_Authorize_AllowedByPolicy(t *testing.T) {
	m := NewMatrix()
	m.AddPolicy("file_read", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	})

	call := &ToolCall{
		ID:         "1",
		Name:       "file_read",
		Parameters: map[string]interface{}{"path": "/test"},
		AgentID:    "agent1",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	if !dec.Allow {
		t.Error("Authorize() should allow file_read")
	}
	if dec.MatchedRule != "file_read" {
		t.Errorf("Authorize() MatchedRule = %v, want file_read", dec.MatchedRule)
	}
	if dec.RiskScore < 50 {
		t.Errorf("Authorize() RiskScore = %d, expected >= 50", dec.RiskScore)
	}
}

func TestMatrix_Authorize_DeniedByPolicy(t *testing.T) {
	m := NewMatrix()
	m.AddPolicy("dangerous_tool", ToolPolicy{
		Allow: false,
	})

	call := &ToolCall{
		ID:   "1",
		Name: "dangerous_tool",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	if dec.Allow {
		t.Error("Authorize() should deny dangerous_tool")
	}
	if dec.Reason != "tool is not allowed by policy" {
		t.Errorf("Authorize() Reason = %v, want 'tool is not allowed by policy'", dec.Reason)
	}
}

func TestMatrix_Authorize_RequiresApproval(t *testing.T) {
	m := NewMatrix()
	m.AddPolicy("shell_command", ToolPolicy{
		Allow:           true,
		RequireApproval: true,
		RiskLevel:       RiskLevelCritical,
	})

	call := &ToolCall{
		ID:   "1",
		Name: "shell_command",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	if dec.Allow {
		t.Error("Authorize() should require approval for shell_command")
	}
	if dec.Reason != "requires approval" {
		t.Errorf("Authorize() Reason = %v, want 'requires approval'", dec.Reason)
	}
}

func TestMatrix_Authorize_NoMatchingPolicy(t *testing.T) {
	m := NewMatrix()

	call := &ToolCall{
		ID:   "1",
		Name: "unknown_tool",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	if dec.Allow {
		t.Error("Authorize() should deny unknown tools")
	}
	if dec.Reason != "No matching policy found" {
		t.Errorf("Authorize() Reason = %v, want 'No matching policy found'", dec.Reason)
	}
}

func TestMatrix_Authorize_WithRules(t *testing.T) {
	m := NewMatrix()

	m.AddRule(AuthorizationRule{
		Name:      "fallback_allow",
		MatchTool: "special_tool",
		Decision:  Decision{Allow: true, Reason: "rule match", RiskScore: 50},
	})

	call := &ToolCall{
		ID:   "1",
		Name: "special_tool",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	if !dec.Allow {
		t.Error("Authorize() should allow via rule")
	}
	if dec.Reason != "rule match" {
		t.Errorf("Authorize() Reason = %v, want 'rule match'", dec.Reason)
	}
}

func TestMatrix_Authorize_RuleMatchRole(t *testing.T) {
	m := NewMatrix()

	m.AddRule(AuthorizationRule{
		Name:      "admin_only",
		MatchTool: "admin_tool",
		MatchRole: "admin",
		Decision:  Decision{Allow: true, Reason: "admin access"},
	})

	call := &ToolCall{
		ID:      "1",
		Name:    "admin_tool",
		AgentID: "admin",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	if !dec.Allow {
		t.Error("Authorize() should allow admin via rule")
	}
}

// ============================================================================
// DEFAULT POLICIES TESTS
// ============================================================================

func TestMatrix_RegisterDefaultPolicies(t *testing.T) {
	m := NewMatrix()
	m.RegisterDefaultPolicies()

	if len(m.policies) == 0 {
		t.Fatal("RegisterDefaultPolicies() should register policies")
	}

	expectedTools := []string{
		"file_read", "web_search", "code_search", "ping",
		"git_status", "git_log", "git_diff",
		"file_write", "http_request", "database_query", "process_list",
		"file_delete", "shell_command", "bash",
		"code_execute_go", "code_execute_py", "code_execute_js",
	}

	for _, tool := range expectedTools {
		if _, ok := m.policies[tool]; !ok {
			t.Errorf("RegisterDefaultPolicies() missing policy for %s", tool)
		}
	}
}

func TestMatrix_DefaultPolicies_LowRisk(t *testing.T) {
	m := NewMatrix()
	m.RegisterDefaultPolicies()

	lowRiskTools := []string{"file_read", "web_search", "code_search", "ping", "git_status", "git_log", "git_diff"}

	for _, tool := range lowRiskTools {
		level := m.GetRiskLevel(tool)
		if level != RiskLevelLow {
			t.Errorf("Default policy for %s: RiskLevel = %v, want %v", tool, level, RiskLevelLow)
		}

		call := &ToolCall{Name: tool}
		dec, err := m.Authorize(context.Background(), call)
		if err != nil {
			t.Fatalf("Authorize(%s) error = %v", tool, err)
		}
		if !dec.Allow {
			t.Errorf("Default policy for %s should allow", tool)
		}
	}
}

func TestMatrix_DefaultPolicies_HighRisk(t *testing.T) {
	m := NewMatrix()
	m.RegisterDefaultPolicies()

	highRiskTools := []struct {
		name         string
		wantLevel    RiskLevel
		wantApproval bool
	}{
		{"shell_command", RiskLevelCritical, true},
		{"bash", RiskLevelCritical, true},
		{"code_execute_go", RiskLevelCritical, true},
		{"code_execute_py", RiskLevelCritical, true},
		{"code_execute_js", RiskLevelCritical, true},
		{"file_delete", RiskLevelHigh, true},
	}

	for _, tt := range highRiskTools {
		t.Run(tt.name, func(t *testing.T) {
			level := m.GetRiskLevel(tt.name)
			if level != tt.wantLevel {
				t.Errorf("GetRiskLevel(%s) = %v, want %v", tt.name, level, tt.wantLevel)
			}

			policy := m.policies[tt.name]
			if policy.RequireApproval != tt.wantApproval {
				t.Errorf("Policy for %s: RequireApproval = %v, want %v", tt.name, policy.RequireApproval, tt.wantApproval)
			}
		})
	}
}

func TestMatrix_DefaultPolicies_MediumRisk(t *testing.T) {
	m := NewMatrix()
	m.RegisterDefaultPolicies()

	mediumRiskTools := []string{"file_write", "http_request", "process_list"}

	for _, tool := range mediumRiskTools {
		level := m.GetRiskLevel(tool)
		if level != RiskLevelMedium {
			t.Errorf("Default policy for %s: RiskLevel = %v, want %v", tool, level, RiskLevelMedium)
		}
	}
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

func TestMatrix_FullWorkflow(t *testing.T) {
	m := NewMatrix()
	m.RegisterDefaultPolicies()

	tests := []struct {
		toolName    string
		wantAllow   bool
		wantReason  string
		wantRiskMin int
	}{
		{"file_read", true, "allowed by policy", 50},
		{"web_search", true, "allowed by policy", 50},
		{"shell_command", false, "requires approval", 50},
		{"bash", false, "requires approval", 50},
		{"unknown", false, "No matching policy found", 0},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			call := &ToolCall{
				ID:      "test-1",
				Name:    tt.toolName,
				AgentID: "test-agent",
			}

			dec, err := m.Authorize(context.Background(), call)
			if err != nil {
				t.Fatalf("Authorize() error = %v", err)
			}

			if dec.Allow != tt.wantAllow {
				t.Errorf("Authorize(%s).Allow = %v, want %v", tt.toolName, dec.Allow, tt.wantAllow)
			}

			if dec.RiskScore < tt.wantRiskMin && tt.wantRiskMin > 0 {
				t.Errorf("Authorize(%s).RiskScore = %d, want >= %d", tt.toolName, dec.RiskScore, tt.wantRiskMin)
			}
		})
	}
}

func TestMatrix_PolicyOverride(t *testing.T) {
	m := NewMatrix()
	m.RegisterDefaultPolicies()

	m.AddPolicy("file_read", ToolPolicy{
		Allow:           true,
		RequireApproval: true,
		RiskLevel:       RiskLevelLow,
	})

	call := &ToolCall{Name: "file_read"}
	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}

	if dec.Allow {
		t.Error("Overridden file_read should require approval")
	}
}
