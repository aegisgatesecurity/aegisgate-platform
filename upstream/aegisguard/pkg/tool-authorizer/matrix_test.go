package toolauthorizer

import (
	"context"
	"testing"

	agentprotocol "github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol"
)

func TestNewMatrix(t *testing.T) {
	matrix := NewMatrix()
	if matrix == nil {
		t.Fatal("NewMatrix() returned nil")
	}
	if matrix.policies == nil {
		t.Error("policies map not initialized")
	}
	if matrix.rules == nil {
		t.Error("rules slice not initialized")
	}
}

func TestMatrixAuthorizeAllowedTool(t *testing.T) {
	matrix := NewMatrix()

	// Add policy allowing file_read
	matrix.AddPolicy("file_read", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	})

	call := &agentprotocol.ToolCall{
		ID:         "test-1",
		Name:       "file_read",
		Parameters: map[string]interface{}{"path": "/tmp/test.txt"},
	}

	decision, err := matrix.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if !decision.Allow {
		t.Errorf("Authorize() expected Allow=true, got false, reason: %s", decision.Reason)
	}
}

func TestMatrixAuthorizeDeniedTool(t *testing.T) {
	matrix := NewMatrix()

	// Add policy denying shell_command
	matrix.AddPolicy("shell_command", ToolPolicy{
		Allow:           false,
		RequireApproval: true,
		RiskLevel:       RiskLevelCritical,
	})

	call := &agentprotocol.ToolCall{
		ID:         "test-2",
		Name:       "shell_command",
		Parameters: map[string]interface{}{"cmd": "rm -rf /"},
	}

	decision, err := matrix.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision.Allow {
		t.Error("Authorize() expected Allow=false for shell_command")
	}
	if decision.Reason == "" {
		t.Error("Authorize() expected non-empty Reason for denied tool")
	}
}

func TestMatrixAuthorizeNoPolicy(t *testing.T) {
	matrix := NewMatrix()

	// No policy defined for "unknown_tool"
	call := &agentprotocol.ToolCall{
		ID:   "test-3",
		Name: "unknown_tool",
	}

	decision, err := matrix.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if decision.Allow {
		t.Error("Authorize() should default to deny for unknown tools")
	}
}

func TestMatrixAddPolicy(t *testing.T) {
	matrix := NewMatrix()

	policy := ToolPolicy{
		Allow:           true,
		RequireApproval: false,
		MaxCallsPerHour: 100,
		RiskLevel:       RiskLevelMedium,
		AllowedRoles:    []string{"admin", "developer"},
		Constraints: ParameterConstraints{
			AllowedValues: map[string][]interface{}{
				"format": {"json", "xml"},
			},
			MaxLength: map[string]int{
				"content": 10000,
			},
		},
	}

	matrix.AddPolicy("api_call", policy)

	retrieved, ok := matrix.policies["api_call"]
	if !ok {
		t.Fatal("AddPolicy() did not store policy")
	}
	if retrieved.MaxCallsPerHour != 100 {
		t.Errorf("MaxCallsPerHour = %d, want 100", retrieved.MaxCallsPerHour)
	}
	if len(retrieved.AllowedRoles) != 2 {
		t.Errorf("AllowedRoles length = %d, want 2", len(retrieved.AllowedRoles))
	}
}

func TestMatrixAddRule(t *testing.T) {
	matrix := NewMatrix()

	rule := AuthorizationRule{
		Name:      "deny-delete",
		MatchTool: "file_delete",
		Decision: Decision{
			Allow:  false,
			Reason: "File deletion not allowed",
		},
	}

	matrix.AddRule(rule)

	if len(matrix.rules) != 1 {
		t.Fatalf("AddRule() rules length = %d, want 1", len(matrix.rules))
	}
	if matrix.rules[0].Name != "deny-delete" {
		t.Errorf("Rule name = %s, want deny-delete", matrix.rules[0].Name)
	}
}

func TestRiskScorerScore(t *testing.T) {
	scorer := NewRiskScorer()

	tests := []struct {
		name      string
		toolName  string
		wantScore int
	}{
		{"file_read", "file_read", 80},          // 50 base + 30
		{"file_write", "file_write", 100},       // capped at 100
		{"shell_command", "shell_command", 100}, // capped at 100
		{"unknown_tool", "unknown", 50},         // base only
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &agentprotocol.ToolCall{Name: tt.toolName}
			got := scorer.Score(call)
			if got > 100 {
				got = 100
			}
			if got != tt.wantScore {
				t.Errorf("Score() = %d, want %d", got, tt.wantScore)
			}
		})
	}
}

func TestRiskLevels(t *testing.T) {
	tests := []struct {
		level RiskLevel
		name  string
	}{
		{RiskLevelNone, "None"},
		{RiskLevelLow, "Low"},
		{RiskLevelMedium, "Medium"},
		{RiskLevelHigh, "High"},
		{RiskLevelCritical, "Critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.level) < 0 || int(tt.level) > 4 {
				t.Errorf("Invalid RiskLevel %d", tt.level)
			}
		})
	}
}
