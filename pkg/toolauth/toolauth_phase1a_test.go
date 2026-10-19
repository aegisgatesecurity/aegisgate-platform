// Copyright 2025 AegisGate Security
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package toolauth

import (
	"context"
	"testing"
)

// ============================================================================
// MATRIX: AllowedRoles enforcement (Authorize)
// ============================================================================

func TestMatrix_Authorize_AllowedRoles_Deny(t *testing.T) {
	m := NewMatrix()
	m.AddPolicy("file_write", ToolPolicy{
		Allow:        true,
		RiskLevel:    RiskLevelMedium,
		AllowedRoles: []string{"admin", "developer"},
	})

	call := &ToolCall{
		ID:   "1",
		Name: "file_write",
		Role: "restricted",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if dec.Allow {
		t.Error("Authorize() should deny for role 'restricted'")
	}
	if dec.Reason != "role not permitted for this tool" {
		t.Errorf("Authorize() Reason = %q, want %q", dec.Reason, "role not permitted for this tool")
	}
}

func TestMatrix_Authorize_AllowedRoles_Allow(t *testing.T) {
	m := NewMatrix()
	m.AddPolicy("file_write", ToolPolicy{
		Allow:        true,
		RiskLevel:    RiskLevelMedium,
		AllowedRoles: []string{"admin", "developer"},
	})

	call := &ToolCall{
		ID:   "1",
		Name: "file_write",
		Role: "developer",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if !dec.Allow {
		t.Error("Authorize() should allow for role 'developer'")
	}
	if dec.Reason != "allowed by policy" {
		t.Errorf("Authorize() Reason = %q, want %q", dec.Reason, "allowed by policy")
	}
}

func TestMatrix_Authorize_AllowedRoles_AdminMatch(t *testing.T) {
	m := NewMatrix()
	m.AddPolicy("database_query", ToolPolicy{
		Allow:        true,
		RiskLevel:    RiskLevelHigh,
		AllowedRoles: []string{"admin", "developer"},
	})

	call := &ToolCall{
		ID:   "1",
		Name: "database_query",
		Role: "admin",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if !dec.Allow {
		t.Error("Authorize() should allow for role 'admin'")
	}
}

// ============================================================================
// MATRIX: Rule skip paths (MatchTool mismatch, MatchRole mismatch)
// ============================================================================

func TestMatrix_Authorize_RuleSkipToolMismatch(t *testing.T) {
	m := NewMatrix()

	// Rule for a different tool — should be skipped.
	m.AddRule(AuthorizationRule{
		Name:      "other_rule",
		MatchTool: "other_tool",
		Decision:  Decision{Allow: true, Reason: "should not match"},
	})
	// Rule with no tool filter but a role filter that doesn't match — should be skipped.
	m.AddRule(AuthorizationRule{
		Name:      "role_filtered",
		MatchRole: "admin",
		Decision:  Decision{Allow: true, Reason: "should not match either"},
	})
	// Rule that matches — should be returned.
	m.AddRule(AuthorizationRule{
		Name:     "catch_all",
		Decision: Decision{Allow: true, Reason: "catch all matched"},
	})

	call := &ToolCall{
		ID:   "1",
		Name: "special_tool",
		Role: "restricted",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if !dec.Allow {
		t.Error("Authorize() should allow via catch_all rule")
	}
	if dec.Reason != "catch all matched" {
		t.Errorf("Authorize() Reason = %q, want %q", dec.Reason, "catch all matched")
	}
}

func TestMatrix_Authorize_RuleSkipRoleMismatch(t *testing.T) {
	m := NewMatrix()

	// Rule matches tool name but not role — should be skipped.
	m.AddRule(AuthorizationRule{
		Name:      "admin_only_rule",
		MatchTool: "shared_tool",
		MatchRole: "admin",
		Decision:  Decision{Allow: true, Reason: "admin only"},
	})
	// Rule matches tool name and has no role filter — should match.
	m.AddRule(AuthorizationRule{
		Name:      "anyone_rule",
		MatchTool: "shared_tool",
		Decision:  Decision{Allow: true, Reason: "anyone can use"},
	})

	call := &ToolCall{
		ID:   "1",
		Name: "shared_tool",
		Role: "restricted",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if !dec.Allow {
		t.Error("Authorize() should allow via anyone_rule")
	}
	if dec.Reason != "anyone can use" {
		t.Errorf("Authorize() Reason = %q, want %q", dec.Reason, "anyone can use")
	}
}

// ============================================================================
// MATRIX: RequireApproval true but score below threshold → allowed
// ============================================================================

func TestMatrix_Authorize_RequireApproval_BelowThreshold(t *testing.T) {
	m := NewMatrix()
	m.AddPolicy("low_risk_tool", ToolPolicy{
		Allow:           true,
		RequireApproval: true,
		RiskLevel:       RiskLevelCritical, // threshold 90
	})
	// "low_risk_tool" is not in the weight table, so score = 50 (base only).
	// 50 < 90 (Critical threshold) → should be allowed.

	call := &ToolCall{
		ID:   "1",
		Name: "low_risk_tool",
	}

	dec, err := m.Authorize(context.Background(), call)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if !dec.Allow {
		t.Errorf("Authorize() should allow when score (50) < threshold (90); got deny: %s", dec.Reason)
	}
}

// ============================================================================
// CHAIN ANALYZER: AnalyzeChain recon-only branch (OverallRisk = Medium)
// ============================================================================

func TestAnalyzeChain_ReconOnly_OverallRiskMedium(t *testing.T) {
	ca := NewChainAnalyzer()
	// Use two calls with the same risk level so detectEscalationChain returns false.
	// First call is a recon tool (prefix "list") at High risk, second is execute at High risk.
	ca.RecordCall("sess-recon-only", ChainEntry{
		ToolName:  "list_files",
		RiskLevel: RiskLevelHigh,
		DataType:  "read",
	})
	ca.RecordCall("sess-recon-only", ChainEntry{
		ToolName:  "run_payload",
		RiskLevel: RiskLevelHigh,
		DataType:  "execute",
	})
	result := ca.AnalyzeChain("sess-recon-only")
	if !result.ReconChain {
		t.Error("expected recon chain to be detected")
	}
	if result.EscalationChain {
		t.Error("did not expect escalation chain (same-or-lower transitions should not escalate)")
	}
	if result.ExfilChain {
		t.Error("did not expect exfil chain")
	}
	if result.OverallRisk != RiskLevelMedium {
		t.Errorf("expected OverallRisk=Medium for recon-only chain, got %s", result.OverallRisk)
	}
}

// ============================================================================
// CHAIN ANALYZER: AnalyzeChain maxRisk branch (no chain patterns, just risk)
// ============================================================================

func TestAnalyzeChain_NoPattern_OverallRiskMaxRisk(t *testing.T) {
	ca := NewChainAnalyzer()
	// Two calls with same risk level → no escalation, no exfil, no recon.
	ca.RecordCall("sess-nopattern", ChainEntry{
		ToolName:  "random_tool",
		RiskLevel: RiskLevelHigh,
		DataType:  "execute",
	})
	ca.RecordCall("sess-nopattern", ChainEntry{
		ToolName:  "another_tool",
		RiskLevel: RiskLevelHigh,
		DataType:  "execute",
	})
	result := ca.AnalyzeChain("sess-nopattern")
	if result.EscalationChain {
		t.Error("did not expect escalation chain")
	}
	if result.ExfilChain {
		t.Error("did not expect exfil chain")
	}
	if result.ReconChain {
		t.Error("did not expect recon chain")
	}
	if result.OverallRisk != RiskLevelHigh {
		t.Errorf("expected OverallRisk=High (maxRisk), got %s", result.OverallRisk)
	}
}

// ============================================================================
// CHAIN ANALYZER: isReconTool exact match
// ============================================================================

func TestIsReconTool_ExactMatch(t *testing.T) {
	prefixes := []string{"list", "read", "get", "browse", "scan"}
	exact := map[string]bool{
		"get_env":     true,
		"read_config": true,
	}

	if !isReconTool("get_env", prefixes, exact) {
		t.Error("expected 'get_env' to match via exact map")
	}
	if !isReconTool("read_config", prefixes, exact) {
		t.Error("expected 'read_config' to match via exact map")
	}
}

func TestIsReconTool_NoMatch(t *testing.T) {
	prefixes := []string{"list", "scan"}
	exact := map[string]bool{"get_env": true}

	if isReconTool("execute_payload", prefixes, exact) {
		t.Error("expected 'execute_payload' to not match any recon pattern")
	}
}

// ============================================================================
// CHAIN ANALYZER: AnalyzeChain with escalation + critical → OverallRisk Critical
// ============================================================================

func TestAnalyzeChain_EscalationCritical_OverallRiskCritical(t *testing.T) {
	ca := NewChainAnalyzer()
	// Escalating chain ending at Critical — should produce OverallRisk = Critical.
	ca.RecordCall("sess-esc-crit", ChainEntry{
		ToolName:  "tool_a",
		RiskLevel: RiskLevelLow,
		DataType:  "read",
	})
	ca.RecordCall("sess-esc-crit", ChainEntry{
		ToolName:  "tool_b",
		RiskLevel: RiskLevelCritical,
		DataType:  "execute",
	})
	result := ca.AnalyzeChain("sess-esc-crit")
	if !result.EscalationChain {
		t.Error("expected escalation chain")
	}
	if result.OverallRisk != RiskLevelCritical {
		t.Errorf("expected OverallRisk=Critical, got %s", result.OverallRisk)
	}
}

// ============================================================================
// CHAIN ANALYZER: AnalyzeChain flags populated correctly
// ============================================================================

func TestAnalyzeChain_FlagsPopulated(t *testing.T) {
	ca := NewChainAnalyzer()
	// Escalation chain should produce the privilege_escalation_chain flag.
	ca.RecordCall("sess-flags", ChainEntry{
		ToolName:  "a",
		RiskLevel: RiskLevelLow,
		DataType:  "read",
	})
	ca.RecordCall("sess-flags", ChainEntry{
		ToolName:  "b",
		RiskLevel: RiskLevelHigh,
		DataType:  "execute",
	})
	result := ca.AnalyzeChain("sess-flags")

	foundEscalation := false
	for _, flag := range result.Flags {
		if flag == "privilege_escalation_chain" {
			foundEscalation = true
		}
	}
	if !foundEscalation {
		t.Errorf("expected 'privilege_escalation_chain' in flags, got %v", result.Flags)
	}
}

// ============================================================================
// CHAIN ANALYZER: Exfil chain flags
// ============================================================================

func TestAnalyzeChain_ExfilFlags(t *testing.T) {
	ca := NewChainAnalyzer()
	ca.RecordCall("sess-exfil-flags", ChainEntry{
		ToolName:  "read_sensitive",
		RiskLevel: RiskLevelMedium,
		DataType:  "read",
	})
	ca.RecordCall("sess-exfil-flags", ChainEntry{
		ToolName:  "write_external",
		RiskLevel: RiskLevelMedium,
		DataType:  "write",
	})
	result := ca.AnalyzeChain("sess-exfil-flags")
	if !result.ExfilChain {
		t.Error("expected exfil chain")
	}

	foundExfil := false
	for _, flag := range result.Flags {
		if flag == "data_exfiltration_chain" {
			foundExfil = true
		}
	}
	if !foundExfil {
		t.Errorf("expected 'data_exfiltration_chain' in flags, got %v", result.Flags)
	}
}

// ============================================================================
// CHAIN ANALYZER: Recon chain flags
// ============================================================================

func TestAnalyzeChain_ReconFlags(t *testing.T) {
	ca := NewChainAnalyzer()
	ca.RecordCall("sess-recon-flags", ChainEntry{
		ToolName:  "list_dir",
		RiskLevel: RiskLevelLow,
		DataType:  "read",
	})
	ca.RecordCall("sess-recon-flags", ChainEntry{
		ToolName:  "run_exploit",
		RiskLevel: RiskLevelHigh,
		DataType:  "execute",
	})
	result := ca.AnalyzeChain("sess-recon-flags")

	foundRecon := false
	for _, flag := range result.Flags {
		if flag == "recon_to_exploit_chain" {
			foundRecon = true
		}
	}
	if !foundRecon {
		t.Errorf("expected 'recon_to_exploit_chain' in flags, got %v", result.Flags)
	}
}
