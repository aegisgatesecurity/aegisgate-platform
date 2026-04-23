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

// Package toolauth implements the AegisGate Tool Authorization risk matrix.
//
// This module provides a policy-driven authorization engine that evaluates
// tool calls against configured policies and rules. It computes risk scores,
// enforces approval requirements, and produces authorization decisions for
// every tool invocation within the AegisGate platform.
//
// The matrix is a port of the AegisGuard Tool Authorizer risk matrix,
// adapted for the unified AegisGate platform.
package toolauth

import "context"

// RiskLevel represents the severity classification for a tool's potential impact.
type RiskLevel int

const (
	// RiskLevelNone indicates no associated risk.
	RiskLevelNone RiskLevel = iota
	// RiskLevelLow indicates minimal risk; typically safe for unrestricted use.
	RiskLevelLow
	// RiskLevelMedium indicates moderate risk; may require role-based approval.
	RiskLevelMedium
	// RiskLevelHigh indicates significant risk; approval is typically required.
	RiskLevelHigh
	// RiskLevelCritical indicates severe risk; strict approval and constraints apply.
	RiskLevelCritical
)

// String returns a human-readable name for the RiskLevel.
func (r RiskLevel) String() string {
	switch r {
	case RiskLevelNone:
		return "none"
	case RiskLevelLow:
		return "low"
	case RiskLevelMedium:
		return "medium"
	case RiskLevelHigh:
		return "high"
	case RiskLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParameterConstraints defines value-level restrictions that can be enforced on
// tool call parameters. Each map key corresponds to a parameter name.
type ParameterConstraints struct {
	// AllowedValues maps parameter names to the set of permitted values.
	AllowedValues map[string][]interface{}
	// MaxLength maps parameter names to their maximum allowed length.
	MaxLength map[string]int
	// Patterns maps parameter names to regex patterns that values must match.
	Patterns map[string]string
}

// ToolPolicy defines the authorization policy for a specific tool.
type ToolPolicy struct {
	// Allow indicates whether the tool is permitted at all.
	Allow bool
	// RequireApproval indicates that a human must approve invocations
	// when the computed risk score meets or exceeds the policy's RiskLevel threshold.
	RequireApproval bool
	// MaxCallsPerHour limits the number of times this tool may be invoked per hour.
	MaxCallsPerHour int
	// RiskLevel is the severity classification used as the approval threshold.
	RiskLevel RiskLevel
	// AllowedRoles lists the roles permitted to invoke this tool. An empty list
	// means all roles are allowed.
	AllowedRoles []string
	// Constraints holds parameter-level restrictions for this tool.
	Constraints ParameterConstraints
}

// Decision captures the outcome of an authorization evaluation for a single tool call.
type Decision struct {
	// Allow indicates whether the tool call is permitted.
	Allow bool
	// Reason provides a human-readable explanation for the decision.
	Reason string
	// RiskScore is the computed risk score (0–100) for the tool call.
	RiskScore int
	// MatchedRule names the policy or rule that determined this decision.
	MatchedRule string
}

// AuthorizationRule defines a rule-based authorization check. Rules are evaluated
// after specific tool policies and allow fine-grained matching on role and conditions.
type AuthorizationRule struct {
	// Name is the human-readable identifier for this rule.
	Name string
	// MatchTool is a tool name pattern this rule applies to.
	MatchTool string
	// MatchRole is the role this rule applies to. Empty matches all roles.
	MatchRole string
	// Conditions holds additional matching criteria (e.g., parameter values).
	Conditions map[string]interface{}
	// Decision is the outcome when this rule matches.
	Decision Decision
}

// ToolCall represents a single tool invocation request within the AegisGate platform.
// This is a platform-native type and does not depend on external agent-protocol packages.
type ToolCall struct {
	// ID is the unique identifier for this tool call.
	ID string
	// Name is the name of the tool being invoked.
	Name string
	// Parameters contains the arguments passed to the tool.
	Parameters map[string]interface{}
	// AgentID identifies the agent making the call.
	AgentID string
	// SessionID identifies the session in which the call occurs.
	SessionID string
}

// RiskScorer computes a risk score (0–100) for a tool call based on configurable
// per-tool weights. The scoring algorithm starts from a base score of 50 and
// adds the weight associated with the tool name, capping the result at 100.
type RiskScorer struct {
	// weights maps tool names to their risk weight contributions.
	weights map[string]int
}

// Score calculates the risk score for the given tool call.
//
// The algorithm:
//  1. Start with a base score of 50.
//  2. If the tool name has an assigned weight, add it to the base.
//  3. Cap the final score at 100.
func (rs *RiskScorer) Score(call *ToolCall) int {
	const baseScore = 50
	score := baseScore
	if w, ok := rs.weights[call.Name]; ok {
		score += w
	}
	if score > 100 {
		score = 100
	}
	return score
}

// newRiskScorer creates a RiskScorer with the default weight table.
func newRiskScorer() *RiskScorer {
	return &RiskScorer{
		weights: map[string]int{
			"shell_command": 95,
			"bash":          95,
			"code_execute":  90,
			"database":      70,
			"file_write":    80,
			"file_read":     30,
			"network_call":  60,
		},
	}
}

// riskLevelThreshold maps RiskLevels to numeric score thresholds used when
// deciding whether a policy's approval requirement is triggered.
var riskLevelThreshold = map[RiskLevel]int{
	RiskLevelNone:     0,
	RiskLevelLow:      25,
	RiskLevelMedium:   50,
	RiskLevelHigh:     75,
	RiskLevelCritical: 90,
}

// Matrix is the central authorization engine. It evaluates tool calls against
// registered policies, computes risk scores, and produces final decisions.
type Matrix struct {
	// policies maps tool names to their authorization policies.
	policies map[string]ToolPolicy
	// rules holds the ordered list of authorization rules evaluated after policies.
	rules []AuthorizationRule
	// riskScorer computes risk scores for tool calls.
	riskScorer *RiskScorer
}

// NewMatrix creates a new Matrix with empty policies, no rules, and the default
// risk scorer.
func NewMatrix() *Matrix {
	return &Matrix{
		policies:   make(map[string]ToolPolicy),
		rules:      nil,
		riskScorer: newRiskScorer(),
	}
}

// Authorize evaluates the given tool call against the matrix and returns a
// Decision.
//
// Evaluation order:
//  1. Look up a specific tool policy by name.
//  2. If a policy exists and Allow is false → deny immediately.
//  3. Compute the risk score using the RiskScorer.
//  4. If the policy requires approval and the risk score meets or exceeds the
//     policy's RiskLevel threshold → deny with "requires approval" reason.
//  5. Otherwise → allow with the computed risk score.
//  6. If no specific policy matches, fall through to rule evaluation.
//  7. Default: deny with "No matching policy found".
func (m *Matrix) Authorize(ctx context.Context, call *ToolCall) (Decision, error) {
	// Step 1: Check for a specific tool policy.
	if policy, ok := m.policies[call.Name]; ok {
		// Step 2: Explicitly denied.
		if !policy.Allow {
			return Decision{
				Allow:       false,
				Reason:      "tool is not allowed by policy",
				RiskScore:   0,
				MatchedRule: call.Name,
			}, nil
		}

		// Step 3: Compute risk score.
		riskScore := m.riskScorer.Score(call)

		// Step 4: Check approval requirement against risk level threshold.
		if policy.RequireApproval && riskScore >= riskLevelThreshold[policy.RiskLevel] {
			return Decision{
				Allow:       false,
				Reason:      "requires approval",
				RiskScore:   riskScore,
				MatchedRule: call.Name,
			}, nil
		}

		// Step 5: Allow with risk score.
		return Decision{
			Allow:       true,
			Reason:      "allowed by policy",
			RiskScore:   riskScore,
			MatchedRule: call.Name,
		}, nil
	}

	// Step 6: Evaluate authorization rules.
	for _, rule := range m.rules {
		if rule.MatchTool != "" && rule.MatchTool != call.Name {
			continue
		}
		if rule.MatchRole != "" && rule.MatchRole != call.AgentID {
			continue
		}
		return rule.Decision, nil
	}

	// Step 7: Default deny.
	return Decision{
		Allow:       false,
		Reason:      "No matching policy found",
		RiskScore:   0,
		MatchedRule: "",
	}, nil
}

// AddPolicy registers or replaces a tool policy in the matrix.
func (m *Matrix) AddPolicy(toolName string, policy ToolPolicy) {
	m.policies[toolName] = policy
}

// AddRule appends an authorization rule to the matrix.
func (m *Matrix) AddRule(rule AuthorizationRule) {
	m.rules = append(m.rules, rule)
}

// GetRiskLevel returns the RiskLevel for the given tool name by looking up its
// registered policy. Returns RiskLevelNone if no policy exists.
func (m *Matrix) GetRiskLevel(toolName string) RiskLevel {
	if policy, ok := m.policies[toolName]; ok {
		return policy.RiskLevel
	}
	return RiskLevelNone
}

// RegisterDefaultPolicies installs a sensible set of default tool policies for
// common AegisGate platform tools. These defaults balance developer productivity
// with security guardrails.
func (m *Matrix) RegisterDefaultPolicies() {
	// Low-risk file and code inspection tools — no approval required.
	m.AddPolicy("file_read", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	})

	m.AddPolicy("web_search", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	})

	m.AddPolicy("code_search", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	})

	m.AddPolicy("ping", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	})

	m.AddPolicy("git_status", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	})

	m.AddPolicy("git_log", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	})

	m.AddPolicy("git_diff", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelLow,
	})

	// Medium-risk tools — approval for restricted roles.
	m.AddPolicy("file_write", ToolPolicy{
		Allow:        true,
		RiskLevel:    RiskLevelMedium,
		AllowedRoles: []string{"admin", "developer"},
	})

	m.AddPolicy("http_request", ToolPolicy{
		Allow:        true,
		RiskLevel:    RiskLevelMedium,
		AllowedRoles: []string{"admin", "developer"},
	})

	m.AddPolicy("database_query", ToolPolicy{
		Allow:        true,
		RiskLevel:    RiskLevelHigh,
		AllowedRoles: []string{"admin", "developer"},
	})

	m.AddPolicy("process_list", ToolPolicy{
		Allow:     true,
		RiskLevel: RiskLevelMedium,
	})

	// High-risk tools — approval required.
	m.AddPolicy("file_delete", ToolPolicy{
		Allow:           true,
		RequireApproval: true,
		RiskLevel:       RiskLevelHigh,
	})

	// Critical-risk tools — strict approval required.
	m.AddPolicy("shell_command", ToolPolicy{
		Allow:           true,
		RequireApproval: true,
		RiskLevel:       RiskLevelCritical,
	})

	m.AddPolicy("bash", ToolPolicy{
		Allow:           true,
		RequireApproval: true,
		RiskLevel:       RiskLevelCritical,
	})

	m.AddPolicy("code_execute_go", ToolPolicy{
		Allow:           true,
		RequireApproval: true,
		RiskLevel:       RiskLevelCritical,
	})

	m.AddPolicy("code_execute_py", ToolPolicy{
		Allow:           true,
		RequireApproval: true,
		RiskLevel:       RiskLevelCritical,
	})

	m.AddPolicy("code_execute_js", ToolPolicy{
		Allow:           true,
		RequireApproval: true,
		RiskLevel:       RiskLevelCritical,
	})
}
