// Package toolauthorizer - Tool call authorization and permission matrix
package toolauthorizer

import (
	"context"

	"github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol"
)

// Matrix manages the authorization policies for tool calls
type Matrix struct {
	policies   map[string]ToolPolicy
	rules      []AuthorizationRule
	riskScorer *RiskScorer
}

// ToolPolicy defines authorization rules for a specific tool
type ToolPolicy struct {
	Allow           bool
	RequireApproval bool
	MaxCallsPerHour int
	RiskLevel       RiskLevel
	Constraints     ParameterConstraints
	AllowedRoles    []string
}

// ParameterConstraints defines constraints on tool parameters
type ParameterConstraints struct {
	AllowedValues map[string][]interface{}
	MaxLength     map[string]int
	Patterns      map[string]string
}

// RiskLevel represents the risk level of a tool
type RiskLevel int

const (
	RiskLevelNone RiskLevel = iota
	RiskLevelLow
	RiskLevelMedium
	RiskLevelHigh
	RiskLevelCritical
)

// AuthorizationRule defines a general authorization rule
type AuthorizationRule struct {
	Name       string
	MatchTool  string
	MatchRole  string
	Conditions map[string]interface{}
	Decision   Decision
}

// Decision represents the result of an authorization check
type Decision struct {
	Allow       bool
	Reason      string
	RiskScore   int
	MatchedRule string
}

// NewMatrix creates a new authorization matrix
func NewMatrix() *Matrix {
	return &Matrix{
		policies:   make(map[string]ToolPolicy),
		rules:      make([]AuthorizationRule, 0),
		riskScorer: NewRiskScorer(),
	}
}

// Authorize evaluates an authorization decision for a tool call
func (m *Matrix) Authorize(ctx context.Context, call *agentprotocol.ToolCall) (Decision, error) {
	// Check specific tool policy
	if policy, ok := m.policies[call.Name]; ok {
		if !policy.Allow {
			return Decision{
				Allow:     false,
				Reason:    "Tool explicitly denied by policy",
				RiskScore: 0,
			}, nil
		}

		// Calculate risk score
		riskScore := m.riskScorer.Score(call)

		// Check if approval is required
		if policy.RequireApproval && riskScore >= int(policy.RiskLevel) {
			return Decision{
				Allow:     false,
				Reason:    "Tool requires human approval",
				RiskScore: riskScore,
			}, nil
		}

		return Decision{
			Allow:     true,
			Reason:    "Allowed by policy",
			RiskScore: riskScore,
		}, nil
	}

	// Default: check rules
	for _, rule := range m.rules {
		if rule.MatchTool != "" && rule.MatchTool != call.Name {
			continue
		}

		decision := m.evaluateRule(ctx, rule, call)
		if decision.Allow || decision.Reason != "" {
			return decision, nil
		}
	}

	// Default deny
	return Decision{
		Allow:     false,
		Reason:    "No matching policy found",
		RiskScore: 100,
	}, nil
}

// evaluateRule checks if a rule matches and returns a decision
func (m *Matrix) evaluateRule(ctx context.Context, rule AuthorizationRule, call *agentprotocol.ToolCall) Decision {
	return Decision{
		Allow:       false,
		Reason:      "Rule did not match",
		RiskScore:   0,
		MatchedRule: rule.Name,
	}
}

// AddPolicy adds a tool policy to the matrix
func (m *Matrix) AddPolicy(toolName string, policy ToolPolicy) {
	m.policies[toolName] = policy
}

// AddRule adds an authorization rule
func (m *Matrix) AddRule(rule AuthorizationRule) {
	m.rules = append(m.rules, rule)
}

// RiskScorer calculates risk scores for tool calls
type RiskScorer struct {
	weights map[string]int
}

// NewRiskScorer creates a new risk scorer
func NewRiskScorer() *RiskScorer {
	return &RiskScorer{
		weights: map[string]int{
			"file_write":    80,
			"file_read":     30,
			"network_call":  60,
			"code_execute":  90,
			"database":      70,
			"shell_command": 95,
		},
	}
}

// Score calculates the risk score for a tool call
func (s *RiskScorer) Score(call *agentprotocol.ToolCall) int {
	score := 50 // Base score

	if weight, ok := s.weights[call.Name]; ok {
		score += weight
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
