// Package authorization - Tool authorization for AegisGuard
package authorization

import (
	"context"
)

// ToolPolicy defines authorization rules for a tool
type ToolPolicy struct {
	Allow           bool
	RequireApproval bool
	MaxCallsPerHour int
	RiskLevel       RiskLevel
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

// DefaultPolicies returns default security policies for tools
func DefaultPolicies() map[string]*ToolPolicy {
	return map[string]*ToolPolicy{
		// High-risk tools - denied by default
		"shell_command": {
			Allow:           false,
			RequireApproval: true,
			MaxCallsPerHour: 0,
			RiskLevel:       RiskLevelCritical,
		},
		"code_execute": {
			Allow:           false,
			RequireApproval: true,
			MaxCallsPerHour: 0,
			RiskLevel:       RiskLevelHigh,
		},
		"database_write": {
			Allow:           false,
			RequireApproval: true,
			MaxCallsPerHour: 0,
			RiskLevel:       RiskLevelHigh,
		},

		// Medium-risk tools - require approval
		"file_write": {
			Allow:           true,
			RequireApproval: true,
			MaxCallsPerHour: 100,
			RiskLevel:       RiskLevelMedium,
		},
		"network_call": {
			Allow:           true,
			RequireApproval: true,
			MaxCallsPerHour: 50,
			RiskLevel:       RiskLevelMedium,
		},

		// Low-risk tools - allowed by default
		"file_read": {
			Allow:           true,
			RequireApproval: false,
			MaxCallsPerHour: 500,
			RiskLevel:       RiskLevelLow,
		},
		"web_search": {
			Allow:           true,
			RequireApproval: false,
			MaxCallsPerHour: 100,
			RiskLevel:       RiskLevelLow,
		},
		"code_search": {
			Allow:           true,
			RequireApproval: false,
			MaxCallsPerHour: 200,
			RiskLevel:       RiskLevelLow,
		},
	}
}

// AuthorizationRule defines a general authorization rule
type AuthorizationRule struct {
	Name       string
	MatchTool  string
	MatchRole  string
	Conditions map[string]interface{}
	Decision   AuthorizationDecision
}

// AuthorizationDecision represents an authorization decision
type AuthorizationDecision struct {
	Allow       bool
	Reason      string
	RiskScore   int
	MatchedRule string
}

// PolicyRule represents a single security rule
type PolicyRule struct {
	ID          string
	Name        string
	Description string
	Condition   RuleCondition
	Action      RuleAction
	Priority    int
	Enabled     bool
}

// RuleCondition defines when a rule applies
type RuleCondition struct {
	ToolNames   []string
	RiskAbove   int
	SessionTags map[string]string
	AgentIDs    []string
}

// RuleAction defines what happens when a rule matches
type RuleAction struct {
	Allow          bool
	DenyReason     string
	LogLevel       string
	NotifyChannels []string
	RiskModifier   int
}

// CommonRules returns a set of common security rules
func CommonRules() []PolicyRule {
	return []PolicyRule{
		{
			ID:          "block-shell",
			Name:        "Block Shell Commands",
			Description: "Block direct shell command execution",
			Condition: RuleCondition{
				ToolNames: []string{"shell", "bash", "exec", "cmd"},
			},
			Action: RuleAction{
				Allow:      false,
				DenyReason: "Shell commands are not allowed",
				LogLevel:   "warn",
			},
			Priority: 100,
			Enabled:  true,
		},
		{
			ID:          "block-file-delete",
			Name:        "Block File Deletion",
			Description: "Block file deletion operations",
			Condition: RuleCondition{
				ToolNames: []string{"file_delete", "rm", "unlink"},
			},
			Action: RuleAction{
				Allow:      false,
				DenyReason: "File deletion requires approval",
				LogLevel:   "warn",
			},
			Priority: 90,
			Enabled:  true,
		},
		{
			ID:          "high-risk-alert",
			Name:        "High Risk Alert",
			Description: "Alert on high-risk operations",
			Condition: RuleCondition{
				RiskAbove: 70,
			},
			Action: RuleAction{
				Allow:          true,
				LogLevel:       "alert",
				NotifyChannels: []string{"security"},
				RiskModifier:   10,
			},
			Priority: 80,
			Enabled:  true,
		},
	}
}

// ToolCallRequest represents a tool call for authorization
type ToolCallRequest struct {
	ID         string
	Name       string
	Parameters map[string]interface{}
	SessionID  string
	AgentID    string
}

// Authorizer evaluates authorization for tool calls
type Authorizer struct {
	policies map[string]*ToolPolicy
	rules    []AuthorizationRule
}

// NewAuthorizer creates a new authorizer with default policies
func NewAuthorizer() *Authorizer {
	policies := DefaultPolicies()
	return &Authorizer{
		policies: policies,
		rules:    make([]AuthorizationRule, 0),
	}
}

// AddPolicy adds a tool policy
func (a *Authorizer) AddPolicy(toolName string, policy *ToolPolicy) {
	a.policies[toolName] = policy
}

// AddRule adds an authorization rule
func (a *Authorizer) AddRule(rule AuthorizationRule) {
	a.rules = append(a.rules, rule)
}

// Authorize evaluates authorization for a tool call
func (a *Authorizer) Authorize(ctx context.Context, call *ToolCallRequest) (*AuthorizationDecision, error) {
	// Check specific tool policy
	if policy, ok := a.policies[call.Name]; ok {
		if !policy.Allow {
			return &AuthorizationDecision{
				Allow:     false,
				Reason:    "Tool explicitly denied by policy",
				RiskScore: int(policy.RiskLevel) * 20,
			}, nil
		}

		return &AuthorizationDecision{
			Allow:     true,
			Reason:    "Allowed by policy",
			RiskScore: calculateRiskScore(call),
		}, nil
	}

	// Check rules
	for _, rule := range a.rules {
		if rule.MatchTool != "" && rule.MatchTool != call.Name {
			continue
		}

		return &AuthorizationDecision{
			Allow:       rule.Decision.Allow,
			Reason:      rule.Decision.Reason,
			RiskScore:   rule.Decision.RiskScore,
			MatchedRule: rule.Name,
		}, nil
	}

	// Default deny
	return &AuthorizationDecision{
		Allow:     false,
		Reason:    "No matching policy found",
		RiskScore: 100,
	}, nil
}

// calculateRiskScore calculates the risk score for a tool call
func calculateRiskScore(call *ToolCallRequest) int {
	// Base score
	score := 50

	// Tool-specific weights
	toolWeights := map[string]int{
		"file_write":    80,
		"file_read":     30,
		"network_call":  60,
		"code_execute":  90,
		"database":      70,
		"shell_command": 95,
	}

	if weight, ok := toolWeights[call.Name]; ok {
		score += weight
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
