// Package policy - Policy engine for agent security rules
// Evaluates security policies against agent actions
package policy

import (
	"context"
	"regexp"
)

// Engine evaluates security policies
type Engine struct {
	rules    []Rule
	policies map[string]*Policy
}

// Rule represents a single security rule
type Rule struct {
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
	ToolNames     []string
	RiskAbove     int
	SessionTags   map[string]string
	AgentIDs      []string
	TimeWindows   []TimeWindow
	CustomMatcher func(context.Context, *EvaluationContext) bool
}

// TimeWindow defines a time-based condition
type TimeWindow struct {
	Start string // HH:MM format
	End   string
	Days  []int // 0=Sunday, 6=Saturday
}

// RuleAction defines what happens when a rule matches
type RuleAction struct {
	Allow          bool
	DenyReason     string
	LogLevel       string
	NotifyChannels []string
	AddTags        map[string]string
	RiskModifier   int
}

// Policy is a collection of rules
type Policy struct {
	ID          string
	Name        string
	Description string
	Version     string
	Rules       []Rule
	Enabled     bool
}

// EvaluationContext contains context for policy evaluation
type EvaluationContext struct {
	ToolName  string
	SessionID string
	AgentID   string
	RiskScore int
	Tags      map[string]string
	Timestamp interface{}
}

// Decision represents the result of policy evaluation
type Decision struct {
	Allowed      bool
	Reason       string
	MatchedRules []string
	ModifiedRisk int
}

// NewEngine creates a new policy engine
func NewEngine() *Engine {
	return &Engine{
		rules:    make([]Rule, 0),
		policies: make(map[string]*Policy),
	}
}

// AddRule adds a rule to the engine
func (e *Engine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

// AddPolicy adds a policy to the engine
func (e *Engine) AddPolicy(policy Policy) {
	e.policies[policy.ID] = &policy
}

// Evaluate evaluates all applicable rules and returns a decision
func (e *Engine) Evaluate(ctx context.Context, evalCtx *EvaluationContext) Decision {
	matchedRules := make([]string, 0)
	modifiedRisk := 0
	allow := true
	reason := "allowed by default"

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if e.matchesCondition(ctx, &rule.Condition, evalCtx) {
			matchedRules = append(matchedRules, rule.ID)

			if !rule.Action.Allow {
				allow = false
				reason = rule.Action.DenyReason
			}

			modifiedRisk += rule.Action.RiskModifier
		}
	}

	return Decision{
		Allowed:      allow,
		Reason:       reason,
		MatchedRules: matchedRules,
		ModifiedRisk: modifiedRisk,
	}
}

// matchesCondition checks if an evaluation context matches a rule condition
func (e *Engine) matchesCondition(ctx context.Context, cond *RuleCondition, evalCtx *EvaluationContext) bool {
	// Check tool names
	if len(cond.ToolNames) > 0 {
		found := false
		for _, name := range cond.ToolNames {
			if name == evalCtx.ToolName || name == "*" {
				found = true
				break
			}
			// Support wildcards
			if matched, _ := regexp.MatchString(name, evalCtx.ToolName); matched {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check risk score
	if cond.RiskAbove > 0 && evalCtx.RiskScore <= cond.RiskAbove {
		return false
	}

	// Check agent IDs
	if len(cond.AgentIDs) > 0 {
		found := false
		for _, id := range cond.AgentIDs {
			if id == evalCtx.AgentID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check session tags
	for k, v := range cond.SessionTags {
		if evalCtx.Tags == nil {
			return false
		}
		if evalCtx.Tags[k] != v {
			return false
		}
	}

	// Check custom matcher
	if cond.CustomMatcher != nil {
		return cond.CustomMatcher(ctx, evalCtx)
	}

	return true
}

// LoadPolicy loads a policy from YAML/JSON
func (e *Engine) LoadPolicy(policy *Policy) error {
	for i := range policy.Rules {
		policy.Rules[i].Enabled = true
	}
	e.policies[policy.ID] = policy
	e.rules = append(e.rules, policy.Rules...)
	return nil
}

// GetPolicy retrieves a policy by ID
func (e *Engine) GetPolicy(id string) (*Policy, bool) {
	p, ok := e.policies[id]
	return p, ok
}

// DeletePolicy removes a policy from the engine
func (e *Engine) DeletePolicy(id string) error {
	if _, ok := e.policies[id]; !ok {
		return ErrPolicyNotFound
	}

	// Remove rules associated with this policy
	policy := e.policies[id]
	e.rules = filterRules(e.rules, policy.Rules)

	delete(e.policies, id)
	return nil
}

// ListPolicies returns all policy IDs
func (e *Engine) ListPolicies() []string {
	ids := make([]string, 0, len(e.policies))
	for id := range e.policies {
		ids = append(ids, id)
	}
	return ids
}

// filterRules removes rules belonging to a specific policy
func filterRules(allRules []Rule, policyRules []Rule) []Rule {
	policyRuleIDs := make(map[string]bool)
	for _, r := range policyRules {
		policyRuleIDs[r.ID] = true
	}

	result := make([]Rule, 0)
	for _, r := range allRules {
		if !policyRuleIDs[r.ID] {
			result = append(result, r)
		}
	}
	return result
}

// DisableRule disables a rule
func (e *Engine) DisableRule(ruleID string) {
	for i := range e.rules {
		if e.rules[i].ID == ruleID {
			e.rules[i].Enabled = false
		}
	}
}

// EnableRule enables a rule
func (e *Engine) EnableRule(ruleID string) {
	for i := range e.rules {
		if e.rules[i].ID == ruleID {
			e.rules[i].Enabled = true
		}
	}
}

// CommonRules returns a set of common security rules
func CommonRules() []Rule {
	return []Rule{
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

// PolicyError represents a policy-related error
type PolicyError struct {
	message string
}

func (e *PolicyError) Error() string {
	return e.message
}

// Errors
var (
	ErrPolicyNotFound = &PolicyError{"policy not found"}
)
