package agentregistry

import (
	"context"
	"fmt"
	"log/slog"
)

// PolicyActionExecutor is the interface for executing policy actions.
// The Registry or main.go wires this to the real incident engine and
// SOAR manager. Tests inject mock implementations.
type PolicyActionExecutor interface {
	// Notify sends a notification via SOAR (PagerDuty, Jira, etc.).
	Notify(ctx context.Context, agentID string, action PolicyAction) error
	// TriggerPlaybook fires an incident playbook by ID.
	TriggerPlaybook(ctx context.Context, agentID, playbookID string, params map[string]string) error
	// Quarantine invalidates all sessions for the agent and blocks new ones.
	Quarantine(ctx context.Context, agentID string) error
	// Revoke disables the agent and invalidates all sessions.
	Revoke(ctx context.Context, agentID string) error
	// Tag adds a tag to the agent record.
	Tag(ctx context.Context, agentID string, key, value string) error
}

// PolicyEngine evaluates lifecycle policies against the current registry
// and executes actions when thresholds are crossed. It uses the
// DormancyEngine to evaluate agent state and the PolicyActionExecutor
// to carry out actions.
type PolicyEngine struct {
	registry   *Registry
	dormancy   *DormancyEngine
	executor   PolicyActionExecutor
	policyStore LifecyclePolicyStore
	logger     *slog.Logger
}

// NewPolicyEngine creates a new PolicyEngine.
func NewPolicyEngine(
	registry *Registry,
	dormancy *DormancyEngine,
	executor PolicyActionExecutor,
	policyStore LifecyclePolicyStore,
	logger *slog.Logger,
) *PolicyEngine {
	if logger == nil {
		logger = slog.Default().With("component", "policy-engine")
	}
	return &PolicyEngine{
		registry:   registry,
		dormancy:   dormancy,
		executor:   executor,
		policyStore: policyStore,
		logger:     logger,
	}
}

// Enforce evaluates all enabled policies against the current registry
// and executes actions for any threshold violations. Returns a list of
// results describing what was executed.
func (p *PolicyEngine) Enforce(ctx context.Context) ([]PolicyEnforcementResult, error) {
	policies, err := p.policyStore.ListPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: enforce: list policies: %w", err)
	}

	records, err := p.registry.List(nil)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: enforce: list records: %w", err)
	}

	var results []PolicyEnforcementResult

	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		for _, record := range records {
			if !policyMatches(record, policy) {
				continue
			}

			recommended, _ := p.dormancy.Evaluate(record, policy)
			if recommended == record.Status {
				continue // No transition needed
			}

			actions := actionsForTransition(record.Status, recommended, policy)
			for _, action := range actions {
				result := p.executeAction(ctx, record, policy, action)
				results = append(results, result)
			}

			// Transition the agent's status
			if err := p.registry.Transition(record.ID, recommended, "policy:"+policy.ID); err != nil {
				p.logger.Warn("agentregistry: enforce: transition failed",
					"agent_id", record.ID, "status", recommended, "error", err)
				results = append(results, PolicyEnforcementResult{
					PolicyID:  policy.ID,
					AgentID:   record.ID,
					Status:    "failed",
					Error:     err.Error(),
					Timestamp: nowFunc(),
				})
			}
		}
	}

	p.logger.Info("agentregistry: enforcement complete",
		"policies_evaluated", len(policies),
		"actions_executed", len(results))

	return results, nil
}

// AddPolicy adds or updates a lifecycle policy.
func (p *PolicyEngine) AddPolicy(ctx context.Context, policy *LifecyclePolicy) error {
	return p.policyStore.UpsertPolicy(ctx, policy)
}

// RemovePolicy removes a policy by ID.
func (p *PolicyEngine) RemovePolicy(ctx context.Context, policyID string) error {
	return p.policyStore.DeletePolicy(ctx, policyID)
}

// ListPolicies returns all configured policies.
func (p *PolicyEngine) ListPolicies(ctx context.Context) ([]*LifecyclePolicy, error) {
	return p.policyStore.ListPolicies(ctx)
}

// executeAction executes a single policy action and returns the result.
func (p *PolicyEngine) executeAction(ctx context.Context, record *AgentRecord, policy *LifecyclePolicy, action PolicyAction) PolicyEnforcementResult {
	now := nowFunc()
	result := PolicyEnforcementResult{
		PolicyID:  policy.ID,
		AgentID:   record.ID,
		Action:    action,
		Timestamp: now,
	}

	var err error
	switch action.Type {
	case "notify":
		err = p.executor.Notify(ctx, record.ID, action)
	case "playbook":
		err = p.executor.TriggerPlaybook(ctx, record.ID, action.Target, action.Params)
	case "quarantine":
		err = p.executor.Quarantine(ctx, record.ID)
	case "revoke":
		err = p.executor.Revoke(ctx, record.ID)
	case "tag":
		key, value := parseTagTarget(action.Target)
		err = p.executor.Tag(ctx, record.ID, key, value)
	default:
		err = fmt.Errorf("unknown action type: %s", action.Type)
	}

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		p.logger.Warn("agentregistry: action failed",
			"agent_id", record.ID, "action", action.Type, "error", err)
	} else {
		result.Status = "executed"
	}

	return result
}

// policyMatches checks if a record matches the policy's filters.
func policyMatches(record *AgentRecord, policy *LifecyclePolicy) bool {
	if policy.Filters == nil {
		return true
	}
	f := policy.Filters

	if len(f.Protocols) > 0 {
		matched := false
		for _, proto := range f.Protocols {
			if hasProtocol(record.Protocols, proto) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(f.Roles) > 0 {
		matched := false
		for _, role := range f.Roles {
			if record.Role == role {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(f.Tags) > 0 {
		for k, v := range f.Tags {
			if record.Tags[k] != v {
				return false
			}
		}
	}

	if len(f.TenantIDs) > 0 {
		matched := false
		for _, tid := range f.TenantIDs {
			if record.TenantID == tid {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// actionsForTransition returns the actions to execute for a given
// status transition based on the policy's configured action lists.
func actionsForTransition(oldStatus, newStatus AgentStatus, policy *LifecyclePolicy) []PolicyAction {
	switch newStatus {
	case StatusDormant:
		return policy.OnDormant
	case StatusQuarantined:
		return policy.OnQuarantine
	case StatusRevoked:
		return policy.OnRevoke
	default:
		return nil
	}
}

// parseTagTarget parses a "key=value" tag target string.
func parseTagTarget(target string) (string, string) {
	for i, c := range target {
		if c == '=' {
			return target[:i], target[i+1:]
		}
	}
	return target, ""
}