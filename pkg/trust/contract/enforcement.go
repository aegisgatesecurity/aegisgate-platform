// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Contract Enforcement

package contract

import (
	"context"
	"fmt"
	"time"
)

type EnforcementDecision string

const (
	DecisionAllow           EnforcementDecision = "allow"
	DecisionDeny            EnforcementDecision = "deny"
	DecisionRequireApproval EnforcementDecision = "require_approval"
	DecisionRateLimited     EnforcementDecision = "rate_limited"
	DecisionExpired         EnforcementDecision = "expired"
)

type EnforcementContext struct {
	AgentID      string
	ContractID   string
	Capability   Capability
	ResourceType string
	ResourceID   string
	RequesterID  string
	Timestamp    time.Time
	Metadata     map[string]string
}

type EnforcementResult struct {
	Decision     EnforcementDecision
	Reason       string
	Contract     *CapabilityContract
	RequiredAppr *string
	ExpiresAt    *time.Time
}

type Enforcer interface {
	Enforce(ctx context.Context, ec *EnforcementContext) (*EnforcementResult, error)
	EnforceMultiple(ctx context.Context, ec *EnforcementContext, caps []Capability) (*EnforcementResult, error)
}

type DefaultEnforcer struct {
	registry  ContractRegistry
	rateLimit RateLimiter
}

type ContractRegistry interface {
	Get(ctx context.Context, contractID string) (*CapabilityContract, error)
	GetByAgent(ctx context.Context, agentID string) (*CapabilityContract, error)
	ListByOwner(ctx context.Context, ownerID string) ([]*CapabilityContract, error)
}

type RateLimiter interface {
	Check(contractID string, capability Capability) (bool, error)
	Record(contractID string, capability Capability) error
}

func NewEnforcer(registry ContractRegistry, rateLimit RateLimiter) Enforcer {
	return &DefaultEnforcer{registry: registry, rateLimit: rateLimit}
}

func (e *DefaultEnforcer) Enforce(ctx context.Context, ec *EnforcementContext) (*EnforcementResult, error) {
	if ec.ContractID == "" && ec.AgentID == "" {
		return &EnforcementResult{Decision: DecisionDeny, Reason: "no contract or agent specified"}, nil
	}

	var contract *CapabilityContract
	var err error

	if ec.ContractID != "" {
		contract, err = e.registry.Get(ctx, ec.ContractID)
	} else {
		contract, err = e.registry.GetByAgent(ctx, ec.AgentID)
	}

	if err != nil {
		return &EnforcementResult{Decision: DecisionDeny, Reason: fmt.Sprintf("contract not found: %v", err)}, nil
	}

	return e.evaluateContract(ctx, contract, ec)
}

func (e *DefaultEnforcer) EnforceMultiple(ctx context.Context, ec *EnforcementContext, caps []Capability) (*EnforcementResult, error) {
	for i := range caps {
		ecCopy := *ec
		ecCopy.Capability = caps[i]
		result, err := e.Enforce(ctx, &ecCopy)
		if err != nil {
			return result, err
		}
		if result.Decision != DecisionAllow {
			return result, nil
		}
	}
	return &EnforcementResult{Decision: DecisionAllow, Reason: "all capabilities allowed"}, nil
}

func (e *DefaultEnforcer) evaluateContract(ctx context.Context, contract *CapabilityContract, ec *EnforcementContext) (*EnforcementResult, error) {
	if !contract.CanVerify() {
		decision := DecisionExpired
		reason := "contract is not active"
		switch contract.Status {
		case ContractStatusSuspended:
			reason = "contract is suspended"
		case ContractStatusRevoked:
			reason = "contract is revoked"
		}
		return &EnforcementResult{Decision: decision, Reason: reason, Contract: contract}, nil
	}

	var matchedRule *ContractRule
	for i := range contract.Rules {
		rule := &contract.Rules[i]
		if rule.Capability == ec.Capability || rule.Capability == CapAdmin {
			matchedRule = rule
			break
		}
	}

	if matchedRule == nil {
		return &EnforcementResult{Decision: DecisionDeny, Reason: fmt.Sprintf("capability %s not granted", ec.Capability), Contract: contract}, nil
	}

	if matchedRule.MaxPerHour > 0 && e.rateLimit != nil {
		allowed, err := e.rateLimit.Check(contract.ID, ec.Capability)
		if err == nil && !allowed {
			return &EnforcementResult{Decision: DecisionRateLimited, Reason: fmt.Sprintf("rate limit exceeded for %s (%d/hour)", ec.Capability, matchedRule.MaxPerHour), Contract: contract}, nil
		}
	}

	if matchedRule.RequiresAppr {
		capStr := string(ec.Capability)
		return &EnforcementResult{Decision: DecisionRequireApproval, Reason: fmt.Sprintf("capability %s requires approval", ec.Capability), Contract: contract, RequiredAppr: &capStr}, nil
	}

	for _, cond := range matchedRule.Conditions {
		if !e.evaluateCondition(cond, ec) {
			return &EnforcementResult{Decision: DecisionDeny, Reason: fmt.Sprintf("condition not met: %s", cond.Key), Contract: contract}, nil
		}
	}

	if matchedRule.ExpiresAt != nil && time.Now().After(*matchedRule.ExpiresAt) {
		return &EnforcementResult{Decision: DecisionExpired, Reason: "rule has expired", Contract: contract}, nil
	}

	return &EnforcementResult{Decision: DecisionAllow, Reason: "capability allowed", Contract: contract}, nil
}

func (e *DefaultEnforcer) evaluateCondition(cond Condition, ec *EnforcementContext) bool {
	switch cond.Type {
	case "time":
		return e.evaluateTimeCondition(cond)
	case "context":
		return e.evaluateContextCondition(cond, ec)
	default:
		return true
	}
}

func (e *DefaultEnforcer) evaluateTimeCondition(cond Condition) bool {
	now := time.Now()
	if cond.Operator == "between" {
		// First check if Value is a map
		valueMap, isMap := cond.Value.(map[string]interface{})
		if !isMap {
			return true // Be permissive on type error
		}
		startVal, ok1 := valueMap["start"].(string)
		endVal, ok2 := valueMap["end"].(string)
		if !ok1 || !ok2 {
			return true
		}
		startTime, err1 := time.Parse("15:04", startVal)
		endTime, err2 := time.Parse("15:04", endVal)
		if err1 != nil || err2 != nil {
			return true
		}
		currentMins := now.Hour()*60 + now.Minute()
		startMins := startTime.Hour()*60 + startTime.Minute()
		endMins := endTime.Hour()*60 + endTime.Minute()
		return currentMins >= startMins && currentMins <= endMins
	}
	return true
}

func (e *DefaultEnforcer) evaluateContextCondition(cond Condition, ec *EnforcementContext) bool {
	if ec.Metadata == nil {
		return cond.Operator == "not_in" || cond.Value == nil
	}
	val, exists := ec.Metadata[cond.Key]
	if !exists {
		return cond.Operator == "not_in" || cond.Value == nil
	}
	switch cond.Operator {
	case "eq":
		return val == cond.Value
	case "ne":
		return val != cond.Value
	case "in":
		if arr, ok := cond.Value.([]string); ok {
			for _, item := range arr {
				if item == val {
					return true
				}
			}
			return false
		}
		return false
	case "not_in":
		if arr, ok := cond.Value.([]string); ok {
			for _, item := range arr {
				if item == val {
					return false
				}
			}
			return true
		}
		return true
	default:
		return true
	}
}

func (e *DefaultEnforcer) RecordUsage(contractID string, cap Capability) error {
	if e.rateLimit == nil {
		return nil
	}
	return e.rateLimit.Record(contractID, cap)
}
