// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026, AegisGate Security - All rights reserved

package contract

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvaluateCondition_TimeUnknown(t *testing.T) {
	e := &DefaultEnforcer{}

	// Test unknown operator - should be permissive
	cond := Condition{
		Type:     "time",
		Operator: "unknown",
		Key:      "work_hours",
		Value:    "invalid",
	}

	result := e.evaluateCondition(cond, &EnforcementContext{})
	assert.True(t, result)
}

func TestEvaluateCondition_TimeInvalidValue(t *testing.T) {
	e := &DefaultEnforcer{}

	// Test with string value instead of map - should be permissive
	cond := Condition{
		Type:     "time",
		Operator: "between",
		Key:      "work_hours",
		Value:    "not a map",
	}

	result := e.evaluateCondition(cond, &EnforcementContext{})
	assert.True(t, result)

	// Test with nil value
	cond2 := Condition{
		Type:     "time",
		Operator: "between",
		Key:      "work_hours",
		Value:    nil,
	}

	result2 := e.evaluateCondition(cond2, &EnforcementContext{})
	assert.True(t, result2)
}

func TestEvaluateCondition_Context(t *testing.T) {
	e := &DefaultEnforcer{}

	tests := []struct {
		name     string
		cond     Condition
		ec       *EnforcementContext
		expected bool
	}{
		{name: "eq match", cond: Condition{Type: "context", Operator: "eq", Key: "env", Value: "production"}, ec: &EnforcementContext{Metadata: map[string]string{"env": "production"}}, expected: true},
		{name: "eq no match", cond: Condition{Type: "context", Operator: "eq", Key: "env", Value: "production"}, ec: &EnforcementContext{Metadata: map[string]string{"env": "staging"}}, expected: false},
		{name: "ne match", cond: Condition{Type: "context", Operator: "ne", Key: "env", Value: "production"}, ec: &EnforcementContext{Metadata: map[string]string{"env": "staging"}}, expected: true},
		{name: "in match", cond: Condition{Type: "context", Operator: "in", Key: "region", Value: []string{"us", "eu"}}, ec: &EnforcementContext{Metadata: map[string]string{"region": "us"}}, expected: true},
		{name: "in no match", cond: Condition{Type: "context", Operator: "in", Key: "region", Value: []string{"us", "eu"}}, ec: &EnforcementContext{Metadata: map[string]string{"region": "asia"}}, expected: false},
		{name: "not_in match", cond: Condition{Type: "context", Operator: "not_in", Key: "region", Value: []string{"us", "eu"}}, ec: &EnforcementContext{Metadata: map[string]string{"region": "asia"}}, expected: true},
		{name: "not_in no match", cond: Condition{Type: "context", Operator: "not_in", Key: "region", Value: []string{"us", "eu"}}, ec: &EnforcementContext{Metadata: map[string]string{"region": "us"}}, expected: false},
		{name: "missing key eq", cond: Condition{Type: "context", Operator: "eq", Key: "missing", Value: "test"}, ec: &EnforcementContext{Metadata: map[string]string{}}, expected: false},
		{name: "missing key not_in", cond: Condition{Type: "context", Operator: "not_in", Key: "missing", Value: "test"}, ec: &EnforcementContext{Metadata: map[string]string{}}, expected: true},
		{name: "nil metadata eq", cond: Condition{Type: "context", Operator: "eq", Key: "env", Value: "test"}, ec: &EnforcementContext{Metadata: nil}, expected: false},
		{name: "nil metadata not_in", cond: Condition{Type: "context", Operator: "not_in", Key: "env", Value: "test"}, ec: &EnforcementContext{Metadata: nil}, expected: true},
		{name: "in non-array value", cond: Condition{Type: "context", Operator: "in", Key: "env", Value: "not array"}, ec: &EnforcementContext{Metadata: map[string]string{"env": "test"}}, expected: false},
		{name: "unknown operator", cond: Condition{Type: "context", Operator: "unknown", Key: "env", Value: "test"}, ec: &EnforcementContext{Metadata: map[string]string{"env": "test"}}, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := e.evaluateCondition(tt.cond, tt.ec)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateCondition_UnknownType(t *testing.T) {
	e := &DefaultEnforcer{}
	cond := Condition{Type: "unknown_type", Operator: "eq", Key: "test", Value: "value"}
	result := e.evaluateCondition(cond, &EnforcementContext{})
	assert.True(t, result)
}

func TestRecordUsage_WithRateLimiter(t *testing.T) {
	rateLimiter := NewSimpleRateLimiter()
	e := &DefaultEnforcer{rateLimit: rateLimiter}

	err := e.RecordUsage("contract-1", CapNetHTTP)
	assert.NoError(t, err)

	for i := 0; i < 5; i++ {
		err = e.RecordUsage("contract-1", CapNetHTTP)
		assert.NoError(t, err)
	}
}

func TestRecordUsage_WithoutRateLimiter(t *testing.T) {
	e := &DefaultEnforcer{rateLimit: nil}
	err := e.RecordUsage("any-contract", CapNetHTTP)
	assert.NoError(t, err)
}

func TestEnforce_MultipleCapabilities(t *testing.T) {
	registry := NewInMemoryRegistry()
	e := NewEnforcer(registry, nil)

	c, _ := registry.Create(context.Background(), "Multi Cap Test", "description", "agent-123", "owner-1", []ContractRule{{Capability: CapNetHTTP}, {Capability: CapFileRead}})
	registry.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	ec := &EnforcementContext{ContractID: c.ID, Capability: CapNetHTTP, Metadata: map[string]string{}}
	result, err := e.Enforce(context.Background(), ec)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestEnforce_ContractNotFound(t *testing.T) {
	registry := NewInMemoryRegistry()
	e := NewEnforcer(registry, nil)

	ec := &EnforcementContext{ContractID: "non-existent"}
	result, err := e.Enforce(context.Background(), ec)
	assert.NoError(t, err)
	assert.Equal(t, DecisionDeny, result.Decision)
	assert.Contains(t, result.Reason, "not found")
}

func TestEnforce_NoContractOrAgent(t *testing.T) {
	e := &DefaultEnforcer{}
	ec := &EnforcementContext{}
	result, err := e.Enforce(context.Background(), ec)
	assert.NoError(t, err)
	assert.Equal(t, DecisionDeny, result.Decision)
}

func TestEnforceMultiple_Success(t *testing.T) {
	registry := NewInMemoryRegistry()
	e := NewEnforcer(registry, nil)

	c, _ := registry.Create(context.Background(), "Multi Test", "desc", "agent-multi", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	registry.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	ec := &EnforcementContext{ContractID: c.ID, Metadata: map[string]string{}}
	result, err := e.EnforceMultiple(context.Background(), ec, []Capability{CapNetHTTP, CapFileRead})
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
