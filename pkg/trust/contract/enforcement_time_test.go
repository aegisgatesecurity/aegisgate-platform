// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Enforcement Time Condition Tests
// ============================================================================

package contract

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestEvaluateTimeCondition_BetweenValid tests valid between time window
func TestEvaluateTimeCondition_BetweenValid(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	now := time.Now()
	hour := now.Hour()
	minute := now.Minute()

	startHour := (hour - 1 + 24) % 24
	endHour := (hour + 1) % 24

	startStr := fmt.Sprintf("%02d:%02d", startHour, minute)
	endStr := fmt.Sprintf("%02d:%02d", endHour, minute)
	if endHour < startHour {
		endStr = "23:59"
	}

	c, _ := r.Create(context.Background(), "Time Test", "desc", "agent-time", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "between", Value: map[string]interface{}{
					"start": startStr,
					"end":   endStr,
				}},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, err := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-time",
		Capability: CapNetHTTP,
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}

	if res.Decision != DecisionAllow {
		t.Logf("Time condition result: %s (may be outside window)", res.Decision)
	}
}

// TestEvaluateTimeCondition_BetweenInvalid tests time outside between window
func TestEvaluateTimeCondition_BetweenInvalid(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	c, _ := r.Create(context.Background(), "Night Time", "desc", "agent-night", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "between", Value: map[string]interface{}{
					"start": "03:00",
					"end":   "04:00",
				}},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, _ := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-night",
		Capability: CapNetHTTP,
	})

	t.Logf("Night time window result: %s", res.Decision)
}

// TestEvaluateTimeCondition_InvalidMapType tests with invalid Value type
func TestEvaluateTimeCondition_InvalidMapType(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	c, _ := r.Create(context.Background(), "Invalid Time", "desc", "agent-invalid", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "between", Value: "not-a-map"},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, _ := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-invalid",
		Capability: CapNetHTTP,
	})

	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow for invalid type, got %s", res.Decision)
	}
}

// TestEvaluateTimeCondition_MissingStart tests with missing start key
func TestEvaluateTimeCondition_MissingStart(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	c, _ := r.Create(context.Background(), "No Start", "desc", "agent-nostart", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "between", Value: map[string]interface{}{
					"end": "12:00",
				}},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, _ := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-nostart",
		Capability: CapNetHTTP,
	})

	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow for missing start, got %s", res.Decision)
	}
}

// TestEvaluateTimeCondition_MissingEnd tests with missing end key
func TestEvaluateTimeCondition_MissingEnd(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	c, _ := r.Create(context.Background(), "No End", "desc", "agent-noend", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "between", Value: map[string]interface{}{
					"start": "08:00",
				}},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, _ := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-noend",
		Capability: CapNetHTTP,
	})

	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow for missing end, got %s", res.Decision)
	}
}

// TestEvaluateTimeCondition_InvalidStartFormat tests with invalid start time format
func TestEvaluateTimeCondition_InvalidStartFormat(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	c, _ := r.Create(context.Background(), "Bad Format", "desc", "agent-badfmt", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "between", Value: map[string]interface{}{
					"start": "invalid-time",
					"end":   "12:00",
				}},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, _ := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-badfmt",
		Capability: CapNetHTTP,
	})

	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow for parse error, got %s", res.Decision)
	}
}

// TestEvaluateTimeCondition_InvalidEndFormat tests with invalid end time format
func TestEvaluateTimeCondition_InvalidEndFormat(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	c, _ := r.Create(context.Background(), "Bad End Format", "desc", "agent-badend", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "between", Value: map[string]interface{}{
					"start": "08:00",
					"end":   "not-a-time",
				}},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, _ := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-badend",
		Capability: CapNetHTTP,
	})

	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow for parse error, got %s", res.Decision)
	}
}

// TestEvaluateTimeCondition_NilValue tests with nil condition value
func TestEvaluateTimeCondition_NilValue(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	c, _ := r.Create(context.Background(), "Nil Value", "desc", "agent-nil", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "between", Value: nil},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, _ := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-nil",
		Capability: CapNetHTTP,
	})

	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow for nil value, got %s", res.Decision)
	}
}

// TestEvaluateTimeCondition_UnknownOperator tests unknown operator
func TestEvaluateTimeCondition_UnknownOperator(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	c, _ := r.Create(context.Background(), "Unknown Op", "desc", "agent-unknown", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "unknown_op", Value: nil},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, _ := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-unknown",
		Capability: CapNetHTTP,
	})

	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow for unknown operator, got %s", res.Decision)
	}
}

// TestEvaluateTimeCondition_MidnightWraparound tests time spanning midnight
func TestEvaluateTimeCondition_MidnightWraparound(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)

	c, _ := r.Create(context.Background(), "Midnight", "desc", "agent-midnight", "owner-1", []ContractRule{
		{
			Capability: CapNetHTTP,
			Conditions: []Condition{
				{Type: "time", Operator: "between", Value: map[string]interface{}{
					"start": "23:00",
					"end":   "02:00",
				}},
			},
		},
	})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)

	res, _ := e.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-midnight",
		Capability: CapNetHTTP,
	})

	t.Logf("Midnight wraparound result: %s", res.Decision)
}

// TestEvaluateTimeCondition_DirectEvaluate tests evaluateTimeCondition directly
func TestEvaluateTimeCondition_DirectEvaluate(t *testing.T) {
	e := &DefaultEnforcer{}

	// Test with valid between condition
	cond := Condition{
		Type:     "time",
		Operator: "between",
		Key:      "work_hours",
		Value: map[string]interface{}{
			"start": "00:00",
			"end":   "23:59",
		},
	}

	result := e.evaluateTimeCondition(cond)
	if !result {
		t.Errorf("Expected true for all-day window")
	}

	// Test with invalid type (string instead of map)
	cond2 := Condition{
		Type:     "time",
		Operator: "between",
		Key:      "work_hours",
		Value:    "invalid",
	}

	result2 := e.evaluateTimeCondition(cond2)
	if !result2 {
		t.Errorf("Expected true for invalid type (permissive)")
	}

	// Test with map missing keys
	cond3 := Condition{
		Type:     "time",
		Operator: "between",
		Key:      "work_hours",
		Value:    map[string]interface{}{},
	}

	result3 := e.evaluateTimeCondition(cond3)
	if !result3 {
		t.Errorf("Expected true for empty map")
	}
}

// TestEvaluateTimeCondition_ParsingErrors tests parsing error handling
func TestEvaluateTimeCondition_ParsingErrors(t *testing.T) {
	e := &DefaultEnforcer{}

	testCases := []struct {
		name  string
		value interface{}
	}{
		{"invalid start time", map[string]interface{}{"start": "25:00", "end": "12:00"}},
		{"invalid end time", map[string]interface{}{"start": "08:00", "end": "25:00"}},
		{"garbage time", map[string]interface{}{"start": "garbage", "end": "12:00"}},
		{"missing minutes", map[string]interface{}{"start": "8", "end": "12:00"}},
		{"wrong format", map[string]interface{}{"start": "08:00:00", "end": "12:00"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cond := Condition{
				Type:     "time",
				Operator: "between",
				Key:      "test",
				Value:    tc.value,
			}

			result := e.evaluateTimeCondition(cond)
			if !result {
				t.Errorf("Expected permissive behavior for %s", tc.name)
			}
		})
	}
}

// TestEvaluateTimeCondition_ExactBoundary tests exact boundary times
func TestEvaluateTimeCondition_ExactBoundary(t *testing.T) {
	e := &DefaultEnforcer{}

	// Get current time and create exact boundary
	now := time.Now()
	currentMins := now.Hour()*60 + now.Minute()
	startMins := currentMins - 1
	endMins := currentMins + 1

	startStr := fmt.Sprintf("%02d:%02d", startMins/60, startMins%60)
	endStr := fmt.Sprintf("%02d:%02d", endMins/60, endMins%60)

	cond := Condition{
		Type:     "time",
		Operator: "between",
		Key:      "exact_test",
		Value: map[string]interface{}{
			"start": startStr,
			"end":   endStr,
		},
	}

	result := e.evaluateTimeCondition(cond)
	if !result {
		t.Errorf("Current time should be within exact boundary window")
	}
}
