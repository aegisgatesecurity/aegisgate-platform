// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Enforcement Tests

package contract

import (
	"time"
	"context"
	"testing"
)

func TestEnforcer_Enforce_Allow(t *testing.T) {
	registry := NewInMemoryRegistry()
	rateLimiter := NewSimpleRateLimiter()
	enforcer := NewEnforcer(registry, rateLimiter)

	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)

	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-1",
		Capability: CapNetHTTP,
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Expected allow, got %s", result.Decision)
	}
}

func TestEnforcer_Enforce_Deny(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)

	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-1",
		Capability: CapNetHTTP,
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Expected deny for unknown agent, got %s", result.Decision)
	}
}

func TestEnforcer_Enforce_NoSpec(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)

	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		Capability: CapNetHTTP,
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Expected deny for no agent/contract, got %s", result.Decision)
	}
}

func TestEnforcer_EnforceByContractID(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)

	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)

	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		ContractID: contract.ID,
		Capability: CapNetHTTP,
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Expected allow, got %s", result.Decision)
	}
}

func TestEnforcer_Enforce_ContractSuspended(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)

	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusSuspended)

	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-1",
		Capability: CapNetHTTP,
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionExpired {
		t.Errorf("Expected expired for suspended contract, got %s", result.Decision)
	}
}

func TestEnforcer_Enforce_RequiresApproval(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)

	rules := []ContractRule{{Capability: CapTerminalExec, Scope: ScopeGlobal, RiskLevel: RiskHigh, RequiresAppr: true}}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)

	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-1",
		Capability: CapTerminalExec,
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionRequireApproval {
		t.Errorf("Expected require_approval, got %s", result.Decision)
	}
}

func TestEnforcer_Enforce_AdminCapability(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)

	rules := []ContractRule{{Capability: CapAdmin, Scope: ScopeGlobal, RiskLevel: RiskCritical}}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)

	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-1",
		Capability: CapNetHTTP,
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Admin capability should allow everything, got %s", result.Decision)
	}
}

func TestEnforcer_EnforceMultiple(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)

	rules := []ContractRule{
		{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow},
		{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskMedium},
	}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)

	result, err := enforcer.EnforceMultiple(context.Background(), &EnforcementContext{
		AgentID: "agent-1",
	}, []Capability{CapNetHTTP, CapFileRead})
	if err != nil {
		t.Fatalf("EnforceMultiple failed: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Expected allow, got %s", result.Decision)
	}
}

func TestEnforcer_EnforceMultiple_DeniesOne(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)

	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)

	result, err := enforcer.EnforceMultiple(context.Background(), &EnforcementContext{
		AgentID: "agent-1",
	}, []Capability{CapNetHTTP, CapFileRead})
	if err != nil {
		t.Fatalf("EnforceMultiple failed: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Expected deny when one capability not allowed, got %s", result.Decision)
	}
}

func TestEnforcer_EnforceMultiple_Empty(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)

	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)

	result, err := enforcer.EnforceMultiple(context.Background(), &EnforcementContext{
		AgentID: "agent-1",
	}, []Capability{})
	if err != nil {
		t.Fatalf("EnforceMultiple failed: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Expected allow for empty capabilities, got %s", result.Decision)
	}
}

func TestSimpleRateLimiter_Check(t *testing.T) {
	limiter := NewSimpleRateLimiter()
	allowed, err := limiter.Check("contract-1", CapNetHTTP)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !allowed {
		t.Error("Should be allowed initially")
	}
}

func TestSimpleRateLimiter_Record(t *testing.T) {
	limiter := NewSimpleRateLimiter()
	err := limiter.Record("contract-1", CapNetHTTP)
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}
}

func TestEnforcer_RecordUsage(t *testing.T) {
	registry := NewInMemoryRegistry()
	rateLimiter := NewSimpleRateLimiter()
	enforcer := NewEnforcer(registry, rateLimiter)
	
	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	
	err := (enforcer.(*DefaultEnforcer)).RecordUsage(contract.ID, CapNetHTTP)
	if err != nil {
		t.Errorf("RecordUsage failed: %v", err)
	}
}

func TestEnforcer_RecordUsage_NoRateLimiter(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)
	
	err := (enforcer.(*DefaultEnforcer)).RecordUsage("contract-1", CapNetHTTP)
	if err != nil {
		t.Errorf("RecordUsage with nil rate limiter should not error: %v", err)
	}
}

func TestInMemoryRegistry_ListByOwner(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	registry.Create(ctx, "Contract1", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	registry.Create(ctx, "Contract2", "desc", "agent-2", "owner-1", []ContractRule{{Capability: CapNetHTTPS}})
	registry.Create(ctx, "Contract3", "desc", "agent-3", "owner-2", []ContractRule{{Capability: CapFileRead}})
	
	contracts, err := registry.ListByOwner(ctx, "owner-1")
	if err != nil {
		t.Fatalf("ListByOwner failed: %v", err)
	}
	if len(contracts) != 2 {
		t.Errorf("Expected 2 contracts for owner-1, got %d", len(contracts))
	}
}

func TestInMemoryRegistry_ListByOwner_Empty(t *testing.T) {
	registry := NewInMemoryRegistry()
	contracts, err := registry.ListByOwner(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("ListByOwner failed: %v", err)
	}
	if len(contracts) != 0 {
		t.Errorf("Expected 0 contracts for nonexistent owner, got %d", len(contracts))
	}
}

func TestInMemoryRegistry_Update(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	contract, _ := registry.Create(ctx, "Original", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	
	newContract := &CapabilityContract{Name: "Updated"}
	updated, err := registry.Update(ctx, contract.ID, newContract)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Name != "Updated" {
		t.Errorf("Name should be 'Updated', got %s", updated.Name)
	}
}

func TestInMemoryRegistry_UpdateNotFound(t *testing.T) {
	registry := NewInMemoryRegistry()
	_, err := registry.Update(context.Background(), "nonexistent", &CapabilityContract{})
	if err == nil {
		t.Error("Expected error for nonexistent contract")
	}
}

func TestInMemoryRegistry_Delete(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	contract, _ := registry.Create(ctx, "Test", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	
	err := registry.Delete(ctx, contract.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	
	_, err = registry.Get(ctx, contract.ID)
	if err == nil {
		t.Error("Contract should not exist after delete")
	}
}

func TestInMemoryRegistry_DeleteNotFound(t *testing.T) {
	registry := NewInMemoryRegistry()
	err := registry.Delete(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent contract")
	}
}

func TestInMemoryRegistry_List(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	registry.Create(ctx, "C1", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	registry.Create(ctx, "C2", "desc", "agent-2", "owner-2", []ContractRule{{Capability: CapNetHTTPS}})
	
	contracts, err := registry.List(ctx, nil)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(contracts) != 2 {
		t.Errorf("Expected 2 contracts, got %d", len(contracts))
	}
}

func TestInMemoryRegistry_ListWithFilter(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	registry.Create(ctx, "C1", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	registry.Create(ctx, "C2", "desc", "agent-2", "owner-2", []ContractRule{{Capability: CapNetHTTPS}})
	
	contracts, err := registry.List(ctx, &ListFilter{OwnerID: "owner-1"})
	if err != nil {
		t.Fatalf("List with filter failed: %v", err)
	}
	if len(contracts) != 1 {
		t.Errorf("Expected 1 contract for owner-1, got %d", len(contracts))
	}
}

func TestInMemoryRegistry_ListWithPagination(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	for i := 0; i < 5; i++ {
		registry.Create(ctx, "Test", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	}
	
	page1, _ := registry.List(ctx, &ListFilter{Limit: 2, Offset: 0})
	if len(page1) != 2 {
		t.Errorf("Expected 2 on page 1, got %d", len(page1))
	}
	
	page2, _ := registry.List(ctx, &ListFilter{Limit: 2, Offset: 2})
	if len(page2) != 2 {
		t.Errorf("Expected 2 on page 2, got %d", len(page2))
	}
}

func TestEnforcer_EnforceWithCondition_Time(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)
	
	future := time.Now().Add(24 * time.Hour)
	rules := []ContractRule{
		{
			Capability: CapNetHTTP,
			Scope:     ScopeGlobal,
			RiskLevel: RiskLow,
			Conditions: []Condition{
				{Type: "time", Key: "hours", Operator: "between", Value: map[string]interface{}{"start": "00:00", "end": "23:59"}},
			},
			ExpiresAt: &future,
		},
	}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)
	
	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-1",
		Capability: CapNetHTTP,
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Expected allow with valid time condition, got %s", result.Decision)
	}
}

func TestEnforcer_EnforceWithCondition_Context(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)
	
	rules := []ContractRule{
		{
			Capability: CapNetHTTP,
			Scope:     ScopeGlobal,
			RiskLevel: RiskLow,
			Conditions: []Condition{
				{Type: "context", Key: "env", Operator: "eq", Value: "production"},
			},
		},
	}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)
	
	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-1",
		Capability: CapNetHTTP,
		Metadata:   map[string]string{"env": "production"},
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Expected allow with matching context, got %s", result.Decision)
	}
}

func TestEnforcer_EnforceWithCondition_ContextMismatch(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)
	
	rules := []ContractRule{
		{
			Capability: CapNetHTTP,
			Scope:     ScopeGlobal,
			RiskLevel: RiskLow,
			Conditions: []Condition{
				{Type: "context", Key: "env", Operator: "eq", Value: "production"},
			},
		},
	}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)
	
	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-1",
		Capability: CapNetHTTP,
		Metadata:   map[string]string{"env": "staging"},
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionDeny {
		t.Errorf("Expected deny with mismatched context, got %s", result.Decision)
	}
}

func TestEnforcer_EnforceWithCondition_InOperator(t *testing.T) {
	registry := NewInMemoryRegistry()
	enforcer := NewEnforcer(registry, nil)
	
	rules := []ContractRule{
		{
			Capability: CapNetHTTP,
			Scope:     ScopeGlobal,
			RiskLevel: RiskLow,
			Conditions: []Condition{
				{Type: "context", Key: "role", Operator: "in", Value: []string{"admin", "developer"}},
			},
		},
	}
	contract, _ := registry.Create(context.Background(), "Test", "desc", "agent-1", "owner-1", rules)
	_ = registry.UpdateStatus(context.Background(), contract.ID, ContractStatusActive)
	
	result, err := enforcer.Enforce(context.Background(), &EnforcementContext{
		AgentID:    "agent-1",
		Capability: CapNetHTTP,
		Metadata:   map[string]string{"role": "developer"},
	})
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("Expected allow with role in list, got %s", result.Decision)
	}
}

func TestContract_HasCapabilityWithScope_NotActive(t *testing.T) {
	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	
	if contract.HasCapabilityWithScope(CapNetHTTP, ScopeGlobal) {
		t.Error("Draft contract should not have capabilities")
	}
}

func TestContract_IsResourceAllowed_NoResources(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow, Resources: []Resource{}},
	}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	contract.Status = ContractStatusActive
	
	if !contract.IsResourceAllowed(CapNetHTTP, "any", "anything") {
		t.Error("Empty resources should allow all")
	}
}

func TestContract_RequiresApproval_NotFound(t *testing.T) {
	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	contract.Status = ContractStatusActive
	
	if contract.RequiresApproval(CapFileRead) {
		t.Error("Capability not in contract should not require approval")
	}
}

func TestInMemoryRegistry_GetByAgent_NotFound(t *testing.T) {
	registry := NewInMemoryRegistry()
	_, err := registry.GetByAgent(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent agent")
	}
}

func TestInMemoryRegistry_UpdateStatus(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	contract, _ := registry.Create(ctx, "Test", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	
	err := registry.UpdateStatus(ctx, contract.ID, ContractStatusSuspended)
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}
	
	updated, _ := registry.Get(ctx, contract.ID)
	if updated.Status != ContractStatusSuspended {
		t.Errorf("Status should be suspended, got %s", updated.Status)
	}
}

func TestInMemoryRegistry_UpdateStatus_NotFound(t *testing.T) {
	registry := NewInMemoryRegistry()
	err := registry.UpdateStatus(context.Background(), "nonexistent", ContractStatusActive)
	if err == nil {
		t.Error("Expected error for nonexistent contract")
	}
}

func TestSimpleRateLimiter_MultipleRecords(t *testing.T) {
	limiter := NewSimpleRateLimiter()
	
	for i := 0; i < 5; i++ {
		err := limiter.Record("contract-1", CapNetHTTP)
		if err != nil {
			t.Fatalf("Record failed: %v", err)
		}
	}
	
	allowed, _ := limiter.Check("contract-1", CapNetHTTP)
	if !allowed {
		t.Error("Should still be allowed after 5 records")
	}
}

func TestInMemoryRegistry_Create(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	contract, err := registry.Create(ctx, "NewContract", "description", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if contract.Name != "NewContract" {
		t.Errorf("Name mismatch: %s", contract.Name)
	}
	if contract.Status != ContractStatusDraft {
		t.Errorf("Status should be draft, got %s", contract.Status)
	}
}

func TestInMemoryRegistry_Store(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	contract := &CapabilityContract{
		ID:          "test-id",
		Name:        "StoredContract",
		Description: "desc",
		AgentID:     "agent-1",
		OwnerID:     "owner-1",
		Rules:       []ContractRule{{Capability: CapNetHTTP}},
	}
	
	stored, err := registry.Store(ctx, contract)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	if stored.Name != "StoredContract" {
		t.Errorf("Name mismatch after store")
	}
	
	retrieved, _ := registry.Get(ctx, "test-id")
	if retrieved.ID != "test-id" {
		t.Errorf("ID mismatch after retrieval")
	}
}

func TestInMemoryRegistry_Update_Description(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	contract, _ := registry.Create(ctx, "Original", "original desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	
	updated, err := registry.Update(ctx, contract.ID, &CapabilityContract{Description: "new desc"})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if updated.Description != "new desc" {
		t.Errorf("Description not updated")
	}
}

func TestInMemoryRegistry_Update_Tags(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	contract, _ := registry.Create(ctx, "Test", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	
	updated, err := registry.Update(ctx, contract.ID, &CapabilityContract{Tags: []string{"tag1", "tag2"}})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if len(updated.Tags) != 2 {
		t.Errorf("Tags not updated: got %d", len(updated.Tags))
	}
}

func TestInMemoryRegistry_Update_Rules(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	contract, _ := registry.Create(ctx, "Test", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	
	newRules := []ContractRule{{Capability: CapNetHTTPS, Scope: ScopeGlobal, RiskLevel: RiskLow}, {Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskMedium}}
	updated, err := registry.Update(ctx, contract.ID, &CapabilityContract{Rules: newRules})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if len(updated.Rules) != 2 {
		t.Errorf("Rules not updated: got %d", len(updated.Rules))
	}
	if len(updated.Rules) == 2 && updated.Fingerprint == contract.Fingerprint {
		t.Error("Fingerprint should change when rules update")
	}
}

func TestInMemoryRegistry_List_ByStatus(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	c1, _ := registry.Create(ctx, "C1", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	registry.Create(ctx, "C2", "desc", "agent-2", "owner-1", []ContractRule{{Capability: CapNetHTTPS}})
	err := registry.UpdateStatus(ctx, c1.ID, ContractStatusSuspended)
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}
	
	active, _ := registry.List(ctx, &ListFilter{Status: ContractStatusActive})
	suspended, _ := registry.List(ctx, &ListFilter{Status: ContractStatusSuspended})
	
	if len(active) != 1 {
		t.Errorf("Expected 1 active, got %d", len(active))
	}
	if len(suspended) != 1 {
		t.Errorf("Expected 1 suspended, got %d", len(suspended))
	}
}

func TestInMemoryRegistry_List_ByAgent(t *testing.T) {
	registry := NewInMemoryRegistry()
	ctx := context.Background()
	
	registry.Create(ctx, "C1", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	registry.Create(ctx, "C2", "desc", "agent-2", "owner-1", []ContractRule{{Capability: CapNetHTTPS}})
	
	byAgent, _ := registry.List(ctx, &ListFilter{AgentID: "agent-1"})
	if len(byAgent) != 1 {
		t.Errorf("Expected 1 contract for agent-1, got %d", len(byAgent))
	}
}
