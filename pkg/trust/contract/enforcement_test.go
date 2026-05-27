package contract

import (
	"context"
	"testing"
)

func TestEnforcer_Enforce_Allow(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)
	res, _ := e.Enforce(context.Background(), &EnforcementContext{AgentID: "a1", Capability: CapNetHTTP})
	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow, got %s", res.Decision)
	}
}

func TestEnforcer_Enforce_Deny(t *testing.T) {
	e := NewEnforcer(NewInMemoryRegistry(), nil)
	res, _ := e.Enforce(context.Background(), &EnforcementContext{AgentID: "a1", Capability: CapNetHTTP})
	if res.Decision != DecisionDeny {
		t.Errorf("Expected deny, got %s", res.Decision)
	}
}

func TestEnforcer_Enforce_NoSpec(t *testing.T) {
	e := NewEnforcer(NewInMemoryRegistry(), nil)
	res, _ := e.Enforce(context.Background(), &EnforcementContext{Capability: CapNetHTTP})
	if res.Decision != DecisionDeny {
		t.Errorf("Expected deny, got %s", res.Decision)
	}
}

func TestEnforcer_EnforceByContractID(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)
	res, _ := e.Enforce(context.Background(), &EnforcementContext{ContractID: c.ID, Capability: CapNetHTTP})
	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow, got %s", res.Decision)
	}
}

func TestEnforcer_Enforce_ContractSuspended(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusSuspended)
	res, _ := e.Enforce(context.Background(), &EnforcementContext{AgentID: "a1", Capability: CapNetHTTP})
	if res.Decision != DecisionExpired {
		t.Errorf("Expected expired, got %s", res.Decision)
	}
}

func TestEnforcer_Enforce_RequiresApproval(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapTerminalExec, RequiresAppr: true}})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)
	res, _ := e.Enforce(context.Background(), &EnforcementContext{AgentID: "a1", Capability: CapTerminalExec})
	if res.Decision != DecisionRequireApproval {
		t.Errorf("Expected approval, got %s", res.Decision)
	}
}

func TestEnforcer_Enforce_AdminCapability(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapAdmin}})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)
	res, _ := e.Enforce(context.Background(), &EnforcementContext{AgentID: "a1", Capability: CapNetHTTP})
	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow, got %s", res.Decision)
	}
}

func TestEnforcer_EnforceMultiple(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}, {Capability: CapFileRead}})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)
	res, _ := e.EnforceMultiple(context.Background(), &EnforcementContext{AgentID: "a1"}, []Capability{CapNetHTTP, CapFileRead})
	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow, got %s", res.Decision)
	}
}

func TestEnforcer_EnforceMultiple_DeniesOne(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)
	res, _ := e.EnforceMultiple(context.Background(), &EnforcementContext{AgentID: "a1"}, []Capability{CapNetHTTP, CapFileRead})
	if res.Decision != DecisionDeny {
		t.Errorf("Expected deny, got %s", res.Decision)
	}
}

func TestEnforcer_EnforceMultiple_Empty(t *testing.T) {
	r := NewInMemoryRegistry()
	e := NewEnforcer(r, nil)
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)
	res, _ := e.EnforceMultiple(context.Background(), &EnforcementContext{AgentID: "a1"}, []Capability{})
	if res.Decision != DecisionAllow {
		t.Errorf("Expected allow, got %s", res.Decision)
	}
}

func TestSimpleRateLimiter_Check(t *testing.T) {
	l := NewSimpleRateLimiter()
	ok, _ := l.Check("c1", CapNetHTTP)
	if !ok {
		t.Error("Should be allowed")
	}
}

func TestSimpleRateLimiter_Record(t *testing.T) {
	l := NewSimpleRateLimiter()
	_ = l.Record("c1", CapNetHTTP)
}

func TestInMemoryRegistry_Create(t *testing.T) {
	r := NewInMemoryRegistry()
	c, err := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if c.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestInMemoryRegistry_Get(t *testing.T) {
	r := NewInMemoryRegistry()
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	g, err := r.Get(context.Background(), c.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if g.ID != c.ID {
		t.Error("ID mismatch")
	}
}

func TestInMemoryRegistry_GetByAgent(t *testing.T) {
	r := NewInMemoryRegistry()
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	g, _ := r.GetByAgent(context.Background(), "a1")
	if g.ID != c.ID {
		t.Error("ID mismatch")
	}
}

func TestInMemoryRegistry_Update(t *testing.T) {
	r := NewInMemoryRegistry()
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	n := "NewName"
	u, _ := r.Update(context.Background(), c.ID, &CapabilityContract{Name: n})
	if u.Name != n {
		t.Errorf("Name should be %s, got %s", n, u.Name)
	}
}

func TestInMemoryRegistry_UpdateStatus(t *testing.T) {
	r := NewInMemoryRegistry()
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	_ = r.UpdateStatus(context.Background(), c.ID, ContractStatusActive)
	g, _ := r.Get(context.Background(), c.ID)
	if g.Status != ContractStatusActive {
		t.Errorf("Status should be active, got %s", g.Status)
	}
}

func TestInMemoryRegistry_Delete(t *testing.T) {
	r := NewInMemoryRegistry()
	c, _ := r.Create(context.Background(), "T", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	_ = r.Delete(context.Background(), c.ID)
	_, err := r.Get(context.Background(), c.ID)
	if err == nil {
		t.Error("Should error after deletion")
	}
}

func TestInMemoryRegistry_List(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Create(context.Background(), "C1", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	r.Create(context.Background(), "C2", "d", "a2", "o1", []ContractRule{{Capability: CapNetHTTPS}})
	l, _ := r.List(context.Background(), nil)
	if len(l) != 2 {
		t.Errorf("Expected 2, got %d", len(l))
	}
}

func TestInMemoryRegistry_List_ByStatus(t *testing.T) {
	r := NewInMemoryRegistry()
	c, _ := r.Create(context.Background(), "C1", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	_ = r.UpdateStatus(context.Background(), c.ID, ContractStatusSuspended)
	l, _ := r.List(context.Background(), &ListFilter{Status: ContractStatusActive})
	if len(l) != 0 {
		t.Errorf("Expected 0 active, got %d", len(l))
	}
}

func TestInMemoryRegistry_List_ByOwner(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Create(context.Background(), "C1", "d", "a1", "owner-a", []ContractRule{{Capability: CapNetHTTP}})
	r.Create(context.Background(), "C2", "d", "a2", "owner-b", []ContractRule{{Capability: CapNetHTTPS}})
	l, _ := r.List(context.Background(), &ListFilter{OwnerID: "owner-a"})
	if len(l) != 1 {
		t.Errorf("Expected 1, got %d", len(l))
	}
}

func TestInMemoryRegistry_ListByOwner(t *testing.T) {
	r := NewInMemoryRegistry()
	r.Create(context.Background(), "C1", "d", "a1", "o1", []ContractRule{{Capability: CapNetHTTP}})
	l, _ := r.ListByOwner(context.Background(), "o1")
	if len(l) != 1 {
		t.Errorf("Expected 1, got %d", len(l))
	}
}

func TestInMemoryRegistry_Get_NotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	_, err := r.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Expected error")
	}
}

func TestInMemoryRegistry_Delete_NotFound(t *testing.T) {
	r := NewInMemoryRegistry()
	err := r.Delete(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Expected error")
	}
}

func TestDecisionConstants(t *testing.T) {
	if DecisionAllow != "allow" || DecisionDeny != "deny" || DecisionRequireApproval != "require_approval" || DecisionRateLimited != "rate_limited" || DecisionExpired != "expired" {
		t.Error("Decision constants mismatch")
	}
}
