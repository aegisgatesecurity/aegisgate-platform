package contract

import (
	"testing"
)

func TestContractFingerprint(t *testing.T) {
	rules := []ContractRule{{Capability: CapFileRead, Scope: ScopeLocal}}
	c, _ := NewContract("test", "desc", "agent-1", "owner-1", rules)
	fp := c.CalculateFingerprint()
	if fp == "" {
		t.Error("Fingerprint should not be empty")
	}
}

func TestContractGetCapabilities(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapFileRead, Scope: ScopeGlobal},
		{Capability: CapFileWrite, Scope: ScopeLocal},
	}
	c, _ := NewContract("test", "desc", "agent-1", "owner-1", rules)
	caps := c.GetCapabilities()
	if len(caps) != 2 {
		t.Errorf("Expected 2 capabilities, got %d", len(caps))
	}
}

func TestContractGetHighRiskCapabilities(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskLow},
		{Capability: CapAdmin, Scope: ScopeGlobal, RiskLevel: RiskCritical},
	}
	c, _ := NewContract("test", "desc", "agent-1", "owner-1", rules)
	highRisk := c.GetHighRiskCapabilities()
	if len(highRisk) != 1 {
		t.Errorf("Expected 1 high risk, got %d", len(highRisk))
	}
}

func TestContractRequiresApproval(t *testing.T) {
	rules := []ContractRule{{Capability: CapFileWrite, Scope: ScopeGlobal, RequiresAppr: true}}
	c, _ := NewContract("test", "desc", "agent-1", "owner-1", rules)
	if !c.RequiresApproval(CapFileWrite) {
		t.Error("CapFileWrite should require approval")
	}
}

func TestContractToJSON(t *testing.T) {
	rules := []ContractRule{{Capability: CapFileRead, Scope: ScopeGlobal}}
	c, _ := NewContract("test", "desc", "agent-1", "owner-1", rules)
	data, err := c.ToJSON()
	if err != nil {
		t.Errorf("ToJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("ToJSON returned empty data")
	}
}

func TestContractFromJSON(t *testing.T) {
	rules := []ContractRule{{Capability: CapFileRead, Scope: ScopeGlobal}}
	c, _ := NewContract("test", "desc", "agent-1", "owner-1", rules)
	data, _ := c.ToJSON()
	c2, err := FromJSON(data)
	if err != nil {
		t.Errorf("FromJSON failed: %v", err)
	}
	if c2.Name != c.Name {
		t.Error("Name mismatch after round-trip")
	}
}
