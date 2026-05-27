// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Contract Tests
// =========================================================================

package contract

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewContract(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow},
	}
	contract, err := NewContract("Test Contract", "A test contract", "agent-1", "owner-1", rules)
	if err != nil {
		t.Fatalf("NewContract failed: %v", err)
	}
	if contract.ID == "" {
		t.Error("ID should not be empty")
	}
	if contract.Name != "Test Contract" {
		t.Errorf("Name mismatch: %s", contract.Name)
	}
	if contract.Status != ContractStatusDraft {
		t.Errorf("Status should be draft, got %s", contract.Status)
	}
	if contract.Fingerprint == "" {
		t.Error("Fingerprint should not be empty")
	}
}

func TestNewContract_MissingName(t *testing.T) {
	_, err := NewContract("", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	if err == nil {
		t.Error("Expected error for missing name")
	}
}

func TestNewContract_MissingAgentID(t *testing.T) {
	_, err := NewContract("name", "desc", "", "owner-1", []ContractRule{{Capability: CapNetHTTP}})
	if err == nil {
		t.Error("Expected error for missing agentID")
	}
}

func TestNewContract_MissingOwnerID(t *testing.T) {
	_, err := NewContract("name", "desc", "agent-1", "", []ContractRule{{Capability: CapNetHTTP}})
	if err == nil {
		t.Error("Expected error for missing ownerID")
	}
}

func TestNewContract_NoRules(t *testing.T) {
	_, err := NewContract("name", "desc", "agent-1", "owner-1", []ContractRule{})
	if err == nil {
		t.Error("Expected error for no rules")
	}
}

func TestContract_CalculateFingerprint(t *testing.T) {
	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	fp1 := contract.CalculateFingerprint()
	fp2 := contract.CalculateFingerprint()
	if fp1 != fp2 {
		t.Error("Fingerprints should be deterministic")
	}
	if len(fp1) != 64 {
		t.Error("Fingerprint should be 64 chars (SHA-256 hex)")
	}
}

func TestContract_HasCapability(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow},
	}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	contract.Status = ContractStatusActive

	if !contract.HasCapability(CapNetHTTP) {
		t.Error("Should have NetHTTP capability")
	}
	if contract.HasCapability(CapFileRead) {
		t.Error("Should not have FileRead capability")
	}
}

func TestContract_HasCapability_Admin(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapAdmin, Scope: ScopeGlobal, RiskLevel: RiskCritical},
	}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	contract.Status = ContractStatusActive

	if !contract.HasCapability(CapNetHTTP) {
		t.Error("Admin should grant all capabilities")
	}
	if !contract.HasCapability(CapFileRead) {
		t.Error("Admin should grant all capabilities")
	}
}

func TestContract_HasCapability_NotActive(t *testing.T) {
	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	// Status is draft by default

	if contract.HasCapability(CapNetHTTP) {
		t.Error("Draft contract should not grant capabilities")
	}
}

func TestContract_HasCapabilityWithScope(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapFileRead, Scope: ScopeResource, RiskLevel: RiskMedium},
	}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	contract.Status = ContractStatusActive

	if !contract.HasCapabilityWithScope(CapFileRead, ScopeResource) {
		t.Error("Should have FileRead with resource scope")
	}
	if contract.HasCapabilityWithScope(CapFileRead, ScopeGlobal) {
		t.Error("Should not have FileRead with global scope")
	}
}

func TestContract_IsResourceAllowed(t *testing.T) {
	rules := []ContractRule{
		{
			Capability: CapFileRead,
			Scope:      ScopeResource,
			Resources:  []Resource{{Type: "file", Pattern: "/data/*"}},
			RiskLevel:  RiskMedium,
		},
	}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	contract.Status = ContractStatusActive

	if !contract.IsResourceAllowed(CapFileRead, "file", "/data/customers") {
		t.Error("Should allow file access to /data/*")
	}
	if contract.IsResourceAllowed(CapFileRead, "database", "users") {
		t.Error("Should not allow database access")
	}
}

func TestContract_GetCapabilities(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow},
		{Capability: CapNetHTTPS, Scope: ScopeGlobal, RiskLevel: RiskLow},
		{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskMedium},
	}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	caps := contract.GetCapabilities()
	if len(caps) != 3 {
		t.Errorf("Expected 3 capabilities, got %d", len(caps))
	}
}

func TestContract_GetHighRiskCapabilities(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow},
		{Capability: CapTerminalExec, Scope: ScopeGlobal, RiskLevel: RiskHigh},
		{Capability: CapAgentSpawn, Scope: ScopeGlobal, RiskLevel: RiskCritical},
	}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	caps := contract.GetHighRiskCapabilities()
	if len(caps) != 2 {
		t.Errorf("Expected 2 high-risk capabilities, got %d", len(caps))
	}
}

func TestContract_RequiresApproval(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow},
		{Capability: CapTerminalExec, Scope: ScopeGlobal, RiskLevel: RiskHigh, RequiresAppr: true},
	}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	contract.Status = ContractStatusActive

	if contract.RequiresApproval(CapNetHTTP) {
		t.Error("NetHTTP should not require approval")
	}
	if !contract.RequiresApproval(CapTerminalExec) {
		t.Error("TerminalExec should require approval")
	}
}

func TestContract_IsExpired(t *testing.T) {
	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	if contract.IsExpired() {
		t.Error("Contract with no expiration should not be expired")
	}

	past := time.Now().Add(-time.Hour)
	contract.ExpiresAt = &past
	if !contract.IsExpired() {
		t.Error("Contract with past expiration should be expired")
	}

	future := time.Now().Add(time.Hour)
	contract.ExpiresAt = &future
	if contract.IsExpired() {
		t.Error("Contract with future expiration should not be expired")
	}
}

func TestContract_CanVerify(t *testing.T) {
	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	contract.Status = ContractStatusActive

	if !contract.CanVerify() {
		t.Error("Active contract without expiration should be verifiable")
	}
}

func TestContract_ToJSON(t *testing.T) {
	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	data, err := contract.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON data should not be empty")
	}
}

func TestFromJSON(t *testing.T) {
	rules := []ContractRule{{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow}}
	original, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)
	original.Status = ContractStatusActive

	data, _ := original.ToJSON()
	restored, err := FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}
	if restored.ID != original.ID {
		t.Error("ID mismatch")
	}
	if restored.Name != original.Name {
		t.Error("Name mismatch")
	}
}

func TestFromJSON_Invalid(t *testing.T) {
	_, err := FromJSON([]byte("invalid json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestCapabilityConstants(t *testing.T) {
	caps := []Capability{
		CapFileRead, CapFileWrite, CapFileDelete, CapFileExecute,
		CapNetHTTP, CapNetHTTPS, CapNetInternal, CapNetExternal,
		CapTerminalExec, CapTerminalSSH,
		CapDBRead, CapDBWrite, CapDBDelete,
		CapAPIInternal, CapAPIExternal,
		CapAgentCall, CapAgentDelegate, CapAgentSpawn,
		CapDataPII, CapDataSensitive, CapDataExport,
		CapAdmin,
	}
	for _, cap := range caps {
		if cap == "" {
			t.Error("Capability constant should not be empty")
		}
	}
}

func TestScopeConstants(t *testing.T) {
	if ScopeGlobal != "global" {
		t.Error("ScopeGlobal should be 'global'")
	}
	if ScopeLocal != "local" {
		t.Error("ScopeLocal should be 'local'")
	}
	if ScopeResource != "resource" {
		t.Error("ScopeResource should be 'resource'")
	}
}

func TestRiskLevelConstants(t *testing.T) {
	if RiskLow != "low" {
		t.Error("RiskLow should be 'low'")
	}
	if RiskMedium != "medium" {
		t.Error("RiskMedium should be 'medium'")
	}
	if RiskHigh != "high" {
		t.Error("RiskHigh should be 'high'")
	}
	if RiskCritical != "critical" {
		t.Error("RiskCritical should be 'critical'")
	}
}

func TestContractStatusConstants(t *testing.T) {
	if ContractStatusDraft != "draft" {
		t.Error("ContractStatusDraft should be 'draft'")
	}
	if ContractStatusActive != "active" {
		t.Error("ContractStatusActive should be 'active'")
	}
	if ContractStatusSuspended != "suspended" {
		t.Error("ContractStatusSuspended should be 'suspended'")
	}
	if ContractStatusExpired != "expired" {
		t.Error("ContractStatusExpired should be 'expired'")
	}
	if ContractStatusRevoked != "revoked" {
		t.Error("ContractStatusRevoked should be 'revoked'")
	}
}

func TestContractJSONSerialization(t *testing.T) {
	rules := []ContractRule{
		{
			Capability: CapNetHTTP,
			Scope:      ScopeGlobal,
			RiskLevel:  RiskLow,
			Conditions: []Condition{
				{Type: "time", Key: "hours", Operator: "between", Value: map[string]interface{}{"start": "09:00", "end": "17:00"}},
			},
		},
	}
	contract, _ := NewContract("Test Contract", "desc", "agent-1", "owner-1", rules)

	data, err := json.Marshal(contract)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var restored map[string]interface{}
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if restored["name"] != "Test Contract" {
		t.Error("Name not preserved in JSON")
	}
	if restored["agentId"] != "agent-1" {
		t.Error("AgentID not preserved in JSON")
	}
}
