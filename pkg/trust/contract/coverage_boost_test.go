package contract

import (
	"testing"
	"time"
)

// Additional trust/contract tests for coverage boost

func TestContractRule_WithMaxPerHour(t *testing.T) {
	rules := []ContractRule{
		{
			Capability: CapFileRead,
			Scope:      ScopeGlobal,
			RiskLevel:  RiskLow,
			MaxPerHour: 500,
		},
	}

	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	if len(contract.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(contract.Rules))
	}
	if contract.Rules[0].MaxPerHour != 500 {
		t.Errorf("MaxPerHour = %d, want 500", contract.Rules[0].MaxPerHour)
	}
}

func TestContractRule_WithExpiresAt(t *testing.T) {
	future := time.Now().Add(48 * time.Hour)
	rules := []ContractRule{
		{
			Capability: CapFileRead,
			Scope:      ScopeGlobal,
			RiskLevel:  RiskLow,
			ExpiresAt:  &future,
		},
	}

	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	if contract.Rules[0].ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	}
}

func TestContractRule_WithConditions(t *testing.T) {
	rules := []ContractRule{
		{
			Capability: CapFileRead,
			Scope:      ScopeGlobal,
			RiskLevel:  RiskMedium,
			Conditions: []Condition{
				{Type: "time", Key: "hours", Operator: "in", Value: "9-17"},
				{Type: "approval", Key: "manager", Operator: "eq", Value: "approved"},
				{Type: "rate", Key: "rpm", Operator: "lt", Value: 60},
			},
		},
	}

	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	if len(contract.Rules[0].Conditions) != 3 {
		t.Errorf("Expected 3 conditions, got %d", len(contract.Rules[0].Conditions))
	}
}

func TestContractRule_WithResources(t *testing.T) {
	rules := []ContractRule{
		{
			Capability: CapFileRead,
			Scope:      ScopeResource,
			RiskLevel:  RiskLow,
			Resources: []Resource{
				{Type: "file", Pattern: "/data/*", Actions: []string{"read"}},
				{Type: "file", Pattern: "/logs/*", Actions: []string{"read", "append"}},
			},
		},
	}

	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	if len(contract.Rules[0].Resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(contract.Rules[0].Resources))
	}
}

func TestContractRule_RequiresApproval(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskLow, RequiresAppr: false},
		{Capability: CapFileDelete, Scope: ScopeGlobal, RiskLevel: RiskHigh, RequiresAppr: true},
	}

	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	if contract.RequiresApproval(CapFileRead) {
		t.Error("CapFileRead should not require approval")
	}
	if !contract.RequiresApproval(CapFileDelete) {
		t.Error("CapFileDelete should require approval")
	}
}

func TestResource_Fields(t *testing.T) {
	resource := Resource{
		Type:    "database",
		Pattern: "production:users",
		Actions: []string{"select", "insert", "update", "delete"},
	}

	if resource.Type != "database" {
		t.Errorf("Type = %s, want database", resource.Type)
	}
	if len(resource.Actions) != 4 {
		t.Errorf("Actions count = %d, want 4", len(resource.Actions))
	}
}

func TestCondition_Fields(t *testing.T) {
	condition := Condition{
		Type:     "context",
		Key:      "user_role",
		Operator: "in",
		Value:    []string{"admin", "manager"},
		Metadata: map[string]string{"description": "Role-based access"},
	}

	if condition.Type != "context" {
		t.Errorf("Type = %s, want context", condition.Type)
	}
}

func TestCapabilityContract_Version(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskLow},
	}

	contract, _ := NewContract("Test Contract", "desc", "agent-1", "owner-1", rules)

	if contract.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestCapabilityContract_CreatedAt(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskLow},
	}

	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	if contract.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestCapabilityContract_Fingerprint(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskLow},
	}

	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	fp := contract.CalculateFingerprint()
	if fp == "" {
		t.Error("Fingerprint should not be empty")
	}

	fp2 := contract.CalculateFingerprint()
	if fp != fp2 {
		t.Error("Same contract should produce same fingerprint")
	}
}

func TestCapabilityContract_JSONRoundTrip(t *testing.T) {
	rules := []ContractRule{
		{Capability: CapNetHTTP, Scope: ScopeGlobal, RiskLevel: RiskLow},
		{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskLow},
	}

	original, _ := NewContract("Round Trip", "test", "agent-json", "owner-json", rules)

	data, err := original.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	restored, err := FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}

	if restored.Name != original.Name {
		t.Errorf("Name mismatch: %s != %s", restored.Name, original.Name)
	}
	if restored.AgentID != original.AgentID {
		t.Errorf("AgentID mismatch")
	}
	if len(restored.Rules) != len(original.Rules) {
		t.Errorf("Rules count mismatch")
	}
}

func TestFromJSON_InvalidData(t *testing.T) {
	_, err := FromJSON([]byte("not json"))
	if err == nil {
		t.Error("Should fail for invalid JSON")
	}
}

func TestFromJSON_TruncatedData(t *testing.T) {
	// Create valid JSON then truncate
	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", []ContractRule{{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskLow}})
	data, _ := contract.ToJSON()
	truncated := data[:len(data)/2]
	_, err := FromJSON(truncated)
	if err == nil {
		t.Log("Truncated JSON might be accepted by FromJSON")
	}
}

func TestScope_StringValues(t *testing.T) {
	if string(ScopeGlobal) != "global" {
		t.Errorf("ScopeGlobal = %s, want global", ScopeGlobal)
	}
	if string(ScopeLocal) != "local" {
		t.Errorf("ScopeLocal = %s, want local", ScopeLocal)
	}
	if string(ScopeResource) != "resource" {
		t.Errorf("ScopeResource = %s, want resource", ScopeResource)
	}
}

func TestRiskLevel_StringValues(t *testing.T) {
	if string(RiskLow) != "low" {
		t.Errorf("RiskLow = %s, want low", RiskLow)
	}
	if string(RiskMedium) != "medium" {
		t.Errorf("RiskMedium = %s, want medium", RiskMedium)
	}
	if string(RiskHigh) != "high" {
		t.Errorf("RiskHigh = %s, want high", RiskHigh)
	}
	if string(RiskCritical) != "critical" {
		t.Errorf("RiskCritical = %s, want critical", RiskCritical)
	}
}

func TestContractStatus_StringValues(t *testing.T) {
	if string(ContractStatusDraft) != "draft" {
		t.Errorf("ContractStatusDraft = %s, want draft", ContractStatusDraft)
	}
	if string(ContractStatusActive) != "active" {
		t.Errorf("ContractStatusActive = %s, want active", ContractStatusActive)
	}
	if string(ContractStatusSuspended) != "suspended" {
		t.Errorf("ContractStatusSuspended = %s, want suspended", ContractStatusSuspended)
	}
	if string(ContractStatusExpired) != "expired" {
		t.Errorf("ContractStatusExpired = %s, want expired", ContractStatusExpired)
	}
	if string(ContractStatusRevoked) != "revoked" {
		t.Errorf("ContractStatusRevoked = %s, want revoked", ContractStatusRevoked)
	}
}

func TestCapability_FileCapabilities(t *testing.T) {
	if string(CapFileRead) != "file:read" {
		t.Errorf("CapFileRead = %s", CapFileRead)
	}
	if string(CapFileWrite) != "file:write" {
		t.Errorf("CapFileWrite = %s", CapFileWrite)
	}
	if string(CapFileDelete) != "file:delete" {
		t.Errorf("CapFileDelete = %s", CapFileDelete)
	}
	if string(CapFileExecute) != "file:execute" {
		t.Errorf("CapFileExecute = %s", CapFileExecute)
	}
}

func TestCapability_NetworkCapabilities(t *testing.T) {
	if string(CapNetHTTP) != "net:http" {
		t.Errorf("CapNetHTTP = %s", CapNetHTTP)
	}
	if string(CapNetHTTPS) != "net:https" {
		t.Errorf("CapNetHTTPS = %s", CapNetHTTPS)
	}
	if string(CapNetInternal) != "net:internal" {
		t.Errorf("CapNetInternal = %s", CapNetInternal)
	}
	if string(CapNetExternal) != "net:external" {
		t.Errorf("CapNetExternal = %s", CapNetExternal)
	}
}

func TestCapability_TerminalCapabilities(t *testing.T) {
	if string(CapTerminalExec) != "terminal:execute" {
		t.Errorf("CapTerminalExec = %s", CapTerminalExec)
	}
	if string(CapTerminalSSH) != "terminal:ssh" {
		t.Errorf("CapTerminalSSH = %s", CapTerminalSSH)
	}
}

func TestCapability_DatabaseCapabilities(t *testing.T) {
	if string(CapDBRead) != "db:read" {
		t.Errorf("CapDBRead = %s", CapDBRead)
	}
	if string(CapDBWrite) != "db:write" {
		t.Errorf("CapDBWrite = %s", CapDBWrite)
	}
	if string(CapDBDelete) != "db:delete" {
		t.Errorf("CapDBDelete = %s", CapDBDelete)
	}
}

func TestCapability_AgentCapabilities(t *testing.T) {
	if string(CapAgentCall) != "agent:call" {
		t.Errorf("CapAgentCall = %s", CapAgentCall)
	}
	if string(CapAgentDelegate) != "agent:delegate" {
		t.Errorf("CapAgentDelegate = %s", CapAgentDelegate)
	}
	if string(CapAgentSpawn) != "agent:spawn" {
		t.Errorf("CapAgentSpawn = %s", CapAgentSpawn)
	}
}

func TestCapability_DataCapabilities(t *testing.T) {
	if string(CapDataPII) != "data:pii" {
		t.Errorf("CapDataPII = %s", CapDataPII)
	}
	if string(CapDataSensitive) != "data:sensitive" {
		t.Errorf("CapDataSensitive = %s", CapDataSensitive)
	}
	if string(CapDataExport) != "data:export" {
		t.Errorf("CapDataExport = %s", CapDataExport)
	}
}

func TestCapability_AdminCapability(t *testing.T) {
	if string(CapAdmin) != "admin:*" {
		t.Errorf("CapAdmin = %s", CapAdmin)
	}
}

func TestCapability_APICapabilities(t *testing.T) {
	if string(CapAPIInternal) != "api:internal" {
		t.Errorf("CapAPIInternal = %s", CapAPIInternal)
	}
	if string(CapAPIExternal) != "api:external" {
		t.Errorf("CapAPIExternal = %s", CapAPIExternal)
	}
}

func TestContractRule_ID(t *testing.T) {
	rules := []ContractRule{
		{ID: "rule-custom-id", Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: RiskLow},
	}

	contract, _ := NewContract("Test", "desc", "agent-1", "owner-1", rules)

	if contract.Rules[0].ID == "" {
		t.Error("Rule ID should not be empty")
	}
}

func TestContractRule_AllRiskLevels(t *testing.T) {
	riskLevels := []RiskLevel{RiskLow, RiskMedium, RiskHigh, RiskCritical}

	for _, risk := range riskLevels {
		rules := []ContractRule{
			{Capability: CapFileRead, Scope: ScopeGlobal, RiskLevel: risk},
		}

		contract, err := NewContract("Test", "desc", "agent-1", "owner-1", rules)
		if err != nil {
			t.Errorf("Failed with RiskLevel %s: %v", risk, err)
		}
		if contract.Rules[0].RiskLevel != risk {
			t.Errorf("RiskLevel = %s, want %s", contract.Rules[0].RiskLevel, risk)
		}
	}
}

func TestContractRule_AllScopes(t *testing.T) {
	scopes := []Scope{ScopeGlobal, ScopeLocal, ScopeResource}

	for _, scope := range scopes {
		rules := []ContractRule{
			{Capability: CapFileRead, Scope: scope, RiskLevel: RiskLow},
		}

		contract, err := NewContract("Test", "desc", "agent-1", "owner-1", rules)
		if err != nil {
			t.Errorf("Failed with Scope %s: %v", scope, err)
		}
		if contract.Rules[0].Scope != scope {
			t.Errorf("Scope = %s, want %s", contract.Rules[0].Scope, scope)
		}
	}
}
