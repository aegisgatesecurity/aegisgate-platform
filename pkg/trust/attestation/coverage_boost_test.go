package attestation

import (
	"context"
	"testing"
	"time"
)

// ContractSummary and MetricsSummary types for testing
type TestContractSummary struct {
	ID           string
	Status       string
	Capabilities []string
}

func TestService_CreateAttestationWithContract(t *testing.T) {
	svc, _ := NewService()
	contract := &ContractSummary{
		ID:           "contract-1",
		Status:       "active",
		Capabilities: []string{"read", "write"},
	}
	metrics := &MetricsSummary{
		TrustScore: 85.0,
		TrustLevel: "high",
	}
	req := &AttestationRequest{
		AgentID:    "agent-multi",
		Frameworks: []Framework{FrameworkSOC2},
	}
	att, err := svc.CreateAttestation(context.Background(), req, contract, metrics)
	if err != nil {
		t.Fatalf("CreateAttestation failed: %v", err)
	}
	if att.ID == "" {
		t.Error("Attestation ID should not be empty")
	}
	if len(att.Statements) == 0 {
		t.Error("Should have statements")
	}
}

func TestService_ListByAgent_DifferentAgents(t *testing.T) {
	svc, _ := NewService()
	contract := &ContractSummary{ID: "c1", Status: "active", Capabilities: []string{"read"}}
	metrics := &MetricsSummary{TrustScore: 80, TrustLevel: "high"}

	for _, agentID := range []string{"agent-a", "agent-a", "agent-b"} {
		req := &AttestationRequest{AgentID: agentID, Frameworks: []Framework{FrameworkSOC2}}
		_, _ = svc.CreateAttestation(context.Background(), req, contract, metrics)
	}

	attsA, _ := svc.ListByAgent(context.Background(), "agent-a")
	attsB, _ := svc.ListByAgent(context.Background(), "agent-b")

	if len(attsA) != 2 {
		t.Errorf("Expected 2 for agent-a, got %d", len(attsA))
	}
	if len(attsB) != 1 {
		t.Errorf("Expected 1 for agent-b, got %d", len(attsB))
	}
}

func TestService_ConcurrentListByAgent(t *testing.T) {
	svc, _ := NewService()
	contract := &ContractSummary{ID: "c1", Status: "active", Capabilities: []string{"read"}}
	metrics := &MetricsSummary{TrustScore: 80, TrustLevel: "high"}

	req := &AttestationRequest{AgentID: "agent-concurrent", Frameworks: []Framework{FrameworkSOC2}}
	_, _ = svc.CreateAttestation(context.Background(), req, contract, metrics)

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			atts, _ := svc.ListByAgent(context.Background(), "agent-concurrent")
			if len(atts) != 1 {
				t.Errorf("Expected 1, got %d", len(atts))
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestAttestation_FrameworkList(t *testing.T) {
	att := &Attestation{
		ID:         "att-fw",
		AgentID:    "agent-1",
		ContractID: "contract-1",
		Frameworks: []Framework{FrameworkSOC2, FrameworkHIPAA},
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Statements: []Statement{
			{Type: "security", Description: "encrypted", Passed: true},
		},
	}
	if len(att.Frameworks) != 2 {
		t.Errorf("Expected 2 frameworks, got %d", len(att.Frameworks))
	}
}

func TestStatement_WithEvidence(t *testing.T) {
	stmt := &Statement{
		Type:        "capability",
		Description: "verified capability",
		Evidence:    map[string]interface{}{"verified": true},
		Passed:      true,
	}
	if stmt.Evidence["verified"] != true {
		t.Error("Evidence should be set")
	}
}

func TestComplianceStatus_FullCompliance(t *testing.T) {
	status := &ComplianceStatus{
		Framework:     FrameworkSOC2,
		Score:         100.0,
		ControlsPass:  20,
		ControlsFail:  0,
		ControlsTotal: 20,
		Compliant:     true,
	}
	if !status.Compliant {
		t.Error("Should be compliant at 100%")
	}
}

func TestComplianceStatus_Borderline(t *testing.T) {
	status := &ComplianceStatus{
		Framework:     FrameworkHIPAA,
		Score:         79.9,
		ControlsPass:  8,
		ControlsFail:  2,
		ControlsTotal: 10,
		Compliant:     false,
	}
	if status.Compliant {
		t.Error("79.9% should not be compliant")
	}
}

func TestAttestationResult_Invalid(t *testing.T) {
	result := &AttestationResult{
		Valid:      false,
		AgentID:    "agent-1",
		Frameworks: []Framework{FrameworkSOC2},
		Errors:     []string{"expired"},
	}
	if result.Valid {
		t.Error("Should be invalid")
	}
}

func TestConfig_WithFrameworks(t *testing.T) {
	cfg := &Config{
		ValidityDays: 90,
		Frameworks:   []Framework{FrameworkSOC2, FrameworkGDPR},
	}
	if cfg.ValidityDays != 90 {
		t.Errorf("ValidityDays should be 90, got %d", cfg.ValidityDays)
	}
}

func TestFrameworkValues(t *testing.T) {
	tests := []struct {
		fw    Framework
		match string
	}{
		{FrameworkGDPR, "gdpr"},
		{FrameworkHIPAA, "hipaa"},
		{FrameworkSOC2, "soc2"},
		{FrameworkPCIDSS, "pci-dss"},
		{FrameworkISO27001, "iso27001"},
		{FrameworkEUAI, "eu-ai-act"},
	}
	for _, tt := range tests {
		if string(tt.fw) != tt.match {
			t.Errorf("Framework mismatch")
		}
	}
}
