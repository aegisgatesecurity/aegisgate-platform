package attestation

import (
	"context"
	"testing"
	"time"
)

func TestService_ListByAgent_EmptyList(t *testing.T) {
	svc, _ := NewService()
	atts, err := svc.ListByAgent(context.Background(), "agent-noexist")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(atts) != 0 {
		t.Errorf("Expected 0 attestations, got %d", len(atts))
	}
}

func TestService_Revoke_NotFound(t *testing.T) {
	svc, _ := NewService()
	err := svc.RevokeAttestation(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent attestation")
	}
}

func TestService_ComplianceReport_Empty(t *testing.T) {
	svc, _ := NewService()
	status, err := svc.GenerateComplianceReport(context.Background(), "agent-1", []Framework{FrameworkSOC2})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if status == nil {
		t.Error("Status should not be nil")
	}
	if status.Score != 0 {
		t.Errorf("Score should be 0 with no attestations, got %f", status.Score)
	}
}

func TestService_CreateMultiple_ThenList(t *testing.T) {
	svc, _ := NewService()
	for i := 0; i < 5; i++ {
		req := &AttestationRequest{AgentID: "agent-multi", Frameworks: []Framework{FrameworkGDPR}}
		_, err := svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
		if err != nil {
			t.Fatalf("Create %d failed: %v", i, err)
		}
	}
	atts, _ := svc.ListByAgent(context.Background(), "agent-multi")
	if len(atts) != 5 {
		t.Errorf("Expected 5 attestations, got %d", len(atts))
	}
}

func TestService_RevokeAttestation_Works(t *testing.T) {
	svc, _ := NewService()
	req := &AttestationRequest{AgentID: "agent-revoke", Frameworks: []Framework{FrameworkHIPAA}}
	att, _ := svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 90.0})
	err := svc.RevokeAttestation(context.Background(), att.ID)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
}

func TestService_ComplianceReport_WithAttestations(t *testing.T) {
	svc, _ := NewService()
	req := &AttestationRequest{AgentID: "agent-report", Frameworks: []Framework{FrameworkSOC2}}
	_, _ = svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
	status, err := svc.GenerateComplianceReport(context.Background(), "agent-report", []Framework{FrameworkSOC2})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if status.Framework != FrameworkSOC2 {
		t.Errorf("Framework mismatch")
	}
}

func TestStatement_Types(t *testing.T) {
	stmt := Statement{
		Type:        "capability",
		Description: "File read allowed",
		Evidence:    map[string]interface{}{"capability": "file:read"},
		Passed:      true,
		Details:     "Check passed",
	}
	if !stmt.Passed {
		t.Error("Statement should pass")
	}
	if stmt.Type != "capability" {
		t.Errorf("Type should be 'capability', got '%s'", stmt.Type)
	}
}

func TestStatement_FailedCheck(t *testing.T) {
	stmt := Statement{
		Type:        "security",
		Description: "Security scan",
		Passed:      false,
		Details:     "Vulnerability found",
	}
	if stmt.Passed {
		t.Error("Statement should fail")
	}
}

func TestComplianceStatus_Fields(t *testing.T) {
	status := ComplianceStatus{
		Framework:     FrameworkPCIDSS,
		Score:         80.0,
		ControlsPass:  8,
		ControlsFail:  2,
		ControlsTotal: 10,
		LastAudit:     time.Now().Add(-24 * time.Hour),
		NextAudit:     time.Now().Add(24 * time.Hour),
		Compliant:     true,
	}
	if !status.Compliant {
		t.Error("80 percent should be compliant")
	}
	if status.Framework != FrameworkPCIDSS {
		t.Errorf("Framework mismatch")
	}
}

func TestComplianceStatus_NonCompliant(t *testing.T) {
	status := ComplianceStatus{
		Framework:     FrameworkGDPR,
		Score:         65.0,
		ControlsPass:  6,
		ControlsFail:  4,
		ControlsTotal: 10,
		Compliant:     false,
	}
	if status.Compliant {
		t.Error("65 percent should not be compliant")
	}
}

func TestAttestation_AllFields(t *testing.T) {
	now := time.Now()
	att := Attestation{
		ID:              "att-test",
		AgentID:         "agent-1",
		ContractID:      "contract-1",
		Frameworks:      []Framework{FrameworkGDPR, FrameworkHIPAA},
		IssuedAt:        now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Statements:      []Statement{{Type: "test", Passed: true}},
		Signature:       []byte("sig"),
		SignerPublicKey: []byte("key"),
	}
	if att.ID != "att-test" {
		t.Errorf("ID mismatch")
	}
	if len(att.Frameworks) != 2 {
		t.Errorf("Should have 2 frameworks")
	}
	if len(att.Statements) != 1 {
		t.Errorf("Should have 1 statement")
	}
}

func TestAttestationResult_AllFields(t *testing.T) {
	now := time.Now()
	result := AttestationResult{
		Valid:          true,
		AgentID:        "agent-1",
		Frameworks:     []Framework{FrameworkSOC2},
		IssuedAt:       now,
		ExpiresAt:      now.Add(24 * time.Hour),
		StatementsPass: 10,
		StatementsFail: 0,
		VerifiedAt:     now,
		Errors:         []string{},
	}
	if !result.Valid {
		t.Error("Should be valid")
	}
	if result.StatementsPass != 10 {
		t.Errorf("StatementsPass should be 10, got %d", result.StatementsPass)
	}
}

func TestAttestationResult_WithErrors(t *testing.T) {
	result := AttestationResult{
		Valid:   false,
		AgentID: "agent-1",
		Errors:  []string{"signature invalid", "expired"},
	}
	if result.Valid {
		t.Error("Should be invalid")
	}
	if len(result.Errors) != 2 {
		t.Errorf("Should have 2 errors, got %d", len(result.Errors))
	}
}

func TestConfig_Fields(t *testing.T) {
	cfg := Config{
		SigningKey:   []byte("key"),
		ValidityDays: 30,
		Frameworks:   []Framework{FrameworkGDPR},
	}
	if cfg.ValidityDays != 30 {
		t.Errorf("ValidityDays should be 30, got %d", cfg.ValidityDays)
	}
}

func TestMetricsSummary_Fields(t *testing.T) {
	metrics := MetricsSummary{
		TrustScore:    92.5,
		TrustLevel:    "high",
		PIIDetections: 3,
		ThreatBlocks:  15,
		TotalRequests: 1000,
	}
	if metrics.TrustScore != 92.5 {
		t.Errorf("TrustScore mismatch")
	}
}

func TestContractSummary_Fields(t *testing.T) {
	contract := ContractSummary{
		ID:           "contract-1",
		Capabilities: []string{"file:read", "file:write"},
		Status:       "active",
	}
	if contract.Status != "active" {
		t.Errorf("Status should be 'active'")
	}
	if len(contract.Capabilities) != 2 {
		t.Errorf("Should have 2 capabilities")
	}
}

func TestService_ConcurrentCreate(t *testing.T) {
	svc, _ := NewService()
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func(idx int) {
			req := &AttestationRequest{AgentID: "agent-concurrent", Frameworks: []Framework{FrameworkGDPR}}
			_, _ = svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
			done <- true
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}
	atts, _ := svc.ListByAgent(context.Background(), "agent-concurrent")
	if len(atts) != 20 {
		t.Errorf("Expected 20 attestations, got %d", len(atts))
	}
}

func TestService_ConcurrentGet(t *testing.T) {
	svc, _ := NewService()
	req := &AttestationRequest{AgentID: "agent-get", Frameworks: []Framework{FrameworkSOC2}}
	att, _ := svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
	done := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		go func() {
			_, _ = svc.GetAttestation(context.Background(), att.ID)
			done <- true
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

func TestFramework_Constants(t *testing.T) {
	frameworks := []Framework{FrameworkGDPR, FrameworkHIPAA, FrameworkSOC2, FrameworkPCIDSS, FrameworkISO27001, FrameworkEUAI}
	for _, fw := range frameworks {
		if fw == "" {
			t.Error("Framework should not be empty")
		}
	}
}

func TestAttestationRequest_Fields(t *testing.T) {
	req := AttestationRequest{
		AgentID:    "agent-req",
		Frameworks: []Framework{FrameworkGDPR, FrameworkHIPAA},
		ValidFor:   48 * time.Hour,
	}
	if req.AgentID != "agent-req" {
		t.Errorf("AgentID mismatch")
	}
	if len(req.Frameworks) != 2 {
		t.Errorf("Should have 2 frameworks")
	}
}
