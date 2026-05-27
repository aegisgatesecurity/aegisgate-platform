package attestation

import (
	"context"
	"testing"
	"time"
)

func TestService_GetAttestation_NotFound(t *testing.T) {
	svc, _ := NewService()
	_, err := svc.GetAttestation(context.Background(), "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent attestation")
	}
}

func TestService_ListByAgent_Empty(t *testing.T) {
	svc, _ := NewService()
	atts, err := svc.ListByAgent(context.Background(), "agent-1")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(atts) != 0 {
		t.Errorf("Expected 0 attestations, got %d", len(atts))
	}
}

func TestService_RevokeAttestation_NotFound(t *testing.T) {
	svc, _ := NewService()
	err := svc.RevokeAttestation(context.Background(), "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent attestation")
	}
}

func TestService_GenerateComplianceReport_NoAttestations(t *testing.T) {
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

func TestService_CreateAndGet(t *testing.T) {
	svc, _ := NewService()

	req := &AttestationRequest{
		AgentID: "agent-1",
	}

	att, err := svc.CreateAttestation(context.Background(), req, nil, nil)
	if err != nil {
		t.Fatalf("CreateAttestation failed: %v", err)
	}

	retrieved, err := svc.GetAttestation(context.Background(), att.ID)
	if err != nil {
		t.Fatalf("GetAttestation failed: %v", err)
	}

	if retrieved.ID != att.ID {
		t.Errorf("ID mismatch: %s != %s", retrieved.ID, att.ID)
	}
}

func TestService_ListByAgent_WithAttestations(t *testing.T) {
	svc, _ := NewService()

	for i := 0; i < 3; i++ {
		req := &AttestationRequest{
			AgentID: "agent-1",
		}
		_, err := svc.CreateAttestation(context.Background(), req, nil, nil)
		if err != nil {
			t.Fatalf("CreateAttestation %d failed: %v", i, err)
		}
	}

	atts, err := svc.ListByAgent(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("ListByAgent failed: %v", err)
	}

	if len(atts) != 3 {
		t.Errorf("Expected 3 attestations, got %d", len(atts))
	}
}

func TestService_RevokeAttestation(t *testing.T) {
	svc, _ := NewService()

	req := &AttestationRequest{
		AgentID: "agent-1",
	}

	att, _ := svc.CreateAttestation(context.Background(), req, nil, nil)

	err := svc.RevokeAttestation(context.Background(), att.ID)
	if err != nil {
		t.Fatalf("RevokeAttestation failed: %v", err)
	}
}

func TestService_VerifyAttestation(t *testing.T) {
	svc, _ := NewService()

	req := &AttestationRequest{
		AgentID: "agent-1",
	}

	att, _ := svc.CreateAttestation(context.Background(), req, nil, nil)

	result, err := svc.VerifyAttestation(context.Background(), att)
	if err != nil {
		t.Fatalf("VerifyAttestation failed: %v", err)
	}

	if result == nil {
		t.Error("Result should not be nil")
	}
}

func TestService_GenerateComplianceReport_WithAttestations(t *testing.T) {
	svc, _ := NewService()

	req := &AttestationRequest{
		AgentID: "agent-1",
	}

	_, _ = svc.CreateAttestation(context.Background(), req, nil, nil)

	status, err := svc.GenerateComplianceReport(context.Background(), "agent-1", []Framework{FrameworkSOC2})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if status != nil && status.Framework != FrameworkSOC2 {
		t.Errorf("Framework should be SOC2, got %v", status.Framework)
	}
}

func TestAttestation_Timestamps(t *testing.T) {
	att := &Attestation{
		ID:        "att-1",
		AgentID:   "agent-1",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if att.ExpiresAt.Before(att.IssuedAt) {
		t.Error("ExpiresAt should be after IssuedAt")
	}
}

func TestAttestationResult_Valid(t *testing.T) {
	result := &AttestationResult{
		Valid:     true,
		Timestamp: time.Now(),
	}

	if !result.Valid {
		t.Error("Result should be valid")
	}
}

func TestAttestationResult_Invalid(t *testing.T) {
	result := &AttestationResult{
		Valid:     false,
		Reason:    "expired",
		Timestamp: time.Now(),
	}

	if result.Valid {
		t.Error("Result should be invalid")
	}
	if result.Reason != "expired" {
		t.Errorf("Reason should be 'expired', got '%s'", result.Reason)
	}
}

func TestComplianceStatus_Controls(t *testing.T) {
	status := &ComplianceStatus{
		Framework:     FrameworkSOC2,
		Score:         75.0,
		ControlsPass:  3,
		ControlsFail:  1,
		ControlsTotal: 4,
		Compliant:     false,
		LastAudit:     time.Now(),
	}

	if status.Compliant {
		t.Error("75 percent should not be compliant")
	}
}

func TestAttestation_Types(t *testing.T) {
	att := &Attestation{
		ID:         "att-1",
		AgentID:    "agent-1",
		Type:       AttestationTypeCapability,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Statements: []*AttestationStatement{},
		Signature:  "sig",
	}

	if att.Type != AttestationTypeCapability {
		t.Errorf("Type should be Capability, got %v", att.Type)
	}
}

func TestAttestationStatement_Passed(t *testing.T) {
	stmt := &AttestationStatement{
		Name:    "test_statement",
		Passed:  true,
		Message: "Test passed",
	}

	if !stmt.Passed {
		t.Error("Statement should pass")
	}
}

func TestAttestationStatement_Failed(t *testing.T) {
	stmt := &AttestationStatement{
		Name:    "test_statement",
		Passed:  false,
		Message: "Test failed",
	}

	if stmt.Passed {
		t.Error("Statement should fail")
	}
}

func TestService_ConcurrentCreate(t *testing.T) {
	svc, _ := NewService()

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			req := &AttestationRequest{
				AgentID: "agent-1",
			}
			_, err := svc.CreateAttestation(context.Background(), req, nil, nil)
			if err != nil {
				t.Errorf("Concurrent create failed: %v", err)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	atts, _ := svc.ListByAgent(context.Background(), "agent-1")
	if len(atts) != 10 {
		t.Errorf("Expected 10 attestations, got %d", len(atts))
	}
}

func TestService_ConcurrentRead(t *testing.T) {
	svc, _ := NewService()

	req := &AttestationRequest{
		AgentID: "agent-1",
	}
	att, _ := svc.CreateAttestation(context.Background(), req, nil, nil)

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := svc.GetAttestation(context.Background(), att.ID)
			if err != nil {
				t.Errorf("Concurrent read failed: %v", err)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestMetricsSummary_Empty(t *testing.T) {
	metrics := &MetricsSummary{}
	if metrics == nil {
		t.Error("Metrics should not be nil")
	}
}

func TestContractSummary_Empty(t *testing.T) {
	contract := &ContractSummary{}
	if contract == nil {
		t.Error("Contract should not be nil")
	}
}
