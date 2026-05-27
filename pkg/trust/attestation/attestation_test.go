package attestation

import (
	"context"
	"testing"
	"time"
)

func TestNewGenerator(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}
	if gen == nil {
		t.Fatal("Generator should not be nil")
	}
}

func TestGenerator_Generate(t *testing.T) {
	gen, _ := NewGenerator()
	req := &AttestationRequest{AgentID: "agent-123", Frameworks: []Framework{FrameworkGDPR}, ValidFor: 24 * time.Hour}
	contract := &ContractSummary{ID: "contract-1", Capabilities: []string{"file:read"}, Status: "active"}
	metrics := &MetricsSummary{TrustScore: 85.0, TrustLevel: "high", PIIDetections: 5}
	att, err := gen.Generate(req, contract, metrics)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if att.ID == "" {
		t.Error("Attestation ID should not be empty")
	}
	if len(att.Signature) == 0 {
		t.Error("Signature should not be empty")
	}
}

func TestGenerator_Generate_NoAgentID(t *testing.T) {
	gen, _ := NewGenerator()
	req := &AttestationRequest{Frameworks: []Framework{FrameworkGDPR}}
	_, err := gen.Generate(req, nil, nil)
	if err == nil {
		t.Error("Expected error for missing agent ID")
	}
}

func TestGenerator_Generate_NoFrameworks(t *testing.T) {
	gen, _ := NewGenerator()
	req := &AttestationRequest{AgentID: "agent-1"}
	_, err := gen.Generate(req, nil, nil)
	if err == nil {
		t.Error("Expected error for missing frameworks")
	}
}

func TestGenerator_FrameworkStatement(t *testing.T) {
	gen, _ := NewGenerator()
	metrics := &MetricsSummary{TrustScore: 85.0, PIIDetections: 5}
	for _, fw := range []Framework{FrameworkGDPR, FrameworkHIPAA, FrameworkSOC2, FrameworkPCIDSS, FrameworkISO27001, FrameworkEUAI} {
		stmt := gen.frameworkStatement(fw, metrics)
		if stmt.Type == "" {
			t.Errorf("Statement type should not be empty for %s", fw)
		}
	}
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("Validator should not be nil")
	}
}

func TestValidator_Verify(t *testing.T) {
	gen, _ := NewGenerator()
	v := NewValidator()
	req := &AttestationRequest{AgentID: "agent-1", Frameworks: []Framework{FrameworkGDPR}}
	att, _ := gen.Generate(req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
	result, err := v.Verify(att)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !result.Valid {
		t.Error("Attestation should be valid")
	}
}

func TestNewService(t *testing.T) {
	svc, err := NewService()
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	if svc == nil {
		t.Fatal("Service should not be nil")
	}
}

func TestService_CreateAttestation(t *testing.T) {
	svc, _ := NewService()
	req := &AttestationRequest{AgentID: "agent-1", Frameworks: []Framework{FrameworkGDPR}}
	att, err := svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
	if err != nil {
		t.Fatalf("CreateAttestation failed: %v", err)
	}
	if att.ID == "" {
		t.Error("Attestation ID should not be empty")
	}
}

func TestService_GetAttestation(t *testing.T) {
	svc, _ := NewService()
	req := &AttestationRequest{AgentID: "agent-1", Frameworks: []Framework{FrameworkGDPR}}
	att, _ := svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
	got, err := svc.GetAttestation(context.Background(), att.ID)
	if err != nil {
		t.Fatalf("GetAttestation failed: %v", err)
	}
	if got.ID != att.ID {
		t.Error("ID mismatch")
	}
}

func TestService_GetAttestation_NotFound(t *testing.T) {
	svc, _ := NewService()
	_, err := svc.GetAttestation(context.Background(), "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent attestation")
	}
}

func TestService_VerifyAttestation(t *testing.T) {
	svc, _ := NewService()
	req := &AttestationRequest{AgentID: "agent-1", Frameworks: []Framework{FrameworkGDPR}}
	att, _ := svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
	result, err := svc.VerifyAttestation(context.Background(), att)
	if err != nil {
		t.Fatalf("VerifyAttestation failed: %v", err)
	}
	if !result.Valid {
		t.Error("Attestation should be valid")
	}
}

func TestService_ListByAgent(t *testing.T) {
	svc, _ := NewService()
	req := &AttestationRequest{AgentID: "agent-1", Frameworks: []Framework{FrameworkGDPR}}
	svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
	list, err := svc.ListByAgent(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("ListByAgent failed: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("Expected 1 attestation, got %d", len(list))
	}
}

func TestService_RevokeAttestation(t *testing.T) {
	svc, _ := NewService()
	req := &AttestationRequest{AgentID: "agent-1", Frameworks: []Framework{FrameworkGDPR}}
	att, _ := svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
	err := svc.RevokeAttestation(context.Background(), att.ID)
	if err != nil {
		t.Fatalf("RevokeAttestation failed: %v", err)
	}
}

func TestService_GenerateComplianceReport(t *testing.T) {
	svc, _ := NewService()
	req := &AttestationRequest{AgentID: "agent-1", Frameworks: []Framework{FrameworkGDPR}}
	svc.CreateAttestation(context.Background(), req, &ContractSummary{ID: "c1", Status: "active"}, &MetricsSummary{TrustScore: 85.0})
	report, err := svc.GenerateComplianceReport(context.Background(), "agent-1", []Framework{FrameworkGDPR})
	if err != nil {
		t.Fatalf("GenerateComplianceReport failed: %v", err)
	}
	if report == nil {
		t.Fatal("Report should not be nil")
	}
}

func TestFrameworkConstants(t *testing.T) {
	for _, fw := range []Framework{FrameworkGDPR, FrameworkHIPAA, FrameworkSOC2, FrameworkPCIDSS, FrameworkISO27001, FrameworkEUAI} {
		if fw == "" {
			t.Error("Framework constant should not be empty")
		}
	}
}

func TestComplianceStatus(t *testing.T) {
	status := &ComplianceStatus{Framework: FrameworkGDPR, Score: 85.0, ControlsPass: 17, ControlsFail: 3, ControlsTotal: 20, Compliant: true}
	if status.Score != 85.0 {
		t.Errorf("Score should be 85.0, got %f", status.Score)
	}
}
