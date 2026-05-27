package attestation

import (
	"context"
	"testing"
)

func TestServiceListByAgent(t *testing.T) {
	svc, _ := NewService()

	atts, err := svc.ListByAgent(context.Background(), "agent-1")
	if err != nil {
		t.Errorf("ListByAgent failed: %v", err)
	}
	_ = atts
}

func TestServiceGenerateComplianceReport(t *testing.T) {
	svc, _ := NewService()

	report, err := svc.GenerateComplianceReport(context.Background(), "agent-1", []Framework{FrameworkGDPR})
	if err != nil {
		t.Errorf("GenerateComplianceReport failed: %v", err)
	}
	_ = report
}

func TestValidatorValidateStatement(t *testing.T) {
	validator := NewValidator()

	stmt := &Statement{
		Type:        "capability_statement",
		Description: "test",
		Evidence:    map[string]interface{}{"key": "value"},
		Passed:      true,
	}

	err := validator.ValidateStatement(stmt)
	if err != nil {
		t.Errorf("ValidateStatement failed: %v", err)
	}
}

func TestParseSignature(t *testing.T) {
	r, s, err := ParseSignature(nil)
	if err == nil {
		t.Error("ParseSignature(nil) should error")
	}
	_ = r
	_ = s
}
