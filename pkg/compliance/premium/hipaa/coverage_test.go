//go:build !race

package hipaa

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestHIPAAFramework_CheckRequest(t *testing.T) {
	hf := NewHIPAAFramework()
	req := &common.HTTPRequest{
		Method:     "POST",
		URL:        "https://example.com/api/patient",
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"ssn": "123-45-6789"}`),
		RemoteAddr: "192.168.1.1:12345",
	}
	findings, err := hf.CheckRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("CheckRequest() error: %v", err)
	}
	// CheckRequest returns empty slice per implementation
	if findings == nil {
		t.Error("CheckRequest() returned nil findings slice, expected empty slice")
	}
}

func TestHIPAAFramework_CheckResponse(t *testing.T) {
	hf := NewHIPAAFramework()
	resp := &common.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"patient": "John Doe", "diagnosis": "flu"}`),
	}
	findings, err := hf.CheckResponse(context.Background(), resp)
	if err != nil {
		t.Fatalf("CheckResponse() error: %v", err)
	}
	// CheckResponse returns empty slice per implementation
	if findings == nil {
		t.Error("CheckResponse() returned nil findings slice, expected empty slice")
	}
}

func TestHIPAAFramework_GetDescription(t *testing.T) {
	hf := NewHIPAAFramework()
	desc := hf.GetDescription()
	if desc != "HIPAA compliance for healthcare AI systems" {
		t.Errorf("GetDescription() = %q, want %q", desc, "HIPAA compliance for healthcare AI systems")
	}
}

func TestHIPAAFramework_Configure(t *testing.T) {
	hf := NewHIPAAFramework()
	config := map[string]interface{}{
		"strict_mode":   true,
		"phi_detection": true,
	}
	err := hf.Configure(config)
	if err != nil {
		t.Fatalf("Configure() error: %v", err)
	}
}

func TestHIPAAFramework_GetSeverityLevels(t *testing.T) {
	hf := NewHIPAAFramework()
	levels := hf.GetSeverityLevels()
	if len(levels) != 4 {
		t.Fatalf("GetSeverityLevels() returned %d levels, want 4", len(levels))
	}
	expected := []common.Severity{
		common.SeverityLow,
		common.SeverityMedium,
		common.SeverityHigh,
		common.SeverityCritical,
	}
	for i, level := range levels {
		if level != expected[i] {
			t.Errorf("GetSeverityLevels()[%d] = %v, want %v", i, level, expected[i])
		}
	}
}

func TestHIPAAFramework_InterfaceCompliance(t *testing.T) {
	var _ common.Framework = (*HIPAAFramework)(nil)
}

func TestHIPAAFramework_CheckRequest_EmptyBody(t *testing.T) {
	hf := NewHIPAAFramework()
	req := &common.HTTPRequest{
		Method:  "GET",
		URL:     "https://example.com/health",
		Headers: map[string][]string{},
		Body:    nil,
	}
	findings, err := hf.CheckRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("CheckRequest() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("CheckRequest with empty body returned %d findings, want 0", len(findings))
	}
}

func TestHIPAAFramework_CheckResponse_EmptyBody(t *testing.T) {
	hf := NewHIPAAFramework()
	resp := &common.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string][]string{},
		Body:       nil,
	}
	findings, err := hf.CheckResponse(context.Background(), resp)
	if err != nil {
		t.Fatalf("CheckResponse() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("CheckResponse with empty body returned %d findings, want 0", len(findings))
	}
}

func TestHIPAAFramework_Configure_NilConfig(t *testing.T) {
	hf := NewHIPAAFramework()
	err := hf.Configure(nil)
	if err != nil {
		t.Fatalf("Configure(nil) error: %v", err)
	}
}
