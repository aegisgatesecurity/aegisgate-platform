//go:build !race

package pci

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestPCIFramework_CheckRequest(t *testing.T) {
	pf := NewPCIFramework()
	req := &common.HTTPRequest{
		Method:  "POST",
		URL:     "https://payment.example.com/charge",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(`{"card_number": "4111111111111111"}`),
	}
	findings, err := pf.CheckRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("CheckRequest() error: %v", err)
	}
	// CheckRequest returns empty slice per implementation
	if findings == nil {
		t.Error("CheckRequest() returned nil findings slice, expected empty slice")
	}
}

func TestPCIFramework_CheckResponse(t *testing.T) {
	pf := NewPCIFramework()
	resp := &common.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"transaction_id": "txn_1234"}`),
	}
	findings, err := pf.CheckResponse(context.Background(), resp)
	if err != nil {
		t.Fatalf("CheckResponse() error: %v", err)
	}
	// CheckResponse returns empty slice per implementation
	if findings == nil {
		t.Error("CheckResponse() returned nil findings slice, expected empty slice")
	}
}

func TestPCIFramework_InterfaceCompliance(t *testing.T) {
	var _ common.Framework = (*PCIFramework)(nil)
}

func TestPCIFramework_CheckRequest_WithHeaders(t *testing.T) {
	pf := NewPCIFramework()
	req := &common.HTTPRequest{
		Method: "GET",
		URL:    "https://payment.example.com/balance",
		Headers: map[string][]string{
			"Authorization": {"Bearer token123"},
			"Content-Type":  {"application/json"},
		},
		Body: nil,
	}
	findings, err := pf.CheckRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("CheckRequest() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("CheckRequest returned %d findings, expected 0", len(findings))
	}
}

func TestPCIFramework_CheckResponse_StatusCodes(t *testing.T) {
	pf := NewPCIFramework()
	tests := []struct {
		name       string
		statusCode int
	}{
		{"OK response", 200},
		{"Client error response", 400},
		{"Server error response", 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &common.HTTPResponse{
				StatusCode: tt.statusCode,
				Headers:    map[string][]string{},
				Body:       []byte("response body"),
			}
			findings, err := pf.CheckResponse(context.Background(), resp)
			if err != nil {
				t.Fatalf("CheckResponse() error: %v", err)
			}
			if findings == nil {
				t.Error("CheckResponse() returned nil findings slice")
			}
		})
	}
}
