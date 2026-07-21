// SPDX-License-Identifier: Apache-2.0
// ISO/IEC 42001 AI Management System Module - Unit Tests
//
// Test coverage target: 80%+ per pkg/compliance coverage floor.

package iso42001

import (
	"context"
	"strings"
	"testing"
)

func TestNewISO42001Module(t *testing.T) {
	m := NewISO42001Module()
	if m == nil {
		t.Fatal("NewISO42001Module returned nil")
	}
	if m.Framework() != "iso_42001" {
		t.Errorf("Framework() = %q, want iso_42001", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0", m.Version())
	}

	// Verify all 8 controls are registered
	controls := m.Controls()
	if len(controls) != 8 {
		t.Errorf("len(Controls()) = %d, want 8", len(controls))
	}

	// Verify the 5 automated control IDs are present
	automated := map[string]bool{
		"ISO42001-5.2": false,
		"ISO42001-6.1": false,
		"ISO42001-7.5": false,
		"ISO42001-8.2": false,
		"ISO42001-9.1": false,
	}
	for _, c := range controls {
		if _, ok := automated[c.ID]; ok {
			automated[c.ID] = true
			if !c.Automated {
				t.Errorf("Control %s should be automated", c.ID)
			}
			if c.CheckFunc == nil {
				t.Errorf("Control %s has nil CheckFunc", c.ID)
			}
		}
	}
	for id, found := range automated {
		if !found {
			t.Errorf("Automated control %s not registered", id)
		}
	}
}

func TestCheckAIPolicy(t *testing.T) {
	m := NewISO42001Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (policy + communicated)",
			input:      `{"ai_policy": "url", "communicated": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (acceptable use policy)",
			input:      `{"acceptable_use_policy": "url", "published": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (policy exists, no communication)",
			input:      `{"ai_policy": "url"}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no policy)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAIPolicy(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAIPolicy: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckRiskAssessment(t *testing.T) {
	m := NewISO42001Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (3+ risk patterns)",
			input:      `{"risk_assessment": true, "ai_risk": true, "adversarial_risk": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (2 risk patterns)",
			input:      `{"risk_assessment": true, "threat_model": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (1 risk pattern)",
			input:      `{"risk_assessment": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no risk patterns)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRiskAssessment(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRiskAssessment: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckDocumentedInfo(t *testing.T) {
	m := NewISO42001Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (all 4 documented info types)",
			input:      `{"statement_of_applicability": true, "risk_register": true, "audit_log": true, "compliance_report": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (3 types)",
			input:      `{"statement_of_applicability": true, "audit_log": true, "compliance_report": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (1 type)",
			input:      `{"audit_log": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no documented info)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkDocumentedInfo(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkDocumentedInfo: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckRiskTreatment(t *testing.T) {
	m := NewISO42001Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (treatment + block)",
			input:      `{"risk_treatment": true, "block": "enabled"}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (treatment + audit_log)",
			input:      `{"treatment_plan": true, "audit_log": "enabled"}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (treatment, no measurable controls)",
			input:      `{"risk_treatment": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no treatment)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRiskTreatment(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRiskTreatment: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckMonitoring(t *testing.T) {
	m := NewISO42001Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (all 3: metrics + dashboard + alerting)",
			input:      `{"prometheus": "enabled", "grafana": "enabled", "pagerduty": "configured"}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (metrics + dashboard)",
			input:      `{"metric": "enabled", "dashboard": "enabled"}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (only metrics)",
			input:      `{"prometheus": "enabled"}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no monitoring)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMonitoring(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMonitoring: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestISO42001Module_AllAutomatedChecks(t *testing.T) {
	// Integration-style: all 5 automated checks on a fully compliant config.
	m := NewISO42001Module()
	ctx := context.Background()

	compliantConfig := `{
		"ai_policy": "url",
		"acceptable_use_policy": "url",
		"communicated": true,
		"published": true,
		"risk_assessment": true,
		"ai_risk": true,
		"threat_model": true,
		"adversarial_risk": true,
		"statement_of_applicability": true,
		"risk_register": true,
		"audit_log": true,
		"compliance_report": true,
		"risk_treatment": true,
		"treatment_plan": true,
		"block": "enabled",
		"prometheus": "enabled",
		"grafana": "enabled",
		"pagerduty": "configured"
	}`

	checkFns := map[string]func(context.Context, []byte) (string, string){
		"ISO42001-5.2": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAIPolicy(c, b)
			return string(r.Status), r.Message
		},
		"ISO42001-6.1": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkRiskAssessment(c, b)
			return string(r.Status), r.Message
		},
		"ISO42001-7.5": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDocumentedInfo(c, b)
			return string(r.Status), r.Message
		},
		"ISO42001-8.2": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkRiskTreatment(c, b)
			return string(r.Status), r.Message
		},
		"ISO42001-9.1": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkMonitoring(c, b)
			return string(r.Status), r.Message
		},
	}

	for controlID, checkFn := range checkFns {
		t.Run(controlID, func(t *testing.T) {
			status, msg := checkFn(ctx, []byte(compliantConfig))
			if status != "compliant" {
				t.Errorf("Control %s on compliant config: status=%s, msg=%s",
					controlID, status, msg)
			}
		})
	}
}

func TestISO42001Module_Dependencies(t *testing.T) {
	m := NewISO42001Module()
	deps := m.Dependencies()
	if len(deps) != 3 {
		t.Errorf("Dependencies() returned %d items, want 3", len(deps))
	}
	depsStr := strings.Join(deps, ",")
	for _, expected := range []string{"scanner", "trust", "metrics"} {
		if !strings.Contains(depsStr, expected) {
			t.Errorf("Dependencies() should include %q", expected)
		}
	}
}
