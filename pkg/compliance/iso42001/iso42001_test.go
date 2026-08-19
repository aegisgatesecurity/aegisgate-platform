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
	if m.Version() != "2.0" {
		t.Errorf("Version() = %q, want 1.1", m.Version())
	}

	// Verify all 38 controls are registered
	controls := m.Controls()
	if len(controls) != 38 {
		t.Errorf("len(Controls()) = %d, want 38", len(controls))
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

// TestNewISO42001v3xTier1Controls verifies the v3.x Tier 1 control set
// is 12 controls total: 4 admin + 1 leadership-policy + 1 planning +
// 1 support + 3 operation + 2 performance-evaluation + 2 AI = 12.
func TestNewISO42001v3xTier1Controls(t *testing.T) {
	m := NewISO42001Module()
	controls := m.Controls()
	if len(controls) != 38 {
		t.Errorf("len(Controls()) = %d, want 38", len(controls))
	}
	// Verify the 4 new control IDs are present
	expectedNewIDs := map[string]bool{
		"ISO42001-8.1": false,
		"ISO42001-8.3": false,
		"ISO42001-9.2": false,
		"ISO42001-9.3": false,
	}
	for _, c := range controls {
		if _, ok := expectedNewIDs[c.ID]; ok {
			expectedNewIDs[c.ID] = true
		}
	}
	for id, found := range expectedNewIDs {
		if !found {
			t.Errorf("Expected new control %s not registered", id)
		}
	}
}

// TestOperationalPlanningCheck verifies § 42001 8.1 — v3.x Tier 1 addition.
func TestOperationalPlanningCheck(t *testing.T) {
	m := NewISO42001Module()
	ctx := context.Background()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ai_policy documented published risk_register audit_log")
		result, err := m.checkOperationalPlanning(ctx, input)
		if err != nil {
			t.Fatalf("checkOperationalPlanning: %v", err)
		}
		if result.ControlID != "ISO42001-8.1" {
			t.Errorf("ControlID = %q, want ISO42001-8.1", result.ControlID)
		}
		if string(result.Status) != "compliant" {
			t.Errorf("Status = %s, want compliant (msg: %q)", result.Status, result.Message)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("ai_policy")
		result, err := m.checkOperationalPlanning(ctx, input)
		if err != nil {
			t.Fatalf("checkOperationalPlanning: %v", err)
		}
		if string(result.Status) != "partial" {
			t.Errorf("Status = %s, want partial", result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.checkOperationalPlanning(ctx, input)
		if err != nil {
			t.Fatalf("checkOperationalPlanning: %v", err)
		}
		if string(result.Status) != "non_compliant" {
			t.Errorf("Status = %s, want non_compliant", result.Status)
		}
	})
}

// TestChangeManagementCheck verifies § 42001 8.3 — v3.x Tier 1 addition.
func TestChangeManagementCheck(t *testing.T) {
	m := NewISO42001Module()
	ctx := context.Background()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("model_version attestation code_review rollback")
		result, err := m.checkChangeManagement(ctx, input)
		if err != nil {
			t.Fatalf("checkChangeManagement: %v", err)
		}
		if result.ControlID != "ISO42001-8.3" {
			t.Errorf("ControlID = %q, want ISO42001-8.3", result.ControlID)
		}
		if string(result.Status) != "compliant" {
			t.Errorf("Status = %s, want compliant", result.Status)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("model_version attestation")
		result, err := m.checkChangeManagement(ctx, input)
		if err != nil {
			t.Fatalf("checkChangeManagement: %v", err)
		}
		if string(result.Status) != "partial" {
			t.Errorf("Status = %s, want partial", result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.checkChangeManagement(ctx, input)
		if err != nil {
			t.Fatalf("checkChangeManagement: %v", err)
		}
		if string(result.Status) != "non_compliant" {
			t.Errorf("Status = %s, want non_compliant", result.Status)
		}
	})
}

// TestInternalAuditCheck verifies § 42001 9.2 — v3.x Tier 1 addition.
func TestInternalAuditCheck(t *testing.T) {
	m := NewISO42001Module()
	ctx := context.Background()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("audit_log audit_schedule audit_report")
		result, err := m.checkInternalAudit(ctx, input)
		if err != nil {
			t.Fatalf("checkInternalAudit: %v", err)
		}
		if result.ControlID != "ISO42001-9.2" {
			t.Errorf("ControlID = %q, want ISO42001-9.2", result.ControlID)
		}
		if string(result.Status) != "compliant" {
			t.Errorf("Status = %s, want compliant", result.Status)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("audit_log")
		result, err := m.checkInternalAudit(ctx, input)
		if err != nil {
			t.Fatalf("checkInternalAudit: %v", err)
		}
		if string(result.Status) != "partial" {
			t.Errorf("Status = %s, want partial", result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.checkInternalAudit(ctx, input)
		if err != nil {
			t.Fatalf("checkInternalAudit: %v", err)
		}
		if string(result.Status) != "non_compliant" {
			t.Errorf("Status = %s, want non_compliant", result.Status)
		}
	})
}

// TestManagementReviewCheck verifies § 42001 9.3 — v3.x Tier 1 addition.
func TestManagementReviewCheck(t *testing.T) {
	m := NewISO42001Module()
	ctx := context.Background()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ciso_digest management_review review_minutes action_items")
		result, err := m.checkManagementReview(ctx, input)
		if err != nil {
			t.Fatalf("checkManagementReview: %v", err)
		}
		if result.ControlID != "ISO42001-9.2" {
			t.Errorf("ControlID = %q, want ISO42001-9.2", result.ControlID)
		}
		if string(result.Status) != "compliant" {
			t.Errorf("Status = %s, want compliant", result.Status)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("ciso_digest")
		result, err := m.checkManagementReview(ctx, input)
		if err != nil {
			t.Fatalf("checkManagementReview: %v", err)
		}
		if string(result.Status) != "partial" {
			t.Errorf("Status = %s, want partial", result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.checkManagementReview(ctx, input)
		if err != nil {
			t.Fatalf("checkManagementReview: %v", err)
		}
		if string(result.Status) != "non_compliant" {
			t.Errorf("Status = %s, want non_compliant", result.Status)
		}
	})
}
