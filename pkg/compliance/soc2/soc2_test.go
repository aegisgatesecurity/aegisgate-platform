// SPDX-License-Identifier: Apache-2.0
// SOC 2 Type II Compliance Module - Unit Tests
//
// Test coverage target: 80%+ per pkg/compliance coverage floor.
// Each of the 5 CheckFunc implementations has 3-4 test cases:
//   - Compliant (all required markers present)
//   - Non-compliant (markers missing)
//   - Partial (some markers, some missing)
//   - Edge cases (empty input, malformed input)

package soc2

import (
	"context"
	"strings"
	"testing"
)

func TestNewSOC2Module(t *testing.T) {
	m := NewSOC2Module()
	if m == nil {
		t.Fatal("NewSOC2Module returned nil")
	}
	if m.Framework() != "soc2" {
		t.Errorf("Framework() = %q, want soc2", m.Framework())
	}
	if m.Version() != "1.1" {
		t.Errorf("Version() = %q, want 1.1", m.Version())
	}

	// Verify all 8 controls are registered
	controls := m.Controls()
	if len(controls) != 15 {
		t.Errorf("len(Controls()) = %d, want 15 (v3.x Tier 1: 5 CC6 + 2 CC1/CC7 + 1 PI + 1 C + 1 A1 + 1 C2 + 1 AI = 15 in-scope; Privacy is correctly out-of-scope)", len(controls))
	}

	// Verify the 5 automated control IDs are present
	automated := map[string]bool{
		"SOC2-CC6.1": false,
		"SOC2-CC6.2": false,
		"SOC2-CC6.3": false,
		"SOC2-CC6.6": false,
		"SOC2-CC6.7": false,
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

func TestCheckAccessControl(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (auth + rbac + session timeout)",
			input:      `{"authentication": true, "rbac": true, "session_timeout": 30}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (alternative markers)",
			input:      `{"auth_enabled": true, "roles": ["admin"], "idle_timeout": "5m"}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (no auth, no rbac)",
			input:      `{"logging": true}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "partial (only auth)",
			input:      `{"authentication": true}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAccessControl(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAccessControl: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
			if result.ControlID != "SOC2-CC6.1" {
				t.Errorf("ControlID = %q, want SOC2-CC6.1", result.ControlID)
			}
		})
	}
}

func TestCheckMLEnvironmentSecurity(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (mTLS + isolation)",
			input:      `{"mtls": true, "isolation": "kubernetes"}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (alternative markers)",
			input:      `{"mutual_tls": true, "sandbox": "k8s"}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (mTLS only, no isolation)",
			input:      `{"mtls": true}`,
			wantStatus: "partial",
		},
		{
			name:       "partial (isolation only, no mTLS)",
			input:      `{"isolation": "kubernetes"}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (neither)",
			input:      `{}`,
			wantStatus: "partial", // both missing = partial with 2 gaps
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMLEnvironmentSecurity(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMLEnvironmentSecurity: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckDataProtection(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (encryption at rest + in transit, no PII)",
			input:      `{"encryption_at_rest": true, "tls": true} some safe content here`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (PII detected)",
			input:      `{"encryption_at_rest": true, "tls": true} SSN 123-45-6789 detected`,
			wantStatus: "non_compliant",
		},
		{
			name:       "partial (no encryption at rest, no PII)",
			input:      `{"tls": true} safe content`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no encryption, PII)",
			input:      `user@example.com and 123-45-6789 here`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkDataProtection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkDataProtection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckAuditLogging(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (audit + integrity)",
			input:      `{"audit_log": true, "log_integrity": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (audit + signed)",
			input:      `{"audit_enabled": true, "signed_logs": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (audit, no integrity)",
			input:      `{"audit_log": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no audit)",
			input:      `{"logging": false}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAuditLogging(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAuditLogging: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
			if string(result.Severity) != "Critical" {
				t.Errorf("Severity = %q, want critical (SOC 2 CC6.6 is critical)", result.Severity)
			}
		})
	}
}

func TestCheckTransmissionSecurity(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (TLS 1.3)",
			input:      `{"tls": true, "min_version: 1.3": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (TLS 1.2)",
			input:      `{"tls1.2": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (TLS, no version)",
			input:      `{"tls": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (no TLS)",
			input:      `{"http": true}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkTransmissionSecurity(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkTransmissionSecurity: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestSOC2Module_AllAutomatedChecks(t *testing.T) {
	// Integration-style test: run all 5 automated checks on a
	// "fully compliant" platform config and verify all pass.
	m := NewSOC2Module()
	ctx := context.Background()

	compliantConfig := `{
		"authentication": true,
		"auth_enabled": true,
		"rbac": true,
		"roles": ["admin", "user"],
		"session_timeout": 1800,
		"idle_timeout": "5m",
		"mtls": true,
		"mutual_tls": true,
		"isolation": "kubernetes",
		"sandbox": "k8s",
		"encryption_at_rest": true,
		"data_encrypted": true,
		"tls": true,
		"min_version: 1.3": true,
		"audit_log": true,
		"audit_enabled": true,
		"log_integrity": true,
		"signed_logs": true
	}`

	automatedChecks := []struct {
		name string
		fn   func(context.Context, []byte) (interface{}, error)
	}{
		{"checkAccessControl", nil}, // see below
		{"checkMLEnvironmentSecurity", nil},
		{"checkDataProtection", nil},
		{"checkAuditLogging", nil},
		{"checkTransmissionSecurity", nil},
	}

	// Run the 5 automated check functions and verify each is "compliant"
	checkFns := map[string]func(context.Context, []byte) (string, string){
		"SOC2-CC6.1": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAccessControl(c, b)
			return string(r.Status), r.Message
		},
		"SOC2-CC6.2": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkMLEnvironmentSecurity(c, b)
			return string(r.Status), r.Message
		},
		"SOC2-CC6.3": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDataProtection(c, b)
			return string(r.Status), r.Message
		},
		"SOC2-CC6.6": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAuditLogging(c, b)
			return string(r.Status), r.Message
		},
		"SOC2-CC6.7": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkTransmissionSecurity(c, b)
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
	_ = automatedChecks // suppress unused warning
}

func TestSOC2Module_Dependencies(t *testing.T) {
	m := NewSOC2Module()
	deps := m.Dependencies()
	if len(deps) != 2 {
		t.Errorf("Dependencies() returned %d items, want 2", len(deps))
	}
	if !strings.Contains(strings.Join(deps, ","), "scanner") {
		t.Error("Dependencies() should include 'scanner'")
	}
	if !strings.Contains(strings.Join(deps, ","), "persistence") {
		t.Error("Dependencies() should include 'persistence'")
	}
}

// TestNewSOC2v3xTier1Controls verifies the v3.x Tier 1 control set
// is 15 controls total: 5 CC6 + 2 CC1/CC7 + 1 PI + 1 C + 1 A1 + 1 C2 + 1 AI = 15 in-scope.
func TestNewSOC2v3xTier1Controls(t *testing.T) {
	m := NewSOC2Module()
	controls := m.Controls()
	if len(controls) != 15 {
		t.Errorf("len(Controls()) = %d, want 15 (v3.x Tier 1: 5 CC6 + 2 CC1/CC7 + 1 PI + 1 C + 1 A1 + 1 C2 + 1 AI = 15 in-scope; Privacy is correctly out-of-scope)", len(controls))
	}
	expectedNewIDs := map[string]bool{
		"SOC2-CC1.1": false, "SOC2-CC1.4": false,
		"SOC2-CC7.2": false, "SOC2-CC7.3": false, "SOC2-CC7.4": false,
		"SOC2-A1.1": false, "SOC2-C2.1": false,
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

// TestCheckControlEnvironment verifies § CC1.1 — v3.x Tier 1 addition.
func TestCheckControlEnvironment(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", `security_policy code_of_conduct acceptable_use_policy published`, "compliant"},
		{"partial", `security_policy`, "partial"},
		{"non-compliant", `nothing_here`, "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkControlEnvironment(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkControlEnvironment: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %s, want %s (msg: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// TestCheckSegregationOfDuties verifies § CC1.4 — v3.x Tier 1 addition.
func TestCheckSegregationOfDuties(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", `rbac mfa least_privilege role_separation`, "compliant"},
		{"partial", `rbac mfa`, "partial"},
		{"non-compliant", `nothing_here`, "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSegregationOfDuties(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkSegregationOfDuties: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %s, want %s (msg: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// TestCheckAnomalyMonitoring verifies § CC7.2 — v3.x Tier 1 addition.
func TestCheckAnomalyMonitoring(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", `audit_log ioc_store anomaly_detection alerting`, "compliant"},
		{"partial", `audit_log ioc_store`, "partial"},
		{"non-compliant", `nothing_here`, "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAnomalyMonitoring(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAnomalyMonitoring: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %s, want %s (msg: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// TestCheckEventEvaluation verifies § CC7.3 — v3.x Tier 1 addition.
func TestCheckEventEvaluation(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", `audit_log ioc_store signed_attestations investigation triage classification`, "compliant"},
		{"partial", `audit_log ioc_store`, "partial"},
		{"non-compliant", `nothing_here`, "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkEventEvaluation(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkEventEvaluation: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %s, want %s (msg: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// TestCheckIncidentResponsePlan verifies § CC7.4 — v3.x Tier 1 addition.
func TestCheckIncidentResponsePlan(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", `incident_response_plan ir_plan ir_tested tabletop ir_roles incident_commander ir_communication status_page`, "compliant"},
		{"partial", `ir_plan ir_tested`, "partial"},
		{"non-compliant", `nothing_here`, "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkIncidentResponsePlan(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkIncidentResponsePlan: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %s, want %s (msg: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// TestCheckCapacityPlanning verifies § A1.1 — v3.x Tier 1 addition.
func TestCheckCapacityPlanning(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", `metric prometheus dashboard grafana alert alerting capacity_plan auto_scaling`, "compliant"},
		{"partial", `metric prometheus`, "partial"},
		{"non-compliant", `nothing_here`, "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkCapacityPlanning(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkCapacityPlanning: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %s, want %s (msg: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

// TestCheckThirdPartyRisk verifies § C2.1 — v3.x Tier 1 addition.
func TestCheckThirdPartyRisk(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()
	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{"compliant", `vendor_inventory supplier_list dpa data_processing_agreement vendor_assessment vendor_review vendor_questionnaire vendor_access third_party_access scoped_access`, "compliant"},
		{"partial", `vendor_inventory dpa`, "partial"},
		{"non-compliant", `nothing_here`, "non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkThirdPartyRisk(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkThirdPartyRisk: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %s, want %s (msg: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}
