// SPDX-License-Identifier: Apache-2.0
// CSA STAR (Cloud Controls Matrix) Compliance Module - Unit Tests
// v3.x Tier 1: 16/16 CCM domains tested.

package csa_star

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewCSASTARModule(t *testing.T) {
	m := NewCSASTARModule()
	if m == nil {
		t.Fatal("NewCSASTARModule returned nil")
	}
	if m.Framework() != "csa_star" {
		t.Errorf("Framework() = %q, want csa_star", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0 (v3.x Tier 1 new module)", m.Version())
	}
	controls := m.Controls()
	if len(controls) != 16 {
		t.Errorf("len(Controls()) = %d, want 16 (v3.x Tier 1: 16 of 16 CCM domains)", len(controls))
	}
	for _, c := range controls {
		if !c.Automated {
			t.Errorf("Control %s should be automated", c.ID)
		}
		if c.CheckFunc == nil {
			t.Errorf("Control %s has nil CheckFunc", c.ID)
		}
	}
}

func TestCSASTARControlIDsPresent(t *testing.T) {
	m := NewCSASTARModule()
	haveIDs := make(map[string]bool)
	for _, c := range m.Controls() {
		haveIDs[c.ID] = true
	}
	expected := []string{
		"CSA-STAR-AIS", "CSA-STAR-AAI", "CSA-STAR-BCR", "CSA-STAR-CBK",
		"CSA-STAR-CEK", "CSA-STAR-DSP", "CSA-STAR-GRC", "CSA-STAR-HRS",
		"CSA-STAR-IAM", "CSA-STAR-IKY", "CSA-STAR-IPY", "CSA-STAR-IVS",
		"CSA-STAR-LOG", "CSA-STAR-STA", "CSA-STAR-SEF", "CSA-STAR-TVM",
	}
	for _, id := range expected {
		if !haveIDs[id] {
			t.Errorf("Expected control %s not registered", id)
		}
	}
}

func TestCSASTAR_Logging(t *testing.T) {
	m := NewCSASTARModule()
	ctx := context.Background()
	t.Run("compliant", func(t *testing.T) {
		input := []byte("audit_log anomaly_detection alerting siem")
		r, err := m.checkLogging(ctx, input)
		if err != nil {
			t.Fatalf("checkLogging: %v", err)
		}
		if string(r.Status) != "compliant" {
			t.Errorf("Status = %s, want compliant (msg: %q)", r.Status, r.Message)
		}
	})
	t.Run("partial", func(t *testing.T) {
		input := []byte("audit_log alerting")
		r, err := m.checkLogging(ctx, input)
		if err != nil {
			t.Fatalf("checkLogging: %v", err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("Status = %s, want partial", r.Status)
		}
	})
	t.Run("non_compliant", func(t *testing.T) {
		input := []byte("nothing_here")
		r, err := m.checkLogging(ctx, input)
		if err != nil {
			t.Fatalf("checkLogging: %v", err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("Status = %s, want non_compliant", r.Status)
		}
	})
}

func TestCSASTAR_AllAutomated(t *testing.T) {
	m := NewCSASTARModule()
	checks := map[string]func(context.Context, []byte) (*compliance.ControlCheckResult, error){
		"CSA-STAR-AIS": m.checkApplicationSecurity,
		"CSA-STAR-AAI": m.checkAuditAssurance,
		"CSA-STAR-BCR": m.checkBusinessContinuity,
		"CSA-STAR-CBK": m.checkChangeControl,
		"CSA-STAR-CEK": m.checkCryptography,
		"CSA-STAR-DSP": m.checkDataSecurity,
		"CSA-STAR-GRC": m.checkGovernance,
		"CSA-STAR-HRS": m.checkHRSecurity,
		"CSA-STAR-IAM": m.checkIAM,
		"CSA-STAR-IKY": m.checkInteroperability,
		"CSA-STAR-IPY": m.checkInfrastructure,
		"CSA-STAR-IVS": m.checkInventory,
		"CSA-STAR-LOG": m.checkLogging,
		"CSA-STAR-STA": m.checkSupplyChain,
		"CSA-STAR-SEF": m.checkIncidentManagement,
		"CSA-STAR-TVM": m.checkThreatVulnerability,
	}
	compliantConfig := []byte(`{
		"api_security": true, "input_validation": true, "owasp": true, "sast": true,
		"audit_log": true, "audit_review": true, "compliance_check": true, "audit_report": true,
		"business_continuity": true, "disaster_recovery": true, "redundancy": true, "backup": true,
		"change_management": true, "config_baseline": true, "config_drift": true, "change_approval": true,
		"aes_256": true, "rsa_2048": true, "key_management": true, "key_rotation": true,
		"data_classification": true, "pii_scanner": true, "encryption_at_rest": true, "data_retention": true,
		"risk_assessment": true, "compliance_review": true, "governance_policy": true, "audit_trail": true,
		"background_check": true, "security_awareness": true, "termination_process": true, "nda": true,
		"rbac": true, "mfa": true, "least_privilege": true, "access_review": true,
		"api_standards": true, "data_export": true, "open_formats": true, "portability": true,
		"network_security": true, "compute_hardening": true, "storage_encryption": true, "vulnerability_patching": true,
		"asset_inventory": true, "cmdb": true, "asset_discovery": true, "shadow_it": true,
		"audit_log": true, "anomaly_detection": true, "alerting": true, "siem": true,
		"vendor_inventory": true, "sbom": true, "vendor_assessment": true, "supply_chain_monitoring": true,
		"incident_response": true, "e_discovery": true, "forensic_log": true, "evidence_preservation": true,
		"vulnerability_scan": true, "govulncheck": true, "trivy": true, "patch_management": true
	}`)
	for controlID, checkFn := range checks {
		t.Run(controlID, func(t *testing.T) {
			r, err := checkFn(context.Background(), compliantConfig)
			if err != nil {
				t.Fatalf("check%s: %v", controlID, err)
			}
			if string(r.Status) != "compliant" {
				t.Errorf("Control %s on compliant config: status=%s, msg=%s",
					controlID, r.Status, r.Message)
			}
		})
	}
}

func TestCSASTARModule_Dependencies(t *testing.T) {
	m := NewCSASTARModule()
	deps := m.Dependencies()
	if len(deps) != 2 {
		t.Errorf("Dependencies() returned %d items, want 2", len(deps))
	}
}
