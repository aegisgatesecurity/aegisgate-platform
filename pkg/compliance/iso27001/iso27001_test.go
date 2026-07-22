// SPDX-License-Identifier: Apache-2.0
// ISO/IEC 27001:2022 Compliance Module - Unit Tests
// v3.x Tier 1: 60/93 in-scope controls tested.

package iso27001

import (
	"context"
	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"strings"
	"testing"
)

func TestNewISO27001Module(t *testing.T) {
	m := NewISO27001Module()
	if m == nil {
		t.Fatal("NewISO27001Module returned nil")
	}
	if m.Framework() != "iso_27001" {
		t.Errorf("Framework() = %q, want iso_27001", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0 (v3.x Tier 1 new module)", m.Version())
	}
	controls := m.Controls()
	if len(controls) != 67 {
		t.Errorf("len(Controls()) = %d, want 67 (v3.x Tier 1: 67 of 93 in-scope Annex A controls; revised count after implementation)", len(controls))
	}
	// Verify all 60 controls have CheckFunc
	for _, c := range controls {
		if !c.Automated {
			t.Errorf("Control %s should be automated", c.ID)
		}
		if c.CheckFunc == nil {
			t.Errorf("Control %s has nil CheckFunc", c.ID)
		}
	}
}

func TestISO27001ControlIDsPresent(t *testing.T) {
	m := NewISO27001Module()
	haveIDs := make(map[string]bool)
	for _, c := range m.Controls() {
		haveIDs[c.ID] = true
	}
	// Spot-check a few critical controls
	expected := []string{
		// Organizational
		"ISO27001-A.5.7", "ISO27001-A.5.10", "ISO27001-A.5.12", "ISO27001-A.5.19",
		"ISO27001-A.5.22", "ISO27001-A.5.23", "ISO27001-A.5.24", "ISO27001-A.5.26", "ISO27001-A.5.30",
		"ISO27001-A.5.31", "ISO27001-A.5.34", "ISO27001-A.5.37", "ISO27001-A.5.38",
		// People
		"ISO27001-A.6.3", "ISO27001-A.6.7", "ISO27001-A.6.8", "ISO27001-A.8.27",
		// Physical
		"ISO27001-A.7.4", "ISO27001-A.7.10", "ISO27001-A.7.13", "ISO27001-A.7.14",
		// Technological
		"ISO27001-A.8.1", "ISO27001-A.8.2", "ISO27001-A.8.5", "ISO27001-A.8.7",
		"ISO27001-A.8.8", "ISO27001-A.8.9", "ISO27001-A.8.15", "ISO27001-A.8.16",
		"ISO27001-A.8.20", "ISO27001-A.8.22", "ISO27001-A.8.24", "ISO27001-A.8.25",
		"ISO27001-A.8.26", "ISO27001-A.8.28", "ISO27001-A.8.29", "ISO27001-A.8.31",
		"ISO27001-A.8.32",
	}
	for _, id := range expected {
		if !haveIDs[id] {
			t.Errorf("Expected control %s not registered", id)
		}
	}
}

func TestISO27001Check_Compliant(t *testing.T) {
	m := NewISO27001Module()
	ctx := context.Background()
	// A "fully compliant" config that satisfies all 60 controls
	compliantConfig := []byte(`{
		"threat_intel": true, "ioc_store": true, "ioc_federation": true, "threat_feed": true,
		"acceptable_use": true, "aup": true, "usage_policy": true, "documented": true,
		"data_classification": true, "classification_label": true, "data_label": true, "public": true, "internal": true, "confidential": true,
		"data_labeling": true, "labeling": true, "tagging": true, "classification": true,
		"transfer_policy": true, "tls": true, "encryption": true, "secure_transfer": true,
		"cloud_security": true, "csp_assessment": true, "cloud_config": true, "shared_responsibility": true,
		"business_continuity": true, "disaster_recovery": true, "backup": true, "redundancy": true,
		"legal_review": true, "compliance_check": true, "regulatory_requirements": true, "contract_review": true,
		"pii_protection": true, "pii_scanner": true, "data_masking": true, "de_identification": true,
		"operating_procedures": true, "runbook": true, "sop": true, "documented": true,
		"security_awareness": true, "training_records": true, "phishing_test": true, "security_training": true,
		"disciplinary_process": true, "policy_violation": true, "consequence": true, "hr_process": true,
		"nda": true, "confidentiality_agreement": true, "non_disclosure": true, "signed_agreement": true,
		"vpn": true, "remote_access": true, "endpoint_protection": true, "device_encryption": true,
		"event_reporting": true, "alerting": true, "alert_channel": true, "incident_notification": true,
		"endpoint_security": true, "edr": true, "antivirus": true, "device_encryption": true,
		"physical_monitoring": true, "cctv": true, "badge_access": true, "security_log": true,
		"retention_policy": true, "media_disposal": true, "secure_erasure": true, "inventory": true,
		"maintenance_log": true, "equipment_inventory": true, "maintenance_schedule": true, "patching": true,
		"secure_disposal": true, "data_erasure": true, "asset_sanitization": true, "disposal_certificate": true,
		"endpoint_protection": true, "device_encryption": true, "edr": true, "device_compliance": true,
		"rbac": true, "privileged_access": true, "least_privilege": true, "pam": true,
		"access_control": true, "rbac": true, "least_privilege": true, "access_review": true,
		"authentication": true, "mfa": true, "multi_factor": true, "secure_session": true,
		"antivirus": true, "edr": true, "malware_scanner": true, "auto_update": true,
		"vulnerability_scan": true, "govulncheck": true, "trivy": true, "patch_management": true,
		"config_management": true, "baseline_config": true, "config_drift": true, "config_audit": true,
		"dlp": true, "data_classification": true, "egress_filter": true, "data_loss_prevention": true,
		"network_monitoring": true, "anomaly_detection": true, "alerting": true, "siem": true,
		"utility_restriction": true, "sudo_policy": true, "admin_audit": true, "privileged_session": true,
		"firewall": true, "network_segmentation": true, "ids": true, "ips": true,
		"network_service_agreement": true, "sla": true, "network_monitoring": true, "service_security": true,
		"network_segmentation": true, "vlan": true, "dmz": true, "security_zone": true,
		"web_filter": true, "url_filter": true, "proxy": true, "content_filter": true,
		"aes_256": true, "rsa_2048": true, "tls_1.2": true, "fips": true,
		"sdlc": true, "secure_sdlc": true, "devsecops": true, "code_review": true,
		"app_sec_requirements": true, "security_spec": true, "threat_modeling": true, "abuse_cases": true,
		"secure_coding": true, "coding_guidelines": true, "sast": true, "code_review": true,
		"security_testing": true, "sast": true, "dast": true, "penetration_test": true,
		"environment_separation": true, "dev_test_prod": true, "namespace_isolation": true, "environment_isolation": true,
		"change_management": true, "change_control": true, "approval_workflow": true, "change_log": true,
		"test_data_management": true, "test_data_protection": true, "test_data_disposal": true, "test_environment_isolation": true,
		"audit_testing": true, "security_audit": true, "compliance_audit": true, "sast_audit": true,
		"acceptance_testing": true, "uat": true, "production_readiness": true, "qa_signoff": true,
		"audit_log": true, "logging_enabled": true, "log_integrity": true, "hash_chain": true,
		"ntp": true, "chrony": true, "time_sync": true, "clock_sync": true,
		"deletion_policy": true, "data_deletion": true, "secure_deletion": true, "retention_expiry": true,
		"data_masking": true, "pii_masking": true, "tokenization": true, "anonymization": true,
		"backup": true, "backup_test": true, "backup_retention": true, "backup_encryption": true,
		"redundancy": true, "high_availability": true, "failover": true, "multi_zone": true,
		"source_code_access": true, "repo_access_control": true, "branch_protection": true, "code_review": true,
		"vendor_security_requirements": true, "supplier_assessment": true, "vendor_inventory": true, "supplier_monitoring": true,
		"supplier_agreement": true, "dpa": true, "security_requirements": true, "contract_review": true,
		"supply_chain_security": true, "sbom": true, "vendor_assessment": true, "supply_chain_monitoring": true,
		"supplier_monitoring": true, "vendor_review": true, "service_review": true, "change_management": true,
		"incident_response_plan": true, "ir_roles": true, "ir_plan": true, "ir_procedures": true,
		"event_assessment": true, "event_classification": true, "triage": true, "severity_classification": true,
		"incident_response": true, "ir_procedure": true, "runbook": true, "incident_commander": true,
		"post_mortem": true, "lessons_learned": true, "ir_review": true, "improvement_actions": true,
		"evidence_collection": true, "chain_of_custody": true, "evidence_preservation": true, "forensic_log": true,
		"ir_during_disruption": true, "continuity_plan": true, "dr_site": true, "failover_during_incident": true,
		"independent_review": true, "external_audit": true, "annual_security_review": true, "third_party_assessment": true,
		"compliance_review": true, "policy_audit": true, "compliance_check": true, "audit_log": true,
		"audit_testing": true, "security_audit": true, "compliance_audit": true, "audit_scheduled": true,
		"fire_suppression": true, "temperature_monitoring": true, "humidity_monitoring": true, "environmental_alerts": true,
		"secure_area_policy": true, "visitor_log": true, "escort_required": true, "clear_desk": true,
		"asset_tracking": true, "device_encryption": true, "remote_wipe": true, "asset_inventory": true
	}`)

	checks := map[string]func(context.Context, []byte) (*compliance.ControlCheckResult, error){
		"A.5.7":  m.checkThreatIntelligence,
		"A.5.10": m.checkAcceptableUse,
		"A.5.12": m.checkDataClassification,
		"A.8.5":  m.checkSecureAuth,
		"A.8.7":  m.checkMalwareProtection,
		"A.8.15": m.checkLogging,
		"A.8.24": m.checkCryptography,
		"A.8.32": m.checkChangeManagement,
	}

	for controlID, checkFn := range checks {
		t.Run(controlID, func(t *testing.T) {
			r, err := checkFn(ctx, compliantConfig)
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

func TestISO27001Check_NonCompliant(t *testing.T) {
	m := NewISO27001Module()
	ctx := context.Background()
	checks := map[string]func(context.Context, []byte) (*compliance.ControlCheckResult, error){
		"A.5.7":  m.checkThreatIntelligence,
		"A.8.5":  m.checkSecureAuth,
		"A.8.7":  m.checkMalwareProtection,
		"A.8.15": m.checkLogging,
		"A.8.24": m.checkCryptography,
		"A.8.32": m.checkChangeManagement,
	}
	for controlID, checkFn := range checks {
		t.Run(controlID, func(t *testing.T) {
			r, err := checkFn(ctx, []byte("nothing_here"))
			if err != nil {
				t.Fatalf("check%s: %v", controlID, err)
			}
			if string(r.Status) == "compliant" {
				t.Errorf("Control %s on empty config: should NOT be compliant", controlID)
			}
		})
	}
}

func TestISO27001Check_Logging(t *testing.T) {
	m := NewISO27001Module()
	ctx := context.Background()

	t.Run("compliant (audit + integrity)", func(t *testing.T) {
		input := []byte("audit_log log_integrity hash_chain")
		r, err := m.checkLogging(ctx, input)
		if err != nil {
			t.Fatalf("checkLogging: %v", err)
		}
		if string(r.Status) != "compliant" {
			t.Errorf("Status = %s, want compliant (msg: %q)", r.Status, r.Message)
		}
	})

	t.Run("partial (audit, no integrity)", func(t *testing.T) {
		input := []byte("audit_log")
		r, err := m.checkLogging(ctx, input)
		if err != nil {
			t.Fatalf("checkLogging: %v", err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("Status = %s, want partial", r.Status)
		}
	})

	t.Run("non-compliant (no audit)", func(t *testing.T) {
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

func TestISO27001Module_Dependencies(t *testing.T) {
	m := NewISO27001Module()
	deps := m.Dependencies()
	if len(deps) < 2 {
		t.Errorf("Dependencies() returned %d items, want at least 2", len(deps))
	}
	depsStr := strings.Join(deps, ",")
	for _, expected := range []string{"scanner", "persistence"} {
		if !strings.Contains(depsStr, expected) {
			t.Errorf("Dependencies() should include %q, got %v", expected, deps)
		}
	}
}
