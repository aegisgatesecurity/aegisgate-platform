// SPDX-License-Identifier: Apache-2.0
// HITRUST CSF Compliance Module - Unit Tests
//
// HITRUST CSF v11.2 — 200 in-scope controls.
// Test coverage target: 80%+ per pkg/compliance coverage floor.
//
// Total controls: 200 (50 automated + 150 manual)
//   AM: 25 (9 automated + 16 manual)
//   ID: 10 ( 4 automated +  6 manual)
//   IP: 25 ( 9 automated + 16 manual)
//   PE: 25 ( 5 automated + 20 manual)
//   OP: 20 ( 5 automated + 15 manual)
//   OR: 10 ( 3 automated +  7 manual)
//   PR: 15 ( 2 automated + 13 manual)
//   BC: 10 ( 1 automated +  9 manual)
//   RA: 10 ( 2 automated +  8 manual)
//   CA: 10 ( 1 automated +  9 manual)
//   IR: 15 ( 3 automated + 12 manual)
//   SD: 15 ( 1 automated + 14 manual)
//   AI: 10 ( 2 automated +  8 manual)

package hitrust

import (
	"context"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewHITRUSTModule(t *testing.T) {
	m := NewHITRUSTModule()
	if m == nil {
		t.Fatal("NewHITRUSTModule returned nil")
	}
	if m.Framework() != "hitrust" {
		t.Errorf("Framework() = %q, want hitrust", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0", m.Version())
	}
	controls := m.Controls()
	if len(controls) != 200 {
		t.Errorf("len(Controls()) = %d, want 200", len(controls))
	}
}

func TestHITRUST_AutomatedCount(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	automated := 0
	manual := 0
	for _, c := range controls {
		if c.Automated {
			automated++
		} else {
			manual++
		}
	}
	if automated != 50 {
		t.Errorf("automated controls = %d, want 50", automated)
	}
	if manual != 150 {
		t.Errorf("manual controls = %d, want 150", manual)
	}
}

func TestHITRUST_ManualControlsHaveNoCheckFunc(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	manualCount := 0
	for _, c := range controls {
		if !c.Automated {
			manualCount++
			if c.CheckFunc != nil {
				t.Errorf("Manual control %s should have nil CheckFunc", c.ID)
			}
		}
	}
	if manualCount != 150 {
		t.Errorf("manual control count = %d, want 150", manualCount)
	}
}

func TestHITRUST_AutomatedControlsHaveCheckFunc(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	autoCount := 0
	for _, c := range controls {
		if c.Automated {
			autoCount++
			if c.CheckFunc == nil {
				t.Errorf("Automated control %s has nil CheckFunc", c.ID)
			}
		}
	}
	if autoCount != 50 {
		t.Errorf("automated control count = %d, want 50", autoCount)
	}
}

func TestHITRUST_AllControlsHaveReferences(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	for _, c := range controls {
		if len(c.References) == 0 {
			t.Errorf("Control %s has no References", c.ID)
		}
	}
}

func TestHITRUST_AllControlsHaveCategory(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	for _, c := range controls {
		if c.Category == "" {
			t.Errorf("Control %s has empty Category", c.ID)
		}
	}
}

func TestHITRUST_CategoryCoverage(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	expectedCategories := map[string]int{
		"Access Management":      25,
		"Identity Management":    10,
		"Information Protection": 25,
		"Privacy and Endpoint":   25,
		"Operations":             20,
		"Organizational Risk":    10,
		"Program":                15,
		"Business Continuity":    10,
		"Regulatory Assessment":  10,
		"Change Management":      10,
		"Incident Response":      15,
		"Supplier/Development":   15,
		"AI Controls":            10,
	}

	categoryCount := map[string]int{}
	for _, c := range controls {
		categoryCount[c.Category]++
	}

	for category, expected := range expectedCategories {
		got := categoryCount[category]
		if got != expected {
			t.Errorf("category %q: got %d controls, want %d", category, got, expected)
		}
	}

	// Verify no unexpected categories
	for category := range categoryCount {
		if _, ok := expectedCategories[category]; !ok {
			t.Errorf("unexpected category %q found", category)
		}
	}
}

func TestHITRUST_AllControlsHaveFields(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	for _, c := range controls {
		if c.ID == "" {
			t.Errorf("Control has empty ID")
		}
		if c.Name == "" {
			t.Errorf("Control %s has empty Name", c.ID)
		}
		if c.Description == "" {
			t.Errorf("Control %s has empty Description", c.ID)
		}
		if c.Severity == "" {
			t.Errorf("Control %s has empty Severity", c.ID)
		}
		if c.Automated && c.CheckFunc == nil {
			t.Errorf("Automated control %s has nil CheckFunc", c.ID)
		}
		if !c.Automated && c.CheckFunc != nil {
			t.Errorf("Manual control %s should have nil CheckFunc", c.ID)
		}
	}
}

func TestHITRUST_Dependencies(t *testing.T) {
	m := NewHITRUSTModule()
	deps := m.Dependencies()
	if len(deps) != 6 {
		t.Errorf("Dependencies() returned %d items, want 6", len(deps))
	}
	depsStr := strings.Join(deps, ",")
	for _, expected := range []string{"hipaa", "iso27001", "fips", "soc2", "ioc", "trust"} {
		if !strings.Contains(depsStr, expected) {
			t.Errorf("Dependencies() should include %q", expected)
		}
	}
}

// ── Fully Compliant Config ────────────────────────────────────────

// fullyCompliantConfig is a JSON string containing all keywords needed
// to make every automated CheckFunc return compliant.
const fullyCompliantConfig = `{
	"authentication": true,
	"auth_enabled": true,
	"user_id": true,
	"unique_id": true,
	"identity": true,
	"mfa": true,
	"multi_factor": true,
	"2fa": true,
	"two_factor": true,
	"otp": true,
	"totp": true,
	"rbac": true,
	"role_based": true,
	"roles": true,
	"least_privilege": true,
	"need_to_know": true,
	"password_policy": true,
	"password_complexity": true,
	"min_length": 16,
	"password_length": 16,
	"password_rotation": 90,
	"password_expiry": 90,
	"key_rotation": true,
	"credential_rotation": true,
	"revocation": true,
	"deprovision": true,
	"termination": true,
	"access_review": true,
	"review": true,
	"audit_log": true,
	"logging_enabled": true,
	"audit_enabled": true,
	"log_integrity": true,
	"hash_chain": true,
	"siem": true,
	"session_timeout": 1800,
	"idle_timeout": 1800,
	"privileged_access": true,
	"admin": true,
	"pam": true,
	"remote_access": true,
	"vpn": true,
	"tls": true,
	"https": true,
	"tls1.2": true,
	"tls1.3": true,
	"account_monitoring": true,
	"monitoring": true,
	"alerting": true,
	"anomaly_detection": true,
	"nac": true,
	"network_access_control": true,
	"nac_enabled": true,
	"network_policy": true,
	"policy_compliance": true,
	"policy": true,
	"key_management": true,
	"key_management_enabled": true,
	"encryption_at_rest": true,
	"data_encrypted": true,
	"aes_256": true,
	"aes-256": true,
	"fips_140": true,
	"fips_mode": true,
	"cmvp": true,
	"rotation_policy": true,
	"data_masking": true,
	"masking": true,
	"redaction": true,
	"anonymization": true,
	"non_production": true,
	"staging": true,
	"test_environment": true,
	"pii": true,
	"phi": true,
	"sensitive_data": true,
	"antimalware": true,
	"anti_malware": true,
	"malware_protection": true,
	"endpoint_protection": true,
	"hardening": true,
	"secure_baseline": true,
	"cis_benchmark": true,
	"edr": true,
	"endpoint_detection_response": true,
	"host_ids": true,
	"ids": true,
	"firewall": true,
	"waf": true,
	"egress_filter": true,
	"egress_filtering": true,
	"network_segmentation": true,
	"segmentation": true,
	"dmz": true,
	"proxy": true,
	"malware_scan": true,
	"signature_update": true,
	"signature_updates": true,
	"auto_update": true,
	"scanner_update": true,
	"scan_entry": true,
	"scan_exit": true,
	"file_upload": true,
	"email_scan": true,
	"vulnerability_scan": true,
	"vulnerability_scanning": true,
	"vuln_scan": true,
	"scanner": true,
	"patch_management": true,
	"patch": true,
	"patching": true,
	"cvss": true,
	"risk_rating": true,
	"risk_assessment": true,
	"remediation": true,
	"vuln_remediation": true,
	"vulnerability_remediation": true,
	"remediation_tracking": true,
	"sla": true,
	"fix": true,
	"backup": true,
	"data_backup": true,
	"recovery": true,
	"recovery_test": true,
	"disaster_recovery": true,
	"dr_test": true,
	"offsite": true,
	"off_site_storage": true,
	"cloud_backup": true,
	"system_backup": true,
	"automated_backup": true,
	"auto_backup": true,
	"backup_automation": true,
	"backup_verification": true,
	"backup_integrity": true,
	"verification": true,
	"dlp": true,
	"data_loss_prevention": true,
	"content_inspection": true,
	"content_filtering": true,
	"storage_encryption": true,
	"storage_object_encryption": true,
	"device_identification": true,
	"device_id": true,
	"device_certificate": true,
	"device_inventory": true,
	"device_registration": true,
	"inventory": true,
	"full_disk_encryption": true,
	"fde": true,
	"disk_encryption": true,
	"device_encryption": true,
	"mobile_encryption": true,
	"mdm": true,
	"mobile_device_management": true,
	"mobile_management": true,
	"remote_wipe": true,
	"wipe": true,
	"remote_lock": true,
	"patch_deployment": true,
	"automatic_patch": true,
	"auto_deploy": true,
	"patch_verification": true,
	"patch_compliance": true,
	"response": true,
	"automated_response": true,
	"incident_response": true,
	"configuration_management": true,
	"config_management": true,
	"cm_enabled": true,
	"baseline_configuration": true,
	"baseline": true,
	"component_inventory": true,
	"asset_inventory": true,
	"inventory_management": true,
	"inventory_updates": true,
	"inventory_refresh": true,
	"asset_tracking": true,
	"tracking": true,
	"change_control": true,
	"change_management": true,
	"change_approval": true,
	"approval": true,
	"change_review": true,
	"configuration_settings": true,
	"config_settings": true,
	"security_settings": true,
	"enforcement": true,
	"settings_enforced": true,
	"enforced": true,
	"controlled_maintenance": true,
	"maintenance": true,
	"maintenance_schedule": true,
	"schedule": true,
	"scheduled": true,
	"maintenance_window": true,
	"risk_analysis": true,
	"risk_evaluation": true,
	"threat": true,
	"threat_identification": true,
	"threats": true,
	"vulnerability": true,
	"vulnerabilities": true,
	"automated_scan": true,
	"scheduled_scan": true,
	"auto_scan": true,
	"scan_report": true,
	"reporting": true,
	"scan_results": true,
	"status_report": true,
	"security_awareness": true,
	"awareness_training": true,
	"training": true,
	"training_completion": true,
	"completion": true,
	"training_records": true,
	"training_tracking": true,
	"training_management": true,
	"role_based_training": true,
	"role_training": true,
	"specialized_training": true,
	"role": true,
	"security_assessment": true,
	"assessment": true,
	"control_assessment": true,
	"periodic": true,
	"scheduled_assessment": true,
	"assessment_schedule": true,
	"assessment_findings": true,
	"findings": true,
	"assessment_report": true,
	"continuous_monitoring": true,
	"alerts": true,
	"monitoring_report": true,
	"change_tracking": true,
	"change_detection": true,
	"drift_detection": true,
	"incident_response_plan": true,
	"ir_plan": true,
	"incident_plan": true,
	"procedures": true,
	"response_procedures": true,
	"ir_procedures": true,
	"ir_roles": true,
	"responsibilities": true,
	"incident_monitoring": true,
	"incident_detection": true,
	"detection": true,
	"incident_alerting": true,
	"incident_handling": true,
	"handling": true,
	"containment": true,
	"isolation": true,
	"auto_containment": true,
	"system_documentation": true,
	"documentation": true,
	"system_docs": true,
	"documentation_complete": true,
	"complete": true,
	"docs_verified": true,
	"documentation_current": true,
	"up_to_date": true,
	"current": true,
	"version_control": true,
	"ai_model_data_protection": true,
	"model_data_protection": true,
	"ai_data_protection": true,
	"encryption": true,
	"access_control": true,
	"data_access_control": true,
	"ai_audit_trail": true,
	"ai_audit": true,
	"model_audit": true,
	"ai_logging": true,
	"model_logging": true,
	"ai_usage_tracking": true,
	"usage_tracking": true,
	"decision_tracking": true
}`

func TestHITRUST_CheckAllAutomated_Compliant(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	results, err := m.CheckAll(ctx, []byte(fullyCompliantConfig))
	if err != nil {
		t.Fatalf("CheckAll failed: %v", err)
	}

	if len(results) != 50 {
		t.Fatalf("CheckAll returned %d results, want 50", len(results))
	}

	for _, r := range results {
		if string(r.Status) != "compliant" {
			t.Errorf("Control %s: status = %q, want compliant (message: %q)", r.ControlID, r.Status, r.Message)
		}
	}
}

// ── Individual CheckFunc tests ────────────────────────────────────

func TestHITRUSTMFA(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (mfa)", input: `{"mfa": true, "authentication": true}`, wantStatus: "compliant"},
		{name: "compliant (multi_factor)", input: `{"multi_factor": true, "authentication": true}`, wantStatus: "compliant"},
		{name: "compliant (2fa)", input: `{"2fa": true, "tls": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no MFA)", input: `{"authentication": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkMFA(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkMFA: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTUserAuthentication(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (auth + unique ID + MFA)", input: `{"authentication": true, "user_id": true, "mfa": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no auth)", input: `{"user_id": true, "mfa": true}`, wantStatus: "non_compliant"},
		{name: "non-compliant (no MFA)", input: `{"authentication": true, "user_id": true}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkUserAuthentication(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkUserAuthentication: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTLogicalAccess(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkLogicalAccess(ctx, []byte(`{"rbac": true, "authentication": true, "least_privilege": true}`))
	if err != nil {
		t.Fatalf("checkLogicalAccess: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTPasswordManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (policy + min_length)", input: `{"password_policy": true, "min_length": 12}`, wantStatus: "compliant"},
		{name: "compliant (policy + rotation)", input: `{"password_policy": true, "password_rotation": 90}`, wantStatus: "compliant"},
		{name: "non-compliant (no policy)", input: `{"min_length": 12}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkPasswordManagement(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkPasswordManagement: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTAccessReview(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkAccessReview(ctx, []byte(`{"rbac": true, "audit_log": true, "access_review": true}`))
	if err != nil {
		t.Fatalf("checkAccessReview: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTSessionManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkSessionManagement(ctx, []byte(`{"session_timeout": 1800, "authentication": true}`))
	if err != nil {
		t.Fatalf("checkSessionManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTPrivilegedAccess(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkPrivilegedAccess(ctx, []byte(`{"rbac": true, "mfa": true, "audit_log": true, "privileged_access": true}`))
	if err != nil {
		t.Fatalf("checkPrivilegedAccess: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTIdentityVerification(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkIdentityVerification(ctx, []byte(`{"authentication": true, "user_id": true, "mfa": true}`))
	if err != nil {
		t.Fatalf("checkIdentityVerification: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTAuthenticatorManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkAuthenticatorManagement(ctx, []byte(`{"password_policy": true, "key_management": true, "mfa": true}`))
	if err != nil {
		t.Fatalf("checkAuthenticatorManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTCredentialManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkCredentialManagement(ctx, []byte(`{"key_rotation": true, "revocation": true, "audit_log": true}`))
	if err != nil {
		t.Fatalf("checkCredentialManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTEncryptionAtRest(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (encryption_at_rest)", input: `{"encryption_at_rest": true, "key_management": true}`, wantStatus: "compliant"},
		{name: "compliant (aes_256)", input: `{"aes_256": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no encryption)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkEncryptionAtRest(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkEncryptionAtRest: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTEncryptionInTransit(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (TLS)", input: `{"tls": true, "https": true}`, wantStatus: "compliant"},
		{name: "compliant (TLS 1.3)", input: `{"tls1.3": true}`, wantStatus: "compliant"},
		{name: "non-compliant (no TLS)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkEncryptionInTransit(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkEncryptionInTransit: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTKeyManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkKeyManagement(ctx, []byte(`{"key_management": true, "key_rotation": true, "fips_140": true}`))
	if err != nil {
		t.Fatalf("checkKeyManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTDataMasking(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (masking + non_production)", input: `{"data_masking": true, "non_production": true}`, wantStatus: "compliant"},
		{name: "compliant (masking + PII)", input: `{"masking": true, "pii": true}`, wantStatus: "compliant"},
		{name: "partial (masking, no env)", input: `{"data_masking": true}`, wantStatus: "partial"},
		{name: "non-compliant (no masking)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkDataMasking(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkDataMasking: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestHITRUSTEndpointProtection(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkEndpointProtection(ctx, []byte(`{"antimalware": true, "hardening": true, "edr": true}`))
	if err != nil {
		t.Fatalf("checkEndpointProtection: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTNetworkProtection(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkNetworkProtection(ctx, []byte(`{"firewall": true, "network_segmentation": true}`))
	if err != nil {
		t.Fatalf("checkNetworkProtection: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTMalwareProtection(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkMalwareProtection(ctx, []byte(`{"antimalware": true, "signature_update": true, "scan_entry": true}`))
	if err != nil {
		t.Fatalf("checkMalwareProtection: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTVulnerabilityManagement(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkVulnerabilityManagement(ctx, []byte(`{"vulnerability_scan": true, "patch": true, "cvss": true}`))
	if err != nil {
		t.Fatalf("checkVulnerabilityManagement: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTBackupAndRecovery(t *testing.T) {
	m := NewHITRUSTModule()
	ctx := context.Background()

	result, err := m.checkBackupAndRecovery(ctx, []byte(`{"backup": true, "recovery_test": true, "offsite": true}`))
	if err != nil {
		t.Fatalf("checkBackupAndRecovery: %v", err)
	}
	if string(result.Status) != "compliant" {
		t.Errorf("Expected compliant, got %q: %q", result.Status, result.Message)
	}
}

func TestHITRUSTControlIDs(t *testing.T) {
	m := NewHITRUSTModule()
	controls := m.Controls()

	controlMap := map[string]compliance.ControlDefinition{}
	for _, c := range controls {
		controlMap[c.ID] = c
	}

	// Verify all expected control IDs exist
	expectedIDs := []string{
		// AM family (25)
		"HITRUST-AM-01", "HITRUST-AM-02", "HITRUST-AM-03", "HITRUST-AM-04",
		"HITRUST-AM-05", "HITRUST-AM-06", "HITRUST-AM-07", "HITRUST-AM-08",
		"HITRUST-AM-09", "HITRUST-AM-10", "HITRUST-AM-11", "HITRUST-AM-12",
		"HITRUST-AM-13", "HITRUST-AM-14", "HITRUST-AM-15", "HITRUST-AM-16",
		"HITRUST-AM-17", "HITRUST-AM-18", "HITRUST-AM-19", "HITRUST-AM-20",
		"HITRUST-AM-21", "HITRUST-AM-22", "HITRUST-AM-23", "HITRUST-AM-24",
		"HITRUST-AM-25",
		// ID family (10)
		"HITRUST-ID-01", "HITRUST-ID-02", "HITRUST-ID-03", "HITRUST-ID-04",
		"HITRUST-ID-05", "HITRUST-ID-06", "HITRUST-ID-07", "HITRUST-ID-08",
		"HITRUST-ID-09", "HITRUST-ID-10",
		// IP family (25)
		"HITRUST-IP-01", "HITRUST-IP-02", "HITRUST-IP-03", "HITRUST-IP-04",
		"HITRUST-IP-05", "HITRUST-IP-06", "HITRUST-IP-07", "HITRUST-IP-08",
		"HITRUST-IP-09", "HITRUST-IP-10", "HITRUST-IP-11", "HITRUST-IP-12",
		"HITRUST-IP-13", "HITRUST-IP-14", "HITRUST-IP-15", "HITRUST-IP-16",
		"HITRUST-IP-17", "HITRUST-IP-18", "HITRUST-IP-19", "HITRUST-IP-20",
		"HITRUST-IP-21", "HITRUST-IP-22", "HITRUST-IP-23", "HITRUST-IP-24",
		"HITRUST-IP-25",
		// PE family (25)
		"HITRUST-PE-01", "HITRUST-PE-02", "HITRUST-PE-03", "HITRUST-PE-04",
		"HITRUST-PE-05", "HITRUST-PE-06", "HITRUST-PE-07", "HITRUST-PE-08",
		"HITRUST-PE-09", "HITRUST-PE-10", "HITRUST-PE-11", "HITRUST-PE-12",
		"HITRUST-PE-13", "HITRUST-PE-14", "HITRUST-PE-15", "HITRUST-PE-16",
		"HITRUST-PE-17", "HITRUST-PE-18", "HITRUST-PE-19", "HITRUST-PE-20",
		"HITRUST-PE-21", "HITRUST-PE-22", "HITRUST-PE-23", "HITRUST-PE-24",
		"HITRUST-PE-25",
		// OP family (20)
		"HITRUST-OP-01", "HITRUST-OP-02", "HITRUST-OP-03", "HITRUST-OP-04",
		"HITRUST-OP-05", "HITRUST-OP-06", "HITRUST-OP-07", "HITRUST-OP-08",
		"HITRUST-OP-09", "HITRUST-OP-10", "HITRUST-OP-11", "HITRUST-OP-12",
		"HITRUST-OP-13", "HITRUST-OP-14", "HITRUST-OP-15", "HITRUST-OP-16",
		"HITRUST-OP-17", "HITRUST-OP-18", "HITRUST-OP-19", "HITRUST-OP-20",
		// OR family (10)
		"HITRUST-OR-01", "HITRUST-OR-02", "HITRUST-OR-03", "HITRUST-OR-04",
		"HITRUST-OR-05", "HITRUST-OR-06", "HITRUST-OR-07", "HITRUST-OR-08",
		"HITRUST-OR-09", "HITRUST-OR-10",
		// PR family (15)
		"HITRUST-PR-01", "HITRUST-PR-02", "HITRUST-PR-03", "HITRUST-PR-04",
		"HITRUST-PR-05", "HITRUST-PR-06", "HITRUST-PR-07", "HITRUST-PR-08",
		"HITRUST-PR-09", "HITRUST-PR-10", "HITRUST-PR-11", "HITRUST-PR-12",
		"HITRUST-PR-13", "HITRUST-PR-14", "HITRUST-PR-15",
		// BC family (10)
		"HITRUST-BC-01", "HITRUST-BC-02", "HITRUST-BC-03", "HITRUST-BC-04",
		"HITRUST-BC-05", "HITRUST-BC-06", "HITRUST-BC-07", "HITRUST-BC-08",
		"HITRUST-BC-09", "HITRUST-BC-10",
		// RA family (10)
		"HITRUST-RA-01", "HITRUST-RA-02", "HITRUST-RA-03", "HITRUST-RA-04",
		"HITRUST-RA-05", "HITRUST-RA-06", "HITRUST-RA-07", "HITRUST-RA-08",
		"HITRUST-RA-09", "HITRUST-RA-10",
		// CA family (10)
		"HITRUST-CA-01", "HITRUST-CA-02", "HITRUST-CA-03", "HITRUST-CA-04",
		"HITRUST-CA-05", "HITRUST-CA-06", "HITRUST-CA-07", "HITRUST-CA-08",
		"HITRUST-CA-09", "HITRUST-CA-10",
		// IR family (15)
		"HITRUST-IR-01", "HITRUST-IR-02", "HITRUST-IR-03", "HITRUST-IR-04",
		"HITRUST-IR-05", "HITRUST-IR-06", "HITRUST-IR-07", "HITRUST-IR-08",
		"HITRUST-IR-09", "HITRUST-IR-10", "HITRUST-IR-11", "HITRUST-IR-12",
		"HITRUST-IR-13", "HITRUST-IR-14", "HITRUST-IR-15",
		// SD family (15)
		"HITRUST-SD-01", "HITRUST-SD-02", "HITRUST-SD-03", "HITRUST-SD-04",
		"HITRUST-SD-05", "HITRUST-SD-06", "HITRUST-SD-07", "HITRUST-SD-08",
		"HITRUST-SD-09", "HITRUST-SD-10", "HITRUST-SD-11", "HITRUST-SD-12",
		"HITRUST-SD-13", "HITRUST-SD-14", "HITRUST-SD-15",
		// AI family (10)
		"HITRUST-AI-01", "HITRUST-AI-02", "HITRUST-AI-03", "HITRUST-AI-04",
		"HITRUST-AI-05", "HITRUST-AI-06", "HITRUST-AI-07", "HITRUST-AI-08",
		"HITRUST-AI-09", "HITRUST-AI-10",
	}

	for _, id := range expectedIDs {
		if _, ok := controlMap[id]; !ok {
			t.Errorf("Expected control %s not found", id)
		}
	}

	if len(expectedIDs) != 200 {
		t.Errorf("expectedIDs has %d entries, want 200", len(expectedIDs))
	}
}
