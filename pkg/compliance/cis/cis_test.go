// SPDX-License-Identifier: Apache-2.0
// CIS Critical Security Controls v8 - Unit Tests
// v2.0 Tier: Professional — 50 safeguards (42 automated, 8 manual)
// All 18 CIS control families are in scope.

package cis

import (
	"context"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// ---------------------------------------------------------------------------
// Module metadata & structural tests
// ---------------------------------------------------------------------------

func TestNewCISModule(t *testing.T) {
	m := NewCISModule()
	if m == nil {
		t.Fatal("NewCISModule returned nil")
	}
	if m.Framework() != "cis" {
		t.Errorf("Framework() = %q, want %q", m.Framework(), "cis")
	}
	if m.Version() != "2.0" {
		t.Errorf("Version() = %q, want %q", m.Version(), "2.0")
	}
	if m.Metadata().Tier != core.TierProfessional {
		t.Errorf("Tier = %v, want %v (Professional)", m.Metadata().Tier, core.TierProfessional)
	}

	controls := m.Controls()
	if len(controls) != 50 {
		t.Errorf("len(Controls()) = %d, want 50 (42 automated + 8 manual)", len(controls))
	}

	// --- Verify all control IDs are unique ---
	seen := make(map[string]bool, len(controls))
	for _, c := range controls {
		if seen[c.ID] {
			t.Errorf("Duplicate control ID: %s", c.ID)
		}
		seen[c.ID] = true
	}

	// --- Count automated vs manual ---
	auto, manual := 0, 0
	for _, c := range controls {
		if c.Automated {
			auto++
			if c.CheckFunc == nil {
				t.Errorf("Automated control %s has nil CheckFunc", c.ID)
			}
		} else {
			manual++
			if c.CheckFunc != nil {
				t.Errorf("Manual control %s should not have a CheckFunc", c.ID)
			}
		}
	}
	if auto != 42 {
		t.Errorf("automated control count = %d, want 42", auto)
	}
	if manual != 8 {
		t.Errorf("manual control count = %d, want 8", manual)
	}
}

func TestCISModule_Dependencies(t *testing.T) {
	m := NewCISModule()
	deps := m.Dependencies()
	if len(deps) < 3 {
		t.Errorf("Dependencies() returned %d items, want at least 3", len(deps))
	}
}

// TestCISModule_ControlIDsInScope verifies that CIS-14, CIS-15, and CIS-18
// are now IN SCOPE (they were out-of-scope in v1.x).
func TestCISModule_ControlIDsInScope(t *testing.T) {
	m := NewCISModule()
	controls := m.Controls()

	families := make(map[string]bool)
	for _, c := range controls {
		// Extract family prefix, e.g. "CIS-14" from "CIS-14.1"
		parts := strings.SplitN(c.ID, ".", 2)
		if len(parts) == 2 {
			families[parts[0]] = true
		}
	}

	for _, fam := range []string{"CIS-14", "CIS-15", "CIS-18"} {
		if !families[fam] {
			t.Errorf("Family %s should be in scope but was not found in controls", fam)
		}
	}
}

// TestCISModule_ManualControlIDs verifies the 8 manual controls are present.
func TestCISModule_ManualControlIDs(t *testing.T) {
	m := NewCISModule()
	controls := m.Controls()

	expectedManual := []string{
		"CIS-1.3",
		"CIS-14.1", "CIS-14.2",
		"CIS-15.1", "CIS-15.2",
		"CIS-17.3", "CIS-18.1", "CIS-18.2",
	}
	have := make(map[string]bool)
	for _, c := range controls {
		if !c.Automated {
			have[c.ID] = true
		}
	}
	for _, id := range expectedManual {
		if !have[id] {
			t.Errorf("Expected manual control %s not found", id)
		}
	}
	if len(have) != len(expectedManual) {
		t.Errorf("manual control count = %d, want %d", len(have), len(expectedManual))
	}
}

// ---------------------------------------------------------------------------
// Compliant configuration tests
// ---------------------------------------------------------------------------

// compliantConfig is a single input string that contains keywords matching
// all 42 automated controls so that each CheckFunc returns "compliant".
const compliantConfig = `{
	"asset_inventory": true,
	"bundle_federation": true,
	"asset_tracking": true,
	"unauthorized_asset": true,
	"rogue_device": true,
	"quarantine": true,
	"block_unauthorized": true,
	"alert_unauthorized": true,
	"model_id": "gpt-4",
	"model_version": "0613",
	"binary_attestation": true,
	"sbom": "cyclonedx",
	"spdx": true,
	"unauthorized_software": true,
	"software_allowlist": true,
	"model_allowlist": true,
	"block_software": true,
	"quarantine_software": true,
	"alert_software": true,
	"allowlist": true,
	"whitelist": true,
	"approved_software": true,
	"allowlist_enforcement": true,
	"block_unlisted": true,
	"enforce_allowlist": true,
	"data_classification": true,
	"classification_policy": true,
	"data_categories": true,
	"data_handling": true,
	"handling_policy": true,
	"retention_policy": true,
	"data_disposal": true,
	"secure_deletion": true,
	"data_retention": true,
	"data_inventory": true,
	"data_mapping": true,
	"data_catalog": true,
	"asset_mapping": true,
	"data_location": true,
	"data_flow": true,
	"encryption_at_rest": true,
	"data_encrypted": true,
	"storage_encryption": true,
	"tls1.3": true,
	"min_version_1.3": true,
	"pii_scanner": true,
	"pii_redaction": true,
	"secret_scanner": true,
	"platformconfig": true,
	"aegisgate-platform.yaml": true,
	"configuration_management": true,
	"hardening": true,
	"secure_config": true,
	"security_headers": true,
	"secure_defaults": true,
	"network_hardening": true,
	"default_deny": true,
	"network_config_management": true,
	"infrastructure_as_code": true,
	"config_versioning": true,
	"session_timeout": 1800,
	"idle_timeout": 1800,
	"session_lock": true,
	"auto_lock": true,
	"lock_policy": true,
	"timeout_policy": true,
	"authentication": true,
	"auth_enabled": true,
	"account_management": true,
	"account_lifecycle": true,
	"provisioning": true,
	"rbac": true,
	"roles": true,
	"privileged_accounts": true,
	"pam": true,
	"privileged_access": true,
	"admin_roles": true,
	"privileged_roles": true,
	"audit_log": true,
	"logging_enabled": true,
	"audit_enabled": true,
	"log_integrity": true,
	"hash_chain": true,
	"mfa": true,
	"multi_factor": true,
	"totp": true,
	"admin_mfa": true,
	"mfa_admin": true,
	"privileged_mfa": true,
	"mfa_required": true,
	"mfa_enforced": true,
	"require_mfa": true,
	"remote_mfa": true,
	"vpn_mfa": true,
	"remote_access_mfa": true,
	"access_granting": true,
	"access_revoking": true,
	"access_process": true,
	"access_approval": true,
	"approval_workflow": true,
	"access_request": true,
	"least_privilege": true,
	"minimum_permissions": true,
	"privilege_minimization": true,
	"govulncheck": true,
	"vuln_scan": true,
	"trivy": true,
	"container_scan": true,
	"remediation": true,
	"remediation_process": true,
	"fix_process": true,
	"remediation_sla": true,
	"sla": true,
	"time_to_remediate": true,
	"vuln_tracking": true,
	"ticketing": true,
	"issue_tracking": true,
	"patch_management": true,
	"automated_patching": true,
	"patch": true,
	"auto_update": true,
	"automatic_updates": true,
	"unattended_upgrades": true,
	"patch_testing": true,
	"staged_patching": true,
	"patch_validation": true,
	"retention": true,
	"audit_log_retention": true,
	"log_management": true,
	"audit_process": true,
	"log_policy": true,
	"centralized_logging": true,
	"log_aggregation": true,
	"siem": true,
	"log_central": true,
	"approved_email": true,
	"email_allowlist": true,
	"email_client_policy": true,
	"email_dlp": true,
	"data_loss_prevention": true,
	"email_scanning": true,
	"aegisgate_lens": true,
	"lens_extension": true,
	"browser_extension": true,
	"content_security_policy": true,
	"csp_header": true,
	"approved_browsers": true,
	"browser_allowlist": true,
	"browser_policy": true,
	"scanner": true,
	"prompt_injection_scanner": true,
	"jailbreak_scanner": true,
	"data_poisoning_scanner": true,
	"aegisgate_scanner": true,
	"anti_malware": true,
	"antivirus": true,
	"malware_scan": true,
	"full_coverage": true,
	"all_assets": true,
	"endpoint_protection": true,
	"pattern_update": true,
	"rule_update": true,
	"signature_update": true,
	"definition_update": true,
	"signature_auto_update": true,
	"regular_scan": true,
	"scheduled_scan": true,
	"scan_interval": true,
	"backup": true,
	"disaster_recovery": true,
	"restore": true,
	"audit_replay": true,
	"recoverable": true,
	"automated_backup": true,
	"auto_backup": true,
	"scheduled_backup": true,
	"backup_retention": true,
	"restore_test": true,
	"backup_test": true,
	"recovery_test": true,
	"firmware_update": true,
	"patch_network": true,
	"network_up_to_date": true,
	"supported_version": true,
	"end_of_life_check": true,
	"version_check": true,
	"mtls": true,
	"mutual_tls": true,
	"client_cert": true,
	"network_segmentation": true,
	"segmented": true,
	"isolated": true,
	"firewall": true,
	"egress_allowlist": true,
	"ingress_allowlist": true,
	"network_access_control": true,
	"nac": true,
	"device_auth": true,
	"change_management": true,
	"config_change_control": true,
	"network_change": true,
	"ioc_store": true,
	"ioc_federation": true,
	"anomaly": true,
	"trust_score": true,
	"anomaly_detection": true,
	"network_monitoring": true,
	"traffic_monitoring": true,
	"continuous_monitoring": true,
	"ids": true,
	"intrusion": true,
	"intrusion_detection": true,
	"ips": true,
	"intrusion_prevention": true,
	"blocking": true,
	"alert": true,
	"soc_alerting": true,
	"ssdf": true,
	"secure_sdlc": true,
	"devsecops": true,
	"code_review": true,
	"peer_review": true,
	"security_review": true,
	"root_cause": true,
	"rca": true,
	"postmortem": true,
	"vuln_management": true,
	"vulnerability_database": true,
	"prevent_recurrence": true,
	"oss_policy": true,
	"open_source_policy": true,
	"license_compliance": true,
	"ir_team": true,
	"incident_response_team": true,
	"designated_personnel": true,
	"ir_roles": true,
	"response_roles": true,
	"incident_roles": true,
	"ir_contact": true,
	"emergency_contact": true,
	"escalation_contact": true,
	"incident_response_plan": true,
	"ir_plan": true,
	"incident_process": true,
	"attestation": true,
	"signed_log": true,
	"trust_framework": true,
	"removable_media": true,
	"usb_control": true,
	"device_restriction": true,
	"password_management": true,
	"password_manager": true,
	"credential_management": true,
	"audit_log_review": true,
	"log_review": true,
	"log_analysis": true,
	"network_traffic": true,
	"traffic_collection": true,
	"netflow": true,
	"traffic_analysis": true,
	"network_monitoring": true,
	"pcap": true
}`

func TestCISCheck_Compliant(t *testing.T) {
	m := NewCISModule()
	ctx := context.Background()
	input := []byte(compliantConfig)

	tests := []struct {
		name    string
		control string
		fn      func(context.Context, []byte) (string, string)
	}{
		{"CIS-1.1", "CIS-1.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkEstablishAssetInventory(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-1.2", "CIS-1.2", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAddressUnauthorizedAssets(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-2.1", "CIS-2.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSoftwareInventory(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-2.3", "CIS-2.3", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSoftwareAllowlists(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-3.1", "CIS-3.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDataManagementProcess(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-3.3", "CIS-3.3", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkConfigureDataStorage(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-4.1", "CIS-4.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSecureConfigurationProcess(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-5.1", "CIS-5.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAccountManagementProcess(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-5.3", "CIS-5.3", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkMFAAdministrative(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-7.1", "CIS-7.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkVulnerabilityManagementProcess(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-8.2", "CIS-8.2", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkCollectCentralizeAuditLogs(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-10.1", "CIS-10.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDeployAntiMalware(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-12.2", "CIS-12.2", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSecureNetworkArchitecture(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-16.1", "CIS-16.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSecureSDLC(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-17.2", "CIS-17.2", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkIncidentResponseProcess(c, b)
			return string(r.Status), r.Message
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, msg := tc.fn(ctx, input)
			if status != "compliant" {
				t.Errorf("Control %s on compliant config: status=%s, msg=%s",
					tc.control, status, msg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Non-compliant configuration tests (empty / minimal input)
// ---------------------------------------------------------------------------

func TestCISCheck_NonCompliant(t *testing.T) {
	m := NewCISModule()
	ctx := context.Background()
	emptyInput := []byte(`{}`)

	tests := []struct {
		name    string
		control string
		fn      func(context.Context, []byte) (string, string)
	}{
		{"CIS-1.1", "CIS-1.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkEstablishAssetInventory(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-2.1", "CIS-2.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSoftwareInventory(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-3.3", "CIS-3.3", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkConfigureDataStorage(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-5.1", "CIS-5.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAccountManagementProcess(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-7.1", "CIS-7.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkVulnerabilityManagementProcess(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-10.1", "CIS-10.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDeployAntiMalware(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-12.2", "CIS-12.2", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSecureNetworkArchitecture(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-16.1", "CIS-16.1", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSecureSDLC(c, b)
			return string(r.Status), r.Message
		}},
		{"CIS-17.2", "CIS-17.2", func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkIncidentResponseProcess(c, b)
			return string(r.Status), r.Message
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := tc.fn(ctx, emptyInput)
			if status != "non_compliant" {
				t.Errorf("Control %s on empty config: status=%s, want non_compliant",
					tc.control, status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Partial configuration tests
// ---------------------------------------------------------------------------

func TestCISCheck_Partial(t *testing.T) {
	m := NewCISModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		control    string
		fn         func(context.Context, []byte) (string, string)
		wantStatus string
	}{
		{
			name:       "CIS-1.1 partial (inventory without federation)",
			input:      `{"asset_inventory": true}`,
			control:    "CIS-1.1",
			wantStatus: "partial",
			fn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkEstablishAssetInventory(c, b)
				return string(r.Status), r.Message
			},
		},
		{
			name:       "CIS-2.1 partial (versioning without SBOM)",
			input:      `{"model_version": "1.0"}`,
			control:    "CIS-2.1",
			wantStatus: "partial",
			fn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkSoftwareInventory(c, b)
				return string(r.Status), r.Message
			},
		},
		{
			name:       "CIS-2.3 partial (allowlist without enforcement)",
			input:      `{"allowlist": true}`,
			control:    "CIS-2.3",
			wantStatus: "partial",
			fn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkSoftwareAllowlists(c, b)
				return string(r.Status), r.Message
			},
		},
		{
			name:       "CIS-4.3 partial (session_timeout without lock_policy)",
			input:      `{"session_timeout": 1800}`,
			control:    "CIS-4.3",
			wantStatus: "partial",
			fn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkSessionLocking(c, b)
				return string(r.Status), r.Message
			},
		},
		{
			name:       "CIS-5.3 partial (mfa without admin enforcement)",
			input:      `{"mfa": true}`,
			control:    "CIS-5.3",
			wantStatus: "partial",
			fn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkMFAAdministrative(c, b)
				return string(r.Status), r.Message
			},
		},
		{
			name:       "CIS-9.1 partial (approved_email without DLP)",
			input:      `{"approved_email": true}`,
			control:    "CIS-9.1",
			wantStatus: "partial",
			fn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkApprovedEmailClients(c, b)
				return string(r.Status), r.Message
			},
		},
		{
			name:       "CIS-11.1 partial (backup without integrity/restore)",
			input:      `{"backup": true}`,
			control:    "CIS-11.1",
			wantStatus: "partial",
			fn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkDataRecoveryProcess(c, b)
				return string(r.Status), r.Message
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, msg := tc.fn(ctx, []byte(tc.input))
			if status != tc.wantStatus {
				t.Errorf("Control %s: status=%s, want %s, msg=%s",
					tc.control, status, tc.wantStatus, msg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// CheckAll integration test
// ---------------------------------------------------------------------------

func TestCISCheck_All(t *testing.T) {
	m := NewCISModule()
	ctx := context.Background()

	results, err := m.CheckAll(ctx, []byte(compliantConfig))
	if err != nil {
		t.Fatalf("CheckAll returned error: %v", err)
	}

	// CheckAll should return results for all 42 automated controls
	if len(results) != 42 {
		t.Errorf("CheckAll returned %d results, want 42 (automated controls only)", len(results))
	}

	// Verify each result has a valid status
	for _, r := range results {
		if r.ControlID == "" {
			t.Error("Result has empty ControlID")
		}
		if r.Status == "" {
			t.Errorf("Result for %s has empty Status", r.ControlID)
		}
	}
}

// TestCISCheck_All_NonCompliant verifies CheckAll with empty input returns
// all 42 results and none are "compliant".
func TestCISCheck_All_NonCompliant(t *testing.T) {
	m := NewCISModule()
	ctx := context.Background()

	results, err := m.CheckAll(ctx, []byte(`{}`))
	if err != nil {
		t.Fatalf("CheckAll returned error: %v", err)
	}
	if len(results) != 42 {
		t.Errorf("CheckAll returned %d results, want 42", len(results))
	}
	for _, r := range results {
		if r.Status == "compliant" {
			t.Errorf("Control %s unexpectedly compliant on empty config", r.ControlID)
		}
	}
}
