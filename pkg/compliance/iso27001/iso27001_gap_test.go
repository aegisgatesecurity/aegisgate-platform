// SPDX-License-Identifier: Apache-2.0
// Coverage gap tests for ISO 27001 compliance module.

package iso27001

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// --- helpers ---

// runStandardCheckTests tests compliant, partial, and non_compliant paths
// for functions that delegate to standardCheck.
func runStandardCheckGap(t *testing.T, name string,
	fn func(context.Context, []byte) (*compliance.ControlCheckResult, error),
	expectedID string, keywords []string,
) {
	t.Helper()
	ctx := context.Background()

	// Compliant: all 4 keywords present (>= 3 required).
	compliantInput := []byte(keywords[0] + " " + keywords[1] + " " + keywords[2] + " " + keywords[3])
	t.Run(name+"_Compliant", func(t *testing.T) {
		r, err := fn(ctx, compliantInput)
		if err != nil {
			t.Fatalf("%s compliant: %v", name, err)
		}
		if r.ControlID != expectedID {
			t.Errorf("ControlID = %q, want %q", r.ControlID, expectedID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Partial: only 1 keyword present (1 <= present < 3).
	partialInput := []byte(keywords[0])
	t.Run(name+"_Partial", func(t *testing.T) {
		r, err := fn(ctx, partialInput)
		if err != nil {
			t.Fatalf("%s partial: %v", name, err)
		}
		if r.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})

	// Non-compliant: no keywords present.
	nonCompliantInput := []byte("nothing_relevant_here")
	t.Run(name+"_NonCompliant", func(t *testing.T) {
		r, err := fn(ctx, nonCompliantInput)
		if err != nil {
			t.Fatalf("%s non-compliant: %v", name, err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// runDualConditionCheck tests compliant, partial (one condition), and
// non_compliant (neither condition) paths for functions with hasX && hasY.
func runDualConditionCheck(t *testing.T, name string,
	fn func(context.Context, []byte) (*compliance.ControlCheckResult, error),
	expectedID, condA, condB string,
) {
	t.Helper()
	ctx := context.Background()

	// Compliant: both conditions present.
	t.Run(name+"_Compliant", func(t *testing.T) {
		r, err := fn(ctx, []byte(condA+" "+condB))
		if err != nil {
			t.Fatalf("%s compliant: %v", name, err)
		}
		if r.ControlID != expectedID {
			t.Errorf("ControlID = %q, want %q", r.ControlID, expectedID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Partial: only condA present.
	t.Run(name+"_PartialA", func(t *testing.T) {
		r, err := fn(ctx, []byte(condA))
		if err != nil {
			t.Fatalf("%s partialA: %v", name, err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Partial: only condB present.
	t.Run(name+"_PartialB", func(t *testing.T) {
		r, err := fn(ctx, []byte(condB))
		if err != nil {
			t.Fatalf("%s partialB: %v", name, err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Non-compliant: neither condition present.
	t.Run(name+"_NonCompliant", func(t *testing.T) {
		r, err := fn(ctx, []byte("nothing_relevant_here"))
		if err != nil {
			t.Fatalf("%s non-compliant: %v", name, err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// --- standardCheck-based gap tests ---

func TestGapCheckAssetInventory(t *testing.T) {
	runStandardCheckGap(t, "AssetInventory", NewISO27001Module().checkAssetInventory, "ISO27001-A.5.9",
		[]string{"asset_inventory", "inventory", "asset_tracking", "cmdb"})
}

func TestGapCheckAccessControlPolicy(t *testing.T) {
	runStandardCheckGap(t, "AccessControlPolicy", NewISO27001Module().checkAccessControlPolicy, "ISO27001-A.5.15",
		[]string{"access_control", "rbac", "access_policy", "access_restriction"})
}

func TestGapCheckIdentityMgmt(t *testing.T) {
	runStandardCheckGap(t, "IdentityMgmt", NewISO27001Module().checkIdentityMgmt, "ISO27001-A.5.16",
		[]string{"identity_management", "iam", "user_provisioning", "lifecycle_management"})
}

func TestGapCheckAuthInfoMgmt(t *testing.T) {
	runStandardCheckGap(t, "AuthInfoMgmt", NewISO27001Module().checkAuthInfoMgmt, "ISO27001-A.5.17",
		[]string{"password_policy", "mfa", "authentication", "credential_management"})
}

func TestGapCheckAccessRights(t *testing.T) {
	runStandardCheckGap(t, "AccessRights", NewISO27001Module().checkAccessRights, "ISO27001-A.5.18",
		[]string{"access_review", "access_rights", "privilege_management", "access_revocation"})
}

func TestGapCheckRecordProtection(t *testing.T) {
	runStandardCheckGap(t, "RecordProtection", NewISO27001Module().checkRecordProtection, "ISO27001-A.5.33",
		[]string{"record_protection", "data_integrity", "backup", "retention_policy"})
}

func TestGapCheckClearDesk(t *testing.T) {
	runStandardCheckGap(t, "ClearDesk", NewISO27001Module().checkClearDesk, "ISO27001-A.7.7",
		[]string{"clear_desk", "screen_lock", "auto_lock", "workstation_security"})
}

func TestGapCheckSupportingUtilities(t *testing.T) {
	runStandardCheckGap(t, "SupportingUtilities", NewISO27001Module().checkSupportingUtilities, "ISO27001-A.7.11",
		[]string{"ups", "power_backup", "environmental_monitoring", "cooling"})
}

func TestGapCheckCapacityMgmt(t *testing.T) {
	runStandardCheckGap(t, "CapacityMgmt", NewISO27001Module().checkCapacityMgmt, "ISO27001-A.8.6",
		[]string{"capacity_monitoring", "resource_monitoring", "disk_usage", "cpu_monitoring"})
}

func TestGapCheckSoftwareInstallation(t *testing.T) {
	runStandardCheckGap(t, "SoftwareInstallation", NewISO27001Module().checkSoftwareInstallation, "ISO27001-A.8.19",
		[]string{"software_installation", "package_management", "whitelist", "patching"})
}

func TestGapCheckComplianceVerification(t *testing.T) {
	runStandardCheckGap(t, "ComplianceVerification", NewISO27001Module().checkComplianceVerification, "ISO27001-A.8.36",
		[]string{"compliance_scan", "policy_audit", "compliance_check", "audit_log"})
}

func TestGapCheckSystemSecuring(t *testing.T) {
	runStandardCheckGap(t, "SystemSecuring", NewISO27001Module().checkSystemSecuring, "ISO27001-A.8.38",
		[]string{"hardening", "baseline_security", "cis_benchmark", "stig"})
}

func TestGapCheckConfigHardening(t *testing.T) {
	runStandardCheckGap(t, "ConfigHardening", NewISO27001Module().checkConfigHardening, "ISO27001-A.8.39",
		[]string{"config_hardening", "baseline_config", "security_baseline", "hardening"})
}

func TestGapCheckMLSecurity(t *testing.T) {
	runStandardCheckGap(t, "MLSecurity", NewISO27001Module().checkMLSecurity, "ISO27001-A.8.40",
		[]string{"ml_security", "ai_security", "model_protection", "adversarial_detection"})
}

func TestGapCheckICTReadiness(t *testing.T) {
	runStandardCheckGap(t, "ICTReadiness", NewISO27001Module().checkICTReadiness, "ISO27001-A.8.41",
		[]string{"dr_test", "failover_test", "recovery_test", "continuity_test"})
}

func TestGapCheckPrivilegedAccessMgmt(t *testing.T) {
	runStandardCheckGap(t, "PrivilegedAccessMgmt", NewISO27001Module().checkPrivilegedAccessMgmt, "ISO27001-A.8.42",
		[]string{"pam", "privileged_access", "root_access", "admin_audit"})
}

func TestGapCheckInfoBackup(t *testing.T) {
	runStandardCheckGap(t, "InfoBackup", NewISO27001Module().checkInfoBackup, "ISO27001-A.8.43",
		[]string{"backup", "backup_test", "backup_retention", "backup_encryption"})
}

func TestGapCheckRedundancyInfo(t *testing.T) {
	runStandardCheckGap(t, "RedundancyInfo", NewISO27001Module().checkRedundancyInfo, "ISO27001-A.8.44",
		[]string{"redundancy", "high_availability", "failover", "multi_zone"})
}

func TestGapCheckClockSync2(t *testing.T) {
	runStandardCheckGap(t, "ClockSync2", NewISO27001Module().checkClockSync2, "ISO27001-A.8.45",
		[]string{"ntp", "chrony", "time_sync", "clock_sync"})
}

func TestGapCheckSecureDisposal2(t *testing.T) {
	runStandardCheckGap(t, "SecureDisposal2", NewISO27001Module().checkSecureDisposal2, "ISO27001-A.8.47",
		[]string{"secure_disposal", "data_erasure", "asset_sanitization", "disposal_certificate"})
}

func TestGapCheckDataPrivacy(t *testing.T) {
	runStandardCheckGap(t, "DataPrivacy", NewISO27001Module().checkDataPrivacy, "ISO27001-A.8.48",
		[]string{"pii_protection", "privacy_controls", "data_privacy", "gdpr_compliance"})
}

func TestGapCheckDataMasking2(t *testing.T) {
	runStandardCheckGap(t, "DataMasking2", NewISO27001Module().checkDataMasking2, "ISO27001-A.8.49",
		[]string{"data_masking", "pii_masking", "tokenization", "anonymization"})
}

func TestGapCheckEndpointSecurity2(t *testing.T) {
	runStandardCheckGap(t, "EndpointSecurity2", NewISO27001Module().checkEndpointSecurity2, "ISO27001-A.8.50",
		[]string{"endpoint_security", "edr", "antivirus", "device_compliance"})
}

func TestGapCheckNetworkSegmentation2(t *testing.T) {
	runStandardCheckGap(t, "NetworkSegmentation2", NewISO27001Module().checkNetworkSegmentation2, "ISO27001-A.8.51",
		[]string{"network_segmentation", "vlan", "dmz", "security_zone"})
}

func TestGapCheckSecretMgmt(t *testing.T) {
	runStandardCheckGap(t, "SecretMgmt", NewISO27001Module().checkSecretMgmt, "ISO27001-A.8.52",
		[]string{"secret_management", "vault", "key_management", "hsm"})
}

// --- dual-condition check gap tests ---

func TestGapCheckInfoSecPolicies(t *testing.T) {
	runDualConditionCheck(t, "InfoSecPolicies", NewISO27001Module().checkInfoSecPolicies,
		"ISO27001-A.5.1", "infosec_policy", "policy_approved")
}

func TestGapCheckInfoSecProjectMgmt(t *testing.T) {
	runDualConditionCheck(t, "InfoSecProjectMgmt", NewISO27001Module().checkInfoSecProjectMgmt,
		"ISO27001-A.5.8", "project_management", "security_integration")
}

func TestGapCheckOutsourcedDevelopment(t *testing.T) {
	runDualConditionCheck(t, "OutsourcedDevelopment", NewISO27001Module().checkOutsourcedDevelopment,
		"ISO27001-A.8.30", "outsourced_development", "outsourced_security")
}

func TestGapCheckSystemAcquisition(t *testing.T) {
	runDualConditionCheck(t, "SystemAcquisition", NewISO27001Module().checkSystemAcquisition,
		"ISO27001-A.8.37", "system_acquisition", "security_requirements_acquisition")
}

func TestGapCheckAISystemSecurityGovernance(t *testing.T) {
	runDualConditionCheck(t, "AISystemSecurityGovernance", NewISO27001Module().checkAISystemSecurityGovernance,
		"ISO27001-A.8.53", "ai_governance", "ai_oversight")
}

// --- single-condition check gap tests ---

func TestGapCheckISOSegregationOfDuties(t *testing.T) {
	m := NewISO27001Module()
	ctx := context.Background()

	// Compliant: SOD keyword present.
	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkISOSegregationOfDuties(ctx, []byte("segregation_of_duties"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "ISO27001-A.5.3" {
			t.Errorf("ControlID = %q, want ISO27001-A.5.3", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	// Non-compliant: no SOD keyword.
	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkISOSegregationOfDuties(ctx, []byte("nothing_relevant_here"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})
}

// --- isoCount gap tests ---

func TestGapIsoCount(t *testing.T) {
	// n == 0
	if got := isoCount(0); got != "0" {
		t.Errorf("isoCount(0) = %q, want \"0\"", got)
	}
	// n > 0 (multi-digit)
	if got := isoCount(42); got != "42" {
		t.Errorf("isoCount(42) = %q, want \"42\"", got)
	}
	// n > 0 (single digit)
	if got := isoCount(7); got != "7" {
		t.Errorf("isoCount(7) = %q, want \"7\"", got)
	}
	// n < 0 (exercises the negative branch)
	_ = isoCount(-5)
}
