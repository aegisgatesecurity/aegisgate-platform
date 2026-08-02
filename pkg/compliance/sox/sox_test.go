// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// SOX Compliance Module Tests
// =========================================================================

package sox

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewSOXModule(t *testing.T) {
	t.Run("CreatesModule", func(t *testing.T) {
		m := NewSOXModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if m.Framework() != "sox" {
			t.Errorf("Framework() = %q, want %q", m.Framework(), "sox")
		}
		if m.Version() != "2002" {
			t.Errorf("Version() = %q, want %q", m.Version(), "2002")
		}
	})

	t.Run("InitializesSOXPatterns", func(t *testing.T) {
		m := NewSOXModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if len(m.soxPatterns) == 0 {
			t.Error("expected SOX patterns to be initialized")
		}
	})
}

func TestSOXModuleControls(t *testing.T) {
	m := NewSOXModule()

	t.Run("ControlsRegistered", func(t *testing.T) {
		controls := m.Controls()
		if len(controls) == 0 {
			t.Error("expected controls to be registered")
		}
	})

	t.Run("AllControlsHaveIDs", func(t *testing.T) {
		controls := m.Controls()
		for _, c := range controls {
			if c.ID == "" {
				t.Error("control has empty ID")
			}
			if c.Name == "" {
				t.Errorf("control %s has empty Name", c.ID)
			}
		}
	})
}

func TestSOXControlCount(t *testing.T) {
	m := NewSOXModule()
	controls := m.Controls()
	if len(controls) != 16 {
		t.Errorf("len(Controls()) = %d, want 16 (3 IC + 3 FR + 3 DP + 3 IT + 2 WP + 2 AI)", len(controls))
	}
	expectedIDs := map[string]bool{
		"SOX-IC-001": false, "SOX-IC-002": false, "SOX-IC-003": false,
		"SOX-FR-001": false, "SOX-FR-002": false, "SOX-FR-003": false,
		"SOX-DP-001": false, "SOX-DP-002": false, "SOX-DP-003": false,
		"SOX-IT-001": false, "SOX-IT-002": false, "SOX-IT-003": false,
		"SOX-WP-001": false, "SOX-WP-002": false,
		"SOX-AI-001": false, "SOX-AI-002": false,
	}
	for _, c := range controls {
		if _, ok := expectedIDs[c.ID]; ok {
			expectedIDs[c.ID] = true
		}
	}
	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected control %s not registered", id)
		}
	}
}

func TestSOXCheckAll(t *testing.T) {
	m := NewSOXModule()

	t.Run("CheckAllWithValidInput", func(t *testing.T) {
		input := []byte("internal_control_assessment records_retention change_management")
		results, err := m.CheckAll(context.Background(), input)
		if err != nil {
			t.Fatalf("CheckAll returned error: %v", err)
		}
		if len(results) == 0 {
			t.Error("expected non-empty results")
		}
	})

	t.Run("CheckAllWithEmptyInput", func(t *testing.T) {
		input := []byte("")
		results, err := m.CheckAll(context.Background(), input)
		if err != nil {
			t.Fatalf("CheckAll returned error: %v", err)
		}
		if len(results) == 0 {
			t.Error("expected non-empty results")
		}
	})
}

func TestFinancialDataDetection(t *testing.T) {
	m := NewSOXModule()

	t.Run("DetectSSN", func(t *testing.T) {
		found := m.detectFinancialData("SSN: 123-45-6789")
		if len(found) == 0 {
			t.Error("expected SSN pattern to be detected")
		}
	})

	t.Run("DetectCreditCard", func(t *testing.T) {
		found := m.detectFinancialData("credit card: 4111111111111111")
		if len(found) == 0 {
			t.Error("expected credit card pattern to be detected")
		}
	})

	t.Run("DetectBankAccount", func(t *testing.T) {
		found := m.detectFinancialData("routing 123456789")
		if len(found) == 0 {
			t.Error("expected bank account/routing pattern to be detected")
		}
	})

	t.Run("DetectSOXMarker", func(t *testing.T) {
		found := m.detectFinancialData("sox compliant framework")
		if len(found) == 0 {
			t.Error("expected SOX marker pattern to be detected")
		}
	})

	t.Run("CleanContent", func(t *testing.T) {
		found := m.detectFinancialData("clean content no financial data")
		if len(found) != 0 {
			t.Errorf("expected no SOX patterns in clean content, got %v", found)
		}
	})
}

// Internal Controls tests

func TestInternalControlAssessmentCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("internal_control_assessment icfr control_testing")
		result, err := m.checkInternalControlAssessment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_policy_defined")
		result, err := m.checkInternalControlAssessment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestControlEnvironmentCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("control_environment tone_at_top governance_policy")
		result, err := m.checkControlEnvironment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkControlEnvironment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestRiskAssessmentCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("risk_assessment risk_framework financial_risk")
		result, err := m.checkRiskAssessment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_risk_policy")
		result, err := m.checkRiskAssessment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Financial Reporting tests

func TestFinancialStatementIntegrityCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("financial_statement reporting_integrity financial_accuracy")
		result, err := m.checkFinancialStatementIntegrity(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_integrity_controls")
		result, err := m.checkFinancialStatementIntegrity(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestRealTimeDisclosureCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("real_time_disclosure material_event current_report")
		result, err := m.checkRealTimeDisclosure(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_disclosure")
		result, err := m.checkRealTimeDisclosure(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAuditCommitteeOversightCheck(t *testing.T) {
	m := NewSOXModule()

	// SOX-FR-003 is NOT automated (Automated: false), so it has no CheckFunc.
	// Verify that the control exists in the Controls list.
	t.Run("AuditCommitteeOversightControlExists", func(t *testing.T) {
		controls := m.Controls()
		found := false
		for _, c := range controls {
			if c.ID == "SOX-FR-003" {
				found = true
				if c.Automated {
					t.Error("expected SOX-FR-003 to not be automated")
				}
				break
			}
		}
		if !found {
			t.Error("expected SOX-FR-003 control to be registered")
		}
	})
}

// Data Protection tests

func TestRecordsRetentionCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("records_retention data_retention_policy retention_schedule")
		result, err := m.checkRecordsRetention(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_retention_policy")
		result, err := m.checkRecordsRetention(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestDataIntegrityCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("data_integrity reconciliation data_validation")
		result, err := m.checkDataIntegrity(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_integrity_controls")
		result, err := m.checkDataIntegrity(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestFinancialAccessControlsCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("access_control rbac mfa financial_access")
		result, err := m.checkFinancialAccessControls(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("access_control rbac")
		result, err := m.checkFinancialAccessControls(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkFinancialAccessControls(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// IT General Controls tests

func TestChangeManagementCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("change_management change_control cab_approval")
		result, err := m.checkChangeManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_changes")
		result, err := m.checkChangeManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestITSecurityControlsCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("it_security security_controls vulnerability_management")
		result, err := m.checkITSecurityControls(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_vuln_mgmt")
		result, err := m.checkITSecurityControls(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestBackupRecoveryCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("backup_recovery disaster_recovery business_continuity")
		result, err := m.checkBackupRecovery(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("backup_recovery disaster_recovery")
		result, err := m.checkBackupRecovery(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_backup_policy")
		result, err := m.checkBackupRecovery(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Whistleblower Protection tests

func TestWhistleblowerProtectionCheck(t *testing.T) {
	m := NewSOXModule()

	// SOX-WP-001 is NOT automated (Automated: false), so it has no CheckFunc.
	// Verify that the control exists in the Controls list.
	t.Run("WhistleblowerProtectionControlExists", func(t *testing.T) {
		controls := m.Controls()
		found := false
		for _, c := range controls {
			if c.ID == "SOX-WP-001" {
				found = true
				if c.Automated {
					t.Error("expected SOX-WP-001 to not be automated")
				}
				break
			}
		}
		if !found {
			t.Error("expected SOX-WP-001 control to be registered")
		}
	})
}

func TestAnonymousReportingCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("anonymous_reporting whistleblower_hotline ethics_line")
		result, err := m.checkAnonymousReporting(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_reporting_channel")
		result, err := m.checkAnonymousReporting(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// AI-Specific tests

func TestAIModelFinancialProtectionCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("NoFinancialData", func(t *testing.T) {
		input := []byte("safe_ai_data with no financial records")
		result, err := m.checkAIModelFinancialProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("FinancialDataDetected", func(t *testing.T) {
		input := []byte("SSN: 123-45-6789")
		result, err := m.checkAIModelFinancialProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAIAuditTrailFinancialCheck(t *testing.T) {
	m := NewSOXModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ai_audit_trail model_logging financial_audit_trail")
		result, err := m.checkAIAuditTrailFinancial(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("ai_audit_trail model_logging")
		result, err := m.checkAIAuditTrailFinancial(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_audit_trail")
		result, err := m.checkAIAuditTrailFinancial(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestDependencies(t *testing.T) {
	m := NewSOXModule()
	deps := m.Dependencies()
	found := false
	for _, dep := range deps {
		if dep == "scanner" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'scanner' in dependencies")
	}
}

func TestCheckControl(t *testing.T) {
	m := NewSOXModule()

	t.Run("ExistingControl", func(t *testing.T) {
		controls := m.Controls()
		if len(controls) == 0 {
			t.Fatal("no controls registered")
		}
		result, err := m.CheckControl(context.Background(), controls[0].ID, []byte("test"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})

	t.Run("NonExistentControl", func(t *testing.T) {
		_, err := m.CheckControl(context.Background(), "NON-EXISTENT", []byte("test"))
		if err == nil {
			t.Error("expected error for non-existent control")
		}
	})
}

func TestGenerateAssessment(t *testing.T) {
	m := NewSOXModule()

	t.Run("GenerateAssessment", func(t *testing.T) {
		assessment, err := m.GenerateAssessment(context.Background(), []byte("test"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if assessment == nil {
			t.Error("expected non-nil assessment")
		}
	})
}

func TestModuleProvisions(t *testing.T) {
	m := NewSOXModule()

	t.Run("ProvidesFrameworks", func(t *testing.T) {
		frameworks := m.Provides()
		if len(frameworks) == 0 {
			t.Error("expected non-empty frameworks")
		}
	})
}