// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// CJIS Compliance Module Tests
// =========================================================================

package cjis

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewCJISModule(t *testing.T) {
	t.Run("CreatesModule", func(t *testing.T) {
		m := NewCJISModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if m.Framework() != "cjis" {
			t.Errorf("Framework() = %q, want %q", m.Framework(), "cjis")
		}
		if m.Version() != "5.9.1" {
			t.Errorf("Version() = %q, want %q", m.Version(), "5.9.1")
		}
	})

	t.Run("InitializesCJIPatterns", func(t *testing.T) {
		m := NewCJISModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if len(m.cjiPatterns) == 0 {
			t.Error("expected CJI patterns to be initialized")
		}
	})
}

func TestCJISModuleControls(t *testing.T) {
	m := NewCJISModule()

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

func TestCJISControlCount(t *testing.T) {
	m := NewCJISModule()
	controls := m.Controls()
	if len(controls) != 16 {
		t.Errorf("len(Controls()) = %d, want 16 (3 IM + 3 PS + 3 AC + 2 PP + 3 CR + 2 AI)", len(controls))
	}
	expectedIDs := map[string]bool{
		"CJIS-IM-001": false, "CJIS-IM-002": false, "CJIS-IM-003": false,
		"CJIS-PS-001": false, "CJIS-PS-002": false, "CJIS-PS-003": false,
		"CJIS-AC-001": false, "CJIS-AC-002": false, "CJIS-AC-003": false,
		"CJIS-PP-001": false, "CJIS-PP-002": false,
		"CJIS-CR-001": false, "CJIS-CR-002": false, "CJIS-CR-003": false,
		"CJIS-AI-001": false, "CJIS-AI-002": false,
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

func TestCJISCheckAll(t *testing.T) {
	m := NewCJISModule()

	t.Run("CheckAllWithValidInput", func(t *testing.T) {
		input := []byte("audit_log enabled rbac configured access_control")
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

func TestCJIDetection(t *testing.T) {
	m := NewCJISModule()

	t.Run("DetectSSN", func(t *testing.T) {
		found := m.detectCJI("SSN: 123-45-6789")
		if len(found) == 0 {
			t.Error("expected SSN pattern to be detected")
		}
	})

	t.Run("DetectCaseNumber", func(t *testing.T) {
		found := m.detectCJI("Case: 23-456789")
		if len(found) == 0 {
			t.Error("expected case number pattern to be detected")
		}
	})

	t.Run("DetectFBINumber", func(t *testing.T) {
		found := m.detectCJI("FBI 12345678")
		if len(found) == 0 {
			t.Error("expected FBI number pattern to be detected")
		}
	})

	t.Run("DetectNCICNumber", func(t *testing.T) {
		found := m.detectCJI("NCIC 1234567890")
		if len(found) == 0 {
			t.Error("expected NCIC number pattern to be detected")
		}
	})

	t.Run("CleanContent", func(t *testing.T) {
		found := m.detectCJI("This is clean content with no CJI")
		if len(found) != 0 {
			t.Errorf("expected no CJI patterns in clean content, got %v", found)
		}
	})
}

// Information Management tests

func TestInformationManagementCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("information_management_policy configured data_classification enabled")
		result, err := m.checkInformationManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_policy_configured")
		result, err := m.checkInformationManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestMediaProtectionCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("media_protection enabled encryption_at_rest configured")
		result, err := m.checkMediaProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("encryption_at_rest configured")
		result, err := m.checkMediaProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_protection")
		result, err := m.checkMediaProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestRecordRetentionCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("record_retention policy data_retention_policy configured")
		result, err := m.checkRecordRetention(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_retention_policy")
		result, err := m.checkRecordRetention(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Personnel Security tests

func TestPersonnelSecurityCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("personnel_security screening background_checks enabled")
		result, err := m.checkPersonnelSecurity(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_policy_no_checks")
		result, err := m.checkPersonnelSecurity(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestSecurityAwarenessTrainingCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("security_training program security_awareness configured")
		result, err := m.checkSecurityAwarenessTraining(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_training_configured")
		result, err := m.checkSecurityAwarenessTraining(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestIncidentResponseTrainingCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("incident_response_training program ir_training configured")
		result, err := m.checkIncidentResponseTraining(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_policy_no_ir")
		result, err := m.checkIncidentResponseTraining(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Access Control tests

func TestAccessControlCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("access_control policy rbac configured")
		result, err := m.checkAccessControl(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_policy_open")
		result, err := m.checkAccessControl(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAccountManagementCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("account_management configured user_provisioning enabled")
		result, err := m.checkAccountManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_policy_no_provisioning")
		result, err := m.checkAccountManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAuditAccountabilityCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("audit_log enabled audit_enabled logging_enabled configured")
		result, err := m.checkAuditAccountability(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_audit_configured")
		result, err := m.checkAuditAccountability(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Physical Protection tests

func TestMobileDeviceSecurityCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("mobile_device_management mdm device_enrollment configured")
		result, err := m.checkMobileDeviceSecurity(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open_devices")
		result, err := m.checkMobileDeviceSecurity(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Cryptography tests

func TestEncryptionAtRestCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("encryption_at_rest configured aes_256 fips validated")
		result, err := m.checkEncryptionAtRest(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_encryption_configured")
		result, err := m.checkEncryptionAtRest(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestEncryptionInTransitCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("TLS13Compliant", func(t *testing.T) {
		input := []byte("tls1.3 enabled https configured")
		result, err := m.checkEncryptionInTransit(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("TLSPartial", func(t *testing.T) {
		input := []byte("tls https configured")
		result, err := m.checkEncryptionInTransit(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("http_only")
		result, err := m.checkEncryptionInTransit(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestKeyManagementCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("key_management configured key_rotation enabled kms")
		result, err := m.checkKeyManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_key_mgmt")
		result, err := m.checkKeyManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// AI-Specific tests

func TestAIModelCJIProtectionCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("NoCJIDetected", func(t *testing.T) {
		input := []byte("safe_ai_data with no criminal justice information")
		result, err := m.checkAIModelCJIProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("CJIDetected", func(t *testing.T) {
		input := []byte("case data SSN: 123-45-6789")
		result, err := m.checkAIModelCJIProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAIAuditTrailCheck(t *testing.T) {
	m := NewCJISModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("audit_log enabled ai_audit_trail model_logging configured")
		result, err := m.checkAIAuditTrail(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("audit_log enabled ai_audit_trail configured")
		result, err := m.checkAIAuditTrail(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_audit_configured")
		result, err := m.checkAIAuditTrail(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestDependencies(t *testing.T) {
	m := NewCJISModule()
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
	m := NewCJISModule()

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
	m := NewCJISModule()

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
	m := NewCJISModule()

	t.Run("ProvidesFrameworks", func(t *testing.T) {
		frameworks := m.Provides()
		if len(frameworks) == 0 {
			t.Error("expected non-empty frameworks")
		}
	})
}