// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// GLBA Compliance Module Tests
// =========================================================================

package glba

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewGLBAModule(t *testing.T) {
	t.Run("CreatesModule", func(t *testing.T) {
		m := NewGLBAModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if m.Framework() != "glba" {
			t.Errorf("Framework() = %q, want %q", m.Framework(), "glba")
		}
		if m.Version() != "1999" {
			t.Errorf("Version() = %q, want %q", m.Version(), "1999")
		}
	})

	t.Run("InitializesNPIPatterns", func(t *testing.T) {
		m := NewGLBAModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if len(m.npiPatterns) == 0 {
			t.Error("expected NPI patterns to be initialized")
		}
	})
}

func TestGLBAModuleControls(t *testing.T) {
	m := NewGLBAModule()

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

func TestGLBAControlCount(t *testing.T) {
	m := NewGLBAModule()
	controls := m.Controls()
	if len(controls) != 14 {
		t.Errorf("len(Controls()) = %d, want 14 (3 FP + 4 SG + 3 DP + 2 PP + 2 AI)", len(controls))
	}
	expectedIDs := map[string]bool{
		"GLBA-FP-001": false, "GLBA-FP-002": false, "GLBA-FP-003": false,
		"GLBA-SG-001": false, "GLBA-SG-002": false, "GLBA-SG-003": false, "GLBA-SG-004": false,
		"GLBA-DP-001": false, "GLBA-DP-002": false, "GLBA-DP-003": false,
		"GLBA-PP-001": false, "GLBA-PP-002": false,
		"GLBA-AI-001": false, "GLBA-AI-002": false,
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

func TestGLBACheckAll(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CheckAllWithValidInput", func(t *testing.T) {
		input := []byte("security_program risk_assessment encryption_at_rest")
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

func TestNPIDetection(t *testing.T) {
	m := NewGLBAModule()

	t.Run("DetectSSN", func(t *testing.T) {
		found := m.detectNPI("SSN: 123-45-6789")
		if len(found) == 0 {
			t.Error("expected SSN pattern to be detected")
		}
	})

	t.Run("DetectCreditCard", func(t *testing.T) {
		found := m.detectNPI("card: 4111-1111-1111-1111")
		if len(found) == 0 {
			t.Error("expected credit card pattern to be detected")
		}
	})

	t.Run("DetectBankAccount", func(t *testing.T) {
		found := m.detectNPI("account number ABC123456")
		if len(found) == 0 {
			t.Error("expected bank account pattern to be detected")
		}
	})

	t.Run("DetectGLBAMarker", func(t *testing.T) {
		found := m.detectNPI("nonpublic personal information")
		if len(found) == 0 {
			t.Error("expected GLBA marker pattern to be detected")
		}
	})

	t.Run("CleanContent", func(t *testing.T) {
		found := m.detectNPI("clean content no financial data")
		if len(found) != 0 {
			t.Errorf("expected no NPI patterns in clean content, got %v", found)
		}
	})
}

// Financial Privacy Rule tests

func TestPrivacyNoticeCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("privacy_notice privacy_disclosure initial_notice")
		result, err := m.checkPrivacyNotice(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkPrivacyNotice(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestOptOutRightsCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("opt_out information_sharing_opt_out privacy_choice")
		result, err := m.checkOptOutRights(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkOptOutRights(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestInformationSharingSafeguardsCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("information_sharing third_party_sharing nonaffiliated_disclosure")
		result, err := m.checkInformationSharingSafeguards(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkInformationSharingSafeguards(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Safeguards Rule tests

func TestInformationSecurityProgramCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("security_program information_security_plan risk_assessment")
		result, err := m.checkInformationSecurityProgram(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkInformationSecurityProgram(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestRiskAssessmentCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("risk_assessment npi_risk threat_analysis")
		result, err := m.checkRiskAssessment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkRiskAssessment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAccessControlsCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("access_control rbac npi_access")
		result, err := m.checkAccessControls(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("access_control rbac")
		result, err := m.checkAccessControls(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkAccessControls(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestVendorManagementCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("vendor_management service_provider contractual_safeguards")
		result, err := m.checkVendorManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkVendorManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Data Protection tests

func TestEncryptionAtRestCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("encryption_at_rest data_encrypted aes_256")
		result, err := m.checkEncryptionAtRest(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
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
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("tls1.3 enabled for all connections")
		result, err := m.checkEncryptionInTransit(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("https enabled for web traffic")
		result, err := m.checkEncryptionInTransit(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkEncryptionInTransit(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestDataRetentionDisposalCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("data_retention secure_disposal npi_retention")
		result, err := m.checkDataRetentionDisposal(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkDataRetentionDisposal(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Pretexting Protection tests

func TestPretextingPreventionCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("pretexting_prevention fraud_detection identity_verification")
		result, err := m.checkPretextingPrevention(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkPretextingPrevention(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestCustomerAuthenticationCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("customer_authentication mfa identity_verification")
		result, err := m.checkCustomerAuthentication(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkCustomerAuthentication(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// AI-Specific tests

func TestAIModelNPIProtectionCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("NoNPI", func(t *testing.T) {
		input := []byte("safe_ai_data with no financial records")
		result, err := m.checkAIModelNPIProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NPIDetected", func(t *testing.T) {
		input := []byte("SSN: 123-45-6789")
		result, err := m.checkAIModelNPIProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAIAuditTrailFinancialPrivacyCheck(t *testing.T) {
	m := NewGLBAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ai_audit_trail model_logging npi_audit_log")
		result, err := m.checkAIAuditTrailFinancialPrivacy(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("ai_audit_trail model_logging")
		result, err := m.checkAIAuditTrailFinancialPrivacy(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_open")
		result, err := m.checkAIAuditTrailFinancialPrivacy(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestDependencies(t *testing.T) {
	m := NewGLBAModule()
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
	m := NewGLBAModule()

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
	m := NewGLBAModule()

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
	m := NewGLBAModule()

	t.Run("ProvidesFrameworks", func(t *testing.T) {
		frameworks := m.Provides()
		if len(frameworks) == 0 {
			t.Error("expected non-empty frameworks")
		}
	})
}
