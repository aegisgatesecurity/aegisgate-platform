// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// FERPA Compliance Module Tests
// =========================================================================

package ferpa

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewFERPAModule(t *testing.T) {
	t.Run("CreatesModule", func(t *testing.T) {
		m := NewFERPAModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if m.Framework() != "ferpa" {
			t.Errorf("Framework() = %q, want %q", m.Framework(), "ferpa")
		}
		if m.Version() != "34cfr99" {
			t.Errorf("Version() = %q, want %q", m.Version(), "34cfr99")
		}
	})

	t.Run("InitializesFERPAPatterns", func(t *testing.T) {
		m := NewFERPAModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if len(m.ferpaPatterns) == 0 {
			t.Error("expected FERPA patterns to be initialized")
		}
	})
}

func TestFERPAModuleControls(t *testing.T) {
	m := NewFERPAModule()

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

func TestFERPAControlCount(t *testing.T) {
	m := NewFERPAModule()
	controls := m.Controls()
	if len(controls) != 16 {
		t.Errorf("len(Controls()) = %d, want 16 (3 ER + 3 DI + 3 CD + 3 DS + 4 AI)", len(controls))
	}
	expectedIDs := map[string]bool{
		"FERPA-ER-001": false, "FERPA-ER-002": false, "FERPA-ER-003": false,
		"FERPA-DI-001": false, "FERPA-DI-002": false, "FERPA-DI-003": false,
		"FERPA-CD-001": false, "FERPA-CD-002": false, "FERPA-CD-003": false,
		"FERPA-DS-001": false, "FERPA-DS-002": false, "FERPA-DS-003": false,
		"FERPA-AI-001": false, "FERPA-AI-002": false, "FERPA-AI-003": false, "FERPA-AI-004": false,
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

func TestFERPACheckAll(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CheckAllWithValidInput", func(t *testing.T) {
		input := []byte("audit_log enabled rbac configured access_controls")
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

func TestStudentPIIDetection(t *testing.T) {
	m := NewFERPAModule()

	t.Run("DetectSSN", func(t *testing.T) {
		found := m.detectStudentPII("SSN: 123-45-6789")
		if len(found) == 0 {
			t.Error("expected SSN pattern to be detected")
		}
	})

	t.Run("DetectStudentID", func(t *testing.T) {
		found := m.detectStudentPII("student id ABC12345")
		if len(found) == 0 {
			t.Error("expected student ID pattern to be detected")
		}
	})

	t.Run("DetectFERPAMarker", func(t *testing.T) {
		found := m.detectStudentPII("FERPA protected record")
		if len(found) == 0 {
			t.Error("expected FERPA marker pattern to be detected")
		}
	})

	t.Run("DetectEducationRecord", func(t *testing.T) {
		found := m.detectStudentPII("education record found")
		if len(found) == 0 {
			t.Error("expected education record pattern to be detected")
		}
	})

	t.Run("CleanContent", func(t *testing.T) {
		found := m.detectStudentPII("clean content no pii")
		if len(found) != 0 {
			t.Errorf("expected no FERPA patterns in clean content, got %v", found)
		}
	})
}

// Education Records tests

func TestEducationRecordsAccessCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("education_records_access student_access records_access_policy")
		result, err := m.checkEducationRecordsAccess(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_policy")
		result, err := m.checkEducationRecordsAccess(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestRecordAmendmentCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("record_amendment amendment_request dispute_resolution")
		result, err := m.checkRecordAmendment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_amendment")
		result, err := m.checkRecordAmendment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestRecordDestructionCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("record_destruction data_retention_policy secure_disposal")
		result, err := m.checkRecordDestruction(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_destruction")
		result, err := m.checkRecordDestruction(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Directory Information tests

func TestDirectoryInformationClassificationCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("directory_information public_directory student_directory")
		result, err := m.checkDirectoryInfoClassification(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_directory_policy")
		result, err := m.checkDirectoryInfoClassification(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestOptOutMechanismCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("opt_out directory_opt_out withhold_directory")
		result, err := m.checkOptOutMechanism(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_withhold")
		result, err := m.checkOptOutMechanism(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestDisclosureConsentCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("disclosure_consent written_consent consent_form")
		result, err := m.checkDisclosureConsent(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_consent")
		result, err := m.checkDisclosureConsent(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Consent & Disclosure tests

func TestAuthorizedDisclosureCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("authorized_disclosure disclosure_policy ferpa_exceptions")
		result, err := m.checkAuthorizedDisclosure(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_policy")
		result, err := m.checkAuthorizedDisclosure(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestHealthSafetyExceptionCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("health_safety_exception emergency_disclosure safety_exception")
		result, err := m.checkHealthSafetyException(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_exception")
		result, err := m.checkHealthSafetyException(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestLawEnforcementRecordsCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("law_enforcement_records campus_police security_records")
		result, err := m.checkLawEnforcementRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_records")
		result, err := m.checkLawEnforcementRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Data Security tests

func TestAdministrativeDataSafeguardsCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("administrative_safeguards data_governance access_controls")
		result, err := m.checkAdministrativeSafeguards(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_safeguards")
		result, err := m.checkAdministrativeSafeguards(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestPhysicalDataSafeguardsCheck(t *testing.T) {
	m := NewFERPAModule()

	// FERPA-DS-002 is NOT automated (Automated: false), so it has no CheckFunc.
	// Verify that the control exists in the Controls list.
	t.Run("PhysicalSafeguardsControlExists", func(t *testing.T) {
		controls := m.Controls()
		found := false
		for _, c := range controls {
			if c.ID == "FERPA-DS-002" {
				found = true
				if c.Automated {
					t.Error("expected FERPA-DS-002 to not be automated")
				}
				break
			}
		}
		if !found {
			t.Error("expected FERPA-DS-002 control to be registered")
		}
	})
}

func TestTechnicalDataSafeguardsCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("technical_safeguards encryption_at_rest audit_log mfa")
		result, err := m.checkTechnicalSafeguards(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("technical_safeguards encryption_at_rest")
		result, err := m.checkTechnicalSafeguards(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_safeguards")
		result, err := m.checkTechnicalSafeguards(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// AI-Specific tests

func TestAIModelStudentDataProtectionCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("NoStudentPII", func(t *testing.T) {
		input := []byte("safe_ai_data with no student records")
		result, err := m.checkAIModelStudentDataProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("StudentPIIDetected", func(t *testing.T) {
		input := []byte("student SSN: 123-45-6789")
		result, err := m.checkAIModelStudentDataProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAITrainingDataConsentCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ai_training_consent student_data_consent opt_in_policy")
		result, err := m.checkAITrainingDataConsent(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_consent")
		result, err := m.checkAITrainingDataConsent(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAIAuditTrailForEducationCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ai_audit_trail model_logging education_record_logging")
		result, err := m.checkAIAuditTrail(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("ai_audit_trail model_logging")
		result, err := m.checkAIAuditTrail(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_audit")
		result, err := m.checkAIAuditTrail(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAIBiasDetectionCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("bias_detection fairness_audit equity_review")
		result, err := m.checkAIBiasDetection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_fairness")
		result, err := m.checkAIBiasDetection(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestDependencies(t *testing.T) {
	m := NewFERPAModule()
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
	m := NewFERPAModule()

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
	m := NewFERPAModule()

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
	m := NewFERPAModule()

	t.Run("ProvidesFrameworks", func(t *testing.T) {
		frameworks := m.Provides()
		if len(frameworks) == 0 {
			t.Error("expected non-empty frameworks")
		}
	})
}
