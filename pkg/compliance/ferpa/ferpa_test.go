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
	if len(controls) != 45 {
		t.Errorf("len(Controls()) = %d, want 45 (8 ER + 6 DI + 8 CD + 8 DS + 6 AI + 9 CE)", len(controls))
	}
	expectedIDs := map[string]bool{
		// Student Education Records (8)
		"FERPA-ER-01": false, "FERPA-ER-02": false, "FERPA-ER-03": false,
		"FERPA-ER-04": false, "FERPA-ER-05": false, "FERPA-ER-06": false,
		"FERPA-ER-07": false, "FERPA-ER-08": false,
		// Directory Information (6)
		"FERPA-DI-01": false, "FERPA-DI-02": false, "FERPA-DI-03": false,
		"FERPA-DI-04": false, "FERPA-DI-05": false, "FERPA-DI-06": false,
		// Consent & Disclosure (8)
		"FERPA-CD-01": false, "FERPA-CD-02": false, "FERPA-CD-03": false,
		"FERPA-CD-04": false, "FERPA-CD-05": false, "FERPA-CD-06": false,
		"FERPA-CD-07": false, "FERPA-CD-08": false,
		// Data Security (8)
		"FERPA-DS-01": false, "FERPA-DS-02": false, "FERPA-DS-03": false,
		"FERPA-DS-04": false, "FERPA-DS-05": false, "FERPA-DS-06": false,
		"FERPA-DS-07": false, "FERPA-DS-08": false,
		// AI Controls (6)
		"FERPA-AI-01": false, "FERPA-AI-02": false, "FERPA-AI-03": false,
		"FERPA-AI-04": false, "FERPA-AI-05": false, "FERPA-AI-06": false,
		// Compliance & Enforcement (9)
		"FERPA-CE-01": false, "FERPA-CE-02": false, "FERPA-CE-03": false,
		"FERPA-CE-04": false, "FERPA-CE-05": false, "FERPA-CE-06": false,
		"FERPA-CE-07": false, "FERPA-CE-08": false, "FERPA-CE-09": false,
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

func TestFERPAAutoManualCount(t *testing.T) {
	m := NewFERPAModule()
	controls := m.Controls()
	autoCount := 0
	manualCount := 0
	for _, c := range controls {
		if c.Automated {
			autoCount++
		} else {
			manualCount++
		}
	}
	if autoCount != 31 {
		t.Errorf("autoCount = %d, want 31", autoCount)
	}
	if manualCount != 14 {
		t.Errorf("manualCount = %d, want 14", manualCount)
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
		if result.ControlID != "FERPA-ER-01" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-ER-01")
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
		if result.ControlID != "FERPA-ER-01" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-ER-01")
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
		if result.ControlID != "FERPA-ER-02" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-ER-02")
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
		if result.ControlID != "FERPA-ER-03" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-ER-03")
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

func TestRightToInspectRecordsCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("inspect_records review_records right_to_inspect")
		result, err := m.checkRightToInspectRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-ER-04" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-ER-04")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_inspect_policy")
		result, err := m.checkRightToInspectRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAnnualNotificationOfRightsCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("annual_notification ferpa_rights_notice student_rights_notification")
		result, err := m.checkAnnualNotificationOfRights(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-ER-06" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-ER-06")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_notification")
		result, err := m.checkAnnualNotificationOfRights(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestRecordAccessLogCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("record_access_log access_log disclosure_log")
		result, err := m.checkRecordAccessLog(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-ER-07" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-ER-07")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_logging")
		result, err := m.checkRecordAccessLog(context.Background(), input)
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
		if result.ControlID != "FERPA-DI-01" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DI-01")
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
		if result.ControlID != "FERPA-DI-02" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DI-02")
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
		if result.ControlID != "FERPA-DI-03" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DI-03")
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

func TestAnnualDirectoryInfoNoticeCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("directory_info_notice annual_directory_notice directory_categories_notice")
		result, err := m.checkAnnualDirectoryInfoNotice(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-DI-04" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DI-04")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_notice")
		result, err := m.checkAnnualDirectoryInfoNotice(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestDirectoryInfoDisclosureTrackingCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("disclosure_tracking directory_disclosure_log third_party_disclosure_log")
		result, err := m.checkDirectoryInfoDisclosureTracking(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-DI-05" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DI-05")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_tracking")
		result, err := m.checkDirectoryInfoDisclosureTracking(context.Background(), input)
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
		if result.ControlID != "FERPA-CD-01" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CD-01")
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
		if result.ControlID != "FERPA-CD-02" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CD-02")
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
		if result.ControlID != "FERPA-CD-03" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CD-03")
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

func TestSchoolOfficialExceptionCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("school_official_exception legitimate_educational_interest school_official_disclosure")
		result, err := m.checkSchoolOfficialException(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-CD-04" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CD-04")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_official_exception")
		result, err := m.checkSchoolOfficialException(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestTransferSchoolEnrollmentCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("transfer_enrollment records_transfer school_transfer_disclosure")
		result, err := m.checkTransferSchoolEnrollment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-CD-05" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CD-05")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_transfer")
		result, err := m.checkTransferSchoolEnrollment(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Data Security tests
// Note: FERPA-CD-08 (Court Order/Subpoena Compliance) is a manual control (Automated: false)

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
		if result.ControlID != "FERPA-DS-01" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DS-01")
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

	// FERPA-DS-02 is NOT automated (Automated: false), so it has no CheckFunc.
	// Verify that the control exists in the Controls list.
	t.Run("PhysicalSafeguardsControlExists", func(t *testing.T) {
		controls := m.Controls()
		found := false
		for _, c := range controls {
			if c.ID == "FERPA-DS-02" {
				found = true
				if c.Automated {
					t.Error("expected FERPA-DS-02 to not be automated")
				}
				break
			}
		}
		if !found {
			t.Error("expected FERPA-DS-02 control to be registered")
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
		if result.ControlID != "FERPA-DS-03" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DS-03")
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

func TestEncryptionOfEducationRecordsCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("encryption_at_rest encryption_in_transit tls_enabled")
		result, err := m.checkEncryptionOfEducationRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-DS-04" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DS-04")
		}
	})

	t.Run("PartialConfig", func(t *testing.T) {
		input := []byte("encryption_at_rest")
		result, err := m.checkEncryptionOfEducationRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusPartial)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_encryption")
		result, err := m.checkEncryptionOfEducationRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestAccessControlForEducationRecordsCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("role_based_access rbac_education_records access_control_policy")
		result, err := m.checkAccessControlForEducationRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-DS-05" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DS-05")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_access_control")
		result, err := m.checkAccessControlForEducationRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestDataMinimizationForEducationRecordsCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("data_minimization minimum_necessary_data data_collection_limit")
		result, err := m.checkDataMinimizationForEducationRecords(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-DS-08" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-DS-08")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_minimization")
		result, err := m.checkDataMinimizationForEducationRecords(context.Background(), input)
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
		if result.ControlID != "FERPA-AI-01" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-AI-01")
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
		if result.ControlID != "FERPA-AI-02" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-AI-02")
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
		if result.ControlID != "FERPA-AI-03" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-AI-03")
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
		if result.ControlID != "FERPA-AI-04" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-AI-04")
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

func TestAIGeneratedContentDisclosureCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ai_content_disclosure ai_generated_label ai_content_attribution")
		result, err := m.checkAIGeneratedContentDisclosure(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-AI-05" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-AI-05")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_ai_disclosure")
		result, err := m.checkAIGeneratedContentDisclosure(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Compliance & Enforcement tests

func TestFERPADesignationCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ferpa_designation ferpa_officer compliance_designation")
		result, err := m.checkFERPADesignation(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-CE-01" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CE-01")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_designation")
		result, err := m.checkFERPADesignation(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestPolicyDocumentationCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ferpa_policy policy_documentation ferpa_procedures")
		result, err := m.checkPolicyDocumentation(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-CE-02" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CE-02")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_policy_docs")
		result, err := m.checkPolicyDocumentation(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestTrainingProgramForStaffCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("ferpa_training staff_training_program annual_training")
		result, err := m.checkTrainingProgramForStaff(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-CE-03" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CE-03")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_training")
		result, err := m.checkTrainingProgramForStaff(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestInternalComplianceAuditsCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("internal_compliance_audit ferpa_audit compliance_review")
		result, err := m.checkInternalComplianceAudits(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-CE-04" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CE-04")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_audits")
		result, err := m.checkInternalComplianceAudits(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

func TestStudentComplaintProcessCheck(t *testing.T) {
	m := NewFERPAModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("student_complaint_process ferpa_complaint grievance_procedure")
		result, err := m.checkStudentComplaintProcess(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusCompliant)
		}
		if result.ControlID != "FERPA-CE-05" {
			t.Errorf("ControlID = %q, want %q", result.ControlID, "FERPA-CE-05")
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("no_complaint_process")
		result, err := m.checkStudentComplaintProcess(context.Background(), input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want %q", result.Status, compliance.StatusNonCompliant)
		}
	})
}

// Manual controls existence tests

func TestManualControlsExist(t *testing.T) {
	m := NewFERPAModule()
	manualIDs := []string{
		"FERPA-ER-05", // Records Custodian Designation
		"FERPA-ER-08", // Records Retention Schedule
		"FERPA-DI-06", // Limited Directory Information Policy
		"FERPA-CD-06", // Financial Aid Disclosure
		"FERPA-CD-07", // Accrediting Organization Disclosure
		"FERPA-CD-08", // Court Order/Subpoena Compliance
		"FERPA-DS-02", // Physical Data Safeguards
		"FERPA-DS-06", // Data Breach Response Plan
		"FERPA-DS-07", // Third-Party Service Provider Security
		"FERPA-AI-06", // AI Model Retraining with Student Data Governance
		"FERPA-CE-06", // DOE Complaint Investigation
		"FERPA-CE-07", // Corrective Action Plans
		"FERPA-CE-08", // FERPA Affidavit Requirements
		"FERPA-CE-09", // State Education Authority Reporting
	}
	controls := m.Controls()
	controlMap := make(map[string]bool)
	for _, c := range controls {
		controlMap[c.ID] = c.Automated
	}
	for _, id := range manualIDs {
		auto, exists := controlMap[id]
		if !exists {
			t.Errorf("expected manual control %s to be registered", id)
		}
		if auto {
			t.Errorf("expected control %s to be manual (Automated: false)", id)
		}
	}
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