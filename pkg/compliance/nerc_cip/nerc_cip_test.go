// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - NERC CIP Compliance Module Tests
package nerc_cip

import (
	"context"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewNERCCIPModule(t *testing.T) {
	t.Run("CreatesModule", func(t *testing.T) {
		m := NewNERCCIPModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if m.Framework() != "nerc_cip" {
			t.Errorf("Framework() = %q, want %q", m.Framework(), "nerc_cip")
		}
		if m.Version() != "v5" {
			t.Errorf("Version() = %q, want %q", m.Version(), "v5")
		}
	})

	t.Run("InitializesNERCPatterns", func(t *testing.T) {
		m := NewNERCCIPModule()
		if m == nil {
			t.Fatal("expected non-nil module")
		}
		if len(m.nercPatterns) == 0 {
			t.Error("expected NERC patterns to be initialized")
		}
	})
}

func TestNERCCIPControlCount(t *testing.T) {
	m := NewNERCCIPModule()
	controls := m.Controls()
	if len(controls) != 18 {
		t.Errorf("len(Controls()) = %d, want 18 (2 CS + 1 SM + 2 PT + 2 EP + 2 PS + 2 SS + 1 IR + 1 RP + 1 CM + 1 IP + 1 SC + 2 AI)", len(controls))
	}

	expectedIDs := map[string]bool{
		"NERC-CIP-CS-001": false, "NERC-CIP-CS-002": false,
		"NERC-CIP-SM-001": false,
		"NERC-CIP-PT-001": false, "NERC-CIP-PT-002": false,
		"NERC-CIP-EP-001": false, "NERC-CIP-EP-002": false,
		"NERC-CIP-PS-001": false, "NERC-CIP-PS-002": false,
		"NERC-CIP-SS-001": false, "NERC-CIP-SS-002": false,
		"NERC-CIP-IR-001": false,
		"NERC-CIP-RP-001": false,
		"NERC-CIP-CM-001": false,
		"NERC-CIP-IP-001": false,
		"NERC-CIP-SC-001": false,
		"NERC-CIP-AI-001": false, "NERC-CIP-AI-002": false,
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

func TestNERCCIPPIIDetection(t *testing.T) {
	m := NewNERCCIPModule()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "SSN pattern detected",
			input:    "config: ssn=123-45-6789, env=prod",
			expected: true,
		},
		{
			name:     "SCADA system reference detected",
			input:    "SCADA monitoring system configuration",
			expected: true,
		},
		{
			name:     "BES cyber reference detected",
			input:    "BES cyber system categorization policy",
			expected: true,
		},
		{
			name:     "Grid control reference detected",
			input:    "grid control operations manual",
			expected: true,
		},
		{
			name:     "Substation reference detected",
			input:    "substation security perimeter definition",
			expected: true,
		},
		{
			name:     "NERC reference detected",
			input:    "NERC compliance report 2024",
			expected: true,
		},
		{
			name:     "CIP standard reference detected",
			input:    "CIP-007 system security requirements",
			expected: true,
		},
		{
			name:     "Bulk electric system reference detected",
			input:    "bulk electric system operations",
			expected: true,
		},
		{
			name:     "Transmission operator reference detected",
			input:    "transmission operator access policy",
			expected: true,
		},
		{
			name:     "Reliability coordinator reference detected",
			input:    "reliability coordinator procedures",
			expected: true,
		},
		{
			name:     "Clean config not detected",
			input:    "basic_config_no_sensitive_data",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.detectBESData(tt.input)
			if result != tt.expected {
				t.Errorf("detectBESData(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// Control-specific check tests

func TestBESCyberSystemCategorizationCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("bes_cyber_system categorization policy configured")
		result, err := m.checkBESCyberSystemCategorization(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
		if result.ControlID != "NERC-CIP-CS-001" {
			t.Errorf("Expected ControlID NERC-CIP-CS-001, got %s", result.ControlID)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_categorization")
		result, err := m.checkBESCyberSystemCategorization(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestImpactRatingAssignmentCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("impact_rating assigned to all BES systems")
		result, err := m.checkImpactRatingAssignment(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_rating")
		result, err := m.checkImpactRatingAssignment(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestSecurityManagementControlsCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("security_management controls implemented")
		result, err := m.checkSecurityManagementControls(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_mgmt")
		result, err := m.checkSecurityManagementControls(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestPersonnelRiskAssessmentCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("personnel_risk assessment completed")
		result, err := m.checkPersonnelRiskAssessment(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_screening")
		result, err := m.checkPersonnelRiskAssessment(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestCyberSecurityTrainingCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("cyber_security_training program implemented")
		result, err := m.checkCyberSecurityTraining(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_curriculum")
		result, err := m.checkCyberSecurityTraining(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestElectronicSecurityPerimeterCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("electronic_security_perimeter defined for all BES systems")
		result, err := m.checkElectronicSecurityPerimeter(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_perimeter")
		result, err := m.checkElectronicSecurityPerimeter(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestElectronicAccessMonitoringCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantAllThree", func(t *testing.T) {
		input := []byte("access_monitoring log_monitoring intrusion_detection all active")
		result, err := m.checkElectronicAccessMonitoring(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("PartialWithTwo", func(t *testing.T) {
		input := []byte("access_monitoring and log_monitoring configured")
		result, err := m.checkElectronicAccessMonitoring(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Expected %v, got %v", compliance.StatusPartial, result.Status)
		}
	})

	t.Run("NonCompliantNone", func(t *testing.T) {
		input := []byte("basic_config_no_monitoring")
		result, err := m.checkElectronicAccessMonitoring(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestPhysicalSecurityPerimeterCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("physical_security perimeter established")
		result, err := m.checkPhysicalSecurityPerimeter(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_physical")
		result, err := m.checkPhysicalSecurityPerimeter(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestTransmissionStationSecurityNonAutomated(t *testing.T) {
	m := NewNERCCIPModule()
	controls := m.Controls()

	var ps002 *compliance.ControlDefinition
	for i := range controls {
		if controls[i].ID == "NERC-CIP-PS-002" {
			ps002 = &controls[i]
			break
		}
	}

	if ps002 == nil {
		t.Fatal("Control NERC-CIP-PS-002 not found")
	}
	if ps002.Automated {
		t.Error("NERC-CIP-PS-002 should be non-automated")
	}
	if ps002.CheckFunc != nil {
		t.Error("NERC-CIP-PS-002 should not have a CheckFunc")
	}
}

func TestSystemSecurityManagementCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("system_security management controls verified")
		result, err := m.checkSystemSecurityManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_hardening")
		result, err := m.checkSystemSecurityManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestPatchManagementCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("patch_management program active")
		result, err := m.checkPatchManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_patching")
		result, err := m.checkPatchManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestIncidentResponseReportingCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("incident_response plan established")
		result, err := m.checkIncidentResponseReporting(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_ir")
		result, err := m.checkIncidentResponseReporting(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestRecoveryPlanningCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantAllThree", func(t *testing.T) {
		input := []byte("recovery_plan business_continuity disaster_recovery all documented")
		result, err := m.checkRecoveryPlanning(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("PartialWithTwo", func(t *testing.T) {
		input := []byte("recovery_plan and business_continuity frameworks")
		result, err := m.checkRecoveryPlanning(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Expected %v, got %v", compliance.StatusPartial, result.Status)
		}
	})

	t.Run("NonCompliantNone", func(t *testing.T) {
		input := []byte("basic_config_no_recovery")
		result, err := m.checkRecoveryPlanning(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestConfigurationChangeManagementCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("change_management process documented")
		result, err := m.checkConfigurationChangeManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_chg_mgmt")
		result, err := m.checkConfigurationChangeManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestInformationProtectionCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("information_protection controls implemented")
		result, err := m.checkInformationProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_info_protect")
		result, err := m.checkInformationProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestSupplyChainRiskManagementCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("supply_chain_risk management program")
		result, err := m.checkSupplyChainRiskManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_scrm")
		result, err := m.checkSupplyChainRiskManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestAIModelBESDataProtectionCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantCleanConfig", func(t *testing.T) {
		input := []byte("safe_ai_config with no grid references")
		result, err := m.checkAIModelBESDataProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantSSN", func(t *testing.T) {
		input := []byte("AI model data contains 123-45-6789 SSN reference")
		result, err := m.checkAIModelBESDataProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})

	t.Run("NonCompliantSCADA", func(t *testing.T) {
		input := []byte("AI model trained on SCADA monitoring data")
		result, err := m.checkAIModelBESDataProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})

	t.Run("NonCompliantBESCyber", func(t *testing.T) {
		input := []byte("model uses BES cyber system configuration")
		result, err := m.checkAIModelBESDataProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})

	t.Run("NonCompliantNERC", func(t *testing.T) {
		input := []byte("compliance with NERC standards in AI output")
		result, err := m.checkAIModelBESDataProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})

	t.Run("CompliantSafeData", func(t *testing.T) {
		input := []byte("safe_ai_data with no sensitive references")
		result, err := m.checkAIModelBESDataProtection(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})
}

func TestAIAuditTrailBESCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantAllThree", func(t *testing.T) {
		input := []byte("ai_audit model_logging bes_audit_trail all implemented")
		result, err := m.checkAIAuditTrailBES(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("PartialWithTwo", func(t *testing.T) {
		input := []byte("ai_audit and model_logging configured")
		result, err := m.checkAIAuditTrailBES(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Expected %v, got %v", compliance.StatusPartial, result.Status)
		}
	})

	t.Run("NonCompliantNone", func(t *testing.T) {
		input := []byte("basic_config_no_trail")
		result, err := m.checkAIAuditTrailBES(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestNERCCIPCheckAll(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CheckAllWithCompliantInput", func(t *testing.T) {
		input := []byte(strings.Join([]string{
			"bes_cyber_system categorization active",
			"impact_rating assigned to all systems",
			"security_management controls implemented",
			"personnel_risk assessment completed",
			"cyber_security_training program active",
			"electronic_security_perimeter defined",
			"access_monitoring log_monitoring intrusion_detection active",
			"physical_security perimeter established",
			"system_security management verified",
			"patch_management program active",
			"incident_response plan documented",
			"recovery_plan business_continuity disaster_recovery all in place",
			"change_management process documented",
			"information_protection controls active",
			"supply_chain_risk management program",
			"safe_ai_config with no sensitive data",
			"ai_audit model_logging bes_audit_trail all active",
		}, " "))

		results, err := m.CheckAll(context.Background(), input)
		if err != nil {
			t.Fatalf("CheckAll returned error: %v", err)
		}
		if len(results) != 17 {
			t.Errorf("Expected 17 results (18 controls minus 1 non-automated), got %d", len(results))
		}

		for _, result := range results {
			if result.Status != compliance.StatusCompliant && result.Status != compliance.StatusPartial {
				t.Errorf("Control %s (%s) expected compliant/partial, got %s: %s",
					result.ControlID, result.ControlName, result.Status, result.Message)
			}
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

func TestNERCCIPModuleProvisions(t *testing.T) {
	m := NewNERCCIPModule()
	controls := m.Controls()

	// Verify control categories, severities, and automation
	expectedControls := map[string]struct {
		category  string
		severity  string
		automated bool
	}{
		"NERC-CIP-CS-001": {category: "Cyber System Categorization", severity: "critical", automated: true},
		"NERC-CIP-CS-002": {category: "Cyber System Categorization", severity: "high", automated: true},
		"NERC-CIP-SM-001": {category: "Security Management", severity: "high", automated: true},
		"NERC-CIP-PT-001": {category: "Personnel & Training", severity: "high", automated: true},
		"NERC-CIP-PT-002": {category: "Personnel & Training", severity: "medium", automated: true},
		"NERC-CIP-EP-001": {category: "Electronic Security", severity: "critical", automated: true},
		"NERC-CIP-EP-002": {category: "Electronic Security", severity: "high", automated: true},
		"NERC-CIP-PS-001": {category: "Physical Security", severity: "high", automated: true},
		"NERC-CIP-PS-002": {category: "Physical Security", severity: "critical", automated: false},
		"NERC-CIP-SS-001": {category: "System Security", severity: "high", automated: true},
		"NERC-CIP-SS-002": {category: "System Security", severity: "critical", automated: true},
		"NERC-CIP-IR-001": {category: "Incident Response", severity: "critical", automated: true},
		"NERC-CIP-RP-001": {category: "Recovery Planning", severity: "high", automated: true},
		"NERC-CIP-CM-001": {category: "Configuration Management", severity: "high", automated: true},
		"NERC-CIP-IP-001": {category: "Information Protection", severity: "high", automated: true},
		"NERC-CIP-SC-001": {category: "Supply Chain", severity: "high", automated: true},
		"NERC-CIP-AI-001": {category: "AI Governance", severity: "critical", automated: true},
		"NERC-CIP-AI-002": {category: "AI Governance", severity: "high", automated: true},
	}

	for _, ctrl := range controls {
		expected, ok := expectedControls[ctrl.ID]
		if !ok {
			t.Errorf("Unexpected control ID: %s", ctrl.ID)
			continue
		}
		if ctrl.Category != expected.category {
			t.Errorf("Control %s: expected category '%s', got '%s'", ctrl.ID, expected.category, ctrl.Category)
		}
		if ctrl.Automated != expected.automated {
			t.Errorf("Control %s: expected automated=%v, got automated=%v", ctrl.ID, expected.automated, ctrl.Automated)
		}
		if expected.automated && ctrl.CheckFunc == nil {
			t.Errorf("Control %s: automated control missing CheckFunc", ctrl.ID)
		}
		if !expected.automated && ctrl.CheckFunc != nil {
			t.Errorf("Control %s: non-automated control should not have CheckFunc", ctrl.ID)
		}
	}

	if len(controls) != 18 {
		t.Errorf("Expected 18 controls, got %d", len(controls))
	}
}
