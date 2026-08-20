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
		if m.Version() != "6" {
			t.Errorf("Version() = %q, want %q", m.Version(), "6")
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
	if len(controls) != 55 {
		t.Errorf("len(Controls()) = %d, want 55 (5 CS + 4 SM + 5 PT + 5 EP + 5 PS + 6 SS + 4 IR + 4 RP + 5 CM + 4 IP + 4 SC + 4 AI)", len(controls))
	}

	expectedIDs := map[string]bool{
		// Cyber System Categorization (5)
		"NERC-CIP-CS-01": false, "NERC-CIP-CS-02": false, "NERC-CIP-CS-03": false,
		"NERC-CIP-CS-04": false, "NERC-CIP-CS-05": false,
		// Security Management (4)
		"NERC-CIP-SM-01": false, "NERC-CIP-SM-02": false,
		"NERC-CIP-SM-03": false, "NERC-CIP-SM-04": false,
		// Personnel & Training (5)
		"NERC-CIP-PT-01": false, "NERC-CIP-PT-02": false, "NERC-CIP-PT-03": false,
		"NERC-CIP-PT-04": false, "NERC-CIP-PT-05": false,
		// Electronic Security (5)
		"NERC-CIP-EP-01": false, "NERC-CIP-EP-02": false, "NERC-CIP-EP-03": false,
		"NERC-CIP-EP-04": false, "NERC-CIP-EP-05": false,
		// Physical Security (5)
		"NERC-CIP-PS-01": false, "NERC-CIP-PS-02": false, "NERC-CIP-PS-03": false,
		"NERC-CIP-PS-04": false, "NERC-CIP-PS-05": false,
		// System Security (6)
		"NERC-CIP-SS-01": false, "NERC-CIP-SS-02": false, "NERC-CIP-SS-03": false,
		"NERC-CIP-SS-04": false, "NERC-CIP-SS-05": false, "NERC-CIP-SS-06": false,
		// Incident Response (4)
		"NERC-CIP-IR-01": false, "NERC-CIP-IR-02": false,
		"NERC-CIP-IR-03": false, "NERC-CIP-IR-04": false,
		// Recovery Planning (4)
		"NERC-CIP-RP-01": false, "NERC-CIP-RP-02": false,
		"NERC-CIP-RP-03": false, "NERC-CIP-RP-04": false,
		// Configuration Management (5)
		"NERC-CIP-CM-01": false, "NERC-CIP-CM-02": false, "NERC-CIP-CM-03": false,
		"NERC-CIP-CM-04": false, "NERC-CIP-CM-05": false,
		// Information Protection (4)
		"NERC-CIP-IP-01": false, "NERC-CIP-IP-02": false,
		"NERC-CIP-IP-03": false, "NERC-CIP-IP-04": false,
		// Supply Chain (4)
		"NERC-CIP-SC-01": false, "NERC-CIP-SC-02": false,
		"NERC-CIP-SC-03": false, "NERC-CIP-SC-04": false,
		// AI Governance (4)
		"NERC-CIP-AI-01": false, "NERC-CIP-AI-02": false,
		"NERC-CIP-AI-03": false, "NERC-CIP-AI-04": false,
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
		if result.ControlID != "NERC-CIP-CS-01" {
			t.Errorf("Expected ControlID NERC-CIP-CS-01, got %s", result.ControlID)
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

func TestBESCyberAssetInventoryCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("cyber_asset_inventory maintained for all BES systems")
		result, err := m.checkBESCyberAssetInventory(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_inventory")
		result, err := m.checkBESCyberAssetInventory(context.Background(), input)
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

func TestCyberSecurityPolicyApprovalCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("policy_approval obtained from senior management")
		result, err := m.checkCyberSecurityPolicyApproval(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_approval")
		result, err := m.checkCyberSecurityPolicyApproval(context.Background(), input)
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

func TestAccessManagementProgramCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("access_management_program defines roles and procedures")
		result, err := m.checkAccessManagementProgram(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_access_mgmt")
		result, err := m.checkAccessManagementProgram(context.Background(), input)
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

func TestNetworkSecurityArchitectureCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantAllThree", func(t *testing.T) {
		input := []byte("firewall_rules network_segmentation traffic_filtering all configured")
		result, err := m.checkNetworkSecurityArchitecture(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("PartialWithTwo", func(t *testing.T) {
		input := []byte("firewall_rules and network_segmentation configured")
		result, err := m.checkNetworkSecurityArchitecture(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusPartial {
			t.Errorf("Expected %v, got %v", compliance.StatusPartial, result.Status)
		}
	})

	t.Run("NonCompliantNone", func(t *testing.T) {
		input := []byte("basic_config_no_network_sec")
		result, err := m.checkNetworkSecurityArchitecture(context.Background(), input)
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

func TestPhysicalAccessControlSystemsCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("access_control_system with badge_access configured")
		result, err := m.checkPhysicalAccessControlSystems(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_pacs")
		result, err := m.checkPhysicalAccessControlSystems(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestVisitorAccessManagementCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("visitor_access management with escort and logging")
		result, err := m.checkVisitorAccessManagement(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_visitor")
		result, err := m.checkVisitorAccessManagement(context.Background(), input)
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

	var ps02 *compliance.ControlDefinition
	for i := range controls {
		if controls[i].ID == "NERC-CIP-PS-02" {
			ps02 = &controls[i]
			break
		}
	}

	if ps02 == nil {
		t.Fatal("Control NERC-CIP-PS-02 not found")
	}
	if ps02.Automated {
		t.Error("NERC-CIP-PS-02 should be non-automated")
	}
	if ps02.CheckFunc != nil {
		t.Error("NERC-CIP-PS-02 should not have a CheckFunc")
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

func TestMalwarePreventionCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("malware_prevention with antivirus and endpoint protection")
		result, err := m.checkMalwarePrevention(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_malware")
		result, err := m.checkMalwarePrevention(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestPortServiceHardeningCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("port_hardening service_hardening unnecessary_ports disabled")
		result, err := m.checkPortServiceHardening(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_hardening")
		result, err := m.checkPortServiceHardening(context.Background(), input)
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

func TestIncidentClassificationCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("incident_classification with severity_level and escalation_criteria")
		result, err := m.checkIncidentClassification(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_classification")
		result, err := m.checkIncidentClassification(context.Background(), input)
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

func TestRecoveryPlanTestingCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("recovery_testing with recovery_exercise and validation")
		result, err := m.checkRecoveryPlanTesting(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_validation")
		result, err := m.checkRecoveryPlanTesting(context.Background(), input)
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

func TestBaselineConfigurationCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("baseline_configuration established for all systems")
		result, err := m.checkBaselineConfiguration(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_baseline")
		result, err := m.checkBaselineConfiguration(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusNonCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusNonCompliant, result.Status)
		}
	})
}

func TestChangeTestingCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("change_testing in test_environment with change_validation")
		result, err := m.checkChangeTesting(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_test")
		result, err := m.checkChangeTesting(context.Background(), input)
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

func TestDataClassificationCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("data_classification with classification_scheme and data_handling")
		result, err := m.checkDataClassification(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_classify")
		result, err := m.checkDataClassification(context.Background(), input)
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

func TestVendorCyberSecurityRequirementsCheck(t *testing.T) {
	m := NewNERCCIPModule()

	t.Run("CompliantConfig", func(t *testing.T) {
		input := []byte("vendor_security_requirements enforced for all suppliers")
		result, err := m.checkVendorCyberSecurityRequirements(context.Background(), input)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Status != compliance.StatusCompliant {
			t.Errorf("Expected %v, got %v", compliance.StatusCompliant, result.Status)
		}
	})

	t.Run("NonCompliantConfig", func(t *testing.T) {
		input := []byte("basic_config_no_vendor_reqs")
		result, err := m.checkVendorCyberSecurityRequirements(context.Background(), input)
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
			"cyber_asset_inventory maintained",
			"security_management controls implemented",
			"policy_approval from management",
			"personnel_risk assessment completed",
			"cyber_security_training program active",
			"access_management_program defined",
			"electronic_security_perimeter defined",
			"access_monitoring log_monitoring intrusion_detection active",
			"firewall_rules network_segmentation traffic_filtering configured",
			"physical_security perimeter established",
			"access_control_system with badge_access",
			"visitor_access management with escort",
			"system_security management verified",
			"patch_management program active",
			"malware_prevention antivirus deployed",
			"port_hardening service_hardening unnecessary_ports disabled",
			"incident_response plan documented",
			"incident_classification severity_level defined",
			"recovery_plan business_continuity disaster_recovery all in place",
			"recovery_testing recovery_exercise validated",
			"change_management process documented",
			"baseline_configuration established",
			"change_testing test_environment validated",
			"information_protection controls active",
			"data_classification scheme defined",
			"supply_chain_risk management program",
			"vendor_security_requirements enforced",
			"safe_ai_config with no sensitive data",
			"ai_audit model_logging bes_audit_trail all active",
			"intrusion_detection ids ips ids_monitoring network_monitoring perimeter_monitoring",
			"security_event_monitoring event_monitoring siem",
			"log_review_procedures log_review log_analysis",
			"incident_response_testing ir_testing ir_test",
		}, " "))

		results, err := m.CheckAll(context.Background(), input)
		if err != nil {
			t.Fatalf("CheckAll returned error: %v", err)
		}
		if len(results) != 35 {
			t.Errorf("Expected 35 results (55 controls minus 20 non-automated), got %d", len(results))
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
		// Cyber System Categorization (5)
		"NERC-CIP-CS-01": {category: "Cyber System Categorization", severity: "critical", automated: true},
		"NERC-CIP-CS-02": {category: "Cyber System Categorization", severity: "high", automated: true},
		"NERC-CIP-CS-03": {category: "Cyber System Categorization", severity: "high", automated: true},
		"NERC-CIP-CS-04": {category: "Cyber System Categorization", severity: "medium", automated: false},
		"NERC-CIP-CS-05": {category: "Cyber System Categorization", severity: "medium", automated: false},
		// Security Management (4)
		"NERC-CIP-SM-01": {category: "Security Management", severity: "high", automated: true},
		"NERC-CIP-SM-02": {category: "Security Management", severity: "high", automated: true},
		"NERC-CIP-SM-03": {category: "Security Management", severity: "medium", automated: false},
		"NERC-CIP-SM-04": {category: "Security Management", severity: "medium", automated: false},
		// Personnel & Training (5)
		"NERC-CIP-PT-01": {category: "Personnel & Training", severity: "high", automated: true},
		"NERC-CIP-PT-02": {category: "Personnel & Training", severity: "medium", automated: true},
		"NERC-CIP-PT-03": {category: "Personnel & Training", severity: "high", automated: true},
		"NERC-CIP-PT-04": {category: "Personnel & Training", severity: "high", automated: false},
		"NERC-CIP-PT-05": {category: "Personnel & Training", severity: "medium", automated: false},
		// Electronic Security (5)
		"NERC-CIP-EP-01": {category: "Electronic Security", severity: "critical", automated: true},
		"NERC-CIP-EP-02": {category: "Electronic Security", severity: "high", automated: true},
		"NERC-CIP-EP-03": {category: "Electronic Security", severity: "high", automated: true},
		"NERC-CIP-EP-04": {category: "Electronic Security", severity: "high", automated: true},
		"NERC-CIP-EP-05": {category: "Electronic Security", severity: "medium", automated: false},
		// Physical Security (5)
		"NERC-CIP-PS-01": {category: "Physical Security", severity: "high", automated: true},
		"NERC-CIP-PS-02": {category: "Physical Security", severity: "critical", automated: false},
		"NERC-CIP-PS-03": {category: "Physical Security", severity: "high", automated: true},
		"NERC-CIP-PS-04": {category: "Physical Security", severity: "medium", automated: true},
		"NERC-CIP-PS-05": {category: "Physical Security", severity: "high", automated: false},
		// System Security (6)
		"NERC-CIP-SS-01": {category: "System Security", severity: "high", automated: true},
		"NERC-CIP-SS-02": {category: "System Security", severity: "critical", automated: true},
		"NERC-CIP-SS-03": {category: "System Security", severity: "high", automated: true},
		"NERC-CIP-SS-04": {category: "System Security", severity: "high", automated: true},
		"NERC-CIP-SS-05": {category: "System Security", severity: "high", automated: true},
		"NERC-CIP-SS-06": {category: "System Security", severity: "medium", automated: true},
		// Incident Response (4)
		"NERC-CIP-IR-01": {category: "Incident Response", severity: "critical", automated: true},
		"NERC-CIP-IR-02": {category: "Incident Response", severity: "high", automated: true},
		"NERC-CIP-IR-03": {category: "Incident Response", severity: "medium", automated: true},
		"NERC-CIP-IR-04": {category: "Incident Response", severity: "medium", automated: false},
		// Recovery Planning (4)
		"NERC-CIP-RP-01": {category: "Recovery Planning", severity: "high", automated: true},
		"NERC-CIP-RP-02": {category: "Recovery Planning", severity: "high", automated: true},
		"NERC-CIP-RP-03": {category: "Recovery Planning", severity: "medium", automated: false},
		"NERC-CIP-RP-04": {category: "Recovery Planning", severity: "medium", automated: false},
		// Configuration Management (5)
		"NERC-CIP-CM-01": {category: "Configuration Management", severity: "high", automated: true},
		"NERC-CIP-CM-02": {category: "Configuration Management", severity: "high", automated: true},
		"NERC-CIP-CM-03": {category: "Configuration Management", severity: "high", automated: true},
		"NERC-CIP-CM-04": {category: "Configuration Management", severity: "medium", automated: false},
		"NERC-CIP-CM-05": {category: "Configuration Management", severity: "medium", automated: false},
		// Information Protection (4)
		"NERC-CIP-IP-01": {category: "Information Protection", severity: "high", automated: true},
		"NERC-CIP-IP-02": {category: "Information Protection", severity: "high", automated: true},
		"NERC-CIP-IP-03": {category: "Information Protection", severity: "medium", automated: false},
		"NERC-CIP-IP-04": {category: "Information Protection", severity: "medium", automated: false},
		// Supply Chain (4)
		"NERC-CIP-SC-01": {category: "Supply Chain", severity: "high", automated: true},
		"NERC-CIP-SC-02": {category: "Supply Chain", severity: "high", automated: true},
		"NERC-CIP-SC-03": {category: "Supply Chain", severity: "medium", automated: false},
		"NERC-CIP-SC-04": {category: "Supply Chain", severity: "medium", automated: false},
		// AI Governance (4)
		"NERC-CIP-AI-01": {category: "AI Governance", severity: "critical", automated: true},
		"NERC-CIP-AI-02": {category: "AI Governance", severity: "high", automated: true},
		"NERC-CIP-AI-03": {category: "AI Governance", severity: "high", automated: false},
		"NERC-CIP-AI-04": {category: "AI Governance", severity: "high", automated: false},
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

	if len(controls) != 55 {
		t.Errorf("Expected 55 controls, got %d", len(controls))
	}
}
