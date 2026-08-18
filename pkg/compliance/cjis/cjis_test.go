// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CJIS Compliance Module Tests
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

	t.Run("Has64Controls", func(t *testing.T) {
		m := NewCJISModule()
		controls := m.Controls()
		if len(controls) != 64 {
			t.Errorf("len(Controls()) = %d, want 64", len(controls))
		}
	})

	t.Run("AllControlsHaveIDs", func(t *testing.T) {
		controls := NewCJISModule().Controls()
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

func TestCJIS_AutomatedCount(t *testing.T) {
	m := NewCJISModule()
	controls := m.Controls()
	automated := 0
	for _, c := range controls {
		if c.Automated {
			automated++
		}
	}
	if automated != 24 {
		t.Errorf("automated controls = %d, want 24", automated)
	}
}

func TestCJIS_ManualControlsHaveNoCheckFunc(t *testing.T) {
	m := NewCJISModule()
	controls := m.Controls()
	manualCount := 0
	for _, c := range controls {
		if !c.Automated {
			manualCount++
			if c.CheckFunc != nil {
				t.Errorf("manual control %s has non-nil CheckFunc", c.ID)
			}
		}
	}
	if manualCount != 40 {
		t.Errorf("manual controls = %d, want 40", manualCount)
	}
}

func TestCJIS_AllControlsHaveReferences(t *testing.T) {
	m := NewCJISModule()
	controls := m.Controls()
	for _, c := range controls {
		if len(c.References) == 0 {
			t.Errorf("control %s has no references", c.ID)
		}
	}
}

func TestCJIS_AllControlsHaveCategory(t *testing.T) {
	m := NewCJISModule()
	controls := m.Controls()
	for _, c := range controls {
		if c.Category == "" {
			t.Errorf("control %s has empty category", c.ID)
		}
	}
}

func TestCJIS_CategoryCoverage(t *testing.T) {
	m := NewCJISModule()
	controls := m.Controls()

	expectedCategories := map[string]bool{
		"Information Management":               false,
		"Personnel Security":                   false,
		"Access Control":                       false,
		"Physical Protection":                  false,
		"Cryptography":                         false,
		"Incident Response":                    false,
		"System and Communications Protection": false,
		"System and Information Integrity":     false,
		"Configuration Management":             false,
		"Maintenance":                          false,
		"Identification and Authentication":    false,
		"Cloud Computing":                      false,
		"AI Controls":                          false,
	}

	for _, c := range controls {
		if _, ok := expectedCategories[c.Category]; ok {
			expectedCategories[c.Category] = true
		} else {
			t.Errorf("unexpected category %q on control %s", c.Category, c.ID)
		}
	}

	for cat, found := range expectedCategories {
		if !found {
			t.Errorf("expected category %q not present in any control", cat)
		}
	}
}

func TestCJIS_CheckAllAutomated_Compliant(t *testing.T) {
	m := NewCJISModule()
	ctx := context.Background()

	compliantConfig := []byte(`information_management_policy data_classification media_protection encryption_at_rest disk_encrypted record_retention data_retention_policy personnel_security background_checks screening security_training security_awareness incident_response_training ir_training access_control rbac account_management user_provisioning audit_log audit_enabled logging_enabled mobile_device_management mdm device_enrollment aes_256 fips tls1.3 tls_13 https key_management key_rotation kms remote_access vpn incident_response_plan ir_plan incident_monitoring siem security_monitoring flaw_remediation patch_management vulnerability_patch antivirus anti_malware malware_detection edr change_control change_management cab_approval configuration_change identification authentication user_identification authenticator_management token_management credential_management advanced_authentication mfa multi_factor totp fido ai_audit_trail model_logging`)

	controls := m.Controls()
	for _, c := range controls {
		if !c.Automated {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			result, err := c.CheckFunc(ctx, compliantConfig)
			if err != nil {
				t.Fatalf("Control %s CheckFunc error: %v", c.ID, err)
			}
			if result.Status != compliance.StatusCompliant {
				t.Errorf("Control %s on compliant config: status=%s, msg=%s",
					c.ID, result.Status, result.Message)
			}
		})
	}
}

func TestCJIS_CheckAllAutomated_NonCompliant(t *testing.T) {
	m := NewCJISModule()
	ctx := context.Background()

	emptyConfig := []byte(`{}`)

	controls := m.Controls()
	for _, c := range controls {
		if !c.Automated {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			result, err := c.CheckFunc(ctx, emptyConfig)
			if err != nil {
				t.Fatalf("Control %s CheckFunc error: %v", c.ID, err)
			}
			// CJIS-AI-01 returns compliant when no CJI is found
			// (no CJI in AI model inputs = compliant by design).
			if c.ID == "CJIS-AI-01" {
				if result.Status != compliance.StatusCompliant {
					t.Errorf("Control CJIS-AI-01 on empty config: should be compliant (no CJI found), got %s", result.Status)
				}
				return
			}
			if result.Status == compliance.StatusCompliant {
				t.Errorf("Control %s on empty config: should NOT be compliant, got %s",
					c.ID, result.Status)
			}
		})
	}
}

func TestCJIS_CJIDetection(t *testing.T) {
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

func TestCJIS_Dependencies(t *testing.T) {
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
