// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOX Compliance Module Tests
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

	t.Run("Has80Controls", func(t *testing.T) {
		m := NewSOXModule()
		controls := m.Controls()
		if len(controls) != 80 {
			t.Errorf("len(Controls()) = %d, want 80", len(controls))
		}
	})

	t.Run("AllControlsHaveIDs", func(t *testing.T) {
		controls := NewSOXModule().Controls()
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

func TestSOX_AutomatedCount(t *testing.T) {
	m := NewSOXModule()
	controls := m.Controls()
	automated := 0
	for _, c := range controls {
		if c.Automated {
			automated++
		}
	}
	if automated != 27 {
		t.Errorf("automated controls = %d, want 27", automated)
	}
}

func TestSOX_ManualControlsHaveNoCheckFunc(t *testing.T) {
	m := NewSOXModule()
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
	if manualCount != 53 {
		t.Errorf("manual controls = %d, want 53", manualCount)
	}
}

func TestSOX_AllControlsHaveReferences(t *testing.T) {
	m := NewSOXModule()
	controls := m.Controls()
	for _, c := range controls {
		if len(c.References) == 0 {
			t.Errorf("control %s has no references", c.ID)
		}
	}
}

func TestSOX_AllControlsHaveCategory(t *testing.T) {
	m := NewSOXModule()
	controls := m.Controls()
	for _, c := range controls {
		if c.Category == "" {
			t.Errorf("control %s has empty category", c.ID)
		}
	}
}

func TestSOX_CategoryCoverage(t *testing.T) {
	m := NewSOXModule()
	controls := m.Controls()

	expectedCategories := map[string]bool{
		"COSO Control Environment":         false,
		"COSO Risk Assessment":             false,
		"COSO Control Activities":          false,
		"COSO Information & Communication": false,
		"COSO Monitoring Activities":       false,
		"ITGC - Access Management":         false,
		"ITGC - Change Management":         false,
		"ITGC - Computer Operations":       false,
		"ITGC - Program Development":       false,
		"ITGC - Program Changes":           false,
		"SOX Legislative Sections":         false,
		"Data Protection":                  false,
		"Financial Reporting":              false,
		"Whistleblower Protection":         false,
		"AI Controls":                      false,
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

func TestSOX_CheckAllAutomated_Compliant(t *testing.T) {
	m := NewSOXModule()
	ctx := context.Background()

	compliantConfig := []byte(`{
		"internal_control_assessment": true, "icfr": true, "control_testing": true,
		"control_environment": true, "tone_at_top": true, "governance_policy": true,
		"risk_assessment": true, "risk_framework": true, "financial_risk": true,
		"financial_statement": true, "reporting_integrity": true, "financial_accuracy": true,
		"real_time_disclosure": true, "material_event": true, "current_report": true,
		"records_retention": true, "data_retention_policy": true, "retention_schedule": true,
		"data_integrity": true, "reconciliation": true, "data_validation": true,
		"access_control": true, "rbac": true, "mfa": true, "financial_access": true,
		"change_management": true, "change_control": true, "cab_approval": true,
		"it_security": true, "security_controls": true, "vulnerability_management": true,
		"backup_recovery": true, "disaster_recovery": true, "business_continuity": true,
		"anonymous_reporting": true, "whistleblower_hotline": true, "ethics_line": true,
		"ai_audit_trail": true, "model_logging": true, "financial_audit_trail": true,
		"privileged_access": true, "pam": true,
		"authentication": true, "sso": true,
		"segregation_of_duties": true, "sod": true, "dual_control": true,
		"section_404": true, "management_assessment": true,
		"data_classification": true, "classification_scheme": true, "sensitive_data": true,
		"encryption_at_rest": true, "data_encrypted": true, "aes": true,
		"tls1.3": true, "https": true, "encryption_in_transit": true,
		"dlp": true, "data_loss_prevention": true,
		"audit_log": true, "logging_enabled": true, "audit_enabled": true,
		"log_integrity": true, "hash_chain": true, "immutable_log": true,
		"data_retention": true, "retention_policy": true, "data_disposal": true,
		"account_reconciliation": true, "financial_reconciliation": true,
		"ai_output_validation": true, "output_validation": true, "model_validation": true
	}`)

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

func TestSOX_CheckAllAutomated_NonCompliant(t *testing.T) {
	m := NewSOXModule()
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
			// SOX-AI-01 returns compliant when no financial data is found
			// (no financial data in AI model inputs = compliant by design).
			if c.ID == "SOX-AI-01" {
				if result.Status != compliance.StatusCompliant {
					t.Errorf("Control SOX-AI-01 on empty config: should be compliant (no financial data), got %s", result.Status)
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

func TestSOX_FinancialDataDetection(t *testing.T) {
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

func TestSOX_Dependencies(t *testing.T) {
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

func TestSOX_CheckControl(t *testing.T) {
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

func TestSOX_GenerateAssessment(t *testing.T) {
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

func TestSOX_ModuleProvisions(t *testing.T) {
	m := NewSOXModule()

	t.Run("ProvidesFrameworks", func(t *testing.T) {
		frameworks := m.Provides()
		if len(frameworks) == 0 {
			t.Error("expected non-empty frameworks")
		}
	})
}
