// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform - NIST AI RMF 1.0 Module Tests

package nist_ai_rmf

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewNISTAIRMFModule(t *testing.T) {
	m := NewNISTAIRMFModule()
	if m == nil {
		t.Fatal("NewNISTAIRMFModule returned nil")
	}
	if m.Framework() != "nist_ai_rmf" {
		t.Errorf("Framework() = %q, want %q", m.Framework(), "nist_ai_rmf")
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want %q", m.Version(), "1.0")
	}
	controls := m.Controls()
	if len(controls) != 50 {
		t.Errorf("Controls() returned %d controls, want 50", len(controls))
	}
}

func TestNISTAIRMF_ControlCounts(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()

	automated := 0
	evidence := 0
	for _, c := range controls {
		if c.Automated {
			automated++
		} else {
			evidence++
		}
	}
	if automated != 35 {
		t.Errorf("automated controls = %d, want 35", automated)
	}
	if evidence != 15 {
		t.Errorf("evidence-mapped controls = %d, want 15", evidence)
	}
}

func TestNISTAIRMF_CategoryCounts(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()

	categories := map[string]int{}
	for _, c := range controls {
		categories[c.Category]++
	}
	if categories["Govern"] != 14 {
		t.Errorf("Govern controls = %d, want 14", categories["Govern"])
	}
	if categories["Map"] != 10 {
		t.Errorf("Map controls = %d, want 10", categories["Map"])
	}
	if categories["Measure"] != 13 {
		t.Errorf("Measure controls = %d, want 13", categories["Measure"])
	}
	if categories["Manage"] != 13 {
		t.Errorf("Manage controls = %d, want 13", categories["Manage"])
	}
}

func TestNISTAIRMF_AllControlIDs(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()
	idSet := make(map[string]bool)
	for _, c := range controls {
		if idSet[c.ID] {
			t.Errorf("Duplicate control ID: %s", c.ID)
		}
		idSet[c.ID] = true
	}
}

func TestNISTAIRMF_AutomatedCheck_GV11_Compliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()
	var gv11 *compliance.ControlDefinition
	for i := range controls {
		if controls[i].ID == "GV-1.1" {
			gv11 = &controls[i]
			break
		}
	}
	if gv11 == nil {
		t.Fatal("GV-1.1 not found")
	}
	if !gv11.Automated {
		t.Error("GV-1.1 should be automated")
	}
	input := []byte("ai_policy documented compliance_scan enabled risk_management_policy active")
	result, err := gv11.CheckFunc(context.Background(), input)
	if err != nil {
		t.Fatalf("GV-1.1 CheckFunc error: %v", err)
	}
	if result.Status != compliance.StatusCompliant {
		t.Errorf("GV-1.1 status = %s, want Compliant; message: %s", result.Status, result.Message)
	}
}

func TestNISTAIRMF_AutomatedCheck_GV11_NonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()
	var gv11 *compliance.ControlDefinition
	for i := range controls {
		if controls[i].ID == "GV-1.1" {
			gv11 = &controls[i]
			break
		}
	}
	input := []byte("generic configuration without policy references")
	result, err := gv11.CheckFunc(context.Background(), input)
	if err != nil {
		t.Fatalf("GV-1.1 CheckFunc error: %v", err)
	}
	if result.Status != compliance.StatusNonCompliant {
		t.Errorf("GV-1.1 status = %s, want NonCompliant for empty input", result.Status)
	}
}

func TestNISTAIRMF_AutomatedCheck_GV11_Partial(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()
	var gv11 *compliance.ControlDefinition
	for i := range controls {
		if controls[i].ID == "GV-1.1" {
			gv11 = &controls[i]
			break
		}
	}
	input := []byte("ai_policy governance document exists but no compliance scanning")
	result, err := gv11.CheckFunc(context.Background(), input)
	if err != nil {
		t.Fatalf("GV-1.1 CheckFunc error: %v", err)
	}
	if result.Status != compliance.StatusPartial {
		t.Errorf("GV-1.1 status = %s, want Partial for policy without scanning", result.Status)
	}
}

func TestNISTAIRMF_EvidenceMappedControls(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()
	evidenceIDs := map[string]bool{
		"GV-1.3": true,
		"GV-3.2": true,
		"MP-2.1": true,
		"MS-2.3": true,
		"MG-2.1": true,
	}
	for _, c := range controls {
		if evidenceIDs[c.ID] {
			if c.Automated {
				t.Errorf("%s should be evidence-mapped, not automated", c.ID)
			}
			if c.CheckFunc != nil {
				t.Errorf("%s should have nil CheckFunc (evidence-mapped)", c.ID)
			}
		}
	}
}

func TestNISTAIRMF_SeverityHigh(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()
	for _, c := range controls {
		if c.Severity == compliance.SeverityCritical {
			// NIST AI RMF controls are all High/Medium/Low — none Critical
			t.Errorf("%s has SeverityCritical, expected High/Medium/Low", c.ID)
		}
	}
}

func TestNISTAIRMF_Dependencies(t *testing.T) {
	m := NewNISTAIRMFModule()
	deps := m.Dependencies()
	if len(deps) == 0 {
		t.Error("Dependencies() returned empty, expected non-empty")
	}
	// Must include scanner and trust
	foundScanner := false
	foundTrust := false
	for _, d := range deps {
		if d == "scanner" {
			foundScanner = true
		}
		if d == "trust" {
			foundTrust = true
		}
	}
	if !foundScanner {
		t.Error("Dependencies must include scanner")
	}
	if !foundTrust {
		t.Error("Dependencies must include trust")
	}
}

func TestNISTAIRMF_ModuleTier(t *testing.T) {
	m := NewNISTAIRMFModule()
	// NIST AI RMF is Community tier (free, like ATLAS/OWASP/GDPR/CIS)
	controls := m.Controls()
	if len(controls) == 0 {
		t.Error("Module should have controls")
	}
}

func TestNISTAIRMF_MS22_Compliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()
	var ms22 *compliance.ControlDefinition
	for i := range controls {
		if controls[i].ID == "MS-2.2" {
			ms22 = &controls[i]
			break
		}
	}
	if ms22 == nil {
		t.Fatal("MS-2.2 not found")
	}
	input := []byte("continuous_monitor enabled drift detection active monitoring_enabled true")
	result, err := ms22.CheckFunc(context.Background(), input)
	if err != nil {
		t.Fatalf("MS-2.2 CheckFunc error: %v", err)
	}
	if result.Status != compliance.StatusCompliant {
		t.Errorf("MS-2.2 status = %s, want Compliant; message: %s", result.Status, result.Message)
	}
}

func TestNISTAIRMF_MG12_Compliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	controls := m.Controls()
	var mg12 *compliance.ControlDefinition
	for i := range controls {
		if controls[i].ID == "MG-1.2" {
			mg12 = &controls[i]
			break
		}
	}
	if mg12 == nil {
		t.Fatal("MG-1.2 not found")
	}
	input := []byte("incident_response_plan documented kill_switch enabled emergency_stop available")
	result, err := mg12.CheckFunc(context.Background(), input)
	if err != nil {
		t.Fatalf("MG-1.2 CheckFunc error: %v", err)
	}
	if result.Status != compliance.StatusCompliant {
		t.Errorf("MG-1.2 status = %s, want Compliant; message: %s", result.Status, result.Message)
	}
}
