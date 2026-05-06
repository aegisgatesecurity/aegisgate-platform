// SPDX-License-Identifier: Apache-2.0
//go:build !race

// Coverage tests for framework_mapping.go
package compliance

import (
	"testing"
)

func TestConsolidatedFinding_New(t *testing.T) {
	f := NewConsolidatedFinding("Test Title", "Test Description", "medium", "Fix it")
	if f == nil {
		t.Fatal("NewConsolidatedFinding returned nil")
	}
	if f.Title != "Test Title" {
		t.Errorf("Title=%q, want Test Title", f.Title)
	}
	if f.ID == "" {
		t.Error("ID should be auto-generated")
	}
}

func TestConsolidatedFinding_AddFramework(t *testing.T) {
	f := NewConsolidatedFinding("T", "D", "low", "R")
	f.AddFramework("OWASP")
	f.AddFramework("OWASP")
	if len(f.Frameworks) != 1 {
		t.Errorf("Duplicate should not double-add, got %d", len(f.Frameworks))
	}
	f.AddFramework("NIST")
	if len(f.Frameworks) != 2 {
		t.Errorf("Frameworks count=%d, want 2", len(f.Frameworks))
	}
}

func TestConsolidatedFinding_AddControl(t *testing.T) {
	f := NewConsolidatedFinding("T", "D", "low", "R")
	f.AddControl("CC1.1")
	f.AddControl("CC1.1")
	if len(f.Controls) != 1 {
		t.Errorf("Duplicate should not double-add, got %d", len(f.Controls))
	}
}

func TestConsolidatedFinding_AddTechnique(t *testing.T) {
	f := NewConsolidatedFinding("T", "D", "low", "R")
	f.AddTechnique("T1234")
	f.AddTechnique("T1234")
	if len(f.Techniques) != 1 {
		t.Errorf("Duplicate should not double-add, got %d", len(f.Techniques))
	}
}

func TestConsolidatedFinding_AddEvidence(t *testing.T) {
	f := NewConsolidatedFinding("T", "D", "low", "R")
	f.AddEvidence("evidence1")
	f.AddEvidence("evidence1")
	// AddEvidence appends without deduplication (source behavior)
	if len(f.Evidence) == 0 {
		t.Error("Evidence should have at least 1 entry")
	}
}

func TestOWASPMapping_GenerateUnifiedReport(t *testing.T) {
	m := NewOWASPMapping()
	report := m.GenerateUnifiedReport(nil)
	if report == nil {
		t.Error("GenerateUnifiedReport should return non-nil")
	}
}

func TestOWASPMapping_GetControlsForTechnique(t *testing.T) {
	m := NewOWASPMapping()
	controls := m.GetControlsForTechnique("T1535")
	if controls == nil {
		t.Error("GetControlsForTechnique should not return nil")
	}
}
