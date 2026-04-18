// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

package compliance

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

func TestNewBaseComplianceModule(t *testing.T) {
	// Create base module with required dependencies
	module := NewBaseComplianceModule("HIPAA", "2.0.0", core.TierProfessional)

	if module == nil {
		t.Fatal("NewBaseComplianceModule() returned nil")
	}

	// Verify metadata
	if module.Framework() != "HIPAA" {
		t.Errorf("Framework() = %s, want HIPAA", module.Framework())
	}

	if module.Version() != "2.0.0" {
		t.Errorf("Version() = %s, want 2.0.0", module.Version())
	}

	// Verify controls initialized - check for empty or nil
	controls := module.Controls()
	if controls == nil {
		// Controls() may return nil for empty, both acceptable
		t.Log("Controls() returned nil (acceptable)")
	}
}

func TestBaseComplianceModule_Framework(t *testing.T) {
	module := NewBaseComplianceModule("SOC2", "3.0.0", core.TierProfessional)

	if module.Framework() != "SOC2" {
		t.Errorf("Framework() = %s, want SOC2", module.Framework())
	}

	// Test different framework
	module2 := NewBaseComplianceModule("PCI-DSS", "1.5.0", core.TierProfessional)

	if module2.Framework() != "PCI-DSS" {
		t.Errorf("Framework() = %s, want PCI-DSS", module2.Framework())
	}
}

func TestBaseComplianceModule_Version(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{"standard version", "1.0.0"},
		{"semantic version", "2.1.3"},
		{"beta version", "0.1.0-beta"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := NewBaseComplianceModule("TEST", tt.version, core.TierCommunity)

			if module.Version() != tt.version {
				t.Errorf("Version() = %s, want %s", module.Version(), tt.version)
			}
		})
	}
}

func TestBaseComplianceModule_Controls(t *testing.T) {
	module := NewBaseComplianceModule("TEST", "1.0.0", core.TierCommunity)

	// Initially should be empty
	controls := module.Controls()
	if len(controls) != 0 {
		t.Errorf("Controls() should be empty initially, got %d", len(controls))
	}

	// Register a control
	module.RegisterControl(ControlDefinition{
		ID:          "control-1",
		Name:        "Test Control",
		Description: "A test control",
		Automated:   true,
	})

	controls = module.Controls()
	if len(controls) != 1 {
		t.Errorf("Controls() should have 1 control, got %d", len(controls))
	}

	if controls[0].ID != "control-1" {
		t.Errorf("Controls()[0].ID = %s, want control-1", controls[0].ID)
	}
}

func TestBaseComplianceModule_RegisterControl(t *testing.T) {
	module := NewBaseComplianceModule("TEST", "1.0.0", core.TierCommunity)

	// Register multiple controls
	for i := 1; i <= 3; i++ {
		module.RegisterControl(ControlDefinition{
			ID:   string(rune('a' + i)),
			Name: "Control",
		})
	}

	controls := module.Controls()
	if len(controls) != 3 {
		t.Errorf("Controls() should have 3 controls, got %d", len(controls))
	}
}

func TestBaseComplianceModule_CheckControl(t *testing.T) {
	module := NewBaseComplianceModule("TEST", "1.0.0", core.TierCommunity)

	// Register control with CheckFunc
	module.RegisterControl(ControlDefinition{
		ID:        "control-check",
		Name:      "Test Control",
		Automated: true,
		CheckFunc: func(ctx context.Context, input []byte) (*ControlCheckResult, error) {
			return &ControlCheckResult{
				Framework:   "TEST",
				ControlID:   "control-check",
				ControlName: "Test Control",
				Status:      StatusCompliant,
				Message:     "Control passed",
			}, nil
		},
	})

	// Register control without CheckFunc
	module.RegisterControl(ControlDefinition{
		ID:        "control-no-check",
		Name:      "Manual Control",
		Automated: false,
	})

	ctx := context.Background()

	// Check control with CheckFunc
	t.Run("with check function", func(t *testing.T) {
		result, err := module.CheckControl(ctx, "control-check", []byte("test"))
		if err != nil {
			t.Errorf("CheckControl() error = %v", err)
		}
		if result.Status != StatusCompliant {
			t.Errorf("CheckControl() status = %s, want %s", result.Status, StatusCompliant)
		}
	})

	// Check control without CheckFunc
	t.Run("without check function", func(t *testing.T) {
		result, err := module.CheckControl(ctx, "control-no-check", []byte("test"))
		if err != nil {
			t.Errorf("CheckControl() error = %v", err)
		}
		if result.Status != StatusNotApplicable {
			t.Errorf("CheckControl() status = %s, want %s", result.Status, StatusNotApplicable)
		}
	})

	// Check non-existent control
	t.Run("non-existent control", func(t *testing.T) {
		_, err := module.CheckControl(ctx, "non-existent", []byte("test"))
		if err == nil {
			t.Error("CheckControl() should fail for non-existent control")
		}
	})
}

func TestBaseComplianceModule_CheckAll(t *testing.T) {
	module := NewBaseComplianceModule("TEST", "1.0.0", core.TierCommunity)

	// Register controls with CheckFunc
	compliantCheck := func(ctx context.Context, input []byte) (*ControlCheckResult, error) {
		return &ControlCheckResult{
			Framework:   "TEST",
			ControlID:   "control-1",
			ControlName: "Compliant Control",
			Status:      StatusCompliant,
		}, nil
	}

	nonCompliantCheck := func(ctx context.Context, input []byte) (*ControlCheckResult, error) {
		return &ControlCheckResult{
			Framework:   "TEST",
			ControlID:   "control-2",
			ControlName: "Non-Compliant Control",
			Status:      StatusNonCompliant,
			Remediation: "Fix this issue",
		}, nil
	}

	module.RegisterControl(ControlDefinition{
		ID:        "control-1",
		Name:      "Compliant Control",
		CheckFunc: compliantCheck,
	})

	module.RegisterControl(ControlDefinition{
		ID:        "control-2",
		Name:      "Non-Compliant Control",
		CheckFunc: nonCompliantCheck,
	})

	ctx := context.Background()
	results, err := module.CheckAll(ctx, []byte("test"))

	if err != nil {
		t.Errorf("CheckAll() error = %v", err)
	}

	if len(results) != 2 {
		t.Errorf("CheckAll() returned %d results, want 2", len(results))
	}
}

func TestBaseComplianceModule_GenerateAssessment(t *testing.T) {
	module := NewBaseComplianceModule("TEST", "1.0.0", core.TierCommunity)

	// Register various controls
	compliantControl := func(ctx context.Context, input []byte) (*ControlCheckResult, error) {
		return &ControlCheckResult{
			Framework:   "TEST",
			ControlID:   "c1",
			ControlName: "Compliant",
			Status:      StatusCompliant,
		}, nil
	}

	nonCompliantControl := func(ctx context.Context, input []byte) (*ControlCheckResult, error) {
		return &ControlCheckResult{
			Framework:   "TEST",
			ControlID:   "c2",
			ControlName: "Non-Compliant",
			Status:      StatusNonCompliant,
			Remediation: "Fix this",
		}, nil
	}

	partialControl := func(ctx context.Context, input []byte) (*ControlCheckResult, error) {
		return &ControlCheckResult{
			Framework:   "TEST",
			ControlID:   "c3",
			ControlName: "Partial",
			Status:      StatusPartial,
			Remediation: "Partially fix",
		}, nil
	}

	module.RegisterControl(ControlDefinition{ID: "c1", Name: "C1", CheckFunc: compliantControl})
	module.RegisterControl(ControlDefinition{ID: "c2", Name: "C2", CheckFunc: nonCompliantControl})
	module.RegisterControl(ControlDefinition{ID: "c3", Name: "C3", CheckFunc: partialControl})

	ctx := context.Background()
	assessment, err := module.GenerateAssessment(ctx, []byte("test"))

	if err != nil {
		t.Errorf("GenerateAssessment() error = %v", err)
	}

	// Verify assessment fields
	if assessment.Framework != "TEST" {
		t.Errorf("Assessment.Framework = %s, want TEST", assessment.Framework)
	}

	if assessment.Version != "1.0.0" {
		t.Errorf("Assessment.Version = %s, want 1.0.0", assessment.Version)
	}

	if len(assessment.Results) != 3 {
		t.Errorf("Assessment.Results length = %d, want 3", len(assessment.Results))
	}

	// Verify summary
	if assessment.Summary.Total != 3 {
		t.Errorf("Summary.Total = %d, want 3", assessment.Summary.Total)
	}

	// Count statuses
	var compliant, nonCompliant, partial int
	for _, r := range assessment.Results {
		switch r.Status {
		case StatusCompliant:
			compliant++
		case StatusNonCompliant:
			nonCompliant++
		case StatusPartial:
			partial++
		}
	}

	if compliant != 1 {
		t.Errorf("Compliant count = %d, want 1", compliant)
	}

	if nonCompliant != 1 {
		t.Errorf("NonCompliant count = %d, want 1", nonCompliant)
	}

	if partial != 1 {
		t.Errorf("Partial count = %d, want 1", partial)
	}

	// Verify remediations (should include both non-compliant and partial)
	if len(assessment.Remediations) < 1 {
		t.Error("Assessment should include remediations for non-compliant controls")
	}
}

func TestBaseComplianceModule_AssessmentScore(t *testing.T) {
	module := NewBaseComplianceModule("TEST", "1.0.0", core.TierCommunity)

	// Test score calculation for all compliant
	for i := 0; i < 4; i++ {
		module.RegisterControl(ControlDefinition{
			ID:        string(rune('a' + i)),
			Name:      "Control",
			CheckFunc: func(ctx context.Context, input []byte) (*ControlCheckResult, error) {
				return &ControlCheckResult{Status: StatusCompliant}, nil
			},
		})
	}

	ctx := context.Background()
	assessment, _ := module.GenerateAssessment(ctx, []byte("test"))

	// Score should be 100% for all compliant
	if assessment.Summary.Score != 100.0 {
		t.Errorf("Score = %f, want 100 for all compliant", assessment.Summary.Score)
	}
}

func TestBaseComplianceModule_OptionalDependencies(t *testing.T) {
	module := NewBaseComplianceModule("TEST", "1.0.0", core.TierCommunity)

	deps := module.OptionalDependencies()

	if deps == nil {
		t.Fatal("OptionalDependencies() returned nil")
	}

	found := false
	for _, dep := range deps {
		if dep == "scanner" || dep == "metrics" {
			found = true
			break
		}
	}

	if !found {
		t.Error("OptionalDependencies() should contain 'scanner' or 'metrics'")
	}
}

func TestBaseComplianceModule_Provides(t *testing.T) {
	module := NewBaseComplianceModule("HIPAA", "2.0.0", core.TierProfessional)

	provides := module.Provides()

	if provides == nil {
		t.Fatal("Provides() returned nil")
	}

	if len(provides) < 1 {
		t.Error("Provides() should return at least one capability")
	}

	// Should include 'compliance' and framework-specific capability
	hasCompliance := false
	hasFramework := false

	for _, cap := range provides {
		if cap == "compliance" {
			hasCompliance = true
		}
		if cap == "HIPAA_compliance" {
			hasFramework = true
		}
	}

	if !hasCompliance {
		t.Error("Provides() should include 'compliance'")
	}

	if !hasFramework {
		t.Error("Provides() should include framework-specific capability")
	}
}

func TestBaseComplianceModule_EmptyCheckAll(t *testing.T) {
	module := NewBaseComplianceModule("TEST", "1.0.0", core.TierCommunity)

	// No controls registered
	ctx := context.Background()
	results, err := module.CheckAll(ctx, []byte("test"))

	if err != nil {
		t.Errorf("CheckAll() error = %v", err)
	}

	if len(results) != 0 {
		t.Errorf("CheckAll() with no controls should return empty, got %d", len(results))
	}
}

// Signed-off-by: jcolvin <josh@aegisgatesecurity.io>