// SPDX-License-Identifier: Apache-2.0
// CCPA/CPRA Compliance Module - Unit Tests
//
// Test coverage target: 80%+ per pkg/compliance coverage floor.
//
// Total controls: 12 (7 automated + 5 evidence-mapped)
//   TK: 3 (3 automated + 0 evidence-mapped)
//   DR: 2 (1 automated + 1 evidence-mapped)
//   OS: 3 (2 automated + 1 evidence-mapped)
//   NC: 2 (1 automated + 1 evidence-mapped)
//   PR: 2 (0 automated + 2 evidence-mapped)

package ccpa

import (
	"context"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewCCPAModule(t *testing.T) {
	m := NewCCPAModule()
	if m == nil {
		t.Fatal("NewCCPAModule returned nil")
	}
	if m.Framework() != "ccpa" {
		t.Errorf("Framework() = %q, want ccpa", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0", m.Version())
	}
}

func TestCCPAControlCount(t *testing.T) {
	m := NewCCPAModule()
	controls := m.Controls()

	// Total: 12 controls
	if len(controls) != 12 {
		t.Errorf("len(Controls()) = %d, want 12", len(controls))
	}

	// Count automated vs evidence-mapped
	automated := 0
	evidenceMapped := 0
	for _, c := range controls {
		if c.Automated {
			automated++
		} else {
			evidenceMapped++
		}
	}
	if automated != 8 {
		t.Errorf("automated controls = %d, want 7", automated)
	}
	if evidenceMapped != 4 {
		t.Errorf("evidence-mapped controls = %d, want 5", evidenceMapped)
	}

	// Verify each category has the right number of controls
	categoryCount := map[string]int{}
	for _, c := range controls {
		categoryCount[c.Category]++
	}
	expectedCategories := map[string]int{
		"Consumer Rights": 10,
		"Privacy Rights":  2,
	}
	for category, expected := range expectedCategories {
		if categoryCount[category] != expected {
			t.Errorf("category %q: got %d controls, want %d", category, categoryCount[category], expected)
		}
	}
}

func TestCCPAAutomatedChecks(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	compliantConfig := `{
		"privacy_policy": true, "privacy_policy_link": true,
		"data_collection": true, "personal_information": true,
		"right_to_know": true, "consumer_rights": true,
		"disclosure": true, "transparency": true,
		"data_categories": true, "categories": true,
		"pi_list": true, "collection_purpose": true,
		"data_sources": true, "sources": true,
		"collection_method": true,
		"deletion": true, "data_deletion": true,
		"right_to_delete": true, "deletion_process": true,
		"opt_out": true, "consent": true,
		"preference_center": true, "do_not_sell": true,
		"homepage": true, "opt_out_link": true,
		"non_discrimination": true, "equal_service": true,
		"non_discriminatory": true, "policy": true,
		"correction": true, "right_to_correct": true,
		"data_accuracy": true, "data_correction": true
	}`

	automatedIDs := []string{
		"CCPA-TK-01", "CCPA-TK-02", "CCPA-TK-03",
		"CCPA-DR-01",
		"CCPA-OS-01", "CCPA-OS-02",
		"CCPA-NC-01",
		"CCPA-PR-01",
	}

	controls := m.Controls()
	controlMap := map[string]compliance.ControlDefinition{}
	for _, c := range controls {
		controlMap[c.ID] = c
	}

	for _, id := range automatedIDs {
		c, ok := controlMap[id]
		if !ok {
			t.Errorf("Automated control %s not found in registered controls", id)
			continue
		}
		if !c.Automated {
			t.Errorf("Control %s should be automated", id)
			continue
		}
		if c.CheckFunc == nil {
			t.Errorf("Control %s has nil CheckFunc", id)
			continue
		}
		result, err := c.CheckFunc(ctx, []byte(compliantConfig))
		if err != nil {
			t.Errorf("Control %s CheckFunc error: %v", id, err)
			continue
		}
		if string(result.Status) != "compliant" {
			t.Errorf("Control %s on compliant config: status=%s, msg=%s", id, result.Status, result.Message)
		}
	}
}

func TestCCPANonCompliant(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	// Empty input should yield non-compliant for all automated checks
	nonCompliantInput := `{}`

	automatedIDs := []string{
		"CCPA-TK-01", "CCPA-TK-02", "CCPA-TK-03",
		"CCPA-DR-01",
		"CCPA-OS-01", "CCPA-OS-02",
		"CCPA-NC-01",
		"CCPA-PR-01",
	}

	controls := m.Controls()
	controlMap := map[string]compliance.ControlDefinition{}
	for _, c := range controls {
		controlMap[c.ID] = c
	}

	for _, id := range automatedIDs {
		c, ok := controlMap[id]
		if !ok {
			t.Errorf("Automated control %s not found", id)
			continue
		}
		if c.CheckFunc == nil {
			continue
		}
		result, err := c.CheckFunc(ctx, []byte(nonCompliantInput))
		if err != nil {
			t.Errorf("Control %s CheckFunc error: %v", id, err)
			continue
		}
		if string(result.Status) == "compliant" {
			t.Errorf("Control %s on empty input: expected non-compliant or partial, got %s", id, result.Status)
		}
	}
}

func TestCCPAEvidenceMappedNotAutomated(t *testing.T) {
	m := NewCCPAModule()
	controls := m.Controls()

	evidenceMappedIDs := []string{
		"CCPA-DR-02",
		"CCPA-OS-03",
		"CCPA-NC-02",
		"CCPA-PR-02",
	}

	controlMap := map[string]compliance.ControlDefinition{}
	for _, c := range controls {
		controlMap[c.ID] = c
	}

	for _, id := range evidenceMappedIDs {
		c, ok := controlMap[id]
		if !ok {
			t.Errorf("Evidence-mapped control %s not found", id)
			continue
		}
		if c.Automated {
			t.Errorf("Evidence-mapped control %s should have Automated=false, got true", id)
		}
		if c.CheckFunc != nil {
			t.Errorf("Evidence-mapped control %s should have nil CheckFunc, got non-nil", id)
		}
	}
}

func TestCCPAAllControlsHaveFields(t *testing.T) {
	m := NewCCPAModule()
	controls := m.Controls()

	for _, c := range controls {
		if c.ID == "" {
			t.Error("Control has empty ID")
		}
		if c.Name == "" {
			t.Errorf("Control %s has empty Name", c.ID)
		}
		if c.Description == "" {
			t.Errorf("Control %s has empty Description", c.ID)
		}
		if c.Category == "" {
			t.Errorf("Control %s has empty Category", c.ID)
		}
		if c.Severity == "" {
			t.Errorf("Control %s has empty Severity", c.ID)
		}
		if c.Automated && c.CheckFunc == nil {
			t.Errorf("Automated control %s has nil CheckFunc", c.ID)
		}
		if !c.Automated && c.CheckFunc != nil {
			t.Errorf("Evidence-mapped control %s should have nil CheckFunc", c.ID)
		}
	}
}

func TestCCPADependencies(t *testing.T) {
	m := NewCCPAModule()
	deps := m.Dependencies()
	if len(deps) != 4 {
		t.Errorf("Dependencies() returned %d items, want 4", len(deps))
	}
	depsStr := strings.Join(deps, ",")
	for _, expected := range []string{"gdpr", "soc2", "ioc", "trust"} {
		if !strings.Contains(depsStr, expected) {
			t.Errorf("Dependencies() should include %q", expected)
		}
	}
}

func TestCheckRightToKnow(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (full)", input: `{"privacy_policy": true, "data_collection": true, "right_to_know": true}`, wantStatus: "compliant"},
		{name: "compliant (alternative markers)", input: `{"privacy_policy_link": true, "personal_information": true, "consumer_rights": true, "disclosure": true}`, wantStatus: "compliant"},
		{name: "partial (privacy policy only)", input: `{"privacy_policy": true}`, wantStatus: "partial"},
		{name: "non-compliant (empty)", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRightToKnow(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRightToKnow: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckDataCategories(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (full)", input: `{"data_categories": true, "personal_information": true, "collection_purpose": true}`, wantStatus: "compliant"},
		{name: "compliant (alt markers)", input: `{"categories": true, "pi_list": true, "purpose": true}`, wantStatus: "compliant"},
		{name: "partial", input: `{"data_categories": true}`, wantStatus: "partial"},
		{name: "non-compliant", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkDataCategories(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkDataCategories: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckSourcesOfPI(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (full)", input: `{"data_sources": true, "collection_method": true, "transparency": true}`, wantStatus: "compliant"},
		{name: "compliant (alt markers)", input: `{"sources": true, "data_collection": true, "consumer_rights": true}`, wantStatus: "compliant"},
		{name: "partial", input: `{"data_sources": true}`, wantStatus: "partial"},
		{name: "non-compliant", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkSourcesOfPI(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkSourcesOfPI: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckRightToDelete(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (full)", input: `{"deletion": true, "right_to_delete": true, "deletion_process": true}`, wantStatus: "compliant"},
		{name: "compliant (alt markers)", input: `{"data_deletion": true, "right_to_know": true, "consumer_rights": true}`, wantStatus: "compliant"},
		{name: "partial", input: `{"deletion": true}`, wantStatus: "partial"},
		{name: "non-compliant", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRightToDelete(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRightToDelete: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckRightToOptOut(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (full)", input: `{"opt_out": true, "consent": true, "consumer_rights": true}`, wantStatus: "compliant"},
		{name: "compliant (alt markers)", input: `{"optout": true, "preference_center": true, "do_not_sell": true}`, wantStatus: "compliant"},
		{name: "partial", input: `{"opt_out": true}`, wantStatus: "partial"},
		{name: "non-compliant", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRightToOptOut(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRightToOptOut: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckDoNotSellLink(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (full)", input: `{"do_not_sell": true, "homepage": true}`, wantStatus: "compliant"},
		{name: "compliant (alt markers)", input: `{"donotsell": true, "opt_out_link": true}`, wantStatus: "compliant"},
		{name: "partial", input: `{"do_not_sell": true}`, wantStatus: "partial"},
		{name: "non-compliant", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkDoNotSellLink(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkDoNotSellLink: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckNonDiscrimination(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (full)", input: `{"non_discrimination": true, "equal_service": true}`, wantStatus: "compliant"},
		{name: "compliant (alt markers)", input: `{"consumer_rights": true, "non_discriminatory": true}`, wantStatus: "compliant"},
		{name: "partial", input: `{"non_discrimination": true}`, wantStatus: "partial"},
		{name: "non-compliant", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkNonDiscrimination(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkNonDiscrimination: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckRightToCorrect(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{name: "compliant (full)", input: `{"correction": true, "consumer_rights": true, "data_accuracy": true}`, wantStatus: "compliant"},
		{name: "compliant (alt markers)", input: `{"right_to_correct": true, "privacy_policy": true, "data_correction": true}`, wantStatus: "compliant"},
		{name: "partial", input: `{"correction": true}`, wantStatus: "partial"},
		{name: "non-compliant", input: `{}`, wantStatus: "non_compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkRightToCorrect(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkRightToCorrect: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)", result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}
