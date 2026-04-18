package atlas

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
)

func TestAtlasFramework_Name(t *testing.T) {
	framework := NewAtlasFramework()
	if framework.GetName() != "MITRE ATLAS" {
		t.Errorf("Expected name 'MITRE ATLAS', got '%s'", framework.GetName())
	}
}

func TestAtlasFramework_Version(t *testing.T) {
	framework := NewAtlasFramework()
	if framework.GetVersion() == "" {
		t.Error("Version should not be empty")
	}
}

func TestAtlasFramework_Description(t *testing.T) {
	framework := NewAtlasFramework()
	if framework.GetDescription() == "" {
		t.Error("Description should not be empty")
	}
}

func TestAtlasFramework_EnableDisable(t *testing.T) {
	framework := NewAtlasFramework()

	// Test initial state
	if !framework.IsEnabled() {
		t.Error("Framework should be enabled by default")
	}

	// Test disable
	framework.Disable()
	if framework.IsEnabled() {
		t.Error("Framework should be disabled after Disable()")
	}

	// Test enable
	framework.Enable()
	if !framework.IsEnabled() {
		t.Error("Framework should be enabled after Enable()")
	}
}

func TestAtlasFramework_FrameworkID(t *testing.T) {
	framework := NewAtlasFramework()
	if framework.GetFrameworkID() == "" {
		t.Error("FrameworkID should not be empty")
	}
	if framework.GetFrameworkID() != "atlas" {
		t.Errorf("Expected FrameworkID 'atlas', got '%s'", framework.GetFrameworkID())
	}
}

func TestAtlasFramework_PatternCount(t *testing.T) {
	framework := NewAtlasFramework()
	if framework.GetPatternCount() < 0 {
		t.Error("PatternCount should be non-negative")
	}
	if framework.GetPatternCount() != 14 {
		t.Errorf("Expected 14 patterns, got %d", framework.GetPatternCount())
	}
}

func TestAtlasFramework_SeverityLevels(t *testing.T) {
	framework := NewAtlasFramework()
	levels := framework.GetSeverityLevels()
	if len(levels) == 0 {
		t.Error("Should have severity levels defined")
	}
	if len(levels) != 4 {
		t.Errorf("Expected 4 severity levels, got %d", len(levels))
	}
}

func TestAtlasFramework_Configure(t *testing.T) {
	framework := NewAtlasFramework()

	config := map[string]interface{}{
		"contextLines": 5,
		"enabled":      true,
	}

	err := framework.Configure(config)
	if err != nil {
		t.Errorf("Configure should not return error: %v", err)
	}
}

func TestAtlasFramework_Check(t *testing.T) {
	framework := NewAtlasFramework()
	framework.Enable()

	ctx := context.Background()
	input := common.CheckInput{
		Content: "test content with suspicious patterns",
		Headers: map[string]string{"Content-Type": "application/json"},
	}

	result, err := framework.Check(ctx, input)
	if err != nil {
		t.Errorf("Check should not return error: %v", err)
	}

	if result == nil {
		t.Error("Check result should not be nil")
		return
	}

	// Verify result structure
	if result.Framework != framework.GetName() {
		t.Errorf("Expected framework '%s', got '%s'", framework.GetName(), result.Framework)
	}
}

func TestAtlasFramework_Check_EmptyContent(t *testing.T) {
	framework := NewAtlasFramework()

	ctx := context.Background()
	input := common.CheckInput{
		Content: "",
	}

	result, err := framework.Check(ctx, input)
	if err != nil {
		t.Errorf("Check should not return error: %v", err)
	}

	if result == nil {
		t.Error("Check result should not be nil")
	}
}

func TestAtlasFramework_CheckRequest(t *testing.T) {
	framework := NewAtlasFramework()
	framework.Enable()

	ctx := context.Background()
	req := &common.HTTPRequest{
		Method:  "POST",
		URL:     "/api/test",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"test": "data"}`,
	}

	findings, err := framework.CheckRequest(ctx, req)
	if err != nil {
		t.Errorf("CheckRequest should not return error: %v", err)
	}

	// Findings can be empty for a benign request
	if findings == nil {
		t.Error("Findings should not be nil")
	}
}

func TestAtlasFramework_CheckResponse(t *testing.T) {
	framework := NewAtlasFramework()
	framework.Enable()

	ctx := context.Background()
	resp := &common.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       `{"result": "success"}`,
	}

	findings, err := framework.CheckResponse(ctx, resp)
	if err != nil {
		t.Errorf("CheckResponse should not return error: %v", err)
	}

	// Findings can be empty for a benign response
	if findings == nil {
		t.Error("Findings should not be nil")
	}
}

func TestAtlasFramework_GetConfig(t *testing.T) {
	framework := NewAtlasFramework()
	config := framework.GetConfig()

	if config == nil {
		t.Error("Config should not be nil")
		return
	}

	if config.Name != "MITRE ATLAS" {
		t.Errorf("Expected config name 'MITRE ATLAS', got '%s'", config.Name)
	}
}

func TestAtlasFramework_GetTier(t *testing.T) {
	framework := NewAtlasFramework()
	tier := framework.GetTier()

	if tier.Name != "Community" {
		t.Errorf("Expected tier name 'Community', got '%s'", tier.Name)
	}
}

func TestAtlasFramework_GetPricing(t *testing.T) {
	framework := NewAtlasFramework()
	pricing := framework.GetPricing()

	if pricing.Tier != "Community" {
		t.Errorf("Expected pricing tier 'Community', got '%s'", pricing.Tier)
	}

	if pricing.MonthlyCost != 0 {
		t.Errorf("Expected monthly cost 0, got %.0f", pricing.MonthlyCost)
	}
}

func TestAtlasFramework_SupportsTier(t *testing.T) {
	framework := NewAtlasFramework()

	if !framework.SupportsTier("Community") {
		t.Error("Should support Community tier")
	}

	if !framework.SupportsTier("Enterprise") {
		t.Error("Should support Enterprise tier")
	}

	if !framework.SupportsTier("Premium") {
		t.Error("Should support Premium tier")
	}
}
