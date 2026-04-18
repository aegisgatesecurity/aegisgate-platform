package nist

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
)

func TestNISTFramework_NewFramework(t *testing.T) {
	f := NewNISTFramework()

	if f == nil {
		t.Fatal("NewNISTFramework returned nil")
	}

	if f.GetName() != FrameworkName {
		t.Errorf("Expected name %s, got %s", FrameworkName, f.GetName())
	}

	if f.GetVersion() != FrameworkVersion {
		t.Errorf("Expected version %s, got %s", FrameworkVersion, f.GetVersion())
	}
}

func TestNISTFramework_GetDescription(t *testing.T) {
	f := NewNISTFramework()
	desc := f.GetDescription()

	if desc == "" {
		t.Error("GetDescription returned empty string")
	}

	expected := "NIST"
	if desc[:len(expected)] != expected {
		t.Errorf("Expected description to start with %s, got %s", expected, desc)
	}
}

func TestNISTFramework_IsEnabled(t *testing.T) {
	f := NewNISTFramework()

	if !f.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestNISTFramework_EnableDisable(t *testing.T) {
	f := NewNISTFramework()

	f.Disable()
	if f.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}

	f.Enable()
	if !f.IsEnabled() {
		t.Error("Enable should make framework enabled")
	}
}

func TestNISTFramework_Configure(t *testing.T) {
	f := NewNISTFramework()

	config := map[string]interface{}{
		"strictMode":      true,
		"assessmentLevel": "comprehensive",
	}

	err := f.Configure(config)
	if err != nil {
		t.Errorf("Configure failed: %v", err)
	}
}

func TestNISTFramework_GetFrameworkID(t *testing.T) {
	f := NewNISTFramework()
	id := f.GetFrameworkID()

	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestNISTFramework_GetPatternCount(t *testing.T) {
	f := NewNISTFramework()
	count := f.GetPatternCount()

	if count <= 0 {
		t.Errorf("Expected positive pattern count, got %d", count)
	}
}

func TestNISTFramework_GetSeverityLevels(t *testing.T) {
	f := NewNISTFramework()
	levels := f.GetSeverityLevels()

	if len(levels) == 0 {
		t.Error("GetSeverityLevels returned empty slice")
	}
}

func TestNISTFramework_Check(t *testing.T) {
	f := NewNISTFramework()
	ctx := context.Background()

	input := common.CheckInput{
		Content:  "AI risk management assessment content",
		Headers:  map[string]string{"Content-Type": "text/plain"},
		Metadata: map[string]string{"source": "test"},
	}

	result, err := f.Check(ctx, input)
	if err != nil {
		t.Errorf("Check failed: %v", err)
	}

	if result == nil {
		t.Fatal("Check returned nil result")
	}

	if result.Framework != FrameworkName {
		t.Errorf("Expected framework %s, got %s", FrameworkName, result.Framework)
	}
}

func TestNISTFramework_CheckRequest(t *testing.T) {
	f := NewNISTFramework()
	ctx := context.Background()

	req := &common.HTTPRequest{
		Method:  "POST",
		URL:     "https://api.example.com/ai-risk",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"model": "gpt-4", "input": "risk assessment"}`,
	}

	findings, err := f.CheckRequest(ctx, req)
	if err != nil {
		t.Errorf("CheckRequest failed: %v", err)
	}

	// Findings may be empty
	_ = len(findings)
}

func TestNISTFramework_CheckResponse(t *testing.T) {
	f := NewNISTFramework()
	ctx := context.Background()

	resp := &common.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       `{"risk_level": "low", "governance_score": 85}`,
	}

	findings, err := f.CheckResponse(ctx, resp)
	if err != nil {
		t.Errorf("CheckResponse failed: %v", err)
	}

	// Findings may be empty
	_ = len(findings)
}

func TestNISTFunctions(t *testing.T) {
	f := NewNISTFramework()

	functions := f.functions
	if len(functions) == 0 {
		t.Error("No functions loaded")
	}

	// Verify expected functions exist
	expectedFuncs := []string{"GOVERN", "MAP", "MEASURE", "MANAGE"}
	foundCount := 0

	for _, fn := range functions {
		for _, expected := range expectedFuncs {
			if fn.ID == expected {
				foundCount++
				if fn.Name == "" {
					t.Errorf("Function %s has empty name", expected)
				}
				if fn.Severity == "" {
					t.Errorf("Function %s has empty severity", expected)
				}
			}
		}
	}

	if foundCount < 4 {
		t.Errorf("Expected 4 functions, found %d", foundCount)
	}
}

func TestNISTFramework_Check_EmptyContent(t *testing.T) {
	f := NewNISTFramework()
	ctx := context.Background()

	input := common.CheckInput{
		Content:  "",
		Headers:  map[string]string{},
		Metadata: map[string]string{},
	}

	result, err := f.Check(ctx, input)
	if err != nil {
		t.Errorf("Check failed with empty content: %v", err)
	}

	if result != nil {
		t.Logf("Empty content result passed: %v", result.Passed)
	}
}
