package gdpr

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestGDPRFramework_NewFramework(t *testing.T) {
	f := NewGDPRFramework()

	if f == nil {
		t.Fatal("NewGDPRFramework returned nil")
	}

	if f.GetName() != FrameworkName {
		t.Errorf("Expected name %s, got %s", FrameworkName, f.GetName())
	}

	if f.GetVersion() != FrameworkVersion {
		t.Errorf("Expected version %s, got %s", FrameworkVersion, f.GetVersion())
	}
}

func TestGDPRFramework_GetDescription(t *testing.T) {
	f := NewGDPRFramework()
	desc := f.GetDescription()

	if desc == "" {
		t.Error("GetDescription returned empty string")
	}

	if len(desc) < 5 {
		t.Errorf("Description too short: %s", desc)
	}
}

func TestGDPRFramework_IsEnabled(t *testing.T) {
	f := NewGDPRFramework()

	if !f.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestGDPRFramework_EnableDisable(t *testing.T) {
	f := NewGDPRFramework()

	f.Disable()
	if f.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}

	f.Enable()
	if !f.IsEnabled() {
		t.Error("Enable should make framework enabled")
	}
}

func TestGDPRFramework_Configure(t *testing.T) {
	f := NewGDPRFramework()

	config := map[string]interface{}{
		"strictMode":        true,
		"dataRetentionDays": 30,
	}

	err := f.Configure(config)
	if err != nil {
		t.Errorf("Configure failed: %v", err)
	}
}

func TestGDPRFramework_GetFrameworkID(t *testing.T) {
	f := NewGDPRFramework()
	id := f.GetFrameworkID()

	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestGDPRFramework_GetPatternCount(t *testing.T) {
	f := NewGDPRFramework()
	count := f.GetPatternCount()

	if count <= 0 {
		t.Errorf("Expected positive pattern count, got %d", count)
	}
}

func TestGDPRFramework_GetSeverityLevels(t *testing.T) {
	f := NewGDPRFramework()
	levels := f.GetSeverityLevels()

	if len(levels) == 0 {
		t.Error("GetSeverityLevels returned empty slice")
	}
}

func TestGDPRFramework_Check(t *testing.T) {
	f := NewGDPRFramework()
	ctx := context.Background()

	input := common.CheckInput{
		Content:  "Personal data processing test content",
		Headers:  map[string]string{"Content-Type": "text/plain"},
		Metadata: map[string]interface{}{"source": "test"},
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

func TestGDPRFramework_CheckRequest(t *testing.T) {
	f := NewGDPRFramework()
	ctx := context.Background()

	req := &common.HTTPRequest{
		Method:  "POST",
		URL:     "https://api.example.com/data",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(`{"name": "John", "email": "john@example.com"}`),
	}

	findings, err := f.CheckRequest(ctx, req)
	if err != nil {
		t.Errorf("CheckRequest failed: %v", err)
	}

	// Findings may be empty
	_ = len(findings)
}

func TestGDPRFramework_CheckResponse(t *testing.T) {
	f := NewGDPRFramework()
	ctx := context.Background()

	resp := &common.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"data": "personal data"}`),
	}

	findings, err := f.CheckResponse(ctx, resp)
	if err != nil {
		t.Errorf("CheckResponse failed: %v", err)
	}

	// Findings may be empty
	_ = len(findings)
}

func TestGDPRRequirements(t *testing.T) {
	f := NewGDPRFramework()

	requirements := f.requirements
	if len(requirements) == 0 {
		t.Error("No requirements loaded")
	}

	// Just verify requirements exist
	t.Logf("GDPR requirements count: %d", len(requirements))
}

func TestGDPRFramework_Check_EmptyContent(t *testing.T) {
	f := NewGDPRFramework()
	ctx := context.Background()

	input := common.CheckInput{
		Content:  "",
		Headers:  map[string]string{},
		Metadata: map[string]interface{}{},
	}

	result, err := f.Check(ctx, input)
	if err != nil {
		t.Errorf("Check failed with empty content: %v", err)
	}

	if result != nil {
		t.Logf("Empty content result passed: %v", result.Passed)
	}
}
