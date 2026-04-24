package owasp

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestOWASPFramework_NewFramework(t *testing.T) {
	f := NewOWASPFramework()

	if f == nil {
		t.Fatal("NewOWASPFramework returned nil")
	}

	if f.GetName() != FrameworkName {
		t.Errorf("Expected name %s, got %s", FrameworkName, f.GetName())
	}

	if f.GetVersion() != FrameworkVersion {
		t.Errorf("Expected version %s, got %s", FrameworkVersion, f.GetVersion())
	}
}

func TestOWASPFramework_GetDescription(t *testing.T) {
	f := NewOWASPFramework()
	desc := f.GetDescription()

	if desc == "" {
		t.Error("GetDescription returned empty string")
	}
}

func TestOWASPFramework_IsEnabled(t *testing.T) {
	f := NewOWASPFramework()

	if !f.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestOWASPFramework_EnableDisable(t *testing.T) {
	f := NewOWASPFramework()

	f.Disable()
	if f.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}

	f.Enable()
	if !f.IsEnabled() {
		t.Error("Enable should make framework enabled")
	}
}

func TestOWASPFramework_Configure(t *testing.T) {
	f := NewOWASPFramework()

	config := map[string]interface{}{
		"strictMode": true,
		"timeout":    30,
	}

	err := f.Configure(config)
	if err != nil {
		t.Errorf("Configure failed: %v", err)
	}
}

func TestOWASPFramework_GetFrameworkID(t *testing.T) {
	f := NewOWASPFramework()
	id := f.GetFrameworkID()

	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestOWASPFramework_GetPatternCount(t *testing.T) {
	f := NewOWASPFramework()
	count := f.GetPatternCount()

	if count <= 0 {
		t.Errorf("Expected positive pattern count, got %d", count)
	}
}

func TestOWASPFramework_GetSeverityLevels(t *testing.T) {
	f := NewOWASPFramework()
	levels := f.GetSeverityLevels()

	if len(levels) == 0 {
		t.Error("GetSeverityLevels returned empty slice")
	}
}

func TestOWASPFramework_Check(t *testing.T) {
	f := NewOWASPFramework()
	ctx := context.Background()

	input := common.CheckInput{
		Content:  "test prompt content",
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

	// Duration may be very small but should be set
	_ = result.Duration

	if result.TotalPatterns == 0 {
		t.Error("TotalPatterns should be set")
	}
}

func TestOWASPFramework_CheckRequest(t *testing.T) {
	f := NewOWASPFramework()
	ctx := context.Background()

	req := &common.HTTPRequest{
		Method:  "POST",
		URL:     "https://api.example.com/v1/completions",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(`{"prompt": "test"}`),
	}

	findings, err := f.CheckRequest(ctx, req)
	if err != nil {
		t.Errorf("CheckRequest failed: %v", err)
	}

	// Findings may be empty
	_ = len(findings)
}

func TestOWASPFramework_CheckResponse(t *testing.T) {
	f := NewOWASPFramework()
	ctx := context.Background()

	resp := &common.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"response": "test"}`),
	}

	findings, err := f.CheckResponse(ctx, resp)
	if err != nil {
		t.Errorf("CheckResponse failed: %v", err)
	}

	// Findings may be empty
	_ = len(findings)
}

func TestOWASPFramework_Check_EmptyContent(t *testing.T) {
	f := NewOWASPFramework()
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

	if result != nil && !result.Passed {
		t.Logf("Empty content check returned findings: %d", len(result.Findings))
	}
}

func TestOWASPRisks(t *testing.T) {
	f := NewOWASPFramework()

	risks := f.risks
	if len(risks) == 0 {
		t.Error("No risks loaded")
	}

	foundLLM01 := false
	for _, r := range risks {
		if r.ID == "LLM01" {
			foundLLM01 = true
			if r.Name == "" {
				t.Error("Risk LLM01 has empty name")
			}
			if r.Severity == 0 {
				t.Error("Risk LLM01 has zero severity")
			}
			break
		}
	}

	if !foundLLM01 {
		t.Error("Missing LLM01 risk")
	}
}

func TestOWASPFramework_CheckResultTimestamp(t *testing.T) {
	f := NewOWASPFramework()
	ctx := context.Background()

	before := time.Now()
	input := common.CheckInput{Content: "test"}
	result, _ := f.Check(ctx, input)
	after := time.Now()

	if result.CheckedAt.Before(before) || result.CheckedAt.After(after) {
		t.Error("CheckedAt timestamp not within expected range")
	}
}
