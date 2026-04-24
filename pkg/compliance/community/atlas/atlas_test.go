package atlas

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestAtlasFramework_NewFramework(t *testing.T) {
	f := NewAtlasFramework()

	if f == nil {
		t.Fatal("NewAtlasFramework returned nil")
	}

	if f.GetName() == "" {
		t.Error("GetName returned empty string")
	}
}

func TestAtlasFramework_GetVersion(t *testing.T) {
	f := NewAtlasFramework()
	version := f.GetVersion()

	if version == "" {
		t.Error("GetVersion returned empty string")
	}
}

func TestAtlasFramework_GetDescription(t *testing.T) {
	f := NewAtlasFramework()
	desc := f.GetDescription()

	if desc == "" {
		t.Error("GetDescription returned empty string")
	}
}

func TestAtlasFramework_IsEnabled(t *testing.T) {
	f := NewAtlasFramework()

	if !f.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestAtlasFramework_EnableDisable(t *testing.T) {
	f := NewAtlasFramework()

	f.Disable()
	if f.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}

	f.Enable()
	if !f.IsEnabled() {
		t.Error("Enable should make framework enabled")
	}
}

func TestAtlasFramework_Configure(t *testing.T) {
	f := NewAtlasFramework()

	config := map[string]interface{}{
		"strictMode": true,
	}

	err := f.Configure(config)
	if err != nil {
		t.Errorf("Configure failed: %v", err)
	}
}

func TestAtlasFramework_GetFrameworkID(t *testing.T) {
	f := NewAtlasFramework()
	id := f.GetFrameworkID()

	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestAtlasFramework_GetPatternCount(t *testing.T) {
	f := NewAtlasFramework()
	count := f.GetPatternCount()

	if count < 0 {
		t.Errorf("Expected non-negative pattern count, got %d", count)
	}
}

func TestAtlasFramework_GetSeverityLevels(t *testing.T) {
	f := NewAtlasFramework()
	levels := f.GetSeverityLevels()

	if len(levels) == 0 {
		t.Error("GetSeverityLevels returned empty slice")
	}
}

func TestAtlasFramework_Check(t *testing.T) {
	f := NewAtlasFramework()
	ctx := context.Background()

	input := common.CheckInput{
		Content:  "Atlas framework test content",
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
}

func TestAtlasFramework_CheckRequest(t *testing.T) {
	f := NewAtlasFramework()
	ctx := context.Background()

	req := &common.HTTPRequest{
		Method:  "POST",
		URL:     "https://api.example.com/atlas",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    []byte(`{"data": "test"}`),
	}

	findings, err := f.CheckRequest(ctx, req)
	if err != nil {
		t.Errorf("CheckRequest failed: %v", err)
	}

	// Findings may be nil or empty
	_ = len(findings)
}

func TestAtlasFramework_CheckResponse(t *testing.T) {
	f := NewAtlasFramework()
	ctx := context.Background()

	resp := &common.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"result": "ok"}`),
	}

	findings, err := f.CheckResponse(ctx, resp)
	if err != nil {
		t.Errorf("CheckResponse failed: %v", err)
	}

	// Findings may be nil or empty
	_ = len(findings)
}
