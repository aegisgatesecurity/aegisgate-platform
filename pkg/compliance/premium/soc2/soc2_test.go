package soc2

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestSOC2Framework_NewFramework(t *testing.T) {
	f := NewSOC2Framework()

	if f == nil {
		t.Fatal("NewSOC2Framework returned nil")
	}

	if f.GetName() != FrameworkName {
		t.Errorf("Expected name %s, got %s", FrameworkName, f.GetName())
	}

	if f.GetVersion() != FrameworkVersion {
		t.Errorf("Expected version %s, got %s", FrameworkVersion, f.GetVersion())
	}
}

func TestSOC2Framework_GetDescription(t *testing.T) {
	f := NewSOC2Framework()
	desc := f.GetDescription()

	if desc == "" {
		t.Error("GetDescription returned empty string")
	}
}

func TestSOC2Framework_IsEnabled(t *testing.T) {
	f := NewSOC2Framework()

	if !f.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestSOC2Framework_EnableDisable(t *testing.T) {
	f := NewSOC2Framework()

	f.Disable()
	if f.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}

	f.Enable()
	if !f.IsEnabled() {
		t.Error("Enable should make framework enabled")
	}
}

func TestSOC2Framework_Configure(t *testing.T) {
	f := NewSOC2Framework()

	config := map[string]interface{}{
		"strictMode":  true,
		"auditPeriod": "90 days",
	}

	err := f.Configure(config)
	if err != nil {
		t.Errorf("Configure failed: %v", err)
	}
}

func TestSOC2Framework_GetFrameworkID(t *testing.T) {
	f := NewSOC2Framework()
	id := f.GetFrameworkID()

	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestSOC2Framework_GetPatternCount(t *testing.T) {
	f := NewSOC2Framework()
	count := f.GetPatternCount()

	if count <= 0 {
		t.Errorf("Expected positive pattern count, got %d", count)
	}
}

func TestSOC2Framework_GetSeverityLevels(t *testing.T) {
	f := NewSOC2Framework()
	levels := f.GetSeverityLevels()

	if len(levels) == 0 {
		t.Error("GetSeverityLevels returned empty slice")
	}
}

func TestSOC2Framework_Check(t *testing.T) {
	f := NewSOC2Framework()
	ctx := context.Background()

	input := common.CheckInput{
		Content:  "SOC 2 test content for trust services",
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

func TestSOC2Principles(t *testing.T) {
	f := NewSOC2Framework()

	principles := f.principles
	if len(principles) == 0 {
		t.Error("No principles loaded")
	}

	foundSecurity := false
	for _, p := range principles {
		if p.ID == "TSP-SEC" {
			foundSecurity = true
			if p.Name == "" {
				t.Error("Security principle has empty name")
			}
			break
		}
	}

	if !foundSecurity {
		t.Error("Missing TSP-SEC principle")
	}
}
