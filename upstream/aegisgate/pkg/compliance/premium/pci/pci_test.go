package pci

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestPCIFramework_NewFramework(t *testing.T) {
	f := NewPCIFramework()

	if f == nil {
		t.Fatal("NewPCIFramework returned nil")
	}

	if f.GetName() != FrameworkName {
		t.Errorf("Expected name %s, got %s", FrameworkName, f.GetName())
	}

	if f.GetVersion() != FrameworkVersion {
		t.Errorf("Expected version %s, got %s", FrameworkVersion, f.GetVersion())
	}
}

func TestPCIFramework_GetDescription(t *testing.T) {
	f := NewPCIFramework()
	desc := f.GetDescription()

	if desc == "" {
		t.Error("GetDescription returned empty string")
	}
}

func TestPCIFramework_IsEnabled(t *testing.T) {
	f := NewPCIFramework()

	if !f.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestPCIFramework_EnableDisable(t *testing.T) {
	f := NewPCIFramework()

	f.Disable()
	if f.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}

	f.Enable()
	if !f.IsEnabled() {
		t.Error("Enable should make framework enabled")
	}
}

func TestPCIFramework_Configure(t *testing.T) {
	f := NewPCIFramework()

	config := map[string]interface{}{
		"strictMode": true,
	}

	err := f.Configure(config)
	if err != nil {
		t.Errorf("Configure failed: %v", err)
	}
}

func TestPCIFramework_Check(t *testing.T) {
	f := NewPCIFramework()
	ctx := context.Background()

	input := common.CheckInput{
		Content:  "PCI DSS test content",
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

func TestPCIFramework_GetFrameworkID(t *testing.T) {
	f := NewPCIFramework()
	id := f.GetFrameworkID()

	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestPCIFramework_GetPatternCount(t *testing.T) {
	f := NewPCIFramework()
	count := f.GetPatternCount()

	if count <= 0 {
		t.Errorf("Expected positive pattern count, got %d", count)
	}
}

func TestPCIFramework_GetSeverityLevels(t *testing.T) {
	f := NewPCIFramework()
	levels := f.GetSeverityLevels()

	if len(levels) == 0 {
		t.Error("GetSeverityLevels returned empty slice")
	}
}

func TestPCIRequirements(t *testing.T) {
	f := NewPCIFramework()

	reqs := f.requirements
	if len(reqs) == 0 {
		t.Error("No requirements loaded")
	}
}
