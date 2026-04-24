package hipaa

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestHIPAAFramework_NewFramework(t *testing.T) {
	f := NewHIPAAFramework()

	if f == nil {
		t.Fatal("NewHIPAAFramework returned nil")
	}

	if f.GetName() != FrameworkName {
		t.Errorf("Expected name %s, got %s", FrameworkName, f.GetName())
	}
}

func TestHIPAAFramework_GetVersion(t *testing.T) {
	f := NewHIPAAFramework()

	if f.GetVersion() != FrameworkVersion {
		t.Errorf("Expected version %s, got %s", FrameworkVersion, f.GetVersion())
	}
}

func TestHIPAAFramework_IsEnabled(t *testing.T) {
	f := NewHIPAAFramework()

	if !f.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestHIPAAFramework_GetFrameworkID(t *testing.T) {
	f := NewHIPAAFramework()

	id := f.GetFrameworkID()
	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestHIPAAFramework_GetPatternCount(t *testing.T) {
	f := NewHIPAAFramework()

	count := f.GetPatternCount()
	if count <= 0 {
		t.Errorf("Expected positive pattern count, got %d", count)
	}
}

func TestHIPAAFramework_EnableDisable(t *testing.T) {
	f := NewHIPAAFramework()

	f.Disable()
	if f.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}

	f.Enable()
	if !f.IsEnabled() {
		t.Error("Enable should make framework enabled")
	}
}

func TestHIPAAFramework_Check(t *testing.T) {
	f := NewHIPAAFramework()
	result, err := f.Check(nil, common.CheckInput{Content: "test"})
	if err != nil {
		t.Errorf("Check failed: %v", err)
	}
	if result == nil {
		t.Fatal("Check returned nil result")
	}
}

func TestHIPAAFramework_Safeguards(t *testing.T) {
	f := NewHIPAAFramework()

	if len(f.safeguards) == 0 {
		t.Error("No safeguards loaded")
	}
}
