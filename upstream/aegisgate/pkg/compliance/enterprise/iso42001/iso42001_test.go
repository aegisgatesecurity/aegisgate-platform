package iso42001

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestISO42001Framework_NewFramework(t *testing.T) {
	f := NewISO42001Framework()

	if f == nil {
		t.Fatal("NewISO42001Framework returned nil")
	}

	if f.GetName() != FrameworkName {
		t.Errorf("Expected name %s, got %s", FrameworkName, f.GetName())
	}

	if f.GetVersion() != FrameworkVersion {
		t.Errorf("Expected version %s, got %s", FrameworkVersion, f.GetVersion())
	}
}

func TestISO42001Framework_GetDescription(t *testing.T) {
	f := NewISO42001Framework()
	desc := f.GetDescription()

	if desc == "" {
		t.Error("GetDescription returned empty string")
	}
}

func TestISO42001Framework_IsEnabled(t *testing.T) {
	f := NewISO42001Framework()

	if !f.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestISO42001Framework_EnableDisable(t *testing.T) {
	f := NewISO42001Framework()

	f.Disable()
	if f.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}

	f.Enable()
	if !f.IsEnabled() {
		t.Error("Enable should make framework enabled")
	}
}

func TestISO42001Framework_Configure(t *testing.T) {
	f := NewISO42001Framework()

	config := map[string]interface{}{
		"strictMode": true,
	}

	err := f.Configure(config)
	if err != nil {
		t.Errorf("Configure failed: %v", err)
	}
}

func TestISO42001Framework_GetFrameworkID(t *testing.T) {
	f := NewISO42001Framework()
	id := f.GetFrameworkID()

	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestISO42001Framework_GetPatternCount(t *testing.T) {
	f := NewISO42001Framework()
	count := f.GetPatternCount()

	if count <= 0 {
		t.Errorf("Expected positive pattern count, got %d", count)
	}
}

func TestISO42001Framework_GetSeverityLevels(t *testing.T) {
	f := NewISO42001Framework()
	levels := f.GetSeverityLevels()

	if len(levels) == 0 {
		t.Error("GetSeverityLevels returned empty slice")
	}
}

func TestISO42001Framework_Check(t *testing.T) {
	f := NewISO42001Framework()
	ctx := context.Background()

	input := common.CheckInput{
		Content:  "ISO 42001 AI management test content",
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

func TestISO42001Clauses(t *testing.T) {
	f := NewISO42001Framework()

	clauses := f.clauses
	if len(clauses) == 0 {
		t.Error("No clauses loaded")
	}

	found5 := false
	for _, c := range clauses {
		if c.Number == "5.0" {
			found5 = true
			if c.Name == "" {
				t.Error("Clause 5.0 has empty name")
			}
			break
		}
	}

	if !found5 {
		t.Error("Missing Clause 5.0")
	}
}
