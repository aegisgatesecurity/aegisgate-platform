// SPDX-License-Identifier: Apache-2.0

package iso42001

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestISO42001NewFramework(t *testing.T) {
	fw := NewISO42001Framework()
	if fw == nil {
		t.Fatal("NewISO42001Framework returned nil")
	}
	if fw.name != FrameworkName {
		t.Errorf("expected name %s, got %s", FrameworkName, fw.name)
	}
}

func TestISO42001GetName(t *testing.T) {
	fw := NewISO42001Framework()
	name := fw.GetName()
	if name == "" {
		t.Error("GetName returned empty string")
	}
}

func TestISO42001GetVersion(t *testing.T) {
	fw := NewISO42001Framework()
	version := fw.GetVersion()
	if version == "" {
		t.Error("GetVersion returned empty string")
	}
}

func TestISO42001GetDescription(t *testing.T) {
	fw := NewISO42001Framework()
	desc := fw.GetDescription()
	if desc == "" {
		t.Error("GetDescription returned empty string")
	}
}

func TestISO42001GetFrameworkID(t *testing.T) {
	fw := NewISO42001Framework()
	id := fw.GetFrameworkID()
	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestISO42001GetPatternCount(t *testing.T) {
	fw := NewISO42001Framework()
	count := fw.GetPatternCount()
	if count < 0 {
		t.Error("GetPatternCount returned negative value")
	}
}

func TestISO42001GetSeverityLevels(t *testing.T) {
	fw := NewISO42001Framework()
	levels := fw.GetSeverityLevels()
	if levels == nil {
		t.Error("GetSeverityLevels returned nil")
	}
}

func TestISO42001IsEnabled(t *testing.T) {
	fw := NewISO42001Framework()
	if !fw.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestISO42001Enable(t *testing.T) {
	fw := NewISO42001Framework()
	fw.Disable()
	if fw.IsEnabled() {
		t.Error("Disable should make IsEnabled return false")
	}
	fw.Enable()
	if !fw.IsEnabled() {
		t.Error("Enable should make IsEnabled return true")
	}
}

func TestISO42001Disable(t *testing.T) {
	fw := NewISO42001Framework()
	fw.Disable()
	if fw.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}
}

func TestISO42001Configure(t *testing.T) {
	fw := NewISO42001Framework()
	config := map[string]interface{}{"key": "value"}
	if err := fw.Configure(config); err != nil {
		t.Errorf("Configure failed: %v", err)
	}
}

func TestISO42001Check(t *testing.T) {
	fw := NewISO42001Framework()
	
	// Test with empty content
	result, err := fw.Check(context.Background(), common.CheckInput{})
	if err != nil {
		t.Errorf("Check failed: %v", err)
	}
	if result == nil {
		t.Fatal("Check returned nil result")
	}
	if result.Framework != FrameworkName {
		t.Errorf("expected framework %s, got %s", FrameworkName, result.Framework)
	}
	
	// Test with content
	result, err = fw.Check(context.Background(), common.CheckInput{Content: "AI model training data"})
	if err != nil {
		t.Errorf("Check with content failed: %v", err)
	}
	if result == nil {
		t.Fatal("Check returned nil result")
	}
}

func TestISO42001CheckRequest(t *testing.T) {
	fw := NewISO42001Framework()
	
	findings, err := fw.CheckRequest(context.Background(), &common.HTTPRequest{})
	if err != nil {
		t.Errorf("CheckRequest failed: %v", err)
	}
	if findings == nil {
		// CheckRequest returns empty findings - expected behavior
	}
	
	// Test with request
	findings, err = fw.CheckRequest(context.Background(), &common.HTTPRequest{
		Method: "POST",
		URL:    "https://ai-api.example.com/train",
		Body:   []byte("training data"),
	})
	if err != nil {
		t.Errorf("CheckRequest with data failed: %v", err)
	}
	_ = findings
}

func TestISO42001CheckResponse(t *testing.T) {
	fw := NewISO42001Framework()
	
	findings, err := fw.CheckResponse(context.Background(), &common.HTTPResponse{})
	if err != nil {
		t.Errorf("CheckResponse failed: %v", err)
	}
	if findings == nil {
		// CheckResponse returns empty findings - expected behavior
	}
	
	// Test with response
	findings, err = fw.CheckResponse(context.Background(), &common.HTTPResponse{
		StatusCode: 200,
		Body:   []byte("AI model response"),
	})
	if err != nil {
		t.Errorf("CheckResponse with data failed: %v", err)
	}
	_ = findings
}

func TestISO42001GetTier(t *testing.T) {
	fw := NewISO42001Framework()
	tier := fw.GetTier()
	if tier.Name == "" {
		t.Error("GetTier returned empty name")
	}
}

func TestISO42001GetConfig(t *testing.T) {
	fw := NewISO42001Framework()
	config := fw.GetConfig()
	if config == nil {
		t.Error("GetConfig returned nil")
	}
	if config.Name != FrameworkName {
		t.Errorf("expected config name %s, got %s", FrameworkName, config.Name)
	}
}

func TestISO42001SupportsTier(t *testing.T) {
	fw := NewISO42001Framework()
	
	// ISO42001 is enterprise tier
	if !fw.SupportsTier("Enterprise") {
		t.Error("ISO42001 should support enterprise tier")
	}
	if fw.SupportsTier("Community") {
		t.Error("ISO42001 should not support community tier")
	}
}

func TestISO42001DebugSupportsTier(t *testing.T) {
	fw := NewISO42001Framework()
	result := fw.SupportsTier("Enterprise")
	t.Logf("SupportsTier(\"Enterprise\") = %v", result)
	result2 := fw.SupportsTier("Premium")
	t.Logf("SupportsTier(\"Premium\") = %v", result2)
}
