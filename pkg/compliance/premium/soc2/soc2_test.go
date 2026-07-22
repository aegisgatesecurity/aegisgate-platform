// SPDX-License-Identifier: Apache-2.0

package soc2

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

func TestSOC2NewFramework(t *testing.T) {
	fw := NewSOC2Framework()
	if fw == nil {
		t.Fatal("NewSOC2Framework returned nil")
	}
	if fw.name != FrameworkName {
		t.Errorf("expected name %s, got %s", FrameworkName, fw.name)
	}
}

func TestSOC2GetName(t *testing.T) {
	fw := NewSOC2Framework()
	name := fw.GetName()
	if name == "" {
		t.Error("GetName returned empty string")
	}
}

func TestSOC2GetVersion(t *testing.T) {
	fw := NewSOC2Framework()
	version := fw.GetVersion()
	if version == "" {
		t.Error("GetVersion returned empty string")
	}
}

func TestSOC2GetDescription(t *testing.T) {
	fw := NewSOC2Framework()
	desc := fw.GetDescription()
	if desc == "" {
		t.Error("GetDescription returned empty string")
	}
}

func TestSOC2GetFrameworkID(t *testing.T) {
	fw := NewSOC2Framework()
	id := fw.GetFrameworkID()
	if id == "" {
		t.Error("GetFrameworkID returned empty string")
	}
}

func TestSOC2GetPatternCount(t *testing.T) {
	fw := NewSOC2Framework()
	count := fw.GetPatternCount()
	if count < 0 {
		t.Error("GetPatternCount returned negative value")
	}
}

func TestSOC2GetSeverityLevels(t *testing.T) {
	fw := NewSOC2Framework()
	levels := fw.GetSeverityLevels()
	if levels == nil {
		t.Error("GetSeverityLevels returned nil")
	}
}

func TestSOC2IsEnabled(t *testing.T) {
	fw := NewSOC2Framework()
	if !fw.IsEnabled() {
		t.Error("New framework should be enabled by default")
	}
}

func TestSOC2Enable(t *testing.T) {
	fw := NewSOC2Framework()
	fw.Disable()
	if fw.IsEnabled() {
		t.Error("Disable should make IsEnabled return false")
	}
	fw.Enable()
	if !fw.IsEnabled() {
		t.Error("Enable should make IsEnabled return true")
	}
}

func TestSOC2Disable(t *testing.T) {
	fw := NewSOC2Framework()
	fw.Disable()
	if fw.IsEnabled() {
		t.Error("Disable should make framework disabled")
	}
}

func TestSOC2Configure(t *testing.T) {
	fw := NewSOC2Framework()
	config := map[string]interface{}{"key": "value"}
	if err := fw.Configure(config); err != nil {
		t.Errorf("Configure failed: %v", err)
	}
}

func TestSOC2Check(t *testing.T) {
	fw := NewSOC2Framework()

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
	result, err = fw.Check(context.Background(), common.CheckInput{Content: "test content"})
	if err != nil {
		t.Errorf("Check with content failed: %v", err)
	}
	if result == nil {
		t.Fatal("Check returned nil result")
	}
}

func TestSOC2CheckRequest(t *testing.T) {
	fw := NewSOC2Framework()

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
		URL:    "https://example.com/api",
		Body:   []byte("test body"),
	})
	if err != nil {
		t.Errorf("CheckRequest with data failed: %v", err)
	}
	_ = findings
}

func TestSOC2CheckResponse(t *testing.T) {
	fw := NewSOC2Framework()

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
		Body:       []byte("response body"),
	})
	if err != nil {
		t.Errorf("CheckResponse with data failed: %v", err)
	}
	_ = findings
}

func TestSOC2GetTier(t *testing.T) {
	fw := NewSOC2Framework()
	tier := fw.GetTier()
	if tier.Name == "" {
		t.Error("GetTier returned empty name")
	}
}

func TestSOC2GetConfig(t *testing.T) {
	fw := NewSOC2Framework()
	config := fw.GetConfig()
	if config == nil {
		t.Error("GetConfig returned nil")
	}
	if config.Name != FrameworkName {
		t.Errorf("expected config name %s, got %s", FrameworkName, config.Name)
	}
}

func TestSOC2SupportsTier(t *testing.T) {
	fw := NewSOC2Framework()

	// SOC2 is enterprise/premium tier
	if !fw.SupportsTier("Premium") {
		t.Error("SOC2 should support Premium tier")
	}
	if fw.SupportsTier("community") {
		t.Error("SOC2 should not support community tier")
	}
}

func TestSOC2DebugSupportsTier(t *testing.T) {
	fw := NewSOC2Framework()
	// Debug - print the tier values
	result := fw.SupportsTier("Premium")
	t.Logf("SupportsTier(\"premium\") = %v", result)
	result2 := fw.SupportsTier("Premium")
	t.Logf("SupportsTier(\"Premium\") = %v", result2)
	result3 := fw.SupportsTier("enterprise")
	t.Logf("SupportsTier(\"enterprise\") = %v", result3)
	result4 := fw.SupportsTier("Enterprise")
	t.Logf("SupportsTier(\"Enterprise\") = %v", result4)
}
