package iso42001

import (
	"context"
	"testing"

	"github.com/aegisguardsecurity/aegisguard/pkg/compliance/common"
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
		Metadata: map[string]string{"source": "test"},
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

func TestISO42001Framework_Check_EmptyContent(t *testing.T) {
	f := NewISO42001Framework()
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

func TestISO42001Framework_CheckRequest(t *testing.T) {
	f := NewISO42001Framework()
	ctx := context.Background()

	req := &common.HTTPRequest{
		Method:  "POST",
		URL:     "https://api.ai-system.com/ai-management",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"operation": "audit", "scope": "clause-5"}`,
	}

	findings, err := f.CheckRequest(ctx, req)
	if err != nil {
		t.Errorf("CheckRequest failed: %v", err)
	}

	// Findings may be empty
	_ = len(findings)
}

func TestISO42001Framework_CheckResponse(t *testing.T) {
	f := NewISO42001Framework()
	ctx := context.Background()

	resp := &common.HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       `{"status": "compliant", "clauses_evaluated": 7}`,
	}

	findings, err := f.CheckResponse(ctx, resp)
	if err != nil {
		t.Errorf("CheckResponse failed: %v", err)
	}

	// Findings may be empty
	_ = len(findings)
}

func TestISO42001Framework_GetTier(t *testing.T) {
	f := NewISO42001Framework()
	tier := f.GetTier()

	if tier.Name != "Enterprise" {
		t.Errorf("Expected tier name 'Enterprise', got '%s'", tier.Name)
	}
}

func TestISO42001Framework_GetPricing(t *testing.T) {
	f := NewISO42001Framework()
	pricing := f.GetPricing()

	if pricing.Tier != "Enterprise" {
		t.Errorf("Expected pricing tier 'Enterprise', got '%s'", pricing.Tier)
	}

	if pricing.MonthlyCost != 12000 {
		t.Errorf("Expected monthly cost 12000, got %.0f", pricing.MonthlyCost)
	}
}

func TestISO42001Framework_SupportsTier(t *testing.T) {
	f := NewISO42001Framework()

	if f.SupportsTier("Community") {
		t.Error("Should not support Community tier")
	}

	if !f.SupportsTier("Enterprise") {
		t.Error("Should support Enterprise tier")
	}

	if !f.SupportsTier("Premium") {
		t.Error("Should support Premium tier")
	}
}
