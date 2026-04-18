package common

import (
	"context"
	"testing"
	"time"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.severity.String()
			if result != tt.expected {
				t.Errorf("Severity.String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFindingStruct(t *testing.T) {
	f := Finding{
		ID:          "TEST-001",
		Framework:   "test",
		Rule:        "test-rule",
		Severity:    SeverityHigh,
		Description: "Test finding",
		Evidence:    "test evidence",
		Remediation: "fix it",
		Location:    "test.go:10",
		Timestamp:   time.Now(),
		Context:     map[string]interface{}{"key": "value"},
	}

	if f.ID != "TEST-001" {
		t.Errorf("Expected ID TEST-001, got %s", f.ID)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Expected SeverityHigh, got %v", f.Severity)
	}
	if f.Context["key"] != "value" {
		t.Errorf("Expected context key value, got %v", f.Context["key"])
	}
}

func TestFrameworkConfig(t *testing.T) {
	config := FrameworkConfig{
		Name:    "Test Framework",
		Version: "1.0",
		Enabled: true,
	}

	if config.Name != "Test Framework" {
		t.Errorf("Expected Name Test Framework, got %s", config.Name)
	}
	if config.Version != "1.0" {
		t.Errorf("Expected Version 1.0, got %s", config.Version)
	}
	if !config.Enabled {
		t.Error("Expected Enabled to be true")
	}
}

func TestTierInfo(t *testing.T) {
	tier := TierInfo{
		Name:        "Enterprise",
		Pricing:     "$1000/month",
		Description: "Enterprise tier",
	}

	if tier.Name != "Enterprise" {
		t.Errorf("Expected Name Enterprise, got %s", tier.Name)
	}
	if tier.Pricing != "$1000/month" {
		t.Errorf("Expected Pricing $1000/month, got %s", tier.Pricing)
	}
}

func TestPricingInfo(t *testing.T) {
	pricing := PricingInfo{
		Tier:        "Premium",
		MonthlyCost: 500,
		Description: "Premium features",
		Features:    []string{"feature1", "feature2"},
	}

	if pricing.Tier != "Premium" {
		t.Errorf("Expected Tier Premium, got %s", pricing.Tier)
	}
	if pricing.MonthlyCost != 500 {
		t.Errorf("Expected MonthlyCost 500, got %d", pricing.MonthlyCost)
	}
	if len(pricing.Features) != 2 {
		t.Errorf("Expected 2 features, got %d", len(pricing.Features))
	}
}

func TestTechniqueFinding(t *testing.T) {
	tf := TechniqueFinding{
		ID:          "T1234",
		Name:        "Test Technique",
		Tactic:      "impact",
		Severity:    SeverityCritical,
		Status:      "detected",
		Description: "Test technique description",
	}

	if tf.ID != "T1234" {
		t.Errorf("Expected ID T1234, got %s", tf.ID)
	}
	if tf.Severity != SeverityCritical {
		t.Errorf("Expected SeverityCritical, got %v", tf.Severity)
	}
}

func TestFindings(t *testing.T) {
	findings := Findings{
		Framework: "OWASP",
		Version:   "2023",
		Timestamp: time.Now(),
		Status:    "complete",
		Techniques: []TechniqueFinding{
			{ID: "T1", Name: "Technique 1", Severity: SeverityHigh},
		},
		Recommendations: []string{"Fix it"},
	}

	if findings.Framework != "OWASP" {
		t.Errorf("Expected Framework OWASP, got %s", findings.Framework)
	}
	if len(findings.Techniques) != 1 {
		t.Errorf("Expected 1 technique, got %d", len(findings.Techniques))
	}
}

func TestCheckInput(t *testing.T) {
	input := CheckInput{
		Content: "test content",
		Headers: map[string]string{"Content-Type": "application/json"},
		Metadata: map[string]interface{}{
			"source": "test",
		},
	}

	if input.Content != "test content" {
		t.Errorf("Expected Content test content, got %s", input.Content)
	}
	if input.Headers["Content-Type"] != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", input.Headers["Content-Type"])
	}
}

func TestCheckResult(t *testing.T) {
	result := CheckResult{
		Framework:       "GDPR",
		Passed:          true,
		Findings:        []Finding{},
		CheckedAt:       time.Now(),
		Duration:        100 * time.Millisecond,
		TotalPatterns:   10,
		MatchedPatterns: 5,
	}

	if result.Framework != "GDPR" {
		t.Errorf("Expected Framework GDPR, got %s", result.Framework)
	}
	if !result.Passed {
		t.Error("Expected Passed to be true")
	}
	if result.TotalPatterns != 10 {
		t.Errorf("Expected TotalPatterns 10, got %d", result.TotalPatterns)
	}
}

// MockFramework implements Framework interface for testing
type MockFramework struct {
	nameVal        string
	versionVal     string
	descriptionVal string
	enabledVal     bool
	configVal      map[string]interface{}
}

func (m *MockFramework) GetName() string        { return m.nameVal }
func (m *MockFramework) GetVersion() string     { return m.versionVal }
func (m *MockFramework) GetDescription() string { return m.descriptionVal }
func (m *MockFramework) Check(ctx context.Context, input CheckInput) (*CheckResult, error) {
	return &CheckResult{Framework: m.nameVal, Passed: true}, nil
}
func (m *MockFramework) CheckRequest(ctx context.Context, req *HTTPRequest) ([]Finding, error) {
	return []Finding{}, nil
}
func (m *MockFramework) CheckResponse(ctx context.Context, resp *HTTPResponse) ([]Finding, error) {
	return []Finding{}, nil
}
func (m *MockFramework) Configure(config map[string]interface{}) error {
	m.configVal = config
	return nil
}
func (m *MockFramework) IsEnabled() bool        { return m.enabledVal }
func (m *MockFramework) Enable()                { m.enabledVal = true }
func (m *MockFramework) Disable()               { m.enabledVal = false }
func (m *MockFramework) GetFrameworkID() string { return "mock-id" }
func (m *MockFramework) GetPatternCount() int   { return 5 }
func (m *MockFramework) GetSeverityLevels() []Severity {
	return []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

func TestMockFrameworkImplementsInterface(t *testing.T) {
	// This test ensures MockFramework implements Framework interface
	var _ Framework = (*MockFramework)(nil)

	f := &MockFramework{
		nameVal:        "Test",
		versionVal:     "1.0",
		descriptionVal: "Test framework",
		enabledVal:     true,
		configVal:      make(map[string]interface{}),
	}

	if f.GetName() != "Test" {
		t.Error("GetName failed")
	}
	if f.GetVersion() != "1.0" {
		t.Error("GetVersion failed")
	}
	if f.IsEnabled() != true {
		t.Error("IsEnabled failed")
	}

	f.Enable()
	if !f.IsEnabled() {
		t.Error("Enable failed")
	}

	f.Disable()
	if f.IsEnabled() {
		t.Error("Disable failed")
	}

	f.Configure(map[string]interface{}{"key": "value"})
	if f.configVal["key"] != "value" {
		t.Error("Configure failed")
	}

	levels := f.GetSeverityLevels()
	if len(levels) != 4 {
		t.Errorf("Expected 4 severity levels, got %d", len(levels))
	}
}
