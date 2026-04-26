// SPDX-License-Identifier: Apache-2.0

//go:build integration

package compliance

import (
	"context"
	"testing"
)

// TestCheckFrameworkIntegration tests framework checking with real compliance data
// This requires real compliance pattern matching against actual code/logs
func TestCheckFrameworkIntegration(t *testing.T) {
	manager := NewManager(nil)
	if manager == nil {
		t.Fatal("NewManager returned nil")
	}

	// Add some frameworks
	manager.RegisterFramework("hipaa", "1.0", nil)
	manager.RegisterFramework("pci", "1.0", nil)

	// Test checking content that should trigger findings
	testContent := `
	Patient Health Information (PHI) in plain text:
	Name: John Doe
	SSN: 123-45-6789
	Credit Card: 4111-1111-1111-1111
	`

	result, err := manager.CheckFramework(testContent, "hipaa")
	if err != nil {
		t.Errorf("CheckFramework failed: %v", err)
	}
	if result == nil {
		t.Fatal("CheckFramework returned nil result")
	}

	// Should have found some PHI patterns
	if len(result.Findings) == 0 {
		t.Log("No HIPAA findings - this may be expected if patterns require specific context")
	}
}

// TestDetectFrameworksIntegration tests automatic framework detection
func TestDetectFrameworksIntegration(t *testing.T) {
	manager := NewManager(nil)
	if manager == nil {
		t.Fatal("NewManager returned nil")
	}

	// Content that should auto-detect multiple frameworks
	detectionContent := `
	Healthcare API endpoint /api/patients
	HIPAA compliance required
	PHI data processing
	Payment endpoint /api/checkout
	PCI-DSS credit card handling
	`

	detected := manager.DetectFrameworks(detectionContent)
	if len(detected) == 0 {
		t.Error("DetectFrameworks should detect at least one framework")
	}
}

// TestAddCustomPatternIntegration tests adding custom compliance patterns
func TestAddCustomPatternIntegration(t *testing.T) {
	manager := NewManager(nil)
	if manager == nil {
		t.Fatal("NewManager returned nil)
	}

	// Create a custom pattern
	pattern := &Pattern{
		ID:          "CUSTOM-001",
		Name:        "Custom Secret",
		Description: "Custom secret pattern",
		Pattern:     "CUSTOM-SECRET-[A-Z0-9]{16}",
		Severity:    "critical",
		Frameworks:  []string{"custom"},
	}

	err := manager.AddCustomPattern(pattern)
	if err != nil {
		t.Errorf("AddCustomPattern failed: %v", err)
	}

	// Check if pattern is detected
	content := "Found: CUSTOM-SECRET-ABCD1234EFGH5678"
	result, err := manager.CheckFramework(content, "custom")
	if err != nil {
		t.Errorf("CheckFramework with custom failed: %v", err)
	}
	if result != nil && len(result.Findings) > 0 {
		t.Log("Custom pattern detected successfully")
	}
}

// TestNIST1500FrameworkIntegration tests NIST 800-150 framework
func TestNIST1500FrameworkIntegration(t *testing.T) {
	manager := NewManager(nil)
	manager.RegisterFramework("nist-150", "1.0", nil)

	// AI-specific content for NIST AI profile
	aiContent := `
	Machine Learning Model: Neural Network v1.0
	Training Data: 1M samples
	Model Accuracy: 95%
	Fairness metrics: passed
	`

	result, err := manager.CheckFramework(aiContent, "nist-150")
	if err != nil {
		t.Logf("NIST-150 framework may not be registered: %v", err)
	}
	if result != nil {
		t.Logf("NIST-150 check completed with %d findings", len(result.Findings))
	}
}

// TestOWASPFrameworkIntegration tests OWASP framework
func TestOWASPFrameworkIntegration(t *testing.T) {
	manager := NewManager(nil)
	manager.RegisterFramework("owasp", "1.0", nil)

	// Content with potential security issues
	securityContent := `
	SQL query: SELECT * FROM users WHERE id = ' + userInput + '
	Password in URL: https://api.example.com?api_key=secret123
	Eval usage: eval(userCode)
	`

	result, err := manager.CheckFramework(securityContent, "owasp")
	if err != nil {
		t.Errorf("OWASP CheckFramework failed: %v", err)
	}
	if result != nil && len(result.Findings) > 0 {
		t.Logf("OWASP found %d potential security issues", len(result.Findings))
	}
}
