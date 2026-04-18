// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.

package compliance

import (
	"testing"
)

func TestOwaspManager_New(t *testing.T) {
	manager := NewOwaspManager()
	if manager == nil {
		t.Fatal("NewOwaspManager() returned nil")
	}

	if len(manager.patterns) == 0 {
		t.Error("NewOwaspManager() should initialize patterns")
	}
}

func TestOwaspManager_OwaspPatterns(t *testing.T) {
	manager := NewOwaspManager()

	// Verify patterns are initialized
	if len(manager.patterns) < 10 {
		t.Errorf("OWASP manager should have at least 10 patterns for LLM Top 10, got %d", len(manager.patterns))
	}

	// Check that patterns contain OWASP LLM Top 10 categories
	categoryMap := make(map[string]int)
	for _, p := range manager.patterns {
		categoryMap[p.Category]++
	}

	// Should include at minimum: LLM01 (Prompt Injection) and LLM02 (Insecure Output Handling)
	if categoryMap["LLM01"] < 1 {
		t.Error("OWASP patterns should include LLM01 (Prompt Injection)")
	}
}

func TestOwaspPattern_Fields(t *testing.T) {
	pattern := OwaspPattern{
		ID:          "LLM01-001",
		Category:    "LLM01",
		Name:        "Test Pattern",
		Description: "Test description",
		Severity:    "high",
		Suggestion:  "Fix it",
	}

	if pattern.ID != "LLM01-001" {
		t.Errorf("Pattern.ID = %s, want LLM01-001", pattern.ID)
	}

	if pattern.Severity != "high" {
		t.Errorf("Pattern.Severity = %s, want high", pattern.Severity)
	}
}

func TestOwaspManager_PromptInjectionPatterns(t *testing.T) {
	manager := NewOwaspManager()

	// Should include prompt injection patterns for LLM01
	promptInjectionPatterns := 0
	for _, p := range manager.patterns {
		if p.Category == "LLM01" {
			promptInjectionPatterns++
		}
	}

	if promptInjectionPatterns == 0 {
		t.Error("OWASP manager should include prompt injection patterns for LLM01")
	}
}

func TestOwaspManager_SeverityLevels(t *testing.T) {
	manager := NewOwaspManager()

	// Verify severity levels are valid
	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	for _, p := range manager.patterns {
		if !validSeverities[p.Severity] {
			t.Errorf("Pattern %s has invalid severity: %s", p.ID, p.Severity)
		}
	}
}

// Signed-off-by: jcolvin <josh@aegisgatesecurity.io>