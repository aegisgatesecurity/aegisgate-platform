// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"encoding/json"
	"testing"
)

func TestPatternJSONRoundtrip(t *testing.T) {
	original := Pattern{
		ID:          "secret_aws_key",
		Name:        "secret_aws_key",
		Regex:       `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
		Severity:    SeverityCritical,
		Category:    CategorySecrets,
		Description: "AWS access key ID",
		Confidence:  1.0,
		Version:     "v1",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Pattern
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
	}
	if decoded.Regex != original.Regex {
		t.Errorf("Regex: got %q, want %q", decoded.Regex, original.Regex)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("Severity: got %q, want %q", decoded.Severity, original.Severity)
	}
	if decoded.Category != original.Category {
		t.Errorf("Category: got %q, want %q", decoded.Category, original.Category)
	}
}

func TestPatternWithLanguages(t *testing.T) {
	p := Pattern{
		ID:        "dangerous_py_eval",
		Name:      "dangerous_py_eval",
		Regex:     `eval\s*\(`,
		Severity:  SeverityCritical,
		Category:  CategoryDangerousFunction,
		Languages: []PatternLanguage{LangPython},
		Version:   "v1",
	}

	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Pattern
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Languages) != 1 || decoded.Languages[0] != LangPython {
		t.Errorf("Languages: got %v, want [%q]", decoded.Languages, LangPython)
	}
}

func TestEventJSONRoundtrip(t *testing.T) {
	original := Event{
		ID:              "550e8400-e29b-41d4-a716-446655440000",
		Source:          SourceRampart,
		SourceVersion:   "v1.2.0",
		SchemaVersion:   "v1",
		TotalDetections: 3,
		Blocked:         true,
		Action:          "blocked",
		Direction:       DirectionResponse,
		Host:            "api.openai.com",
		Categories:      []string{"secrets", "pii-us-core"},
		Severities:      []string{"critical", "high"},
		Rules:           []string{"secret_aws_key", "pii_ssn"},
		Findings: []EventFinding{
			{
				RuleID:     "secret_aws_key",
				Category:   "secrets",
				Severity:   "critical",
				Confidence: 1.0,
				Message:    "AWS access key ID detected",
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Source != original.Source {
		t.Errorf("Source: got %q, want %q", decoded.Source, original.Source)
	}
	if decoded.Blocked != original.Blocked {
		t.Errorf("Blocked: got %v, want %v", decoded.Blocked, original.Blocked)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("Findings: got %d, want 1", len(decoded.Findings))
	}
	if decoded.Findings[0].RuleID != "secret_aws_key" {
		t.Errorf("Findings[0].RuleID: got %q, want %q", decoded.Findings[0].RuleID, "secret_aws_key")
	}
}

func TestEventBatchJSON(t *testing.T) {
	batch := EventBatch{
		SchemaVersion: "v1",
		Source:        SourceScanner,
		Events: []Event{
			{
				ID:              "event-1",
				Source:          SourceScanner,
				SchemaVersion:   "v1",
				TotalDetections: 5,
				Blocked:         false,
				Action:          "logged",
				Direction:       DirectionScan,
				Artifact:        "src/handlers/secret.py",
			},
			{
				ID:              "event-2",
				Source:          SourceScanner,
				SchemaVersion:   "v1",
				TotalDetections: 2,
				Blocked:         false,
				Action:          "logged",
				Direction:       DirectionScan,
				Artifact:        "src/utils/config.ts",
			},
		},
	}

	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EventBatch
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Events) != 2 {
		t.Fatalf("Events: got %d, want 2", len(decoded.Events))
	}
	if decoded.Events[0].Artifact != "src/handlers/secret.py" {
		t.Errorf("Events[0].Artifact: got %q", decoded.Events[0].Artifact)
	}
}

func TestPatternSetResponseJSON(t *testing.T) {
	resp := PatternSetResponse{
		APIVersion: "v1",
		PatternSet: PatternSet{
			Version:     "v1",
			Source:      "platform",
			GeneratedAt: "2026-10-14T15:30:00Z",
			Hash:        "sha256:abc123",
			Patterns: []Pattern{
				{
					ID:       "secret_aws_key",
					Name:     "secret_aws_key",
					Regex:    `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
					Severity: SeverityCritical,
					Category: CategorySecrets,
					Version:  "v1",
				},
			},
		},
		UpdatedAt: "2026-10-14T15:00:00Z",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PatternSetResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.APIVersion != "v1" {
		t.Errorf("APIVersion: got %q", decoded.APIVersion)
	}
	if len(decoded.PatternSet.Patterns) != 1 {
		t.Fatalf("Patterns: got %d, want 1", len(decoded.PatternSet.Patterns))
	}
}

func TestEventAcknowledgmentJSON(t *testing.T) {
	ack := EventAcknowledgment{
		Accepted: 5,
		Rejected: 1,
		Errors: []EventError{
			{
				EventID: "event-bad",
				Reason:  "invalid schema_version",
			},
		},
		UpdatedAt: "2026-10-14T15:00:00Z",
	}

	data, err := json.Marshal(ack)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EventAcknowledgment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Accepted != 5 {
		t.Errorf("Accepted: got %d, want 5", decoded.Accepted)
	}
	if len(decoded.Errors) != 1 {
		t.Fatalf("Errors: got %d, want 1", len(decoded.Errors))
	}
}

// TestEventMetadataOnly verifies that no sensitive values appear in the JSON.
// This is the core privacy guarantee — events carry metadata, not content.
func TestEventMetadataOnly(t *testing.T) {
	e := Event{
		ID:              "test-123",
		Source:          SourceRampart,
		SchemaVersion:   "v1",
		TotalDetections: 1,
		Blocked:         true,
		Findings: []EventFinding{
			{
				RuleID:   "secret_aws_key",
				Category: "secrets",
				Severity: "critical",
				Message:  "AWS access key ID detected", // description, NOT the matched value
			},
		},
	}

	data, _ := json.Marshal(e)
	jsonStr := string(data)

	// The event should NOT contain any of these sensitive fields
	sensitive := []string{"matched_text", "prompt", "value", "content", "plaintext"}
	for _, s := range sensitive {
		if contains(jsonStr, s) {
			t.Errorf("Event JSON contains sensitive field %q: %s", s, jsonStr)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
