// SPDX-License-Identifier: Apache-2.0
// v3.5.0+ Phase 2: New automated control tests (Output Filtering +
// Human Oversight). These tests cover the 8 controls that were
// upgraded from manual to automated in v3.5.0+.

package eu_ai_act

import (
	"context"
	"testing"
)

func TestCheckTrainingDataSanitization(t *testing.T) {
	m := NewEUAIModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (training_data_sanitized enabled, no PII)",
			input:      `{"training_data_sanitized": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (pii_scrubbing + secret_scrubbing enabled)",
			input:      `{"pii_scrubbing": true, "secret_scrubbing": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (no sanitization config)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "partial (sanitization enabled but raw SSN in input)",
			input:      `{"training_data_sanitized": true, "raw_data": "patient SSN 123-45-6789"}`,
			wantStatus: "partial",
		},
		{
			name:       "partial (sanitization enabled but AWS key in input)",
			input:      `{"pii_scrubbing": true, "config": "AKIAIOSFODNN7EXAMPLE"}`,
			wantStatus: "partial",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkTrainingDataSanitization(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkTrainingDataSanitization: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckAIOutputFiltering(t *testing.T) {
	m := NewEUAIModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (all 3 filters enabled)",
			input:      `{"response_filter_enabled": true, "pii_filter": true, "secret_filter": true, "toxicity_filter": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (filter enabled, only PII)",
			input:      `{"response_filter_enabled": true, "pii_filter": true}`,
			wantStatus: "partial",
		},
		{
			name:       "partial (filter enabled, PII + toxicity but no secret)",
			input:      `{"response_filter_enabled": true, "pii_filter": true, "toxicity_filter": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (filter not enabled)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAIOutputFiltering(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAIOutputFiltering: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckHallucinationDetection(t *testing.T) {
	m := NewEUAIModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (detector enabled, no markers)",
			input:      `{"hallucination_detector": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (detector enabled, markers detected - this is good)",
			input:      `{"hallucination_detector": true, "output": "This is certainly true"}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (detector not enabled)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkHallucinationDetection(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkHallucinationDetection: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckAgentCapabilityAttestation(t *testing.T) {
	m := NewEUAIModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (trust_framework enabled)",
			input:      `{"trust_framework": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (agent_attestation enabled)",
			input:      `{"agent_attestation": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (not enabled)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkAgentCapabilityAttestation(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkAgentCapabilityAttestation: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckModelVersioningLineage(t *testing.T) {
	m := NewEUAIModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (version + id + lineage)",
			input:      `{"model_version": "1.0", "model_id": "abc-123", "lineage": "github.com/foo/bar"}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (version + id)",
			input:      `{"model_version": "1.0", "model_id": "abc-123"}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (only one marker)",
			input:      `{"model_version": "1.0"}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (no markers)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkModelVersioningLineage(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkModelVersioningLineage: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckOversightMeasuresEffective(t *testing.T) {
	m := NewEUAIModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (all 3 measures)",
			input:      `{"kill_switch": true, "override": true, "human_review": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "partial (2 of 3)",
			input:      `{"kill_switch": true, "override": true}`,
			wantStatus: "partial",
		},
		{
			name:       "partial (1 of 3)",
			input:      `{"kill_switch": true}`,
			wantStatus: "partial",
		},
		{
			name:       "non-compliant (0 of 3)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkOversightMeasuresEffective(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkOversightMeasuresEffective: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckHumanReviewersCanIntervene(t *testing.T) {
	m := NewEUAIModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (human_reviewer configured)",
			input:      `{"human_reviewer": "alice@example.com"}`,
			wantStatus: "compliant",
		},
		{
			name:       "compliant (reviewer_role)",
			input:      `{"reviewer_role": "compliance_officer"}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (no reviewer)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkHumanReviewersCanIntervene(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkHumanReviewersCanIntervene: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestCheckKillSwitchAbortCapability(t *testing.T) {
	m := NewEUAIModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		wantStatus string
	}{
		{
			name:       "compliant (kill_switch + abort both present)",
			input:      `{"kill_switch": true, "abort": true}`,
			wantStatus: "compliant",
		},
		{
			name:       "non-compliant (only kill_switch, no abort)",
			input:      `{"kill_switch": true}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (only abort, no kill_switch)",
			input:      `{"abort": true}`,
			wantStatus: "non_compliant",
		},
		{
			name:       "non-compliant (neither)",
			input:      `{}`,
			wantStatus: "non_compliant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.checkKillSwitchAbortCapability(ctx, []byte(tt.input))
			if err != nil {
				t.Fatalf("checkKillSwitchAbortCapability: %v", err)
			}
			if string(result.Status) != tt.wantStatus {
				t.Errorf("Status = %q, want %q (message: %q)",
					result.Status, tt.wantStatus, result.Message)
			}
		})
	}
}

func TestEUAIModule_V350Coverage(t *testing.T) {
	// Integration: all 8 new automated checks on a fully compliant config.
	m := NewEUAIModule()
	ctx := context.Background()

	compliantConfig := []byte(`{
		"training_data_sanitized": true,
		"pii_scrubbing": true,
		"secret_scrubbing": true,
		"response_filter_enabled": true,
		"pii_filter": true,
		"secret_filter": true,
		"toxicity_filter": true,
		"hallucination_detector": true,
		"trust_framework": true,
		"agent_attestation": true,
		"model_version": "1.0",
		"model_id": "abc-123",
		"lineage": "github.com/foo/bar",
		"kill_switch": true,
		"override": true,
		"human_review": true,
		"human_reviewer": "alice",
		"abort": true,
		"training_data_source": "cleaned_dataset_v3.csv"
	}`)

	checks := map[string]func(context.Context, []byte) (string, string){
		"EUAIAct-AI-002": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkTrainingDataSanitization(c, b)
			return string(r.Status), r.Message
		},
		"EUAIAct-AI-003": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAIOutputFiltering(c, b)
			return string(r.Status), r.Message
		},
		"EUAIAct-AI-005": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkHallucinationDetection(c, b)
			return string(r.Status), r.Message
		},
		"EUAIAct-AI-006": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAgentCapabilityAttestation(c, b)
			return string(r.Status), r.Message
		},
		"EUAIAct-AI-007": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkModelVersioningLineage(c, b)
			return string(r.Status), r.Message
		},
		"EUAIAct-Art14-002": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkOversightMeasuresEffective(c, b)
			return string(r.Status), r.Message
		},
		"EUAIAct-Art14-003": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkHumanReviewersCanIntervene(c, b)
			return string(r.Status), r.Message
		},
		"EUAIAct-Art14-004": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkKillSwitchAbortCapability(c, b)
			return string(r.Status), r.Message
		},
	}

	for controlID, checkFn := range checks {
		t.Run(controlID, func(t *testing.T) {
			status, msg := checkFn(ctx, compliantConfig)
			if status != "compliant" {
				t.Errorf("Control %s on compliant config: status=%s, msg=%s",
					controlID, status, msg)
			}
		})
	}
}

func TestEUAIModule_V350AutomatedCount(t *testing.T) {
	// Verify the v3.5.0+ automated count is correct: 37 controls automated
	// (9 from v3.3.0 + 8 new in v3.5.0+ + 20 new in v3.5.1+ Phase 3).
	m := NewEUAIModule()
	automated := 0
	for _, c := range m.Controls() {
		if c.Automated {
			automated++
		}
	}
	if automated != 55 {
		t.Errorf("Automated count = %d, want 55", automated)
	}
}
