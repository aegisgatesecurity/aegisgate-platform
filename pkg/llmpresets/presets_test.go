// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Self-Hosted LLM Presets Tests

package llmpresets

import (
	"testing"
)

func TestGetPresets(t *testing.T) {
	presets := GetPresets()
	if len(presets) != 5 {
		t.Fatalf("expected 5 presets, got %d", len(presets))
	}
	for _, p := range presets {
		if p.Name == "" {
			t.Error("preset has empty Name")
		}
		if p.URL == "" {
			t.Errorf("preset %q has empty URL", p.Name)
		}
		if p.Type == "" {
			t.Errorf("preset %q has empty Type", p.Name)
		}
		if p.Description == "" {
			t.Errorf("preset %q has empty Description", p.Name)
		}
		if len(p.DefaultModels) < 1 {
			t.Errorf("preset %q has no DefaultModels", p.Name)
		}
	}
}

func TestGetPreset(t *testing.T) {
	preset, err := GetPreset("ollama")
	if err != nil {
		t.Fatalf("expected no error for 'ollama', got %v", err)
	}
	if preset.Name != "ollama" {
		t.Errorf("expected preset name 'ollama', got %q", preset.Name)
	}
	if preset.URL != "http://localhost:11434/v1" {
		t.Errorf("expected ollama URL, got %q", preset.URL)
	}

	_, err = GetPreset("nonexistent")
	if err == nil {
		t.Fatal("expected error for 'nonexistent', got nil")
	}
}

func TestGetPresetNames(t *testing.T) {
	names := GetPresetNames()
	if len(names) != 5 {
		t.Fatalf("expected 5 names, got %d", len(names))
	}

	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["ollama"] {
		t.Error("expected 'ollama' in preset names")
	}
	if !found["vllm"] {
		t.Error("expected 'vllm' in preset names")
	}
}

func TestPresetFields(t *testing.T) {
	presets := GetPresets()
	for _, p := range presets {
		if p.Type != "openai-compatible" {
			t.Errorf("preset %q has type %q, expected 'openai-compatible'", p.Name, p.Type)
		}
	}
}