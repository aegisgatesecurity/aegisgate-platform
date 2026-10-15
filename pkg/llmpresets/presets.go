// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Self-Hosted LLM Presets
//
// Pre-configured endpoints for popular self-hosted LLM servers.
// All use OpenAI-compatible APIs for seamless integration.

package llmpresets

import "fmt"

// Preset defines a self-hosted LLM configuration.
type Preset struct {
	Name          string   `json:"name"`
	URL           string   `json:"url"`
	Type          string   `json:"type"`
	Description   string   `json:"description"`
	DefaultModels []string `json:"default_models"`
}

// GetPresets returns all available LLM presets.
func GetPresets() []Preset {
	return []Preset{
		{
			Name:          "ollama",
			URL:           "http://localhost:11434/v1",
			Type:          "openai-compatible",
			Description:   "Ollama local LLM server (https://ollama.ai)",
			DefaultModels: []string{"llama2", "mistral", "codellama"},
		},
		{
			Name:          "lm-studio",
			URL:           "http://localhost:1234/v1",
			Type:          "openai-compatible",
			Description:   "LM Studio desktop app (https://lmstudio.ai)",
			DefaultModels: []string{"local-model"},
		},
		{
			Name:          "localai",
			URL:           "http://localhost:8080/v1",
			Type:          "openai-compatible",
			Description:   "LocalAI self-hosted API (https://localai.io)",
			DefaultModels: []string{"gpt-3.5-turbo"},
		},
		{
			Name:          "vllm",
			URL:           "http://localhost:8000/v1",
			Type:          "openai-compatible",
			Description:   "vLLM high-throughput inference (https://vllm.ai)",
			DefaultModels: []string{"facebook/opt-125m"},
		},
		{
			Name:          "text-generation-webui",
			URL:           "http://localhost:5000/v1",
			Type:          "openai-compatible",
			Description:   "Oobabooga Text Generation WebUI",
			DefaultModels: []string{"model"},
		},
	}
}

// GetPreset returns a preset by name.
func GetPreset(name string) (*Preset, error) {
	presets := GetPresets()
	for _, p := range presets {
		if p.Name == name {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("preset '%s' not found", name)
}

// GetPresetNames returns the names of all available LLM presets.
func GetPresetNames() []string {
	presets := GetPresets()
	names := make([]string, len(presets))
	for i, p := range presets {
		names[i] = p.Name
	}
	return names
}
