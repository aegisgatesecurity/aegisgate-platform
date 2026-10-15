// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Self-Hosted LLM Presets
//
// Package llmpresets provides pre-configured endpoint presets for popular
// self-hosted LLM servers. All presets use OpenAI-compatible APIs for
// seamless integration with Platform's LLM subsystem.
//
// This package was ported from AegisGate Rampart's internal/llm/presets.go
// as part of the Phase 5 consolidation effort (task 2H). It provides the
// same preset definitions (ollama, lm-studio, localai, vllm,
// text-generation-webui) with the addition of a GetPresetNames helper for
// listing available preset names.
//
// Usage:
//
//	presets := llmpresets.GetPresets()
//	preset, err := llmpresets.GetPreset("ollama")
//	names := llmpresets.GetPresetNames()
package llmpresets
