// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM component builder coverage (D24, audit P2 #10)
//
// coverage_test.go constructs full AIBOMs with all 5 protocol
// pillar fields populated, plus the model and RAG corpora, to
// drive coverage of the build*Component helpers in generator.go
// from 86.8% to 95%+. The build* functions are unexported, so
// they are exercised indirectly via GenerateFromAIBOM.

package aibom

import (
	"encoding/json"
	"testing"
	"time"
)

// TestGenerateFromAIBOM_AllPillarsPopulated covers the full
// AIBOM happy path with all 5 protocol pillars (HTTP, MCP,
// A2A, ACP, ANP) populated, plus a model, prompt, and RAG
// corpus. This drives coverage of buildHTTPComponent (94%),
// buildMCPComponent (54.5%), buildA2AComponent (61.5%),
// buildACPComponent (69.2%), and buildANPComponent (55.6%).
func TestGenerateFromAIBOM_AllPillarsPopulated(t *testing.T) {
	a := &AIBOM{
		DeploymentID:    "test-deploy-full",
		PlatformVersion: "3.4.0-beta.1",
		PlatformTier:    "professional",
		InstanceID:      "inst-test-full",
		GeneratedAt:     time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		GeneratorNotes:  "D24 coverage test: all pillars populated",
		HTTP: HTTPComponent{
			Enabled:          true,
			TLSVersion:       "1.3",
			MutualTLSEnabled: true,
			CipherSuites:     []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
			ListenerPorts:    []int{8080, 8443, 9443},
		},
		MCP: MCPComponent{
			Enabled:                         true,
			PromptInjectionDetectionEnabled: true,
			PromptInjectionSensitivity:      80,
			ServerCount:                     3,
			GuardrailConfigFile:             "/etc/aegisgate/mcp.yaml",
			ServerNames:                     []string{"github", "filesystem", "web"},
		},
		A2A: A2AComponent{
			Enabled:    true,
			AgentCount: 2,
			ConfigFile: "/etc/aegisgate/a2a.yaml",
			CapsFile:   "/etc/aegisgate/a2a_caps.json",
			AgentNames: []string{"agent-alpha", "agent-beta"},
		},
		ACP: ACPComponent{
			Enabled:         true,
			CapabilityCount: 5,
			ConfigFile:      "/etc/aegisgate/acp.yaml",
			HMACAlgorithm:   "SHA-256",
			CapabilityNames: []string{"cap-1", "cap-2", "cap-3", "cap-4", "cap-5"},
		},
		ANP: ANPComponent{
			Enabled:       true,
			TaskCount:     2,
			DefaultConfig: true,
			TaskNames:     []string{"task-foo", "task-bar"},
		},
		Model: ModelComponent{
			Provider: "openai",
			ModelID:  "gpt-4o",
			Version:  "2024-08-06",
		},
		Prompts: []PromptComponent{
			{
				ID: "prompt-1", SHA256: "abc123",
				Source:   "system",
				ByteSize: 142,
			},
		},
		Corpora: []RAGCorpusComponent{
			{
				ID: "corpus-1", SHA256: "def456",
				Source:        "rag-corpus",
				DocumentCount: 42,
			},
		},
	}
	bom, err := GenerateFromAIBOM(a)
	if err != nil {
		t.Fatalf("GenerateFromAIBOM: %v", err)
	}

	// Verify all 5 pillars + metadata + model + prompts + corpora
	// produce a valid JSON.
	if bom == nil {
		t.Fatal("BOM is nil")
	}
	// JSON round-trip to verify serializability.
	if _, err := json.Marshal(bom); err != nil {
		t.Errorf("BOM is not JSON-serializable: %v", err)
	}
}

// TestGenerateFromAIBOM_EmptyAIBOM covers the empty/zero-value
// AIBOM path (the v0.1 "always skipped" path where most fields
// are zero). This exercises the default-zero branches in
// buildHTTPComponent and others.
func TestGenerateFromAIBOM_EmptyAIBOM(t *testing.T) {
	a := &AIBOM{
		DeploymentID: "test-empty",
	}
	_, err := GenerateFromAIBOM(a)
	if err != nil {
		t.Errorf("GenerateFromAIBOM on empty AIBOM: %v", err)
	}
}
