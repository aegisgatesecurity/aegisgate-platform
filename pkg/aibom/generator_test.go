// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM generator tests (TODO-302)
//
// generator_test.go tests the BOM generator: structural
// correctness, determinism, the 5-pillar requirement, and
// the prompt/corpus hashing helpers.

package aibom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateFromAIBOM_NilAIBOM(t *testing.T) {
	if _, err := GenerateFromAIBOM(nil); err == nil {
		t.Error("nil AIBOM: expected error, got nil")
	}
}

func TestGenerateFromAIBOM_HappyPath(t *testing.T) {
	a := &AIBOM{
		DeploymentID:    "test-deploy-001",
		PlatformVersion: "3.4.0-beta.1",
		PlatformTier:    "professional",
		InstanceID:      "inst-12345",
		GeneratedAt:     time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
		GeneratorNotes:  "test snapshot",
		HTTP: HTTPComponent{
			Enabled:          true,
			TLSVersion:       "1.3",
			MutualTLSEnabled: true,
			ListenerPorts:    []int{8443, 9443},
		},
		MCP: MCPComponent{
			Enabled:                         true,
			PromptInjectionDetectionEnabled: true,
			PromptInjectionSensitivity:      75,
		},
		A2A: A2AComponent{Enabled: true, ConfigFile: "/etc/aegisgate/a2a.yaml"},
		ACP: ACPComponent{Enabled: true, ConfigFile: "/etc/aegisgate/acp.yaml", HMACAlgorithm: "SHA-256"},
		ANP: ANPComponent{Enabled: true, DefaultConfig: true},
	}
	bom, err := GenerateFromAIBOM(a)
	if err != nil {
		t.Fatalf("GenerateFromAIBOM: %v", err)
	}
	// 1. Required CycloneDX fields.
	if bom.BOMFormat != CycloneDXBOMFormat {
		t.Errorf("bomFormat: got %q, want %q", bom.BOMFormat, CycloneDXBOMFormat)
	}
	if bom.SpecVersion != CycloneDXSpecVersion {
		t.Errorf("specVersion: got %q, want %q", bom.SpecVersion, CycloneDXSpecVersion)
	}
	if bom.Version != 1 {
		t.Errorf("version: got %d, want 1", bom.Version)
	}
	if bom.SerialNumber != "urn:uuid:test-deploy-001" {
		t.Errorf("serialNumber: got %q, want urn:uuid:test-deploy-001", bom.SerialNumber)
	}
	// 2. Metadata.
	if !bom.Metadata.Timestamp.Equal(a.GeneratedAt) {
		t.Errorf("metadata.timestamp: got %v, want %v", bom.Metadata.Timestamp, a.GeneratedAt)
	}
	if len(bom.Metadata.Tools) != 1 {
		t.Errorf("metadata.tools: got %d, want 1", len(bom.Metadata.Tools))
	}
	if bom.Metadata.Component.Name != "AegisGate Security Platform" {
		t.Errorf("metadata.component.name: got %q", bom.Metadata.Component.Name)
	}
	if bom.Metadata.Component.Version != "3.4.0-beta.1" {
		t.Errorf("metadata.component.version: got %q, want 3.4.0-beta.1", bom.Metadata.Component.Version)
	}
	// 3. The 5 protocol pillars must be present.
	refs := make(map[string]bool)
	for _, c := range bom.Components {
		refs[c.BOMRef] = true
	}
	for _, want := range []string{"aegisgate-http", "aegisgate-mcp", "aegisgate-a2a", "aegisgate-acp", "aegisgate-anp"} {
		if !refs[want] {
			t.Errorf("components: missing %q", want)
		}
	}
}

func TestGenerateFromAIBOM_DefaultsApplied(t *testing.T) {
	a := &AIBOM{} // empty
	bom, err := GenerateFromAIBOM(a)
	if err != nil {
		t.Fatalf("GenerateFromAIBOM: %v", err)
	}
	// Empty AIBOM should still produce a valid BOM with
	// sensible defaults.
	if bom.SerialNumber == "" {
		t.Error("serialNumber: empty (should be auto-generated)")
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("serialNumber: got %q, want urn:uuid: prefix", bom.SerialNumber)
	}
	if bom.Metadata.Component.Version != "unknown" {
		t.Errorf("default version: got %q, want %q", bom.Metadata.Component.Version, "unknown")
	}
	// The 5 pillars should still be present (with default
	// "unknown" data).
	if len(bom.Components) < 5 {
		t.Errorf("default components: got %d, want >= 5", len(bom.Components))
	}
}

func TestGenerateFromAIBOM_ComponentsSorted(t *testing.T) {
	// Build a BOM, then verify the components are sorted
	// by bom-ref. The generator sorts them internally; this
	// test catches regressions.
	a := &AIBOM{DeploymentID: "sort-test"}
	bom, _ := GenerateFromAIBOM(a)
	for i := 1; i < len(bom.Components); i++ {
		if bom.Components[i-1].BOMRef > bom.Components[i].BOMRef {
			t.Errorf("components not sorted: [%d]=%q > [%d]=%q",
				i-1, bom.Components[i-1].BOMRef, i, bom.Components[i].BOMRef)
		}
	}
}

func TestGenerateFromAIBOM_ModelOnlyIfRegistered(t *testing.T) {
	a := &AIBOM{DeploymentID: "model-test"} // no model
	bom, _ := GenerateFromAIBOM(a)
	for _, c := range bom.Components {
		if c.BOMRef == "aegisgate-model" {
			t.Error("model component should not be present when IsRegistered=false")
		}
	}
	// Now register a model.
	a.Model = ModelComponent{
		Provider:     "openai",
		ModelID:      "gpt-4-turbo",
		Version:      "2024-04-09",
		IsRegistered: true,
	}
	bom, _ = GenerateFromAIBOM(a)
	found := false
	for _, c := range bom.Components {
		if c.BOMRef == "aegisgate-model" {
			found = true
			if c.Type != "machine-learning-model" {
				t.Errorf("model type: got %q, want machine-learning-model", c.Type)
			}
		}
	}
	if !found {
		t.Error("model component not present when IsRegistered=true")
	}
}

func TestGenerateFromAIBOM_PromptsAndCorpora(t *testing.T) {
	a := &AIBOM{
		DeploymentID: "prompts-test",
		Prompts: []PromptComponent{
			{ID: "p1", SHA256: "abc123", ByteSize: 100, Source: "prompts/system.txt"},
		},
		Corpora: []RAGCorpusComponent{
			{ID: "c1", SHA256: "def456", DocumentCount: 50, Source: "corpora/legal/"},
		},
	}
	bom, _ := GenerateFromAIBOM(a)
	promptCount := 0
	corpusCount := 0
	for _, c := range bom.Components {
		if strings.HasPrefix(c.BOMRef, "aegisgate-prompt-") {
			promptCount++
			if len(c.Hashes) != 1 || c.Hashes[0].Algorithm != "SHA-256" {
				t.Errorf("prompt hashes: %+v", c.Hashes)
			}
		}
		if strings.HasPrefix(c.BOMRef, "aegisgate-rag-") {
			corpusCount++
		}
	}
	if promptCount != 1 {
		t.Errorf("prompt components: got %d, want 1", promptCount)
	}
	if corpusCount != 1 {
		t.Errorf("corpus components: got %d, want 1", corpusCount)
	}
}

func TestGenerateFromAIBOM_DeterministicForFixedInputs(t *testing.T) {
	// Same AIBOM, different GeneratedAt -> different BOM
	// in metadata.timestamp ONLY. The other fields must be
	// identical. The signer/caller can fix the timestamp
	// (the AIBOM struct is mutable; the generator is pure
	// given fixed inputs).
	a := &AIBOM{
		DeploymentID:    "det-test",
		PlatformVersion: "3.4.0-beta.1",
		PlatformTier:    "professional",
		GeneratedAt:     time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	}
	bom1, _ := GenerateFromAIBOM(a)
	bom2, _ := GenerateFromAIBOM(a)
	if bom1.Metadata.Timestamp != bom2.Metadata.Timestamp {
		t.Errorf("timestamp changed: %v vs %v", bom1.Metadata.Timestamp, bom2.Metadata.Timestamp)
	}
	// Serial-number roundtrip: same input -> same output.
	if bom1.SerialNumber != bom2.SerialNumber {
		t.Errorf("serialNumber changed: %q vs %q", bom1.SerialNumber, bom2.SerialNumber)
	}
}

func TestGenerateFromAIBOM_JSONMarshalable(t *testing.T) {
	a := &AIBOM{DeploymentID: "json-test", PlatformVersion: "3.4.0-beta.1", PlatformTier: "professional"}
	bom, _ := GenerateFromAIBOM(a)
	bytes, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if len(bytes) < 1000 {
		t.Errorf("BOM JSON suspiciously small: %d bytes", len(bytes))
	}
	// Roundtrip: unmarshal and compare.
	var bom2 BOM
	if err := json.Unmarshal(bytes, &bom2); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if bom2.SerialNumber != bom.SerialNumber {
		t.Errorf("roundtrip serialNumber: got %q, want %q", bom2.SerialNumber, bom.SerialNumber)
	}
}

// --------------------------------------------------------------------
// HashPrompt / HashCorpus tests
// --------------------------------------------------------------------

func TestHashPrompt_Deterministic(t *testing.T) {
	h1 := HashPrompt("Hello, World!")
	h2 := HashPrompt("Hello, World!")
	if h1 != h2 {
		t.Errorf("HashPrompt: not deterministic: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("HashPrompt: len %d, want 64 (hex SHA-256)", len(h1))
	}
}

func TestHashPrompt_Normalization(t *testing.T) {
	// Different formatting should produce the same hash.
	cases := []string{
		"Hello, World!",
		"hello, world!",
		"  Hello, World!  ",
		"hello,  world!", // multiple spaces -> single
		"HELLO, WORLD!",
		"hello,\tworld!", // tab -> single space
	}
	h0 := HashPrompt(cases[0])
	for i := 1; i < len(cases); i++ {
		if got := HashPrompt(cases[i]); got != h0 {
			t.Errorf("case %d (%q): hash %s != base hash %s", i, cases[i], got, h0)
		}
	}
}

func TestHashPrompt_DifferentContent(t *testing.T) {
	h1 := HashPrompt("Hello, World!")
	h2 := HashPrompt("Hello, World?")
	if h1 == h2 {
		t.Error("HashPrompt: different content produced same hash (collision)")
	}
}

func TestHashCorpus_Deterministic(t *testing.T) {
	docs := []string{"doc1hash", "doc2hash", "doc3hash"}
	h1 := HashCorpus(docs)
	h2 := HashCorpus(docs)
	if h1 != h2 {
		t.Errorf("HashCorpus: not deterministic")
	}
}

func TestHashCorpus_OrderIndependent(t *testing.T) {
	// A corpus is a SET of documents, not a list. Order
	// should not affect the hash.
	docs := []string{"doc1hash", "doc2hash", "doc3hash"}
	reversed := []string{"doc3hash", "doc2hash", "doc1hash"}
	if HashCorpus(docs) != HashCorpus(reversed) {
		t.Error("HashCorpus: order affected the hash (corpus should be order-independent)")
	}
}

func TestHashCorpus_DifferentContent(t *testing.T) {
	h1 := HashCorpus([]string{"doc1", "doc2"})
	h2 := HashCorpus([]string{"doc1", "doc3"})
	if h1 == h2 {
		t.Error("HashCorpus: different content produced same hash")
	}
}

func TestHashCorpus_Empty(t *testing.T) {
	// An empty corpus should produce a valid SHA-256 of the
	// empty string. (No special case; the operator should
	// not register empty corpora, but if they do, we still
	// produce a valid hash.)
	h := HashCorpus(nil)
	if len(h) != 64 {
		t.Errorf("empty HashCorpus: len %d, want 64", len(h))
	}
}

func TestNormalizePrompt(t *testing.T) {
	cases := map[string]string{
		"Hello, World!":     "hello, world!",
		"  Hello, World!  ": "hello, world!",
		"hello,  world!":    "hello, world!",
		"HELLO, WORLD!":     "hello, world!",
		"hello,\nworld!":    "hello, world!",
		"hello,\tworld!":    "hello, world!",
		"":                  "",
		"   ":               "",
		"single":            "single",
	}
	for input, want := range cases {
		if got := normalizePrompt(input); got != want {
			t.Errorf("normalizePrompt(%q): got %q, want %q", input, got, want)
		}
	}
}

// --------------------------------------------------------------------
// boolToString test (kept internal; the helper is unexported)
// --------------------------------------------------------------------

func TestBoolToString(t *testing.T) {
	if got := boolToString(true); got != "true" {
		t.Errorf("boolToString(true): got %q, want %q", got, "true")
	}
	if got := boolToString(false); got != "false" {
		t.Errorf("boolToString(false): got %q, want %q", got, "false")
	}
}

// --------------------------------------------------------------------
// GenerateFromConfig (the convenience wrapper)
// --------------------------------------------------------------------

func TestGenerateFromConfig_Basic(t *testing.T) {
	bom, err := GenerateFromConfig(nil,
		WithTier("professional"),
		WithPlatformVersion("3.4.0-beta.1"),
		WithInstanceID("test-inst"),
		WithGeneratorNotes("test run"),
	)
	if err != nil {
		t.Fatalf("GenerateFromConfig: %v", err)
	}
	if bom == nil {
		t.Fatal("BOM is nil")
	}
	if bom.Metadata.Component.Version != "3.4.0-beta.1" {
		t.Errorf("version: got %q, want 3.4.0-beta.1", bom.Metadata.Component.Version)
	}
	// Tier should appear in the metadata component properties.
	found := false
	for _, p := range bom.Metadata.Component.Properties {
		if p.Name == "aegisgate:platform_tier" && p.Value == "professional" {
			found = true
		}
	}
	if !found {
		t.Errorf("platform_tier property not found in: %+v", bom.Metadata.Component.Properties)
	}
}

func TestGenerateFromConfig_WithPromptsAndCorpora(t *testing.T) {
	prompts := []PromptComponent{
		{ID: "p1", SHA256: "abc", ByteSize: 10, Source: "src1"},
	}
	corpora := []RAGCorpusComponent{
		{ID: "c1", SHA256: "def", DocumentCount: 5, Source: "src2"},
	}
	bom, _ := GenerateFromConfig(nil,
		WithPrompts(prompts),
		WithCorpora(corpora),
	)
	promptCount := 0
	corpusCount := 0
	for _, c := range bom.Components {
		if strings.HasPrefix(c.BOMRef, "aegisgate-prompt-") {
			promptCount++
		}
		if strings.HasPrefix(c.BOMRef, "aegisgate-rag-") {
			corpusCount++
		}
	}
	if promptCount != 1 || corpusCount != 1 {
		t.Errorf("counts: prompts=%d (want 1), corpora=%d (want 1)", promptCount, corpusCount)
	}
}

func TestGenerateFromConfig_WithModel(t *testing.T) {
	m := ModelComponent{Provider: "anthropic", ModelID: "claude-opus-4", Version: "20250514", IsRegistered: true}
	bom, _ := GenerateFromConfig(nil, WithModel(m))
	found := false
	for _, c := range bom.Components {
		if c.BOMRef == "aegisgate-model" {
			found = true
		}
	}
	if !found {
		t.Error("model component not present")
	}
}

// --------------------------------------------------------------------
// applyConfigOptions tests
// --------------------------------------------------------------------

func TestApplyConfigOptions_Empty(t *testing.T) {
	o := applyConfigOptions(nil)
	if o.tier != "" || o.platformVer != "" || o.instanceID != "" {
		t.Errorf("empty options: %+v", o)
	}
}

func TestApplyConfigOptions_Override(t *testing.T) {
	o := applyConfigOptions([]ConfigGeneratorOption{
		WithTier("tier1"),
		WithPlatformVersion("v1"),
		WithInstanceID("id1"),
		WithGeneratorNotes("n1"),
	})
	if o.tier != "tier1" || o.platformVer != "v1" || o.instanceID != "id1" || o.generatorNotes != "n1" {
		t.Errorf("options: %+v", o)
	}
}

// --------------------------------------------------------------------
// Property ordering (determinism)
// --------------------------------------------------------------------

func TestPropertiesAreSortedByName(t *testing.T) {
	a := &AIBOM{
		DeploymentID:    "sort-props",
		PlatformVersion: "3.4.0-beta.1",
		PlatformTier:    "professional",
		InstanceID:      "inst-123",
		GeneratorNotes:  "notes",
	}
	bom, _ := GenerateFromAIBOM(a)
	checkSorted := func(props []Property, where string) {
		for i := 1; i < len(props); i++ {
			if props[i-1].Name > props[i].Name {
				t.Errorf("%s: properties not sorted: [%d]=%q > [%d]=%q",
					where, i-1, props[i-1].Name, i, props[i].Name)
			}
		}
	}
	checkSorted(bom.Metadata.Properties, "metadata.properties")
	checkSorted(bom.Metadata.Component.Properties, "metadata.component.properties")
	checkSorted(bom.Properties, "properties")
	for _, c := range bom.Components {
		checkSorted(c.Properties, "component["+c.BOMRef+"].properties")
	}
}
