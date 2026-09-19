// SPDX-License-Identifier: Apache-2.0
// Integration tests for P3: AIBOM Model Provenance enrichment.
// Verifies that provenance metadata flows through the generator
// and appears as CycloneDX properties on the model component.

package aibom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateFromAIBOM_ProvenanceEnrichesModelComponent(t *testing.T) {
	prov := &ModelProvenance{
		ModelName:         "aegisgate-l3",
		ModelVersion:      "v11b",
		ModelFormat:       "onnx",
		ModelSizeBytes:    31522978,
		ModelParamCount:   1596034,
		ModelHash:         "abc123def456", // pre-set hash for direct test
		TrainingDataset:   "aegisgate-prompt-corpus-v3",
		TrainingFramework: "PyTorch 2.4.0",
		TrainingStartDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		TrainingEndDate:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		Hyperparameters:   map[string]any{"lr": 0.001, "epochs": 50},
		EvalMetrics:       map[string]float64{"accuracy": 98.27, "f1": 0.98},
		ConversionTool:    "onnxexport 1.16.0",
		ConversionSource:  "pytorch",
		SignedBy:          "security@aegisgatesecurity.io",
	}

	a := &AIBOM{
		DeploymentID:    "test-deployment-prov",
		PlatformVersion: "4.5.0",
		PlatformTier:    "community",
		GeneratedAt:     time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
		Model: ModelComponent{
			Provider:     "self-hosted",
			ModelID:      "aegisgate-l3",
			Version:      "v11b",
			IsRegistered: true,
		},
		Provenance: prov,
	}

	bom, err := GenerateFromAIBOM(a)
	if err != nil {
		t.Fatalf("GenerateFromAIBOM failed: %v", err)
	}

	// Find the model component
	var modelComp *Component
	for i := range bom.Components {
		if bom.Components[i].BOMRef == "aegisgate-model" {
			modelComp = &bom.Components[i]
			break
		}
	}
	if modelComp == nil {
		t.Fatal("model component not found in BOM")
	}

	// Verify provenance properties exist
	propMap := make(map[string]string)
	for _, p := range modelComp.Properties {
		propMap[p.Name] = p.Value
	}

	checks := map[string]string{
		"aegisgate:model_format":       "onnx",
		"aegisgate:training_dataset":   "aegisgate-prompt-corpus-v3",
		"aegisgate:training_framework": "PyTorch 2.4.0",
		"aegisgate:conversion_tool":    "onnxexport 1.16.0",
		"aegisgate:signed_by":          "security@aegisgatesecurity.io",
		"aegisgate:eval_accuracy":      "98.2700",
		"aegisgate:hyperparam_lr":      "0.001",
	}
	for name, want := range checks {
		got, ok := propMap[name]
		if !ok {
			t.Errorf("missing provenance property %s", name)
		} else if got != want {
			t.Errorf("property %s = %q, want %q", name, got, want)
		}
	}

	// Verify hash is present
	if len(modelComp.Hashes) != 1 {
		t.Errorf("expected 1 hash, got %d", len(modelComp.Hashes))
	} else if modelComp.Hashes[0].Algorithm != "SHA-256" {
		t.Errorf("expected SHA-256 hash, got %s", modelComp.Hashes[0].Algorithm)
	}
}

func TestGenerateFromAIBOM_ProvenanceNil_UsesBasicModelComponent(t *testing.T) {
	a := &AIBOM{
		DeploymentID:    "test-deployment-noprov",
		PlatformVersion: "4.5.0",
		PlatformTier:    "community",
		GeneratedAt:     time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
		Model: ModelComponent{
			Provider:     "openai",
			ModelID:      "gpt-4",
			Version:      "turbo",
			IsRegistered: true,
		},
		Provenance: nil,
	}

	bom, err := GenerateFromAIBOM(a)
	if err != nil {
		t.Fatalf("GenerateFromAIBOM failed: %v", err)
	}

	var modelComp *Component
	for i := range bom.Components {
		if bom.Components[i].BOMRef == "aegisgate-model" {
			modelComp = &bom.Components[i]
			break
		}
	}
	if modelComp == nil {
		t.Fatal("model component not found")
	}

	// Should NOT have provenance properties
	for _, p := range modelComp.Properties {
		if strings.HasPrefix(p.Name, "aegisgate:training_") || strings.HasPrefix(p.Name, "aegisgate:eval_") {
			t.Errorf("provenance property %s should not exist when Provenance is nil", p.Name)
		}
	}
}

func TestGenerateFromAIBOM_ProvenanceJSONRoundtrip(t *testing.T) {
	prov := &ModelProvenance{
		ModelName:       "test-model",
		ModelVersion:    "v1",
		ModelFormat:     "onnx",
		ModelSizeBytes:  1024,
		ModelParamCount: 1000,
		ModelHash:       "abc123",
		TrainingDataset: "test-dataset",
	}

	a := &AIBOM{
		DeploymentID:    "test-json-roundtrip",
		PlatformVersion: "4.5.0",
		PlatformTier:    "community",
		GeneratedAt:     time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC),
		Model: ModelComponent{
			Provider:     "self-hosted",
			ModelID:      "test-model",
			Version:      "v1",
			IsRegistered: true,
		},
		Provenance: prov,
	}

	bom, err := GenerateFromAIBOM(a)
	if err != nil {
		t.Fatalf("GenerateFromAIBOM failed: %v", err)
	}

	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed BOM
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Verify model component survived roundtrip
	found := false
	for _, c := range parsed.Components {
		if c.BOMRef == "aegisgate-model" {
			found = true
			// Check provenance properties survived
			hasTrainingDataset := false
			for _, p := range c.Properties {
				if p.Name == "aegisgate:training_dataset" && p.Value == "test-dataset" {
					hasTrainingDataset = true
				}
			}
			if !hasTrainingDataset {
				t.Error("training_dataset property not found after JSON roundtrip")
			}
		}
	}
	if !found {
		t.Fatal("model component not found after JSON roundtrip")
	}
}

func TestBuildAIBOMFromOptions_WithProvenance(t *testing.T) {
	prov := &ModelProvenance{
		ModelName:       "opt-model",
		ModelVersion:    "v2",
		ModelFormat:     "onnx",
		ModelSizeBytes:  2048,
		ModelParamCount: 2000,
		TrainingDataset: "opt-dataset",
	}

	a := BuildAIBOMFromOptions(AIBOMOptions{
		Tier:            "enterprise",
		PlatformVersion: "4.5.0",
		Model: ModelComponent{
			Provider:     "self-hosted",
			ModelID:      "opt-model",
			Version:      "v2",
			IsRegistered: true,
		},
		Provenance: prov,
	})

	if a.Provenance == nil {
		t.Fatal("Provenance should be set from options")
	}
	if a.Provenance.ModelName != "opt-model" {
		t.Errorf("expected opt-model, got %s", a.Provenance.ModelName)
	}
}

func TestProvenanceRecorder_IntegrationWithGenerator(t *testing.T) {
	pr := NewProvenanceRecorder()
	modelBytes := []byte("fake model bytes for integration test")
	meta := validModelMeta()

	err := pr.RecordModel(modelBytes, meta)
	if err != nil {
		t.Fatalf("RecordModel failed: %v", err)
	}

	// Validate provenance is complete
	issues := pr.ValidateProvenance("aegisgate-l3", "v11b")
	if len(issues) != 0 {
		t.Fatalf("provenance validation failed: %v", issues)
	}

	// Get provenance and build AIBOM with it
	prov, ok := pr.GetProvenance("aegisgate-l3", "v11b")
	if !ok {
		t.Fatal("provenance not found")
	}

	a := BuildAIBOMFromOptions(AIBOMOptions{
		Tier:            "community",
		PlatformVersion: "4.5.0",
		Model: ModelComponent{
			Provider:     "self-hosted",
			ModelID:      "aegisgate-l3",
			Version:      "v11b",
			IsRegistered: true,
		},
		Provenance: prov,
	})

	bom, err := GenerateFromAIBOM(a)
	if err != nil {
		t.Fatalf("GenerateFromAIBOM failed: %v", err)
	}

	// Verify model component has the hash from the recorder
	var modelComp *Component
	for i := range bom.Components {
		if bom.Components[i].BOMRef == "aegisgate-model" {
			modelComp = &bom.Components[i]
			break
		}
	}
	if modelComp == nil {
		t.Fatal("model component not found")
	}

	if len(modelComp.Hashes) != 1 || modelComp.Hashes[0].Content == "" {
		t.Error("model component should have non-empty SHA-256 hash from provenance")
	}
}
