// SPDX-License-Identifier: Apache-2.0
// Test stub for provenance.go (P3: AIBOM Model Provenance)

package aibom

import (
	"encoding/json"
	"testing"
	"time"
)

func validModelMeta() ModelProvenance {
	return ModelProvenance{
		ModelName:         "aegisgate-l3",
		ModelVersion:      "v11b",
		ModelFormat:       "onnx",
		ModelParamCount:   1596034,
		TrainingDataset:   "aegisgate-prompt-corpus-v3",
		TrainingFramework: "PyTorch 2.4.0",
		TrainingStartDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		TrainingEndDate:   time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		Hyperparameters:   map[string]any{"lr": 0.001, "epochs": 50},
		EvalMetrics:       map[string]float64{"accuracy": 98.27, "f1": 0.98},
	}
}

func TestNewProvenanceRecorder(t *testing.T) {
	pr := NewProvenanceRecorder()
	if pr == nil {
		t.Fatal("NewProvenanceRecorder returned nil")
	}
}

func TestRecordModel_Success(t *testing.T) {
	pr := NewProvenanceRecorder()
	modelBytes := []byte("fake model bytes")
	meta := validModelMeta()

	err := pr.RecordModel(modelBytes, meta)
	if err != nil {
		t.Fatalf("RecordModel failed: %v", err)
	}

	rec, ok := pr.GetProvenance("aegisgate-l3", "v11b")
	if !ok {
		t.Fatal("provenance not found after recording")
	}
	if rec.ModelHash == "" {
		t.Error("modelHash should be computed")
	}
	if rec.ModelSizeBytes != int64(len(modelBytes)) {
		t.Errorf("expected size=%d, got %d", len(modelBytes), rec.ModelSizeBytes)
	}
}

func TestRecordModel_MissingName(t *testing.T) {
	pr := NewProvenanceRecorder()
	meta := validModelMeta()
	meta.ModelName = ""
	err := pr.RecordModel([]byte("x"), meta)
	if err == nil {
		t.Error("expected error for missing name")
	}
}

func TestRecordModel_MissingVersion(t *testing.T) {
	pr := NewProvenanceRecorder()
	meta := validModelMeta()
	meta.ModelVersion = ""
	err := pr.RecordModel([]byte("x"), meta)
	if err == nil {
		t.Error("expected error for missing version")
	}
}

func TestGetProvenance_NotFound(t *testing.T) {
	pr := NewProvenanceRecorder()
	_, ok := pr.GetProvenance("unknown", "v0")
	if ok {
		t.Error("expected not found for unknown model")
	}
}

func TestListProvenance(t *testing.T) {
	pr := NewProvenanceRecorder()
	meta := validModelMeta()
	_ = pr.RecordModel([]byte("bytes1"), meta)
	meta.ModelName = "aegisgate-l1"
	_ = pr.RecordModel([]byte("bytes2"), meta)

	list := pr.ListProvenance()
	if len(list) != 2 {
		t.Errorf("expected 2 records, got %d", len(list))
	}
}

func TestValidateProvenance_Complete(t *testing.T) {
	pr := NewProvenanceRecorder()
	meta := validModelMeta()
	_ = pr.RecordModel([]byte("bytes"), meta)

	issues := pr.ValidateProvenance("aegisgate-l3", "v11b")
	if len(issues) != 0 {
		t.Errorf("expected no issues, got: %v", issues)
	}
}

func TestValidateProvenance_MissingFields(t *testing.T) {
	pr := NewProvenanceRecorder()
	meta := ModelProvenance{
		ModelName:    "incomplete",
		ModelVersion: "v1",
		// everything else empty
	}
	_ = pr.RecordModel([]byte("bytes"), meta)

	issues := pr.ValidateProvenance("incomplete", "v1")
	if len(issues) == 0 {
		t.Error("expected validation issues for incomplete record")
	}
}

func TestValidateProvenance_NotFound(t *testing.T) {
	pr := NewProvenanceRecorder()
	issues := pr.ValidateProvenance("missing", "v0")
	if len(issues) != 1 || issues[0] != "record not found" {
		t.Errorf("expected 'record not found', got: %v", issues)
	}
}

func TestToJSON_Success(t *testing.T) {
	pr := NewProvenanceRecorder()
	meta := validModelMeta()
	_ = pr.RecordModel([]byte("bytes"), meta)

	data, err := pr.ToJSON("aegisgate-l3", "v11b")
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var parsed ModelProvenance
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if parsed.ModelName != "aegisgate-l3" {
		t.Errorf("expected model name aegisgate-l3, got %s", parsed.ModelName)
	}
}

func TestToJSON_NotFound(t *testing.T) {
	pr := NewProvenanceRecorder()
	_, err := pr.ToJSON("missing", "v0")
	if err == nil {
		t.Error("expected error for missing model")
	}
}

func TestRecordModel_HashDeterministic(t *testing.T) {
	pr := NewProvenanceRecorder()
	modelBytes := []byte("same bytes")
	meta := validModelMeta()
	_ = pr.RecordModel(modelBytes, meta)
	rec1, _ := pr.GetProvenance("aegisgate-l3", "v11b")

	pr2 := NewProvenanceRecorder()
	_ = pr2.RecordModel(modelBytes, meta)
	rec2, _ := pr2.GetProvenance("aegisgate-l3", "v11b")

	if rec1.ModelHash != rec2.ModelHash {
		t.Error("hash should be deterministic for same bytes")
	}
}
