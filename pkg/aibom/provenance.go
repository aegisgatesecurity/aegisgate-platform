// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM Model Provenance (v4.5.0 Enhancement P3)
//
// provenance.go tracks and records model provenance metadata for the AIBOM.
// It captures the full lineage of ML models used in the platform:
//   - Model hash (SHA-256 of model bytes)
//   - Training dataset references
//   - Training framework + version
//   - Training hyperparameters
//   - Evaluation metrics snapshot
//   - Conversion toolchain (e.g., PyTorch → ONNX)
//   - Signature chain (who signed, when, with what key)
//
// This data is attached to the AIBOM at generation time and becomes
// part of the CycloneDX component metadata for the ML model component.

package aibom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// ModelProvenance captures the full lineage metadata for a single ML model.
type ModelProvenance struct {
	ModelName       string `json:"modelName"`
	ModelVersion    string `json:"modelVersion"`
	ModelHash       string `json:"modelHash"`   // SHA-256 of model bytes
	ModelFormat     string `json:"modelFormat"` // "onnx", "pytorch", "tensorflow"
	ModelSizeBytes  int64  `json:"modelSizeBytes"`
	ModelParamCount int64  `json:"modelParamCount"`

	// Training provenance
	TrainingDataset   string         `json:"trainingDataset"`   // dataset name/version
	TrainingFramework string         `json:"trainingFramework"` // e.g., "PyTorch 2.4.0"
	TrainingStartDate time.Time      `json:"trainingStartDate"`
	TrainingEndDate   time.Time      `json:"trainingEndDate"`
	Hyperparameters   map[string]any `json:"hyperparameters"`

	// Evaluation snapshot at training completion
	EvalMetrics map[string]float64 `json:"evalMetrics"`

	// Conversion toolchain (if model was converted)
	ConversionTool   string `json:"conversionTool,omitempty"`   // e.g., "onnxexport 1.16.0"
	ConversionSource string `json:"conversionSource,omitempty"` // original format

	// Signature chain
	SigningKey string    `json:"signingKey,omitempty"`
	SignedAt   time.Time `json:"signedAt,omitempty"`
	SignedBy   string    `json:"signedBy,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ProvenanceRecorder builds and validates ModelProvenance records.
type ProvenanceRecorder struct {
	records map[string]*ModelProvenance // keyed by ModelName:ModelVersion
}

// NewProvenanceRecorder creates a new ProvenanceRecorder.
func NewProvenanceRecorder() *ProvenanceRecorder {
	return &ProvenanceRecorder{
		records: make(map[string]*ModelProvenance),
	}
}

// RecordModel computes the model hash and stores provenance metadata.
func (pr *ProvenanceRecorder) RecordModel(modelBytes []byte, meta ModelProvenance) error {
	if meta.ModelName == "" {
		return fmt.Errorf("modelName is required")
	}
	if meta.ModelVersion == "" {
		return fmt.Errorf("modelVersion is required")
	}

	hash := sha256.Sum256(modelBytes)
	meta.ModelHash = hex.EncodeToString(hash[:])
	meta.ModelSizeBytes = int64(len(modelBytes))
	now := time.Now()
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = now
	}
	meta.UpdatedAt = now

	key := pr.key(meta.ModelName, meta.ModelVersion)
	pr.records[key] = &meta

	return nil
}

// GetProvenance retrieves the provenance record for a model.
func (pr *ProvenanceRecorder) GetProvenance(modelName, modelVersion string) (*ModelProvenance, bool) {
	key := pr.key(modelName, modelVersion)
	rec, ok := pr.records[key]
	return rec, ok
}

// ListProvenance returns all recorded model provenance entries.
func (pr *ProvenanceRecorder) ListProvenance() []*ModelProvenance {
	list := make([]*ModelProvenance, 0, len(pr.records))
	for _, rec := range pr.records {
		list = append(list, rec)
	}
	return list
}

// ValidateProvenance checks a provenance record for completeness.
// Returns a list of missing or invalid fields.
func (pr *ProvenanceRecorder) ValidateProvenance(modelName, modelVersion string) []string {
	key := pr.key(modelName, modelVersion)
	rec, ok := pr.records[key]
	if !ok {
		return []string{"record not found"}
	}

	var issues []string
	if rec.ModelHash == "" {
		issues = append(issues, "modelHash is empty")
	}
	if rec.TrainingDataset == "" {
		issues = append(issues, "trainingDataset is empty")
	}
	if rec.TrainingFramework == "" {
		issues = append(issues, "trainingFramework is empty")
	}
	if rec.ModelFormat == "" {
		issues = append(issues, "modelFormat is empty")
	}
	if rec.ModelSizeBytes <= 0 {
		issues = append(issues, "modelSizeBytes must be positive")
	}
	if rec.ModelParamCount <= 0 {
		issues = append(issues, "modelParamCount must be positive")
	}

	return issues
}

// ToJSON serializes a model's provenance to JSON.
func (pr *ProvenanceRecorder) ToJSON(modelName, modelVersion string) ([]byte, error) {
	rec, ok := pr.GetProvenance(modelName, modelVersion)
	if !ok {
		return nil, fmt.Errorf("provenance not found for %s:%s", modelName, modelVersion)
	}
	return json.MarshalIndent(rec, "", "  ")
}

// key generates a unique key for a model record.
func (pr *ProvenanceRecorder) key(name, version string) string {
	return name + ":" + version
}
