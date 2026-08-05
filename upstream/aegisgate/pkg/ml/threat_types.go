// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Threat Detection Types
// =========================================================================
//
// Core types for the Char CNN-BiLSTM threat detector. These types define
// the interface between the ONNX model and the proxy pipeline.
//
// =========================================================================

package ml

// ThreatScore represents the output of the neural network threat detector.
type ThreatScore struct {
	// Score is the raw sigmoid output from the model [0, 1].
	// Higher = more likely adversarial.
	Score float64

	// IsThreat is true if Score >= calibrated threshold.
	IsThreat bool

	// Threshold is the calibrated zero-FPR threshold.
	Threshold float64

	// Variant is the normalization variant that triggered detection,
	// or "original" if unmodified text was detected.
	Variant string

	// ModelVersion is the version/sha256 of the ONNX model used.
	ModelVersion string
}

// DetectorConfig holds configuration for the neural network detector.
type DetectorConfig struct {
	// Enabled controls whether the ML detector is active.
	// When false, Detect() always returns ThreatScore{Score: 0, IsThreat: false}.
	Enabled bool

	// ShadowMode when true logs predictions but never blocks.
	// Use for 7-day calibration period before enabling.
	ShadowMode bool

	// Threshold is the score above which content is classified as adversarial.
	// Calibrated from benign corpus to achieve 0% FPR.
	// Default: 0.7 (override after calibration)
	Threshold float64

	// ModelPath is the path to the ONNX model file.
	// Default: "pkg/ml/models/threat_cnn_bilstm.onnx"
	ModelPath string

	// MaxSequenceLength is the maximum number of characters to feed the model.
	// Longer sequences are truncated. Default: 128.
	MaxSequenceLength int

	// Timeout is the maximum time for a single inference in milliseconds.
	// Default: 10ms.
	Timeout int
}

// DefaultDetectorConfig returns sensible defaults.
func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		Enabled:           false, // Disabled by default — cold-start safety
		ShadowMode:        true,  // Shadow mode on by default
		Threshold:         0.7,   // Will be calibrated
		ModelPath:         "/opt/aegisgate-platform/models/threat_cnn_bilstm.onnx",
		MaxSequenceLength: 128,
		Timeout:           10,
	}
}

// ShadowLogEntry records a shadow-mode prediction for offline analysis.
type ShadowLogEntry struct {
	Timestamp    string  `json:"timestamp"`
	InputHash    string  `json:"input_hash"` // SHA256 of input (for dedup)
	Score        float64 `json:"score"`
	Threshold    float64 `json:"threshold"`
	IsThreat     bool    `json:"is_threat"`
	Variant      string  `json:"variant"`
	ModelVersion string  `json:"model_version"`
	InputLength  int     `json:"input_length"`
}

// CalibrationResult holds the result of a calibration run.
type CalibrationResult struct {
	// Threshold is the calibrated zero-FPR threshold.
	Threshold float64 `json:"threshold"`

	// MaxBenignScore is the highest score on the benign corpus.
	MaxBenignScore float64 `json:"max_benign_score"`

	// Margin is the buffer above max benign score.
	Margin float64 `json:"margin"`

	// BenignSamples is the number of benign samples tested.
	BenignSamples int `json:"benign_samples"`

	// FalsePositives is the number of benign samples above threshold.
	FalsePositives int `json:"false_positives"`

	// FPR is the false positive rate on the benign corpus.
	FPR float64 `json:"fpr"`

	// Timestamp of the calibration run.
	Timestamp string `json:"timestamp"`

	// ModelVersion used for calibration.
	ModelVersion string `json:"model_version"`
}
