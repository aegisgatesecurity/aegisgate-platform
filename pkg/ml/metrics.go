// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Shadow Mode Metrics HTTP Handler
// =========================================================================
//
// metrics.go exposes an HTTP endpoint (GET /api/v1/ml/metrics) that returns
// the current shadow-mode performance metrics of the ML threat detector.
// The endpoint is only available when AEGIS_ML_SHADOW_MODE is enabled (the
// default); requests return 404 when shadow mode is disabled.
//
// Response includes:
//   - Total shadow predictions processed
//   - Current precision / recall / F1 / AUROC
//   - Confusion matrix (TP / TN / FP / FN)
//   - Calibration threshold
//   - Model version
//   - Timestamp
//
// Pattern matches pkg/compliance/api.go (raw net/http, ServeHTTP, JSON).
// =========================================================================

package ml

import (
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// MetricsHandler serves GET /api/v1/ml/metrics. It exposes the current
// shadow-mode ML performance metrics as JSON. The handler checks
// AEGIS_ML_SHADOW_MODE and returns 404 when shadow mode is disabled.
type MetricsHandler struct {
	calibrator *CalibrationManager
}

// NewMetricsHandler creates a new metrics handler backed by the given
// CalibrationManager. The calibrator must not be nil.
func NewMetricsHandler(cm *CalibrationManager) *MetricsHandler {
	return &MetricsHandler{calibrator: cm}
}

// metricsResponse is the JSON envelope returned by the metrics endpoint.
type metricsResponse struct {
	ShadowModeEnabled bool         `json:"shadow_mode_enabled"`
	TotalPredictions  int          `json:"total_predictions"`
	Precision         float64      `json:"precision"`
	Recall            float64      `json:"recall"`
	F1Score           float64      `json:"f1_score"`
	AUROC             float64      `json:"auroc"`
	ConfusionMatrix   confusionRow `json:"confusion_matrix"`
	Threshold         float64      `json:"threshold"`
	ModelVersion      string       `json:"model_version"`
	Timestamp         string       `json:"timestamp"`
}

// confusionRow represents the 2×2 confusion matrix in a flat structure.
type confusionRow struct {
	TruePositives  int `json:"true_positives"`
	TrueNegatives  int `json:"true_negatives"`
	FalsePositives int `json:"false_positives"`
	FalseNegatives int `json:"false_negatives"`
}

// ServeHTTP implements http.Handler. Only GET is allowed; the endpoint
// returns 404 when AEGIS_ML_SHADOW_MODE is not set to "true".
func (h *MetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Only expose metrics when shadow mode is enabled.
	if !isShadowModeEnabled() {
		http.NotFound(w, r)
		return
	}

	if h.calibrator == nil {
		writeMetricsError(w, http.StatusInternalServerError, "metrics handler not configured (calibrator nil)")
		return
	}

	m := h.calibrator.GetRunningMetrics()

	resp := metricsResponse{
		ShadowModeEnabled: true,
		TotalPredictions:  m.TotalPredictions,
		Precision:         m.Precision,
		Recall:            m.Recall,
		F1Score:           m.F1Score,
		AUROC:             m.AUROC,
		ConfusionMatrix: confusionRow{
			TruePositives:  m.TruePositives,
			TrueNegatives:  m.TrueNegatives,
			FalsePositives: m.FalsePositives,
			FalseNegatives: m.FalseNegatives,
		},
		Threshold:    m.Threshold,
		ModelVersion: m.ModelVersion,
		Timestamp:    m.Timestamp.UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// isShadowModeEnabled checks the AEGIS_ML_SHADOW_MODE environment variable.
// Returns true when set to "true" (case-insensitive) or when the variable is
// unset (default-on). Returns false only when explicitly set to "false".
func isShadowModeEnabled() bool {
	v := os.Getenv("AEGIS_ML_SHADOW_MODE")
	if v == "" {
		return true // default: shadow mode on
	}
	return v != "false"
}

// RegisterMetricsRoute registers the /api/v1/ml/metrics handler on the
// given mux. The route respects the AEGIS_ML_SHADOW_MODE gate.
func RegisterMetricsRoute(mux *http.ServeMux, cm *CalibrationManager) {
	handler := NewMetricsHandler(cm)
	mux.Handle("/api/v1/ml/metrics", handler)
}

// writeMetricsError writes a JSON error response.
func writeMetricsError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   http.StatusText(status),
		"message": message,
		"status":  status,
	})
}
