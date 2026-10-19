// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =========================================================================
// calibration.go — IsEnabled, SetEnabled, IsShadowMode, SetShadowMode, sortFloat64s
// =========================================================================

func TestPhase5_CalibrationManager_IsEnabled_SetEnabled(t *testing.T) {
	cm := NewCalibrationManager(DetectorConfig{})

	// Default should be false
	if cm.IsEnabled() {
		t.Error("expected IsEnabled() to be false by default")
	}

	// Enable
	cm.SetEnabled(true)
	if !cm.IsEnabled() {
		t.Error("expected IsEnabled() to be true after SetEnabled(true)")
	}

	// Disable
	cm.SetEnabled(false)
	if cm.IsEnabled() {
		t.Error("expected IsEnabled() to be false after SetEnabled(false)")
	}
}

func TestPhase5_CalibrationManager_IsShadowMode_SetShadowMode(t *testing.T) {
	cm := NewCalibrationManager(DetectorConfig{})

	// Default should be false
	if cm.IsShadowMode() {
		t.Error("expected IsShadowMode() to be false by default")
	}

	// Enable shadow mode
	cm.SetShadowMode(true)
	if !cm.IsShadowMode() {
		t.Error("expected IsShadowMode() to be true after SetShadowMode(true)")
	}

	// Disable shadow mode
	cm.SetShadowMode(false)
	if cm.IsShadowMode() {
		t.Error("expected IsShadowMode() to be false after SetShadowMode(false)")
	}
}

func TestPhase5_SortFloat64s(t *testing.T) {
	tests := []struct {
		name  string
		input []float64
		want  []float64
	}{
		{"empty", []float64{}, []float64{}},
		{"single", []float64{3.14}, []float64{3.14}},
		{"sorted", []float64{1.0, 2.0, 3.0}, []float64{1.0, 2.0, 3.0}},
		{"reverse", []float64{3.0, 2.0, 1.0}, []float64{1.0, 2.0, 3.0}},
		{"duplicates", []float64{2.0, 1.0, 2.0, 1.0}, []float64{1.0, 1.0, 2.0, 2.0}},
		{"negatives", []float64{-1.0, 0.0, -2.0, 3.0}, []float64{-2.0, -1.0, 0.0, 3.0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]float64, len(tt.input))
			copy(input, tt.input)
			sortFloat64s(input)
			if len(input) != len(tt.want) {
				t.Fatalf("length mismatch: got %d, want %d", len(input), len(tt.want))
			}
			for i := range input {
				if input[i] != tt.want[i] {
					t.Errorf("element[%d]: got %f, want %f", i, input[i], tt.want[i])
				}
			}
		})
	}
}

// =========================================================================
// detector.go — GetCalibrator, IsEnabled
// =========================================================================

func TestPhase5_ThreatDetector_GetCalibrator(t *testing.T) {
	td := NewThreatDetector(DetectorConfig{})
	cm := td.GetCalibrator()
	if cm == nil {
		t.Fatal("expected non-nil calibrator")
	}
}

func TestPhase5_ThreatDetector_IsEnabled(t *testing.T) {
	td := NewThreatDetector(DetectorConfig{Enabled: true})
	if !td.IsEnabled() {
		t.Error("expected IsEnabled() to be true")
	}

	td2 := NewThreatDetector(DetectorConfig{Enabled: false})
	if td2.IsEnabled() {
		t.Error("expected IsEnabled() to be false")
	}
}

// =========================================================================
// latency.go — Len, newBatchPanicError, Error
// =========================================================================

func TestPhase5_LRUCache_Len(t *testing.T) {
	c := newLRUCache(10)
	if c.Len() != 0 {
		t.Errorf("empty cache Len: got %d, want 0", c.Len())
	}

	// Add some entries
	c.Put(1, ThreatScore{Score: 0.5})
	c.Put(2, ThreatScore{Score: 0.8})
	if c.Len() != 2 {
		t.Errorf("cache with 2 entries Len: got %d, want 2", c.Len())
	}
}

func TestPhase5_NewBatchPanicError(t *testing.T) {
	err := newBatchPanicError("test panic")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "batch detection panic" {
		t.Errorf("Error(): got %q, want %q", err.Error(), "batch detection panic")
	}
}

func TestPhase5_BatchPanicError_WithStruct(t *testing.T) {
	type customPanic struct{ msg string }
	err := newBatchPanicError(customPanic{msg: "custom"})
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "batch detection panic" {
		t.Errorf("Error(): got %q, want %q", err.Error(), "batch detection panic")
	}
}

// =========================================================================
// metrics.go — NewMetricsHandler, ServeHTTP, isShadowModeEnabled,
//              RegisterMetricsRoute, writeMetricsError
// =========================================================================

func TestPhase5_NewMetricsHandler(t *testing.T) {
	cm := NewCalibrationManager(DetectorConfig{})
	h := NewMetricsHandler(cm)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
	if h.calibrator == nil {
		t.Error("expected non-nil calibrator in handler")
	}
}

func TestPhase5_MetricsHandler_ServeHTTP_Get(t *testing.T) {
	cm := NewCalibrationManager(DetectorConfig{})
	h := NewMetricsHandler(cm)

	// Enable shadow mode
	t.Setenv("AEGIS_ML_SHADOW_MODE", "true")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ml/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}

	var resp metricsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.ShadowModeEnabled {
		t.Error("expected shadow_mode_enabled to be true")
	}
}

func TestPhase5_MetricsHandler_ServeHTTP_PostMethod(t *testing.T) {
	cm := NewCalibrationManager(DetectorConfig{})
	h := NewMetricsHandler(cm)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ml/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestPhase5_MetricsHandler_ServeHTTP_ShadowModeDisabled(t *testing.T) {
	cm := NewCalibrationManager(DetectorConfig{})
	h := NewMetricsHandler(cm)

	// Disable shadow mode
	t.Setenv("AEGIS_ML_SHADOW_MODE", "false")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ml/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestPhase5_MetricsHandler_ServeHTTP_NilCalibrator(t *testing.T) {
	h := NewMetricsHandler(nil)

	// Enable shadow mode but calibrator is nil
	t.Setenv("AEGIS_ML_SHADOW_MODE", "true")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ml/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestPhase5_IsShadowModeEnabled(t *testing.T) {
	// Default (unset) → true
	t.Setenv("AEGIS_ML_SHADOW_MODE", "")
	if !isShadowModeEnabled() {
		t.Error("expected true for unset env var")
	}

	// Explicit "true" → true
	t.Setenv("AEGIS_ML_SHADOW_MODE", "true")
	if !isShadowModeEnabled() {
		t.Error("expected true for 'true'")
	}

	// Explicit "false" → false
	t.Setenv("AEGIS_ML_SHADOW_MODE", "false")
	if isShadowModeEnabled() {
		t.Error("expected false for 'false'")
	}

	// Any other value → true (only "false" disables)
	t.Setenv("AEGIS_ML_SHADOW_MODE", "yes")
	if !isShadowModeEnabled() {
		t.Error("expected true for 'yes'")
	}
}

func TestPhase5_RegisterMetricsRoute(t *testing.T) {
	cm := NewCalibrationManager(DetectorConfig{})
	mux := http.NewServeMux()
	RegisterMetricsRoute(mux, cm)

	// Verify the route is registered by making a request
	t.Setenv("AEGIS_ML_SHADOW_MODE", "true")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ml/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
}

// =========================================================================
// latency.go — LRU cache eviction, update existing, newLRUCache default
// =========================================================================

func TestPhase5_LRUCache_Put_UpdateExisting(t *testing.T) {
	c := newLRUCache(10)
	c.Put(1, ThreatScore{Score: 0.5})
	c.Put(1, ThreatScore{Score: 0.9}) // update existing

	result, ok := c.Get(1)
	if !ok {
		t.Fatal("expected to find key 1")
	}
	if result.Score != 0.9 {
		t.Errorf("score: got %f, want 0.9", result.Score)
	}
}

func TestPhase5_LRUCache_Put_Eviction(t *testing.T) {
	c := newLRUCache(2) // small capacity
	c.Put(1, ThreatScore{Score: 0.1})
	c.Put(2, ThreatScore{Score: 0.2})
	c.Put(3, ThreatScore{Score: 0.3}) // should evict key 1

	if _, ok := c.Get(1); ok {
		t.Error("key 1 should have been evicted")
	}
	if _, ok := c.Get(2); !ok {
		t.Error("key 2 should still be in cache")
	}
	if _, ok := c.Get(3); !ok {
		t.Error("key 3 should be in cache")
	}
}

func TestPhase5_NewLRUCache_DefaultCapacity(t *testing.T) {
	c := newLRUCache(0) // should default to 10000
	if c.capacity != 10000 {
		t.Errorf("expected default capacity 10000, got %d", c.capacity)
	}
	c.Put(1, ThreatScore{Score: 0.5})
	if c.Len() != 1 {
		t.Errorf("expected Len 1, got %d", c.Len())
	}
}

// =========================================================================
// latency.go — minf
// =========================================================================

func TestPhase5_Minf(t *testing.T) {
	if minf(1.0, 2.0) != 1.0 {
		t.Error("minf(1.0, 2.0) should return 1.0")
	}
	if minf(2.0, 1.0) != 1.0 {
		t.Error("minf(2.0, 1.0) should return 1.0")
	}
	if minf(1.0, 1.0) != 1.0 {
		t.Error("minf(1.0, 1.0) should return 1.0")
	}
}

// =========================================================================
// normalizer.go — Decode with UnkID and Latin-1 supplement
// =========================================================================

func TestPhase5_CharNormalizer_Decode_UnknownAndLatin1(t *testing.T) {
	cn := NewCharNormalizer()
	// Include UnkID (1), printable ASCII (65='A'), and Latin-1 (200='È')
	result := cn.Decode([]int32{PadID, UnkID, 65, 200, 0})
	if result == "" {
		t.Fatal("expected non-empty decoded string")
	}
	// Should contain the replacement character for UnkID
	if !strings.ContainsRune(result, '\uFFFD') {
		t.Error("expected replacement character for UnkID")
	}
	// Should contain 'A' (ASCII 65)
	if !strings.ContainsRune(result, 'A') {
		t.Error("expected 'A' in decoded string")
	}
}

// =========================================================================
// drift.go — NewDriftMonitor defaults, findBin with baseline
// =========================================================================

func TestPhase5_NewDriftMonitor_Defaults(t *testing.T) {
	dm := NewDriftMonitor(DriftMonitorConfig{
		BinCount:      0,   // should default to 10
		PSIThresholds: nil, // should get defaults
	})
	if dm.config.BinCount != 10 {
		t.Errorf("expected default BinCount 10, got %d", dm.config.BinCount)
	}
	if dm.config.PSIThresholds == nil {
		t.Error("expected non-nil default PSIThresholds")
	}
	if dm.config.PSIThresholds["minor"] != 0.1 {
		t.Errorf("expected minor threshold 0.1, got %f", dm.config.PSIThresholds["minor"])
	}
}

// =========================================================================
// latency.go — optimizedDetectWithSets via LatencyOptimizer.Detect
// =========================================================================

func TestPhase5_LatencyOptimizer_Detect_ThreatText(t *testing.T) {
	td := NewThreatDetector(DetectorConfig{Enabled: true})
	opt := NewLatencyOptimizer(DetectorConfig{})

	// Use a long enough text (> 32 chars) to avoid fast-path
	// and containing a known attack word
	text := "this is a prompt injection attack that bypasses all security measures completely"
	score := OptimizedDetect(td, opt, text)
	// Should detect a threat (score > 0)
	if score.Score <= 0 {
		t.Errorf("expected non-zero score for threat text, got %f", score.Score)
	}
}

func TestPhase5_LatencyOptimizer_Detect_EmptyText(t *testing.T) {
	td := NewThreatDetector(DetectorConfig{Enabled: true})
	opt := NewLatencyOptimizer(DetectorConfig{})

	score := OptimizedDetect(td, opt, "")
	if score.Score != 0 {
		t.Errorf("expected score 0 for empty text, got %f", score.Score)
	}
	if score.IsThreat {
		t.Error("expected IsThreat false for empty text")
	}
}

func TestPhase5_LatencyOptimizer_Detect_BenignText(t *testing.T) {
	td := NewThreatDetector(DetectorConfig{Enabled: true})
	opt := NewLatencyOptimizer(DetectorConfig{})

	// Long benign text that shouldn't trigger detection
	text := "the quick brown fox jumps over the lazy dog and runs through the forest"
	score := OptimizedDetect(td, opt, text)
	// Should not be a threat
	if score.IsThreat {
		t.Error("expected IsThreat false for benign text")
	}
}

func TestPhase5_WriteMetricsError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeMetricsError(rec, http.StatusBadRequest, "test error message")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp["message"] != "test error message" {
		t.Errorf("message: got %v, want %q", resp["message"], "test error message")
	}
}
