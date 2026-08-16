// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Scan Latency Metrics Tests
// =========================================================================

package metrics

import (
	"testing"
	"time"
)

func TestRecordScanDuration(t *testing.T) {
	// Record some scan durations
	RecordScanDuration(ResultBlocked, 5*time.Millisecond)
	RecordScanDuration(ResultSuccess, 2*time.Millisecond)
	RecordScanDuration(ResultBlocked, 10*time.Millisecond)
	RecordScanDuration(ResultError, 50*time.Millisecond)

	// If we got here without panicking, the histograms are registered
	// and accepting observations. Prometheus testutil could verify further.
}

func TestRecordRegexScanDuration(t *testing.T) {
	RecordRegexScanDuration(ResultSuccess, 500*time.Microsecond)
	RecordRegexScanDuration(ResultBlocked, 1*time.Millisecond)
	RecordRegexScanDuration(ResultSuccess, 250*time.Microsecond)
}

func TestRecordMLInferenceDuration(t *testing.T) {
	RecordMLInferenceDuration(ResultSuccess, 2*time.Millisecond)
	RecordMLInferenceDuration(ResultBlocked, 5*time.Millisecond)
	RecordMLInferenceDuration("threat", 3*time.Millisecond)
}

func TestRecordShadowPrediction(t *testing.T) {
	RecordShadowPrediction("threat")
	RecordShadowPrediction("benign")
	RecordShadowPrediction("error")
	RecordShadowPrediction("threat")
}

func TestMetricNames(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		want     string
	}{
		{"scan_duration", MetricScanDuration, "aegisgate_scan_pipeline_duration_seconds"},
		{"regex_scan_duration", MetricRegexScanDuration, "aegisgate_regex_scan_duration_seconds"},
		{"ml_inference_duration", MetricMLInferenceDuration, "aegisgate_ml_inference_duration_seconds"},
		{"shadow_prediction_total", MetricShadowPredictionTotal, "aegisgate_shadow_prediction_total"},
	}

	for _, tt := range tests {
		if tt.constant != tt.want {
			t.Errorf("%s: expected %q, got %q", tt.name, tt.want, tt.constant)
		}
	}
}

func TestScanDurationBuckets(t *testing.T) {
	// Verify the histogram buckets cover the expected range (1ms to 100ms)
	// The actual bucket verification is done via Prometheus registration,
	// but we can at least confirm observations at different scales work.
	durations := []time.Duration{
		500 * time.Microsecond, // sub-bucket (0.5ms < 1ms bucket)
		1 * time.Millisecond,   // exactly at first bucket
		5 * time.Millisecond,   // middle bucket
		50 * time.Millisecond,  // near top
		100 * time.Millisecond, // at top bucket
		200 * time.Millisecond, // above top bucket (still recorded)
	}

	for _, d := range durations {
		RecordScanDuration(ResultSuccess, d)
	}
}
