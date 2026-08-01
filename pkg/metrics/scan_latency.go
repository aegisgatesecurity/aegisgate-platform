// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Scan Detection Latency Histogram (P2.5)
// =========================================================================
//
// Exposes Prometheus histograms for detection/scan latency so operators
// can monitor p50/p95/p99 and set SLO alerts. Three granularities:
//
//   - aegisgate_scan_duration_seconds: full scan pipeline (regex + ML)
//   - aegisgate_regex_scan_duration_seconds: regex-only phase
//   - aegisgate_ml_inference_duration_seconds: ML model inference phase
//
// All histograms use bounded buckets (1ms → 100ms) to keep cardinality
// controlled while still providing useful percentile resolution.
//
// =========================================================================

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Scan latency histogram metric names.
const (
	MetricScanDuration         = "aegisgate_scan_duration_seconds"
	MetricRegexScanDuration    = "aegisgate_regex_scan_duration_seconds"
	MetricMLInferenceDuration  = "aegisgate_ml_inference_duration_seconds"
	MetricShadowPredictionTotal = "aegisgate_shadow_prediction_total"
)

// scanDuration tracks full scan pipeline latency (regex + ML).
// Buckets: 1ms, 2.5ms, 5ms, 10ms, 25ms, 50ms, 100ms.
var scanDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    MetricScanDuration,
		Help:    "Full scan pipeline latency in seconds (regex + ML), partitioned by scan result.",
		Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1},
	},
	[]string{LabelResult},
)

// regexScanDuration tracks regex-only scan phase latency.
var regexScanDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    MetricRegexScanDuration,
		Help:    "Regex-only scan phase latency in seconds, partitioned by scan result.",
		Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05},
	},
	[]string{LabelResult},
)

// mlInferenceDuration tracks ML model inference latency.
var mlInferenceDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    MetricMLInferenceDuration,
		Help:    "ML inference latency in seconds, partitioned by threat/no-threat result.",
		Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1},
	},
	[]string{LabelResult},
)

// shadowPredictionTotal tracks shadow-mode prediction counts by result.
var shadowPredictionTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: MetricShadowPredictionTotal,
		Help: "Total shadow-mode ML predictions, partitioned by result (threat, benign, error).",
	},
	[]string{LabelResult},
)

func init() {
	prometheus.MustRegister(
		scanDuration,
		regexScanDuration,
		mlInferenceDuration,
		shadowPredictionTotal,
	)
}

// RecordScanDuration records the duration of a full scan pipeline.
// result should be one of ResultBlocked, ResultAllowed, ResultError.
func RecordScanDuration(result string, duration time.Duration) {
	scanDuration.WithLabelValues(result).Observe(duration.Seconds())
}

// RecordRegexScanDuration records the duration of the regex scan phase.
func RecordRegexScanDuration(result string, duration time.Duration) {
	regexScanDuration.WithLabelValues(result).Observe(duration.Seconds())
}

// RecordMLInferenceDuration records the duration of ML model inference.
func RecordMLInferenceDuration(result string, duration time.Duration) {
	mlInferenceDuration.WithLabelValues(result).Observe(duration.Seconds())
}

// RecordShadowPrediction records a shadow-mode prediction.
func RecordShadowPrediction(result string) {
	shadowPredictionTotal.WithLabelValues(result).Inc()
}