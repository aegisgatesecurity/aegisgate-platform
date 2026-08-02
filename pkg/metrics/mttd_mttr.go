// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// MTTD/MTTR Prometheus Metrics for AegisGate
// =========================================================================
//
// This module provides Prometheus histograms and counters for Mean Time To
// Detect (MTTD) and Mean Time To Respond (MTTR) — the two metrics SOC teams
// care about most when evaluating security tooling.
//
// Metric definitions:
//
//	aegisgate_mttd_seconds            — histogram, time from event to detection
//	aegisgate_mttr_seconds            — histogram, time from detection to response
//	aegisgate_incident_total          — counter, total incidents by outcome
//	aegisgate_detection_latency_seconds — histogram, end-to-end scan latency
//
// All metrics follow Prometheus naming conventions with aegisgate_ prefix.
// Buckets are chosen for realistic SOC response times (10ms–10s for detection,
// 1ms–1s for scan latency).
// =========================================================================

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// MTTDRecorder records MTTD, MTTR, incident, and detection latency metrics.
type MTTDRecorder struct {
	mttd       *prometheus.HistogramVec
	mttr       *prometheus.HistogramVec
	incidents  *prometheus.CounterVec
	detectLat  *prometheus.HistogramVec
	registered bool
}

// MTTD metric buckets: realistic detection times (10ms → 10s).
var mttdBuckets = prometheus.ExponentialBuckets(0.01, 2.5, 10) // 10ms, 25ms, 62ms, 155ms, 390ms, 976ms, 2.4s, 6.1s, 15s, 38s

// MTTR metric buckets: realistic response times (10ms → 10s).
var mttrBuckets = prometheus.ExponentialBuckets(0.01, 2.5, 10)

// Detection latency buckets: scan latency (1ms → 1s).
var detectLatBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0}

// NewMTTDRecorder creates and registers MTTD/MTTR metrics with Prometheus.
func NewMTTDRecorder(reg prometheus.Registerer) *MTTDRecorder {
	r := &MTTDRecorder{}

	r.mttd = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "aegisgate_mttd_seconds",
		Help:    "Mean Time To Detect: time from event occurrence to detection. Labels: framework, technique, severity.",
		Buckets: mttdBuckets,
	}, []string{"framework", "technique", "severity"})

	r.mttr = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "aegisgate_mttr_seconds",
		Help:    "Mean Time To Respond: time from detection to response action. Labels: framework, technique, severity.",
		Buckets: mttrBuckets,
	}, []string{"framework", "technique", "severity"})

	r.incidents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "aegisgate_incident_total",
		Help: "Total incidents detected. Labels: framework, technique, severity, status (detected/blocked/responded/missed).",
	}, []string{"framework", "technique", "severity", "status"})

	r.detectLat = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "aegisgate_detection_latency_seconds",
		Help:    "End-to-end detection latency. Labels: framework, method (regex/ml/anomaly).",
		Buckets: detectLatBuckets,
	}, []string{"framework", "method"})

	if reg != nil {
		reg.MustRegister(r.mttd, r.mttr, r.incidents, r.detectLat)
		r.registered = true
	}

	return r
}

// RecordDetection records a Mean Time To Detect observation.
func (r *MTTDRecorder) RecordDetection(framework, technique, severity string, duration time.Duration) {
	if r.registered {
		r.mttd.WithLabelValues(framework, technique, severity).Observe(duration.Seconds())
	}
}

// RecordResponse records a Mean Time To Respond observation.
func (r *MTTDRecorder) RecordResponse(framework, technique, severity string, duration time.Duration) {
	if r.registered {
		r.mttr.WithLabelValues(framework, technique, severity).Observe(duration.Seconds())
	}
}

// RecordIncident increments the incident counter for a detection event.
func (r *MTTDRecorder) RecordIncident(framework, technique, severity, status string) {
	if r.registered {
		r.incidents.WithLabelValues(framework, technique, severity, status).Inc()
	}
}

// RecordDetectionLatency records an end-to-end detection latency observation.
func (r *MTTDRecorder) RecordDetectionLatency(framework, method string, duration time.Duration) {
	if r.registered {
		r.detectLat.WithLabelValues(framework, method).Observe(duration.Seconds())
	}
}
