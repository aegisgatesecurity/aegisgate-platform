// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Shadow Detector Metrics & Response Headers
// =========================================================================
//
// shadow_metrics.go provides Prometheus metrics and HTTP response headers
// for shadow-mode detectors (P2, P4, DIST2-5, L3). In shadow mode, detectors
// fire alerts without blocking. This file:
//
//   1. Registers Prometheus counters for shadow detector alerts
//   2. Provides a per-request context to collect shadow alerts
//   3. Sets X-AegisGate-Shadow-* response headers for k6 validation
//
// Metrics exposed:
//   aegisgate_shadow_alerts_total{detector} — total alerts per detector
//   aegisgate_shadow_predictions_total{detector} — total predictions per detector
//
// Response headers (set on proxied responses):
//   X-AegisGate-Shadow-P2: 1     — tool chain alert
//   X-AegisGate-Shadow-P4: 1     — API key anomaly alert
//   X-AegisGate-Shadow-DIST2: 1  — proxy/datacenter IP alert
//   X-AegisGate-Shadow-DIST3: 1  — distillation pattern alert
//   X-AegisGate-Shadow-DIST4: 1  — account cluster alert
//   X-AegisGate-Shadow-DIST5: 1  — stolen key alert
//   X-AegisGate-Shadow-L3: 1     — ML neural network alert
//
// This enables the k6 shadow-validation-7day.js script to measure FPR/TPR
// per detector by inspecting response headers.
// =========================================================================

package proxy

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Detector names for metric labels.
const (
	ShadowDetectorP2    = "p2_chain"
	ShadowDetectorP4    = "p4_anomaly"
	ShadowDetectorDIST2 = "dist2_proxy"
	ShadowDetectorDIST3 = "dist3_pattern"
	ShadowDetectorDIST4 = "dist4_cluster"
	ShadowDetectorDIST5 = "dist5_stolen_key"
	ShadowDetectorL3    = "l3_neural"
)

// Response header names for shadow alerts.
const (
	HeaderShadowP2    = "X-AegisGate-Shadow-P2"
	HeaderShadowP4    = "X-AegisGate-Shadow-P4"
	HeaderShadowDIST2 = "X-AegisGate-Shadow-DIST2"
	HeaderShadowDIST3 = "X-AegisGate-Shadow-DIST3"
	HeaderShadowDIST4 = "X-AegisGate-Shadow-DIST4"
	HeaderShadowDIST5 = "X-AegisGate-Shadow-DIST5"
	HeaderShadowL3    = "X-AegisGate-Shadow-L3"
)

// Prometheus metrics for shadow detectors.
var (
	shadowAlertsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_shadow_alerts_total",
			Help: "Total shadow detector alerts (non-blocking), partitioned by detector.",
		},
		[]string{"detector"},
	)

	shadowPredictionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_shadow_predictions_total",
			Help: "Total shadow detector predictions (both alert and clean), partitioned by detector.",
		},
		[]string{"detector"},
	)
)

func init() {
	prometheus.MustRegister(shadowAlertsTotal, shadowPredictionsTotal)
}

// shadowAlertContext collects shadow detector alerts for the current request.
// It is attached to the request context and populated by recordToolCalls,
// recordKeyUsage, and the ML threat detector. The ServeHTTP method reads
// the collected alerts and sets response headers before writing the response.
type shadowAlertContext struct {
	mu     sync.Mutex
	alerts map[string]bool // detector name → alerted
}

// newShadowAlertContext creates a fresh alert context for a single request.
func newShadowAlertContext() *shadowAlertContext {
	return &shadowAlertContext{
		alerts: make(map[string]bool),
	}
}

// RecordAlert marks a shadow detector as having fired for this request.
func (sac *shadowAlertContext) RecordAlert(detector string) {
	sac.mu.Lock()
	defer sac.mu.Unlock()
	sac.alerts[detector] = true

	// Increment Prometheus counter
	shadowAlertsTotal.WithLabelValues(detector).Inc()
}

// RecordPrediction records that a shadow detector processed a prediction
// (regardless of whether it alerted).
func (sac *shadowAlertContext) RecordPrediction(detector string) {
	shadowPredictionsTotal.WithLabelValues(detector).Inc()
}

// HasAlert checks if a specific detector fired.
func (sac *shadowAlertContext) HasAlert(detector string) bool {
	sac.mu.Lock()
	defer sac.mu.Unlock()
	return sac.alerts[detector]
}

// HasAnyAlert checks if any shadow detector fired.
func (sac *shadowAlertContext) HasAnyAlert() bool {
	sac.mu.Lock()
	defer sac.mu.Unlock()
	return len(sac.alerts) > 0
}

// SetResponseHeaders writes X-AegisGate-Shadow-* headers for all detectors
// that fired during this request. Call this BEFORE writing the response body.
func (sac *shadowAlertContext) SetResponseHeaders(w http.ResponseWriter) {
	sac.mu.Lock()
	defer sac.mu.Unlock()

	for detector := range sac.alerts {
		switch detector {
		case ShadowDetectorP2:
			w.Header().Set(HeaderShadowP2, "1")
		case ShadowDetectorP4:
			w.Header().Set(HeaderShadowP4, "1")
		case ShadowDetectorDIST2:
			w.Header().Set(HeaderShadowDIST2, "1")
		case ShadowDetectorDIST3:
			w.Header().Set(HeaderShadowDIST3, "1")
		case ShadowDetectorDIST4:
			w.Header().Set(HeaderShadowDIST4, "1")
		case ShadowDetectorDIST5:
			w.Header().Set(HeaderShadowDIST5, "1")
		case ShadowDetectorL3:
			w.Header().Set(HeaderShadowL3, "1")
		}
	}
}

// shadowCtxKey is the context key for the shadow alert context.
type shadowCtxKey struct{}

// getShadowAlertContext retrieves the shadow alert context from the request.
// Returns nil if no context has been set (e.g., for health check endpoints).
func getShadowAlertContext(req *http.Request) *shadowAlertContext {
	if v, ok := req.Context().Value(shadowCtxKey{}).(*shadowAlertContext); ok {
		return v
	}
	return nil
}
