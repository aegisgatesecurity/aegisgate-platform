// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP Prometheus Metrics
// =========================================================================

package acp

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ACP metrics
var (
	ACPMessageTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_acp_messages_total",
			Help: "Total ACP messages processed",
		},
		[]string{"method", "result"},
	)

	ACPMessageSizeBytes = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisgate_acp_message_size_bytes",
			Help:    "ACP message sizes",
			Buckets: prometheus.ExponentialBuckets(64, 2, 12),
		},
		[]string{"method"},
	)

	ACPHMACVerifications = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_acp_hmac_verifications_total",
			Help: "HMAC verification attempts",
		},
		[]string{"status"},
	)

	ACPRateLimitHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_acp_rate_limit_hits_total",
			Help: "Rate limit violations",
		},
		[]string{"identity"},
	)

	ACPScanDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisgate_acp_scan_duration_seconds",
			Help:    "Scan latency",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"scan_type"},
	)

	ACPDetectedPII = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_acp_detected_pii_total",
			Help: "PII detections",
		},
		[]string{"category"},
	)

	ACPDetectedSecrets = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_acp_detected_secrets_total",
			Help: "Secret detections",
		},
		[]string{"type"},
	)

	ACPBlockedMethods = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_acp_blocked_methods_total",
			Help: "Blocked method calls",
		},
		[]string{"method"},
	)

	ACPSessionActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisgate_acp_sessions_active",
			Help: "Active ACP sessions",
		},
	)

	ACPGuardEnabled = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisgate_acp_guard_enabled",
			Help: "ACP guard enabled status",
		},
	)
)

// RecordMessage records an ACP message metric
func RecordMessage(method string, allowed bool, sizeBytes int) {
	result := "allowed"
	if !allowed {
		result = "blocked"
	}
	ACPMessageTotal.WithLabelValues(method, result).Inc()
	ACPMessageSizeBytes.WithLabelValues(method).Observe(float64(sizeBytes))
}

// RecordHMACVerification records HMAC verification result
func RecordHMACVerification(success bool, expired bool) {
	status := "success"
	if expired {
		status = "expired"
	} else if !success {
		status = "failure"
	}
	ACPHMACVerifications.WithLabelValues(status).Inc()
}

// RecordRateLimitHit records a rate limit violation
func RecordRateLimitHit(identity string) {
	ACPRateLimitHits.WithLabelValues(identity).Inc()
}

// RecordScanDuration records scan latency
func RecordScanDuration(scanType string, durationSeconds float64) {
	ACPScanDuration.WithLabelValues(scanType).Observe(durationSeconds)
}

// RecordDetectedPII records PII detection
func RecordDetectedPII(category string) {
	ACPDetectedPII.WithLabelValues(category).Inc()
}

// RecordDetectedSecret records secret detection
func RecordDetectedSecret(secretType string) {
	ACPDetectedSecrets.WithLabelValues(secretType).Inc()
}

// RecordBlockedMethod records a blocked method
func RecordBlockedMethod(method string) {
	ACPBlockedMethods.WithLabelValues(method).Inc()
}

// SetGuardEnabled sets the guard enabled status
func SetGuardEnabled(enabled bool) {
	if enabled {
		ACPGuardEnabled.Set(1)
	} else {
		ACPGuardEnabled.Set(0)
	}
}

// SetActiveSessions sets the number of active sessions
func SetActiveSessions(count int) {
	ACPSessionActive.Set(float64(count))
}
