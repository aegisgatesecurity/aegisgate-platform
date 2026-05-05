// Package metrics provides A2A‑specific Prometheus counters.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// A2A specific metric names (prefixed with aegisgate_).
	MetricA2ALicenseFailures   = "aegisgate_a2a_license_failures_total"
	MetricA2ACapabilityDenials = "aegisgate_a2a_capability_denials_total"
	MetricA2AAuthFailures      = "aegisgate_a2a_auth_failures_total"
	MetricA2AIntegrityFailures = "aegisgate_a2a_integrity_failures_total"
)

var (
	a2aLicenseFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricA2ALicenseFailures,
			Help: "Total A2A requests rejected due to missing or invalid license header.",
		},
		[]string{"agent"},
	)
	a2aCapabilityDenials = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricA2ACapabilityDenials,
			Help: "Total A2A requests denied because the agent lacked the required capability.",
		},
		[]string{"agent", "capability"},
	)
	a2aAuthFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricA2AAuthFailures,
			Help: "Total A2A authentication failures (missing or invalid client certificate).",
		},
		[]string{"agent"},
	)
	a2aIntegrityFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricA2AIntegrityFailures,
			Help: "Total A2A requests rejected due to missing or invalid HMAC‑SHA256 signature.",
		},
		[]string{"agent"},
	)
)

func init() {
	prometheus.MustRegister(
		a2aLicenseFailures,
		a2aCapabilityDenials,
		a2aAuthFailures,
		a2aIntegrityFailures,
	)
}

// Recording helpers for A2A metrics.
func RecordA2ALicenseFailure(agent string) {
	a2aLicenseFailures.WithLabelValues(agent).Inc()
}
func RecordA2ACapabilityDenial(agent, capability string) {
	a2aCapabilityDenials.WithLabelValues(agent, capability).Inc()
}
func RecordA2AAuthFailure(agent string) {
	a2aAuthFailures.WithLabelValues(agent).Inc()
}
func RecordA2AIntegrityFailure(agent string) {
	a2aIntegrityFailures.WithLabelValues(agent).Inc()
}
