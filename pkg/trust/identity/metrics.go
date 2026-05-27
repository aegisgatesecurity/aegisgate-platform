// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Identity Metrics
// =========================================================================

package identity

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	agentsRegisteredTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_trust_agents_registered_total",
		Help: "Total number of agents registered",
	})
	agentsRevokedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_trust_agents_revoked_total",
		Help: "Total number of agents revoked",
	})
	agentsSuspendedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_trust_agents_suspended_total",
		Help: "Total number of agents suspended",
	})
	verificationAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_trust_verification_attempts_total",
			Help: "Total verification attempts",
		},
		[]string{"result"},
	)
	verificationLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "aegisgate_trust_verification_latency_seconds",
		Help:    "Verification latency in seconds",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
	})
	keyRotationsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "aegisgate_trust_key_rotations_total",
		Help: "Total number of key rotations",
	})
	activeAgentsGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "aegisgate_trust_active_agents",
		Help: "Current number of active agents",
	})
)

func RecordRegistration() { agentsRegisteredTotal.Inc(); activeAgentsGauge.Inc() }
func RecordRevocation()   { agentsRevokedTotal.Inc(); activeAgentsGauge.Dec() }
func RecordSuspension()   { agentsSuspendedTotal.Inc(); activeAgentsGauge.Dec() }
func RecordReactivation() { activeAgentsGauge.Inc() }
func RecordVerification(success bool) {
	if success {
		verificationAttemptsTotal.WithLabelValues("success").Inc()
	} else {
		verificationAttemptsTotal.WithLabelValues("failure").Inc()
	}
}
func RecordVerificationLatency(seconds float64) { verificationLatency.Observe(seconds) }
func RecordKeyRotation()                        { keyRotationsTotal.Inc() }
