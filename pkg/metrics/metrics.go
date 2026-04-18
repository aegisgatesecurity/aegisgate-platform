// Package metrics provides Prometheus metrics for AegisGate Platform.
// Exports standard application metrics for monitoring and alerting.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
)

var (
	// HTTP request metrics
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisgate_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	// Active connections gauge
	activeConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "aegisgate_active_connections",
			Help: "Number of active connections",
		},
		[]string{"service"},
	)

	// Rate limiting metrics
	rateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_rate_limit_hits_total",
			Help: "Total number of rate limit hits",
		},
		[]string{"service", "client"},
	)

	// Security scan metrics
	securityScansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_security_scans_total",
			Help: "Total security scans performed",
		},
		[]string{"type", "result"},
	)

	// MCP metrics
	mcpConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisgate_mcp_connections",
			Help: "Number of active MCP connections",
		},
	)

	mcpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_mcp_requests_total",
			Help: "Total MCP requests",
		},
		[]string{"tool", "status"},
	)

	// Tier usage metrics
	tierRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_tier_requests_total",
			Help: "Requests by tier",
		},
		[]string{"tier"},
	)

	// Audit log metrics
	auditEventsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "aegisgate_audit_events_total",
			Help: "Total audit events logged",
		},
	)

	// Build info metric
	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "aegisgate_build_info",
			Help: "Build information",
		},
		[]string{"version", "goversion", "platform"},
	)
)

func init() {
	// Register all metrics with Prometheus
	prometheus.MustRegister(
		httpRequestsTotal,
		httpRequestDuration,
		activeConnections,
		rateLimitHits,
		securityScansTotal,
		mcpConnections,
		mcpRequestsTotal,
		tierRequests,
		auditEventsTotal,
		buildInfo,
	)
}

// RecordHTTPRequest records an HTTP request
func RecordHTTPRequest(method, endpoint string, status int, duration time.Duration) {
	httpRequestsTotal.WithLabelValues(method, endpoint, http.StatusText(status)).Inc()
	httpRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// SetActiveConnections sets the active connections gauge
func SetActiveConnections(service string, count int) {
	activeConnections.WithLabelValues(service).Set(float64(count))
}

// IncActiveConnections increments active connections
func IncActiveConnections(service string) {
	activeConnections.WithLabelValues(service).Inc()
}

// DecActiveConnections decrements active connections
func DecActiveConnections(service string) {
	activeConnections.WithLabelValues(service).Dec()
}

// RecordRateLimitHit records a rate limit hit
func RecordRateLimitHit(service, client string) {
	rateLimitHits.WithLabelValues(service, client).Inc()
}

// RecordSecurityScan records a security scan
func RecordSecurityScan(scanType, result string) {
	securityScansTotal.WithLabelValues(scanType, result).Inc()
}

// SetMCPConnections sets MCP connection count
func SetMCPConnections(count int) {
	mcpConnections.Set(float64(count))
}

// RecordMCPRequest records an MCP request
func RecordMCPRequest(tool, status string) {
	mcpRequestsTotal.WithLabelValues(tool, status).Inc()
}

// RecordTierRequest records a request by tier
func RecordTierRequest(tier string) {
	tierRequests.WithLabelValues(tier).Inc()
}

// RecordAuditEvent records an audit event
func RecordAuditEvent() {
	auditEventsTotal.Inc()
}

// SetBuildInfo sets build information
func SetBuildInfo(version, goversion, platform string) {
	buildInfo.WithLabelValues(version, goversion, platform).Set(1)
}

// Handler returns the Prometheus metrics HTTP handler
func Handler() http.Handler {
	return promhttp.Handler()
}

// InstrumentHandler wraps an HTTP handler with metrics
func InstrumentHandler(name string, handler http.Handler) http.Handler {
	return promhttp.InstrumentHandlerDuration(
		httpRequestDuration.MustCurryWith(prometheus.Labels{"endpoint": name}),
		promhttp.InstrumentHandlerCounter(
			httpRequestsTotal.MustCurryWith(prometheus.Labels{"endpoint": name}),
			handler,
		),
	)
}

// PushMetrics pushes metrics to a pushgateway (optional)
func PushMetrics(pushgatewayURL, job string) error {
	pusher := push.New(pushgatewayURL, job).
		Collector(httpRequestsTotal).
		Collector(httpRequestDuration).
		Collector(activeConnections)
	
	return pusher.Push()
}

// MetricsEndpoint returns the standard Prometheus endpoint path
func MetricsEndpoint() string {
	return "/metrics"
}

// GetRegistry returns the Prometheus registry
func GetRegistry() *prometheus.Registry {
	return prometheus.NewRegistry()
}
