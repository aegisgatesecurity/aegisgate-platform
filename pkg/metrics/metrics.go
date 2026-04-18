// Copyright 2024 AegisGate Security. All rights reserved.
//
// Prometheus metrics for AegisGate Platform.
// All metric definitions use canonical label names from labels.go
// and cardinality-safe value sanitization from cardinality.go.
//
// # Metric Design Principles
//
//  1. Bounded cardinality: Every label uses a sanitizer or fixed enumeration
//     to prevent metrics explosion in production.
//  2. Consistent naming: All metrics prefixed with "aegisgate_", following
//     Prometheus naming conventions.
//  3. Appropriate types: Counters for totals, histograms for distributions,
//     gauges for current state.
//  4. Label consistency: Same label name means the same thing across all metrics.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
)

// Metric name constants following Prometheus naming conventions.
// All metrics are prefixed with "aegisgate_" to avoid collision.
const (
	MetricHTTPRequestsTotal        = "aegisgate_http_requests_total"
	MetricHTTPRequestDuration      = "aegisgate_http_request_duration_seconds"
	MetricActiveConnections        = "aegisgate_active_connections"
	MetricRateLimitHits            = "aegisgate_rate_limit_hits_total"
	MetricSecurityScansTotal       = "aegisgate_security_scans_total"
	MetricMCPConnections           = "aegisgate_mcp_connections"
	MetricMCPRequestsTotal         = "aegisgate_mcp_requests_total"
	MetricTierRequests             = "aegisgate_tier_requests_total"
	MetricAuditEventsTotal         = "aegisgate_audit_events_total"
	MetricBuildInfo                = "aegisgate_build_info"
)

var (
	// HTTP request metrics — the highest volume metrics in the system.
	// Endpoint labels are sanitized via SanitizeEndpoint() to prevent cardinality explosion
	// from REST API resource IDs and query parameters.
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricHTTPRequestsTotal,
			Help: "Total number of HTTP requests processed, partitioned by method, endpoint, and status class.",
		},
		[]string{LabelMethod, LabelEndpoint, LabelStatus},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    MetricHTTPRequestDuration,
			Help:    "HTTP request latency in seconds, partitioned by method and sanitized endpoint.",
			Buckets: DefaultHTTPBuckets,
		},
		[]string{LabelMethod, LabelEndpoint},
	)

	// Active connections gauge — tracks current connections by service component.
	activeConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: MetricActiveConnections,
			Help: "Number of currently active connections, partitioned by service component.",
		},
		[]string{LabelService},
	)

	// Rate limiting metrics — tracks throttle events by service and client bucket.
	rateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricRateLimitHits,
			Help: "Total number of rate limit hits, partitioned by service and sanitized client identifier.",
		},
		[]string{LabelService, LabelClient},
	)

	// Security scan metrics — tracks security scan invocations by type and result.
	securityScansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricSecurityScansTotal,
			Help: "Total security scans performed, partitioned by scan type and result.",
		},
		[]string{LabelScanType, LabelResult},
	)

	// MCP connection gauge — current number of active MCP sessions.
	mcpConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricMCPConnections,
			Help: "Number of active MCP (Model Context Protocol) connections.",
		},
	)

	// MCP request metrics — tracks tool invocations by name and result.
	// Tool names are sanitized via SanitizeToolName() to prevent cardinality explosion
	// from dynamically-named MCP tools.
	mcpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricMCPRequestsTotal,
			Help: "Total MCP tool invocations, partitioned by sanitized tool name and result.",
		},
		[]string{LabelTool, LabelResult},
	)

	// Tier usage metrics — tracks requests by license tier.
	tierRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricTierRequests,
			Help: "Total requests partitioned by platform tier (community, developer, professional, enterprise).",
		},
		[]string{LabelTier},
	)

	// Audit event counter — unpartitioned counter for total audit log entries.
	auditEventsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: MetricAuditEventsTotal,
			Help: "Total audit events logged across all components.",
		},
	)

	// Build info gauge — set once at startup with version, Go version, and platform.
	buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: MetricBuildInfo,
			Help: "Build and runtime information. Value is always 1; labels provide the details.",
		},
		[]string{LabelVersion, LabelGoVersion, LabelPlatform},
	)
)

func init() {
	// Register all platform metrics with the default Prometheus registry.
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

// --------------------------------------------------------------------------
// Recording functions
// --------------------------------------------------------------------------

// RecordHTTPRequest records an HTTP request with cardinality-safe labels.
// Endpoint is sanitized to collapse high-cardinality path segments (UUIDs,
// numeric IDs, etc.). Status is recorded as a class ("2xx", "4xx") rather
// than a raw code to bound cardinality.
func RecordHTTPRequest(method, endpoint string, status int, duration time.Duration) {
	httpRequestsTotal.WithLabelValues(
		method,
		SanitizeEndpoint(endpoint),
		StatusClass(status),
	).Inc()
	httpRequestDuration.WithLabelValues(
		method,
		SanitizeEndpoint(endpoint),
	).Observe(duration.Seconds())
}

// SetActiveConnections sets the active connections gauge to an absolute value.
// Use this for snapshot-style reporting; prefer Inc/Dec for incremental updates.
func SetActiveConnections(service string, count int) {
	activeConnections.WithLabelValues(service).Set(float64(count))
}

// IncActiveConnections increments the active connections gauge for a service.
// Pair with DecActiveConnections in a defer pattern for accurate tracking.
func IncActiveConnections(service string) {
	activeConnections.WithLabelValues(service).Inc()
}

// DecActiveConnections decrements the active connections gauge for a service.
func DecActiveConnections(service string) {
	activeConnections.WithLabelValues(service).Dec()
}

// RecordRateLimitHit records a rate limit hit with sanitized client identifier.
// The client parameter is bucketed via SanitizeClientID() to prevent
// cardinality explosion from per-IP metrics.
func RecordRateLimitHit(service, client string) {
	rateLimitHits.WithLabelValues(service, SanitizeClientID(client)).Inc()
}

// RecordSecurityScan records a security scan invocation.
// scanType should use one of the Scan* constants (ScanVuln, ScanSecret, etc.).
func RecordSecurityScan(scanType, result string) {
	securityScansTotal.WithLabelValues(scanType, result).Inc()
}

// SetMCPConnections sets the MCP connection count gauge to an absolute value.
func SetMCPConnections(count int) {
	mcpConnections.Set(float64(count))
}

// RecordMCPRequest records an MCP tool invocation.
// Tool names should be sanitized via SanitizeToolName() before calling.
func RecordMCPRequest(tool, result string) {
	mcpRequestsTotal.WithLabelValues(tool, result).Inc()
}

// RecordTierRequest records a request attributed to a specific tier.
// Use the Tier* constants for the tier parameter.
func RecordTierRequest(tier string) {
	tierRequests.WithLabelValues(tier).Inc()
}

// RecordAuditEvent increments the total audit event counter.
func RecordAuditEvent() {
	auditEventsTotal.Inc()
}

// SetBuildInfo sets the build information gauge. Call once at startup.
// This creates a time series with value 1 for each unique (version, goversion, platform)
// combination, enabling discovery of deployment configurations via PromQL.
func SetBuildInfo(version, goversion, platform string) {
	buildInfo.WithLabelValues(version, goversion, platform).Set(1)
}

// --------------------------------------------------------------------------
// HTTP handlers
// --------------------------------------------------------------------------

// Handler returns the standard Prometheus metrics HTTP handler for the default registry.
// Mount this on /metrics to expose metrics for scraping.
func Handler() http.Handler {
	return promhttp.Handler()
}

// PushMetrics pushes all registered metrics to a Prometheus Pushgateway.
// This is optional and typically used for short-lived batch jobs that cannot
// be scraped. For long-running services, prefer pull-based scraping via Handler().
func PushMetrics(pushgatewayURL, job string) error {
	pusher := push.New(pushgatewayURL, job).
		Collector(httpRequestsTotal).
		Collector(httpRequestDuration).
		Collector(activeConnections)
	return pusher.Push()
}

// MetricsEndpoint returns the standard Prometheus endpoint path ("/metrics").
func MetricsEndpoint() string {
	return "/metrics"
}

// GetRegistry returns a new isolated Prometheus registry.
// Deprecated: Use NewRegistry() instead for better naming clarity.
func GetRegistry() *prometheus.Registry {
	return prometheus.NewRegistry()
}