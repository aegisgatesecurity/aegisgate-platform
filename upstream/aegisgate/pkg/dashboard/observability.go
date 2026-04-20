// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package dashboard

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus metric collectors
var (
	// Request metrics
	requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_requests_total",
			Help: "Total number of requests processed",
		},
		[]string{"method", "path", "status"},
	)

	blockedRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_blocked_requests_total",
			Help: "Total number of blocked requests",
		},
		[]string{"reason", "category"},
	)

	violationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_violations_total",
			Help: "Total number of security violations detected",
		},
		[]string{"severity", "category", "pattern"},
	)

	// Latency metrics
	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aegisgate_request_duration_seconds",
			Help:    "Request processing duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	scanDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "aegisgate_scan_duration_seconds",
			Help:    "WAF scan processing duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	proxyLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "aegisgate_proxy_latency_seconds",
			Help:    "Proxy forwarding latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	// System metrics
	goGoroutines = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisgate_goroutines",
			Help: "Number of goroutines",
		},
	)

	goMemoryAlloc = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisgate_memory_alloc_bytes",
			Help: "Memory allocated in bytes",
		},
	)

	goMemoryHeap = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisgate_memory_heap_bytes",
			Help: "Heap memory allocated in bytes",
		},
	)

	goMemoryStack = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "aegisgate_memory_stack_bytes",
			Help: "Stack memory allocated in bytes",
		},
	)

	// Component health status
	componentHealth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "aegisgate_component_health",
			Help: "Health status of components (1=healthy, 0=unhealthy)",
		},
		[]string{"component"},
	)

	// Error metrics
	errorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aegisgate_errors_total",
			Help: "Total number of system errors",
		},
		[]string{"type"},
	)
)

// ComponentStatus represents the health status of a component
type ComponentStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// handlePrometheusMetrics handles GET /metrics
// Returns Prometheus-compatible metrics for scraping
func (d *Dashboard) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) error {
	// Update system metrics before serving
	d.updateSystemMetrics()

	// Update component health metrics
	d.updateComponentHealthMetrics()

	// Use promhttp handler for metrics
	handler := promhttp.Handler()
	handler.ServeHTTP(w, r)
	return nil
}

// updateSystemMetrics collects and updates system-level Prometheus metrics
func (d *Dashboard) updateSystemMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	goGoroutines.Set(float64(runtime.NumGoroutine()))
	goMemoryAlloc.Set(float64(memStats.Alloc))
	goMemoryHeap.Set(float64(memStats.HeapAlloc))
	goMemoryStack.Set(float64(memStats.StackInuse))
}

// updateComponentHealthMetrics updates Prometheus metrics for component health
func (d *Dashboard) updateComponentHealthMetrics() {
	components := d.checkComponents()

	for _, comp := range components {
		status := 0.0
		if comp.Status == "healthy" {
			status = 1.0
		}
		componentHealth.WithLabelValues(comp.Name).Set(status)
	}
}

// checkComponents performs health checks on all platform components
// Returns a slice of ComponentStatus for each component
func (d *Dashboard) checkComponents() []ComponentStatus {
	components := []ComponentStatus{
		{Name: "metrics", Status: "healthy"},
		{Name: "websocket", Status: "healthy"},
		{Name: "http_server", Status: "healthy"},
	}

	// Check metrics collector
	if d.metrics == nil {
		components[0] = ComponentStatus{
			Name:    "metrics",
			Status:  "unhealthy",
			Message: "metrics collector not initialized",
		}
	}

	// Check WebSocket SSE server
	if d.sseServer == nil {
		components[1] = ComponentStatus{
			Name:    "websocket",
			Status:  "unhealthy",
			Message: "SSE server not initialized",
		}
	}

	// Check HTTP server
	if d.server == nil {
		components[2] = ComponentStatus{
			Name:    "http_server",
			Status:  "unhealthy",
			Message: "HTTP server not initialized",
		}
	}

	return components
}

// handleEnhancedHealth handles GET /health
// Returns comprehensive health status including all components
func (d *Dashboard) handleEnhancedHealth(w http.ResponseWriter, r *http.Request) error {
	components := d.checkComponents()

	// Determine overall health
	allHealthy := true
	for _, comp := range components {
		if comp.Status != "healthy" {
			allHealthy = false
			break
		}
	}

	// Include system metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	healthResponse := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"uptime":    time.Since(d.startTime).Seconds(),
		"components": map[string]interface{}{
			"metrics":     components[0].Status,
			"websocket":   components[1].Status,
			"http_server": components[2].Status,
		},
		"system": map[string]interface{}{
			"goroutines":   runtime.NumGoroutine(),
			"memory_mb":    memStats.Alloc / (1024 * 1024),
			"heap_mb":      memStats.HeapAlloc / (1024 * 1024),
			"stack_mb":     memStats.StackInuse / (1024 * 1024),
			"num_gc":       memStats.NumGC,
			"total_alloc":  memStats.TotalAlloc / (1024 * 1024),
			"mcache_inuse": memStats.MCacheInuse,
			"mspan_inuse":  memStats.MSpanInuse,
		},
	}

	if !allHealthy {
		healthResponse["status"] = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(healthResponse)
	return nil
}

// handleComponentHealth handles GET /health/components
// Returns detailed component status for Kubernetes probes
func (d *Dashboard) handleComponentHealth(w http.ResponseWriter, r *http.Request) error {
	components := d.checkComponents()

	allHealthy := true
	for _, comp := range components {
		if comp.Status != "healthy" {
			allHealthy = false
			break
		}
	}

	response := map[string]interface{}{
		"status":     "ok",
		"healthy":    allHealthy,
		"components": components,
		"timestamp":  time.Now(),
	}

	status := http.StatusOK
	if !allHealthy {
		status = http.StatusServiceUnavailable
	}

	d.writeJSON(w, status, APIResponse{
		Success:   true,
		Data:      response,
		Timestamp: time.Now(),
	})
	return nil
}

// syncMetricsToPrometheus synchronizes internal metrics to Prometheus counters
// This should be called periodically or when metrics are updated
func (d *Dashboard) syncMetricsToPrometheus() {
	if d.metrics == nil {
		return
	}

	realtime := d.metrics.GetRealtimeMetrics()

	// Update request count (approximation using current count)
	requestsTotal.WithLabelValues("", "").Add(float64(realtime.RequestCount))

	// Update violation counts by severity
	severityCounts := realtime.SeverityCounts.Get()
	violationsTotal.WithLabelValues("critical", "", "").Add(float64(severityCounts.Critical))
	violationsTotal.WithLabelValues("high", "", "").Add(float64(severityCounts.High))
	violationsTotal.WithLabelValues("medium", "", "").Add(float64(severityCounts.Medium))
	violationsTotal.WithLabelValues("low", "", "").Add(float64(severityCounts.Low))
	violationsTotal.WithLabelValues("info", "", "").Add(float64(severityCounts.Info))

	// Update category counts
	for category, count := range realtime.CategoryCounts {
		violationsTotal.WithLabelValues("", category, "").Add(float64(count))
	}

	// Update error count
	errorsTotal.WithLabelValues("total").Add(float64(realtime.ErrorCount))
}

// RecordPrometheusRequest records a request to Prometheus metrics
// Called by the proxy when processing requests
func (d *Dashboard) RecordPrometheusRequest(method, path string, status int, duration time.Duration) {
	requestsTotal.WithLabelValues(method, path, strconv.Itoa(status)).Inc()
	requestDuration.WithLabelValues(method, path).Observe(duration.Seconds())
}

// RecordPrometheusBlocked records a blocked request to Prometheus metrics
func (d *Dashboard) RecordPrometheusBlocked(reason, category string) {
	blockedRequestsTotal.WithLabelValues(reason, category).Inc()
}

// RecordPrometheusViolation records a violation to Prometheus metrics
func (d *Dashboard) RecordPrometheusViolation(severity, category, pattern string) {
	violationsTotal.WithLabelValues(severity, category, pattern).Inc()
}

// RecordPrometheusScanDuration records WAF scan duration to Prometheus metrics
func (d *Dashboard) RecordPrometheusScanDuration(duration time.Duration) {
	scanDuration.Observe(duration.Seconds())
}

// RecordPrometheusProxyLatency records proxy latency to Prometheus metrics
func (d *Dashboard) RecordPrometheusProxyLatency(latency time.Duration) {
	proxyLatency.Observe(latency.Seconds())
}

// RecordPrometheusError records an error to Prometheus metrics
func (d *Dashboard) RecordPrometheusError(errorType string) {
	errorsTotal.WithLabelValues(errorType).Inc()
}

// StartMetricsSync starts a background goroutine that syncs internal metrics to Prometheus
// The sync interval determines how often the metrics are updated
func (d *Dashboard) StartMetricsSync(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			d.syncMetricsToPrometheus()
		}
	}()
}

// GetComponentStatus returns the current status of all components
// Useful for external monitoring systems
func (d *Dashboard) GetComponentStatus() []ComponentStatus {
	return d.checkComponents()
}

// IsHealthy returns true if all components are healthy
func (d *Dashboard) IsHealthy() bool {
	components := d.checkComponents()
	for _, comp := range components {
		if comp.Status != "healthy" {
			return false
		}
	}
	return true
}

// GetSystemMetrics returns current system metrics
func (d *Dashboard) GetSystemMetrics() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]interface{}{
		"goroutines":   runtime.NumGoroutine(),
		"memory_mb":    memStats.Alloc / (1024 * 1024),
		"heap_mb":      memStats.HeapAlloc / (1024 * 1024),
		"stack_mb":     memStats.StackInuse / (1024 * 1024),
		"num_gc":       memStats.NumGC,
		"total_alloc":  memStats.TotalAlloc / (1024 * 1024),
		"mcache_inuse": memStats.MCacheInuse,
		"mspan_inuse":  memStats.MSpanInuse,
		"mspan_sys":    memStats.MSpanSys,
		"mcache_sys":   memStats.MCacheSys,
		"buckhash_sys": memStats.BuckHashSys,
	}
}
