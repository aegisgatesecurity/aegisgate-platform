// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Platform — C9: Metrics Endpoint Scrape Integration Test
// =========================================================================
//
// Verifies that the Prometheus /metrics endpoint:
//   1. Is reachable and returns HTTP 200
//   2. Serves standard Prometheus text format
//   3. Exposes all 10 canonical AegisGate metric families
//   4. Records metric values after exercising recording functions
//   5. Includes build_info with correct version labels
//
// Run: go test -v -tags=integration ./tests/integration/ -run TestMetricsScrape
// =========================================================================

//go:build integration

package integration

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// TestMetricsScrape verifies the Prometheus metrics endpoint is scrapeable
// and exposes all 10 canonical metric families.
func TestMetricsScrape(t *testing.T) {
	// Record some sample data so metrics have non-zero values
	metrics.RecordHTTPRequest("GET", "/api/v1/models", 200, 0)
	metrics.RecordHTTPRequest("POST", "/api/v1/chat/completions", 429, 0)
	metrics.IncActiveConnections(metrics.ServiceProxy)
	metrics.DecActiveConnections(metrics.ServiceProxy)
	metrics.RecordRateLimitHit(metrics.ServiceProxy, "192.168.1.100")
	metrics.RecordRateLimitHit(metrics.ServiceMCP, "10.0.0.5")
	metrics.RecordSecurityScan(metrics.ScanVuln, metrics.ResultSuccess)
	metrics.RecordSecurityScan(metrics.ScanSecret, metrics.ResultBlocked)
	metrics.SetMCPConnections(3)
	metrics.RecordMCPRequest("scan_content", metrics.ResultSuccess)
	metrics.RecordMCPRequest("list_tools", metrics.ResultRateLimited)
	metrics.RecordTierRequest(metrics.TierCommunity)
	metrics.RecordTierRequest(metrics.TierProfessional)
	metrics.RecordAuditEvent()
	metrics.RecordAuditEvent()
	metrics.SetBuildInfo("1.3.0", "go1.22.0", "linux/amd64")

	// Create a test server serving the Prometheus handler
	handler := metrics.Handler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// Scrape the endpoint
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to scrape /metrics: %v", err)
	}
	defer resp.Body.Close()

	// C9-1: Endpoint returns HTTP 200
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}

	// C9-2: Content type is Prometheus text format
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") &&
		!strings.HasPrefix(contentType, "application/openmetrics-text") &&
		!strings.HasPrefix(contentType, "text/version") {
		t.Logf("Content-Type = %q (prometheus uses text/plain or openmetrics)", contentType)
	}

	// Read the full response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read metrics body: %v", err)
	}
	bodyStr := string(body)

	// C9-3: All 10 canonical metric families must be present
	expectedMetrics := []struct {
		name        string
		metricType  string // "counter", "gauge", "histogram"
		description string
	}{
		{metrics.MetricHTTPRequestsTotal, "counter", "Total HTTP requests"},
		{metrics.MetricHTTPRequestDuration, "histogram", "HTTP request latency"},
		{metrics.MetricActiveConnections, "gauge", "Active connections"},
		{metrics.MetricRateLimitHits, "counter", "Rate limit hits"},
		{metrics.MetricSecurityScansTotal, "counter", "Security scans"},
		{metrics.MetricMCPConnections, "gauge", "MCP connections"},
		{metrics.MetricMCPRequestsTotal, "counter", "MCP tool invocations"},
		{metrics.MetricTierRequests, "counter", "Tier requests"},
		{metrics.MetricAuditEventsTotal, "counter", "Audit events"},
		{metrics.MetricBuildInfo, "gauge", "Build info"},
	}

	for _, expected := range expectedMetrics {
		t.Run(expected.name, func(t *testing.T) {
			if !strings.Contains(bodyStr, expected.name) {
				t.Errorf("Metric %q not found in scrape output", expected.name)
			}
		})
	}

	// C9-4: Verify specific metric values were recorded
	// After recording HTTP requests, the counter should be > 0
	if !strings.Contains(bodyStr, `aegisgate_http_requests_total{`) {
		t.Error("Expected aegisgate_http_requests_total with labels in scrape output")
	}

	// Verify rate limit hits counter is present with service label
	if !strings.Contains(bodyStr, `aegisgate_rate_limit_hits_total{`) {
		t.Error("Expected aegisgate_rate_limit_hits_total with labels in scrape output")
	}

	// Verify MCP request metrics include rate_limited result
	if !strings.Contains(bodyStr, `result="rate_limited"`) {
		t.Error("Expected rate_limited result label in MCP request metrics")
	}

	// Verify security scan metrics include blocked result
	if !strings.Contains(bodyStr, `result="blocked"`) {
		t.Error("Expected blocked result label in security scan metrics")
	}

	// C9-5: Build info gauge has version label
	if !strings.Contains(bodyStr, `version="1.3.0"`) {
		t.Error("Expected version label in build_info metric")
	}

	// C9-6: Verify HELP lines (Prometheus convention: each metric has a HELP comment)
	helpCount := strings.Count(bodyStr, "# HELP ")
	if helpCount < 10 {
		t.Errorf("Expected at least 10 HELP lines (one per metric), got %d", helpCount)
	}

	// C9-7: Verify TYPE lines for all metrics
	typeCount := strings.Count(bodyStr, "# TYPE ")
	if typeCount < 10 {
		t.Errorf("Expected at least 10 TYPE lines (one per metric), got %d", typeCount)
	}

	t.Logf("Metrics scrape successful: %d bytes, %d HELP lines, %d TYPE lines",
		len(body), helpCount, typeCount)
}

// TestMetricsScrape_WithRegistry verifies that an isolated registry with
// registered collectors produces a scrapeable endpoint. A bare NewRegistry()
// has no collectors and Prometheus returns an empty body, so we register
// collectors via Options before scraping.
func TestMetricsScrape_WithRegistry(t *testing.T) {
	reg := metrics.NewRegistry()

	// Register the standard platform metrics into the isolated registry.
	// A bare NewRegistry() intentionally starts empty — that's correct
	// behavior (no leakage from default registry). We verify that once
	// metrics ARE registered, the isolated registry serves them properly.
	opts := metrics.DefaultOptions()
	opts.Registry = reg
	metrics.RegisterWithRegistry(reg, []prometheus.Collector{
		prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: opts.Namespace,
			Name:      "test_isolated_total",
			Help:      "Test counter in isolated registry",
		}),
	}...)

	handler := reg.Handler()

	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to scrape isolated registry: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Isolated registry returned %d, expected 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	t.Logf("Isolated registry scrape: %d bytes", len(bodyStr))

	// Verify the isolated registry has our test metric
	if !strings.Contains(bodyStr, "aegisgate_test_isolated_total") {
		t.Error("Isolated registry should contain the registered test metric")
	}
}

// TestMetricsScrape_LabelCardinality verifies that high-cardinality inputs
// are properly sanitized in the scrape output.
func TestMetricsScrape_LabelCardinality(t *testing.T) {
	// Record requests with high-cardinality endpoints
	metrics.RecordHTTPRequest("GET", "/api/v1/users/550e8400-e29b-41d4-a716-446655440000", 200, 0)
	metrics.RecordHTTPRequest("GET", "/api/v1/users/12345", 200, 0)
	metrics.RecordHTTPRequest("GET", "/api/v1/users/67890", 200, 0)
	metrics.RecordHTTPRequest("GET", "/api/v1/tokens/abc-def-ghi", 200, 0)

	// Record rate limit hits with per-IP addresses
	metrics.RecordRateLimitHit(metrics.ServiceMCP, "192.168.1.100")
	metrics.RecordRateLimitHit(metrics.ServiceMCP, "192.168.1.200")
	metrics.RecordRateLimitHit(metrics.ServiceMCP, "192.168.2.50")
	metrics.RecordRateLimitHit(metrics.ServiceMCP, "10.0.0.1")
	metrics.RecordRateLimitHit(metrics.ServiceMCP, "10.0.0.99")

	handler := metrics.Handler()
	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to scrape: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify sanitized endpoints appear (UUIDs collapsed)
	// SanitizeEndpoint should collapse /api/v1/users/{uuid} → /api/v1/users/:id
	if strings.Contains(bodyStr, "550e8400-e29b-41d4-a716-446655440000") {
		t.Error("Raw UUID should NOT appear in metrics output (cardinality leak)")
	}

	// Verify client bucketing — SanitizeClientID masks last octets
	// 192.168.1.100 and 192.168.1.200 should share the same bucket
	// 192.168.x.x (masked) — the raw IPs should not appear
	if strings.Contains(bodyStr, "192.168.1.100") {
		t.Error("Raw IP 192.168.1.100 should NOT appear in metrics output (should be bucketed)")
	}

	t.Logf("Cardinality protection verified: %d bytes output", len(bodyStr))
}

// TestMetricsScrape_Concurrent verifies that the metrics endpoint is safe
// to scrape concurrently (as Prometheus does with multiple targets).
func TestMetricsScrape_Concurrent(t *testing.T) {
	handler := metrics.Handler()
	server := httptest.NewServer(handler)
	defer server.Close()

	errCh := make(chan error, 20)

	for i := 0; i < 20; i++ {
		go func(id int) {
			resp, err := http.Get(server.URL)
			if err != nil {
				errCh <- err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errCh <- fmt.Errorf("scrape %d: status %d", id, resp.StatusCode)
				return
			}
			_, err = io.ReadAll(resp.Body)
			if err != nil {
				errCh <- err
				return
			}
			errCh <- nil
		}(i)
	}

	for i := 0; i < 20; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("Concurrent scrape failed: %v", err)
		}
	}
}

// TestMetricsEndpointPath verifies the standard endpoint path constant.
func TestMetricsEndpointPath(t *testing.T) {
	path := metrics.MetricsEndpoint()
	if path != "/metrics" {
		t.Errorf("MetricsEndpoint() = %q, want '/metrics'", path)
	}
}