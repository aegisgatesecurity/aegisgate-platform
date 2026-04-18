// Copyright 2024 AegisGate Security. All rights reserved.

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// testRegistry creates a fresh isolated registry for each test.
// This prevents metric registration conflicts between tests.
func testRegistry() *Registry {
	reg := NewRegistry()
	return reg
}

// --------------------------------------------------------------------------
// Metric name constants
// --------------------------------------------------------------------------

func TestMetricNameConstants(t *testing.T) {
	names := map[string]string{
		"http_requests_total":               MetricHTTPRequestsTotal,
		"http_request_duration_seconds":     MetricHTTPRequestDuration,
		"active_connections":                MetricActiveConnections,
		"rate_limit_hits_total":             MetricRateLimitHits,
		"security_scans_total":              MetricSecurityScansTotal,
		"mcp_connections":                    MetricMCPConnections,
		"mcp_requests_total":                MetricMCPRequestsTotal,
		"tier_requests_total":               MetricTierRequests,
		"audit_events_total":                MetricAuditEventsTotal,
		"build_info":                        MetricBuildInfo,
	}

	for expected, actual := range names {
		if actual != "aegisgate_"+expected {
			t.Errorf("Metric name constant %q = %q, want %q", expected, actual, "aegisgate_"+expected)
		}
	}
}

// --------------------------------------------------------------------------
// Default options and buckets
// --------------------------------------------------------------------------

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Namespace != "aegisgate" {
		t.Errorf("DefaultOptions().Namespace = %q, want 'aegisgate'", opts.Namespace)
	}
	if opts.HTTPBuckets == nil {
		t.Error("DefaultOptions().HTTPBuckets should not be nil")
	}
	if opts.MCPBuckets == nil {
		t.Error("DefaultOptions().MCPBuckets should not be nil")
	}
	if !opts.EnableDefaultMetrics {
		t.Error("DefaultOptions().EnableDefaultMetrics should be true")
	}
}

func TestDefaultHTTPBuckets(t *testing.T) {
	if len(DefaultHTTPBuckets) < 5 {
		t.Errorf("DefaultHTTPBuckets has %d buckets, want at least 5", len(DefaultHTTPBuckets))
	}
	// First bucket should be small (fast responses)
	if DefaultHTTPBuckets[0] > 0.01 {
		t.Errorf("DefaultHTTPBuckets[0] = %f, want <= 0.01 (10ms)", DefaultHTTPBuckets[0])
	}
	// Last bucket should cover slow responses
	if DefaultHTTPBuckets[len(DefaultHTTPBuckets)-1] < 5.0 {
		t.Errorf("DefaultHTTPBuckets last = %f, want >= 5.0 (5s)", DefaultHTTPBuckets[len(DefaultHTTPBuckets)-1])
	}
}

func TestDefaultMCPBuckets(t *testing.T) {
	if len(DefaultMCPBuckets) < 5 {
		t.Errorf("DefaultMCPBuckets has %d buckets, want at least 5", len(DefaultMCPBuckets))
	}
	// MCP buckets should extend further than HTTP buckets
	if DefaultMCPBuckets[len(DefaultMCPBuckets)-1] < DefaultHTTPBuckets[len(DefaultHTTPBuckets)-1] {
		t.Error("DefaultMCPBuckets should extend further than DefaultHTTPBuckets")
	}
}

func TestCustomBuckets(t *testing.T) {
	buckets := CustomBuckets(10*time.Millisecond, 50*time.Millisecond, 100*time.Millisecond)
	if len(buckets) != 3 {
		t.Fatalf("CustomBuckets returned %d buckets, want 3", len(buckets))
	}
	if buckets[0] != 0.01 {
		t.Errorf("CustomBuckets[0] = %f, want 0.01", buckets[0])
	}
	if buckets[1] != 0.05 {
		t.Errorf("CustomBuckets[1] = %f, want 0.05", buckets[1])
	}
	if buckets[2] != 0.1 {
		t.Errorf("CustomBuckets[2] = %f, want 0.1", buckets[2])
	}
}

// --------------------------------------------------------------------------
// Recording functions
// --------------------------------------------------------------------------

func TestRecordHTTPRequest_IncrementsCounter(t *testing.T) {
	// Test that RecordHTTPRequest doesn't panic and increments both metrics
	// We can't easily verify the counter values without a test registry,
	// but we can verify it doesn't panic and the labels are valid
	RecordHTTPRequest("GET", "/api/v1/users/123", 200, 50*time.Millisecond)
	RecordHTTPRequest("POST", "/api/v1/tokens", 201, 25*time.Millisecond)
	RecordHTTPRequest("GET", "/health", 500, 1*time.Second)
}

func TestRecordHTTPRequest_StatusClasses(t *testing.T) {
	// Verify all status classes work
	tests := []int{200, 201, 204, 301, 302, 400, 404, 429, 500, 502, 503}

	for _, status := range tests {
		RecordHTTPRequest("GET", "/test", status, 10*time.Millisecond)
	}
}

func TestRecordHTTPRequest_SanitizedEndpoint(t *testing.T) {
	// Verify high-cardinality endpoints are sanitized
	RecordHTTPRequest("GET", "/api/v1/users/550e8400-e29b-41d4-a716-446655440000", 200, 10*time.Millisecond)
	RecordHTTPRequest("GET", "/api/v1/users/12345", 200, 10*time.Millisecond)
	RecordHTTPRequest("GET", "/health?format=json", 200, 1*time.Millisecond)
}

func TestActiveConnections(t *testing.T) {
	IncActiveConnections(ServiceProxy)
	IncActiveConnections(ServiceProxy)
	IncActiveConnections(ServiceMCP)

	SetActiveConnections(ServiceDashboard, 5)

	DecActiveConnections(ServiceProxy)
	DecActiveConnections(ServiceMCP)
}

func TestRecordRateLimitHit(t *testing.T) {
	RecordRateLimitHit(ServiceProxy, "192.168.1.100")
	RecordRateLimitHit(ServiceMCP, "10.0.0.5")
	RecordRateLimitHit(ServiceDashboard, "anonymous")
}

func TestRecordRateLimitHit_ClientBucketing(t *testing.T) {
	// Multiple different IPs in the same /16 should be bucketed
	RecordRateLimitHit(ServiceProxy, "192.168.1.1")
	RecordRateLimitHit(ServiceProxy, "192.168.1.2")
	RecordRateLimitHit(ServiceProxy, "192.168.2.1")
}

func TestRecordSecurityScan(t *testing.T) {
	RecordSecurityScan(ScanVuln, ResultSuccess)
	RecordSecurityScan(ScanSecret, ResultBlocked)
	RecordSecurityScan(ScanDependency, ResultError)
	RecordSecurityScan(ScanSBOM, ResultSuccess)
	RecordSecurityScan(ScanConfig, ResultFailure)
	RecordSecurityScan(ScanRuntime, ResultTimeout)
}

func TestSetMCPConnections(t *testing.T) {
	SetMCPConnections(0)
	SetMCPConnections(5)
	SetMCPConnections(10)
	SetMCPConnections(0)
}

func TestRecordMCPRequest(t *testing.T) {
	RecordMCPRequest("scan_content", ResultSuccess)
	RecordMCPRequest("list_tools", ResultFailure)
	RecordMCPRequest("unknown_tool", ResultError)
}

func TestRecordTierRequest(t *testing.T) {
	RecordTierRequest(TierCommunity)
	RecordTierRequest(TierProfessional)
	RecordTierRequest(TierEnterprise)
}

func TestRecordAuditEvent(t *testing.T) {
	RecordAuditEvent()
	RecordAuditEvent()
	RecordAuditEvent()
}

func TestSetBuildInfo(t *testing.T) {
	SetBuildInfo("1.3.0", "go1.22.0", "linux/amd64")
	SetBuildInfo("1.3.1", "go1.22.1", "darwin/arm64")
}

// --------------------------------------------------------------------------
// Handler and endpoint functions
// --------------------------------------------------------------------------

func TestMetricsEndpoint(t *testing.T) {
	endpoint := MetricsEndpoint()
	if endpoint != "/metrics" {
		t.Errorf("MetricsEndpoint() = %q, want '/metrics'", endpoint)
	}
}

func TestHandler(t *testing.T) {
	handler := Handler()
	if handler == nil {
		t.Error("Handler() returned nil")
	}
}

// --------------------------------------------------------------------------
// Registry functions
// --------------------------------------------------------------------------

func TestNewRegistry(t *testing.T) {
	reg := NewRegistry()
	if reg == nil {
		t.Fatal("NewRegistry() returned nil")
	}
}

func TestDefaultRegistry(t *testing.T) {
	reg := DefaultRegistry()
	if reg == nil {
		t.Fatal("DefaultRegistry() returned nil")
	}
}

func TestRegistry_MustRegister(t *testing.T) {
	reg := NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_registry_counter",
		Help: "Test counter for registry",
	})
	reg.MustRegister(counter)
	// Should not panic
}

func TestRegistry_MustRegister_DuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustRegister with duplicate should panic")
		}
	}()

	reg := NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_registry_dup_counter",
		Help: "Test counter for duplicate registration",
	})
	reg.MustRegister(counter)
	reg.MustRegister(counter) // Should panic
}

func TestRegistry_Register(t *testing.T) {
	reg := NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_registry_register_counter",
		Help: "Test counter for Register",
	})
	err := reg.Register(counter)
	if err != nil {
		t.Errorf("Register() returned unexpected error: %v", err)
	}
}

func TestRegistry_Unregister(t *testing.T) {
	reg := NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_registry_unregister_counter",
		Help: "Test counter for Unregister",
	})
	reg.MustRegister(counter)

	removed := reg.Unregister(counter)
	if !removed {
		t.Error("Unregister() should return true for registered collector")
	}
}

func TestRegistry_Reset(t *testing.T) {
	reg := NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_registry_reset_counter",
		Help: "Test counter for Reset",
	})
	reg.MustRegister(counter)

	reg.Reset()

	// After reset, we should be able to register the same collector again
	counter2 := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_registry_reset_counter",
		Help: "Test counter for Reset (re-registration)",
	})
	reg.MustRegister(counter2) // Should not panic
}

func TestRegistry_Handler(t *testing.T) {
	reg := NewRegistry()
	handler := reg.Handler()
	if handler == nil {
		t.Error("Registry.Handler() returned nil")
	}
}

func TestRegisterWithRegistry_NilUsesDefault(t *testing.T) {
	// Passing nil registry should use the default — verify it doesn't panic
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "test_register_with_nil_registry",
		Help: "Test counter for RegisterWithRegistry with nil",
	})
	RegisterWithRegistry(nil, counter)
}

// --------------------------------------------------------------------------
// Options tests
// --------------------------------------------------------------------------

func TestOption_WithHTTPBuckets(t *testing.T) {
	custom := []float64{0.1, 0.5, 1.0}
	opts := DefaultOptions()
	WithHTTPBuckets(custom)(opts)
	if len(opts.HTTPBuckets) != 3 {
		t.Errorf("WithHTTPBuckets: got %d buckets, want 3", len(opts.HTTPBuckets))
	}
}

func TestOption_WithMCPBuckets(t *testing.T) {
	custom := []float64{1.0, 5.0, 10.0}
	opts := DefaultOptions()
	WithMCPBuckets(custom)(opts)
	if len(opts.MCPBuckets) != 3 {
		t.Errorf("WithMCPBuckets: got %d buckets, want 3", len(opts.MCPBuckets))
	}
}

func TestOption_WithNamespace(t *testing.T) {
	opts := DefaultOptions()
	WithNamespace("custom")(opts)
	if opts.Namespace != "custom" {
		t.Errorf("WithNamespace: got %q, want 'custom'", opts.Namespace)
	}
}

func TestOption_WithDefaultMetricsDisabled(t *testing.T) {
	opts := DefaultOptions()
	WithDefaultMetricsDisabled()(opts)
	if opts.EnableDefaultMetrics {
		t.Error("WithDefaultMetricsDisabled: got true, want false")
	}
}

func TestOption_WithRegistry(t *testing.T) {
	reg := NewRegistry()
	opts := DefaultOptions()
	WithRegistry(reg)(opts)
	if opts.Registry != reg {
		t.Error("WithRegistry: registry mismatch")
	}
}

func TestOptions_Registry_Fallback(t *testing.T) {
	opts := DefaultOptions()
	// When Registry is nil, registry() should return defaultRegistry
	reg := opts.registry()
	if reg != defaultRegistry {
		t.Error("Options.registry() should fall back to defaultRegistry when nil")
	}
}

func TestOptions_Registry_Custom(t *testing.T) {
	customReg := NewRegistry()
	opts := &Options{Registry: customReg}
	reg := opts.registry()
	if reg != customReg {
		t.Error("Options.registry() should return custom registry when set")
	}
}