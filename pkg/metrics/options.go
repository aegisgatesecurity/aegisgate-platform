// Functional options for configuring AegisGate metrics.
// Options allow customization of histogram buckets, registry selection,
// and cardinality limits without changing the package API.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Options holds configuration for the metrics subsystem.
// Use WithOptions() to create a configured metrics provider,
// or use package-level defaults for simple setups.
type Options struct {
	// Registry is the Prometheus registry to use for registering metrics.
	// If nil, the default global registry is used.
	// Useful for isolated testing or multi-tenant deployments.
	Registry *Registry

	// HTTPBuckets defines histogram buckets for HTTP request duration.
	// If nil, uses DefaultHTTPBuckets.
	HTTPBuckets []float64

	// MCPBuckets defines histogram buckets for MCP request duration.
	// If nil, uses DefaultMCPBuckets.
	MCPBuckets []float64

	// Namespace is prepended to all metric names.
	// Default: "aegisgate"
	Namespace string

	// EnableDefaultMetrics controls whether the standard set of
	// platform metrics (HTTP, MCP, tier, audit) is registered.
	// Set to false if you want to register only specific metrics.
	EnableDefaultMetrics bool
}

// DefaultOptions returns the recommended production configuration.
func DefaultOptions() *Options {
	return &Options{
		Registry:             nil, // use global default
		HTTPBuckets:          DefaultHTTPBuckets,
		MCPBuckets:           DefaultMCPBuckets,
		Namespace:            "aegisgate",
		EnableDefaultMetrics: true,
	}
}

// CustomBuckets creates a slice of float64 buckets from a list of time.Duration
// values, converting each to seconds (as required by Prometheus histograms).
// This is a convenience function for creating custom bucket configurations.
//
// Example:
//
//	buckets := CustomBuckets(10*time.Millisecond, 50*time.Millisecond, 100*time.Millisecond)
func CustomBuckets(durations ...time.Duration) []float64 {
	buckets := make([]float64, len(durations))
	for i, d := range durations {
		buckets[i] = d.Seconds()
	}
	return buckets
}

// Option is a functional option that modifies Options.
type Option func(*Options)

// WithRegistry sets a custom Prometheus registry for metric registration.
// Use this for isolated testing or multi-tenant deployments where each
// tenant needs its own metric registry.
func WithRegistry(reg *Registry) Option {
	return func(o *Options) {
		o.Registry = reg
	}
}

// WithHTTPBuckets configures custom histogram buckets for HTTP request duration.
// The default buckets are suitable for most web service workloads.
// Use CustomBuckets() to convert time.Duration values to float64 seconds.
func WithHTTPBuckets(buckets []float64) Option {
	return func(o *Options) {
		o.HTTPBuckets = buckets
	}
}

// WithMCPBuckets configures custom histogram buckets for MCP request duration.
// MCP tool calls may have longer tails than typical HTTP requests,
// so the defaults include higher upper bounds.
func WithMCPBuckets(buckets []float64) Option {
	return func(o *Options) {
		o.MCPBuckets = buckets
	}
}

// WithNamespace sets a custom namespace prefix for all metric names.
// Default is "aegisgate". Useful for deployments where metric name
// collision is a concern.
func WithNamespace(namespace string) Option {
	return func(o *Options) {
		o.Namespace = namespace
	}
}

// WithDefaultMetricsDisabled prevents automatic registration of the
// default platform metrics. Use this when you need fine-grained control
// over which metrics are registered, such as in testing.
func WithDefaultMetricsDisabled() Option {
	return func(o *Options) {
		o.EnableDefaultMetrics = false
	}
}

// registry returns the effective registry for these options.
// Falls back to the global default registry if none is configured.
func (o *Options) registry() *Registry {
	if o.Registry == nil {
		return defaultRegistry
	}
	return o.Registry
}

// registerCollector registers a collector with the effective registry.
func (o *Options) registerCollector(c prometheus.Collector) {
	o.registry().MustRegister(c)
}

// DefaultHTTPBuckets defines sensible defaults for HTTP request duration histograms.
// These cover the range from fast cache hits (5ms) to slow upstream responses (10s).
var DefaultHTTPBuckets = []float64{
	0.005, // 5ms   - cache hits, health checks
	0.01,  // 10ms  - fast proxy passes
	0.025, // 25ms  - typical API calls
	0.05,  // 50ms  - proxy with light scanning
	0.1,   // 100ms - proxy with moderate scanning
	0.25,  // 250ms - proxy with full security stack
	0.5,   // 500ms - MCP tool calls, slow upstream
	1.0,   // 1s    - very slow upstream, MCP inference
	2.5,   // 2.5s  - timeout territory
	5.0,   // 5s    - extreme latency
	10.0,  // 10s   - near timeout
}

// DefaultMCPBuckets defines sensible defaults for MCP request duration histograms.
// MCP tool calls (especially LLM operations) have higher latency than
// typical HTTP requests, so the buckets extend to longer durations.
var DefaultMCPBuckets = []float64{
	0.05, // 50ms  - fast tool lookups
	0.1,  // 100ms - simple tool execution
	0.25, // 250ms - moderate tool execution
	0.5,  // 500ms - typical MCP operation
	1.0,  // 1s    - LLM inference (small model)
	2.5,  // 2.5s  - LLM inference (medium model)
	5.0,  // 5s    - LLM inference (large model)
	10.0, // 10s   - complex multi-step operations
	30.0, // 30s   - very slow operations, near timeout
	60.0, // 60s   - streaming completions, timeouts
}
