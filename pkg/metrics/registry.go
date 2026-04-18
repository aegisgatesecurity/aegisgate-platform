// Copyright 2024 AegisGate Security. All rights reserved.
//
// Registry management for Prometheus metrics. Supports both the default
// global registry and isolated custom registries for testing and
// multi-tenant deployments.
//
// # Default Registry
//
// The default registry is used by all package-level metric variables and
// convenience functions. It is automatically registered during init().
//
// # Custom Registries
//
// For testing and isolation, create a NewRegistry() and pass it via
// Options when creating metric collectors. This prevents test metrics
// from leaking into production endpoints.
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry wraps a Prometheus registry with thread-safe metric management.
// It supports both the global default registry and isolated registries for testing.
type Registry struct {
	mu       sync.RWMutex
	registry *prometheus.Registry
}

// defaultRegistry is the global singleton used by package-level functions.
var defaultRegistry *Registry

func init() {
	defaultRegistry = NewRegistry()
}

// NewRegistry creates a new isolated Prometheus registry.
// Use this for testing or multi-tenant scenarios where metric sets
// must be kept separate from the default registry.
func NewRegistry() *Registry {
	return &Registry{
		registry: prometheus.NewRegistry(),
	}
}

// DefaultRegistry returns the global default registry.
// All package-level convenience functions use this registry.
func DefaultRegistry() *Registry {
	return defaultRegistry
}

// MustRegister registers one or more collectors with the registry.
// Panics if a collector with the same descriptor is already registered,
// matching the behavior of prometheus.MustRegister.
func (r *Registry) MustRegister(collectors ...prometheus.Collector) {
	r.registry.MustRegister(collectors...)
}

// Register attempts to register a collector. Returns an error if a
// collector with the same descriptor is already registered.
func (r *Registry) Register(collector prometheus.Collector) error {
	return r.registry.Register(collector)
}

// Unregister removes a collector from the registry.
// Returns true if the collector was found and removed.
func (r *Registry) Unregister(collector prometheus.Collector) bool {
	return r.registry.Unregister(collector)
}

// Gather collects all metrics from the registry and returns them
// as metric families. This delegates to the underlying Prometheus registry.
func (r *Registry) Gather() ([]interface{}, error) {
	families, err := r.registry.Gather()
	if err != nil {
		return nil, err
	}
	result := make([]interface{}, len(families))
	for i, f := range families {
		result[i] = f
	}
	return result, nil
}

// Reset clears all collectors from the registry by recreating it.
// This is primarily useful for testing to start with a clean slate.
func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registry = prometheus.NewRegistry()
}

// Handler returns an HTTP handler that serves metrics from this registry.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// RegisterWithRegistry is a convenience function that registers collectors
// with a specific registry. Falls back to the default registry if reg is nil.
func RegisterWithRegistry(reg *Registry, collectors ...prometheus.Collector) {
	if reg == nil {
		reg = defaultRegistry
	}
	reg.MustRegister(collectors...)
}