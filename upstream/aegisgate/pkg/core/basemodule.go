// Package core provides a base module implementation for easy module development.
package core

import (
	"context"
	"sync"
	"time"
)

// Now is a variable for testing purposes.
var Now = func() time.Time {
	return time.Now()
}

// BaseModule provides a default implementation of the Module interface.
// Modules can embed this struct to avoid implementing all methods.
type BaseModule struct {
	mu       sync.RWMutex
	meta     ModuleMetadata
	status   ModuleStatus
	config   ModuleConfig
	registry *Registry

	// Lifecycle hooks
	beforeStart func(ctx context.Context) error
	afterStart  func(ctx context.Context) error
	beforeStop  func(ctx context.Context) error
	afterStop   func(ctx context.Context) error
	onError     func(ctx context.Context, err error)
}

// NewBaseModule creates a new base module with the given metadata.
func NewBaseModule(meta ModuleMetadata) *BaseModule {
	return &BaseModule{
		meta:   meta,
		status: StatusUnregistered,
		config: ModuleConfig{Enabled: true},
	}
}

// Metadata returns the module's metadata.
func (m *BaseModule) Metadata() ModuleMetadata {
	return m.meta
}

// Initialize prepares the module for operation.
func (m *BaseModule) Initialize(ctx context.Context, config ModuleConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = config
	m.status = StatusInitialized
	return nil
}

// Start begins the module's operation.
func (m *BaseModule) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = StatusActive
	return nil
}

// Stop gracefully shuts down the module.
func (m *BaseModule) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = StatusInitialized
	return nil
}

// Status returns the current operational status.
func (m *BaseModule) Status() ModuleStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// Health returns the module's health status.
func (m *BaseModule) Health(ctx context.Context) HealthStatus {
	return HealthStatus{
		Healthy:   m.status == StatusActive,
		Message:   m.status.String(),
		LastCheck: Now(),
	}
}

// Dependencies returns the IDs of modules this module depends on.
func (m *BaseModule) Dependencies() []string {
	return []string{}
}

// OptionalDependencies returns IDs of modules that enhance functionality.
func (m *BaseModule) OptionalDependencies() []string {
	return []string{}
}

// Provides returns what capabilities this module provides.
func (m *BaseModule) Provides() []string {
	return []string{}
}

// SetRegistry allows the module to access other modules.
func (m *BaseModule) SetRegistry(registry *Registry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registry = registry
}

// GetRegistry returns the module registry.
func (m *BaseModule) GetRegistry() *Registry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.registry
}

// SetStatus updates the module status.
func (m *BaseModule) SetStatus(status ModuleStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = status
}

// GetConfig returns the current module configuration.
func (m *BaseModule) GetConfig() ModuleConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// SetBeforeStart sets the before-start lifecycle hook.
func (m *BaseModule) SetBeforeStart(fn func(ctx context.Context) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.beforeStart = fn
}

// SetAfterStart sets the after-start lifecycle hook.
func (m *BaseModule) SetAfterStart(fn func(ctx context.Context) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.afterStart = fn
}

// SetBeforeStop sets the before-stop lifecycle hook.
func (m *BaseModule) SetBeforeStop(fn func(ctx context.Context) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.beforeStop = fn
}

// SetAfterStop sets the after-stop lifecycle hook.
func (m *BaseModule) SetAfterStop(fn func(ctx context.Context) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.afterStop = fn
}

// SetOnError sets the error handler hook.
func (m *BaseModule) SetOnError(fn func(ctx context.Context, err error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onError = fn
}

// Lifecycle returns the module lifecycle hooks.
func (m *BaseModule) Lifecycle() *ModuleLifecycle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &ModuleLifecycle{
		OnBeforeStart: m.beforeStart,
		OnAfterStart:  m.afterStart,
		OnBeforeStop:  m.beforeStop,
		OnAfterStop:   m.afterStop,
		OnError:       m.onError,
	}
}
