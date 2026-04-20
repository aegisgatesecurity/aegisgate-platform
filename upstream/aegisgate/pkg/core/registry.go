// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package core provides the module registry for managing all AegisGate modules.
package core

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Registry manages all registered modules and their lifecycle.
type Registry struct {
	mu             sync.RWMutex
	modules        map[string]Module
	status         map[string]ModuleStatus
	configs        map[string]ModuleConfig
	capabilities   map[string]*Capability
	licenseManager *LicenseManager
	initialized    bool
	startTime      time.Time
	healthInterval time.Duration
	healthCancel   context.CancelFunc
}

// RegistryConfig contains configuration for the registry.
type RegistryConfig struct {
	LicenseKey     string
	HealthInterval time.Duration
}

// NewRegistry creates a new module registry.
func NewRegistry(config *RegistryConfig) *Registry {
	if config == nil {
		config = &RegistryConfig{}
	}
	if config.HealthInterval == 0 {
		config.HealthInterval = 30 * time.Second
	}

	return &Registry{
		modules:        make(map[string]Module),
		status:         make(map[string]ModuleStatus),
		configs:        make(map[string]ModuleConfig),
		capabilities:   make(map[string]*Capability),
		licenseManager: NewLicenseManager(config.LicenseKey),
		healthInterval: config.HealthInterval,
	}
}

// Register adds a module to the registry.
func (r *Registry) Register(module Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	meta := module.Metadata()
	id := meta.ID

	if _, exists := r.modules[id]; exists {
		return fmt.Errorf("module %q already registered", id)
	}

	// Store default config
	defaultConfig := ModuleConfig{Enabled: true}
	if mc, ok := module.(ModuleWithConfig); ok {
		defaultConfig = mc.DefaultConfig()
	}

	r.modules[id] = module
	r.status[id] = StatusRegistered
	r.configs[id] = defaultConfig

	// Allow module to access registry
	module.SetRegistry(r)

	// Register capabilities
	for _, capID := range module.Provides() {
		r.capabilities[capID] = &Capability{
			ID:         capID,
			Name:       capID, // Could be enhanced with a capability registry
			ProviderID: id,
			Version:    meta.Version,
		}
	}

	return nil
}

// Unregister removes a module from the registry.
func (r *Registry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	module, exists := r.modules[id]
	if !exists {
		return fmt.Errorf("module %q not found", id)
	}

	// Stop module if active
	if r.status[id] == StatusActive {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := module.Stop(ctx); err != nil {
			return fmt.Errorf("failed to stop module %q: %w", id, err)
		}
	}

	// Remove capabilities
	for _, capID := range module.Provides() {
		delete(r.capabilities, capID)
	}

	delete(r.modules, id)
	delete(r.status, id)
	delete(r.configs, id)

	return nil
}

// Get retrieves a module by ID.
func (r *Registry) Get(id string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	module, exists := r.modules[id]
	return module, exists
}

// GetStatus returns the current status of a module.
func (r *Registry) GetStatus(id string) ModuleStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status[id]
}

// SetConfig updates the configuration for a module.
func (r *Registry) SetConfig(id string, config ModuleConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	module, exists := r.modules[id]
	if !exists {
		return fmt.Errorf("module %q not found", id)
	}

	// Validate config if module supports it
	if mc, ok := module.(ModuleWithConfig); ok {
		if err := mc.ValidateConfig(config); err != nil {
			return fmt.Errorf("invalid config for module %q: %w", id, err)
		}
	}

	r.configs[id] = config
	return nil
}

// GetConfig returns the current configuration for a module.
func (r *Registry) GetConfig(id string) (ModuleConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	config, exists := r.configs[id]
	return config, exists
}

// Initialize initializes all registered modules in dependency order.
func (r *Registry) Initialize(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.initialized {
		return fmt.Errorf("registry already initialized")
	}

	// Get initialization order based on dependencies
	order, err := r.getInitializationOrder()
	if err != nil {
		return fmt.Errorf("dependency resolution failed: %w", err)
	}

	// Initialize modules in order
	for _, id := range order {
		module := r.modules[id]
		config := r.configs[id]

		// Check license for non-core modules
		meta := module.Metadata()
		if meta.Tier > TierCommunity {
			if !r.licenseManager.IsModuleLicensed(meta.ID, meta.Tier) {
				r.status[id] = StatusDisabled
				continue
			}
		}

		if !config.Enabled {
			r.status[id] = StatusDisabled
			continue
		}

		if err := module.Initialize(ctx, config); err != nil {
			r.status[id] = StatusError
			return fmt.Errorf("failed to initialize module %q: %w", id, err)
		}
		r.status[id] = StatusInitialized
	}

	r.initialized = true
	return nil
}

// Start starts all initialized modules in dependency order.
func (r *Registry) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	order, err := r.getInitializationOrder()
	if err != nil {
		return err
	}

	for _, id := range order {
		if r.status[id] != StatusInitialized {
			continue
		}

		module := r.modules[id]

		// Call lifecycle hook if available
		if ml, ok := module.(ModuleWithLifecycle); ok {
			if lc := ml.Lifecycle(); lc != nil && lc.OnBeforeStart != nil {
				if err := lc.OnBeforeStart(ctx); err != nil {
					r.status[id] = StatusError
					return fmt.Errorf("lifecycle error for module %q: %w", id, err)
				}
			}
		}

		if err := module.Start(ctx); err != nil {
			r.status[id] = StatusError
			return fmt.Errorf("failed to start module %q: %w", id, err)
		}
		r.status[id] = StatusActive

		// Call after start hook
		if ml, ok := module.(ModuleWithLifecycle); ok {
			if lc := ml.Lifecycle(); lc != nil && lc.OnAfterStart != nil {
				if err := lc.OnAfterStart(ctx); err != nil {
					// Log the error but don't fail the start
					_ = err
				}
			}
		}
	}

	r.startTime = time.Now()

	// Start health monitoring
	healthCtx, cancel := context.WithCancel(context.Background())
	r.healthCancel = cancel
	go r.healthMonitor(healthCtx)

	return nil
}

// Stop stops all modules in reverse dependency order.
func (r *Registry) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Stop health monitoring
	if r.healthCancel != nil {
		r.healthCancel()
	}

	order, err := r.getInitializationOrder()
	if err != nil {
		return err
	}

	// Reverse order for shutdown
	for i := len(order) - 1; i >= 0; i-- {
		id := order[i]
		if r.status[id] != StatusActive {
			continue
		}

		module := r.modules[id]

		// Call lifecycle hook
		if ml, ok := module.(ModuleWithLifecycle); ok {
			if lc := ml.Lifecycle(); lc != nil && lc.OnBeforeStop != nil {
				if err := lc.OnBeforeStop(ctx); err != nil {
					// Log the error but continue stopping
					_ = err
				}
			}
		}

		if err := module.Stop(ctx); err != nil {
			r.status[id] = StatusError
			// Continue stopping other modules
		} else {
			r.status[id] = StatusInitialized
		}

		// Call after stop hook
		if ml, ok := module.(ModuleWithLifecycle); ok {
			if lc := ml.Lifecycle(); lc != nil && lc.OnAfterStop != nil {
				if err := lc.OnAfterStop(ctx); err != nil {
					// Log the error but continue
					_ = err
				}
			}
		}
	}

	return nil
}

// Enable activates a previously disabled module.
func (r *Registry) Enable(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	module, exists := r.modules[id]
	if !exists {
		return fmt.Errorf("module %q not found", id)
	}

	if r.status[id] == StatusActive {
		return nil // Already active
	}

	// Check dependencies
	for _, depID := range module.Dependencies() {
		if r.status[depID] != StatusActive {
			return fmt.Errorf("dependency %q not active for module %q", depID, id)
		}
	}

	// Check license
	meta := module.Metadata()
	if meta.Tier > TierCommunity {
		if !r.licenseManager.IsModuleLicensed(meta.ID, meta.Tier) {
			return fmt.Errorf("module %q requires a valid license", id)
		}
	}

	config := r.configs[id]
	config.Enabled = true

	if err := module.Initialize(ctx, config); err != nil {
		r.status[id] = StatusError
		return err
	}
	r.status[id] = StatusInitialized

	if err := module.Start(ctx); err != nil {
		r.status[id] = StatusError
		return err
	}
	r.status[id] = StatusActive

	return nil
}

// Disable deactivates a module.
func (r *Registry) Disable(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	module, exists := r.modules[id]
	if !exists {
		return fmt.Errorf("module %q not found", id)
	}

	// Check if other modules depend on this one
	for modID, mod := range r.modules {
		if modID == id {
			continue
		}
		for _, depID := range mod.Dependencies() {
			if depID == id && r.status[modID] == StatusActive {
				return fmt.Errorf("cannot disable module %q: module %q depends on it", id, modID)
			}
		}
	}

	if r.status[id] == StatusActive {
		if err := module.Stop(ctx); err != nil {
			return err
		}
	}

	r.status[id] = StatusDisabled
	r.configs[id] = ModuleConfig{Enabled: false}

	return nil
}

// List returns all registered module IDs.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.modules))
	for id := range r.modules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ListByTier returns module IDs for a specific tier.
func (r *Registry) ListByTier(tier Tier) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0)
	for id, module := range r.modules {
		if module.Metadata().Tier == tier {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ListByCategory returns module IDs for a specific category.
func (r *Registry) ListByCategory(category ModuleCategory) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0)
	for id, module := range r.modules {
		if module.Metadata().Category == category {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// GetCapability returns the module providing a capability.
func (r *Registry) GetCapability(capID string) (*Capability, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cap, exists := r.capabilities[capID]
	return cap, exists
}

// HasCapability checks if a capability is available.
func (r *Registry) HasCapability(capID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.capabilities[capID]
	return exists
}

// Health returns health status for all modules.
func (r *Registry) Health(ctx context.Context) map[string]HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	health := make(map[string]HealthStatus)
	for id, module := range r.modules {
		if r.status[id] == StatusActive {
			health[id] = module.Health(ctx)
		} else {
			health[id] = HealthStatus{
				Healthy:   r.status[id] != StatusError,
				Message:   fmt.Sprintf("module %s", r.status[id]),
				LastCheck: time.Now(),
			}
		}
	}
	return health
}

// getInitializationOrder returns module IDs in dependency order.
func (r *Registry) getInitializationOrder() ([]string, error) {
	visited := make(map[string]bool)
	visiting := make(map[string]bool)
	order := make([]string, 0)

	var visit func(id string) error
	visit = func(id string) error {
		if visited[id] {
			return nil
		}
		if visiting[id] {
			return fmt.Errorf("circular dependency detected involving %q", id)
		}

		module, exists := r.modules[id]
		if !exists {
			return fmt.Errorf("module %q not found", id)
		}

		visiting[id] = true

		// Visit required dependencies
		for _, depID := range module.Dependencies() {
			if err := visit(depID); err != nil {
				return err
			}
		}

		// Visit optional dependencies (ignore if not registered)
		for _, depID := range module.OptionalDependencies() {
			if _, exists := r.modules[depID]; exists {
				if err := visit(depID); err != nil {
					return err
				}
			}
		}

		visiting[id] = false
		visited[id] = true
		order = append(order, id)

		return nil
	}

	// Visit all modules
	for id := range r.modules {
		if !visited[id] {
			if err := visit(id); err != nil {
				return nil, err
			}
		}
	}

	return order, nil
}

// healthMonitor periodically checks module health.
func (r *Registry) healthMonitor(ctx context.Context) {
	ticker := time.NewTicker(r.healthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.RLock()
			for id, module := range r.modules {
				if r.status[id] == StatusActive {
					health := module.Health(ctx)
					if !health.Healthy {
						// Could trigger alerts or auto-restart
						_ = health // Log this in production
					}
				}
			}
			r.mu.RUnlock()
		}
	}
}

// Uptime returns how long the registry has been running.
func (r *Registry) Uptime() time.Duration {
	if r.startTime.IsZero() {
		return 0
	}
	return time.Since(r.startTime)
}
