// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package plugin provides the plugin manager for loading and managing plugins.
package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"plugin"
	"sort"
	"sync"
	"time"
)

// Manager handles the lifecycle of plugins
type Manager struct {
	mu           sync.RWMutex
	plugins      map[string]*PluginState
	hookPlugins  map[HookType][]*PluginState
	capabilities map[string][]string
	config       *ManagerConfig
	logger       *slog.Logger
	started      bool
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

// ManagerConfig contains configuration for the plugin manager
type ManagerConfig struct {
	// PluginDirs directories to search for plugins
	PluginDirs []string
	// PluginConfig configuration for each plugin
	PluginConfig map[string]PluginConfig
	// EnabledPluginTypes only load plugins of these types (empty = all)
	EnabledPluginTypes []Type
	// DisabledPlugins list of plugin IDs to skip loading
	DisabledPlugins []string
	// WatchDir watch for plugin changes (development)
	WatchDir bool
	// PluginTimeout default timeout for plugin operations
	PluginTimeout time.Duration
	// EnablePeriodic enable periodic hook processing
	EnablePeriodic bool
}

// DefaultManagerConfig returns sensible defaults
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		PluginDirs:     []string{"./plugins", "/etc/aegisgate/plugins"},
		PluginConfig:   make(map[string]PluginConfig),
		PluginTimeout:  30 * time.Second,
		EnablePeriodic: true,
	}
}

// NewManager creates a new plugin manager
func NewManager(config *ManagerConfig) *Manager {
	if config == nil {
		config = DefaultManagerConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		plugins:      make(map[string]*PluginState),
		hookPlugins:  make(map[HookType][]*PluginState),
		capabilities: make(map[string][]string),
		config:       config,
		logger:       slog.Default(),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Register registers a plugin with the manager
func (m *Manager) Register(p Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	meta := p.Metadata()

	if meta.ID == "" {
		return fmt.Errorf("plugin ID cannot be empty")
	}

	if _, exists := m.plugins[meta.ID]; exists {
		return fmt.Errorf("plugin %q already registered", meta.ID)
	}

	// Get plugin configuration
	cfg := m.config.PluginConfig[meta.ID]
	if !cfg.Enabled {
		cfg.Enabled = true // Default to enabled
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = m.config.PluginTimeout
	}

	state := &PluginState{
		Metadata: meta,
		Config:   cfg,
		Status:   StatusUnregistered,
		Plugin:   p,
	}

	m.plugins[meta.ID] = state

	// Register for hooks
	for _, hook := range p.Hooks() {
		m.hookPlugins[hook] = append(m.hookPlugins[hook], state)
	}

	// Register capabilities
	for _, cap := range meta.Capabilities {
		m.capabilities[cap] = append(m.capabilities[cap], meta.ID)
	}

	m.logger.Debug("Plugin registered", "id", meta.ID, "name", meta.Name, "hooks", p.Hooks())

	return nil
}

// LoadGoPlugin loads a plugin from a Go plugin file (.so)
func (m *Manager) LoadGoPlugin(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Open the plugin
	pl, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin %q: %w", path, err)
	}

	// Look for the plugin symbol
	sym, err := pl.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("failed to find Plugin symbol in %q: %w", path, err)
	}

	// Type assert to our Plugin interface
	p, ok := sym.(Plugin)
	if !ok {
		return fmt.Errorf("plugin %q does not implement plugin.Plugin interface", path)
	}

	// Register the plugin
	meta := p.Metadata()
	if _, exists := m.plugins[meta.ID]; exists {
		return fmt.Errorf("plugin %q already loaded", meta.ID)
	}

	// Get plugin configuration
	cfg := m.config.PluginConfig[meta.ID]
	if !cfg.Enabled {
		cfg.Enabled = true
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = m.config.PluginTimeout
	}

	state := &PluginState{
		Metadata: meta,
		Config:   cfg,
		Status:   StatusUnregistered,
		Plugin:   p,
	}

	m.plugins[meta.ID] = state

	// Register for hooks
	for _, hook := range p.Hooks() {
		m.hookPlugins[hook] = append(m.hookPlugins[hook], state)
	}

	// Register capabilities
	for _, cap := range meta.Capabilities {
		m.capabilities[cap] = append(m.capabilities[cap], meta.ID)
	}

	m.logger.Info("Plugin loaded from file", "id", meta.ID, "path", path)

	return nil
}

// Init initializes all registered plugins
func (m *Manager) Init(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Initializing plugins", "count", len(m.plugins))

	// Check dependencies
	if err := m.checkDependencies(); err != nil {
		return fmt.Errorf("dependency check failed: %w", err)
	}

	// Sort plugins by priority for initialization order
	plugins := m.sortedPlugins()

	for _, state := range plugins {
		if !state.Config.Enabled {
			m.logger.Debug("Skipping disabled plugin", "id", state.Metadata.ID)
			continue
		}

		m.logger.Debug("Initializing plugin", "id", state.Metadata.ID)

		if err := state.Plugin.Init(ctx, state.Config); err != nil {
			state.Status = StatusError
			state.LastError = err
			return fmt.Errorf("failed to initialize plugin %q: %w", state.Metadata.ID, err)
		}

		state.Status = StatusInitialized
	}

	m.logger.Info("All plugins initialized successfully")
	return nil
}

// Start starts all initialized plugins
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()

	if m.started {
		m.mu.Unlock()
		return fmt.Errorf("plugin manager already started")
	}

	m.logger.Info("Starting plugins", "count", len(m.plugins))

	plugins := m.sortedPlugins()

	for _, state := range plugins {
		if !state.Config.Enabled {
			continue
		}

		if state.Status != StatusInitialized {
			m.logger.Debug("Skipping plugin not in initialized state", "id", state.Metadata.ID, "status", state.Status)
			continue
		}

		m.logger.Debug("Starting plugin", "id", state.Metadata.ID)

		state.Status = StatusStarting
		if err := state.Plugin.Start(ctx); err != nil {
			state.Status = StatusError
			state.LastError = err
			m.mu.Unlock()
			return fmt.Errorf("failed to start plugin %q: %w", state.Metadata.ID, err)
		}

		state.Status = StatusRunning
		state.StartedAt = time.Now()
	}

	m.started = true

	// Copy periodic plugins before unlocking
	var periodicPlugins []*PluginState
	if m.config.EnablePeriodic {
		for _, state := range m.plugins {
			if _, ok := state.Plugin.(PeriodicTask); ok {
				if state.Status == StatusRunning {
					periodicPlugins = append(periodicPlugins, state)
				}
			}
		}
	}

	m.mu.Unlock()

	// Start periodic tasks in background (after releasing lock to avoid deadlock)
	for _, state := range periodicPlugins {
		go m.runPeriodicTask(state)
	}

	m.logger.Info("All plugins started successfully")
	return nil
}

// Stop stops all running plugins gracefully
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.started {
		return nil
	}

	m.logger.Info("Stopping plugins", "count", len(m.plugins))

	// Cancel periodic tasks
	m.cancel()

	// Stop plugins in reverse order
	plugins := m.sortedPlugins()
	for i := len(plugins) - 1; i >= 0; i-- {
		state := plugins[i]
		if state.Status != StatusRunning {
			continue
		}

		m.logger.Debug("Stopping plugin", "id", state.Metadata.ID)

		state.Status = StatusStopping
		if err := state.Plugin.Stop(ctx); err != nil {
			m.logger.Error("Error stopping plugin", "id", state.Metadata.ID, "error", err)
			state.LastError = err
			continue
		}

		state.Status = StatusStopped
	}

	m.started = false
	m.wg.Wait()

	m.logger.Info("All plugins stopped")
	return nil
}

// ExecuteHook executes a hook across all registered plugins
func (m *Manager) ExecuteHook(ctx context.Context, hookType HookType, fn func(ctx context.Context, state *PluginState) (*HookResult, error)) (*HookResult, error) {
	m.mu.RLock()
	plugins := m.hookPlugins[hookType]
	m.mu.RUnlock()

	if len(plugins) == 0 {
		result := DefaultHookResult()
		return &result, nil
	}

	// Create request context for metadata passing
	reqCtx := &RequestContext{
		Metadata: make(map[string]interface{}),
	}

	result := DefaultHookResult()

	for _, state := range plugins {
		if state.Status != StatusRunning {
			continue
		}

		if !state.Config.Enabled {
			continue
		}

		// Execute with timeout
		timeout := state.Config.Timeout
		if timeout == 0 {
			timeout = m.config.PluginTimeout
		}

		hookCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		hookResult, err := fn(hookCtx, state)
		if err != nil {
			m.logger.Error("Hook execution error", "hook", hookType, "plugin", state.Metadata.ID, "error", err)
			result.Error = err
			result.Continue = false
			result.Stop = true
			return &result, err
		}

		if hookResult != nil {
			// Merge metadata
			for k, v := range hookResult.Metadata {
				reqCtx.Metadata[k] = v
			}

			if !hookResult.Continue {
				result.Continue = false
			}
			if hookResult.Stop {
				result.Stop = true
				break
			}
		}
	}

	result.Metadata = reqCtx.Metadata
	return &result, nil
}

// GetPlugin returns a plugin by ID
func (m *Manager) GetPlugin(id string) (*PluginState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.plugins[id]
	return state, ok
}

// ListPlugins returns all registered plugins
func (m *Manager) ListPlugins() []*PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make([]*PluginState, 0, len(m.plugins))
	for _, state := range m.plugins {
		states = append(states, state)
	}
	return states
}

// GetPluginsByHook returns all plugins registered for a specific hook
func (m *Manager) GetPluginsByHook(hookType HookType) []*PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hookPlugins[hookType]
}

// HasCapability checks if a capability is available
func (m *Manager) HasCapability(capability string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.capabilities[capability]
	return ok
}

// GetPluginsByCapability returns all plugins providing a capability
func (m *Manager) GetPluginsByCapability(capability string) []*PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pluginIDs := m.capabilities[capability]
	states := make([]*PluginState, 0, len(pluginIDs))
	for _, id := range pluginIDs {
		if state, ok := m.plugins[id]; ok {
			states = append(states, state)
		}
	}
	return states
}

// UpdateConfig updates a plugin's configuration at runtime
func (m *Manager) UpdateConfig(pluginID string, config PluginConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.plugins[pluginID]
	if !ok {
		return fmt.Errorf("plugin %q not found", pluginID)
	}

	if state.Status == StatusRunning {
		return fmt.Errorf("cannot update config while plugin is running")
	}

	state.Config = config
	return nil
}

// GetStatus returns the overall status of all plugins
func (m *Manager) GetStatus() map[string]Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := make(map[string]Status)
	for id, state := range m.plugins {
		status[id] = state.Status
	}
	return status
}

// sortedPlugins returns plugins sorted by priority
func (m *Manager) sortedPlugins() []*PluginState {
	plugins := make([]*PluginState, 0, len(m.plugins))
	for _, state := range m.plugins {
		plugins = append(plugins, state)
	}

	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Config.Priority < plugins[j].Config.Priority
	})

	return plugins
}

// checkDependencies verifies all plugin dependencies are met
func (m *Manager) checkDependencies() error {
	for id, state := range m.plugins {
		for _, dep := range state.Metadata.Dependencies {
			if _, exists := m.plugins[dep]; !exists {
				return fmt.Errorf("plugin %q depends on %q which is not loaded", id, dep)
			}
		}
	}
	return nil
}

// runPeriodicTask runs the periodic task for a plugin
func (m *Manager) runPeriodicTask(state *PluginState) {
	defer m.wg.Done()

	pt, ok := state.Plugin.(PeriodicTask)
	if !ok {
		return
	}

	interval := pt.Interval()
	if interval <= 0 {
		interval = 1 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	m.logger.Debug("Starting periodic task", "plugin", state.Metadata.ID, "interval", interval)

	for {
		select {
		case <-m.ctx.Done():
			m.logger.Debug("Periodic task stopping", "plugin", state.Metadata.ID)
			return
		case <-ticker.C:
			periodicCtx := &PeriodicContext{
				Timestamp: time.Now(),
				Interval:  interval,
				Metadata:  make(map[string]interface{}),
			}

			hookCtx, cancel := context.WithTimeout(m.ctx, state.Config.Timeout)
			if err := pt.OnPeriodic(hookCtx, periodicCtx); err != nil {
				m.logger.Error("Periodic task error", "plugin", state.Metadata.ID, "error", err)
			}
			cancel()
		}
	}
}
