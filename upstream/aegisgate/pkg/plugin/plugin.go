// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package plugin provides the plugin system for AegisGate extensibility.
// It defines the Plugin interface, hook system, and plugin manager.
package plugin

import (
	"context"
	"fmt"
	"time"
)

// Type defines the category of plugin
type Type string

const (
	// TypeFilter filters/modifies requests and responses
	TypeFilter Type = "filter"
	// TypeAuth provides authentication providers
	TypeAuth Type = "auth"
	// TypeAnalytics provides analytics/reporting
	TypeAnalytics Type = "analytics"
	// TypeProcessor processes data in pipeline
	TypeProcessor Type = "processor"
	// TypeExporter exports data to external systems
	TypeExporter Type = "exporter"
	// TypeValidator validates data/policies
	TypeValidator Type = "validator"
)

// HookType defines when a plugin hook is invoked
type HookType string

const (
	// HookRequestReceived When request is first received
	HookRequestReceived HookType = "request_received"
	// HookBeforeForward Before forwarding to upstream
	HookBeforeForward HookType = "before_forward"
	// HookAfterResponse After response received from upstream
	HookAfterResponse HookType = "after_response"
	// HookResponseSent Before response is sent to client
	HookResponseSent HookType = "response_sent"
	// HookConnectionOpen When a new connection is opened
	HookConnectionOpen HookType = "connection_open"
	// HookConnectionClose When a connection is closed
	HookConnectionClose HookType = "connection_close"
	// HookError When an error occurs in the proxy
	HookError HookType = "error"
	// HookPeriodic Run on a periodic interval
	HookPeriodic HookType = "periodic"
)

// Plugin is the core interface that all AegisGate plugins must implement.
// Each plugin can hook into various stages of the proxy lifecycle.
type Plugin interface {
	// Metadata returns plugin information
	Metadata() PluginMetadata

	// Init is called once when the plugin is loaded
	Init(ctx context.Context, config PluginConfig) error

	// Start is called when the plugin should begin operation
	Start(ctx context.Context) error

	// Stop is called when the plugin should gracefully shut down
	Stop(ctx context.Context) error

	// Hooks returns the hooks this plugin implements
	Hooks() []HookType
}

// PluginMetadata contains information about the plugin
type PluginMetadata struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Version     string   `json:"version" yaml:"version"`
	Description string   `json:"description" yaml:"description"`
	Author      string   `json:"author" yaml:"author"`
	Website     string   `json:"website,omitempty" yaml:"website,omitempty"`
	Type        Type     `json:"type" yaml:"type"`
	Tags        []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	// Dependencies lists plugin IDs that must be loaded before this one
	Dependencies []string `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	// Capabilities lists what this plugin provides
	Capabilities []string `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
}

// PluginConfig contains configuration for a specific plugin instance
type PluginConfig struct {
	Enabled     bool                   `json:"enabled" yaml:"enabled"`
	Priority    int                    `json:"priority" yaml:"priority"` // Lower = earlier execution
	Settings    map[string]interface{} `json:"settings" yaml:"settings"`
	Timeout     time.Duration          `json:"timeout" yaml:"timeout"`
	RetryConfig *RetryConfig           `json:"retry,omitempty" yaml:"retry,omitempty"`
}

// RetryConfig defines retry behavior for plugin operations
type RetryConfig struct {
	MaxAttempts  int           `json:"max_attempts" yaml:"max_attempts"`
	InitialDelay time.Duration `json:"initial_delay" yaml:"initial_delay"`
	MaxDelay     time.Duration `json:"max_delay" yaml:"max_delay"`
	Multiplier   float64       `json:"multiplier" yaml:"multiplier"`
}

// DefaultRetryConfig returns sensible defaults for retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     5 * time.Second,
		Multiplier:   2.0,
	}
}

// Status represents the current state of a plugin
type Status int

const (
	StatusUnregistered Status = iota
	StatusInitialized
	StatusStarting
	StatusRunning
	StatusStopping
	StatusStopped
	StatusError
)

func (s Status) String() string {
	switch s {
	case StatusUnregistered:
		return "unregistered"
	case StatusInitialized:
		return "initialized"
	case StatusStarting:
		return "starting"
	case StatusRunning:
		return "running"
	case StatusStopping:
		return "stopping"
	case StatusStopped:
		return "stopped"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// PluginState holds the runtime state of a plugin
type PluginState struct {
	Metadata  PluginMetadata
	Config    PluginConfig
	Status    Status
	Plugin    Plugin
	StartedAt time.Time
	LastError error
}

// Validate validates the plugin configuration
func (p *PluginConfig) Validate() error {
	if p == nil {
		return fmt.Errorf("plugin config is nil")
	}
	if p.Timeout == 0 {
		p.Timeout = 30 * time.Second
	}
	if p.RetryConfig == nil {
		p.RetryConfig = DefaultRetryConfig()
	}
	return nil
}

// GetSetting retrieves a setting value with type safety
func (p *PluginConfig) GetSetting(key string, defaultValue interface{}) interface{} {
	if p.Settings == nil {
		return defaultValue
	}
	if val, ok := p.Settings[key]; ok {
		return val
	}
	return defaultValue
}

// GetString retrieves a string setting
func (p *PluginConfig) GetString(key string, defaultValue string) string {
	if val, ok := p.GetSetting(key, defaultValue).(string); ok {
		return val
	}
	return defaultValue
}

// GetInt retrieves an int setting
func (p *PluginConfig) GetInt(key string, defaultValue int) int {
	if val, ok := p.GetSetting(key, defaultValue).(int); ok {
		return val
	}
	return defaultValue
}

// GetBool retrieves a bool setting
func (p *PluginConfig) GetBool(key string, defaultValue bool) bool {
	if val, ok := p.GetSetting(key, defaultValue).(bool); ok {
		return val
	}
	return defaultValue
}

// GetDuration retrieves a duration setting (supports "30s", "1m", etc.)
func (p *PluginConfig) GetDuration(key string, defaultValue time.Duration) time.Duration {
	if val, ok := p.GetSetting(key, defaultValue).(time.Duration); ok {
		return val
	}
	// Try parsing string
	if str, ok := p.GetSetting(key, "").(string); ok && str != "" {
		if d, err := time.ParseDuration(str); err == nil {
			return d
		}
	}
	return defaultValue
}
