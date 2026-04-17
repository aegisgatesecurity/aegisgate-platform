// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Security Platform - Unified Configuration
// =========================================================================
//
// Platform-wide configuration that composes the AegisGate and AegisGuard
// upstream config systems into a single YAML-loadable structure.
//
// Design principle: One config file to rule them all. The platform operator
// sets config once here, and it propagates to both AegisGate (proxy, TLS,
// security, ML) and AegisGuard (MCP, RBAC, audit, policies) subsystems.
// =========================================================================

package platformconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/config"
	agconfig "github.com/aegisguardsecurity/aegisguard/pkg/config"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/persistence"
	"gopkg.in/yaml.v3"
)

// Config is the unified platform configuration.
// It embeds sub-configs for each subsystem so a single YAML file drives everything.
type Config struct {
	// Platform-level settings
	Platform PlatformConfig `yaml:"platform"`

	// AegisGate proxy configuration (from upstream pkg/config)
	Proxy config.Config `yaml:"proxy"`

	// AegisGuard MCP agent configuration (from upstream pkg/config)
	Agent agconfig.Config `yaml:"agent"`

	// Dashboard configuration
	Dashboard DashboardConfig `yaml:"dashboard"`

	// TLS configuration for all listeners
	TLS TLSConfig `yaml:"tls"`

	// Security middleware configuration
	Security SecurityConfig `yaml:"security"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging"`

	// Persistence configuration (audit storage, retention, pruning)
	Persistence persistence.Config `yaml:"persistence"`
}

// PlatformConfig holds platform-specific settings not in either upstream
type PlatformConfig struct {
	Version     string        `yaml:"version"`
	Mode        string        `yaml:"mode"` // "standalone" or "connected"
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// DashboardConfig holds dashboard/API server settings
type DashboardConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BindAddr string `yaml:"bind_addr"`
	Port     int    `yaml:"port"`
	UIDir    string `yaml:"ui_dir"`
}

// TLSConfig holds TLS settings for all platform listeners
type TLSConfig struct {
	Enabled      bool   `yaml:"enabled"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	CertDir      string `yaml:"cert_dir"`
	AutoGenerate bool   `yaml:"auto_generate"`
	MinVersion   string `yaml:"min_version"` // "1.2" or "1.3"
	// mTLS for internal MCP communication
	MutualTLS MutualTLSConfig `yaml:"mutual_tls"`
	// FIPS compliance
	FIPS FIPSConfig `yaml:"fips"`
}

// MutualTLSConfig holds mTLS configuration
type MutualTLSConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Mode        string `yaml:"mode"` // "optional" or "required"
	ClientCAFile string `yaml:"client_ca_file"`
}

// FIPSConfig holds FIPS compliance settings for the platform
type FIPSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Level    string `yaml:"level"` // "140-2" or "140-3"
}

// SecurityConfig holds security middleware settings
type SecurityConfig struct {
	EnableSecurityHeaders bool     `yaml:"enable_security_headers"`
	EnableCSRF            bool     `yaml:"enable_csrf"`
	EnableXSS             bool     `yaml:"enable_xss"`
	EnablePanicRecovery   bool     `yaml:"enable_panic_recovery"`
	EnableAuditMiddleware  bool     `yaml:"enable_audit_middleware"`
	AllowedOrigins        []string `yaml:"allowed_origins"`
	AllowedMethods        []string `yaml:"allowed_methods"`
	AllowedHeaders        []string `yaml:"allowed_headers"`
}

// LoggingConfig holds structured logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json or text
}

// DefaultConfig returns a fully-populated default configuration
func DefaultConfig() *Config {
	return &Config{
		Platform: PlatformConfig{
			Version:         "2.0.0-dev",
			Mode:            "standalone",
			ShutdownTimeout: 30 * time.Second,
		},
		Proxy: config.Config{
			BindAddress: ":8080",
			CertDir:     "./certs",
			Upstream:    "https://api.openai.com",
			MaxBodySize: 10 * 1024 * 1024,
			MaxConns:    1000,
			Timeout:     30 * time.Second,
			RateLimit:   200,
			LogLevel:    "info",
			TLS:         &config.TLSConfig{Enabled: false},
			ML:          config.DefaultMLConfig(),
			Plugins:     config.DefaultPluginConfig(),
			Security:    config.DefaultSecurityConfig(),
		},
		Agent: *agconfig.DefaultConfig(),
		Dashboard: DashboardConfig{
			Enabled:  true,
			BindAddr: "0.0.0.0",
			Port:     8443,
			UIDir:    "ui/frontend",
		},
		TLS: TLSConfig{
			Enabled:      false,
			CertDir:      "./certs",
			AutoGenerate: true,
			MinVersion:   "1.2",
			MutualTLS: MutualTLSConfig{
				Enabled: false,
				Mode:    "optional",
			},
			FIPS: FIPSConfig{
				Enabled: false,
				Level:   "140-2",
			},
		},
		Security: SecurityConfig{
			EnableSecurityHeaders: true,
			EnableCSRF:            true,
			EnableXSS:             true,
			EnablePanicRecovery:   true,
			EnableAuditMiddleware:  true,
			AllowedOrigins:        []string{},
			AllowedMethods:        []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
			AllowedHeaders:        []string{"Content-Type", "Authorization", "X-API-Key", "X-CSRF-Token"},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Persistence: persistence.DefaultConfig(),
	}
}

// LoadFromFile loads configuration from a YAML file, applying defaults for missing fields
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Config file doesn't exist — use defaults
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply environment variable overrides
	cfg.applyEnvOverrides()

	return cfg, nil
}

// Load is the primary entry point — tries the file, falls back to defaults
func Load(path string) (*Config, error) {
	if path == "" {
		cfg := DefaultConfig()
		cfg.applyEnvOverrides()
		return cfg, nil
	}
	return LoadFromFile(path)
}

// applyEnvOverrides applies environment variable overrides to the config.
// Environment variables take precedence over YAML for deployment flexibility
// (e.g., Kubernetes secrets injected as env vars, not written to config files).
func (c *Config) applyEnvOverrides() {
	// Platform overrides
	if v := os.Getenv("AEGISGATE_PLATFORM_MODE"); v != "" {
		c.Platform.Mode = v
	}

	// Proxy overrides
	if v := os.Getenv("AEGISGATE_BIND_ADDRESS"); v != "" {
		c.Proxy.BindAddress = v
	}
	if v := os.Getenv("AEGISGATE_UPSTREAM"); v != "" {
		c.Proxy.Upstream = v
	}
	if v := os.Getenv("AEGISGATE_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Proxy.RateLimit = n
		}
	}
	if v := os.Getenv("AEGISGATE_LOG_LEVEL"); v != "" {
		c.Proxy.LogLevel = v
		c.Logging.Level = v
	}

	// TLS overrides
	if v := os.Getenv("AEGISGATE_TLS_ENABLED"); v != "" {
		c.TLS.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("AEGISGATE_TLS_CERT"); v != "" {
		c.TLS.CertFile = v
	}
	if v := os.Getenv("AEGISGATE_TLS_KEY"); v != "" {
		c.TLS.KeyFile = v
	}

	// Dashboard overrides
	if v := os.Getenv("AEGISGATE_DASHBOARD_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Dashboard.Port = n
		}
	}

	// Agent (AegisGuard) overrides
	if v := os.Getenv("AEGIS_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.Agent.Server.Port = n
		}
	}
	if v := os.Getenv("AEGIS_LOG_LEVEL"); v != "" {
		c.Agent.Logging.Level = v
	}
	if v := os.Getenv("AEGIS_AUDIT_ENABLED"); v != "" {
		c.Agent.Audit.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("LICENSE_KEY"); v != "" {
		c.Agent.License.LicenseKey = v
	}

	// Security overrides
	if v := os.Getenv("AEGISGATE_SECURITY_HEADERS"); v != "" {
		c.Security.EnableSecurityHeaders = strings.ToLower(v) == "true"
	}

	// FIPS overrides
	if v := os.Getenv("AEGISGATE_FIPS_ENABLED"); v != "" {
		c.TLS.FIPS.Enabled = strings.ToLower(v) == "true"
	}

	// Persistence overrides
	if v := os.Getenv("AEGISGATE_PERSISTENCE_ENABLED"); v != "" {
		c.Persistence.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("AEGISGATE_DATA_DIR"); v != "" {
		c.Persistence.DataDir = v
		c.Persistence.AuditDir = filepath.Join(v, "audit")
		if c.TLS.CertDir == "" || c.TLS.CertDir == "./certs" {
			c.TLS.CertDir = filepath.Join(v, "certs")
		}
	}
}

// ProxyPort extracts the port from the proxy bind address
func (c *Config) ProxyPort() int {
	parts := strings.Split(c.Proxy.BindAddress, ":")
	if len(parts) == 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			return n
		}
	}
	return 8080
}

// MCPPort returns the AegisGuard MCP server port
func (c *Config) MCPPort() int {
	if c.Agent.Server.Port != 0 {
		return c.Agent.Server.Port
	}
	return 8081
}

// IsStandaloneMode returns true if --embedded-mcp or mode=standalone
func (c *Config) IsStandaloneMode(cliFlag bool) bool {
	if cliFlag {
		return true
	}
	return c.Platform.Mode == "standalone"
}