// Package config - Configuration management for AegisGuard
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the AegisGuard configuration
type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Logging       LoggingConfig       `yaml:"logging"`
	Policies      PoliciesConfig      `yaml:"policies"`
	Risk          RiskConfig          `yaml:"risk"`
	Session       SessionConfig       `yaml:"session"`
	Sandbox       SandboxConfig       `yaml:"sandbox"`
	Audit         AuditConfig         `yaml:"audit"`
	RateLimit     RateLimitConfig     `yaml:"rate_limit"`
	TLS           TLSConfig           `yaml:"tls"`
	Bridge        BridgeConfig        `yaml:"bridge"`
	RBAC          RBACConfig          `yaml:"rbac"`
	Context       ContextConfig       `yaml:"context"`
	UnifiedAudit  *UnifiedAuditConfig `yaml:"unified_audit"`
	Compliance    ComplianceConfig    `yaml:"compliance"`
	Observability ObservabilityConfig `yaml:"observability"`
	Health        HealthConfig        `yaml:"health"`
	License       LicenseConfig       `yaml:"license"`
}

// ServerConfig holds server settings
type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

// PoliciesConfig holds security policy settings
type PoliciesConfig struct {
	DefaultAllow    []string `yaml:"default_allow"`
	HighRisk        []string `yaml:"high_risk"`
	RequireApproval []string `yaml:"require_approval"`
}

// RiskConfig holds risk scoring settings
type RiskConfig struct {
	Thresholds   RiskThresholds `yaml:"thresholds"`
	DefaultScore int            `yaml:"default_score"`
}

// RiskThresholds holds risk score thresholds
type RiskThresholds struct {
	Low      int `yaml:"low"`
	Medium   int `yaml:"medium"`
	High     int `yaml:"high"`
	Critical int `yaml:"critical"`
}

// SessionConfig holds session management settings
type SessionConfig struct {
	MaxSessions int           `yaml:"max_sessions"`
	TTL         time.Duration `yaml:"ttl"`
	MemoryLimit int64         `yaml:"memory_limit"`
}

// SandboxConfig holds sandbox settings
type SandboxConfig struct {
	MaxDepth         int           `yaml:"max_depth"`
	Timeout          time.Duration `yaml:"timeout"`
	AllowedActions   []string      `yaml:"allowed_actions"`
	ApprovalRequired []string      `yaml:"approval_required"`
}

// AuditConfig holds audit logging settings
type AuditConfig struct {
	Enabled bool     `yaml:"enabled"`
	Format  string   `yaml:"format"`
	Events  []string `yaml:"events"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerMinute int  `yaml:"requests_per_minute"`
	Burst             int  `yaml:"burst"`
}

// TLSConfig holds TLS settings
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// BridgeConfig holds AegisGate bridge settings
type BridgeConfig struct {
	Enabled       bool          `yaml:"enabled"`
	AegisGateURL  string        `yaml:"aegisgate_url"`
	Timeout       time.Duration `yaml:"timeout"`
	SkipTLSVerify bool          `yaml:"skip_tls_verify"`
	DefaultTarget string        `yaml:"default_target"`
	APIKey        string        `yaml:"api_key"`
	MaxRetries    int           `yaml:"max_retries"`
}

// RBACConfig holds RBAC settings
type RBACConfig struct {
	Enabled       bool        `yaml:"enabled"`
	DefaultAction string      `yaml:"default_action"`
	DefaultRole   string      `yaml:"default_role"`
	Session       RBACSession `yaml:"session"`
	HighRiskTools []string    `yaml:"high_risk_tools"`
}

// RBACSession holds RBAC session settings
type RBACSession struct {
	Duration        time.Duration `yaml:"duration"`
	MaxConcurrent   int           `yaml:"max_concurrent"`
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
}

// ContextConfig holds context isolation settings
type ContextConfig struct {
	Enabled                bool          `yaml:"enabled"`
	SessionIsolation       bool          `yaml:"session_isolation"`
	MaxMemoryPerSession    int64         `yaml:"max_memory_per_session"`
	ContextTTL             time.Duration `yaml:"context_ttl"`
	CrossSessionProtection bool          `yaml:"cross_session_protection"`
}

// UnifiedAuditConfig holds unified audit settings
type UnifiedAuditConfig struct {
	Enabled             bool          `yaml:"enabled"`
	ShareWithAegisGate  bool          `yaml:"share_with_aegisgate"`
	CorrelationIDHeader string        `yaml:"correlation_id_header"`
	Secret              string        `yaml:"secret"`
	Retention           time.Duration `yaml:"retention"`
}

// ComplianceConfig holds compliance settings
type ComplianceConfig struct {
	Frameworks []string `yaml:"frameworks"`
	ReportPath string   `yaml:"report_path"`
}

// ObservabilityConfig holds observability settings
type ObservabilityConfig struct {
	Metrics MetricsConfig `yaml:"metrics"`
	Tracing TracingConfig `yaml:"tracing"`
}

// MetricsConfig holds metrics settings
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// TracingConfig holds tracing settings
type TracingConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Endpoint    string `yaml:"endpoint"`
	ServiceName string `yaml:"service_name"`
}

// HealthConfig holds health check settings
type HealthConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// LicenseConfig holds license validation settings
type LicenseConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	LicenseKey    string        `yaml:"license_key" json:"license_key"`
	AdminPanelURL string        `yaml:"admin_panel_url" json:"admin_panel_url"`
	PublicKeyPEM  string        `yaml:"public_key_pem" json:"public_key_pem"`
	CacheDuration time.Duration `yaml:"cache_duration" json:"cache_duration"`
	FailOpen      bool          `yaml:"fail_open" json:"fail_open"`
	GracePeriod   time.Duration `yaml:"grace_period" json:"grace_period"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	cfg := &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  5 * time.Minute,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Policies: PoliciesConfig{
			DefaultAllow:    []string{"file_read", "web_search", "code_search", "http_get"},
			HighRisk:        []string{"shell_command", "code_execute", "database_write", "file_delete"},
			RequireApproval: []string{"file_write", "network_call", "database_query"},
		},
		Risk: RiskConfig{
			Thresholds: RiskThresholds{
				Low:      30,
				Medium:   60,
				High:     80,
				Critical: 95,
			},
			DefaultScore: 50,
		},
		Session: SessionConfig{
			MaxSessions: 1000,
			TTL:         24 * time.Hour,
			MemoryLimit: 100 * 1024 * 1024,
		},
		Sandbox: SandboxConfig{
			MaxDepth:         5,
			Timeout:          5 * time.Minute,
			AllowedActions:   []string{"file_read"},
			ApprovalRequired: []string{"file_write", "network_call", "code_execute", "shell_command"},
		},
		Audit: AuditConfig{
			Enabled: true,
			Format:  "json",
			Events:  []string{"session_start", "session_end", "tool_call", "tool_denied", "policy_denial", "risk_alert"},
		},
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerMinute: 100,
			Burst:             20,
		},
		TLS: TLSConfig{
			Enabled: false,
		},
	}

	// Add default values for new configuration sections
	applyDefaultExtensions(cfg)

	return cfg
}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
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

// applyDefaultExtensions applies default extensions to the config
func applyDefaultExtensions(c *Config) {
	// Ensure UnifiedAudit is initialized
	if c.UnifiedAudit == nil {
		c.UnifiedAudit = &UnifiedAuditConfig{
			Enabled:   true,
			Retention: 90 * 24 * time.Hour,
		}
	}

	// Ensure Observability is initialized
	if c.Observability.Metrics.Enabled && c.Observability.Metrics.Port == 0 {
		c.Observability.Metrics.Port = 9091
	}
}

// applyEnvOverrides applies environment variable overrides to the config
func (c *Config) applyEnvOverrides() {
	// Server overrides
	if v := os.Getenv("AEGIS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			c.Server.Port = port
		}
	}
	if v := os.Getenv("AEGIS_HOST"); v != "" {
		c.Server.Host = v
	}

	// Logging overrides
	if v := os.Getenv("AEGIS_LOG_LEVEL"); v != "" {
		c.Logging.Level = v
	}

	// Session overrides
	if v := os.Getenv("AEGIS_MAX_SESSIONS"); v != "" {
		if max, err := strconv.Atoi(v); err == nil {
			c.Session.MaxSessions = max
		}
	}

	// Risk overrides
	if v := os.Getenv("AEGIS_RISK_DEFAULT"); v != "" {
		if risk, err := strconv.Atoi(v); err == nil {
			c.Risk.DefaultScore = risk
		}
	}

	// Audit overrides
	if v := os.Getenv("AEGIS_AUDIT_ENABLED"); v != "" {
		c.Audit.Enabled = strings.ToLower(v) == "true"
	}

	// TLS overrides
	if v := os.Getenv("AEGIS_TLS_ENABLED"); v != "" {
		c.TLS.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("AEGIS_TLS_CERT"); v != "" {
		c.TLS.CertFile = v
	}
	if v := os.Getenv("AEGIS_TLS_KEY"); v != "" {
		c.TLS.KeyFile = v
	}

	// License overrides
	if v := os.Getenv("LICENSE_KEY"); v != "" {
		c.License.LicenseKey = v
		c.License.Enabled = true
	}
	if v := os.Getenv("ADMIN_PANEL_URL"); v != "" {
		c.License.AdminPanelURL = v
	}
	if v := os.Getenv("LICENSE_FAIL_OPEN"); v != "" {
		c.License.FailOpen = strings.ToLower(v) == "true"
	}
}

// IsHighRiskTool checks if a tool is in the high-risk list
func (c *Config) IsHighRiskTool(toolName string) bool {
	for _, t := range c.Policies.HighRisk {
		if t == toolName {
			return true
		}
	}
	return false
}

// RequiresApproval checks if a tool requires approval
func (c *Config) RequiresApproval(toolName string) bool {
	for _, t := range c.Policies.RequireApproval {
		if t == toolName {
			return true
		}
	}
	return false
}

// IsAllowedByDefault checks if a tool is allowed by default
func (c *Config) IsAllowedByDefault(toolName string) bool {
	for _, t := range c.Policies.DefaultAllow {
		if t == toolName {
			return true
		}
	}
	return false
}

// GetRiskLevel returns the risk level for a given score
func (c *Config) GetRiskLevel(score int) string {
	if score >= c.Risk.Thresholds.Critical {
		return "critical"
	}
	if score >= c.Risk.Thresholds.High {
		return "high"
	}
	if score >= c.Risk.Thresholds.Medium {
		return "medium"
	}
	if score >= c.Risk.Thresholds.Low {
		return "low"
	}
	return "none"
}
