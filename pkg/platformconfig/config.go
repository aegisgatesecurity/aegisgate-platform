// SPDX-License-Identifier: Apache-2.0
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
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/persistence"
	"github.com/aegisgatesecurity/aegisgate/pkg/config"
	agconfig "github.com/aegisgatesecurity/aegisguard/pkg/config"
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

	// A2A (Agent-to-Agent) guardrails configuration
	A2A A2AConfig `yaml:"a2a"`

	// ACP (Agent Communication Protocol) guardrails configuration
	ACP ACPConfig `yaml:"acp"`

	// Trust Framework (6th pillar) configuration
	// Provides per-agent cryptographic identity, capability contracts,
	// real-time trust scoring, anomaly detection, signed attestations,
	// and a customer-facing HTTP API at /api/v1/trust/*.
	Trust TrustConfig `yaml:"trust"`

	// Persistence configuration (audit storage, retention, pruning)
	Persistence persistence.Config `yaml:"persistence"`

	// SIEM integration configuration
	SIEM SIEMConfig `yaml:"siem"`
}

// PlatformConfig holds platform-specific settings not in either upstream
type PlatformConfig struct {
	Version         string        `yaml:"version"`
	Mode            string        `yaml:"mode"` // "standalone" or "connected"
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
	Enabled      bool   `yaml:"enabled"`
	Mode         string `yaml:"mode"` // "optional" or "required"
	ClientCAFile string `yaml:"client_ca_file"`
}

// FIPSConfig holds FIPS compliance settings for the platform
type FIPSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Level   string `yaml:"level"` // "140-2" or "140-3"
}

// A2AConfig holds A2A (Agent-to-Agent) guardrails configuration
type A2AConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ConfigFile string `yaml:"config_file"` // path to a2a.yaml
	CapsFile   string `yaml:"caps_file"`   // path to a2a_caps.yaml
}

// ACPConfig holds ACP (Agent Communication Protocol) guardrails configuration.
// ACP is a protocol for code editors and coding agents; this config drives
// the HMAC integrity, rate limiting, capability enforcement, and response
// scanning middleware mounted at /acp/ by the platform binary.
type ACPConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ConfigFile string `yaml:"config_file"` // path to acp.yaml (HMAC secret, blocked methods, etc.)
}

// TrustConfig holds Trust Framework (6th pillar) configuration.
// The Trust Framework provides per-agent cryptographic identity
// (pkg/trust/identity), capability contracts (pkg/trust/contract),
// real-time trust scoring (pkg/trust/score), anomaly detection,
// signed attestations (pkg/trust/attestation), and a customer-facing
// HTTP API at /api/v1/trust/* (pkg/trust/api.go). The dashboard is
// served by pkg/trust/dashboard/. The envelope primitive that wraps
// trust attestations is pkg/attestation/ (frozen 2026-06-15).
//
// Tier gate: Professional+ per locked decision Q3 (see plans/sprint-16/).
// Set RequireLicense=false to expose the API on Community/Developer tiers
// (useful for self-hosted testing).
type TrustConfig struct {
	Enabled        bool   `yaml:"enabled"`
	ConfigFile     string `yaml:"config_file"`     // path to trust.yaml
	RequireLicense bool   `yaml:"require_license"` // gate behind license middleware (Professional+)
}

// SecurityConfig holds security middleware settings
type SecurityConfig struct {
	EnableSecurityHeaders bool     `yaml:"enable_security_headers"`
	EnableCSRF            bool     `yaml:"enable_csrf"`
	EnableXSS             bool     `yaml:"enable_xss"`
	EnablePanicRecovery   bool     `yaml:"enable_panic_recovery"`
	EnableAuditMiddleware bool     `yaml:"enable_audit_middleware"`
	AllowedOrigins        []string `yaml:"allowed_origins"`
	AllowedMethods        []string `yaml:"allowed_methods"`
	AllowedHeaders        []string `yaml:"allowed_headers"`
}

// LoggingConfig holds structured logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json or text
}

// SIEMConfig holds SIEM integration settings. The SIEM dispatcher
// polls the audit ring buffer and forwards events to configured
// platforms (Splunk, Elasticsearch, QRadar, etc.).
type SIEMConfig struct {
	// Enabled controls whether the SIEM dispatcher runs.
	Enabled bool `yaml:"enabled"`

	// Platforms is the list of configured SIEM platform outputs.
	// Each platform has its own endpoint, auth, format, and retry settings.
	Platforms []SIEMPlatformConfig `yaml:"platforms"`

	// PollInterval is how often the dispatcher polls the audit ring
	// buffer for new events. Default: 5s.
	PollInterval time.Duration `yaml:"poll_interval"`

	// BatchSize is the maximum number of event summaries per poll
	// cycle. Default: 100.
	BatchSize int `yaml:"batch_size"`

	// Source is the "source" field set on every siem.Event.
	// Default: "aegisgate".
	Source string `yaml:"source"`

	// BufferMaxSize is the internal SIEM manager buffer size.
	// Default: 10000.
	BufferMaxSize int `yaml:"buffer_max_size"`
}

// SIEMPlatformConfig holds one SIEM platform output configuration.
type SIEMPlatformConfig struct {
	// Platform type: splunk, elasticsearch, qradar, sentinel,
	// sumologic, logrhythm, cloudwatch, securityhub, arcsight,
	// syslog, custom.
	Platform string `yaml:"platform"`

	// Enabled controls whether this platform output is active.
	Enabled bool `yaml:"enabled"`

	// Format: cef, leef, json, syslog.
	Format string `yaml:"format"`

	// Endpoint URL for HTTP-based platforms.
	Endpoint string `yaml:"endpoint"`

	// Auth configuration.
	Auth SIEMAuthConfig `yaml:"auth"`

	// TLS configuration.
	TLS SIEMTLSConfig `yaml:"tls"`

	// Platform-specific settings.
	Settings map[string]interface{} `yaml:"settings"`

	// Retry configuration.
	Retry SIEMRetryConfig `yaml:"retry"`

	// Batch configuration.
	Batch SIEMBatchConfig `yaml:"batch"`
}

// SIEMAuthConfig holds authentication settings.
type SIEMAuthConfig struct {
	Type         string `yaml:"type"`           // api_key, oauth2, basic, certificate
	APIKey       string `yaml:"api_key"`        // env: AEGISGATE_SIEM_API_KEY
	APIKeyHeader string `yaml:"api_key_header"` // default: Authorization
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	TokenURL     string `yaml:"token_url"`     // OAuth2
	ClientID     string `yaml:"client_id"`     // env: AEGISGATE_SIEM_OAUTH_CLIENT_ID
	ClientSecret string `yaml:"client_secret"` // env: AEGISGATE_SIEM_OAUTH_CLIENT_SECRET
}

// SIEMTLSConfig holds TLS settings for SIEM connections.
type SIEMTLSConfig struct {
	Enabled            bool   `yaml:"enabled"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CAFile             string `yaml:"ca_file"`
	ServerName         string `yaml:"server_name"`
}

// SIEMRetryConfig holds retry settings.
type SIEMRetryConfig struct {
	Enabled           bool    `yaml:"enabled"`
	MaxAttempts       int     `yaml:"max_attempts"`       // default: 3
	InitialBackoff    string  `yaml:"initial_backoff"`    // e.g. "1s"
	MaxBackoff        string  `yaml:"max_backoff"`        // e.g. "30s"
	BackoffMultiplier float64 `yaml:"backoff_multiplier"` // default: 2.0
}

// SIEMBatchConfig holds batching settings.
type SIEMBatchConfig struct {
	Enabled bool   `yaml:"enabled"`
	MaxSize int    `yaml:"max_size"` // default: 100
	MaxWait string `yaml:"max_wait"` // e.g. "5s"
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
			EnableAuditMiddleware: true,
			AllowedOrigins:        []string{},
			AllowedMethods:        []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
			AllowedHeaders:        []string{"Content-Type", "Authorization", "X-API-Key", "X-CSRF-Token"},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		A2A: A2AConfig{
			Enabled:    false,
			ConfigFile: "configs/a2a.yaml",
			CapsFile:   "configs/a2a_caps.yaml",
		},
		ACP: ACPConfig{
			Enabled:    false,
			ConfigFile: "configs/acp.yaml",
		},
		Trust: TrustConfig{
			Enabled:        false,
			ConfigFile:     "configs/trust.yaml",
			RequireLicense: true, // Professional+ tier per locked decision Q3
		},
		Persistence: persistence.DefaultConfig(),
		SIEM: SIEMConfig{
			Enabled:       false,
			PollInterval:  5 * time.Second,
			BatchSize:     100,
			Source:        "aegisgate",
			BufferMaxSize: 10000,
		},
	}
}

// LoadFromFile loads configuration from a YAML file, applying defaults for missing fields.
// On D17 (P0 fix): wraps yaml in a legacy-key translation layer. See translateLegacyConfigKeys.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- Config path comes from CLI flag or hardcoded default, not user input
	if err != nil {
		if os.IsNotExist(err) {
			// Config file doesn't exist — use defaults with env overrides
			cfg := DefaultConfig()
			cfg.applyEnvOverrides()
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Translate legacy yaml keys (server.*, scanner.*, bridge.*, redis.*, lens.*)
	// to canonical Config struct keys. Without this, ~70% of the user-facing
	// aegisgate-platform.yaml was silently dropped on load (see audit
	// plans/FULL-CODEBASE-AUDIT-2026-07-20.md, Finding #1).
	translated, warnings := translateLegacyConfigKeys(data)

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(translated, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Log deprecation warnings so users know to update their yaml.
	for _, w := range warnings {
		log.Printf("config: %s", w)
	}

	// Apply environment variable overrides
	cfg.applyEnvOverrides()

	return cfg, nil
}

// translateLegacyConfigKeys rewrites aegisgate-platform.yaml's legacy/wrong
// field names to canonical Go struct yaml tags. The audit found the user-facing
// config file used keys like `server.*`, `scanner.*`, `bridge.*`, `redis.*`,
// `lens.*` that don't match any Go struct field, so ~70% of the file was
// silently dropped on load. This translator makes both old and new keys work.
//
// Returns the translated yaml bytes and a list of deprecation warnings
// (to be logged by the caller).
func translateLegacyConfigKeys(data []byte) ([]byte, []string) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		// Not a valid yaml map; pass through and let the caller error.
		return data, nil
	}
	if raw == nil {
		return data, nil
	}

	var warnings []string
	translated := make(map[string]interface{})

	// Copy all top-level keys as-is, then apply translations.
	for k, v := range raw {
		translated[k] = v
	}

	// server.* — was the main config block in the v3.3.0-beta.2 era.
	// Translate to proxy.* + dashboard.* to match the Go struct.
	if server, ok := raw["server"].(map[string]interface{}); ok {
		// server.host + server.proxy_port → proxy.bind_address
		host, hasHost := server["host"].(string)
		port, hasPort := server["proxy_port"]
		if hasHost || hasPort {
			hostStr := "0.0.0.0"
			if hasHost {
				hostStr = host
			}
			portStr := "8080"
			if p, ok := port.(int); ok {
				portStr = strconv.Itoa(p)
			} else if p, ok := port.(float64); ok { // yaml numbers are float64
				portStr = strconv.Itoa(int(p))
			}
			bind := hostStr + ":" + portStr
			translated["proxy"] = mergeIntoMap(asMap(translated["proxy"]), "bind_address", bind)
			warnings = append(warnings, "config: 'server.host' and 'server.proxy_port' are deprecated; use 'proxy.bind_address' (e.g. \""+bind+"\")")
		}
		// server.mcp_port — not in Go struct (MCP port is CLI flag/env var only)
		if _, hasMCP := server["mcp_port"]; hasMCP {
			warnings = append(warnings, "config: 'server.mcp_port' is deprecated; use the --mcp-port CLI flag or AEGIS_PORT env var (MCP port is not yaml-configurable)")
		}
		// server.dashboard_port → dashboard.port
		if dp, hasDP := server["dashboard_port"]; hasDP {
			var portVal int
			if p, ok := dp.(int); ok {
				portVal = p
			} else if p, ok := dp.(float64); ok {
				portVal = int(p)
			}
			if portVal > 0 {
				translated["dashboard"] = mergeIntoMap(asMap(translated["dashboard"]), "port", portVal)
				warnings = append(warnings, "config: 'server.dashboard_port' is deprecated; use 'dashboard.port'")
			}
		}
		delete(translated, "server")
	}

	// tier (top-level) — deprecated since D0; tier is now license-derived
	if _, hasTier := raw["tier"]; hasTier {
		warnings = append(warnings, "config: top-level 'tier' is deprecated and ignored; tier is now license-derived (set AEGISGATE_LICENSE_KEY or use --license)")
		delete(translated, "tier")
	}

	// scanner.* — not in Go struct (scanner is CLI flag only)
	if _, hasScanner := raw["scanner"]; hasScanner {
		warnings = append(warnings, "config: 'scanner' section is deprecated and ignored; use the --scanner-address CLI flag or AEGIS_SCANNER_ADDRESS env var")
		delete(translated, "scanner")
	}

	// bridge.* — not in Go struct (bridge is CLI flag only)
	if _, hasBridge := raw["bridge"]; hasBridge {
		warnings = append(warnings, "config: 'bridge' section is deprecated and ignored; use the --bridge-url CLI flag or AEGISGATE_BRIDGE_URL env var")
		delete(translated, "bridge")
	}

	// redis.* — not in Go struct and not used by main.go
	if _, hasRedis := raw["redis"]; hasRedis {
		warnings = append(warnings, "config: 'redis' section is deprecated and ignored; the platform does not currently use Redis")
		delete(translated, "redis")
	}

	// lens.* — translate to top-level proxyMux flag or env-var note
	if lens, ok := raw["lens"].(map[string]interface{}); ok {
		// lens.enabled, lens.bearer_token, lens.ioc_store_dir all map to
		// CLI flags / env vars (not in the Go config struct). We note
		// them and remove.
		if en, hasEn := lens["enabled"]; hasEn {
			warnings = append(warnings, fmt.Sprintf("config: 'lens.enabled' (%v) is deprecated; use the --lens-enabled CLI flag or AEGISGATE_LENS_ENABLED env var", en))
		}
		if bt, hasBT := lens["bearer_token"]; hasBT && bt != "" {
			warnings = append(warnings, "config: 'lens.bearer_token' is deprecated; use the --lens-bearer-token CLI flag or AEGISGATE_LENS_BEARER_TOKEN env var")
		}
		if sd, hasSD := lens["ioc_store_dir"]; hasSD && sd != "" {
			warnings = append(warnings, "config: 'lens.ioc_store_dir' is deprecated; use the --lens-ioc-store-dir CLI flag or AEGISGATE_LENS_IOC_STORE_DIR env var")
		}
		delete(translated, "lens")
	}

	out, err := yaml.Marshal(translated)
	if err != nil {
		return data, warnings // best-effort: return original
	}
	return out, warnings
}

// asMap returns v as a map[string]interface{} if it is one, else nil.
func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

// mergeIntoMap returns a copy of base with key=k set to value=v.
func mergeIntoMap(base map[string]interface{}, k string, v interface{}) map[string]interface{} {
	if base == nil {
		base = map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(base)+1)
	for kk, vv := range base {
		out[kk] = vv
	}
	out[k] = v
	return out
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

	// A2A overrides
	if v := os.Getenv("AEGISGATE_A2A_ENABLED"); v != "" {
		c.A2A.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("AEGISGATE_A2A_CONFIG_FILE"); v != "" {
		c.A2A.ConfigFile = v
	}
	if v := os.Getenv("AEGISGATE_A2A_CAPS_FILE"); v != "" {
		c.A2A.CapsFile = v
	}

	// ACP overrides
	if v := os.Getenv("AEGISGATE_ACP_ENABLED"); v != "" {
		c.ACP.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("AEGISGATE_ACP_CONFIG_FILE"); v != "" {
		c.ACP.ConfigFile = v
	}

	// Trust Framework overrides
	if v := os.Getenv("AEGISGATE_TRUST_ENABLED"); v != "" {
		c.Trust.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("AEGISGATE_TRUST_CONFIG_FILE"); v != "" {
		c.Trust.ConfigFile = v
	}
	if v := os.Getenv("AEGISGATE_TRUST_REQUIRE_LICENSE"); v != "" {
		c.Trust.RequireLicense = strings.ToLower(v) == "true"
	}

	// SIEM overrides
	if v := os.Getenv("AEGISGATE_SIEM_ENABLED"); v != "" {
		c.SIEM.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv("AEGISGATE_SIEM_SOURCE"); v != "" {
		c.SIEM.Source = v
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
