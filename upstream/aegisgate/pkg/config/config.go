// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all application configuration
type Config struct {
	BindAddress     string        `json:"bind_address" yaml:"bind_address"`
	CertDir         string        `json:"cert_dir" yaml:"cert_dir"`
	Upstream        string        `json:"upstream" yaml:"upstream"`
	MaxBodySize     int64         `json:"max_body_size" yaml:"max_body_size"`
	MaxConns        int           `json:"max_conns" yaml:"max_conns"`
	Timeout         time.Duration `json:"timeout" yaml:"timeout"`
	ShutdownTimeout time.Duration `json:"shutdown_timeout" yaml:"shutdown_timeout"`
	RateLimit       int           `json:"rate_limit" yaml:"rate_limit"`
	LogLevel        string        `json:"log_level" yaml:"log_level"`
	TLS             *TLSConfig    `json:"tls,omitempty" yaml:"tls,omitempty"`
	UpstreamTLS     *TLSConfig    `json:"upstream_tls,omitempty" yaml:"upstream_tls,omitempty"`

	// ML Anomaly Detection configuration
	ML *MLConfig `json:"ml,omitempty" yaml:"ml,omitempty"`

	// Plugin configuration
	Plugins *PluginConfig `json:"plugins,omitempty" yaml:"plugins,omitempty"`

	// Security configuration
	Security *SecurityConfig `json:"security,omitempty" yaml:"security,omitempty"`

	mu sync.RWMutex
}

// TLSConfig holds TLS-specific configuration
type TLSConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	CertFile   string `json:"cert_file" yaml:"cert_file"`
	KeyFile    string `json:"key_file" yaml:"key_file"`
	CAFile     string `json:"ca_file" yaml:"ca_file"`
	SkipVerify bool   `json:"skip_verify" yaml:"skip_verify"`
	MinVersion string `json:"min_version" yaml:"min_version"`
	MaxVersion string `json:"max_version" yaml:"max_version"`
}

// MLConfig holds ML anomaly detection configuration
type MLConfig struct {
	// Enabled toggles ML anomaly detection on/off
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Sensitivity determines the threshold for anomaly detection
	// Options: "low", "medium", "high", "paranoid"
	Sensitivity string `json:"sensitivity" yaml:"sensitivity"`

	// BlockOnCriticalSeverity blocks critical severity anomalies
	BlockOnCriticalSeverity bool `json:"block_on_critical" yaml:"block_on_critical"`

	// BlockOnHighSeverity blocks high severity anomalies
	BlockOnHighSeverity bool `json:"block_on_high" yaml:"block_on_high"`

	// MinScoreToBlock minimum z-score to trigger blocking
	MinScoreToBlock float64 `json:"min_score_to_block" yaml:"min_score_to_block"`

	// SampleRate percentage of requests to analyze (0-100)
	SampleRate int `json:"sample_rate" yaml:"sample_rate"`

	// ExcludedPaths URL paths to exclude from ML analysis
	ExcludedPaths []string `json:"excluded_paths" yaml:"excluded_paths"`

	// ExcludedMethods HTTP methods to exclude from ML analysis
	ExcludedMethods []string `json:"excluded_methods" yaml:"excluded_methods"`

	// LogAllAnomalies whether to log all anomalies or only blocked ones
	LogAllAnomalies bool `json:"log_all_anomalies" yaml:"log_all_anomalies"`

	// EnablePromptInjectionDetection enables prompt injection detection
	EnablePromptInjectionDetection bool `json:"enable_prompt_injection" yaml:"enable_prompt_injection"`

	// PromptInjectionSensitivity sensitivity for prompt injection (0-100)
	PromptInjectionSensitivity int `json:"prompt_injection_sensitivity" yaml:"prompt_injection_sensitivity"`

	// EnableContentAnalysis enables content analysis (LLM response inspection)
	EnableContentAnalysis bool `json:"enable_content_analysis" yaml:"enable_content_analysis"`

	// EnableBehavioralAnalysis enables behavioral analysis
	EnableBehavioralAnalysis bool `json:"enable_behavioral_analysis" yaml:"enable_behavioral_analysis"`

	// WindowSize for baseline calculation
	WindowSize int `json:"window_size" yaml:"window_size"`

	// ZThreshold for anomaly detection
	ZThreshold float64 `json:"z_threshold" yaml:"z_threshold"`

	// MinSamples before detection starts
	MinSamples int `json:"min_samples" yaml:"min_samples"`

	// EntropyThreshold for entropy-based detection
	EntropyThreshold float64 `json:"entropy_threshold" yaml:"entropy_threshold"`
}

// DefaultMLConfig returns sensible defaults for ML configuration
func DefaultMLConfig() *MLConfig {
	return &MLConfig{
		Enabled:                        true,
		Sensitivity:                    "medium",
		BlockOnCriticalSeverity:        true,
		BlockOnHighSeverity:            false,
		MinScoreToBlock:                3.0,
		SampleRate:                     100,
		ExcludedPaths:                  []string{"/health", "/ready", "/metrics"},
		ExcludedMethods:                []string{"OPTIONS", "HEAD"},
		LogAllAnomalies:                true,
		EnablePromptInjectionDetection: true,
		PromptInjectionSensitivity:     75,
		EnableContentAnalysis:          true,
		EnableBehavioralAnalysis:       true,
		WindowSize:                     1000,
		ZThreshold:                     3.0,
		MinSamples:                     10,
		EntropyThreshold:               4.5,
	}
}

// PluginConfig holds plugin configuration
type PluginConfig struct {
	Enabled        bool              `json:"enabled" yaml:"enabled"`
	Directories    []string          `json:"directories" yaml:"directories"`
	PluginSettings map[string]string `json:"plugin_settings" yaml:"plugin_settings"`
	Timeout        time.Duration     `json:"timeout" yaml:"timeout"`
	EnablePeriodic bool              `json:"enable_periodic" yaml:"enable_periodic"`
}

// DefaultPluginConfig returns default plugin configuration
func DefaultPluginConfig() *PluginConfig {
	return &PluginConfig{
		Enabled:        false,
		Directories:    []string{"./plugins"},
		PluginSettings: make(map[string]string),
		Timeout:        30 * time.Second,
		EnablePeriodic: false,
	}
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	EnableFIPS            bool     `json:"enable_fips" yaml:"enable_fips"`
	EnableAuditLogging    bool     `json:"enable_audit_logging" yaml:"enable_audit_logging"`
	AuditLogPath          string   `json:"audit_log_path" yaml:"audit_log_path"`
	EnableOPSEC           bool     `json:"enable_opsec" yaml:"enable_opsec"`
	EnableImmutableConfig bool     `json:"enable_immutable_config" yaml:"enable_immutable_config"`
	EnableReadOnlyFS      bool     `json:"enable_readonly_fs" yaml:"enable_readonly_fs"`
	EnableWAL             bool     `json:"enable_wal" yaml:"enable_wal"`
	EnableSnapshot        bool     `json:"enable_snapshot" yaml:"enable_snapshot"`
	EnableRollback        bool     `json:"enable_rollback" yaml:"enable_rollback"`
	MaxMemoryMB           int      `json:"max_memory_mb" yaml:"max_memory_mb"`
	EnableSecurityHeaders bool     `json:"enable_security_headers" yaml:"enable_security_headers"`
	AllowedMethods        []string `json:"allowed_methods" yaml:"allowed_methods"`
	BlockedIPs            []string `json:"blocked_ips" yaml:"blocked_ips"`
	AllowedHosts          []string `json:"allowed_hosts" yaml:"allowed_hosts"`
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		EnableFIPS:            false,
		EnableAuditLogging:    true,
		AuditLogPath:          "/var/log/aegisgate/audit.log",
		EnableOPSEC:           true,
		EnableImmutableConfig: true,
		EnableReadOnlyFS:      false,
		EnableWAL:             true,
		EnableSnapshot:        true,
		EnableRollback:        true,
		MaxMemoryMB:           512,
		EnableSecurityHeaders: true,
		AllowedMethods:        []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"},
		BlockedIPs:            []string{},
		AllowedHosts:          []string{},
	}
}

// Validate validates the security configuration
func (sc SecurityConfig) Validate() error {
	if sc.MaxMemoryMB < 64 {
		return fmt.Errorf("max_memory_mb must be at least 64MB")
	}
	return nil
}

// Load loads configuration from environment and defaults
func Load() (*Config, error) {
	cfg := &Config{
		BindAddress:     getEnv("AEGISGATE_BIND_ADDRESS", ":8443"),
		CertDir:         getEnv("AEGISGATE_CERT_DIR", "./certs"),
		Upstream:        getEnv("AEGISGATE_UPSTREAM", "http://localhost:8080"),
		MaxBodySize:     getEnvAsInt64("AEGISGATE_MAX_BODY_SIZE", 10*1024*1024),
		MaxConns:        getEnvAsInt("AEGISGATE_MAX_CONNS", 1000),
		Timeout:         getEnvAsDuration("AEGISGATE_TIMEOUT", 30*time.Second),
		ShutdownTimeout: getEnvAsDuration("AEGISGATE_SHUTDOWN_TIMEOUT", 60*time.Second),
		RateLimit:       getEnvAsInt("AEGISGATE_RATE_LIMIT", 1000),
		LogLevel:        getEnv("AEGISGATE_LOG_LEVEL", "info"),
	}

	// Load ML config with defaults
	cfg.ML = DefaultMLConfig()

	// Override from environment if present
	if val := os.Getenv("AEGISGATE_ML_ENABLED"); val != "" {
		cfg.ML.Enabled = val == "true"
	}
	if val := os.Getenv("AEGISGATE_ML_SENSITIVITY"); val != "" {
		cfg.ML.Sensitivity = val
	}

	// Load plugin config
	cfg.Plugins = DefaultPluginConfig()

	// Load security config
	cfg.Security = DefaultSecurityConfig()

	return cfg, nil
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Start with defaults
	cfg := &Config{
		BindAddress:     ":8443",
		CertDir:         "./certs",
		Upstream:        "http://localhost:8080",
		MaxBodySize:     10 * 1024 * 1024,
		MaxConns:        1000,
		Timeout:         30 * time.Second,
		ShutdownTimeout: 60 * time.Second,
		RateLimit:       1000,
		LogLevel:        "info",
	}

	// Set default ML and Security configs
	cfg.ML = DefaultMLConfig()
	cfg.Plugins = DefaultPluginConfig()
	cfg.Security = DefaultSecurityConfig()

	// Unmarshal YAML (using empty interface to handle partial configs)
	var yamlConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Manually map fields to support partial configs
	if val, ok := yamlConfig["bind_address"].(string); ok && val != "" {
		cfg.BindAddress = val
	}
	if val, ok := yamlConfig["cert_dir"].(string); ok && val != "" {
		cfg.CertDir = val
	}
	if val, ok := yamlConfig["upstream"].(string); ok && val != "" {
		cfg.Upstream = val
	}
	if val, ok := yamlConfig["max_body_size"].(int64); ok && val > 0 {
		cfg.MaxBodySize = val
	}
	if val, ok := yamlConfig["max_body_size"].(int); ok && val > 0 {
		cfg.MaxBodySize = int64(val)
	}
	if val, ok := yamlConfig["max_conns"].(int); ok && val > 0 {
		cfg.MaxConns = val
	}
	if val, ok := yamlConfig["timeout"].(string); ok && val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			cfg.Timeout = duration
		}
	}
	if val, ok := yamlConfig["shutdown_timeout"].(string); ok && val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			cfg.ShutdownTimeout = duration
		}
	}
	if val, ok := yamlConfig["rate_limit"].(int); ok && val > 0 {
		cfg.RateLimit = val
	}
	if val, ok := yamlConfig["log_level"].(string); ok && val != "" {
		cfg.LogLevel = val
	}

	// Handle TLS config
	if tlsVal, ok := yamlConfig["tls"].(map[string]interface{}); ok {
		cfg.TLS = &TLSConfig{}
		if val, ok := tlsVal["enabled"].(bool); ok {
			cfg.TLS.Enabled = val
		}
		if val, ok := tlsVal["cert_file"].(string); ok {
			cfg.TLS.CertFile = val
		}
		if val, ok := tlsVal["key_file"].(string); ok {
			cfg.TLS.KeyFile = val
		}
		if val, ok := tlsVal["ca_file"].(string); ok {
			cfg.TLS.CAFile = val
		}
		if val, ok := tlsVal["skip_verify"].(bool); ok {
			cfg.TLS.SkipVerify = val
		}
	}

	// Handle ML config
	if mlVal, ok := yamlConfig["ml"].(map[string]interface{}); ok {
		cfg.ML = parseMLConfig(mlVal)
	}

	// Handle Security config
	if secVal, ok := yamlConfig["security"].(map[string]interface{}); ok {
		cfg.Security = parseSecurityConfig(secVal)
	}

	// Handle Plugins config
	if plugVal, ok := yamlConfig["plugins"].(map[string]interface{}); ok {
		cfg.Plugins = parsePluginConfig(plugVal)
	}

	return cfg, nil
}

// parseMLConfig parses ML configuration from map
func parseMLConfig(mlVal map[string]interface{}) *MLConfig {
	ml := DefaultMLConfig()

	if val, ok := mlVal["enabled"].(bool); ok {
		ml.Enabled = val
	}
	if val, ok := mlVal["sensitivity"].(string); ok && val != "" {
		ml.Sensitivity = val
	}
	if val, ok := mlVal["block_on_critical"].(bool); ok {
		ml.BlockOnCriticalSeverity = val
	}
	if val, ok := mlVal["block_on_high"].(bool); ok {
		ml.BlockOnHighSeverity = val
	}
	if val, ok := mlVal["min_score_to_block"].(float64); ok {
		ml.MinScoreToBlock = val
	}
	if val, ok := mlVal["sample_rate"].(int); ok {
		ml.SampleRate = val
	}
	if val, ok := mlVal["excluded_paths"].([]interface{}); ok {
		ml.ExcludedPaths = make([]string, len(val))
		for i, v := range val {
			ml.ExcludedPaths[i] = fmt.Sprintf("%v", v)
		}
	}
	if val, ok := mlVal["excluded_methods"].([]interface{}); ok {
		ml.ExcludedMethods = make([]string, len(val))
		for i, v := range val {
			ml.ExcludedMethods[i] = fmt.Sprintf("%v", v)
		}
	}
	if val, ok := mlVal["log_all_anomalies"].(bool); ok {
		ml.LogAllAnomalies = val
	}
	if val, ok := mlVal["enable_prompt_injection"].(bool); ok {
		ml.EnablePromptInjectionDetection = val
	}
	if val, ok := mlVal["prompt_injection_sensitivity"].(int); ok {
		ml.PromptInjectionSensitivity = val
	}
	if val, ok := mlVal["enable_content_analysis"].(bool); ok {
		ml.EnableContentAnalysis = val
	}
	if val, ok := mlVal["enable_behavioral_analysis"].(bool); ok {
		ml.EnableBehavioralAnalysis = val
	}
	if val, ok := mlVal["window_size"].(int); ok {
		ml.WindowSize = val
	}
	if val, ok := mlVal["z_threshold"].(float64); ok {
		ml.ZThreshold = val
	}
	if val, ok := mlVal["min_samples"].(int); ok {
		ml.MinSamples = val
	}
	if val, ok := mlVal["entropy_threshold"].(float64); ok {
		ml.EntropyThreshold = val
	}

	return ml
}

// parseSecurityConfig parses Security configuration from map
func parseSecurityConfig(secVal map[string]interface{}) *SecurityConfig {
	sec := DefaultSecurityConfig()

	if val, ok := secVal["enable_fips"].(bool); ok {
		sec.EnableFIPS = val
	}
	if val, ok := secVal["enable_audit_logging"].(bool); ok {
		sec.EnableAuditLogging = val
	}
	if val, ok := secVal["audit_log_path"].(string); ok {
		sec.AuditLogPath = val
	}
	if val, ok := secVal["enable_opsec"].(bool); ok {
		sec.EnableOPSEC = val
	}
	if val, ok := secVal["enable_immutable_config"].(bool); ok {
		sec.EnableImmutableConfig = val
	}
	if val, ok := secVal["enable_readonly_fs"].(bool); ok {
		sec.EnableReadOnlyFS = val
	}
	if val, ok := secVal["enable_wal"].(bool); ok {
		sec.EnableWAL = val
	}
	if val, ok := secVal["enable_snapshot"].(bool); ok {
		sec.EnableSnapshot = val
	}
	if val, ok := secVal["enable_rollback"].(bool); ok {
		sec.EnableRollback = val
	}
	if val, ok := secVal["max_memory_mb"].(int); ok {
		sec.MaxMemoryMB = val
	}
	if val, ok := secVal["enable_security_headers"].(bool); ok {
		sec.EnableSecurityHeaders = val
	}
	if val, ok := secVal["allowed_methods"].([]interface{}); ok {
		sec.AllowedMethods = make([]string, len(val))
		for i, v := range val {
			sec.AllowedMethods[i] = fmt.Sprintf("%v", v)
		}
	}
	if val, ok := secVal["blocked_ips"].([]interface{}); ok {
		sec.BlockedIPs = make([]string, len(val))
		for i, v := range val {
			sec.BlockedIPs[i] = fmt.Sprintf("%v", v)
		}
	}
	if val, ok := secVal["allowed_hosts"].([]interface{}); ok {
		sec.AllowedHosts = make([]string, len(val))
		for i, v := range val {
			sec.AllowedHosts[i] = fmt.Sprintf("%v", v)
		}
	}

	return sec
}

// parsePluginConfig parses Plugin configuration from map
func parsePluginConfig(plugVal map[string]interface{}) *PluginConfig {
	plug := DefaultPluginConfig()

	if val, ok := plugVal["enabled"].(bool); ok {
		plug.Enabled = val
	}
	if val, ok := plugVal["directories"].([]interface{}); ok {
		plug.Directories = make([]string, len(val))
		for i, v := range val {
			plug.Directories[i] = fmt.Sprintf("%v", v)
		}
	}
	if val, ok := plugVal["timeout"].(string); ok && val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			plug.Timeout = duration
		}
	}
	if val, ok := plugVal["enable_periodic"].(bool); ok {
		plug.EnablePeriodic = val
	}

	return plug
}

// LoadWithEnvOverrides applies environment variable overrides to an existing config
func LoadWithEnvOverrides(cfg *Config) (*Config, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	// Override from environment
	if val := os.Getenv("AEGISGATE_BIND_ADDRESS"); val != "" {
		cfg.BindAddress = val
	}
	if val := os.Getenv("AEGISGATE_CERT_DIR"); val != "" {
		cfg.CertDir = val
	}
	if val := os.Getenv("AEGISGATE_UPSTREAM"); val != "" {
		cfg.Upstream = val
	}
	if val := os.Getenv("AEGISGATE_MAX_BODY_SIZE"); val != "" {
		if intVal, err := strconv.ParseInt(val, 10, 64); err == nil {
			cfg.MaxBodySize = intVal
		}
	}
	if val := os.Getenv("AEGISGATE_MAX_CONNS"); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			cfg.MaxConns = intVal
		}
	}
	if val := os.Getenv("AEGISGATE_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			cfg.Timeout = duration
		}
	}
	if val := os.Getenv("AEGISGATE_SHUTDOWN_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			cfg.ShutdownTimeout = duration
		}
	}
	if val := os.Getenv("AEGISGATE_RATE_LIMIT"); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			cfg.RateLimit = intVal
		}
	}
	if val := os.Getenv("AEGISGATE_LOG_LEVEL"); val != "" {
		cfg.LogLevel = val
	}

	// ML overrides
	if cfg.ML == nil {
		cfg.ML = DefaultMLConfig()
	}
	if val := os.Getenv("AEGISGATE_ML_ENABLED"); val != "" {
		cfg.ML.Enabled = val == "true"
	}
	if val := os.Getenv("AEGISGATE_ML_SENSITIVITY"); val != "" {
		cfg.ML.Sensitivity = val
	}
	if val := os.Getenv("AEGISGATE_ML_BLOCK_ON_CRITICAL"); val != "" {
		cfg.ML.BlockOnCriticalSeverity = val == "true"
	}
	if val := os.Getenv("AEGISGATE_ML_BLOCK_ON_HIGH"); val != "" {
		cfg.ML.BlockOnHighSeverity = val == "true"
	}
	if val := os.Getenv("AEGISGATE_ML_SAMPLE_RATE"); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			cfg.ML.SampleRate = intVal
		}
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.BindAddress == "" {
		return fmt.Errorf("bind_address is required")
	}
	if c.Upstream == "" {
		return fmt.Errorf("upstream is required")
	}
	if c.MaxBodySize <= 0 {
		return fmt.Errorf("max_body_size must be positive")
	}
	if c.MaxConns <= 0 {
		return fmt.Errorf("max_conns must be positive")
	}
	if c.RateLimit <= 0 {
		return fmt.Errorf("rate_limit must be positive")
	}

	// Validate ML config
	if c.ML != nil {
		if c.ML.Sensitivity != "" {
			switch c.ML.Sensitivity {
			case "low", "medium", "high", "paranoid":
				// Valid
			default:
				return fmt.Errorf("invalid ml.sensitivity: %s (must be low, medium, high, or paranoid)", c.ML.Sensitivity)
			}
		}
		if c.ML.SampleRate < 0 || c.ML.SampleRate > 100 {
			return fmt.Errorf("ml.sample_rate must be between 0 and 100")
		}
		if c.ML.WindowSize <= 0 {
			return fmt.Errorf("ml.window_size must be positive")
		}
		if c.ML.ZThreshold <= 0 {
			return fmt.Errorf("ml.z_threshold must be positive")
		}
	}

	// Validate security config
	if c.Security != nil {
		if err := c.Security.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// GetMLConfig returns the ML configuration
func (c *Config) GetMLConfig() *MLConfig {
	if c.ML == nil {
		return DefaultMLConfig()
	}
	return c.ML
}

// SetMLConfig sets the ML configuration
func (c *Config) SetMLConfig(ml *MLConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ML = ml
}

// GetProxyOptions converts config to proxy.Options for the proxy package
func (c *Config) GetProxyOptions() map[string]interface{} {
	opts := map[string]interface{}{
		"ListenAddr":  c.BindAddress,
		"UpstreamURL": c.Upstream,
		"MaxBodySize": c.MaxBodySize,
		"MaxConns":    c.MaxConns,
		"RateLimit":   c.RateLimit,
	}

	// Add ML options if enabled
	if c.ML != nil && c.ML.Enabled {
		opts["EnableMLDetection"] = true
		opts["MLSensitivity"] = c.ML.Sensitivity
		opts["MLBlockOnCriticalSeverity"] = c.ML.BlockOnCriticalSeverity
		opts["MLBlockOnHighSeverity"] = c.ML.BlockOnHighSeverity
		opts["MLMinScoreToBlock"] = c.ML.MinScoreToBlock
		opts["MLSampleRate"] = c.ML.SampleRate
		opts["MLExcludedPaths"] = c.ML.ExcludedPaths
		opts["MLExcludedMethods"] = c.ML.ExcludedMethods
		opts["EnablePromptInjectionDetection"] = c.ML.EnablePromptInjectionDetection
		opts["PromptInjectionSensitivity"] = c.ML.PromptInjectionSensitivity
		opts["EnableContentAnalysis"] = c.ML.EnableContentAnalysis
		opts["EnableBehavioralAnalysis"] = c.ML.EnableBehavioralAnalysis
	}

	return opts
}

func getEnv(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func getEnvAsInt64(key string, defaultValue int64) int64 {
	if value, ok := os.LookupEnv(key); ok {
		if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value, ok := os.LookupEnv(key); ok {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value, ok := os.LookupEnv(key); ok {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
