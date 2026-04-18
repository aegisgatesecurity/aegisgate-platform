package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Errorf("Load() returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil configuration")
	}

	// Verify MVP fields exist
	if cfg.BindAddress == "" {
		t.Error("BindAddress should not be empty")
	}
	if cfg.Upstream == "" {
		t.Error("Upstream should not be empty")
	}
	if cfg.CertDir == "" {
		t.Error("CertDir should not be empty")
	}
	if cfg.MaxBodySize <= 0 {
		t.Error("MaxBodySize should be positive")
	}
	if cfg.MaxConns <= 0 {
		t.Error("MaxConns should be positive")
	}
}

func TestMLConfigDefaults(t *testing.T) {
	mlCfg := DefaultMLConfig()
	if mlCfg == nil {
		t.Fatal("DefaultMLConfig() returned nil")
	}
	if !mlCfg.Enabled {
		t.Error("ML should be enabled by default")
	}
	if mlCfg.Sensitivity != "medium" {
		t.Errorf("Expected sensitivity 'medium', got '%s'", mlCfg.Sensitivity)
	}
	if mlCfg.SampleRate != 100 {
		t.Errorf("Expected SampleRate 100, got %d", mlCfg.SampleRate)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				BindAddress: ":8443",
				Upstream:    "http://localhost:8080",
				CertDir:     "./certs",
				MaxBodySize: 1024 * 1024,
				MaxConns:    100,
				RateLimit:   100,
			},
			wantErr: false,
		},
		{
			name: "missing bind address",
			cfg: &Config{
				BindAddress: "",
				Upstream:    "http://localhost:8080",
				CertDir:     "./certs",
				MaxBodySize: 1024 * 1024,
				MaxConns:    100,
				RateLimit:   100,
			},
			wantErr: true,
		},
		{
			name: "missing upstream",
			cfg: &Config{
				BindAddress: ":8443",
				Upstream:    "",
				CertDir:     "./certs",
				MaxBodySize: 1024 * 1024,
				MaxConns:    100,
				RateLimit:   100,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	// Test with environment variable
	t.Setenv("AEGISGATE_TEST_VAR", "test_value")
	val := getEnv("AEGISGATE_TEST_VAR", "default")
	if val != "test_value" {
		t.Errorf("Expected 'test_value', got '%s'", val)
	}

	// Test with default value
	val = getEnv("AEGISGATE_NONEXISTENT_VAR", "default_val")
	if val != "default_val" {
		t.Errorf("Expected 'default_val', got '%s'", val)
	}
}

func TestGetEnvAsInt(t *testing.T) {
	t.Setenv("AEGISGATE_TEST_INT", "42")
	val := getEnvAsInt("AEGISGATE_TEST_INT", 0)
	if val != 42 {
		t.Errorf("Expected 42, got %d", val)
	}

	val = getEnvAsInt("AEGISGATE_NONEXISTENT_INT", 100)
	if val != 100 {
		t.Errorf("Expected 100, got %d", val)
	}
}

func TestGetEnvAsDuration(t *testing.T) {
	t.Setenv("AEGISGATE_TEST_DURATION", "30s")
	val := getEnvAsDuration("AEGISGATE_TEST_DURATION", 10*time.Second)
	if val != 30*time.Second {
		t.Errorf("Expected 30s, got %v", val)
	}

	val = getEnvAsDuration("AEGISGATE_NONEXISTENT_DURATION", 60*time.Second)
	if val != 60*time.Second {
		t.Errorf("Expected 60s, got %v", val)
	}
}

// Test YAML file loading
func TestLoadFromFile(t *testing.T) {
	// Create a temporary config file
	content := `
bind_address: ":9090"
upstream: "https://api.anthropic.com"
max_body_size: 20971520
rate_limit: 2000

ml:
  enabled: true
  sensitivity: "high"
  sample_rate: 50
  block_on_critical: true
  block_on_high: true

security:
  enable_audit_logging: true
  max_memory_mb: 1024
`

	tmpFile, err := os.CreateTemp("", "aegisgate-config-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Load config from file
	cfg, err := LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadFromFile() returned error: %v", err)
	}

	// Verify values
	if cfg.BindAddress != ":9090" {
		t.Errorf("Expected bind_address ':9090', got '%s'", cfg.BindAddress)
	}
	if cfg.Upstream != "https://api.anthropic.com" {
		t.Errorf("Expected upstream 'https://api.anthropic.com', got '%s'", cfg.Upstream)
	}
	if cfg.MaxBodySize != 20971520 {
		t.Errorf("Expected max_body_size 20971520, got %d", cfg.MaxBodySize)
	}
	if cfg.RateLimit != 2000 {
		t.Errorf("Expected rate_limit 2000, got %d", cfg.RateLimit)
	}

	// Verify ML config
	if cfg.ML == nil {
		t.Fatal("ML config should not be nil")
	}
	if !cfg.ML.Enabled {
		t.Error("ML should be enabled")
	}
	if cfg.ML.Sensitivity != "high" {
		t.Errorf("Expected ML sensitivity 'high', got '%s'", cfg.ML.Sensitivity)
	}
	if cfg.ML.SampleRate != 50 {
		t.Errorf("Expected ML sample_rate 50, got %d", cfg.ML.SampleRate)
	}
	if !cfg.ML.BlockOnCriticalSeverity {
		t.Error("ML block_on_critical should be true")
	}
	if !cfg.ML.BlockOnHighSeverity {
		t.Error("ML block_on_high should be true")
	}

	// Verify Security config
	if cfg.Security == nil {
		t.Fatal("Security config should not be nil")
	}
	if !cfg.Security.EnableAuditLogging {
		t.Error("Security enable_audit_logging should be true")
	}
	if cfg.Security.MaxMemoryMB != 1024 {
		t.Errorf("Expected Security max_memory_mb 1024, got %d", cfg.Security.MaxMemoryMB)
	}
}

// Test LoadFromFile with non-existent file (should error)
func TestLoadFromFileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("LoadFromFile() should error for non-existent file")
	}
}

// Test environment variable overrides
func TestLoadWithEnvOverrides(t *testing.T) {
	// Set environment variables
	t.Setenv("AEGISGATE_BIND_ADDRESS", ":9999")
	t.Setenv("AEGISGATE_UPSTREAM", "https://test.example.com")
	t.Setenv("AEGISGATE_ML_ENABLED", "false")
	t.Setenv("AEGISGATE_ML_SENSITIVITY", "paranoid")

	// Create base config
	cfg := &Config{
		BindAddress: ":8443",
		Upstream:    "http://localhost:8080",
		ML: &MLConfig{
			Enabled:     true,
			Sensitivity: "medium",
		},
	}

	// Apply overrides
	cfg, err := LoadWithEnvOverrides(cfg)
	if err != nil {
		t.Errorf("LoadWithEnvOverrides() returned error: %v", err)
	}

	// Verify overrides
	if cfg.BindAddress != ":9999" {
		t.Errorf("Expected bind_address ':9999', got '%s'", cfg.BindAddress)
	}
	if cfg.Upstream != "https://test.example.com" {
		t.Errorf("Expected upstream 'https://test.example.com', got '%s'", cfg.Upstream)
	}
	if cfg.ML.Enabled != false {
		t.Errorf("Expected ML enabled false, got %v", cfg.ML.Enabled)
	}
	if cfg.ML.Sensitivity != "paranoid" {
		t.Errorf("Expected ML sensitivity 'paranoid', got '%s'", cfg.ML.Sensitivity)
	}
}

// Test TLS configuration parsing
func TestTLSConfig(t *testing.T) {
	cfg := &Config{
		BindAddress: ":8443",
		Upstream:    "https://api.openai.com",
		TLS: &TLSConfig{
			Enabled:    true,
			CertFile:   "/path/to/cert.pem",
			KeyFile:    "/path/to/key.pem",
			CAFile:     "/path/to/ca.pem",
			SkipVerify: false,
		},
	}

	if cfg.TLS == nil {
		t.Fatal("TLS config should not be nil")
	}
	if !cfg.TLS.Enabled {
		t.Error("TLS should be enabled")
	}
	if cfg.TLS.CertFile != "/path/to/cert.pem" {
		t.Errorf("Expected cert file, got '%s'", cfg.TLS.CertFile)
	}
}

// Test Plugin configuration
func TestPluginConfig(t *testing.T) {
	cfg := &Config{
		BindAddress: ":8443",
		Upstream:    "http://localhost:8080",
		Plugins: &PluginConfig{
			Enabled:     true,
			Directories: []string{"./plugins", "./custom"},
			Timeout:     60 * time.Second,
		},
	}

	if cfg.Plugins == nil {
		t.Fatal("Plugins config should not be nil")
	}
	if !cfg.Plugins.Enabled {
		t.Error("Plugins should be enabled")
	}
	if len(cfg.Plugins.Directories) != 2 {
		t.Errorf("Expected 2 plugin directories, got %d", len(cfg.Plugins.Directories))
	}
	if cfg.Plugins.Timeout != 60*time.Second {
		t.Errorf("Expected 60s timeout, got %v", cfg.Plugins.Timeout)
	}
}

// Test GetProxyOptions
func TestGetProxyOptions(t *testing.T) {
	cfg := &Config{
		BindAddress: ":8443",
		Upstream:    "https://api.openai.com",
		MaxBodySize: 10 * 1024 * 1024,
		MaxConns:    500,
		RateLimit:   500,
		ML: &MLConfig{
			Enabled:                        true,
			Sensitivity:                    "high",
			BlockOnCriticalSeverity:        true,
			BlockOnHighSeverity:            true,
			MinScoreToBlock:                2.5,
			SampleRate:                     75,
			ExcludedPaths:                  []string{"/health"},
			ExcludedMethods:                []string{"OPTIONS"},
			EnablePromptInjectionDetection: true,
			PromptInjectionSensitivity:     80,
			EnableContentAnalysis:          true,
			EnableBehavioralAnalysis:       true,
		},
	}

	opts := cfg.GetProxyOptions()

	// Check basic options
	if opts["ListenAddr"] != ":8443" {
		t.Errorf("Expected ListenAddr ':8443', got '%v'", opts["ListenAddr"])
	}
	if opts["UpstreamURL"] != "https://api.openai.com" {
		t.Errorf("Expected UpstreamURL, got '%v'", opts["UpstreamURL"])
	}

	// Check ML options
	if opts["EnableMLDetection"] != true {
		t.Error("Expected EnableMLDetection true")
	}
	if opts["MLSensitivity"] != "high" {
		t.Errorf("Expected MLSensitivity 'high', got '%v'", opts["MLSensitivity"])
	}
	if opts["MLBlockOnCriticalSeverity"] != true {
		t.Error("Expected MLBlockOnCriticalSeverity true")
	}
	if opts["MLSampleRate"] != 75 {
		t.Errorf("Expected MLSampleRate 75, got %v", opts["MLSampleRate"])
	}
}

// Test Security validation
func TestSecurityConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		sec     SecurityConfig
		wantErr bool
	}{
		{
			name: "valid security config",
			sec: SecurityConfig{
				MaxMemoryMB: 512,
			},
			wantErr: false,
		},
		{
			name: "invalid - too low memory",
			sec: SecurityConfig{
				MaxMemoryMB: 32,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sec.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("SecurityConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
