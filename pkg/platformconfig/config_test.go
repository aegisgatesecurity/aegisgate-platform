package platformconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if config.Platform.Version != "2.0.0-dev" {
		t.Errorf("Platform.Version = %v, want 2.0.0-dev", config.Platform.Version)
	}
	if config.Platform.Mode != "standalone" {
		t.Errorf("Platform.Mode = %v, want standalone", config.Platform.Mode)
	}
	if !config.Dashboard.Enabled {
		t.Error("Dashboard.Enabled should be true")
	}
	if config.Dashboard.Port == 0 {
		t.Error("Dashboard.Port should not be 0")
	}
	if config.TLS.Enabled {
		t.Error("TLS.Enabled should be false by default")
	}
	if config.Persistence.DataDir == "" {
		t.Error("Persistence.DataDir should not be empty")
	}
	if !config.Security.EnableSecurityHeaders {
		t.Error("Security.EnableSecurityHeaders should be true")
	}
	if config.Logging.Level == "" {
		t.Error("Logging.Level should not be empty")
	}
	if config.Logging.Format == "" {
		t.Error("Logging.Format should not be empty")
	}
}

func TestLoadFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `
platform:
  version: "1.0.0-test"
  mode: connected
dashboard:
  enabled: false
  port: 9090
tls:
  enabled: true
  cert_dir: "/certs"
logging:
  level: debug
  format: json
security:
  enable_security_headers: true
  enable_csrf: true
`

	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	config, err := LoadFromFile(configFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if config.Platform.Version != "1.0.0-test" {
		t.Errorf("Platform.Version = %v, want 1.0.0-test", config.Platform.Version)
	}
	if config.Platform.Mode != "connected" {
		t.Errorf("Platform.Mode = %v, want connected", config.Platform.Mode)
	}
	if config.Dashboard.Enabled {
		t.Error("Dashboard.Enabled should be false")
	}
	if !config.TLS.Enabled {
		t.Error("TLS.Enabled should be true")
	}
	if config.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %v, want debug", config.Logging.Level)
	}
	if config.Logging.Format != "json" {
		t.Errorf("Logging.Format = %v, want json", config.Logging.Format)
	}
	if !config.Security.EnableSecurityHeaders {
		t.Error("Security.EnableSecurityHeaders should be true")
	}
	if !config.Security.EnableCSRF {
		t.Error("Security.EnableCSRF should be true")
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	// When config file doesn't exist, LoadFromFile returns default config with env overrides
	// This is NOT an error - it's expected behavior
	config, err := LoadFromFile("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("LoadFromFile with nonexistent path should return default config, got error: %v", err)
	}
	if config == nil {
		t.Error("LoadFromFile should return default config when path doesn't exist")
	}
}

func TestLoad_WithEmptyPath(t *testing.T) {
	config, err := Load("")
	if err != nil {
		t.Fatalf("Load with empty path failed: %v", err)
	}
	if config == nil {
		t.Fatal("Load returned nil config")
	}
	if config.Platform.Version != "2.0.0-dev" {
		t.Errorf("Expected default version, got %v", config.Platform.Version)
	}
}

func TestConfig_ProxyPort(t *testing.T) {
	config := DefaultConfig()
	port := config.ProxyPort()
	if port == 0 {
		t.Error("ProxyPort should not return 0")
	}
}

func TestConfig_MCPPort(t *testing.T) {
	config := DefaultConfig()
	port := config.MCPPort()
	if port == 0 {
		t.Error("MCPPort should not return 0")
	}
}

func TestConfig_IsStandaloneMode(t *testing.T) {
	config := DefaultConfig()
	
	result := config.IsStandaloneMode(false)
	if !result {
		t.Error("IsStandaloneMode should return true for standalone mode")
	}

	result = config.IsStandaloneMode(true)
	if !result {
		t.Error("IsStandaloneMode should return true when cliFlag is true")
	}

	config.Platform.Mode = "connected"
	result = config.IsStandaloneMode(false)
	if result {
		t.Error("IsStandaloneMode should return false for connected mode")
	}

	result = config.IsStandaloneMode(true)
	if !result {
		t.Error("IsStandaloneMode should return true when cliFlag is true regardless of config")
	}
}

func TestConfig_applyEnvOverrides(t *testing.T) {
	savedVars := map[string]string{
		"AEGISGATE_PLATFORM_MODE":     os.Getenv("AEGISGATE_PLATFORM_MODE"),
		"AEGISGATE_BIND_ADDRESS":      os.Getenv("AEGISGATE_BIND_ADDRESS"),
		"AEGISGATE_UPSTREAM":          os.Getenv("AEGISGATE_UPSTREAM"),
		"AEGISGATE_RATE_LIMIT":        os.Getenv("AEGISGATE_RATE_LIMIT"),
		"AEGISGATE_LOG_LEVEL":         os.Getenv("AEGISGATE_LOG_LEVEL"),
		"AEGISGATE_TLS_ENABLED":       os.Getenv("AEGISGATE_TLS_ENABLED"),
	}
	
	defer func() {
		for k, v := range savedVars {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()
	
	for k := range savedVars {
		os.Unsetenv(k)
	}
	
	os.Setenv("AEGISGATE_PLATFORM_MODE", "connected")
	os.Setenv("AEGISGATE_BIND_ADDRESS", "0.0.0.0:8080")
	os.Setenv("AEGISGATE_UPSTREAM", "http://upstream:9090")
	os.Setenv("AEGISGATE_RATE_LIMIT", "500")
	os.Setenv("AEGISGATE_LOG_LEVEL", "debug")
	os.Setenv("AEGISGATE_TLS_ENABLED", "true")
	
	config, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	
	if config.Platform.Mode != "connected" {
		t.Errorf("Platform.Mode = %v, want connected", config.Platform.Mode)
	}
	if config.Proxy.BindAddress != "0.0.0.0:8080" {
		t.Errorf("Proxy.BindAddress = %v, want 0.0.0.0:8080", config.Proxy.BindAddress)
	}
	if config.Proxy.Upstream != "http://upstream:9090" {
		t.Errorf("Proxy.Upstream = %v, want http://upstream:9090", config.Proxy.Upstream)
	}
	if config.Proxy.RateLimit != 500 {
		t.Errorf("Proxy.RateLimit = %v, want 500", config.Proxy.RateLimit)
	}
	if config.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %v, want debug", config.Logging.Level)
	}
	if config.Proxy.LogLevel != "debug" {
		t.Errorf("Proxy.LogLevel = %v, want debug", config.Proxy.LogLevel)
	}
	if !config.TLS.Enabled {
		t.Error("TLS.Enabled should be true")
	}
}

func TestConfig_applyEnvOverrides_InvalidRateLimit(t *testing.T) {
	oldRateLimit := os.Getenv("AEGISGATE_RATE_LIMIT")
	defer os.Setenv("AEGISGATE_RATE_LIMIT", oldRateLimit)
	
	os.Setenv("AEGISGATE_RATE_LIMIT", "invalid")
	
	config, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	
	_ = config.Proxy.RateLimit
}

func TestConfig_applyEnvOverrides_RateLimitInvalid(t *testing.T) {
	saved := os.Getenv("AEGISGATE_RATE_LIMIT")
	os.Setenv("AEGISGATE_RATE_LIMIT", "invalid")
	defer os.Setenv("AEGISGATE_RATE_LIMIT", saved)
	
	config, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	
	// Should still load with invalid rate limit - uses default
	if config == nil {
		t.Error("Should still return config with invalid rate limit")
	}
}

// Test MCPPort additional coverage
func TestConfig_MCPPort_Extended(t *testing.T) {
	config := DefaultConfig()
	
	// Test default MCP port
	port := config.MCPPort()
	if port == 0 {
		t.Error("MCPPort should return non-zero")
	}
	
	// Check that it's a valid port number
	if port < 1 || port > 65535 {
		t.Errorf("MCPPort %d is not a valid port number", port)
	}
}
