// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// platformconfig Coverage Hardening — Round 3
// Target: LoadFromFile (91.7% → 95%+), applyEnvOverrides (93.6% → 95%+)
// =========================================================================

//go:build !race

package platformconfig

import (
	"os"
	"testing"
	"time"
)

func TestApplyEnvOverrides_PlatformMode(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_PLATFORM_MODE", "standalone")
	defer os.Unsetenv("AEGISGATE_PLATFORM_MODE")
	cfg.applyEnvOverrides()
	if cfg.Platform.Mode != "standalone" {
		t.Errorf("Platform.Mode = %q, want standalone", cfg.Platform.Mode)
	}
}

func TestApplyEnvOverrides_ProxyBindAddress(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_BIND_ADDRESS", "0.0.0.0:9090")
	defer os.Unsetenv("AEGISGATE_BIND_ADDRESS")
	cfg.applyEnvOverrides()
	if cfg.Proxy.BindAddress != "0.0.0.0:9090" {
		t.Errorf("Proxy.BindAddress = %q, want 0.0.0.0:9090", cfg.Proxy.BindAddress)
	}
}

func TestApplyEnvOverrides_Upstream(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_UPSTREAM", "https://api.openai.com")
	defer os.Unsetenv("AEGISGATE_UPSTREAM")
	cfg.applyEnvOverrides()
	if cfg.Proxy.Upstream != "https://api.openai.com" {
		t.Errorf("Proxy.Upstream = %q, want https://api.openai.com", cfg.Proxy.Upstream)
	}
}

func TestApplyEnvOverrides_RateLimit(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_RATE_LIMIT", "500")
	defer os.Unsetenv("AEGISGATE_RATE_LIMIT")
	cfg.applyEnvOverrides()
	if cfg.Proxy.RateLimit != 500 {
		t.Errorf("Proxy.RateLimit = %d, want 500", cfg.Proxy.RateLimit)
	}
}

func TestApplyEnvOverrides_RateLimitNonNumeric(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_RATE_LIMIT", "not-a-number")
	defer os.Unsetenv("AEGISGATE_RATE_LIMIT")
	cfg.applyEnvOverrides()
	// Should keep the default value when non-numeric
	if cfg.Proxy.RateLimit == 0 {
		t.Error("Proxy.RateLimit should not be 0 when rate limit is non-numeric")
	}
}

func TestApplyEnvOverrides_LogLevel(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_LOG_LEVEL", "debug")
	defer os.Unsetenv("AEGISGATE_LOG_LEVEL")
	cfg.applyEnvOverrides()
	if cfg.Proxy.LogLevel != "debug" || cfg.Logging.Level != "debug" {
		t.Errorf("LogLevel mismatch: Proxy=%q Logging=%q", cfg.Proxy.LogLevel, cfg.Logging.Level)
	}
}

func TestApplyEnvOverrides_TLSEnabled(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_TLS_ENABLED", "true")
	defer os.Unsetenv("AEGISGATE_TLS_ENABLED")
	cfg.applyEnvOverrides()
	if !cfg.TLS.Enabled {
		t.Error("TLS.Enabled should be true")
	}
}

func TestApplyEnvOverrides_A2AEnabled(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_A2A_ENABLED", "false")
	defer os.Unsetenv("AEGISGATE_A2A_ENABLED")
	cfg.applyEnvOverrides()
	if cfg.A2A.Enabled {
		t.Error("A2A.Enabled should be false")
	}
}

func TestApplyEnvOverrides_A2AConfigFile_Round3(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_A2A_CONFIG_FILE", "/etc/aegisgate/a2a.yaml")
	defer os.Unsetenv("AEGISGATE_A2A_CONFIG_FILE")
	cfg.applyEnvOverrides()
	if cfg.A2A.ConfigFile != "/etc/aegisgate/a2a.yaml" {
		t.Errorf("A2A.ConfigFile = %q, want /etc/aegisgate/a2a.yaml", cfg.A2A.ConfigFile)
	}
}

func TestApplyEnvOverrides_A2ACapsFile_Round3(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_A2A_CAPS_FILE", "/etc/aegisgate/caps.yaml")
	defer os.Unsetenv("AEGISGATE_A2A_CAPS_FILE")
	cfg.applyEnvOverrides()
	if cfg.A2A.CapsFile != "/etc/aegisgate/caps.yaml" {
		t.Errorf("A2A.CapsFile = %q, want /etc/aegisgate/caps.yaml", cfg.A2A.CapsFile)
	}
}

func TestApplyEnvOverrides_PersistenceEnabled(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_PERSISTENCE_ENABLED", "false")
	defer os.Unsetenv("AEGISGATE_PERSISTENCE_ENABLED")
	cfg.applyEnvOverrides()
	if cfg.Persistence.Enabled {
		t.Error("Persistence.Enabled should be false")
	}
}

func TestApplyEnvOverrides_ShutdownTimeout(t *testing.T) {
	cfg := DefaultConfig()
	os.Setenv("AEGISGATE_SHUTDOWN_TIMEOUT", "30s")
	defer os.Unsetenv("AEGISGATE_SHUTDOWN_TIMEOUT")
	cfg.applyEnvOverrides()
	if cfg.Platform.ShutdownTimeout != 30*time.Second {
		t.Errorf("Platform.ShutdownTimeout = %v, want 30s", cfg.Platform.ShutdownTimeout)
	}
}

func TestLoadFromFile_EnvOverridePrecedence(t *testing.T) {
	// Write a YAML file, then verify env overrides take precedence
	tmpDir := t.TempDir()
	configPath := tmpDir + "/config.yaml"
	// Write a config that sets BindAddress to :8080
	if err := os.WriteFile(configPath, []byte(`
platform:
  mode: connected
proxy:
  bind_address: "127.0.0.1:8080"
`), 0644); err != nil {
		t.Fatal(err)
	}
	os.Setenv("AEGISGATE_BIND_ADDRESS", "0.0.0.0:9999")
	defer os.Unsetenv("AEGISGATE_BIND_ADDRESS")

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	// Env override should win over file value
	if cfg.Proxy.BindAddress != "0.0.0.0:9999" {
		t.Errorf("Proxy.BindAddress = %q, want env override 0.0.0.0:9999", cfg.Proxy.BindAddress)
	}
}

func TestMCPPort_ExplicitPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Server.Port = 5000
	if port := cfg.MCPPort(); port != 5000 {
		t.Errorf("MCPPort() = %d, want 5000", port)
	}
}

func TestMCPPort_Fallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Server.Port = 0
	if port := cfg.MCPPort(); port != 8081 {
		t.Errorf("MCPPort() = %d, want default 8081", port)
	}
}

func TestProxyPort_IpPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Proxy.BindAddress = "192.168.1.1:8888"
	if port := cfg.ProxyPort(); port != 8888 {
		t.Errorf("ProxyPort() = %d, want 8888", port)
	}
}

func TestIsStandaloneMode_Connected_Round3(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Platform.Mode = "connected"
	if cfg.IsStandaloneMode(false) {
		t.Error("IsStandaloneMode(connected) = true, want false")
	}
}
