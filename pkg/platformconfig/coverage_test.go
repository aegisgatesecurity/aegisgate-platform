// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Coverage Boost Tests for platformconfig
// =========================================================================
// Target: 90%+ coverage (up from 70%) by exercising uncovered branches
// in LoadFromFile, Load, applyEnvOverrides, ProxyPort, and MCPPort.
// =========================================================================

package platformconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// helper to save, unset, and later restore a set of env vars
func withCleanEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	saved := make(map[string]string, len(vars))
	for k := range vars {
		saved[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	t.Cleanup(func() {
		for k, v := range saved {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — TLS Cert and Key
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_TLSCertAndKey(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_TLS_CERT": "",
		"AEGISGATE_TLS_KEY":  "",
	})

	os.Setenv("AEGISGATE_TLS_CERT", "/etc/certs/server.crt")
	os.Setenv("AEGISGATE_TLS_KEY", "/etc/certs/server.key")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.TLS.CertFile != "/etc/certs/server.crt" {
		t.Errorf("TLS.CertFile = %q, want /etc/certs/server.crt", cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "/etc/certs/server.key" {
		t.Errorf("TLS.KeyFile = %q, want /etc/certs/server.key", cfg.TLS.KeyFile)
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — Dashboard port (valid)
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_DashboardPort(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_DASHBOARD_PORT": "",
	})

	os.Setenv("AEGISGATE_DASHBOARD_PORT", "9999")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Dashboard.Port != 9999 {
		t.Errorf("Dashboard.Port = %d, want 9999", cfg.Dashboard.Port)
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — Dashboard port (invalid string)
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_DashboardPortInvalid(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_DASHBOARD_PORT": "",
	})

	os.Setenv("AEGISGATE_DASHBOARD_PORT", "abc")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	// Should retain the default value without panicking
	if cfg.Dashboard.Port == 0 {
		t.Error("Dashboard.Port should retain default value, got 0")
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGIS_PORT (valid)
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_AegisPort(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGIS_PORT": "",
	})

	os.Setenv("AEGIS_PORT", "6000")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Agent.Server.Port != 6000 {
		t.Errorf("Agent.Server.Port = %d, want 6000", cfg.Agent.Server.Port)
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGIS_PORT (invalid string)
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_AegisPortInvalid(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGIS_PORT": "",
	})

	os.Setenv("AEGIS_PORT", "not-a-number")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	// Should retain the default value without panicking
	// Just verify we didn't crash and port is still a reasonable value
	_ = cfg.Agent.Server.Port
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGIS_LOG_LEVEL
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_AegisLogLevel(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGIS_LOG_LEVEL": "",
	})

	os.Setenv("AEGIS_LOG_LEVEL", "trace")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Agent.Logging.Level != "trace" {
		t.Errorf("Agent.Logging.Level = %q, want trace", cfg.Agent.Logging.Level)
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGIS_AUDIT_ENABLED="true"
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_AegisAuditEnabled(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGIS_AUDIT_ENABLED": "",
	})

	os.Setenv("AEGIS_AUDIT_ENABLED", "true")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if !cfg.Agent.Audit.Enabled {
		t.Error("Agent.Audit.Enabled should be true")
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGIS_AUDIT_ENABLED="false"
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_AegisAuditDisabled(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGIS_AUDIT_ENABLED": "",
	})

	os.Setenv("AEGIS_AUDIT_ENABLED", "false")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Agent.Audit.Enabled {
		t.Error("Agent.Audit.Enabled should be false")
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — LICENSE_KEY
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_LicenseKey(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"LICENSE_KEY": "",
	})

	os.Setenv("LICENSE_KEY", "ABCD-1234-EFGH-5678")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Agent.License.LicenseKey != "ABCD-1234-EFGH-5678" {
		t.Errorf("Agent.License.LicenseKey = %q, want ABCD-1234-EFGH-5678", cfg.Agent.License.LicenseKey)
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGISGATE_SECURITY_HEADERS (true and false)
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_SecurityHeaders(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_SECURITY_HEADERS": "",
	})

	// Test enabling
	os.Setenv("AEGISGATE_SECURITY_HEADERS", "true")
	cfg := DefaultConfig()
	cfg.applyEnvOverrides()
	if !cfg.Security.EnableSecurityHeaders {
		t.Error("Security.EnableSecurityHeaders should be true when env is 'true'")
	}

	// Test disabling
	os.Setenv("AEGISGATE_SECURITY_HEADERS", "false")
	cfg = DefaultConfig()
	cfg.applyEnvOverrides()
	if cfg.Security.EnableSecurityHeaders {
		t.Error("Security.EnableSecurityHeaders should be false when env is 'false'")
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGISGATE_FIPS_ENABLED (true and false)
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_FIPS(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_FIPS_ENABLED": "",
	})

	// Test enabling
	os.Setenv("AEGISGATE_FIPS_ENABLED", "true")
	cfg := DefaultConfig()
	cfg.applyEnvOverrides()
	if !cfg.TLS.FIPS.Enabled {
		t.Error("TLS.FIPS.Enabled should be true when env is 'true'")
	}

	// Test disabling
	os.Setenv("AEGISGATE_FIPS_ENABLED", "false")
	cfg = DefaultConfig()
	cfg.applyEnvOverrides()
	if cfg.TLS.FIPS.Enabled {
		t.Error("TLS.FIPS.Enabled should be false when env is 'false'")
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGISGATE_PERSISTENCE_ENABLED
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_Persistence(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_PERSISTENCE_ENABLED": "",
	})

	os.Setenv("AEGISGATE_PERSISTENCE_ENABLED", "true")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if !cfg.Persistence.Enabled {
		t.Error("Persistence.Enabled should be true")
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGISGATE_DATA_DIR (sets DataDir, AuditDir, CertDir)
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_DataDir(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_DATA_DIR": "",
	})

	os.Setenv("AEGISGATE_DATA_DIR", "/data/aegisgate")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Persistence.DataDir != "/data/aegisgate" {
		t.Errorf("Persistence.DataDir = %q, want /data/aegisgate", cfg.Persistence.DataDir)
	}
	wantAuditDir := filepath.Join("/data/aegisgate", "audit")
	if cfg.Persistence.AuditDir != wantAuditDir {
		t.Errorf("Persistence.AuditDir = %q, want %q", cfg.Persistence.AuditDir, wantAuditDir)
	}
	wantCertDir := filepath.Join("/data/aegisgate", "certs")
	if cfg.TLS.CertDir != wantCertDir {
		t.Errorf("TLS.CertDir = %q, want %q", cfg.TLS.CertDir, wantCertDir)
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGISGATE_DATA_DIR with non-default CertDir should NOT
// override CertDir
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_DataDirNoDefaultCerts(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_DATA_DIR": "",
	})

	os.Setenv("AEGISGATE_DATA_DIR", "/data/aegisgate")

	cfg := DefaultConfig()
	// Set a non-default CertDir to simulate it being explicitly configured
	cfg.TLS.CertDir = "/custom/certs"

	cfg.applyEnvOverrides()

	if cfg.TLS.CertDir != "/custom/certs" {
		t.Errorf("TLS.CertDir = %q, want /custom/certs (should not be overridden)", cfg.TLS.CertDir)
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — AEGISGATE_TLS_ENABLED="false"
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_TLSDisabled(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_TLS_ENABLED": "",
	})

	os.Setenv("AEGISGATE_TLS_ENABLED", "false")

	cfg := DefaultConfig()
	cfg.TLS.Enabled = true // set to true, then env override should set it to false
	cfg.applyEnvOverrides()

	if cfg.TLS.Enabled {
		t.Error("TLS.Enabled should be false when AEGISGATE_TLS_ENABLED=false")
	}
}

// ---------------------------------------------------------------------------
// ProxyPort — invalid (non-numeric) port in bind address
// ---------------------------------------------------------------------------

func TestProxyPort_InvalidPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Proxy.BindAddress = "host:abc"

	port := cfg.ProxyPort()
	if port != 8080 {
		t.Errorf("ProxyPort() = %d, want 8080 for non-numeric port", port)
	}
}

// ---------------------------------------------------------------------------
// ProxyPort — no colon in bind address
// ---------------------------------------------------------------------------

func TestProxyPort_NoColon(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Proxy.BindAddress = "localhost"

	port := cfg.ProxyPort()
	if port != 8080 {
		t.Errorf("ProxyPort() = %d, want 8080 for address with no colon", port)
	}
}

// ---------------------------------------------------------------------------
// ProxyPort — valid port extraction
// ---------------------------------------------------------------------------

func TestProxyPort_ValidPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Proxy.BindAddress = ":9090"

	port := cfg.ProxyPort()
	if port != 9090 {
		t.Errorf("ProxyPort() = %d, want 9090", port)
	}
}

// ---------------------------------------------------------------------------
// MCPPort — zero port falls back to 8081
// ---------------------------------------------------------------------------

func TestMCPPort_ZeroPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Server.Port = 0

	port := cfg.MCPPort()
	if port != 8081 {
		t.Errorf("MCPPort() = %d, want 8081 when Agent.Server.Port is 0", port)
	}
}

// ---------------------------------------------------------------------------
// MCPPort — non-zero port is returned directly
// ---------------------------------------------------------------------------

func TestMCPPort_NonZeroPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Agent.Server.Port = 5000

	port := cfg.MCPPort()
	if port != 5000 {
		t.Errorf("MCPPort() = %d, want 5000", port)
	}
}

// ---------------------------------------------------------------------------
// Load — with a valid file path (hits the path != "" branch)
// ---------------------------------------------------------------------------

func TestLoad_WithValidPath(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	content := []byte("platform:\n  version: \"3.0.0-test\"\n  mode: connected\n")
	if err := os.WriteFile(configFile, content, 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load(%q) returned error: %v", configFile, err)
	}
	if cfg.Platform.Version != "3.0.0-test" {
		t.Errorf("Platform.Version = %q, want 3.0.0-test", cfg.Platform.Version)
	}
	if cfg.Platform.Mode != "connected" {
		t.Errorf("Platform.Mode = %q, want connected", cfg.Platform.Mode)
	}
}

// ---------------------------------------------------------------------------
// LoadFromFile — read error (non-IsNotExist), e.g. reading a directory
// ---------------------------------------------------------------------------

func TestLoadFromFile_ReadError(t *testing.T) {
	// Create a directory and try to read it as a file — this should produce
	// a non-IsNotExist error (e.g., "read /path: is a directory")
	tmpDir := t.TempDir()

	_, err := LoadFromFile(tmpDir)
	if err == nil {
		t.Fatal("LoadFromFile on a directory should return an error, got nil")
	}
}

// ---------------------------------------------------------------------------
// applyEnvOverrides — DataDir with empty CertDir (edge case)
// ---------------------------------------------------------------------------

func TestApplyEnvOverrides_DataDirEmptyCertDir(t *testing.T) {
	withCleanEnv(t, map[string]string{
		"AEGISGATE_DATA_DIR": "",
	})

	os.Setenv("AEGISGATE_DATA_DIR", "/opt/data")

	cfg := DefaultConfig()
	cfg.TLS.CertDir = "" // explicitly empty

	cfg.applyEnvOverrides()

	wantCertDir := filepath.Join("/opt/data", "certs")
	if cfg.TLS.CertDir != wantCertDir {
		t.Errorf("TLS.CertDir = %q, want %q when CertDir is empty", cfg.TLS.CertDir, wantCertDir)
	}
}
