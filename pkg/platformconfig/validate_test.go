// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Config Validation Tests
// =========================================================================
//
// Tests that verify the Validate() method catches common misconfigurations:
//   - Port conflicts
//   - Empty required fields
//   - Invalid TLS versions / mTLS modes / FIPS levels
//   - Invalid log levels / formats
//   - Missing cert files when TLS is enabled
//   - SIEM platforms with no endpoint
//   - ML detection with shadow mode off
//   - Persistence with empty data dir
//
// =========================================================================

package platformconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// validTestConfig returns a Config that should pass validation with zero errors.
func validTestConfig() *Config {
	cfg := DefaultConfig()
	// Ensure no port conflicts
	cfg.Proxy.BindAddress = ":8080"
	cfg.Agent.Server.Port = 8081
	cfg.Dashboard.Port = 8443
	// Ensure required fields
	cfg.Proxy.Upstream = "https://api.openai.com"
	cfg.Dashboard.BindAddr = "0.0.0.0"
	// TLS off to avoid cert file checks
	cfg.TLS.Enabled = false
	return cfg
}

func TestValidationPassesForValidConfig(t *testing.T) {
	cfg := validTestConfig()
	result := cfg.Validate()
	if result.HasErrors() {
		t.Errorf("Valid config should have no errors, got %d: %s", len(result.Errors()), result.Summary())
	}
}

// ---------------------------------------------------------------------------
// Port conflict tests
// ---------------------------------------------------------------------------

func TestValidationDetectsProxyMCPConflict(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.Server.Port = cfg.ProxyPort() // same as proxy
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for proxy/MCP port conflict, got none")
	}
	found := false
	for _, f := range result.Errors() {
		if f.Field == "proxy.bind_address / agent.server.port" {
			found = true
		}
	}
	if !found {
		t.Error("Expected port conflict error for proxy/MCP")
	}
}

func TestValidationDetectsProxyDashboardConflict(t *testing.T) {
	cfg := validTestConfig()
	cfg.Dashboard.Port = cfg.ProxyPort()
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for proxy/dashboard port conflict, got none")
	}
}

func TestValidationDetectsMCPDashboardConflict(t *testing.T) {
	cfg := validTestConfig()
	cfg.Dashboard.Port = cfg.MCPPort()
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for MCP/dashboard port conflict, got none")
	}
}

// ---------------------------------------------------------------------------
// Required field tests
// ---------------------------------------------------------------------------

func TestValidationEmptyBindAddress(t *testing.T) {
	cfg := validTestConfig()
	cfg.Proxy.BindAddress = ""
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for empty bind_address")
	}
}

func TestValidationEmptyUpstream(t *testing.T) {
	cfg := validTestConfig()
	cfg.Proxy.Upstream = ""
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for empty upstream")
	}
}

func TestValidationEmptyDashboardBindAddr(t *testing.T) {
	cfg := validTestConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.BindAddr = ""
	result := cfg.Validate()
	// This is a warning, not an error
	if !result.HasWarnings() {
		t.Fatal("Expected warning for empty dashboard bind_addr")
	}
}

// ---------------------------------------------------------------------------
// Rate limit tests
// ---------------------------------------------------------------------------

func TestValidationNegativeRateLimit(t *testing.T) {
	cfg := validTestConfig()
	cfg.Proxy.RateLimit = -1
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for negative rate limit")
	}
}

func TestValidationZeroRateLimitIsOK(t *testing.T) {
	cfg := validTestConfig()
	cfg.Proxy.RateLimit = 0 // unlimited
	result := cfg.Validate()
	for _, f := range result.Errors() {
		if f.Field == "proxy.rate_limit" {
			t.Error("Zero rate limit should not be an error (means unlimited)")
		}
	}
}

func TestValidationAgentRateLimitEnabledButZero(t *testing.T) {
	cfg := validTestConfig()
	cfg.Agent.RateLimit.Enabled = true
	cfg.Agent.RateLimit.RequestsPerMinute = 0
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for agent rate limit enabled with 0 rpm")
	}
}

// ---------------------------------------------------------------------------
// TLS tests
// ---------------------------------------------------------------------------

func TestValidationInvalidTLSMinVersion(t *testing.T) {
	cfg := validTestConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.MinVersion = "1.0"
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for invalid TLS min version")
	}
}

func TestValidationValidTLSMinVersions(t *testing.T) {
	for _, ver := range []string{"1.2", "1.3"} {
		cfg := validTestConfig()
		cfg.TLS.Enabled = true
		cfg.TLS.MinVersion = ver
		cfg.TLS.AutoGenerate = true
		result := cfg.Validate()
		for _, f := range result.Errors() {
			if f.Field == "tls.min_version" {
				t.Errorf("TLS min_version %q should not be an error", ver)
			}
		}
	}
}

func TestValidationTLSEnabledNoCertsNoAutoGen(t *testing.T) {
	cfg := validTestConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.AutoGenerate = false
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for TLS enabled with no certs and no auto-generate")
	}
}

func TestValidationTLSEnabledWithNonexistentCerts(t *testing.T) {
	cfg := validTestConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.AutoGenerate = false
	cfg.TLS.CertFile = "/nonexistent/cert.pem"
	cfg.TLS.KeyFile = "/nonexistent/key.pem"
	result := cfg.Validate()
	// Nonexistent cert files are warnings (may be mounted at runtime), not errors
	if !result.HasWarnings() {
		t.Fatal("Expected warning for nonexistent cert files")
	}
}

func TestValidationTLSEnabledWithExistingCerts(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	os.WriteFile(certFile, []byte("fake cert"), 0644)
	os.WriteFile(keyFile, []byte("fake key"), 0644)

	cfg := validTestConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.AutoGenerate = false
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	result := cfg.Validate()
	for _, f := range result.Findings {
		if f.Field == "tls.cert_file" || f.Field == "tls.key_file" {
			t.Errorf("Existing cert/key should not generate findings: %s", f.Message)
		}
	}
}

func TestValidationTLSAutoGenSkipsCertCheck(t *testing.T) {
	cfg := validTestConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.AutoGenerate = true
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""
	result := cfg.Validate()
	for _, f := range result.Errors() {
		if f.Field == "tls.cert_file" || f.Field == "tls.key_file" {
			t.Errorf("Auto-generate should skip cert file check: %s", f.Message)
		}
	}
}

// ---------------------------------------------------------------------------
// mTLS tests
// ---------------------------------------------------------------------------

func TestValidationInvalidMTLSMode(t *testing.T) {
	cfg := validTestConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.AutoGenerate = true
	cfg.TLS.MutualTLS.Enabled = true
	cfg.TLS.MutualTLS.Mode = "invalid"
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for invalid mTLS mode")
	}
}

func TestValidationMTLSRequiredWithoutTLS(t *testing.T) {
	cfg := validTestConfig()
	cfg.TLS.Enabled = false
	cfg.TLS.MutualTLS.Enabled = true
	cfg.TLS.MutualTLS.Mode = "required"
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for mTLS required without TLS enabled")
	}
}

func TestValidationMTLSOptionalValid(t *testing.T) {
	cfg := validTestConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.AutoGenerate = true
	cfg.TLS.MutualTLS.Enabled = true
	cfg.TLS.MutualTLS.Mode = "optional"
	result := cfg.Validate()
	for _, f := range result.Errors() {
		if f.Field == "tls.mutual_tls.mode" {
			t.Errorf("mTLS mode 'optional' should not be an error: %s", f.Message)
		}
	}
}

// ---------------------------------------------------------------------------
// FIPS tests
// ---------------------------------------------------------------------------

func TestValidationInvalidFIPSLevel(t *testing.T) {
	cfg := validTestConfig()
	cfg.TLS.FIPS.Enabled = true
	cfg.TLS.FIPS.Level = "invalid"
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for invalid FIPS level")
	}
}

func TestValidationValidFIPSLevels(t *testing.T) {
	for _, level := range []string{"140-2", "140-3"} {
		cfg := validTestConfig()
		cfg.TLS.FIPS.Enabled = true
		cfg.TLS.FIPS.Level = level
		result := cfg.Validate()
		for _, f := range result.Errors() {
			if f.Field == "tls.fips.level" {
				t.Errorf("FIPS level %q should not be an error", level)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Logging tests
// ---------------------------------------------------------------------------

func TestValidationInvalidLogLevel(t *testing.T) {
	cfg := validTestConfig()
	cfg.Logging.Level = "verbose"
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for invalid log level")
	}
}

func TestValidationInvalidLogFormat(t *testing.T) {
	cfg := validTestConfig()
	cfg.Logging.Format = "xml"
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for invalid log format")
	}
}

func TestValidationValidLogLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		cfg := validTestConfig()
		cfg.Logging.Level = level
		result := cfg.Validate()
		for _, f := range result.Errors() {
			if f.Field == "logging.level" {
				t.Errorf("Log level %q should not be an error", level)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Persistence tests
// ---------------------------------------------------------------------------

func TestValidationEmptyDataDir(t *testing.T) {
	cfg := validTestConfig()
	cfg.Persistence.Enabled = true
	cfg.Persistence.DataDir = ""
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for empty data_dir with persistence enabled")
	}
}

func TestValidationEmptyAuditDir(t *testing.T) {
	cfg := validTestConfig()
	cfg.Persistence.Enabled = true
	cfg.Persistence.DataDir = "/data"
	cfg.Persistence.AuditDir = ""
	result := cfg.Validate()
	if !result.HasWarnings() {
		t.Fatal("Expected warning for empty audit_dir")
	}
}

// ---------------------------------------------------------------------------
// SIEM tests
// ---------------------------------------------------------------------------

func TestValidationSIEMEnabledNoEndpoint(t *testing.T) {
	cfg := validTestConfig()
	cfg.SIEM.Enabled = true
	cfg.SIEM.Platforms = []SIEMPlatformConfig{
		{Platform: "splunk", Enabled: true, Endpoint: ""},
	}
	result := cfg.Validate()
	if !result.HasErrors() {
		t.Fatal("Expected error for SIEM platform enabled with no endpoint")
	}
}

func TestValidationSIEMDisabledPlatformNoEndpointOK(t *testing.T) {
	cfg := validTestConfig()
	cfg.SIEM.Enabled = true
	cfg.SIEM.Platforms = []SIEMPlatformConfig{
		{Platform: "splunk", Enabled: false, Endpoint: ""},
	}
	result := cfg.Validate()
	for _, f := range result.Errors() {
		if f.Field == "siem.platforms[0].endpoint" {
			t.Error("Disabled SIEM platform should not require endpoint")
		}
	}
}

// ---------------------------------------------------------------------------
// ML tests
// ---------------------------------------------------------------------------

func TestValidationMLDetectionWithoutShadowMode(t *testing.T) {
	cfg := validTestConfig()
	cfg.Security.MLThreatDetectionEnabled = true
	cfg.Security.MLShadowMode = false
	result := cfg.Validate()
	if !result.HasWarnings() {
		t.Fatal("Expected warning for ML detection without shadow mode")
	}
}

func TestValidationMLDetectionWithShadowModeOK(t *testing.T) {
	cfg := validTestConfig()
	cfg.Security.MLThreatDetectionEnabled = true
	cfg.Security.MLShadowMode = true
	result := cfg.Validate()
	for _, f := range result.Findings {
		if f.Field == "security.ml_threat_detection_enabled / security.ml_shadow_mode" {
			t.Errorf("ML detection with shadow mode should not generate findings: %s", f.Message)
		}
	}
}

// ---------------------------------------------------------------------------
// Platform mode tests
// ---------------------------------------------------------------------------

func TestValidationInvalidPlatformMode(t *testing.T) {
	cfg := validTestConfig()
	cfg.Platform.Mode = "invalid"
	result := cfg.Validate()
	if !result.HasWarnings() {
		t.Fatal("Expected warning for invalid platform mode")
	}
}

// ---------------------------------------------------------------------------
// Shutdown timeout tests
// ---------------------------------------------------------------------------

func TestValidationShortShutdownTimeout(t *testing.T) {
	cfg := validTestConfig()
	cfg.Platform.ShutdownTimeout = 2 * time.Second
	result := cfg.Validate()
	if !result.HasWarnings() {
		t.Fatal("Expected warning for short shutdown timeout")
	}
}

func TestValidationAdequateShutdownTimeout(t *testing.T) {
	cfg := validTestConfig()
	cfg.Platform.ShutdownTimeout = 30 * time.Second
	result := cfg.Validate()
	for _, f := range result.Findings {
		if f.Field == "platform.shutdown_timeout" {
			t.Errorf("30s shutdown timeout should not generate findings: %s", f.Message)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidationResult method tests
// ---------------------------------------------------------------------------

func TestValidationResultSummaryNoFindings(t *testing.T) {
	r := &ValidationResult{Findings: nil}
	s := r.Summary()
	if !contains(s, "no errors or warnings") {
		t.Errorf("Summary for no findings should say 'no errors or warnings', got: %s", s)
	}
}

func TestValidationResultSummaryWithErrors(t *testing.T) {
	r := &ValidationResult{
		Findings: []ValidationFinding{
			{Severity: SeverityError, Field: "test", Message: "test error"},
		},
	}
	s := r.Summary()
	if !contains(s, "1 error") {
		t.Errorf("Summary should mention '1 error', got: %s", s)
	}
}

func TestValidationResultSummaryWithWarnings(t *testing.T) {
	r := &ValidationResult{
		Findings: []ValidationFinding{
			{Severity: SeverityWarning, Field: "test", Message: "test warning"},
		},
	}
	s := r.Summary()
	if !contains(s, "1 warning") {
		t.Errorf("Summary should mention '1 warning', got: %s", s)
	}
}

func TestValidationResultSummaryWithSuggestion(t *testing.T) {
	r := &ValidationResult{
		Findings: []ValidationFinding{
			{Severity: SeverityError, Field: "test", Message: "test error", Suggestion: "fix it"},
		},
	}
	s := r.Summary()
	if !contains(s, "fix it") {
		t.Errorf("Summary should contain suggestion, got: %s", s)
	}
}

func TestValidationResultHasErrorsAndWarnings(t *testing.T) {
	r := &ValidationResult{
		Findings: []ValidationFinding{
			{Severity: SeverityError, Field: "e", Message: "err"},
			{Severity: SeverityWarning, Field: "w", Message: "warn"},
		},
	}
	if !r.HasErrors() {
		t.Error("HasErrors should be true")
	}
	if !r.HasWarnings() {
		t.Error("HasWarnings should be true")
	}
	if len(r.Errors()) != 1 {
		t.Errorf("Errors() should return 1, got %d", len(r.Errors()))
	}
	if len(r.Warnings()) != 1 {
		t.Errorf("Warnings() should return 1, got %d", len(r.Warnings()))
	}
}

// ---------------------------------------------------------------------------
// A2A/ACP tests
// ---------------------------------------------------------------------------

func TestValidationA2AEnabledNoConfigFile(t *testing.T) {
	cfg := validTestConfig()
	cfg.A2A.Enabled = true
	cfg.A2A.ConfigFile = ""
	result := cfg.Validate()
	if !result.HasWarnings() {
		t.Fatal("Expected warning for A2A enabled with no config file")
	}
}

func TestValidationACPEnabledNonexistentConfigFile(t *testing.T) {
	cfg := validTestConfig()
	cfg.ACP.Enabled = true
	cfg.ACP.ConfigFile = "/nonexistent/acp.yaml"
	result := cfg.Validate()
	if !result.HasWarnings() {
		t.Fatal("Expected warning for ACP enabled with nonexistent config file")
	}
}

// ---------------------------------------------------------------------------
// Trust tests
// ---------------------------------------------------------------------------

func TestValidationTrustEnabledRequireLicense(t *testing.T) {
	cfg := validTestConfig()
	cfg.Trust.Enabled = true
	cfg.Trust.RequireLicense = true
	result := cfg.Validate()
	if !result.HasWarnings() {
		t.Fatal("Expected warning for Trust enabled with require_license")
	}
}

func TestValidationTrustEnabledNoRequireLicense(t *testing.T) {
	cfg := validTestConfig()
	cfg.Trust.Enabled = true
	cfg.Trust.RequireLicense = false
	result := cfg.Validate()
	for _, f := range result.Findings {
		if f.Field == "trust.require_license" {
			t.Errorf("Trust without require_license should not warn: %s", f.Message)
		}
	}
}

// ---------------------------------------------------------------------------
// ValidateFile test
// ---------------------------------------------------------------------------

func TestValidateFileValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "valid.yaml")
	content := `
platform:
  mode: standalone
proxy:
  bind_address: "0.0.0.0:8080"
  upstream: "https://api.openai.com"
  rate_limit: 100
dashboard:
  enabled: true
  bind_addr: "0.0.0.0"
  port: 8443
agent:
  server:
    port: 8081
logging:
  level: info
  format: json
persistence:
  enabled: true
  data_dir: "/data"
  audit_dir: "/data/audit"
`
	os.WriteFile(cfgPath, []byte(content), 0644)

	result, err := ValidateFile(cfgPath)
	if err != nil {
		t.Fatalf("ValidateFile error: %v", err)
	}
	if result.HasErrors() {
		t.Errorf("Valid file should have no errors: %s", result.Summary())
	}
}

func TestValidateFileNonexistent(t *testing.T) {
	// LoadFromFile returns defaults when file doesn't exist (existing behavior).
	// ValidateFile should still work — it validates the defaults.
	result, err := ValidateFile("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("ValidateFile should not error for nonexistent file (uses defaults): %v", err)
	}
	if result == nil {
		t.Fatal("ValidateFile should return a result even for nonexistent file")
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
