package platformconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// TestSaveToFile verifies that SaveToFile marshals and writes a config file.
func TestSaveToFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "saved_config.yaml")
	cfg := DefaultConfig()
	if err := cfg.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("saved file is empty")
	}
	// Round-trip: load it back
	cfg2, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile failed on saved file: %v", err)
	}
	if cfg2.Platform.Mode != cfg.Platform.Mode {
		t.Errorf("platform mode mismatch: got %q want %q", cfg2.Platform.Mode, cfg.Platform.Mode)
	}
}

// TestSaveToFileWriteError ensures the write-error path is exercised.
func TestSaveToFileWriteError(t *testing.T) {
	cfg := DefaultConfig()
	// Write to a directory path which will fail with WriteFile
	err := cfg.SaveToFile(t.TempDir()) // temp dir itself is not a file
	if err == nil {
		t.Fatal("expected error writing to a directory, got nil")
	}
}

// TestApplyEnvOverridesWrapper tests the exported ApplyEnvOverrides wrapper.
func TestApplyEnvOverridesWrapper(t *testing.T) {
	cfg := DefaultConfig()
	t.Setenv("AEGISGATE_ML_THRESHOLD", "0.75")
	t.Setenv("AEGISGATE_ML_MODEL_PATH", "/custom/model.onnx")
	t.Setenv("AEGISGATE_SIEM_ENABLED", "true")
	t.Setenv("AEGISGATE_SIEM_SOURCE", "custom-source")

	cfg.ApplyEnvOverrides()

	if cfg.Security.MLThreshold != 0.75 {
		t.Errorf("MLThreshold = %v, want 0.75", cfg.Security.MLThreshold)
	}
	if cfg.Security.MLModelPath != "/custom/model.onnx" {
		t.Errorf("MLModelPath = %q, want /custom/model.onnx", cfg.Security.MLModelPath)
	}
	if !cfg.SIEM.Enabled {
		t.Error("SIEM.Enabled = false, want true")
	}
	if cfg.SIEM.Source != "custom-source" {
		t.Errorf("SIEM.Source = %q, want custom-source", cfg.SIEM.Source)
	}
}

// TestAsMapNonMapInput covers the else branch of asMap.
func TestAsMapNonMapInput(t *testing.T) {
	m := asMap("not a map")
	if m == nil {
		t.Fatal("asMap returned nil for non-map input; expected empty map")
	}
	if len(m) != 0 {
		t.Fatalf("asMap returned non-empty map for non-map input: %v", m)
	}
	// Verify a real map passes through
	orig := map[string]interface{}{"key": "val"}
	m2 := asMap(orig)
	if m2["key"] != "val" {
		t.Fatal("asMap did not return the original map values")
	}
}

// TestMergeIntoMapNilBase covers the nil base branch of mergeIntoMap.
func TestMergeIntoMapNilBase(t *testing.T) {
	out := mergeIntoMap(nil, "foo", "bar")
	if out["foo"] != "bar" {
		t.Fatalf("mergeIntoMap(nil,...) did not set key: %v", out)
	}
	// Verify existing keys are preserved
	base := map[string]interface{}{"a": 1}
	out2 := mergeIntoMap(base, "b", 2)
	if out2["a"] != 1 || out2["b"] != 2 {
		t.Fatalf("mergeIntoMap did not preserve base or set new key: %v", out2)
	}
}

// TestTranslateLegacyConfigKeysMCPPort covers the server.mcp_port deprecated key.
func TestTranslateLegacyConfigKeysMCPPort(t *testing.T) {
	data := []byte("server:\n  mcp_port: 9090\n")
	_, warnings := translateLegacyConfigKeys(data)
	found := false
	for _, w := range warnings {
		if contains(w, "server.mcp_port") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected mcp_port deprecation warning, got: %v", warnings)
	}
}

// TestTranslateLegacyConfigKeysDashboardPort covers the server.dashboard_port deprecated key.
func TestTranslateLegacyConfigKeysDashboardPort(t *testing.T) {
	data := []byte("server:\n  dashboard_port: 3000\n")
	out, _ := translateLegacyConfigKeys(data)
	// out is YAML bytes; unmarshal to verify dashboard.port
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal translated output: %v", err)
	}
	dash, ok := parsed["dashboard"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected dashboard key in translated output, got: %v", parsed)
	}
	// yaml numbers come as float64 or int depending on size
	if port, ok := dash["port"].(int); !ok || port != 3000 {
		if pf, ok := dash["port"].(float64); ok && int(pf) == 3000 {
			return // correct
		}
		t.Fatalf("dashboard port not set correctly: got %v", dash["port"])
	}
}

// TestValidateHasWarnings tests HasWarnings returns true when warnings exist.
func TestValidateHasWarnings(t *testing.T) {
	r := &ValidationResult{
		Findings: []ValidationFinding{
			{Severity: SeverityWarning, Field: "test", Message: "test warning"},
		},
	}
	if !r.HasWarnings() {
		t.Fatal("HasWarnings() = false, expected true")
	}
	// Empty result should return false
	r2 := &ValidationResult{}
	if r2.HasWarnings() {
		t.Fatal("HasWarnings() = true for empty result, expected false")
	}
}

// TestSummaryWithSuggestions covers the error and warning suggestion branches.
func TestSummaryWithSuggestions(t *testing.T) {
	r := &ValidationResult{
		Findings: []ValidationFinding{
			{
				Severity:   SeverityError,
				Field:      "test.error",
				Message:    "error message",
				Suggestion: "fix the error",
			},
			{
				Severity:   SeverityWarning,
				Field:      "test.warning",
				Message:    "warning message",
				Suggestion: "fix the warning",
			},
		},
	}
	summary := r.Summary()
	if !contains(summary, "fix the error") {
		t.Errorf("summary missing error suggestion: %s", summary)
	}
	if !contains(summary, "fix the warning") {
		t.Errorf("summary missing warning suggestion: %s", summary)
	}
	if !contains(summary, "\n") {
		t.Errorf("summary should contain newline separator between errors and warnings")
	}
}

// TestValidateMutualTLSValidMode covers the valid mTLS mode branches.
func TestValidateMutualTLSValidMode(t *testing.T) {
	// "optional" mode — valid, should not add error for mode
	cfg := DefaultConfig()
	cfg.TLS.MutualTLS.Enabled = true
	cfg.TLS.MutualTLS.Mode = "optional"
	r := cfg.Validate()
	for _, f := range r.Findings {
		if f.Field == "tls.mutual_tls.mode" && f.Severity == SeverityError {
			t.Errorf("unexpected mTLS mode error for 'optional': %s", f.Message)
		}
	}

	// "required" mode with TLS enabled — valid
	cfg.TLS.MutualTLS.Mode = "required"
	cfg.TLS.Enabled = true
	r2 := cfg.Validate()
	for _, f := range r2.Findings {
		if f.Field == "tls.mutual_tls.enabled / tls.enabled" {
			t.Errorf("unexpected mTLS+TLS error for 'required' with TLS enabled: %s", f.Message)
		}
	}
}

// TestValidateFIPSValidLevel covers the valid FIPS level branches.
func TestValidateFIPSValidLevel(t *testing.T) {
	for _, level := range []string{"140-2", "140-3"} {
		cfg := DefaultConfig()
		cfg.TLS.FIPS.Enabled = true
		cfg.TLS.FIPS.Level = level
		r := cfg.Validate()
		for _, f := range r.Findings {
			if f.Field == "tls.fips.level" && f.Severity == SeverityError {
				t.Errorf("unexpected FIPS level error for %q: %s", level, f.Message)
			}
		}
	}
}

// TestValidateA2AConfigFileMissing covers the A2A config_file os.Stat error path.
func TestValidateA2AConfigFileMissing(t *testing.T) {
	cfg := DefaultConfig()
	cfg.A2A.Enabled = true
	cfg.A2A.ConfigFile = "/nonexistent/path/a2a.yaml"
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "a2a.config_file" && contains(f.Message, "does not exist") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a2a.config_file does-not-exist warning, got: %v", r.Findings)
	}
}

// TestValidateACPConfigFileMissing covers the ACP config_file os.Stat error path.
func TestValidateACPConfigFileMissing(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ACP.Enabled = true
	cfg.ACP.ConfigFile = "/nonexistent/path/acp.yaml"
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "acp.config_file" && contains(f.Message, "does not exist") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected acp.config_file does-not-exist warning, got: %v", r.Findings)
	}
}

// TestValidateSIEMBatchAndBuffer covers the SIEM batch_size and buffer_max_size warnings.
func TestValidateSIEMBatchAndBuffer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SIEM.Enabled = true
	cfg.SIEM.BatchSize = 0
	cfg.SIEM.BufferMaxSize = 0
	r := cfg.Validate()
	foundBatch := false
	foundBuffer := false
	for _, f := range r.Findings {
		if f.Field == "siem.batch_size" {
			foundBatch = true
		}
		if f.Field == "siem.buffer_max_size" {
			foundBuffer = true
		}
	}
	if !foundBatch {
		t.Errorf("expected siem.batch_size warning, got: %v", r.Findings)
	}
	if !foundBuffer {
		t.Errorf("expected siem.buffer_max_size warning, got: %v", r.Findings)
	}
}

// TestValidateFileLoadError covers the ValidateFile error path when the file is a directory.
func TestValidateFileLoadError(t *testing.T) {
	// Use a directory path which causes a read error (not IsNotExist)
	r, err := ValidateFile(t.TempDir())
	if err == nil {
		t.Fatal("expected error for directory path, got nil")
	}
	if r != nil {
		t.Fatalf("expected nil result on error, got: %v", r)
	}
}

// TestValidateFileSuccess covers the ValidateFile success path.
func TestValidateFileSuccess(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "valid_config.yaml")
	cfg := DefaultConfig()
	if err := cfg.SaveToFile(path); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}
	r, err := ValidateFile(path)
	if err != nil {
		t.Fatalf("ValidateFile failed: %v", err)
	}
	if r == nil {
		t.Fatal("expected non-nil ValidationResult")
	}
}

// TestApplyEnvOverridesMLShadowMode covers the ML shadow mode env override (line 709-715).
func TestApplyEnvOverridesMLShadowMode(t *testing.T) {
	cfg := DefaultConfig()
	t.Setenv("AEGISGATE_ML_SHADOW_MODE", "true")
	cfg.applyEnvOverrides()
	if !cfg.Security.MLShadowMode {
		t.Error("MLShadowMode = false, want true")
	}
}

// TestApplyEnvOverridesChainBlocking covers the chain blocking env override (line 757-761).
func TestApplyEnvOverridesChainBlocking(t *testing.T) {
	cfg := DefaultConfig()
	t.Setenv("AEGISGATE_CHAIN_BLOCKING_ENABLED", "true")
	cfg.applyEnvOverrides()
	if !cfg.Security.ChainBlockingEnabled {
		t.Error("ChainBlockingEnabled = false, want true")
	}
}

// TestTranslateLegacyConfigKeysHostOnly covers the hasHost-only path.
func TestTranslateLegacyConfigKeysHostOnly(t *testing.T) {
	data := []byte("server:\n  host: 127.0.0.1\n")
	out, warnings := translateLegacyConfigKeys(data)
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal translated output: %v", err)
	}
	proxy, ok := parsed["proxy"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected proxy key, got: %v", parsed)
	}
	bind, ok := proxy["bind_address"].(string)
	if !ok {
		t.Fatalf("expected bind_address string, got: %v", proxy)
	}
	if bind != "127.0.0.1:8080" {
		t.Fatalf("bind_address = %q, want 127.0.0.1:8080", bind)
	}
	if len(warnings) == 0 {
		t.Fatal("expected deprecation warning for server.host")
	}
}

// TestTranslateLegacyConfigKeysPortOnly covers the hasPort-only path with float64.
func TestTranslateLegacyConfigKeysPortOnly(t *testing.T) {
	data := []byte("server:\n  proxy_port: 9999\n")
	out, _ := translateLegacyConfigKeys(data)
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("failed to unmarshal translated output: %v", err)
	}
	proxy, ok := parsed["proxy"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected proxy key, got: %v", parsed)
	}
	bind, ok := proxy["bind_address"].(string)
	if !ok {
		t.Fatalf("expected bind_address string, got: %v", proxy)
	}
	if bind != "0.0.0.0:9999" {
		t.Fatalf("bind_address = %q, want 0.0.0.0:9999", bind)
	}
}

// TestValidateMutualTLSInvalidMode covers the default (invalid) mTLS mode error.
func TestValidateMutualTLSInvalidMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.MutualTLS.Enabled = true
	cfg.TLS.MutualTLS.Mode = "bogus"
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "tls.mutual_tls.mode" && f.Severity == SeverityError {
			found = true
		}
	}
	if !found {
		t.Fatal("expected mTLS mode error for invalid mode")
	}
}

// TestValidateMutualTLSRequiredNoTLS covers the mTLS required but TLS disabled error.
func TestValidateMutualTLSRequiredNoTLS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.MutualTLS.Enabled = true
	cfg.TLS.MutualTLS.Mode = "required"
	cfg.TLS.Enabled = false
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "tls.mutual_tls.enabled / tls.enabled" && f.Severity == SeverityError {
			found = true
		}
	}
	if !found {
		t.Fatal("expected mTLS+TLS error for required mode with TLS disabled")
	}
}

// TestValidateFIPSInvalidLevel covers the FIPS invalid level error.
func TestValidateFIPSInvalidLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.FIPS.Enabled = true
	cfg.TLS.FIPS.Level = "invalid"
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "tls.fips.level" && f.Severity == SeverityError {
			found = true
		}
	}
	if !found {
		t.Fatal("expected FIPS level error for invalid level")
	}
}

// TestValidateFIPSEmptyLevel covers the FIPS empty level warning.
func TestValidateFIPSEmptyLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.FIPS.Enabled = true
	cfg.TLS.FIPS.Level = ""
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "tls.fips.level" && f.Severity == SeverityWarning {
			found = true
		}
	}
	if !found {
		t.Fatal("expected FIPS level warning for empty level")
	}
}

// TestValidateMutualTLSEmptyMode covers the mTLS empty mode warning.
func TestValidateMutualTLSEmptyMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.MutualTLS.Enabled = true
	cfg.TLS.MutualTLS.Mode = ""
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "tls.mutual_tls.mode" && f.Severity == SeverityWarning {
			found = true
		}
	}
	if !found {
		t.Fatal("expected mTLS mode warning for empty mode")
	}
}

// TestValidateA2AEmptyConfigFile covers the A2A empty config_file warning.
func TestValidateA2AEmptyConfigFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.A2A.Enabled = true
	cfg.A2A.ConfigFile = ""
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "a2a.config_file" && f.Severity == SeverityWarning {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a2a.config_file empty warning")
	}
}

// TestValidateACPEmptyConfigFile covers the ACP empty config_file warning.
func TestValidateACPEmptyConfigFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ACP.Enabled = true
	cfg.ACP.ConfigFile = ""
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "acp.config_file" && f.Severity == SeverityWarning {
			found = true
		}
	}
	if !found {
		t.Fatal("expected acp.config_file empty warning")
	}
}

// TestValidateShutdownTimeoutShort covers the short shutdown timeout warning.
func TestValidateShutdownTimeoutShort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Platform.ShutdownTimeout = 2 * time.Second
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "platform.shutdown_timeout" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected shutdown_timeout warning, got: %v", r.Findings)
	}
}

// TestValidateSIEMPlatformNoEndpoint covers the SIEM platform enabled but no endpoint error.
func TestValidateSIEMPlatformNoEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SIEM.Enabled = true
	cfg.SIEM.Platforms = []SIEMPlatformConfig{
		{Platform: "splunk", Enabled: true, Endpoint: ""},
	}
	r := cfg.Validate()
	found := false
	for _, f := range r.Findings {
		if f.Field == "siem.platforms[0].endpoint" && f.Severity == SeverityError {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected siem platform endpoint error, got: %v", r.Findings)
	}
}

// TestSummaryNoErrorsOrWarnings covers the "passed" summary branch.
func TestSummaryNoErrorsOrWarnings(t *testing.T) {
	r := &ValidationResult{}
	summary := r.Summary()
	if !contains(summary, "passed") {
		t.Errorf("summary should mention passed, got: %s", summary)
	}
}

// TestSummaryOnlyErrors covers the case where there are errors but no warnings.
func TestSummaryOnlyErrors(t *testing.T) {
	r := &ValidationResult{
		Findings: []ValidationFinding{
			{Severity: SeverityError, Field: "test", Message: "err"},
		},
	}
	summary := r.Summary()
	if !contains(summary, "error") {
		t.Errorf("summary should mention error, got: %s", summary)
	}
}
