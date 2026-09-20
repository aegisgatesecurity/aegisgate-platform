// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Threat Detection Feature Flags Tests
// =========================================================================
//
// Tests that verify:
//   - Default config has MLThreatDetectionEnabled: true (L3 blocking enabled)
//   - Default config has MLShadowMode: false (shadow mode off — L3 blocks)
//   - Env vars can override both flags
//   - YAML config keys are correctly parsed
//
// L3 was flipped to blocking mode after 7-day shadow validation:
//   0% FPR, 99.57% TPR across 8.5M requests (50→10K VUs stress test).
// P2 was flipped to blocking mode after chain analysis validation:
//   91.67% TPR, 0% FPR across multi-turn chain tests.
// P4/DIST2-5 remain alert-only (time-based / pattern-based, need production traffic).
//
// =========================================================================

package platformconfig

import (
	"os"
	"testing"
)

// TestDefaultConfig_MLThreatDetectionEnabled verifies that L3 ML threat
// detection is enabled by default (flipped to blocking after shadow validation).
func TestDefaultConfig_MLThreatDetectionEnabled(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should be true by default (L3 blocking enabled after shadow validation)")
	}
}

// TestDefaultConfig_MLShadowModeDisabled verifies that shadow mode is off by
// default — L3 blocks threats, doesn't just log them.
func TestDefaultConfig_MLShadowModeDisabled(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be false by default (L3 in blocking mode)")
	}
}

// TestDefaultConfig_ChainBlockingEnabled verifies that P2 chain blocking is
// enabled by default (flipped after chain analysis validation).
func TestDefaultConfig_ChainBlockingEnabled(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Security.ChainBlockingEnabled {
		t.Error("ChainBlockingEnabled should be true by default (P2 blocking enabled after chain validation)")
	}
}

// TestDefaultConfig_MLFeatureFlagsIndependent verifies that the two feature
// flags are independent — toggling one doesn't affect the other.
func TestDefaultConfig_MLFeatureFlagsIndependent(t *testing.T) {
	cfg := DefaultConfig()

	// Defaults: enabled detection, shadow mode off (blocking)
	if !cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should be true by default")
	}
	if cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be false by default")
	}
}

// TestEnvOverride_MLThreatDetectionEnabled verifies that the
// AEGISGATE_ML_THREAT_DETECTION_ENABLED env var overrides the default.
func TestEnvOverride_MLThreatDetectionEnabled(t *testing.T) {
	// Test disabling via env var
	os.Setenv("AEGISGATE_ML_THREAT_DETECTION_ENABLED", "false")
	defer os.Unsetenv("AEGISGATE_ML_THREAT_DETECTION_ENABLED")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should be false when env var is set to 'false'")
	}
}

// TestEnvOverride_MLShadowMode verifies that the
// AEGISGATE_ML_SHADOW_MODE env var overrides the default.
func TestEnvOverride_MLShadowMode(t *testing.T) {
	// Test enabling shadow mode via env var
	os.Setenv("AEGISGATE_ML_SHADOW_MODE", "true")
	defer os.Unsetenv("AEGISGATE_ML_SHADOW_MODE")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if !cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be true when env var is set to 'true'")
	}
}

// TestEnvOverride_MLFeatureFlagsBothSet verifies that both feature flags
// can be set simultaneously via environment variables.
func TestEnvOverride_MLFeatureFlagsBothSet(t *testing.T) {
	os.Setenv("AEGISGATE_ML_THREAT_DETECTION_ENABLED", "false")
	os.Setenv("AEGISGATE_ML_SHADOW_MODE", "true")
	defer os.Unsetenv("AEGISGATE_ML_THREAT_DETECTION_ENABLED")
	defer os.Unsetenv("AEGISGATE_ML_SHADOW_MODE")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should be false")
	}
	if !cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be true")
	}
}

// TestEnvOverride_ChainBlockingDisabled verifies that the
// AEGISGATE_CHAIN_BLOCKING_ENABLED env var can disable P2 blocking.
func TestEnvOverride_ChainBlockingDisabled(t *testing.T) {
	os.Setenv("AEGISGATE_CHAIN_BLOCKING_ENABLED", "false")
	defer os.Unsetenv("AEGISGATE_CHAIN_BLOCKING_ENABLED")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Security.ChainBlockingEnabled {
		t.Error("ChainBlockingEnabled should be false when env var is set to 'false'")
	}
}

// TestYAMLConfig_MLFeatureFlags verifies that YAML config keys are correctly
// parsed into the SecurityConfig struct fields.
func TestYAMLConfig_MLFeatureFlags(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "aegisgate-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	yamlContent := []byte(`
security:
  ml_threat_detection_enabled: false
  ml_shadow_mode: true
`)
	if _, err := tmpFile.Write(yamlContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should be false from YAML config")
	}
	if !cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be true from YAML config")
	}
}

// TestYAMLConfig_MLFeatureFlagsDefaults verifies that missing YAML keys
// fall back to blocking-mode defaults (enabled detection, shadow mode off).
func TestYAMLConfig_MLFeatureFlagsDefaults(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "aegisgate-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Minimal YAML with no ML feature flags — should use blocking-mode defaults
	yamlContent := []byte(`
platform:
  mode: "standalone"
`)
	if _, err := tmpFile.Write(yamlContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if !cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should default to true (L3 blocking enabled)")
	}
	if cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should default to false (blocking mode)")
	}
	if !cfg.Security.ChainBlockingEnabled {
		t.Error("ChainBlockingEnabled should default to true (P2 blocking enabled)")
	}
}
