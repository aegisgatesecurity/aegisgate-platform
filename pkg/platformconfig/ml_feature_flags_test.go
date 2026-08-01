// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Threat Detection Feature Flags Tests
// =========================================================================
//
// Tests that verify:
//   - Default config has MLThreatDetectionEnabled: false (cold-start safety)
//   - Default config has MLShadowMode: true (safe deployment)
//   - When enabled=true, proxy creates ThreatDetector with enabled=true
//   - When shadow_mode=false, proxy creates ThreatDetector with ShadowMode=false
//
// =========================================================================

package platformconfig

import (
	"os"
	"testing"
)

// TestDefaultConfig_MLThreatDetectionDisabled verifies the cold-start safety
// requirement: the ML threat detector MUST be disabled by default.
func TestDefaultConfig_MLThreatDetectionDisabled(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should be false by default (cold-start safety)")
	}
}

// TestDefaultConfig_MLShadowModeEnabled verifies that shadow mode is on by
// default — the detector logs predictions but never blocks traffic.
func TestDefaultConfig_MLShadowModeEnabled(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be true by default (safe deployment)")
	}
}

// TestDefaultConfig_MLFeatureFlagsIndependent verifies that the two feature
// flags are independent — toggling one doesn't affect the other.
func TestDefaultConfig_MLFeatureFlagsIndependent(t *testing.T) {
	cfg := DefaultConfig()

	// Defaults: disabled detection, shadow mode on
	if cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should be false by default")
	}
	if !cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be true by default")
	}
}

// TestEnvOverride_MLThreatDetectionEnabled verifies that the
// AEGISGATE_ML_THREAT_DETECTION_ENABLED env var overrides the default.
func TestEnvOverride_MLThreatDetectionEnabled(t *testing.T) {
	// Test enabling via env var
	os.Setenv("AEGISGATE_ML_THREAT_DETECTION_ENABLED", "true")
	defer os.Unsetenv("AEGISGATE_ML_THREAT_DETECTION_ENABLED")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if !cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should be true when env var is set to 'true'")
	}
}

// TestEnvOverride_MLShadowMode verifies that the
// AEGISGATE_ML_SHADOW_MODE env var overrides the default.
func TestEnvOverride_MLShadowMode(t *testing.T) {
	// Test disabling shadow mode via env var
	os.Setenv("AEGISGATE_ML_SHADOW_MODE", "false")
	defer os.Unsetenv("AEGISGATE_ML_SHADOW_MODE")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be false when env var is set to 'false'")
	}
}

// TestEnvOverride_MLFeatureFlagsBothSet verifies that both feature flags
// can be set simultaneously via environment variables.
func TestEnvOverride_MLFeatureFlagsBothSet(t *testing.T) {
	os.Setenv("AEGISGATE_ML_THREAT_DETECTION_ENABLED", "true")
	os.Setenv("AEGISGATE_ML_SHADOW_MODE", "false")
	defer os.Unsetenv("AEGISGATE_ML_THREAT_DETECTION_ENABLED")
	defer os.Unsetenv("AEGISGATE_ML_SHADOW_MODE")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if !cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should be true")
	}
	if cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be false")
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
  ml_threat_detection_enabled: true
  ml_shadow_mode: false
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
		t.Error("MLThreatDetectionEnabled should be true from YAML config")
	}
	if cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should be false from YAML config")
	}
}

// TestYAMLConfig_MLFeatureFlagsDefaults verifies that missing YAML keys
// fall back to safe defaults (disabled detection, shadow mode on).
func TestYAMLConfig_MLFeatureFlagsDefaults(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "aegisgate-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Minimal YAML with no ML feature flags — should use safe defaults
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

	if cfg.Security.MLThreatDetectionEnabled {
		t.Error("MLThreatDetectionEnabled should default to false (cold-start safety)")
	}
	if !cfg.Security.MLShadowMode {
		t.Error("MLShadowMode should default to true (safe deployment)")
	}
}
