// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// billing coverage tests — round 2
// Targets: getDefaultConfigPath 71.4%→100%, LoadBillingConfig 61.1%→95%+
// =========================================================================

//go:build !race

package billing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// saveBillingState saves the current global billing state and returns a restore function
func saveBillingState() func() {
	origConfigPath := configPath
	origPrices := make(map[string]int64)
	origProducts := make(map[string]string)
	for k, v := range TierPrices {
		origPrices[k] = v
	}
	for k, v := range TierProducts {
		origProducts[k] = v
	}
	return func() {
		configPath = origConfigPath
		TierPrices = origPrices
		TierProducts = origProducts
	}
}

// =========================================================================
// getDefaultConfigPath — AEGISGATE_BILLING_CONFIG env var path (line 48-50)
// =========================================================================

func TestGetDefaultConfigPath_EnvVar(t *testing.T) {
	restore := saveBillingState()
	defer restore()

	testPath := "/tmp/test-billing-config.json"
	os.Setenv("AEGISGATE_BILLING_CONFIG", testPath)
	defer os.Unsetenv("AEGISGATE_BILLING_CONFIG")

	result := getDefaultConfigPath()
	if result != testPath {
		t.Errorf("getDefaultConfigPath() with env var = %q, want %q", result, testPath)
	}
}

// =========================================================================
// LoadBillingConfig — config file not found (lines 70-81)
// =========================================================================

func TestLoadBillingConfig_ConfigNotFound(t *testing.T) {
	restore := saveBillingState()
	defer restore()

	configPath = "/nonexistent/path/billing-config.json"

	err := LoadBillingConfig()
	if err == nil {
		t.Error("LoadBillingConfig() with non-existent config should return error")
	}
	t.Logf("LoadBillingConfig() error (expected): %v", err)

	if len(TierPrices) != 0 {
		t.Error("TierPrices should be empty when config not found")
	}
	if TierProducts["starter"] != "" || TierProducts["developer"] != "" {
		t.Error("TierProducts should have empty string defaults when config not found")
	}
}

// =========================================================================
// LoadBillingConfig — invalid JSON (lines 84-86)
// =========================================================================

func TestLoadBillingConfig_InvalidJSON(t *testing.T) {
	restore := saveBillingState()
	defer restore()

	dir := t.TempDir()
	badConfig := filepath.Join(dir, "billing-config.json")
	if err := os.WriteFile(badConfig, []byte("{invalid json!!!"), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	configPath = badConfig

	err := LoadBillingConfig()
	if err == nil {
		t.Error("LoadBillingConfig() with invalid JSON should return error")
	}
	t.Logf("LoadBillingConfig() error (expected): %v", err)
}

// =========================================================================
// LoadBillingConfig — valid JSON with tier prices (lines 88-93)
// =========================================================================

func TestLoadBillingConfig_ValidJSON(t *testing.T) {
	restore := saveBillingState()
	defer restore()

	dir := t.TempDir()
	configFile := filepath.Join(dir, "billing-config.json")

	config := billingConfig{
		TierPrices: map[string]int64{
			"starter":      2900,
			"developer":    7900,
			"professional": 24900,
		},
		TierProducts: map[string]string{
			"starter":      "price_starter",
			"developer":    "price_developer",
			"professional": "price_professional",
			"enterprise":   "price_enterprise",
		},
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	if err := os.WriteFile(configFile, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	configPath = configFile

	err = LoadBillingConfig()
	if err != nil {
		t.Fatalf("LoadBillingConfig() with valid JSON error: %v", err)
	}

	if TierPrices["starter"] != 2900 {
		t.Errorf("TierPrices[starter] = %d, want 2900", TierPrices["starter"])
	}
	if TierProducts["starter"] != "price_starter" {
		t.Errorf("TierProducts[starter] = %q, want price_starter", TierProducts["starter"])
	}
}

// =========================================================================
// LoadBillingConfig — AEGISGATE_PRICE_* env var override (lines 97-101)
// =========================================================================

func TestLoadBillingConfig_EnvVarOverride(t *testing.T) {
	restore := saveBillingState()
	defer restore()

	dir := t.TempDir()
	configFile := filepath.Join(dir, "billing-config.json")

	config := billingConfig{
		TierPrices: map[string]int64{
			"starter":      2900,
			"developer":    7900,
			"professional": 24900,
		},
		TierProducts: map[string]string{
			"starter":    "price_1",
			"developer":  "price_2",
			"enterprise": "price_4",
		},
	}

	data, _ := json.Marshal(config)
	if err := os.WriteFile(configFile, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	configPath = configFile

	os.Setenv("AEGISGATE_PRICE_STARTER", "3900")
	os.Setenv("AEGISGATE_PRICE_DEVELOPER", "8900")
	os.Setenv("AEGISGATE_PRICE_PROFESSIONAL", "29900")
	defer func() {
		os.Unsetenv("AEGISGATE_PRICE_STARTER")
		os.Unsetenv("AEGISGATE_PRICE_DEVELOPER")
		os.Unsetenv("AEGISGATE_PRICE_PROFESSIONAL")
	}()

	err := LoadBillingConfig()
	if err != nil {
		t.Fatalf("LoadBillingConfig() error: %v", err)
	}

	if TierPrices["starter"] != 3900 {
		t.Errorf("TierPrices[starter] = %d, want 3900 (env override)", TierPrices["starter"])
	}
	if TierPrices["developer"] != 8900 {
		t.Errorf("TierPrices[developer] = %d, want 8900 (env override)", TierPrices["developer"])
	}
	if TierPrices["professional"] != 29900 {
		t.Errorf("TierPrices[professional] = %d, want 29900 (env override)", TierPrices["professional"])
	}
}

// =========================================================================
// LoadBillingConfig — AEGISGATE_PRICE_* with invalid value (line 99-100)
// =========================================================================

func TestLoadBillingConfig_EnvVarOverride_InvalidValue(t *testing.T) {
	restore := saveBillingState()
	defer restore()

	dir := t.TempDir()
	configFile := filepath.Join(dir, "billing-config.json")

	config := billingConfig{
		TierPrices: map[string]int64{
			"starter": 2900,
		},
		TierProducts: map[string]string{
			"starter": "",
		},
	}

	data, _ := json.Marshal(config)
	os.WriteFile(configFile, data, 0o644)
	configPath = configFile

	os.Setenv("AEGISGATE_PRICE_STARTER", "not-a-number")
	defer os.Unsetenv("AEGISGATE_PRICE_STARTER")

	err := LoadBillingConfig()
	if err != nil {
		t.Fatalf("LoadBillingConfig() error: %v", err)
	}

	// Sscanf fails → price stays from config file, not overridden
	if TierPrices["starter"] != 2900 {
		t.Errorf("TierPrices[starter] = %d, want 2900 (no override for invalid env)", TierPrices["starter"])
	}
}

// =========================================================================
// LoadBillingConfig — AEGISGATE_PRICE_* with zero value (line 99-100)
// =========================================================================

func TestLoadBillingConfig_EnvVarOverride_ZeroValue(t *testing.T) {
	restore := saveBillingState()
	defer restore()

	dir := t.TempDir()
	configFile := filepath.Join(dir, "billing-config.json")

	config := billingConfig{
		TierPrices: map[string]int64{
			"starter": 2900,
		},
		TierProducts: map[string]string{
			"starter": "",
		},
	}

	data, _ := json.Marshal(config)
	os.WriteFile(configFile, data, 0o644)
	configPath = configFile

	os.Setenv("AEGISGATE_PRICE_STARTER", "0")
	defer os.Unsetenv("AEGISGATE_PRICE_STARTER")

	err := LoadBillingConfig()
	if err != nil {
		t.Fatalf("LoadBillingConfig() error: %v", err)
	}

	// price > 0 check fails for zero → stays from config file
	if TierPrices["starter"] != 2900 {
		t.Errorf("TierPrices[starter] = %d, want 2900 (zero not > 0)", TierPrices["starter"])
	}
}

// =========================================================================
// tierToUpper — default case
// =========================================================================

func TestTierToUpper_DefaultCase(t *testing.T) {
	result := tierToUpper("enterprise")
	if result != "" {
		t.Errorf("tierToUpper(enterprise) = %q, want empty (default case)", result)
	}
}
