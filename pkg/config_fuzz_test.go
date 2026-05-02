package config

import (
	"testing"
)

// FuzzParseConfig tests configuration parsing with arbitrary input
//
//go:generate go test -fuzz=FuzzParseConfig -fuzztime=60s
func FuzzParseConfig(f *testing.F) {
	// Seed with valid configuration formats
	validConfigs := []string{
		// YAML
		`tier: community
log_level: info
data_dir: /data`,
		// JSON
		`{"tier":"community","log_level":"info"}`,
		// ENV-style
		`tier=community
log_level=info
data_dir=/data`,
	}

	for _, seed := range validConfigs {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, configData string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Config parsing panicked on: %s", configData[:min(50, len(configData))])
			}
		}()

		// Test YAML parsing - should not panic
		_ = parseYAML(configData)

		// Test JSON parsing - should not panic
		_ = parseJSON(configData)
	})
}

// FuzzValidateConfig tests config validation with arbitrary values
//
//go:generate go test -fuzz=FuzzValidateConfig -fuzztime=60s
func FuzzValidateConfig(f *testing.F) {
	f.Fuzz(func(t *testing.T, tier string, logLevel string, dataDir string) {
		// Skip empty inputs
		if tier == "" && logLevel == "" && dataDir == "" {
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Config validation panicked")
			}
		}()

		// Validate tier
		_ = validateTier(tier)

		// Validate log level
		_ = validateLogLevel(logLevel)

		// Validate data dir
		_ = validateDataDir(dataDir)
	})
}

// Helper functions (implement based on actual config validation)
func parseYAML(data string) error { return nil }
func parseJSON(data string) error { return nil }
func validateTier(tier string) bool {
	return tier == "community" || tier == "developer" ||
		tier == "professional" || tier == "enterprise"
}
func validateLogLevel(level string) bool {
	return level == "debug" || level == "info" || level == "warn" || level == "error"
}
func validateDataDir(dir string) bool {
	return len(dir) > 0 && len(dir) < 4096
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
