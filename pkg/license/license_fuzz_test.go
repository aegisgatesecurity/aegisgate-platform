package license

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// FuzzParseLicense tests the license validation with arbitrary input
//
//go:generate go test -fuzz=FuzzParseLicense -fuzztime=60s
func FuzzParseLicense(f *testing.F) {
	// Seed corpus with valid and invalid license formats
	validKeys := []string{
		"AGE-XXXX-XXXX-XXXX-XXXX-XXXX",
		"AGT-AAAA-BBBB-CCCC-DDDD-EEEE",
	}

	for _, seed := range validKeys {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, licenseKey string) {
		// Skip empty keys
		if licenseKey == "" {
			return
		}

		// Create a manager for testing
		mgr, err := NewManager()
		if err != nil {
			// Manager creation failed - skip this iteration
			t.Skip("Manager creation failed")
		}

		// Validate the key - should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("License validation panicked on key: %s", licenseKey)
			}
		}()

		result := mgr.Validate(licenseKey)

		// Validate the result fields are consistent
		// Valid license must have a recognized tier
		if result.Valid && result.Tier < tier.TierCommunity {
			t.Error("Valid license has invalid tier")
		}
	})
}

// FuzzValidateFeatures tests feature access with arbitrary license keys
//
//go:generate go test -fuzz=FuzzValidateFeatures -fuzztime=60s
func FuzzValidateFeatures(f *testing.F) {
	f.Fuzz(func(t *testing.T, licenseKey string) {
		if licenseKey == "" {
			return
		}

		mgr, err := NewManager()
		if err != nil {
			t.Skip("Manager creation failed")
		}

		result := mgr.Validate(licenseKey)

		// Should not panic when checking features
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Feature check panicked on key: %s", licenseKey)
			}
		}()

		// Test feature licensing with the MCP feature
		// This ensures the feature lookup doesn't panic
		_ = mgr.IsFeatureLicensed(&result, tier.Feature("mcp"))
	})
}
