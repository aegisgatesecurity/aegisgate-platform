// Package license provides license management functionality
package license

import (
	"context"
)

// LicenseManager handles license validation and feature access
type LicenseManager struct {
	tier     string
	features []string
}

// NewLicenseManager creates a new license manager
func NewLicenseManager(tier string, features []string) *LicenseManager {
	return &LicenseManager{
		tier:     tier,
		features: features,
	}
}

// GetTier returns the current license tier
func (lm *LicenseManager) GetTier(ctx context.Context) string {
	return lm.tier
}

// IsFeatureLicensed checks if a feature is available under the current license
func (lm *LicenseManager) IsFeatureLicensed(ctx context.Context, feature string) bool {
	for _, f := range lm.features {
		if f == feature {
			return true
		}
	}
	return false
}

// Validate validates the current license
func (lm *LicenseManager) Validate(ctx context.Context) error {
	return nil
}

// GetFeatures returns all licensed features
func (lm *LicenseManager) GetFeatures(ctx context.Context) []string {
	return lm.features
}
