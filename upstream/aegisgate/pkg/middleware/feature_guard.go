package middleware

import (
	"net/http"
	"strings"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
	"github.com/aegisgatesecurity/aegisgate/pkg/core/license"
)

// FeatureGuard middleware checks if the current license tier allows access to a feature
func FeatureGuard(featureKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get license manager from context (set by LicenseMiddleware)
		lm := getLicenseManager(r.Context())

		if lm == nil {
			// No license - default to community
			requiredTier := core.GetRequiredTier(featureKey)
			if requiredTier > core.TierCommunity {
				http.Error(w, "Professional tier required for this feature", http.StatusPaymentRequired)
				return
			}
		} else {
			// Check if feature is licensed
			if !lm.IsFeatureLicensed(r.Context(), featureKey) {
				// Get current tier info
				tierStr := lm.GetTier(r.Context())
				currentTier := core.GetTierByName(tierStr)
				requiredTier := core.GetRequiredTier(featureKey)

				w.Header().Set("X-Required-Tier", requiredTier.String())
				w.Header().Set("X-Current-Tier", currentTier.String())

				http.Error(w, getUpgradeMessage(requiredTier, currentTier), http.StatusPaymentRequired)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// FeatureGuardFunc is a convenience wrapper for http.HandlerFunc
func FeatureGuardFunc(featureKey string, next func(http.ResponseWriter, *http.Request)) http.Handler {
	return FeatureGuard(featureKey, http.HandlerFunc(next))
}

// RequireTier ensures the request comes from an account with minimum tier
func RequireTier(minimumTier core.Tier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lm := getLicenseManager(r.Context())

		var currentTier core.Tier
		if lm == nil {
			currentTier = core.TierCommunity
		} else {
			currentTier = core.GetTierByName(lm.GetTier(r.Context()))
		}

		if currentTier < minimumTier {
			http.Error(w, getTierUpgradeMessage(minimumTier, currentTier), http.StatusPaymentRequired)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireFeature checks if a specific feature is available
func RequireFeature(featureKeys ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lm := getLicenseManager(r.Context())

			for _, feature := range featureKeys {
				hasFeature := false

				if lm == nil {
					// No license - check if feature is community
					hasFeature = core.GetRequiredTier(feature) == core.TierCommunity
				} else {
					hasFeature = lm.IsFeatureLicensed(r.Context(), feature)
				}

				if !hasFeature {
					requiredTier := core.GetRequiredTier(feature)
					w.Header().Set("X-Required-Feature", feature)
					w.Header().Set("X-Required-Tier", requiredTier.String())
					http.Error(w, "Feature not available: "+feature, http.StatusPaymentRequired)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getLicenseManager retrieves the license manager from context
func getLicenseManager(ctx interface{ Value(interface{}) interface{} }) *license.LicenseManager {
	// This would be set by the LicenseMiddleware
	// Implementation depends on your context setup
	return nil // Placeholder
}

func getUpgradeMessage(required, current core.Tier) string {
	upgradeLink := "/pricing"
	if strings.Contains(required.String(), "Enterprise") {
		upgradeLink = "/contact-sales"
	}

	return `{"error": "upgrade_required", "message": "This feature requires ` +
		required.String() + ` tier", "current_tier": "` + current.String() +
		`", "upgrade_url": "` + upgradeLink + `"}`
}

func getTierUpgradeMessage(required, current core.Tier) string {
	return `{"error": "tier_upgrade_required", "message": "This endpoint requires ` +
		required.String() + ` tier or higher", "current_tier": "` + current.String() + `"}`
}

// TierBasedResponse modifies the response based on tier
func TierBasedResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lm := getLicenseManager(r.Context())

		var tier core.Tier
		if lm == nil {
			tier = core.TierCommunity
		} else {
			tier = core.GetTierByName(lm.GetTier(r.Context()))
		}

		// Add tier header to response
		w.Header().Set("X-AegisGate-Tier", tier.String())

		// Add available features based on tier
		features := core.GetFeaturesByTier(tier)
		w.Header().Set("X-Available-Features", strings.Join(features, ","))

		next.ServeHTTP(w, r)
	})
}
