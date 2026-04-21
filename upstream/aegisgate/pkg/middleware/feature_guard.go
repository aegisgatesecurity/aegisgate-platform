// SPDX-License-Identifier: Apache-2.0
// Package middleware provides HTTP middleware for AegisGate Platform.
//
// FeatureGuard middleware enforces tier-based feature access using the
// platform's client-side license validation system. No remote API calls
// are required — all validation happens locally with ECDSA P-256 signatures.
package middleware

import (
	"net/http"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// FeatureGuard middleware checks if the current license tier allows access
// to a feature. Uses the platform's client-side license validation.
func FeatureGuard(featureKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get license manager from context (set by LicenseMiddleware)
		lm := license.ManagerFromContext(r.Context())

		if lm == nil {
			// No license manager — default to Community tier
			if !tier.IsFeatureCommunity(featureKey) {
				requiredTier := tier.RequiredTier(featureKeyForKey(featureKey))
				http.Error(w, getUpgradeMessage(requiredTier, tier.TierCommunity), http.StatusPaymentRequired)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Check if feature is licensed using context-aware method
		if !lm.IsFeatureLicensedForContext(r.Context(), featureKey) {
			// Get current tier for upgrade message
			tierStr := lm.GetTierForContext(r.Context())
			currentTier, _ := tier.ParseTier(tierStr)
			requiredTier := tier.RequiredTier(featureKeyForKey(featureKey))

			w.Header().Set("X-Required-Tier", requiredTier.DisplayName())
			w.Header().Set("X-Current-Tier", currentTier.DisplayName())

			http.Error(w, getUpgradeMessage(requiredTier, currentTier), http.StatusPaymentRequired)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// FeatureGuardFunc is a convenience wrapper for http.HandlerFunc
func FeatureGuardFunc(featureKey string, next func(http.ResponseWriter, *http.Request)) http.Handler {
	return FeatureGuard(featureKey, http.HandlerFunc(next))
}

// RequireTier ensures the request comes from an account with minimum tier.
// Uses the platform's client-side license validation.
func RequireTier(minimumTier tier.Tier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lm := license.ManagerFromContext(r.Context())

		var currentTier tier.Tier
		if lm == nil {
			currentTier = tier.TierCommunity
		} else {
			tierStr := lm.GetTierForContext(r.Context())
			currentTier, _ = tier.ParseTier(tierStr)
		}

		if currentTier < minimumTier {
			http.Error(w, getTierUpgradeMessage(minimumTier, currentTier), http.StatusPaymentRequired)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireFeature checks if a specific feature is available.
// Uses the platform's client-side license validation.
func RequireFeature(featureKeys ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lm := license.ManagerFromContext(r.Context())

			for _, feature := range featureKeys {
				hasFeature := false

				if lm == nil {
					// No license — check if feature is Community tier
					hasFeature = tier.IsFeatureCommunity(feature)
				} else {
					hasFeature = lm.IsFeatureLicensedForContext(r.Context(), feature)
				}

				if !hasFeature {
					requiredTier := tier.RequiredTier(featureKeyForKey(feature))
					w.Header().Set("X-Required-Feature", feature)
					w.Header().Set("X-Required-Tier", requiredTier.DisplayName())
					http.Error(w, "Feature not available: "+feature, http.StatusPaymentRequired)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// TierBasedResponse modifies the response based on tier using client-side validation.
func TierBasedResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lm := license.ManagerFromContext(r.Context())

		var currentTier tier.Tier
		if lm == nil {
			currentTier = tier.TierCommunity
		} else {
			tierStr := lm.GetTierForContext(r.Context())
			currentTier, _ = tier.ParseTier(tierStr)
		}

		// Add tier header to response
		w.Header().Set("X-AegisGate-Tier", currentTier.String())

		// Add available features based on tier
		features := tier.AllFeatures(currentTier)
		featureStrs := make([]string, len(features))
		for i, f := range features {
			featureStrs[i] = string(f)
		}
		w.Header().Set("X-Available-Features", strings.Join(featureStrs, ","))

		next.ServeHTTP(w, r)
	})
}

// featureKeyForKey resolves a string feature key to a tier.Feature constant.
// Returns a zero-value Feature if the key is unknown.
func featureKeyForKey(key string) tier.Feature {
	f, ok := tier.FeatureForKey(key)
	if !ok {
		// Unknown feature — return zero value (defaults to Community)
		return tier.Feature("")
	}
	return f
}

func getUpgradeMessage(required, current tier.Tier) string {
	upgradeLink := "/pricing"
	if required == tier.TierEnterprise {
		upgradeLink = "/contact-sales"
	}

	return `{"error": "upgrade_required", "message": "This feature requires ` +
		required.DisplayName() + ` tier", "current_tier": "` + current.String() +
		`", "upgrade_url": "` + upgradeLink + `"}`
}

func getTierUpgradeMessage(required, current tier.Tier) string {
	return `{"error": "tier_upgrade_required", "message": "This endpoint requires ` +
		required.DisplayName() + ` tier or higher", "current_tier": "` + current.String() + `"}`
}