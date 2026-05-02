// SPDX-License-Identifier: Apache-2.0
// Package license provides HTTP middleware for license-aware feature gating
// in the AegisGate Security Platform.
//
// The middleware suite supports three gating strategies:
//   - RequireLicense: Ensures a license is resolved (falls back to Community)
//   - RequireTier: Gates access by minimum tier level (403 on insufficient tier)
//   - RequireFeature: Gates access by specific feature (403 on unlicensed feature)
//
// Additionally, InjectLicenseContext reads the license key from the environment
// or request headers and injects the validated Manager, tier, and key into
// the request context for downstream handlers.
package license

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// licenseStatusResponse is the JSON structure returned by LicenseStatus.
type licenseStatusResponse struct {
	Valid         bool   `json:"valid"`
	Tier          string `json:"tier"`
	DisplayName   string `json:"display_name"`
	ExpiresAt     string `json:"expires_at"`
	GracePeriod   bool   `json:"grace_period"`
	Customer      string `json:"customer"`
	FeaturesCount int    `json:"features_count"`
	Message       string `json:"message"`
}

// errorResponse is the JSON structure for 403 error replies.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Tier    string `json:"tier,omitempty"`
}

// LicenseMiddleware wraps a license.Manager and provides HTTP middleware
// functions for license-aware feature gating.
type LicenseMiddleware struct {
	manager *Manager
}

// NewLicenseMiddleware creates a new LicenseMiddleware that wraps the given
// license Manager.
func NewLicenseMiddleware(manager *Manager) *LicenseMiddleware {
	return &LicenseMiddleware{
		manager: manager,
	}
}

// RequireLicense validates the license from context or the Manager's stored key
// and injects license information into the request context. If no valid license
// is found, the tier falls back to Community — this is not treated as an error.
// The resolved tier and manager are always available downstream via context.
func (lm *LicenseMiddleware) RequireLicense(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Resolve license key from context (may have been injected by InjectLicenseContext)
		var result ValidationResult
		if key, ok := ctx.Value(CtxKeyLicenseKey).(string); ok && key != "" {
			result = lm.manager.Validate(key)
		} else {
			// Use the Manager's stored key (set from env or config)
			result = lm.manager.Validate(lm.manager.GetLicenseKey())
		}

		// Determine effective tier: invalid/expired licenses fall back to Community
		effectiveTier := result.Tier
		if !result.Valid {
			effectiveTier = tier.TierCommunity
		}

		// Inject Manager, tier, and license key into context for downstream handlers
		ctx = ContextWithManager(ctx, lm.manager)
		ctx = contextWithTier(ctx, effectiveTier)
		if key, _ := ctx.Value(CtxKeyLicenseKey).(string); key == "" && result.Payload.LicenseID != "" {
			// Propagate the key if it wasn't already in context
			ctx = ContextWithLicenseKey(ctx, lm.manager.GetLicenseKey())
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// RequireTier returns middleware that enforces a minimum tier level.
// If the resolved license tier is below the minimum, a 403 JSON error is returned.
func (lm *LicenseMiddleware) RequireTier(minimumTier tier.Tier) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			currentTier := resolveTierFromContext(ctx, lm.manager)

			if !currentTier.CanAccess(minimumTier) {
				writeForbidden(w, fmt.Sprintf("requires %s tier or above", minimumTier.DisplayName()), currentTier.String())
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

// RequireFeature returns middleware that enforces access to a specific feature.
// If the resolved license tier does not include the feature, a 403 JSON error is returned.
func (lm *LicenseMiddleware) RequireFeature(feature tier.Feature) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			currentTier := resolveTierFromContext(ctx, lm.manager)

			if !tier.HasFeature(currentTier, feature) {
				requiredTier := tier.RequiredTier(feature)
				writeForbidden(w, fmt.Sprintf("feature %s requires %s tier", string(feature), requiredTier.DisplayName()), currentTier.String())
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

// LicenseStatus returns an http.HandlerFunc that reports the current license
// status as JSON. The response includes: valid, tier, display_name, expires_at,
// grace_period, customer, features_count, and message.
func (lm *LicenseMiddleware) LicenseStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Resolve the license key from context or manager
		var result ValidationResult
		if key, ok := ctx.Value(CtxKeyLicenseKey).(string); ok && key != "" {
			result = lm.manager.Validate(key)
		} else {
			result = lm.manager.Validate(lm.manager.GetLicenseKey())
		}

		effectiveTier := result.Tier
		if !result.Valid {
			effectiveTier = tier.TierCommunity
		}

		expiresAt := ""
		if !result.Payload.ExpiresAt.IsZero() {
			expiresAt = result.Payload.ExpiresAt.Format(time.RFC3339)
		}

		resp := licenseStatusResponse{
			Valid:         result.Valid,
			Tier:          effectiveTier.String(),
			DisplayName:   effectiveTier.DisplayName(),
			ExpiresAt:     expiresAt,
			GracePeriod:   result.GracePeriod,
			Customer:      result.Payload.Customer,
			FeaturesCount: len(tier.AllFeatures(effectiveTier)),
			Message:       result.Message,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			// Log error but don't fail
			return
		}
	}
}

// InjectLicenseContext reads the license key from the AEGISGATE_LICENSE_KEY
// environment variable or the X-License-Key request header, validates it,
// and injects the Manager, resolved tier, and license key into the request
// context for downstream handlers.
//
// The header takes precedence over the environment variable, allowing
// per-request key overrides.
func (lm *LicenseMiddleware) InjectLicenseContext(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Determine license key: header overrides env
		licenseKey := r.Header.Get("X-License-Key")
		if licenseKey == "" {
			licenseKey = os.Getenv("AEGISGATE_LICENSE_KEY")
		}

		// Validate the key
		result := lm.manager.Validate(licenseKey)

		// Determine effective tier
		effectiveTier := result.Tier
		if !result.Valid {
			effectiveTier = tier.TierCommunity
		}

		// Set the key on the manager for context-aware methods
		if licenseKey != "" {
			lm.manager.SetLicenseKey(licenseKey)
		}

		// Inject all context values for downstream handlers
		ctx = ContextWithManager(ctx, lm.manager)
		ctx = ContextWithLicenseKey(ctx, licenseKey)
		ctx = contextWithTier(ctx, effectiveTier)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// contextWithTier injects the resolved tier into the context using the
// license package's CtxKeyTier key. This enables downstream handlers
// to retrieve the tier without re-validating the license.
func contextWithTier(ctx context.Context, t tier.Tier) context.Context {
	return context.WithValue(ctx, CtxKeyTier, t.String())
}

// resolveTierFromContext attempts to determine the effective tier from the
// request context. It checks:
//  1. The license package's CtxKeyTier (set by InjectLicenseContext / RequireLicense)
//  2. The auth middleware's "auth_tier" context key (for interop)
//  3. Falls back to validating via the Manager
func resolveTierFromContext(ctx context.Context, mgr *Manager) tier.Tier {
	// Check license middleware's tier key first
	if tierStr, ok := ctx.Value(CtxKeyTier).(string); ok && tierStr != "" {
		if t, err := tier.ParseTier(tierStr); err == nil {
			return t
		}
	}

	// Check auth middleware's tier key for interoperability
	if tierStr, ok := ctx.Value(authTierKey).(string); ok && tierStr != "" {
		if t, err := tier.ParseTier(tierStr); err == nil {
			return t
		}
	}

	// Fall back to Manager-based resolution
	result := mgr.Validate(mgr.GetLicenseKey())
	if result.Valid {
		return result.Tier
	}

	return tier.TierCommunity
}

// writeForbidden writes a 403 Forbidden JSON response.
func writeForbidden(w http.ResponseWriter, message, currentTier string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(errorResponse{
		Error:   "forbidden",
		Message: message,
		Tier:    currentTier,
	}); err != nil {
		// Log error but don't fail
	}
}

// authTierKey mirrors the context key used by the auth middleware for tier
// lookups ("auth_tier"), enabling interoperability between auth and license
// middleware without a direct package import cycle.
var authTierKey = contextKey("auth_tier")
