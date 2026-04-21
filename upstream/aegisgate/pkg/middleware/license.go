// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// License Validation Middleware — Client-Side Validation
// =========================================================================
//
// This middleware performs all license validation locally using ECDSA P-256
// cryptographic signatures. No remote API calls are required for license
// validation. License activation-only endpoints may contact
// license.aegisgatesecurity.io for initial registration.
//
// The license key is sourced from:
//   1. The LICENSE_KEY environment variable
//   2. The X-License-Key HTTP header (for API usage)
//   3. A configured license key file
//
// Once validated, the license Manager is injected into the request context
// for downstream FeatureGuard and RequireTier middleware to use.

package middleware

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// globalManager is the singleton license Manager, initialized once.
var globalManager *license.Manager
var managerOnce sync.Once

// getGlobalManager returns the singleton license Manager, creating it if needed.
func getGlobalManager() *license.Manager {
	managerOnce.Do(func() {
		var err error
		globalManager, err = license.NewManager()
		if err != nil {
			log.Printf("[LICENSE] Failed to create license manager: %v", err)
			return
		}

		// Set the license key from environment
		key := getLicenseKey()
		if key != "" {
			globalManager.SetLicenseKey(key)
			result := globalManager.Validate(key)
			if result.Valid {
				log.Printf("[LICENSE] Valid license: %s tier (customer: %s)", result.Tier.DisplayName(), result.Payload.Customer)
			} else if result.GracePeriod {
				log.Printf("[LICENSE] License in grace period: %s (expires: %s)", result.Message, result.Payload.ExpiresAt.Format(time.RFC3339))
			} else {
				log.Printf("[LICENSE] License validation failed: %s", result.Message)
			}
		} else {
			log.Printf("[LICENSE] No license key configured — using Community tier")
		}
	})
	return globalManager
}

// getLicenseKey returns the license key from environment or file.
func getLicenseKey() string {
	// Check environment variable first
	if key := os.Getenv("LICENSE_KEY"); key != "" {
		return strings.TrimSpace(key)
	}

	// Check for license key file
	keyFile := os.Getenv("LICENSE_KEY_FILE")
	if keyFile == "" {
		keyFile = "/etc/aegisgate/license.key"
	}
	if data, err := os.ReadFile(keyFile); err == nil {
		return strings.TrimSpace(string(data))
	}

	return ""
}

// LicenseMiddleware injects the license Manager into the request context
// and validates the license key. Uses client-side ECDSA P-256 validation.
//
// The license key is sourced from (in order of priority):
//  1. X-License-Key HTTP header (for API usage)
//  2. Global LICENSE_KEY environment variable (default)
func LicenseMiddleware() func(http.Handler) http.Handler {
	mgr := getGlobalManager()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip license check for health/version/stats endpoints
			if strings.HasPrefix(r.URL.Path, "/health") ||
				strings.HasPrefix(r.URL.Path, "/version") ||
				strings.HasPrefix(r.URL.Path, "/stats") {
				next.ServeHTTP(w, r)
				return
			}

			if mgr == nil {
				// No license manager available — inject Community tier context
				ctx := context.WithValue(r.Context(), license.CtxKeyTier, tier.TierCommunity)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Determine the license key for this request
			// Priority: header override > global config
			key := mgr.GetLicenseKey()
			if headerKey := r.Header.Get("X-License-Key"); headerKey != "" {
				key = strings.TrimSpace(headerKey)
			}

			// Validate the license
			result := mgr.Validate(key)

			// Build context with license information
			ctx := r.Context()
			ctx = license.ContextWithManager(ctx, mgr)
			ctx = license.ContextWithLicenseKey(ctx, key)

			if result.Valid {
				ctx = context.WithValue(ctx, license.CtxKeyTier, result.Tier)
			} else {
				ctx = context.WithValue(ctx, license.CtxKeyTier, tier.TierCommunity)
			}

			// If license is completely invalid (not even grace period), return 402
			if !result.Valid && !result.GracePeriod && key != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired)
				w.Write([]byte(`{"error":"license_invalid","message":"` + result.Message + `"}`))
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetLicenseTierFromContext returns the current license tier from context
func GetLicenseTierFromContext(ctx context.Context) tier.Tier {
	if t, ok := ctx.Value(license.CtxKeyTier).(tier.Tier); ok {
		return t
	}
	return tier.TierCommunity
}

// HealthCheck returns license health information
func HealthCheck() map[string]any {
	mgr := getGlobalManager()
	if mgr == nil {
		return map[string]any{
			"status":  "no_license_manager",
			"tier":    "community",
			"message": "License manager not initialized",
		}
	}

	key := mgr.GetLicenseKey()
	if key == "" {
		return map[string]any{
			"status":  "community",
			"tier":    "community",
			"message": "No license key — Community tier",
		}
	}

	result := mgr.Validate(key)
	return map[string]any{
		"status":       result.Message,
		"tier":         result.Tier.String(),
		"valid":        result.Valid,
		"expired":      result.Expired,
		"grace_period": result.GracePeriod,
	}
}