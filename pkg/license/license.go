// SPDX-License-Identifier: Apache-2.0
// Package license provides client-side license validation for the AegisGate Security Platform.
//
// Design Principles:
//   - Client-side validation: No remote API calls for license checks
//   - Cryptographic integrity: ECDSA P-256 signatures with SHA-256
//   - Graceful degradation: Expired licenses get 7-day grace period
//   - Fallback to Community tier on validation failure
//
// License Key Format:
//
//	Base64 encoded JSON containing:
//	- license_id: Unique license identifier (UUID)
//	- tier: License tier (community, developer, professional, enterprise)
//	- customer: Customer identifier
//	- issued_at: RFC3339 timestamp
//	- expires_at: RFC3339 timestamp (or "never" for perpetual)
//	- features: Optional feature flags array
//	- signature: ECDSA signature (base64) covering all other fields
//
// Usage:
//
//	lm := license.NewManager()
//	result := lm.Validate("base64-encoded-license-key")
//	if result.Valid {
//	    tier := result.Tier
//	    // proceed with feature access
//	}
package license

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// contextKey is the type for license context keys
type contextKey string

const (
	// CtxKeyManager is the context key for the license Manager
	CtxKeyManager contextKey = "aegisgate_license_manager"
	// CtxKeyLicenseKey is the context key for the active license key string
	CtxKeyLicenseKey contextKey = "aegisgate_license_key"
	// CtxKeyTier is the context key for the resolved tier
	CtxKeyTier contextKey = "aegisgate_license_tier"
)

const (
	// GracePeriodDays is the number of days after expiration where the
	// license still functions (allows for renewal processing)
	GracePeriodDays = 7

	// CacheDuration is how long validation results are cached
	CacheDuration = 5 * time.Minute
)

// LicensePayload represents the decoded license data
// Note: This struct is serialized to JSON and signed
type LicensePayload struct {
	LicenseID  string    `json:"license_id"`  // UUID
	Tier       string    `json:"tier"`        // Tier name
	Customer   string    `json:"customer"`    // Customer identifier
	IssuedAt   time.Time `json:"issued_at"`   // When license was issued
	ExpiresAt  time.Time `json:"expires_at"`  // When license expires
	Features   []string  `json:"features"`    // Optional specific features
	MaxServers int       `json:"max_servers"` // Max servers allowed
	MaxUsers   int       `json:"max_users"`   // Max users allowed
}

// ValidationResult contains the outcome of license validation
type ValidationResult struct {
	Valid       bool           // Is the license currently valid
	Expired     bool           // Has the license expired (but in grace period)
	GracePeriod bool           // Currently in grace period
	Tier        tier.Tier      // Resolved tier level
	Payload     LicensePayload // Decoded license data
	Message     string         // Human-readable status message
	Error       error          // Validation error (if any)
	ValidatedAt time.Time      // When validation occurred
}

// LicenseKeyFormat represents the complete license key structure
type LicenseKeyFormat struct {
	Payload   LicensePayload `json:"payload"`              // License data
	Signature string         `json:"signature"`            // Base64-encoded ECDSA signature
	PublicKey string         `json:"public_key,omitempty"` // Optional: override embedded key
}

// Manager handles license validation and caching.
// It supports two usage patterns:
//  1. Explicit: lm.Validate(key) → inspect ValidationResult
//  2. Context-aware: lm.SetLicenseKey(key) → lm.GetTierForContext(ctx) / lm.IsFeatureLicensedForContext(ctx, feature)
//
// The context-aware pattern is used by middleware that receives the license key
// via context (set by LicenseMiddleware).
type Manager struct {
	publicKey    *ecdsa.PublicKey // Embedded public key for verification
	licenseKey   string           // Active license key (set by middleware or SetLicenseKey)
	cache        map[string]*cachedResult
	cacheMu      sync.RWMutex
	cacheEnabled bool
}

type cachedResult struct {
	result    ValidationResult
	expiresAt time.Time
}

// NewManager creates a new license manager with the embedded public key
func NewManager() (*Manager, error) {
	pubKey, err := GetEmbeddedPublicKey()
	if err != nil {
		// If key is placeholder, still create manager but mark as dev mode
		return &Manager{
			publicKey:    nil,
			cache:        make(map[string]*cachedResult),
			cacheEnabled: true,
		}, nil
	}

	return &Manager{
		publicKey:    pubKey,
		cache:        make(map[string]*cachedResult),
		cacheEnabled: true,
	}, nil
}

// NewManagerWithKey creates a manager with a custom public key (for testing)
func NewManagerWithKey(pubKeyPEM string) (*Manager, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key")
	}

	return &Manager{
		publicKey:    ecdsaPub,
		cache:        make(map[string]*cachedResult),
		cacheEnabled: true,
	}, nil
}

// DisableCache disables validation caching (useful for testing)
func (m *Manager) DisableCache() {
	m.cacheEnabled = false
}

// Validate validates a license key and returns the result
func (m *Manager) Validate(licenseKey string) ValidationResult {
	// Check cache first
	if m.cacheEnabled {
		m.cacheMu.RLock()
		if cached, ok := m.cache[licenseKey]; ok && time.Now().Before(cached.expiresAt) {
			m.cacheMu.RUnlock()
			return cached.result
		}
		m.cacheMu.RUnlock()
	}

	result := m.validateInternal(licenseKey)

	// Cache the result
	if m.cacheEnabled {
		m.cacheMu.Lock()
		m.cache[licenseKey] = &cachedResult{
			result:    result,
			expiresAt: time.Now().Add(CacheDuration),
		}
		m.cacheMu.Unlock()
	}

	return result
}

// validateInternal performs the actual validation without caching
func (m *Manager) validateInternal(licenseKey string) ValidationResult {
	now := time.Now()

	// Handle empty key (Community tier)
	if strings.TrimSpace(licenseKey) == "" {
		return ValidationResult{
			Valid:       true,
			Expired:     false,
			GracePeriod: false,
			Tier:        tier.TierCommunity,
			Message:     "No license key - using Community tier",
			ValidatedAt: now,
		}
	}

	// Decode license key
	payload, err := m.decodeLicense(licenseKey)
	if err != nil {
		return ValidationResult{
			Valid:       false,
			Expired:     false,
			GracePeriod: false,
			Tier:        tier.TierCommunity,
			Message:     fmt.Sprintf("Invalid license format: %v", err),
			Error:       err,
			ValidatedAt: now,
		}
	}

	// Check expiration
	expired := now.After(payload.ExpiresAt)
	inGracePeriod := false

	if expired {
		graceEnd := payload.ExpiresAt.Add(GracePeriodDays * 24 * time.Hour)
		if now.After(graceEnd) {
			// Grace period expired
			return ValidationResult{
				Valid:       false,
				Expired:     true,
				GracePeriod: false,
				Tier:        tier.TierCommunity,
				Payload:     *payload,
				Message:     fmt.Sprintf("License expired on %s (grace period ended)", payload.ExpiresAt.Format(time.RFC3339)),
				Error:       fmt.Errorf("license expired"),
				ValidatedAt: now,
			}
		}
		inGracePeriod = true
	}

	// Parse tier
	licenseTier, err := tier.ParseTier(payload.Tier)
	if err != nil {
		return ValidationResult{
			Valid:       false,
			Expired:     expired,
			GracePeriod: inGracePeriod,
			Tier:        tier.TierCommunity,
			Payload:     *payload,
			Message:     fmt.Sprintf("Invalid tier in license: %v", err),
			Error:       err,
			ValidatedAt: now,
		}
	}

	// Build success result
	message := fmt.Sprintf("License valid - %s tier", licenseTier.DisplayName())
	if inGracePeriod {
		message = fmt.Sprintf("License in grace period (expires %s) - %s tier", payload.ExpiresAt.Format(time.RFC3339), licenseTier.DisplayName())
	}

	return ValidationResult{
		Valid:       true,
		Expired:     expired,
		GracePeriod: inGracePeriod,
		Tier:        licenseTier,
		Payload:     *payload,
		Message:     message,
		ValidatedAt: now,
	}
}

// decodeLicense decodes and cryptographically verifies a license key
func (m *Manager) decodeLicense(licenseKey string) (*LicensePayload, error) {
	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(licenseKey)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Parse JSON
	var keyFormat LicenseKeyFormat
	if err := json.Unmarshal(decoded, &keyFormat); err != nil {
		return nil, fmt.Errorf("JSON parse failed: %w", err)
	}

	// Verify signature if we have a public key
	if m.publicKey != nil {
		if err := m.verifySignature(&keyFormat); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
	}

	return &keyFormat.Payload, nil
}

// verifySignature verifies the ECDSA signature on the license
func (m *Manager) verifySignature(keyFormat *LicenseKeyFormat) error {
	if m.publicKey == nil {
		return fmt.Errorf("no public key available for verification")
	}

	// Create canonical JSON of payload (without signature)
	payloadJSON, err := json.Marshal(keyFormat.Payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Hash the payload
	hash := sha256.Sum256(payloadJSON)

	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(keyFormat.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// ECDSA signature format: r || s (32 bytes each for P-256)
	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid signature length: expected 64, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	// Verify
	if !ecdsa.Verify(m.publicKey, hash[:], r, s) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// IsFeatureLicensed checks if a specific feature is available in the license
func (m *Manager) IsFeatureLicensed(result *ValidationResult, feature tier.Feature) bool {
	if !result.Valid {
		// Only Community features work without valid license
		return tier.RequiredTier(feature) == tier.TierCommunity
	}

	// Check if tier has access to feature
	return tier.HasFeature(result.Tier, feature)
}

// GetTier returns the current effective tier from a validation result
func (m *Manager) GetTier(result *ValidationResult) tier.Tier {
	if result == nil || !result.Valid {
		return tier.TierCommunity
	}
	return result.Tier
}

// SetLicenseKey sets the active license key for context-aware methods.
// This is typically called by the LicenseMiddleware when it reads the
// license key from the environment or request.
func (m *Manager) SetLicenseKey(key string) {
	m.licenseKey = key
}

// GetLicenseKey returns the currently set license key
func (m *Manager) GetLicenseKey() string {
	return m.licenseKey
}

// GetTierForContext returns the tier name string for the active license.
// This matches the interface expected by the upstream middleware, which
// calls lm.GetTier(ctx) and gets a string like "enterprise" or "community".
// It first checks the context for a license key override, then falls back
// to the Manager's stored license key.
func (m *Manager) GetTierForContext(ctx context.Context) string {
	key := m.keyFromContext(ctx)
	result := m.Validate(key)
	return result.Tier.String()
}

// IsFeatureLicensedForContext checks if a feature (by string key) is licensed.
// This matches the interface expected by the upstream middleware, which
// calls lm.IsFeatureLicensed(ctx, featureKey) with a string feature key
// (e.g., "mtls", "compliance_hipaa").
//
// It resolves the feature's required tier using the platform tier system,
// then validates that the current license tier meets or exceeds it.
func (m *Manager) IsFeatureLicensedForContext(ctx context.Context, featureKey string) bool {
	key := m.keyFromContext(ctx)
	result := m.Validate(key)

	if !result.Valid {
		// Only community features available without valid license
		return tier.IsFeatureCommunity(featureKey)
	}

	// Check if the validated tier has this feature
	return tier.TierHasFeatureKey(result.Tier, featureKey)
}

// keyFromContext resolves the license key from context or the Manager's stored key
func (m *Manager) keyFromContext(ctx context.Context) string {
	// Check context first (allows per-request key override)
	if key, ok := ctx.Value(CtxKeyLicenseKey).(string); ok && key != "" {
		return key
	}
	// Fall back to Manager's stored key
	return m.licenseKey
}

// ManagerFromContext retrieves the license Manager from context.
// Returns nil if no Manager is in the context.
func ManagerFromContext(ctx context.Context) *Manager {
	if m, ok := ctx.Value(CtxKeyManager).(*Manager); ok {
		return m
	}
	return nil
}

// ContextWithManager returns a new context with the license Manager set.
func ContextWithManager(ctx context.Context, m *Manager) context.Context {
	return context.WithValue(ctx, CtxKeyManager, m)
}

// ContextWithLicenseKey returns a new context with the license key set.
func ContextWithLicenseKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, CtxKeyLicenseKey, key)
}

// ClearCache clears the validation cache
func (m *Manager) ClearCache() {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	m.cache = make(map[string]*cachedResult)
}

// GetCachedEntries returns the number of cached validation entries
func (m *Manager) GetCachedEntries() int {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	return len(m.cache)
}
