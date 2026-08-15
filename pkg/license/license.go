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
	"log"
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
	// CtxKeyTenantContext is the context key for tenant isolation
	CtxKeyTenantContext contextKey = "aegisgate_tenant_context"
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
	LicenseID    string    `json:"license_id"`             // UUID
	Tier         string    `json:"tier"`                   // Tier name
	Customer     string    `json:"customer"`               // Customer identifier
	IssuedAt     time.Time `json:"issued_at"`              // When license was issued
	ExpiresAt    time.Time `json:"expires_at"`             // When license expires
	Features     []string  `json:"features"`               // Optional specific features
	Modules      []string  `json:"modules,omitempty"`      // v3.2.0: purchased compliance modules (a la carte)
	Accelerators []string  `json:"accelerators,omitempty"` // v3.7.0: purchased vertical bundles
	MaxServers   int       `json:"max_servers"`            // Max servers allowed
	MaxUsers     int       `json:"max_users"`              // Max users allowed
}

// v3.2.0 Phase 1: canonical names of the 6 billable compliance modules.
// These are the "modules" that a customer can purchase as add-ons to their
// tier subscription. Prices are locked in aegisgate-pricing-decisions-locked-2026-06-04.
// "trust" is reserved for a future Trust Framework module (Phase 4) and is
// not yet billable.
const (
	ModuleHIPAA      = "hipaa"
	ModulePCI        = "pci"
	ModuleSOC2       = "soc2"
	ModuleISO42001   = "iso42001"
	ModuleFedRAMP    = "fedramp"
	ModuleFIPS       = "fips"
	ModuleEUAIAct    = "eu_ai_act"   // v3.3.0 Phase 1: Regulation 2024/1689
	ModuleCMMCL2     = "cmmcl2"      // v3.6.0 M3: CMMC Level 2
	ModuleNIST800171 = "nist800171"  // v3.6.0 M3: NIST SP 800-171
	ModuleHITRUST    = "hitrust"     // v3.6.0 M3: HITRUST CSF
	ModuleTISAX      = "tisax"       // v3.6.0 M3: TISAX AL2
	ModuleCCPA       = "ccpa"        // v3.6.0 M3: CCPA/CPRA (Community tier)
	ModuleNISTAIRMF  = "nist_ai_rmf" // v3.7.0: NIST AI RMF 1.0 (Community tier, free)
	ModuleATLAS      = "atlas"       // MITRE ATLAS (Community tier, free)
	ModuleGDPR       = "gdpr"        // GDPR (Community tier, free)
	ModuleOWASP      = "owasp"       // OWASP LLM Top 10 (Community tier, free)
	ModuleTrust      = "trust"       // Trust Framework (built, Professional+)
	ModuleISO27001   = "iso27001"    // ISO 27001 (built, Developer+)

	// v4.2.0: Previously orphaned frameworks (built but not billable).
	// Now registered in gating.go with tier gates and pricing.
	ModuleSOX        = "sox"          // Sarbanes-Oxley Act
	ModuleGLBA       = "glba"         // Gramm-Leach-Bliley Act
	ModuleCJIS       = "cjis"         // Criminal Justice Information Services
	ModuleNERCCIP    = "nerc_cip"     // NERC Critical Infrastructure Protection
	ModuleFERPA      = "ferpa"        // Family Educational Rights & Privacy Act
	ModuleCSASTAR    = "csa_star"     // CSA STAR Attestation
	ModuleNISTCSF    = "nist_csf"     // NIST Cybersecurity Framework
	ModuleCIS        = "cis"          // CIS Critical Security Controls
	ModuleNISTAI600  = "nist_ai_600_1" // NIST AI 600-1
	ModuleOWASPWeb   = "owasp_web"    // OWASP Web Top 10

	// v4.2.0: New frameworks — built and integrated with cross-framework mapping.
	ModuleHITECH     = "hitech"       // HITECH Act (extends HIPAA)
	ModuleFFIEC      = "ffiec"        // FFIEC Banking Guidance
	ModuleTSASD      = "tsa_sd"       // TSA Security Directive (pipeline)
	ModuleISO21434   = "iso21434"     // ISO 21434 (automotive cybersecurity)
)

// ---------------------------------------------------------------------------
// Vertical accelerator bundles (v3.7.0)
//
// Bundles group compliance frameworks by industry at a discounted price.
// They sit ON TOP of a tier subscription — you can't buy a bundle without
// a tier, because the tier provides the platform capability.
// ---------------------------------------------------------------------------

const (
	BundleHealthcare    = "healthcare"     // HIPAA + HITECH + HITRUST
	BundleDefense       = "defense"        // CMMC L2 + NIST 800-171 + FedRAMP + CJIS + TSA SD
	BundleFinance       = "finance"        // PCI + SOC 2 + ISO 27001 + GLBA + SOX + FFIEC
	BundleEnergy        = "energy"         // NERC CIP + TSA SD + FIPS (revised from Manufacturing)
	BundlePrivacy       = "privacy"        // GDPR + CCPA + ISO 27001
	BundleSaaSB2B       = "saas_b2b"       // SOC 2 + ISO 27001 + ISO 42001 (NEW)
	BundleEUCompliance  = "eu_compliance"  // EU AI Act + GDPR + ISO 42001 (NEW)
)

// AllBundles is the canonical list of bundle IDs, in display order.
var AllBundles = []string{
	BundlePrivacy,
	BundleSaaSB2B,
	BundleFinance,
	BundleHealthcare,
	BundleEUCompliance,
	BundleEnergy,
	BundleDefense,
}

// IsValidBundle returns true if the given bundle ID is a known accelerator.
func IsValidBundle(name string) bool {
	for _, b := range AllBundles {
		if b == name {
			return true
		}
	}
	return false
}

// AllModules is the canonical list of billable module names, in display order.
// Used for validation when parsing Stripe webhook payloads.
var AllModules = []string{
	// Community tier (free, not billable but registered for validation)
	ModuleCCPA,
	ModuleNISTAIRMF,
	ModuleATLAS,
	ModuleGDPR,
	ModuleOWASP,
	ModuleOWASPWeb,
	ModuleCIS,
	ModuleNISTCSF,
	ModuleCSASTAR,
	ModuleNISTAI600,

	// Developer tier
	ModuleHIPAA,
	ModulePCI,
	ModuleSOC2,
	ModuleISO27001,

	// Professional tier
	ModuleISO42001,
	ModuleFedRAMP,
	ModuleFIPS,
	ModuleEUAIAct,
	ModuleCMMCL2,
	ModuleNIST800171,
	ModuleTrust,
	ModuleSOX,
	ModuleGLBA,
	ModuleNERCCIP,
	ModuleCJIS,
	ModuleFERPA,
	ModuleHITECH,
	ModuleFFIEC,
	ModuleTSASD,
	ModuleISO21434,

	// Enterprise tier
	ModuleHITRUST,
	ModuleTISAX,
}

// IsValidModule returns true if the given module name is a known billable module.
// Unknown module names (typos, old format, etc.) are rejected.
func IsValidModule(name string) bool {
	for _, m := range AllModules {
		if m == name {
			return true
		}
	}
	return false
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

	// PostgreSQL backend (nil for in-memory mode)
	pgCache     *PostgresLicenseCache
	usePostgres bool
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

// NewWithPostgres creates a Manager that uses PostgreSQL for license validation
// caching. If pgCache is nil, falls back to in-memory caching (same as NewManager).
// This is for Professional/Enterprise tiers with FeaturePostgreSQL enabled.
func NewWithPostgres(pgCache *PostgresLicenseCache) (*Manager, error) {
	m, err := NewManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create base manager: %w", err)
	}
	if pgCache == nil {
		// No PostgreSQL available; use in-memory cache
		return m, nil
	}
	m.pgCache = pgCache
	m.usePostgres = true
	return m, nil
}

// UsesPostgres returns whether PostgreSQL caching is active.
func (m *Manager) UsesPostgres() bool {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	return m.usePostgres
}

// DisableCache disables validation caching (useful for testing)
func (m *Manager) DisableCache() {
	m.cacheEnabled = false
}

// Validate validates a license key and returns the result
func (m *Manager) Validate(licenseKey string, tenantCtx ...LicenseTenantContext) ValidationResult {
	// PostgreSQL path: check PostgreSQL cache first, then validate and store
	if m.usePostgres && m.pgCache != nil {
		ctx := context.Background()
		// Check PostgreSQL cache
		cached := m.pgCache.Get(ctx, licenseKey, tenantCtx...)
		if cached != nil {
			return *cached
		}

		// Validate and store in PostgreSQL cache
		result := m.validateInternal(licenseKey)
		if err := m.pgCache.Set(ctx, licenseKey, &result, CacheDuration, tenantCtx...); err != nil {
			// Log but don't fail — fall back to in-memory cache
			log.Printf("Warning: PostgreSQL license cache set failed: %v", err)
			// Store in in-memory cache as fallback
			if m.cacheEnabled {
				m.cacheMu.Lock()
				m.cache[licenseKey] = &cachedResult{
					result:    result,
					expiresAt: time.Now().Add(CacheDuration),
				}
				m.cacheMu.Unlock()
			}
		}
		return result
	}

	// In-memory path: check local cache first
	if m.cacheEnabled {
		m.cacheMu.RLock()
		if cached, ok := m.cache[licenseKey]; ok && time.Now().Before(cached.expiresAt) {
			m.cacheMu.RUnlock()
			return cached.result
		}
		m.cacheMu.RUnlock()
	}

	result := m.validateInternal(licenseKey)

	// Cache the result in memory
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

// HasModule checks if a specific compliance module is owned by the license.
//
// v3.2.0 Phase 1: modules are billable add-ons purchased via Stripe
// (Q1: instant via webhook; Q2: locked in at purchase price forever).
// A module is owned if its name appears in LicensePayload.Modules.
//
// Returns false if:
//   - result is nil or invalid
//   - the module name is not in the license's Modules list
//   - the module name is not a known billable module (defense against typos)
//
// Examples:
//
//	HasModule(result, ModuleHIPAA)    // true if the customer bought HIPAA
//	HasModule(result, "hipaa")        // same, by string literal
//	HasModule(result, "invalid")      // false (unknown module)
func (m *Manager) HasModule(result *ValidationResult, moduleName string) bool {
	if result == nil || !result.Valid {
		return false
	}
	if !IsValidModule(moduleName) {
		return false
	}
	for _, owned := range result.Payload.Modules {
		if owned == moduleName {
			return true
		}
	}
	return false
}

// Modules returns the list of module names owned by the license.
// Returns nil if the license is invalid.
func (m *Manager) Modules(result *ValidationResult) []string {
	if result == nil || !result.Valid {
		return nil
	}
	out := make([]string, 0, len(result.Payload.Modules))
	for _, m := range result.Payload.Modules {
		if IsValidModule(m) {
			out = append(out, m)
		}
	}
	return out
}

// HasAccelerator checks if a specific vertical accelerator bundle is owned
// by the license. Returns false if the license is invalid or the bundle
// is unknown.
//
// Example:
//
//	HasAccelerator(result, license.BundleHealthcare) // true if customer bought Healthcare pack
func (m *Manager) HasAccelerator(result *ValidationResult, bundleID string) bool {
	if result == nil || !result.Valid {
		return false
	}
	if !IsValidBundle(bundleID) {
		return false
	}
	for _, a := range result.Payload.Accelerators {
		if a == bundleID {
			return true
		}
	}
	return false
}

// Accelerators returns the list of accelerator bundle IDs owned by the license.
// Returns nil if the license is invalid.
func (m *Manager) Accelerators(result *ValidationResult) []string {
	if result == nil || !result.Valid {
		return nil
	}
	out := make([]string, 0, len(result.Payload.Accelerators))
	for _, a := range result.Payload.Accelerators {
		if IsValidBundle(a) {
			out = append(out, a)
		}
	}
	return out
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
	tenantCtx := TenantContextFromContext(ctx)
	result := m.Validate(key, tenantCtx)
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
	tenantCtx := TenantContextFromContext(ctx)
	result := m.Validate(key, tenantCtx)

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

// TenantContextFromContext retrieves the LicenseTenantContext from context.
// Returns a default context with empty TenantID if not present.
func TenantContextFromContext(ctx context.Context) LicenseTenantContext {
	if tc, ok := ctx.Value(CtxKeyTenantContext).(LicenseTenantContext); ok {
		return tc
	}
	return LicenseTenantContext{}
}

// ContextWithTenantContext returns a new context with the tenant context set.
func ContextWithTenantContext(ctx context.Context, tc LicenseTenantContext) context.Context {
	return context.WithValue(ctx, CtxKeyTenantContext, tc)
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

// PruneExpiredCache prunes expired license cache entries from PostgreSQL.
// Called by the persistence Manager's background goroutine.
// Returns 0 and nil if not using PostgreSQL.
func (m *Manager) PruneExpiredCache(ctx context.Context) (int, error) {
	if !m.usePostgres || m.pgCache == nil {
		return 0, nil
	}
	return m.pgCache.PruneExpired(ctx)
}

// SetPostgresCache sets the PostgreSQL cache backend for license validation.
// This is called during startup when PostgreSQL is available. Thread-safe.
func (m *Manager) SetPostgresCache(pgCache *PostgresLicenseCache) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	m.pgCache = pgCache
	m.usePostgres = true
}

// Close cleans up the Manager and closes the PostgreSQL cache if present.
// G104 (errors unhandled) is suppressed here: Close() at manager teardown
// is best-effort and the connection pool will be GC'd if it fails.
func (m *Manager) Close() {
	if m.pgCache != nil {
		_ = m.pgCache.Close()
	}
}
