// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — PostgreSQL License Validation Cache (v3.5.0+ D1 Phase 1C)
// =========================================================================
//
// postgres_cache.go implements a PostgreSQL-backed license validation cache
// that replaces the in-memory map[string]*cachedResult in license.Manager.
//
// This enables multi-instance deployment: when one instance validates a license,
// all other instances can read the cached result from PostgreSQL instead of
// re-validating the ECDSA signature. The cache TTL (5 minutes) matches the
// in-memory cache duration.
//
// Architecture:
//
//   - Shares the pgxpool.Pool from ioc.PostgresStore (single pool per process)
//   - INSERT ON CONFLICT for cache upsert
//   - expires_at column for automatic staleness detection
//   - Pruned by the persistence Manager's background goroutine
//
// Tier gating: FeaturePostgreSQL is required. Falls back to in-memory
// caching when PostgreSQL is not available.
//
// v3.5.0+ D1 Phase 1C.
// =========================================================================

package license

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// LicenseTenantContext provides tenant isolation for license operations.
type LicenseTenantContext struct {
	TenantID string
	IsAdmin  bool // if true, can access cross-tenant data
}

// PostgresLicenseCache implements a PostgreSQL-backed license validation cache.
type PostgresLicenseCache struct {
	pool   *pgxpool.Pool
	mgr    *ioc.PostgresStore // owns the pool lifecycle
	closed bool
}

// NewPostgresLicenseCache creates a PostgreSQL-backed license cache.
// If pgStore is nil, returns nil (caller should fall back to in-memory).
func NewPostgresLicenseCache(pgStore *ioc.PostgresStore) (*PostgresLicenseCache, error) {
	if pgStore == nil {
		return nil, fmt.Errorf("postgres store is nil, cannot create license cache")
	}

	return &PostgresLicenseCache{
		pool: pgStore.Pool(),
		mgr:  pgStore,
	}, nil
}

// Get retrieves a cached validation result by license key and tenant context.
// Returns nil if the cache entry is expired or not found.
// RLS policies provide defense-in-depth on top of the app-layer WHERE clause.
func (c *PostgresLicenseCache) Get(ctx context.Context, licenseKey string, tenantCtx ...LicenseTenantContext) *ValidationResult {
	if c.closed {
		return nil
	}

	// Extract tenant context (optional, backward compatible)
	var tenantID string
	var isAdmin bool
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	// Build query with tenant isolation
	var sql string
	var args []interface{}

	if tenantID != "" && !isAdmin {
		// Tenant-scoped query
		sql = `
			SELECT tier, valid, expired, grace_period, payload, message, error_msg, validated_at, expires_at
			FROM license_cache
			WHERE tenant_id = $1 AND license_key = $2 AND expires_at > NOW()`
		args = []interface{}{tenantID, licenseKey}
	} else {
		// Admin or legacy: allow empty tenant_id
		sql = `
			SELECT tier, valid, expired, grace_period, payload, message, error_msg, validated_at, expires_at
			FROM license_cache
			WHERE (tenant_id = $1 OR tenant_id = '') AND license_key = $2 AND expires_at > NOW()`
		args = []interface{}{tenantID, licenseKey}
	}

	var result *ValidationResult
	_ = ioc.WithTenantContextOrPool(ctx, c.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		var tierStr, message, errorMsg string
		var valid, expired, gracePeriod bool
		var payloadJSON []byte
		var validatedAt, expiresAt time.Time

		err := q.QueryRow(ctx, sql, args...).Scan(
			&tierStr, &valid, &expired, &gracePeriod,
			&payloadJSON, &message, &errorMsg,
			&validatedAt, &expiresAt,
		)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil // cache miss
			}
			log.Printf("PostgreSQL license cache get error: %v", err)
			return nil // fall back to re-validation
		}

		licenseTier, err := tier.ParseTier(tierStr)
		if err != nil {
			licenseTier = tier.TierCommunity
		}

		var payload LicensePayload
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			payload = LicensePayload{}
		}

		result = &ValidationResult{
			Valid:       valid,
			Expired:     expired,
			GracePeriod: gracePeriod,
			Tier:        licenseTier,
			Payload:     payload,
			Message:     message,
			ValidatedAt: validatedAt,
		}

		if errorMsg != "" {
			result.Error = fmt.Errorf("%s", errorMsg)
		}
		return nil
	})
	return result
}

// Set stores a validation result in the cache with the given TTL and tenant context.
// When tenant context is provided, runs in a transaction with RLS context.
func (c *PostgresLicenseCache) Set(ctx context.Context, licenseKey string, result *ValidationResult, ttl time.Duration, tenantCtx ...LicenseTenantContext) error {
	if c.closed {
		return fmt.Errorf("postgres license cache is closed")
	}
	if result == nil {
		return nil
	}

	// Extract tenant context (optional, backward compatible)
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	payloadJSON, err := json.Marshal(result.Payload)
	if err != nil {
		payloadJSON = []byte("{}")
	}

	errorMsg := ""
	if result.Error != nil {
		errorMsg = result.Error.Error()
	}

	expiresAt := result.ValidatedAt.Add(ttl)
	if expiresAt.IsZero() || expiresAt.Before(time.Now()) {
		expiresAt = time.Now().Add(ttl)
	}

	const sql = `
		INSERT INTO license_cache (tenant_id, license_key, tier, valid, expired, grace_period, payload, message, error_msg, validated_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, license_key) DO UPDATE SET
			tier = EXCLUDED.tier,
			valid = EXCLUDED.valid,
			expired = EXCLUDED.expired,
			grace_period = EXCLUDED.grace_period,
			payload = EXCLUDED.payload,
			message = EXCLUDED.message,
			error_msg = EXCLUDED.error_msg,
			validated_at = EXCLUDED.validated_at,
			expires_at = EXCLUDED.expires_at`

	return ioc.WithTenantContextOrPool(ctx, c.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx, sql,
			tenantID, licenseKey, result.Tier.String(), result.Valid, result.Expired, result.GracePeriod,
			payloadJSON, result.Message, errorMsg,
			result.ValidatedAt, expiresAt,
		)
		if err != nil {
			return fmt.Errorf("postgres license cache set: %w", err)
		}
		return nil
	})
}

// Invalidate removes a cached validation result by tenant and license key.
// RLS policies provide defense-in-depth on top of the app-layer WHERE clause.
func (c *PostgresLicenseCache) Invalidate(ctx context.Context, licenseKey string, tenantCtx ...LicenseTenantContext) error {
	if c.closed {
		return fmt.Errorf("postgres license cache is closed")
	}

	// Extract tenant context (optional, backward compatible)
	var tenantID string
	var isAdmin bool
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	var sql string
	var args []interface{}

	if tenantID != "" && !isAdmin {
		// Tenant-scoped delete
		sql = `DELETE FROM license_cache WHERE tenant_id = $1 AND license_key = $2`
		args = []interface{}{tenantID, licenseKey}
	} else {
		// Admin or legacy: delete from empty tenant_id
		sql = `DELETE FROM license_cache WHERE (tenant_id = $1 OR tenant_id = '') AND license_key = $2`
		args = []interface{}{tenantID, licenseKey}
	}

	return ioc.WithTenantContextOrPool(ctx, c.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("postgres license cache invalidate: %w", err)
		}
		return nil
	})
}

// PruneExpired removes all expired cache entries.
// Called by the persistence Manager's background goroutine.
// Runs as admin (bypasses RLS) since pruning is a platform-level operation.
func (c *PostgresLicenseCache) PruneExpired(ctx context.Context, tenantCtx ...LicenseTenantContext) (int, error) {
	if c.closed {
		return 0, fmt.Errorf("postgres license cache is closed")
	}

	// Extract tenant context (optional)
	var tenantID string
	var isAdmin bool
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	var sql string
	var args []interface{}

	if tenantID != "" && !isAdmin {
		// Tenant-scoped prune
		sql = `DELETE FROM license_cache WHERE tenant_id = $1 AND expires_at < NOW()`
		args = []interface{}{tenantID}
	} else {
		// Admin or global prune
		sql = `DELETE FROM license_cache WHERE expires_at < NOW()`
	}

	var pruned int
	err := ioc.WithTenantContextOrPool(ctx, c.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		tag, err := q.Exec(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("postgres license cache prune: %w", err)
		}
		pruned = int(tag.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, err
	}
	if pruned > 0 {
		log.Printf("PostgreSQL license cache prune: removed %d expired entries", pruned)
	}
	return pruned, nil
}

// Close marks the cache as closed. Does NOT close the pool (PostgresStore owns it).
func (c *PostgresLicenseCache) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	log.Println("PostgreSQL license cache closed (pool remains open for IOC store)")
	return nil
}
