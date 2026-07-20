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

// Get retrieves a cached validation result by license key.
// Returns nil if the cache entry is expired or not found.
func (c *PostgresLicenseCache) Get(ctx context.Context, licenseKey string) *ValidationResult {
	if c.closed {
		return nil
	}

	const sql = `
		SELECT tier, valid, expired, grace_period, payload, message, error_msg, validated_at, expires_at
		FROM license_cache
		WHERE license_key = $1 AND expires_at > NOW()`

	var tierStr, message, errorMsg string
	var valid, expired, gracePeriod bool
	var payloadJSON []byte
	var validatedAt, expiresAt time.Time

	err := c.pool.QueryRow(ctx, sql, licenseKey).Scan(
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

	result := &ValidationResult{
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

	return result
}

// Set stores a validation result in the cache with the given TTL.
func (c *PostgresLicenseCache) Set(ctx context.Context, licenseKey string, result *ValidationResult, ttl time.Duration) error {
	if c.closed {
		return fmt.Errorf("postgres license cache is closed")
	}
	if result == nil {
		return nil
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
		INSERT INTO license_cache (license_key, tier, valid, expired, grace_period, payload, message, error_msg, validated_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (license_key) DO UPDATE SET
			tier = EXCLUDED.tier,
			valid = EXCLUDED.valid,
			expired = EXCLUDED.expired,
			grace_period = EXCLUDED.grace_period,
			payload = EXCLUDED.payload,
			message = EXCLUDED.message,
			error_msg = EXCLUDED.error_msg,
			validated_at = EXCLUDED.validated_at,
			expires_at = EXCLUDED.expires_at`

	_, err = c.pool.Exec(ctx, sql,
		licenseKey, result.Tier.String(), result.Valid, result.Expired, result.GracePeriod,
		payloadJSON, result.Message, errorMsg,
		result.ValidatedAt, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("postgres license cache set: %w", err)
	}

	return nil
}

// Invalidate removes a cached validation result.
func (c *PostgresLicenseCache) Invalidate(ctx context.Context, licenseKey string) error {
	if c.closed {
		return fmt.Errorf("postgres license cache is closed")
	}

	const sql = `DELETE FROM license_cache WHERE license_key = $1`
	_, err := c.pool.Exec(ctx, sql, licenseKey)
	if err != nil {
		return fmt.Errorf("postgres license cache invalidate: %w", err)
	}
	return nil
}

// PruneExpired removes all expired cache entries.
// Called by the persistence Manager's background goroutine.
func (c *PostgresLicenseCache) PruneExpired(ctx context.Context) (int, error) {
	if c.closed {
		return 0, fmt.Errorf("postgres license cache is closed")
	}

	tag, err := c.pool.Exec(ctx, `DELETE FROM license_cache WHERE expires_at < NOW()`)
	if err != nil {
		return 0, fmt.Errorf("postgres license cache prune: %w", err)
	}

	pruned := int(tag.RowsAffected())
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
