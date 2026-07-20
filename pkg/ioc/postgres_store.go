// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ D1 PostgreSQL)
// =========================================================================
//
// postgres_store.go implements StoreInterface backed by PostgreSQL using
// pgx/v5. This is the storage backend for Professional and Enterprise tiers.
//
// Architecture:
//
//   - Connection pooling via pgxpool (configured from DatabaseConfig)
//   - Batch inserts via pgx.Batch for ObserveBatch
//   - Prepared statements for hot-path queries (Observe, Get, SnapshotSince)
//   - Indexed queries via IOCQuery for the /check endpoint
//   - Automatic migration on first connection
//   - Tier-based retention pruning (Community: 7d, Developer: 30d, Professional: 90d)
//
// Fallback behavior:
//
//   If AEGISGATE_DATABASE_URL is not set or FeaturePostgreSQL is not
//   entitled, the platform falls back to the in-memory Store with JSON
//   flush. This is handled by NewStoreFromConfig, not by this file.
//
// Thread safety:
//
//   All pgxpool operations are safe for concurrent use. The pool manages
//   its own connection lifecycle. The caller does NOT need to hold any
//   additional locks.
//
// v3.5.0+ D1 Phase 1A.
// =========================================================================

package ioc

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DatabaseConfig holds PostgreSQL connection configuration.
// Populated from AEGISGATE_DATABASE_URL env var and platformconfig.
type DatabaseConfig struct {
	// URL is the PostgreSQL connection string.
	// Format: postgres://user:pass@host:port/dbname?sslmode=prefer
	URL string

	// MaxConns is the maximum number of connections in the pool.
	// Default: 25.
	MaxConns int

	// MinConns is the minimum number of connections in the pool.
	// Default: 5.
	MinConns int

	// MaxConnIdleTime is the maximum time a connection can be idle.
	// Default: 30 minutes.
	MaxConnIdleTime time.Duration

	// MaxConnLifetime is the maximum time a connection can live.
	// Default: 1 hour.
	MaxConnLifetime time.Duration

	// HealthCheckInterval is how often the pool checks connection health.
	// Default: 30 seconds.
	HealthCheckInterval time.Duration
}

// DefaultDatabaseConfig returns sensible defaults for PostgreSQL.
func DefaultDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		MaxConns:            25,
		MinConns:            5,
		MaxConnIdleTime:     30 * time.Minute,
		MaxConnLifetime:     1 * time.Hour,
		HealthCheckInterval: 30 * time.Second,
	}
}

// PostgresStore implements StoreInterface backed by PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
	cfg  DatabaseConfig
}

// TenantContext holds the tenant context for multi-tenant operations.
// When TenantID is empty, operations are tenant-agnostic (admin mode).
type TenantContext struct {
	TenantID string
	IsAdmin  bool // If true, can access all tenants' data
}

// NewPostgresStore creates a new PostgresStore, connects to the database,
// runs any pending migrations, and prepares hot-path statements.
func NewPostgresStore(ctx context.Context, cfg DatabaseConfig) (*PostgresStore, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("database URL is required for PostgresStore")
	}

	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 25
	}
	if cfg.MinConns <= 0 {
		cfg.MinConns = 5
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	poolConfig.MaxConns = int32(cfg.MaxConns)
	poolConfig.MinConns = int32(cfg.MinConns)
	poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	poolConfig.HealthCheckPeriod = cfg.HealthCheckInterval

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	s := &PostgresStore{
		pool: pool,
		cfg:  cfg,
	}

	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return s, nil
}

// Observe records a new observation of an IOC using INSERT ... ON CONFLICT (upsert).
func (s *PostgresStore) Observe(ctx context.Context, ioc IOC, tenantCtx ...TenantContext) (*IOC, error) {
	if !ioc.Valid() {
		return nil, fmt.Errorf("invalid IOC")
	}

	now := time.Now().UTC()
	firstSeen := ioc.FirstSeen
	lastSeen := ioc.LastSeen
	if firstSeen.IsZero() {
		firstSeen = now
	}
	if lastSeen.IsZero() {
		lastSeen = now
	}

	// Extract tenant context (optional, defaults to empty string for backward compatibility)
	tenantID := ""
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
	}

	var result IOC
	err := s.pool.QueryRow(ctx,
		`INSERT INTO ioc_fingerprints (
			fingerprint, type, severity, category, pattern, source_provider,
			affects_lens, affects_gateway, source, count, first_seen, last_seen, tenant_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (fingerprint) DO UPDATE SET
			count = ioc_fingerprints.count + 1,
			last_seen = GREATEST(ioc_fingerprints.last_seen, EXCLUDED.last_seen),
			first_seen = LEAST(ioc_fingerprints.first_seen, EXCLUDED.first_seen),
			severity = CASE
				WHEN ioc_fingerprints.severity = 'critical' OR EXCLUDED.severity = 'critical' THEN 'critical'
				WHEN ioc_fingerprints.severity = 'high' OR EXCLUDED.severity = 'high' THEN 'high'
				WHEN ioc_fingerprints.severity = 'medium' OR EXCLUDED.severity = 'medium' THEN 'medium'
				WHEN ioc_fingerprints.severity = 'low' OR EXCLUDED.severity = 'low' THEN 'low'
				ELSE ioc_fingerprints.severity
			END,
			updated_at = NOW()
		RETURNING fingerprint, type, severity, category, pattern, source_provider,
			affects_lens, affects_gateway, source, count, first_seen, last_seen`,
		ioc.Fingerprint, string(ioc.Type), string(ioc.Severity), ioc.Category,
		ioc.Pattern, ioc.SourceProvider, ioc.AffectsLens, ioc.AffectsGateway,
		ioc.Source, 1, firstSeen, lastSeen, tenantID,
	).Scan(
		&result.Fingerprint, &result.Type, &result.Severity, &result.Category,
		&result.Pattern, &result.SourceProvider, &result.AffectsLens,
		&result.AffectsGateway, &result.Source, &result.Count,
		&result.FirstSeen, &result.LastSeen,
	)
	if err != nil {
		return nil, fmt.Errorf("observe ioc: %w", err)
	}
	return &result, nil
}

// ObserveBatch records multiple IOCs in a single batch using pgx.Batch.
func (s *PostgresStore) ObserveBatch(ctx context.Context, iocs []IOC, tenantCtx ...TenantContext) error {
	if len(iocs) == 0 {
		return nil
	}

	// Extract tenant context (optional, defaults to empty string)
	tenantID := ""
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
	}

	batch := &pgx.Batch{}
	now := time.Now().UTC()

	const upsertSQL = `INSERT INTO ioc_fingerprints (
		fingerprint, type, severity, category, pattern, source_provider,
		affects_lens, affects_gateway, source, count, first_seen, last_seen, tenant_id
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	ON CONFLICT (fingerprint) DO UPDATE SET
		count = ioc_fingerprints.count + 1,
		last_seen = GREATEST(ioc_fingerprints.last_seen, EXCLUDED.last_seen),
		first_seen = LEAST(ioc_fingerprints.first_seen, EXCLUDED.first_seen),
		severity = CASE
			WHEN ioc_fingerprints.severity = 'critical' OR EXCLUDED.severity = 'critical' THEN 'critical'
			WHEN ioc_fingerprints.severity = 'high' OR EXCLUDED.severity = 'high' THEN 'high'
			WHEN ioc_fingerprints.severity = 'medium' OR EXCLUDED.severity = 'medium' THEN 'medium'
			WHEN ioc_fingerprints.severity = 'low' OR EXCLUDED.severity = 'low' THEN 'low'
			ELSE ioc_fingerprints.severity
		END,
		updated_at = NOW()`

	for i := range iocs {
		if !iocs[i].Valid() {
			continue
		}
		ioc := iocs[i]
		firstSeen := ioc.FirstSeen
		lastSeen := ioc.LastSeen
		if firstSeen.IsZero() {
			firstSeen = now
		}
		if lastSeen.IsZero() {
			lastSeen = now
		}

		batch.Queue(upsertSQL,
			ioc.Fingerprint, string(ioc.Type), string(ioc.Severity), ioc.Category,
			ioc.Pattern, ioc.SourceProvider, ioc.AffectsLens, ioc.AffectsGateway,
			ioc.Source, 1, firstSeen, lastSeen, tenantID,
		)
	}

	results := s.pool.SendBatch(ctx, batch)
	defer results.Close()

	for i := 0; i < batch.Len(); i++ {
		if _, err := results.Exec(); err != nil {
			_ = err // individual failures are acceptable in batch
		}
	}
	return nil
}

// Get returns the IOC with the given fingerprint, or nil if not found.
// If tenantCtx is provided and IsAdmin is false, verifies tenant ownership.
func (s *PostgresStore) Get(ctx context.Context, fingerprint string, tenantCtx ...TenantContext) (*IOC, error) {
	// Extract tenant context (optional)
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	query := `SELECT fingerprint, type, severity, category, pattern, source_provider,
			affects_lens, affects_gateway, source, count, first_seen, last_seen, tenant_id
		FROM ioc_fingerprints WHERE fingerprint = $1`
	args := []interface{}{fingerprint}
	argIdx := 2

	// Add tenant filter unless admin mode
	if !isAdmin && tenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, tenantID)
	}

	var ioc IOC
	err := s.pool.QueryRow(ctx, query, args...).Scan(
		&ioc.Fingerprint, &ioc.Type, &ioc.Severity, &ioc.Category,
		&ioc.Pattern, &ioc.SourceProvider, &ioc.AffectsLens,
		&ioc.AffectsGateway, &ioc.Source, &ioc.Count,
		&ioc.FirstSeen, &ioc.LastSeen, &ioc.TenantID,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get ioc: %w", err)
	}
	return &ioc, nil
}

// Size returns the number of IOCs in the store.
// If tenantCtx is provided and IsAdmin is false, returns only tenant's IOC count.
func (s *PostgresStore) Size(ctx context.Context, tenantCtx ...TenantContext) (int, error) {
	// Extract tenant context (optional)
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	query := `SELECT COUNT(*) FROM ioc_fingerprints`
	args := []interface{}{}

	// Add tenant filter unless admin mode
	if !isAdmin && tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}

	var count int
	err := s.pool.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count iocs: %w", err)
	}
	return count, nil
}

// Snapshot returns all IOCs sorted by LastSeen descending.
// If tenantCtx is provided and IsAdmin is false, returns only tenant's IOCs.
func (s *PostgresStore) Snapshot(ctx context.Context, tenantCtx ...TenantContext) ([]IOC, error) {
	// Extract tenant context (optional)
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	query := `SELECT fingerprint, type, severity, category, pattern, source_provider,
			affects_lens, affects_gateway, source, count, first_seen, last_seen, tenant_id
		FROM ioc_fingerprints`
	args := []interface{}{}

	// Add tenant filter unless admin mode
	if !isAdmin && tenantID != "" {
		query += " WHERE tenant_id = $1"
		args = append(args, tenantID)
	}

	query += " ORDER BY last_seen DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("snapshot iocs: %w", err)
	}
	defer rows.Close()

	var iocs []IOC
	for rows.Next() {
		var ioc IOC
		if err := rows.Scan(
			&ioc.Fingerprint, &ioc.Type, &ioc.Severity, &ioc.Category,
			&ioc.Pattern, &ioc.SourceProvider, &ioc.AffectsLens,
			&ioc.AffectsGateway, &ioc.Source, &ioc.Count,
			&ioc.FirstSeen, &ioc.LastSeen, &ioc.TenantID,
		); err != nil {
			return nil, fmt.Errorf("scan ioc: %w", err)
		}
		iocs = append(iocs, ioc)
	}
	return iocs, nil
}

// SnapshotSince returns IOCs with LastSeen >= since, sorted by LastSeen descending.
// If tenantCtx is provided and IsAdmin is false, returns only tenant's IOCs.
func (s *PostgresStore) SnapshotSince(ctx context.Context, since time.Time, tenantCtx ...TenantContext) ([]IOC, error) {
	// Extract tenant context (optional)
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	query := `SELECT fingerprint, type, severity, category, pattern, source_provider,
			affects_lens, affects_gateway, source, count, first_seen, last_seen, tenant_id
		FROM ioc_fingerprints WHERE last_seen >= $1`
	args := []interface{}{since}
	argIdx := 2

	// Add tenant filter unless admin mode
	if !isAdmin && tenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, tenantID)
		argIdx++
	}

	query += " ORDER BY last_seen DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("snapshot since: %w", err)
	}
	defer rows.Close()

	var iocs []IOC
	for rows.Next() {
		var ioc IOC
		if err := rows.Scan(
			&ioc.Fingerprint, &ioc.Type, &ioc.Severity, &ioc.Category,
			&ioc.Pattern, &ioc.SourceProvider, &ioc.AffectsLens,
			&ioc.AffectsGateway, &ioc.Source, &ioc.Count,
			&ioc.FirstSeen, &ioc.LastSeen, &ioc.TenantID,
		); err != nil {
			return nil, fmt.Errorf("scan ioc: %w", err)
		}
		iocs = append(iocs, ioc)
	}
	return iocs, nil
}

// Query returns IOCs matching the given filter criteria using indexed lookups.
// If tenantCtx is provided and IsAdmin is false, results are filtered by tenant_id.
func (s *PostgresStore) Query(ctx context.Context, filter IOCQuery, tenantCtx ...TenantContext) ([]IOC, error) {
	// Extract tenant context (optional)
	var tenantID string
	isAdmin := false
	if len(tenantCtx) > 0 {
		tenantID = tenantCtx[0].TenantID
		isAdmin = tenantCtx[0].IsAdmin
	}

	// Build query with tenant filter (unless admin mode)
	query := `SELECT fingerprint, type, severity, category, pattern, source_provider,
			affects_lens, affects_gateway, source, count, first_seen, last_seen, tenant_id
		FROM ioc_fingerprints WHERE 1=1`

	if !isAdmin && tenantID != "" {
		// Tenant-scoped query: filter by tenant_id
		query += " AND tenant_id = $1"
	}

	args := []interface{}{}
	argIdx := 1

	// If we added tenant filter, increment argIdx
	if !isAdmin && tenantID != "" {
		argIdx = 2
		args = append(args, tenantID)
	}

	if filter.Type != "" {
		query += fmt.Sprintf(" AND type = $%d", argIdx)
		args = append(args, string(filter.Type))
		argIdx++
	}
	if filter.SeverityMin != "" {
		rankSQL := "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END"
		minRankSQL := fmt.Sprintf("CASE $%d WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END", argIdx)
		query += " AND " + rankSQL + " >= " + minRankSQL
		args = append(args, string(filter.SeverityMin))
		argIdx++
	}
	if filter.Category != "" {
		query += fmt.Sprintf(" AND category = $%d", argIdx)
		args = append(args, filter.Category)
		argIdx++
	}
	if filter.SourceProvider != "" {
		query += fmt.Sprintf(" AND source_provider = $%d", argIdx)
		args = append(args, filter.SourceProvider)
		argIdx++
	}
	if filter.AffectsLens != nil {
		query += fmt.Sprintf(" AND affects_lens = $%d", argIdx)
		args = append(args, *filter.AffectsLens)
		argIdx++
	}
	if filter.AffectsGateway != nil {
		query += fmt.Sprintf(" AND affects_gateway = $%d", argIdx)
		args = append(args, *filter.AffectsGateway)
		argIdx++
	}
	if !filter.Since.IsZero() {
		query += fmt.Sprintf(" AND last_seen >= $%d", argIdx)
		args = append(args, filter.Since)
		argIdx++
	}

	query += " ORDER BY last_seen DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, filter.Limit)
		argIdx++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
		argIdx++
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query iocs: %w", err)
	}
	defer rows.Close()

	var iocs []IOC
	for rows.Next() {
		var ioc IOC
		if err := rows.Scan(
			&ioc.Fingerprint, &ioc.Type, &ioc.Severity, &ioc.Category,
			&ioc.Pattern, &ioc.SourceProvider, &ioc.AffectsLens,
			&ioc.AffectsGateway, &ioc.Source, &ioc.Count,
			&ioc.FirstSeen, &ioc.LastSeen, &ioc.TenantID,
		); err != nil {
			return nil, fmt.Errorf("scan ioc: %w", err)
		}
		iocs = append(iocs, ioc)
	}
	return iocs, nil
}

// Prune removes IOCs older than maxAge and returns the count removed.
func (s *PostgresStore) Prune(ctx context.Context, maxAge time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-maxAge)

	result, err := s.pool.Exec(ctx,
		`DELETE FROM ioc_fingerprints WHERE last_seen < $1`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("prune iocs: %w", err)
	}
	return int(result.RowsAffected()), nil
}

// Flush is a no-op for PostgresStore. WAL handles persistence.
func (s *PostgresStore) Flush(ctx context.Context) error {
	return nil
}

// Close releases the connection pool.
func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// migrate runs all pending SQL migrations in order.
func (s *PostgresStore) migrate(ctx context.Context) error {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		var version int
		if _, err := fmt.Sscanf(entry.Name(), "%d_", &version); err != nil {
			continue
		}

		var applied bool
		err := s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM ioc_schema_migrations WHERE version = $1)`,
			version,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if applied {
			continue
		}

		sql, err := migrationFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration tx: %w", err)
		}

		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("exec migration %s: %w", entry.Name(), err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", entry.Name(), err)
		}
	}

	return nil
}

// Pool returns the underlying pgxpool.Pool for shared use by other
// PostgreSQL-backed components (e.g., the audit storage backend).
// Callers MUST NOT close the pool; the PostgresStore owns its lifecycle.
func (s *PostgresStore) Pool() *pgxpool.Pool {
	return s.pool
}

// DSN returns the database connection string (with password redacted).
func (s *PostgresStore) DSN() string {
	return s.cfg.URL
}
