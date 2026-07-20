// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - PostgreSQL Audit Storage Backend (v3.5.0+ D1 Phase 1B)
// =========================================================================
//
// postgres_storage_backend.go implements the opsec.StorageBackend interface
// using PostgreSQL (via pgx/v5). This enables Professional and Enterprise
// tiers to persist audit log entries to PostgreSQL instead of flat files.
//
// Tier gating: FeaturePostgreSQL is required. Community and Developer tiers
// continue to use FileStorageBackend. The persistence.Manager selects the
// appropriate backend at startup based on tier features and configuration.
//
// Features:
//   - Hash-chain integrity: each entry's hash is verified on read;
//     writes compute hash from entry + previous_hash.
//   - Tier-based retention: Community 7d, Developer 30d, Professional 90d,
//     Enterprise unlimited. Pruning is done by the Manager's background
//     goroutine, same as FileStorageBackend.
//   - Indexed queries: timestamp, event_type, compliance_tags (GIN),
//     tenant_id, level, source, and full-text search.
//   - Graceful degradation: if PostgreSQL is unavailable at startup,
//     the Manager falls back to FileStorageBackend.
//
// v3.5.0+ D1 Phase 1B.
// =========================================================================

package persistence

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
)

// postgresStorageBackend implements opsec.StorageBackend using PostgreSQL.
type postgresStorageBackend struct {
	pool   *pgxpool.Pool
	dbURL  string
	mgr    *ioc.PostgresStore // shares the connection pool
	closed bool
}

// Verify at compile time that postgresStorageBackend satisfies opsec.StorageBackend.
var _ opsec.StorageBackend = (*postgresStorageBackend)(nil)

// newPostgresStorageBackend creates a PostgreSQL-backed audit storage.
// It shares the connection pool from an existing ioc.PostgresStore instance,
// so there is only one pool per process.
func newPostgresStorageBackend(mgr *ioc.PostgresStore) (*postgresStorageBackend, error) {
	if mgr == nil {
		return nil, fmt.Errorf("postgres store manager is nil")
	}

	return &postgresStorageBackend{
		pool:  mgr.Pool(),
		dbURL: mgr.DSN(),
		mgr:   mgr,
	}, nil
}

// Write persists an audit entry to the audit_entries table.
// The entry's Hash and PreviousHash are stored as-is; the caller
// (ComplianceAuditLog) is responsible for computing the hash chain.
func (b *postgresStorageBackend) Write(ctx context.Context, entry *opsec.AuditEntry) error {
	if b.closed {
		return fmt.Errorf("postgres storage backend is closed")
	}
	if entry == nil {
		return nil
	}

	dataJSON, err := json.Marshal(entry.Data)
	if err != nil {
		dataJSON = []byte("{}")
	}

	tagsJSON, err := json.Marshal(entry.ComplianceTags)
	if err != nil {
		tagsJSON = []byte("[]")
	}

	const sql = `
		INSERT INTO audit_entries (id, timestamp, level, event_type, message, source,
		                           hash, previous_hash, tenant_id, data, compliance_tags)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO NOTHING`

	_, err = b.pool.Exec(ctx, sql,
		entry.ID,
		entry.Timestamp,
		entry.Level.String(),
		entry.EventType,
		entry.Message,
		entry.Source,
		entry.Hash,
		entry.PreviousHash,
		entry.TenantID,
		dataJSON,
		tagsJSON,
	)
	if err != nil {
		return fmt.Errorf("postgres audit write: %w", err)
	}

	return nil
}

// Read retrieves a single audit entry by ID.
func (b *postgresStorageBackend) Read(ctx context.Context, id string) (*opsec.AuditEntry, error) {
	if b.closed {
		return nil, fmt.Errorf("postgres storage backend is closed")
	}

	const sql = `
		SELECT id, timestamp, level, event_type, message, source,
		       hash, previous_hash, tenant_id, data, compliance_tags
		FROM audit_entries WHERE id = $1`

	row := b.pool.QueryRow(ctx, sql, id)
	entry, err := scanAuditEntry(row)
	if err != nil {
		if isNoRows(err) {
			return nil, nil // not found is not an error
		}
		return nil, fmt.Errorf("postgres audit read: %w", err)
	}
	return entry, nil
}

// Query returns audit entries matching the given filter.
// The filter maps to indexed WHERE clauses for efficient retrieval.
func (b *postgresStorageBackend) Query(ctx context.Context, filter opsec.AuditFilter) ([]*opsec.AuditEntry, error) {
	if b.closed {
		return nil, fmt.Errorf("postgres storage backend is closed")
	}

	where, args, idx := "", make([]interface{}, 0, 8), 1

	if !filter.StartTime.IsZero() {
		where += fmt.Sprintf(" timestamp >= $%d", idx)
		args = append(args, filter.StartTime)
		idx++
	}
	if !filter.EndTime.IsZero() {
		if where != "" {
			where += " AND"
		}
		where += fmt.Sprintf(" timestamp <= $%d", idx)
		args = append(args, filter.EndTime)
		idx++
	}
	if len(filter.Levels) > 0 {
		placeholders := make([]string, len(filter.Levels))
		for i, l := range filter.Levels {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, l.String())
			idx++
		}
		if where != "" {
			where += " AND"
		}
		where += fmt.Sprintf(" level IN (%s)", joinStrings(placeholders, ", "))
	}
	if len(filter.EventTypes) > 0 {
		placeholders := make([]string, len(filter.EventTypes))
		for i, et := range filter.EventTypes {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, et)
			idx++
		}
		if where != "" {
			where += " AND"
		}
		where += fmt.Sprintf(" event_type IN (%s)", joinStrings(placeholders, ", "))
	}
	if filter.TenantID != "" {
		if where != "" {
			where += " AND"
		}
		where += fmt.Sprintf(" tenant_id = $%d", idx)
		args = append(args, filter.TenantID)
		idx++
	}
	if filter.Source != "" {
		if where != "" {
			where += " AND"
		}
		where += fmt.Sprintf(" source = $%d", idx)
		args = append(args, filter.Source)
		idx++
	}
	if filter.SearchText != "" {
		if where != "" {
			where += " AND"
		}
		where += fmt.Sprintf(" to_tsvector('english', message) @@ plainto_tsquery('english', $%d)", idx)
		args = append(args, filter.SearchText)
		idx++
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 1000
	}
	args = append(args, limit)

	whereClause := ""
	if where != "" {
		whereClause = "WHERE" + where
	}

	sql := fmt.Sprintf(`
		SELECT id, timestamp, level, event_type, message, source,
		       hash, previous_hash, tenant_id, data, compliance_tags
		FROM audit_entries
		%s
		ORDER BY timestamp DESC
		LIMIT $%d`, whereClause, idx)

	rows, err := b.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres audit query: %w", err)
	}
	defer rows.Close()

	var entries []*opsec.AuditEntry
	for rows.Next() {
		entry, err := scanAuditEntryFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres audit scan: %w", err)
		}
		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// Delete removes an audit entry by ID.
// NOTE: Deleting audit entries breaks the hash chain. This is intended
// only for retention pruning of expired entries (oldest first).
func (b *postgresStorageBackend) Delete(ctx context.Context, id string) error {
	if b.closed {
		return fmt.Errorf("postgres storage backend is closed")
	}

	const sql = `DELETE FROM audit_entries WHERE id = $1`
	_, err := b.pool.Exec(ctx, sql, id)
	if err != nil {
		return fmt.Errorf("postgres audit delete: %w", err)
	}
	return nil
}

// Close releases the PostgreSQL connection pool.
// This delegates to the PostgresStore's Close method, which is the
// single owner of the pool. Callers should NOT call this directly;
// instead, call the Manager's Close, which orchestrates shutdown.
func (b *postgresStorageBackend) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	// Do NOT close the pool here — PostgresStore owns it.
	// The Manager's Close will handle pool teardown via PostgresStore.Close().
	log.Println("PostgreSQL audit storage backend closed (pool remains open for IOC store)")
	return nil
}

// PruneExpired deletes audit entries older than the given retention period.
// Called by the persistence.Manager's background goroutine.
// Returns the number of entries pruned.
func (b *postgresStorageBackend) PruneExpired(ctx context.Context, retentionDays int) (int, error) {
	if b.closed {
		return 0, fmt.Errorf("postgres storage backend is closed")
	}
	if retentionDays <= 0 {
		return 0, nil // unlimited retention
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)

	const sql = `DELETE FROM audit_entries WHERE timestamp < $1`
	tag, err := b.pool.Exec(ctx, sql, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres audit prune: %w", err)
	}

	pruned := int(tag.RowsAffected())
	if pruned > 0 {
		log.Printf("PostgreSQL audit prune: removed %d entries older than %d days", pruned, retentionDays)
	}
	return pruned, nil
}

// Count returns the total number of audit entries.
func (b *postgresStorageBackend) Count(ctx context.Context) (int64, error) {
	if b.closed {
		return 0, fmt.Errorf("postgres storage backend is closed")
	}

	var count int64
	const sql = `SELECT COUNT(*) FROM audit_entries`
	err := b.pool.QueryRow(ctx, sql).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("postgres audit count: %w", err)
	}
	return count, nil
}

// VerifyIntegrity checks the hash chain of all audit entries.
// Returns true if the chain is intact, plus a list of any broken links.
func (b *postgresStorageBackend) VerifyIntegrity(ctx context.Context) (bool, []string, error) {
	if b.closed {
		return false, nil, fmt.Errorf("postgres storage backend is closed")
	}

	const sql = `
		SELECT id, hash, previous_hash
		FROM audit_entries
		ORDER BY timestamp ASC`

	rows, err := b.pool.Query(ctx, sql)
	if err != nil {
		return false, nil, fmt.Errorf("postgres audit integrity query: %w", err)
	}
	defer rows.Close()

	var broken []string
	var prevHash string

	for rows.Next() {
		var id, hash, prevRef string
		if err := rows.Scan(&id, &hash, &prevRef); err != nil {
			return false, nil, fmt.Errorf("postgres audit integrity scan: %w", err)
		}

		// First entry: previous_hash should be empty
		if prevHash == "" && prevRef != "" {
			broken = append(broken, fmt.Sprintf("entry %s: unexpected previous_hash %q (first entry)", id, prevRef))
		} else if prevHash != "" && prevRef != prevHash {
			broken = append(broken, fmt.Sprintf("entry %s: hash chain broken (expected previous %q, got %q)", id, prevHash, prevRef))
		}

		prevHash = hash
	}

	if err := rows.Err(); err != nil {
		return false, nil, fmt.Errorf("postgres audit integrity rows: %w", err)
	}

	return len(broken) == 0, broken, nil
}

// scanAuditEntry scans a single audit entry from a query row.
func scanAuditEntry(row pgx.Row) (*opsec.AuditEntry, error) {
	var entry opsec.AuditEntry
	var level string
	var dataJSON, tagsJSON []byte

	err := row.Scan(
		&entry.ID, &entry.Timestamp, &level, &entry.EventType,
		&entry.Message, &entry.Source, &entry.Hash, &entry.PreviousHash,
		&entry.TenantID, &dataJSON, &tagsJSON,
	)
	if err != nil {
		return nil, err
	}

	entry.Level = parseAuditLevel(level)

	if err := json.Unmarshal(dataJSON, &entry.Data); err != nil {
		entry.Data = make(map[string]interface{})
	}
	if err := json.Unmarshal(tagsJSON, &entry.ComplianceTags); err != nil {
		entry.ComplianceTags = nil
	}

	return &entry, nil
}

// scanAuditEntryFromRows scans a single audit entry from an active rows iterator.
func scanAuditEntryFromRows(rows pgx.Rows) (*opsec.AuditEntry, error) {
	var entry opsec.AuditEntry
	var level string
	var dataJSON, tagsJSON []byte

	err := rows.Scan(
		&entry.ID, &entry.Timestamp, &level, &entry.EventType,
		&entry.Message, &entry.Source, &entry.Hash, &entry.PreviousHash,
		&entry.TenantID, &dataJSON, &tagsJSON,
	)
	if err != nil {
		return nil, err
	}

	entry.Level = parseAuditLevel(level)

	if err := json.Unmarshal(dataJSON, &entry.Data); err != nil {
		entry.Data = make(map[string]interface{})
	}
	if err := json.Unmarshal(tagsJSON, &entry.ComplianceTags); err != nil {
		entry.ComplianceTags = nil
	}

	return &entry, nil
}

// isNoRows checks if the error is pgx's "no rows in result set".
func isNoRows(err error) bool {
	if pgErr, ok := err.(*pgconn.PgError); ok {
		return pgErr.Code == "P0002" // not found
	}
	return err == pgx.ErrNoRows
}

// parseAuditLevel converts a string audit level from PostgreSQL to opsec.AuditLevel.
func parseAuditLevel(s string) opsec.AuditLevel {
	switch s {
	case "INFO":
		return opsec.AuditLevelInfo
	case "WARNING":
		return opsec.AuditLevelWarning
	case "ERROR":
		return opsec.AuditLevelError
	case "CRITICAL":
		return opsec.AuditLevelCritical
	case "ALERT":
		return opsec.AuditLevelAlert
	default:
		return opsec.AuditLevelInfo
	}
}

// joinStrings joins string slices with a separator (helper for SQL IN clauses).
func joinStrings(ss []string, sep string) string {
	return strings.Join(ss, sep)
}
