// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — PostgreSQL RLS Tenant Context Helper
// =========================================================================
//
// tenant_rls.go provides functions to set PostgreSQL session variables
// for Row-Level Security (RLS) policies defined in migration 008.
//
// The application calls SetTenantContext before executing queries on
// tenant-scoped tables. This sets `app.tenant_id` and `app.is_admin`
// as session-local variables that the RLS policies check via
// current_setting().
//
// USAGE:
//
//	// In an HTTP handler with auth context:
//	tenantID := auth.GetTenantID(r.Context())
//	isAdmin := auth.IsAdmin(r.Context())
//	err := pgStore.SetTenantContext(ctx, tenantID, isAdmin)
//	// ... then execute queries ...
//
// IMPORTANT: SetTenantContext uses SET LOCAL, which scopes the
// variables to the current transaction. If you're not in a transaction,
// use SetTenantContextSession for session-level scope. For pooled
// connections with pool.Query/Exec (no explicit transaction), use
// WithTenantContext which acquires a connection, sets context, runs
// your function, and releases the connection.
//
// =========================================================================

package ioc

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DBQuerier is the common interface satisfied by both *pgxpool.Pool and
// pgx.Tx. It allows query methods to work with either a direct pool
// connection or a tenant-scoped transaction with RLS context set.
//
// When tenant context is available, WithTenantContextOrPool wraps queries
// in a transaction that sets SET LOCAL app.tenant_id and app.is_admin,
// causing the RLS policies from migration 008 to fire. When no tenant
// context is available, queries run directly on the pool (RLS policies
// won't fire, but application-layer filtering handles isolation).
type DBQuerier interface {
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults
}

// SetTenantContext sets the app.tenant_id and app.is_admin session
// variables on a specific connection (within a transaction). Use this
// when you have an explicit pgx.Tx and want RLS policies to apply to
// all queries within that transaction.
//
// Example:
//
//	err := pgStore.Pool().AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
//	    tx, err := conn.Begin(ctx)
//	    defer tx.Rollback(ctx)
//	    if err := ioc.SetTenantContext(ctx, tx, tenantID, isAdmin); err != nil {
//	        return err
//	    }
//	    // ... queries ...
//	    return tx.Commit(ctx)
//	})
func SetTenantContext(ctx context.Context, tx pgx.Tx, tenantID string, isAdmin bool) error {
	// PostgreSQL SET LOCAL does not support parameterized queries ($1).
	// We must use string literals. Single quotes in tenantID are escaped
	// by doubling them (standard SQL escaping).
	escapedTenant := strings.ReplaceAll(tenantID, "'", "''")
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL app.tenant_id = '%s'", escapedTenant)); err != nil {
		return fmt.Errorf("set app.tenant_id: %w", err)
	}
	isAdminStr := "false"
	if isAdmin {
		isAdminStr = "true"
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL app.is_admin = '%s'", isAdminStr)); err != nil {
		return fmt.Errorf("set app.is_admin: %w", err)
	}
	return nil
}

// WithTenantContext acquires a connection from the pool, sets the
// tenant context variables, executes the provided function within a
// transaction, and releases the connection. This is the recommended
// way to run tenant-scoped queries when using pgxpool.
//
// The function receives a pgx.Tx with tenant context already set.
// If the function returns nil, the transaction is committed; otherwise
// it is rolled back.
func WithTenantContext(ctx context.Context, pool *pgxpool.Pool, tenantID string, isAdmin bool, fn func(pgx.Tx) error) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection for tenant context: %w", err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction for tenant context: %w", err)
	}
	defer tx.Rollback(ctx) // safe to call after commit

	if err := SetTenantContext(ctx, tx, tenantID, isAdmin); err != nil {
		return err
	}

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// WithTenantContextOrPool is the primary entry point for RLS
// defense-in-depth wiring. It executes the provided function with a
// DBQuerier that has tenant RLS context set when tenant information is
// available, or directly on the pool when it is not.
//
// When tenantID is non-empty OR isAdmin is true:
//   - Acquires a connection, begins a transaction
//   - Sets SET LOCAL app.tenant_id and app.is_admin
//   - Calls fn with the transaction (RLS policies fire)
//   - Commits if fn returns nil, rolls back otherwise
//
// When tenantID is empty AND isAdmin is false:
//   - Calls fn with the pool directly (RLS policies don't fire,
//     but application-layer filtering handles isolation)
//
// This design ensures backward compatibility for single-tenant
// deployments while providing defense-in-depth for multi-tenant ones.
func WithTenantContextOrPool(ctx context.Context, pool *pgxpool.Pool, tenantID string, isAdmin bool, fn func(DBQuerier) error) error {
	if pool == nil {
		panic("pgxpool.Pool is nil")
	}
	if tenantID == "" && !isAdmin {
		// No tenant context — use pool directly. RLS policies won't
		// fire (table owner bypasses RLS anyway until FORCE is applied),
		// but application-layer filtering handles isolation.
		return fn(pool)
	}
	// Tenant context provided — wrap in transaction with RLS context.
	return WithTenantContext(ctx, pool, tenantID, isAdmin, func(tx pgx.Tx) error {
		return fn(tx)
	})
}

// SetTenantContextOnConn sets tenant context variables directly on a
// pooled connection (session-level, not transaction-level). This is
// useful when you need to run multiple independent statements with the
// same tenant context without an explicit transaction.
//
// IMPORTANT: When using session-level variables with pooled connections,
// you MUST release the connection back to the pool when done. Otherwise
// the tenant context leaks to the next user of that connection. Prefer
// WithTenantContext (transaction-scoped) unless you have a specific
// reason to use session-level.
func SetTenantContextOnConn(ctx context.Context, conn *pgxpool.Conn, tenantID string, isAdmin bool) error {
	escapedTenant := strings.ReplaceAll(tenantID, "'", "''")
	if _, err := conn.Exec(ctx, fmt.Sprintf("SET app.tenant_id = '%s'", escapedTenant)); err != nil {
		return fmt.Errorf("set app.tenant_id on conn: %w", err)
	}
	isAdminStr := "false"
	if isAdmin {
		isAdminStr = "true"
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("SET app.is_admin = '%s'", isAdminStr)); err != nil {
		return fmt.Errorf("set app.is_admin on conn: %w", err)
	}
	return nil
}

// ClearTenantContextOnConn resets the tenant context variables on a
// pooled connection before returning it to the pool. This prevents
// tenant context leakage between requests.
func ClearTenantContextOnConn(ctx context.Context, conn *pgxpool.Conn) error {
	if _, err := conn.Exec(ctx, "SET app.tenant_id = ''"); err != nil {
		return fmt.Errorf("clear app.tenant_id: %w", err)
	}
	if _, err := conn.Exec(ctx, "SET app.is_admin = 'false'"); err != nil {
		return fmt.Errorf("clear app.is_admin: %w", err)
	}
	return nil
}
