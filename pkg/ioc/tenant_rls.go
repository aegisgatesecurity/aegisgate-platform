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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
	if _, err := tx.Exec(ctx, "SET LOCAL app.tenant_id = $1", tenantID); err != nil {
		return fmt.Errorf("set app.tenant_id: %w", err)
	}
	isAdminStr := "false"
	if isAdmin {
		isAdminStr = "true"
	}
	if _, err := tx.Exec(ctx, "SET LOCAL app.is_admin = $1", isAdminStr); err != nil {
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
	if _, err := conn.Exec(ctx, "SET app.tenant_id = $1", tenantID); err != nil {
		return fmt.Errorf("set app.tenant_id on conn: %w", err)
	}
	isAdminStr := "false"
	if isAdmin {
		isAdminStr = "true"
	}
	if _, err := conn.Exec(ctx, "SET app.is_admin = $1", isAdminStr); err != nil {
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
