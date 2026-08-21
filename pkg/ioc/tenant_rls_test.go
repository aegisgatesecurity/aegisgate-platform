// SPDX-License-Identifier: Apache-2.0

package ioc

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestSetTenantContextNilTx verifies SetTenantContext does not silently
// succeed with a nil transaction. Full integration tests require a
// live PostgreSQL instance with migration 008 applied.
func TestSetTenantContextNilTx(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("SetTenantContext with nil tx should panic, not silently succeed")
		}
	}()
	_ = SetTenantContext(context.Background(), nil, "test-tenant", false)
}

// TestWithTenantContextNilPool verifies WithTenantContext does not
// silently succeed with a nil pool.
func TestWithTenantContextNilPool(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("WithTenantContext with nil pool should panic, not silently succeed")
		}
	}()
	_ = WithTenantContext(context.Background(), nil, "test-tenant", false, func(pgx.Tx) error {
		return nil
	})
}
