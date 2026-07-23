// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - IOC PostgreSQL Store Panic-Recovery Unit Tests
//
// Tests pool-call paths via panic recovery and input validation.
//go:build !integration

package ioc

import (
	"context"
	"testing"
	"time"
)

// --------------------------------------------------------------------
// Input validation (no pool needed)
// --------------------------------------------------------------------

func TestPostgresPanic_Observe_InvalidIOC(t *testing.T) {
	// Create a PostgresStore with nil internals to test validation
	store := &PostgresStore{}
	ctx := context.Background()

	// An empty IOC should fail Valid() check
	invalidIOC := IOC{}
	result, err := store.Observe(ctx, invalidIOC)
	if err == nil {
		t.Fatal("expected error for invalid IOC")
	}
	if result != nil {
		t.Fatal("expected nil result for invalid IOC")
	}
}

func TestPostgresPanic_ObserveBatch_EmptySlice(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	err := store.ObserveBatch(ctx, []IOC{})
	if err != nil {
		t.Fatalf("expected nil for empty batch, got: %v", err)
	}
}

// --------------------------------------------------------------------
// Panic-recovery tests (exercise code paths up to pool access)
// --------------------------------------------------------------------

func TestPostgresPanic_Observe_PanicsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	// Need 64-char fingerprint for Valid() check
	validIOC := IOC{
		Fingerprint:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Type:           IOCTypeProxyResponse,
		Severity:       SeverityLow,
		Category:       "threat",
		Pattern:        "test-pattern",
		SourceProvider: "test",
		AffectsLens:    true,
		AffectsGateway: false,
		Source:         "test",
		Count:          1,
		FirstSeen:      time.Now(),
		LastSeen:       time.Now(),
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Observe(ctx, validIOC)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool")
	}
}

func TestPostgresPanic_Observe_WithTenantCtx(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	validIOC := IOC{
		Fingerprint:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Type:           IOCTypeProxyResponse,
		Severity:       SeverityLow,
		Category:       "threat",
		SourceProvider: "test",
		AffectsLens:    true,
		Count:          1,
		FirstSeen:      time.Now(),
		LastSeen:       time.Now(),
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Observe(ctx, validIOC, TenantContext{TenantID: "t1", IsAdmin: false})
	}()
	if !didPanic {
		t.Error("expected panic on nil pool with tenant ctx")
	}
}

func TestPostgresPanic_ObserveBatch_PanicsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	validIOC := IOC{
		Fingerprint:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Type:           IOCTypeProxyResponse,
		Severity:       SeverityMedium,
		Category:       "test",
		SourceProvider: "test",
		AffectsLens:    true,
		FirstSeen:      time.Now(),
		LastSeen:       time.Now(),
	}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = store.ObserveBatch(ctx, []IOC{validIOC})
	}()
	if !didPanic {
		t.Error("expected panic on nil pool")
	}
}

func TestPostgresPanic_Get_PanicsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Get(ctx, "test-fingerprint")
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Get")
	}
}

func TestPostgresPanic_Get_WithTenantCtx(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Get(ctx, "test-fp", TenantContext{TenantID: "t1", IsAdmin: true})
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Get with tenant ctx")
	}
}

func TestPostgresPanic_Size_PanicsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Size(ctx)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Size")
	}
}

func TestPostgresPanic_Snapshot_PanicsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Snapshot(ctx)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Snapshot")
	}
}

func TestPostgresPanic_SnapshotSince_PanicsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.SnapshotSince(ctx, time.Now().Add(-time.Hour))
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in SnapshotSince")
	}
}

func TestPostgresPanic_Query_PanicsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Query(ctx, IOCQuery{Type: IOCTypeProxyResponse})
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Query")
	}
}

func TestPostgresPanic_Prune_PanicsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, _ = store.Prune(ctx, time.Hour)
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Prune")
	}
}

func TestPostgresPanic_Close_PanicsOnNilPool(t *testing.T) {
	store := &PostgresStore{}

	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_ = store.Close()
	}()
	if !didPanic {
		t.Error("expected panic on nil pool in Close")
	}
}
