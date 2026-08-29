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

func TestPostgresPanic_Observe_ErrorsOnNilPool(t *testing.T) {
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

	_, err := store.Observe(ctx, validIOC)
	if err == nil {
		t.Error("expected error on nil pool")
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

	_, err := store.Observe(ctx, validIOC, TenantContext{TenantID: "t1", IsAdmin: false})
	if err == nil {
		t.Error("expected error on nil pool with tenant ctx")
	}
}

func TestPostgresPanic_ObserveBatch_ErrorsOnNilPool(t *testing.T) {
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

	err := store.ObserveBatch(ctx, []IOC{validIOC})
	if err == nil {
		t.Error("expected error on nil pool")
	}
}

func TestPostgresPanic_Get_ErrorsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	_, err := store.Get(ctx, "test-fingerprint")
	if err == nil {
		t.Error("expected error on nil pool in Get")
	}
}

func TestPostgresPanic_Get_WithTenantCtx_ErrorsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	_, err := store.Get(ctx, "test-fp", TenantContext{TenantID: "t1", IsAdmin: true})
	if err == nil {
		t.Error("expected error on nil pool in Get with tenant ctx")
	}
}

func TestPostgresPanic_Size_ErrorsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	_, err := store.Size(ctx)
	if err == nil {
		t.Error("expected error on nil pool in Size")
	}
}

func TestPostgresPanic_Snapshot_ErrorsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	_, err := store.Snapshot(ctx)
	if err == nil {
		t.Error("expected error on nil pool in Snapshot")
	}
}

func TestPostgresPanic_SnapshotSince_ErrorsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	_, err := store.SnapshotSince(ctx, time.Now().Add(-time.Hour))
	if err == nil {
		t.Error("expected error on nil pool in SnapshotSince")
	}
}

func TestPostgresPanic_Query_ErrorsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	_, err := store.Query(ctx, IOCQuery{Type: IOCTypeProxyResponse})
	if err == nil {
		t.Error("expected error on nil pool in Query")
	}
}

func TestPostgresPanic_Prune_ErrorsOnNilPool(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.Background()

	_, err := store.Prune(ctx, time.Hour)
	if err == nil {
		t.Error("expected error on nil pool in Prune")
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
		t.Error("expected error on nil pool in Close")
	}
}
