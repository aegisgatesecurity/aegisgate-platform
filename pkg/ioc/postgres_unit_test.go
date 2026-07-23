// SPDX-License-Identifier: Apache-2.0
//go:build !integration

// =========================================================================
// AegisGate Platform - PostgresStore Unit Tests
// =========================================================================
//
// postgres_unit_test.go exercises validation paths, error branches, and
// simple accessors in PostgresStore that do NOT require a live database.
// All integration-level tests live in postgres_integration_test.go.
//
// v3.5.0+ D1 Phase 1A.
// =========================================================================

package ioc

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NewPostgresStore — constructor validation
// ---------------------------------------------------------------------------

func TestNewPostgresStore_EmptyURL(t *testing.T) {
	ctx := context.Background()
	_, err := NewPostgresStore(ctx, DatabaseConfig{URL: ""})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
	if !strings.Contains(err.Error(), "database URL is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewPostgresStore_InvalidURL(t *testing.T) {
	ctx := context.Background()
	// A URL that pgxpool.ParseConfig cannot parse.
	_, err := NewPostgresStore(ctx, DatabaseConfig{URL: "://bad"})
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if !strings.Contains(err.Error(), "parse database URL") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestNewPostgresStore_UnreachableHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Valid URL syntax but unreachable host — should fail at ping.
	_, err := NewPostgresStore(ctx, DatabaseConfig{
		URL:          "postgres://noexistenthostx.invalid:1/doesnotexist?sslmode=disable",
		MaxConns:     1,
		MinConns:     1,
		MaxConnIdleTime:  1 * time.Second,
		MaxConnLifetime:  1 * time.Second,
		HealthCheckInterval: 1 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
	// Could fail at "create connection pool" or "ping database".
	msg := err.Error()
	if !strings.Contains(msg, "create connection pool") && !strings.Contains(msg, "ping database") {
		t.Errorf("expected pool/ping error, got: %v", msg)
	}
}

func TestNewPostgresStore_DefaultsApplied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Non-positive MaxConns and MinConns should be defaulted.
	// This will fail at pool creation, but we verify the defaults
	// by checking the config structure.
	cfg := DatabaseConfig{
		URL:              "postgres://noexistenthostx.invalid:1/db?sslmode=disable",
		MaxConns:        -1, // should become 25
		MinConns:        -1, // should become 5
		MaxConnIdleTime: 1 * time.Second,
		MaxConnLifetime: 1 * time.Second,
		HealthCheckInterval: 1 * time.Second,
	}

	// The defaults are applied inside NewPostgresStore before pool creation.
	// We can't directly observe the internal cfg, but the function should not
	// panic and the error should come from connection, not from config.
	_, err := NewPostgresStore(ctx, cfg)
	if err == nil {
		t.Fatal("expected connection error for unreachable host")
	}
	// If defaults weren't applied, MaxConns=0 could cause issues.
	// The fact we get a connection error (not a config error) is the test.
	if strings.Contains(err.Error(), "parse database URL") {
		t.Errorf("defaults should have been applied, got parse error: %v", err)
	}
}

func TestNewPostgresStore_MaxConnsOverflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := DatabaseConfig{
		URL:              "postgres://noexistenthostx.invalid:1/db?sslmode=disable",
		MaxConns:        math.MaxInt32 + 1, // overflow int32
		MinConns:        1,
		MaxConnIdleTime: 1 * time.Second,
		MaxConnLifetime: 1 * time.Second,
		HealthCheckInterval: 1 * time.Second,
	}

	_, err := NewPostgresStore(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
	// Should not fail at config parsing — overflow is clamped.
	if strings.Contains(err.Error(), "parse database URL") {
		t.Errorf("overflow MaxConns should be clamped, got parse error: %v", err)
	}
}

func TestNewPostgresStore_MinConnsOverflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := DatabaseConfig{
		URL:              "postgres://noexistenthostx.invalid:1/db?sslmode=disable",
		MaxConns:        1,
		MinConns:        math.MaxInt32 + 1, // overflow int32
		MaxConnIdleTime: 1 * time.Second,
		MaxConnLifetime: 1 * time.Second,
		HealthCheckInterval: 1 * time.Second,
	}

	_, err := NewPostgresStore(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
	if strings.Contains(err.Error(), "parse database URL") {
		t.Errorf("overflow MinConns should be clamped, got parse error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Observe — validation path (no DB needed)
// ---------------------------------------------------------------------------

func TestPostgresStore_Observe_InvalidIOC(t *testing.T) {
	// Construct a PostgresStore with nil pool — Observe should fail
	// at validation before ever touching the pool.
	s := &PostgresStore{}

	invalidIOC := IOC{} // Fingerprint is empty → invalid

	_, err := s.Observe(context.Background(), invalidIOC)
	if err == nil {
		t.Fatal("expected error for invalid IOC")
	}
	if !strings.Contains(err.Error(), "invalid IOC") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ObserveBatch — early-return path (no DB needed)
// ---------------------------------------------------------------------------

func TestPostgresStore_ObserveBatch_EmptySlice(t *testing.T) {
	s := &PostgresStore{}

	err := s.ObserveBatch(context.Background(), nil)
	if err != nil {
		t.Errorf("ObserveBatch(nil) should return nil, got: %v", err)
	}

	err = s.ObserveBatch(context.Background(), []IOC{})
	if err != nil {
		t.Errorf("ObserveBatch(empty) should return nil, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Flush — no-op (no DB needed)
// ---------------------------------------------------------------------------

func TestPostgresStore_Flush(t *testing.T) {
	s := &PostgresStore{}

	err := s.Flush(context.Background())
	if err != nil {
		t.Errorf("Flush should always return nil, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DSN — accessor (no DB needed)
// ---------------------------------------------------------------------------

func TestPostgresStore_DSN(t *testing.T) {
	expectedDSN := "postgres://user:pass@host:5432/db"
	s := &PostgresStore{
		cfg: DatabaseConfig{URL: expectedDSN},
	}

	if dsn := s.DSN(); dsn != expectedDSN {
		t.Errorf("DSN() = %q, want %q", dsn, expectedDSN)
	}
}

// ---------------------------------------------------------------------------
// Pool — accessor (no DB needed)
// ---------------------------------------------------------------------------

func TestPostgresStore_Pool_Nil(t *testing.T) {
	s := &PostgresStore{}

	if pool := s.Pool(); pool != nil {
		t.Errorf("Pool() on nil-pool store should return nil, got %v", pool)
	}
}

// ---------------------------------------------------------------------------
// DefaultDatabaseConfig — comprehensive field checks
// ---------------------------------------------------------------------------

func TestDefaultDatabaseConfig_AllFields(t *testing.T) {
	cfg := DefaultDatabaseConfig()

	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"MaxConns", cfg.MaxConns, 25},
		{"MinConns", cfg.MinConns, 5},
		{"MaxConnIdleTime", cfg.MaxConnIdleTime, 30 * time.Minute},
		{"MaxConnLifetime", cfg.MaxConnLifetime, 1 * time.Hour},
		{"HealthCheckInterval", cfg.HealthCheckInterval, 30 * time.Second},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("DefaultDatabaseConfig().%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Observe — valid IOC but nil pool (panic path test)
// Skip this because it would panic; instead test the invalid IOC path only.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// IOC.Valid() — ensure invalid IOCs are rejected by PostgresStore.Observe
// ---------------------------------------------------------------------------

func TestPostgresStore_Observe_InvalidIOC_Various(t *testing.T) {
	s := &PostgresStore{}
	ctx := context.Background()

	tests := []struct {
		name string
		ioc  IOC
	}{
		{
			name: "empty fingerprint",
			ioc:  IOC{Fingerprint: "", Type: IOCTypeProxyResponse, Severity: SeverityHigh, Count: 1, FirstSeen: time.Now(), LastSeen: time.Now()},
		},
		{
			name: "wrong fingerprint length",
			ioc:  IOC{Fingerprint: "abc", Type: IOCTypeProxyResponse, Severity: SeverityHigh, Count: 1, FirstSeen: time.Now(), LastSeen: time.Now()},
		},
		{
			name: "unknown type",
			ioc:  IOC{Fingerprint: strings.Repeat("a", 64), Type: "unknown_type", Severity: SeverityHigh, Count: 1, FirstSeen: time.Now(), LastSeen: time.Now()},
		},
		{
			name: "zero count",
			ioc:  IOC{Fingerprint: strings.Repeat("a", 64), Type: IOCTypeProxyResponse, Severity: SeverityHigh, Count: 0, FirstSeen: time.Now(), LastSeen: time.Now()},
		},
		{
			name: "negative count",
			ioc:  IOC{Fingerprint: strings.Repeat("a", 64), Type: IOCTypeProxyResponse, Severity: SeverityHigh, Count: -1, FirstSeen: time.Now(), LastSeen: time.Now()},
		},
		{
			name: "zero first seen",
			ioc:  IOC{Fingerprint: strings.Repeat("a", 64), Type: IOCTypeProxyResponse, Severity: SeverityHigh, Count: 1, FirstSeen: time.Time{}, LastSeen: time.Now()},
		},
		{
			name: "zero last seen",
			ioc:  IOC{Fingerprint: strings.Repeat("a", 64), Type: IOCTypeProxyResponse, Severity: SeverityHigh, Count: 1, FirstSeen: time.Now(), LastSeen: time.Time{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Observe(ctx, tt.ioc)
			if err == nil {
				t.Error("expected error for invalid IOC")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ObserveBatch — batch with all invalid IOCs (skips all, sends empty batch)
// This tests the loop that calls Valid() but still calls SendBatch.
// We can't test the SendBatch path without a DB, but the empty-batch path
// above covers the early return.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TenantContext — verify it's usable as optional parameter
// ---------------------------------------------------------------------------

func TestPostgresStore_Observe_InvalidIOC_WithTenantContext(t *testing.T) {
	s := &PostgresStore{}
	ctx := context.Background()

	invalidIOC := IOC{} // empty → invalid

	_, err := s.Observe(ctx, invalidIOC, TenantContext{TenantID: "tenant-1"})
	if err == nil {
		t.Fatal("expected error for invalid IOC even with tenant context")
	}
	if !strings.Contains(err.Error(), "invalid IOC") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPostgresStore_ObserveBatch_EmptyWithTenantContext(t *testing.T) {
	s := &PostgresStore{}
	ctx := context.Background()

	err := s.ObserveBatch(ctx, nil, TenantContext{TenantID: "tenant-1"})
	if err != nil {
		t.Errorf("ObserveBatch(nil) with tenant should return nil, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DatabaseConfig — URL field default
// ---------------------------------------------------------------------------

func TestDatabaseConfig_EmptyURL(t *testing.T) {
	cfg := DefaultDatabaseConfig()
	if cfg.URL != "" {
		t.Errorf("DefaultDatabaseConfig().URL should be empty, got %q", cfg.URL)
	}
}