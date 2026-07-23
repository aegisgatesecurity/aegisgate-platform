// SPDX-License-Identifier: Apache-2.0
// Package testdb provides a shared test helper for spinning up ephemeral
// PostgreSQL containers during tests. It uses testcontainers-go to
// manage the container lifecycle.
//
// Usage:
//
//	pgStore, cleanup := testdb.SetupTestDB(t)
//	defer cleanup()
//	// use pgStore for integration tests
package testdb

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// SetupTestDB creates an ephemeral PostgreSQL container, runs migrations,
// and returns an *ioc.PostgresStore ready for testing.
// The caller must defer the returned cleanup function to stop the container.
func SetupTestDB(t *testing.T) (*ioc.PostgresStore, func()) {
	t.Helper()
	ctx := context.Background()

	container, dbURL := startPostgresContainer(t, ctx)
	pgStore := connectAndMigrate(t, ctx, dbURL)

	cleanup := func() {
		pgStore.Close()
		if err := container.Terminate(ctx); err != nil {
			t.Logf("warning: failed to terminate postgres container: %v", err)
		}
	}

	return pgStore, cleanup
}

// SetupTestDBPool returns just a *pgxpool.Pool for packages that
// consume the pool directly (correlation, attestation).
func SetupTestDBPool(t *testing.T) (*ioc.PostgresStore, func()) {
	return SetupTestDB(t)
}

func startPostgresContainer(t *testing.T, ctx context.Context) (testcontainers.Container, string) {
	t.Helper()

	c, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("aegisgate_test"),
		postgres.WithUsername("aegisgate"),
		postgres.WithPassword("aegisgate_test_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Skipf("testdb: could not start postgres container (Docker not available?): %v", err)
		return nil, ""
	}

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("testdb: could not get container host: %v", err)
	}

	port, err := c.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("testdb: could not get container port: %v", err)
	}

	dbURL := fmt.Sprintf("postgres://aegisgate:aegisgate_test_password@%s:%s/aegisgate_test?sslmode=disable", host, port.Port())
	return c, dbURL
}

func connectAndMigrate(t *testing.T, ctx context.Context, dbURL string) *ioc.PostgresStore {
	t.Helper()

	cfg := ioc.DefaultDatabaseConfig()
	cfg.URL = dbURL
	cfg.MaxConns = 5
	cfg.MinConns = 2

	store, err := ioc.NewPostgresStore(ctx, cfg)
	if err != nil {
		t.Fatalf("testdb: could not connect to postgres: %v", err)
	}
	return store
}
