// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Test Database Helpers
// =========================================================================
//
// Package testdb provides test database helpers for integration tests
// that require a running PostgreSQL instance. It is only compiled when
// the "integration" build tag is set.
//
// Usage:
//
//	//go:build integration
//	db := testdb.Setup(t)
//	defer testdb.Teardown(db)
//
// =========================================================================

package testdb
