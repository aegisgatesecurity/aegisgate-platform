// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ D1 PostgreSQL)
// =========================================================================
//
// store_interface_test.go tests the StoreInterface contract, the StoreAdapter
// (which wraps the in-memory Store), and IOCQuery filtering. These tests
// run without PostgreSQL — they exercise the in-memory path exclusively.
//
// v3.5.0+ D1 Phase 1A.
// =========================================================================

package ioc

import (
	"context"
	"testing"
	"time"
)

// Valid 64-char hex fingerprints for testing.
const (
	fp1 = "3f5851617f36fea315c859432f5568ff32b893f53373d7a10de45a59228d3bc9"
	fp2 = "ed1e1dcf971990c1b89676ae785436106f7548b1ae41d174ca9d3bfb9661a477"
	fp3 = "2a8c9f051e91be1d0f801980a9e87f8495582668d966b633bfde5d8a93d0e049"
	fp4 = "e063cdf36f817a24e97839b0799c023644dd1c31c668bda6481869027035a655"
)

func newTestIOC(fp string, iocType IOCType, severity Severity) IOC {
	return IOC{
		Fingerprint:    fp,
		Type:           iocType,
		Severity:       severity,
		Count:          1,
		FirstSeen:      time.Now().UTC().Add(-time.Hour),
		LastSeen:       time.Now().UTC(),
		Source:         "test",
		AffectsGateway: true, // Non-Lens IOCs affect Gateway by default
	}
}

func newTestLensIOC(fp string, iocType IOCType, severity Severity, category string, provider string) IOC {
	ioc := newTestIOC(fp, iocType, severity)
	ioc.Category = category
	ioc.SourceProvider = provider
	ioc.AffectsLens = true
	ioc.AffectsGateway = false
	ioc.Pattern = "test_pattern"
	return ioc
}

func newAdapter(t *testing.T) *StoreAdapter {
	t.Helper()
	store, err := NewStore(StoreConfig{Capacity: 1000})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return NewStoreAdapter(store)
}

func TestStoreInterface_AdapterObserve(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	result, err := a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if result.Fingerprint != fp1 {
		t.Errorf("Expected fingerprint %s, got %s", fp1, result.Fingerprint)
	}
	if result.Count != 1 {
		t.Errorf("Expected count 1, got %d", result.Count)
	}

	// Observe again — count should increment.
	result2, err := a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))
	if err != nil {
		t.Fatalf("Observe again: %v", err)
	}
	if result2.Count != 2 {
		t.Errorf("Expected count 2, got %d", result2.Count)
	}
}

func TestStoreInterface_AdapterObserveBatch(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	iocs := []IOC{
		newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh),
		newTestIOC(fp2, IOCTypePromptInjection, SeverityCritical),
		newTestIOC(fp3, IOCTypeSecretLeak, SeverityMedium),
	}
	if err := a.ObserveBatch(ctx, iocs); err != nil {
		t.Fatalf("ObserveBatch: %v", err)
	}

	size, err := a.Size(ctx)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != 3 {
		t.Errorf("Expected size 3, got %d", size)
	}
}

func TestStoreInterface_AdapterObserveBatchEmpty(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	if err := a.ObserveBatch(ctx, nil); err != nil {
		t.Errorf("ObserveBatch(nil) should not error, got: %v", err)
	}
	if err := a.ObserveBatch(ctx, []IOC{}); err != nil {
		t.Errorf("ObserveBatch(empty) should not error, got: %v", err)
	}
}

func TestStoreInterface_AdapterGet(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))

	result, err := a.Get(ctx, fp1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if result == nil {
		t.Fatal("Expected IOC, got nil")
	}
	if result.Fingerprint != fp1 {
		t.Errorf("Expected fingerprint %s, got %s", fp1, result.Fingerprint)
	}

	// Non-existent fingerprint.
	missing, err := a.Get(ctx, "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Get missing: %v", err)
	}
	if missing != nil {
		t.Error("Expected nil for missing fingerprint")
	}
}

func TestStoreInterface_AdapterSize(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	size, err := a.Size(ctx)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != 0 {
		t.Errorf("Expected size 0, got %d", size)
	}

	a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))
	size, _ = a.Size(ctx)
	if size != 1 {
		t.Errorf("Expected size 1, got %d", size)
	}
}

func TestStoreInterface_AdapterSnapshot(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	snap, err := a.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) != 0 {
		t.Errorf("Expected empty snapshot, got %d items", len(snap))
	}

	a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))
	a.Observe(ctx, newTestIOC(fp2, IOCTypePromptInjection, SeverityCritical))

	snap, err = a.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) != 2 {
		t.Errorf("Expected 2 items, got %d", len(snap))
	}
}

func TestStoreInterface_AdapterSnapshotSince(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	since := time.Now().UTC().Add(-time.Hour)
	snap, err := a.SnapshotSince(ctx, since)
	if err != nil {
		t.Fatalf("SnapshotSince: %v", err)
	}
	if len(snap) != 0 {
		t.Errorf("Expected empty, got %d", len(snap))
	}

	a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))

	snap, err = a.SnapshotSince(ctx, since)
	if err != nil {
		t.Fatalf("SnapshotSince: %v", err)
	}
	if len(snap) != 1 {
		t.Errorf("Expected 1 item since %v, got %d", since, len(snap))
	}
}

func TestStoreInterface_AdapterQuery(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))
	a.Observe(ctx, newTestIOC(fp2, IOCTypePromptInjection, SeverityCritical))
	a.Observe(ctx, newTestIOC(fp3, IOCTypeSecretLeak, SeverityMedium))
	a.Observe(ctx, newTestLensIOC(fp4, IOCTypePIIDetected, SeverityLow, "pii_email", "chatgpt"))

	// Query by type.
	results, err := a.Query(ctx, IOCQuery{Type: IOCTypePromptInjection})
	if err != nil {
		t.Fatalf("Query by type: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 prompt_injection, got %d", len(results))
	}

	// Query by severity min.
	results, err = a.Query(ctx, IOCQuery{SeverityMin: SeverityHigh})
	if err != nil {
		t.Fatalf("Query by severity: %v", err)
	}
	if len(results) < 2 {
		t.Errorf("Expected at least 2 with severity >= high, got %d", len(results))
	}

	// Query by category.
	results, err = a.Query(ctx, IOCQuery{Category: "pii_email"})
	if err != nil {
		t.Fatalf("Query by category: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 pii_email, got %d", len(results))
	}

	// Query by source provider.
	results, err = a.Query(ctx, IOCQuery{SourceProvider: "chatgpt"})
	if err != nil {
		t.Fatalf("Query by provider: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 chatgpt, got %d", len(results))
	}

	// Query by affects_lens.
	affectsLens := true
	results, err = a.Query(ctx, IOCQuery{AffectsLens: &affectsLens})
	if err != nil {
		t.Fatalf("Query by affects_lens: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 affects_lens=true, got %d", len(results))
	}

	// Query by affects_gateway.
	affectsGateway := true
	results, err = a.Query(ctx, IOCQuery{AffectsGateway: &affectsGateway})
	if err != nil {
		t.Fatalf("Query by affects_gateway: %v", err)
	}
	if len(results) < 3 {
		t.Errorf("Expected at least 3 affects_gateway=true, got %d", len(results))
	}

	// Query with limit.
	results, err = a.Query(ctx, IOCQuery{Limit: 2})
	if err != nil {
		t.Fatalf("Query with limit: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 results with limit, got %d", len(results))
	}

	// Empty query — returns all.
	results, err = a.Query(ctx, IOCQuery{})
	if err != nil {
		t.Fatalf("Query all: %v", err)
	}
	if len(results) != 4 {
		t.Errorf("Expected 4 results for empty query, got %d", len(results))
	}
}

func TestStoreInterface_AdapterPrune(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))

	pruned, err := a.Prune(ctx, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 1 {
		t.Errorf("Expected 1 pruned, got %d", pruned)
	}

	size, _ := a.Size(ctx)
	if size != 0 {
		t.Errorf("Expected size 0 after prune, got %d", size)
	}
}

func TestStoreInterface_AdapterFlush(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	if err := a.Flush(ctx); err != nil {
		t.Errorf("Flush should not error without DiskPath: %v", err)
	}
}

func TestStoreInterface_AdapterClose(t *testing.T) {
	a := newAdapter(t)

	if err := a.Close(); err != nil {
		t.Errorf("Close should not error: %v", err)
	}
}

func TestStoreInterface_AdapterObserveInvalid(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	ioc := IOC{Fingerprint: "", Type: IOCTypeProxyResponse, Severity: SeverityHigh, Count: 1}
	_, err := a.Observe(ctx, ioc)
	if err == nil {
		t.Error("Expected error for invalid IOC")
	}
}

func TestStoreInterface_AdapterObserveBatchWithInvalid(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	iocs := []IOC{
		{Fingerprint: "", Type: IOCTypeProxyResponse, Severity: SeverityHigh, Count: 1},
		newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh),
	}
	if err := a.ObserveBatch(ctx, iocs); err == nil {
		t.Error("Expected error for invalid IOC in batch")
	}
}

func TestStoreInterface_AdapterQueryOffsetBeyondResults(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))

	results, err := a.Query(ctx, IOCQuery{Offset: 100})
	if err != nil {
		t.Fatalf("Query with large offset: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 results with offset beyond data, got %d", len(results))
	}
}

func TestStoreInterface_AdapterQueryWithSince(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	a.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))

	// Since the beginning of time.
	results, err := a.Query(ctx, IOCQuery{Since: time.Time{}})
	if err != nil {
		t.Fatalf("Query with zero since: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}

	// Since the future.
	results, err = a.Query(ctx, IOCQuery{Since: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatalf("Query with future since: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

func TestStoreInterface_PostgresStoreNewWithoutURL(t *testing.T) {
	ctx := context.Background()
	_, err := NewPostgresStore(ctx, DatabaseConfig{URL: ""})
	if err == nil {
		t.Error("Expected error when URL is empty")
	}
}

func TestStoreInterface_DefaultDatabaseConfig(t *testing.T) {
	cfg := DefaultDatabaseConfig()
	if cfg.MaxConns != 25 {
		t.Errorf("Expected MaxConns 25, got %d", cfg.MaxConns)
	}
	if cfg.MinConns != 5 {
		t.Errorf("Expected MinConns 5, got %d", cfg.MinConns)
	}
	if cfg.MaxConnIdleTime != 30*time.Minute {
		t.Errorf("Expected MaxConnIdleTime 30m, got %v", cfg.MaxConnIdleTime)
	}
	if cfg.MaxConnLifetime != 1*time.Hour {
		t.Errorf("Expected MaxConnLifetime 1h, got %v", cfg.MaxConnLifetime)
	}
	if cfg.HealthCheckInterval != 30*time.Second {
		t.Errorf("Expected HealthCheckInterval 30s, got %v", cfg.HealthCheckInterval)
	}
}

func TestStoreInterface_AdapterQueryCombineFilters(t *testing.T) {
	a := newAdapter(t)
	ctx := context.Background()

	affectsLens := true
	a.Observe(ctx, newTestLensIOC(fp1, IOCTypePIIDetected, SeverityHigh, "pii_email", "chatgpt"))
	a.Observe(ctx, newTestLensIOC(fp2, IOCTypePIIDetected, SeverityMedium, "pii_phone", "claude"))
	a.Observe(ctx, newTestIOC(fp3, IOCTypeProxyResponse, SeverityCritical))

	// Combine type + affects_lens.
	results, err := a.Query(ctx, IOCQuery{Type: IOCTypePIIDetected, AffectsLens: &affectsLens})
	if err != nil {
		t.Fatalf("Query combine: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Expected 2 pii_detected + affects_lens, got %d", len(results))
	}

	// Combine severity min + source provider.
	results, err = a.Query(ctx, IOCQuery{SeverityMin: SeverityHigh, SourceProvider: "chatgpt"})
	if err != nil {
		t.Fatalf("Query severity+provider: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 high+chatgpt, got %d", len(results))
	}
}

func TestStoreInterface_AdapterFlushWithDiskPath(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewStore(StoreConfig{Capacity: 1000, DiskPath: tmpDir + "/ioc_store.json"})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	adapter := NewStoreAdapter(store)
	ctx := context.Background()

	adapter.Observe(ctx, newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh))

	if err := adapter.Flush(ctx); err != nil {
		t.Errorf("Flush with DiskPath should not error: %v", err)
	}

	adapter.Close()
}

func TestStoreInterface_IOCQueryFilterMatch(t *testing.T) {
	ioc := newTestIOC(fp1, IOCTypeProxyResponse, SeverityHigh)

	// Type match.
	if !matchFilter(ioc, IOCQuery{Type: IOCTypeProxyResponse}) {
		t.Error("Expected type match")
	}
	if matchFilter(ioc, IOCQuery{Type: IOCTypePromptInjection}) {
		t.Error("Expected type mismatch")
	}

	// Severity min match.
	if !matchFilter(ioc, IOCQuery{SeverityMin: SeverityHigh}) {
		t.Error("Expected severity min match")
	}
	if matchFilter(ioc, IOCQuery{SeverityMin: SeverityCritical}) {
		t.Error("Expected severity min mismatch")
	}

	// Empty filter matches everything.
	if !matchFilter(ioc, IOCQuery{}) {
		t.Error("Empty filter should match everything")
	}
}
