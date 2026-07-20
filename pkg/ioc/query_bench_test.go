// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - IOC Store Query Performance Benchmarks
// =========================================================================
//
// Benchmarks the O(1) indexed Query vs O(n) Snapshot scan for the
// /api/v1/lens/check endpoint performance (Phase 5).
//
// Run: go test -bench=Benchmark -benchmem ./pkg/ioc/
// =========================================================================

package ioc

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkQueryBySourceProvider benchmarks the indexed Query method
// (O(k) where k = IOCs for that provider, typically 10-100).
func BenchmarkQueryBySourceProvider(b *testing.B) {
	dir := b.TempDir()
	store, err := NewStore(StoreConfig{
		Capacity:      100000,
		FlushInterval: 1 * time.Hour,
		DiskPath:      filepath.Join(dir, "ioc.json"),
	})
	if err != nil {
		b.Fatal(err)
	}

	// Seed 10,000 IOCs across 10 providers.
	providers := []string{"chatgpt", "claude", "gemini", "copilot", "perplexity",
		"deepseek", "mistral", "grok", "huggingface", "groq"}
	for i := 0; i < 10000; i++ {
		provider := providers[i%len(providers)]
		cat := "pii_email"
		if i%3 == 0 {
			cat = "secret_api_key_generic"
		}
		ioc := IOC{
			Fingerprint:    fmt.Sprintf("%064d", i),
			Type:           IOCTypePIIDetected,
			Severity:       SeverityHigh,
			Category:       cat,
			SourceProvider: provider,
			AffectsLens:    true,
			AffectsGateway: false,
			Source:         "lens",
			Count:          1,
			FirstSeen:      time.Now().UTC(),
			LastSeen:       time.Now().UTC(),
		}
		if _, err := store.Observe(ioc); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results := store.Query(IOCQuery{SourceProvider: "chatgpt"})
		_ = results
	}
}

// BenchmarkSnapshotFullScan benchmarks the old approach (Snapshot()
// returns all 10,000 IOCs, then filter in the handler).
func BenchmarkSnapshotFullScan(b *testing.B) {
	dir := b.TempDir()
	store, err := NewStore(StoreConfig{
		Capacity:      100000,
		FlushInterval: 1 * time.Hour,
		DiskPath:      filepath.Join(dir, "ioc.json"),
	})
	if err != nil {
		b.Fatal(err)
	}

	providers := []string{"chatgpt", "claude", "gemini", "copilot", "perplexity",
		"deepseek", "mistral", "grok", "huggingface", "groq"}
	for i := 0; i < 10000; i++ {
		provider := providers[i%len(providers)]
		cat := "pii_email"
		if i%3 == 0 {
			cat = "secret_api_key_generic"
		}
		ioc := IOC{
			Fingerprint:    fmt.Sprintf("%064d", i),
			Type:           IOCTypePIIDetected,
			Severity:       SeverityHigh,
			Category:       cat,
			SourceProvider: provider,
			AffectsLens:    true,
			AffectsGateway: false,
			Source:         "lens",
			Count:          1,
			FirstSeen:      time.Now().UTC(),
			LastSeen:       time.Now().UTC(),
		}
		if _, err := store.Observe(ioc); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		all := store.Snapshot()
		_ = all
	}
}
