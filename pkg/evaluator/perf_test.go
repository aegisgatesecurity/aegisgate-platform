// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Evaluator Performance Benchmarks

package evaluator

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

func BenchmarkRunnerCreation(b *testing.B) {
	scanner := &perfMockScanner{}
	kr := mustPerfKeyRing(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runner, err := NewBenchmarkRunner(scanner, kr)
		if err != nil {
			b.Fatalf("NewBenchmarkRunner: %v", err)
		}
		_ = runner
	}
}

func BenchmarkCorpusLookup(b *testing.B) {
	corpus := DefaultCorpus()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		patterns := corpus.Patterns
		_ = patterns
	}
}

func BenchmarkCorpusFilterByIDs(b *testing.B) {
	corpus := DefaultCorpus()
	ids := []string{"SCRT-secret_aws_key-pos-001", "XSS-reflected-neg-002"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		corpus.Filter(ids)
	}
}

func BenchmarkDefaultCorpusLoad(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DefaultCorpus()
	}
}

func mustPerfKeyRing(b *testing.B) *ioc.KeyRing {
	tmpDir := b.TempDir()
	kr, err := ioc.LoadKeyRing(filepath.Join(tmpDir, "kr.json"))
	if err != nil {
		b.Fatalf("ioc.LoadKeyRing: %v", err)
	}
	if _, err := kr.Rotate(); err != nil {
		b.Fatalf("kr.Rotate: %v", err)
	}
	return kr
}

type perfMockScanner struct{}

func (m *perfMockScanner) Scan(_ context.Context, record SXCRecord) (*BenchmarkDetection, error) {
	return &BenchmarkDetection{
		Detected:     record.ExpectedLabel > 0,
		LatencyMillis: 1,
	}, nil
}

func (m *perfMockScanner) Name() string { return "perf-mock" }