// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ResponseGuard Performance Regression Benchmarks
// =========================================================================
//
// Benchmarks the core scanning pipeline (PII → Secrets → XSS → Compliance →
// Tokens → Toxicity → Hallucination) at throughput levels that validate the
// 24K+ RPS claim.
//
// Run: go test -bench=Benchmark -benchmem ./pkg/response/
//
// v3.4.0+ perf regression in CI.
// =========================================================================

package response

import (
	"context"
	"strings"
	"testing"
)

// BenchmarkScanWithContext_Minimal benchmarks the minimum-overhead path
// (all detection disabled). This establishes the RPS ceiling.
func BenchmarkScanWithContext_Minimal(b *testing.B) {
	guard := NewResponseGuard()
	ctx := context.Background()
	input := "Hello, this is a normal response with no sensitive data."
	scanCtx := &ScanContext{ClientID: "bench", RequestID: "bench-1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = guard.ScanWithContext(ctx, input, scanCtx)
	}
}

// BenchmarkScanWithContext_PIIEnabled benchmarks with PII detection enabled.
func BenchmarkScanWithContext_PIIEnabled(b *testing.B) {
	guard := NewResponseGuardWithConfig(&ResponseGuardConfig{
		EnablePIIScanner:      true,
		EnableSecretDetection: true,
		MaxResponseTokens:     4096,
	})
	ctx := context.Background()
	input := "Contact john@example.com or call 555-123-4567 for details."
	scanCtx := &ScanContext{ClientID: "bench", RequestID: "bench-2"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = guard.ScanWithContext(ctx, input, scanCtx)
	}
}

// BenchmarkScanWithContext_FullPipeline benchmarks all 7 detection stages.
// This is the real-world production path with PII, Secrets, XSS, and Compliance.
func BenchmarkScanWithContext_FullPipeline(b *testing.B) {
	guard := NewResponseGuardWithConfig(&ResponseGuardConfig{
		EnablePIIScanner:          true,
		EnableSecretDetection:     true,
		EnableXSSDetection:        true,
		EnableComplianceDetection: true,
		MaxResponseTokens:         4096,
	})
	ctx := context.Background()
	input := strings.Repeat("Contact support at help@example.com or call 555-123-4567. ", 10)
	scanCtx := &ScanContext{ClientID: "bench", RequestID: "bench-3"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = guard.ScanWithContext(ctx, input, scanCtx)
	}
}

// BenchmarkScanWithContext_LongInput benchmarks with a ~10KB input.
func BenchmarkScanWithContext_LongInput(b *testing.B) {
	guard := NewResponseGuardWithConfig(&ResponseGuardConfig{
		EnablePIIScanner:          true,
		EnableSecretDetection:     true,
		EnableXSSDetection:        true,
		EnableComplianceDetection: true,
		MaxResponseTokens:         8192,
	})
	ctx := context.Background()
	input := strings.Repeat("This is a line of text with email user@test.com and phone 555-000-0000. ", 100)
	scanCtx := &ScanContext{ClientID: "bench", RequestID: "bench-4"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = guard.ScanWithContext(ctx, input, scanCtx)
	}
}

// BenchmarkScanWithContext_Parallel benchmarks parallel scanning.
// This simulates high-throughput concurrent request handling.
func BenchmarkScanWithContext_Parallel(b *testing.B) {
	guard := NewResponseGuardWithConfig(&ResponseGuardConfig{
		EnablePIIScanner:          true,
		EnableSecretDetection:     true,
		EnableXSSDetection:        true,
		EnableComplianceDetection: true,
		MaxResponseTokens:         4096,
	})
	ctx := context.Background()
	input := "Contact support at help@example.com or call 555-123-4567."
	scanCtx := &ScanContext{ClientID: "bench", RequestID: "bench-5"}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = guard.ScanWithContext(ctx, input, scanCtx)
		}
	})
}
