// Package scanner_test provides benchmark tests for the scanner package.
// These tests measure performance of pattern matching, request scanning,
// threat detection, and multi-pattern engine scalability.
//
// Run benchmarks with: go test -bench=. -benchmem ./pkg/scanner/...
//
//go:build !integration
// +build !integration

package scanner_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/scanner"
)

// ============================================================================
// Benchmark Helpers
// ============================================================================

// generatePayload creates a payload of specified size with realistic content
func generatePayload(size int) string {
	// Base content with some realistic patterns
	base := `{"user": "john.doe@example.com", "action": "login", "timestamp": "2024-01-15T10:30:00Z"}`

	if size <= len(base) {
		return base[:size]
	}

	// Repeat base content to reach desired size
	var sb strings.Builder
	sb.Grow(size)
	for sb.Len() < size {
		sb.WriteString(base)
	}
	return sb.String()[:size]
}

// generatePayloadWithPatterns creates a payload containing detectable patterns
func generatePayloadWithPatterns(size int, includeSensitive bool) string {
	var sb strings.Builder
	sb.Grow(size)

	for sb.Len() < size {
		sb.WriteString(`{"user": "john.doe@example.com", "action": "process", "data": "`)
		if includeSensitive {
			// Add patterns that should be detected
			sb.WriteString(`Credit card: 4532015112830366, SSN: 123-45-6789, API Key: AKIAIOSFODNN7EXAMPLE, `)
			sb.WriteString(`Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx, `)
			sb.WriteString(`password: "supersecret123", JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`)
		}
		sb.WriteString(`"}`)
	}
	return sb.String()[:size]
}

// getPatternCount returns the number of active patterns
func getPatternCount(count int) []*scanner.Pattern {
	allPatterns := scanner.DefaultPatterns()
	if count >= len(allPatterns) {
		return allPatterns
	}
	return allPatterns[:count]
}

// ============================================================================
// Benchmark 1: Pattern Matching - MITRE ATLAS pattern detection
// ============================================================================

// BenchmarkPatternMatching_1Pattern measures pattern matching with 1 active pattern
func BenchmarkPatternMatching_1Pattern(b *testing.B) {
	patterns := getPatternCount(1)
	cfg := &scanner.Config{
		Patterns:       patterns,
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
		IncludeContext: false,
	}
	sc := scanner.New(cfg)
	content := generatePayload(1024)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = findings
	}
}

// BenchmarkPatternMatching_10Patterns measures pattern matching with 10 active patterns
func BenchmarkPatternMatching_10Patterns(b *testing.B) {
	patterns := getPatternCount(10)
	cfg := &scanner.Config{
		Patterns:       patterns,
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
		IncludeContext: false,
	}
	sc := scanner.New(cfg)
	content := generatePayload(1024)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = findings
	}
}

// BenchmarkPatternMatching_100Patterns measures pattern matching with all patterns active
func BenchmarkPatternMatching_100Patterns(b *testing.B) {
	patterns := scanner.AllPatterns() // Get all patterns including extended
	cfg := &scanner.Config{
		Patterns:       patterns,
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
		IncludeContext: false,
	}
	sc := scanner.New(cfg)
	content := generatePayload(1024)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = findings
	}
}

// BenchmarkPatternMatching_TimePerMatch measures time per individual pattern match
func BenchmarkPatternMatching_TimePerMatch(b *testing.B) {
	patterns := scanner.DefaultPatterns()
	cfg := &scanner.Config{
		Patterns:       patterns,
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
		IncludeContext: false,
	}
	sc := scanner.New(cfg)
	content := generatePayloadWithPatterns(1024, true)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		// Calculate per-match metric
		if len(findings) > 0 {
			_ = len(findings)
		}
	}

	// Report findings per iteration
	b.ReportMetric(float64(len(sc.Scan(content)))/float64(b.N), "findings/op")
}

// ============================================================================
// Benchmark 2: Request Scanning - Full request body scanning
// ============================================================================

// BenchmarkRequestScanning_1KB measures scanning throughput for 1KB payloads
func BenchmarkRequestScanning_1KB(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generatePayload(1024) // 1KB

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = findings
	}

	// Report throughput in MB/sec
	b.SetBytes(int64(len(content)))
}

// BenchmarkRequestScanning_100KB measures scanning throughput for 100KB payloads
func BenchmarkRequestScanning_100KB(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generatePayload(100 * 1024) // 100KB

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = findings
	}

	b.SetBytes(int64(len(content)))
}

// BenchmarkRequestScanning_1MB measures scanning throughput for 1MB payloads
func BenchmarkRequestScanning_1MB(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generatePayload(1024 * 1024) // 1MB

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = findings
	}

	b.SetBytes(int64(len(content)))
}

// BenchmarkRequestScanning_10MB measures scanning throughput for 10MB payloads
func BenchmarkRequestScanning_10MB(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generatePayload(10 * 1024 * 1024) // 10MB

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = findings
	}

	b.SetBytes(int64(len(content)))
}

// BenchmarkRequestScanning_Concurrent measures concurrent scanning performance
func BenchmarkRequestScanning_Concurrent(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generatePayload(100 * 1024) // 100KB

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			findings := sc.Scan(content)
			_ = findings
		}
	})

	b.SetBytes(int64(len(content)))
}

// ============================================================================
// Benchmark 3: Threat Detection - End-to-end threat detection
// ============================================================================

// generateAttackPayload creates a payload with known attack patterns
func generateAttackPayload(attackType string) string {
	switch attackType {
	case "sql_injection":
		return `{"query": "SELECT * FROM users WHERE id=1 OR 1=1--", "action": "search"}`
	case "xss":
		return `{"comment": "<script>alert('XSS')</script>", "user": "attacker"}`
	case "command_injection":
		return `{"cmd": "ls -la; cat /etc/passwd", "exec": true}`
	case "path_traversal":
		return `{"file": "../../../etc/passwd", "action": "read"}`
	case "sensitive_data":
		return generatePayloadWithPatterns(512, true)
	default:
		return generatePayload(512)
	}
}

// BenchmarkThreatDetection_SQLInjection measures SQL injection detection latency
func BenchmarkThreatDetection_SQLInjection(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generateAttackPayload("sql_injection")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = sc.HasViolation(findings)
	}
}

// BenchmarkThreatDetection_XSS measures XSS detection latency
func BenchmarkThreatDetection_XSS(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generateAttackPayload("xss")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = sc.HasViolation(findings)
	}
}

// BenchmarkThreatDetection_SensitiveData measures sensitive data detection latency
func BenchmarkThreatDetection_SensitiveData(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generateAttackPayload("sensitive_data")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = sc.HasViolation(findings)
	}
}

// BenchmarkThreatDetection_EndToEnd measures full end-to-end detection with all checks
func BenchmarkThreatDetection_EndToEnd(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.AllPatterns(),
		BlockThreshold: scanner.High,
		LogFindings:    false,
		IncludeContext: true,
		ContextSize:    50,
		MaxFindings:    100,
	}
	sc := scanner.New(cfg)

	// Mix of attack payloads
	attackTypes := []string{"sql_injection", "xss", "sensitive_data"}
	payloads := make([]string, len(attackTypes))
	for i, t := range attackTypes {
		payloads[i] = generateAttackPayload(t)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, payload := range payloads {
			findings := sc.Scan(payload)
			_ = sc.ShouldBlock(findings)
			_ = sc.GetViolationSummary(findings)
		}
	}
}

// BenchmarkThreatDetection_FalsePositiveRate measures impact of false positive checking
func BenchmarkThreatDetection_FalsePositiveRate(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	// Clean payload with no actual threats
	content := generatePayload(1024)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		// Check if any findings are false positives (they shouldn't be for clean payload)
		if len(findings) > 0 {
			_ = sc.GetFindingsBySeverity(findings, scanner.Critical)
		}
	}
}

// ============================================================================
// Benchmark 4: Multi-Pattern Engine - Parallel pattern matching
// ============================================================================

// BenchmarkMultiPatternEngine_AllPatterns measures all 60+ patterns
func BenchmarkMultiPatternEngine_AllPatterns(b *testing.B) {
	patterns := scanner.AllPatterns()
	cfg := &scanner.Config{
		Patterns:       patterns,
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generatePayloadWithPatterns(2048, true)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = findings
	}

	// Report patterns checked per operation
	b.ReportMetric(float64(len(patterns)), "patterns/op")
}

// BenchmarkMultiPatternEngine_Scalability measures scalability with pattern count
func BenchmarkMultiPatternEngine_Scalability(b *testing.B) {
	patternCounts := []int{10, 20, 40, 60}
	content := generatePayloadWithPatterns(1024, true)

	for _, count := range patternCounts {
		b.Run(fmt.Sprintf("Patterns_%d", count), func(b *testing.B) {
			patterns := getPatternCount(count)
			cfg := &scanner.Config{
				Patterns:       patterns,
				BlockThreshold: scanner.Critical,
				LogFindings:    false,
			}
			sc := scanner.New(cfg)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				findings := sc.Scan(content)
				_ = findings
			}
		})
	}
}

// BenchmarkMultiPatternEngine_CategoryPII measures PII pattern category
func BenchmarkMultiPatternEngine_CategoryPII(b *testing.B) {
	allPatterns := scanner.AllPatterns()
	var piiPatterns []*scanner.Pattern
	for _, p := range allPatterns {
		if p.Category == scanner.CategoryPII {
			piiPatterns = append(piiPatterns, p)
		}
	}

	cfg := &scanner.Config{
		Patterns:       piiPatterns,
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generatePayload(1024)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		filtered := sc.GetFindingsByCategory(findings, scanner.CategoryPII)
		_ = filtered
	}
}

// BenchmarkMultiPatternEngine_CategoryCredential measures Credential pattern category
func BenchmarkMultiPatternEngine_CategoryCredential(b *testing.B) {
	allPatterns := scanner.AllPatterns()
	var credPatterns []*scanner.Pattern
	for _, p := range allPatterns {
		if p.Category == scanner.CategoryCredential {
			credPatterns = append(credPatterns, p)
		}
	}

	cfg := &scanner.Config{
		Patterns:       credPatterns,
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generatePayloadWithPatterns(1024, true)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		filtered := sc.GetFindingsByCategory(findings, scanner.CategoryCredential)
		_ = filtered
	}
}

// BenchmarkMultiPatternEngine_ContextExtraction measures overhead of context extraction
func BenchmarkMultiPatternEngine_ContextExtraction(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.DefaultPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
		IncludeContext: true,
		ContextSize:    50,
	}
	sc := scanner.New(cfg)
	content := generatePayloadWithPatterns(1024, true)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.ScanWithContext(content)
		_ = findings
	}
}

// BenchmarkMultiPatternEngine_MaxFindingsLimit measures impact of findings limit
func BenchmarkMultiPatternEngine_MaxFindingsLimit(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.AllPatterns(),
		BlockThreshold: scanner.Info,
		LogFindings:    false,
		MaxFindings:    10, // Limit to 10 findings
	}
	sc := scanner.New(cfg)
	// Payload with many potential matches
	content := strings.Repeat(generatePayloadWithPatterns(100, true), 20)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		findings := sc.Scan(content)
		_ = len(findings)
	}
}

// BenchmarkMultiPatternEngine_ParallelScanning measures parallel pattern engine
func BenchmarkMultiPatternEngine_ParallelScanning(b *testing.B) {
	cfg := &scanner.Config{
		Patterns:       scanner.AllPatterns(),
		BlockThreshold: scanner.Critical,
		LogFindings:    false,
	}
	sc := scanner.New(cfg)
	content := generatePayloadWithPatterns(1024, true)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			findings := sc.Scan(content)
			_ = findings
		}
	})
}

// BenchmarkMultiPatternEngine_Bottleneck_Identification identifies bottlenecks
func BenchmarkMultiPatternEngine_Bottleneck_Identification(b *testing.B) {
	allPatterns := scanner.AllPatterns()
	content := generatePayloadWithPatterns(4096, true)

	// Test each pattern individually to identify slow patterns
	for i, pattern := range allPatterns {
		b.Run(fmt.Sprintf("Pattern_%d_%s", i, pattern.Name), func(b *testing.B) {
			cfg := &scanner.Config{
				Patterns:    []*scanner.Pattern{pattern},
				LogFindings: false,
			}
			sc := scanner.New(cfg)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				findings := sc.Scan(content)
				_ = findings
			}
		})
	}
}
