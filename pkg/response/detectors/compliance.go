// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Compliance Detection
// =========================================================================
//
// Compliance detection is now delegated to the upstream scanner package
// which serves as the single source of truth for detection patterns.
//
// All 35 compliance patterns (OWASP LLM Top 10, MITRE ATLAS, EU AI Act,
// GDPR/ANP, consumer protection, regulatory framework references, and
// toxicity regex fallback) are in the scanner under CategoryCompliance.
//
// Lens parity: compliance.js v0.2.0 (35 patterns).
// =========================================================================

package detectors

// CompliancePatterns is retained as an empty slice for backward
// compatibility. The actual 35 patterns now live in the upstream
// scanner under CategoryCompliance.
//
// Deprecated: Use scanner.DefaultPatterns() filtered by
// CategoryCompliance instead. This slice will be removed in a
// future release.
var CompliancePatterns = []PatternDef{}

// CompiledCompliancePatterns is retained as nil for backward
// compatibility. Patterns are compiled in the upstream scanner.
//
// Deprecated: Use the upstream scanner package directly.
var CompiledCompliancePatterns []compiledPattern

func init() {
	// No-op: patterns are now compiled in the upstream scanner.
	// Kept for backward compatibility with any code that references
	// CompiledCompliancePatterns.
}

// DetectCompliance scans text for all compliance patterns and returns
// matches. Delegates to the upstream scanner (CategoryCompliance).
func DetectCompliance(text string) []Match {
	return detectViaScanner(text, complianceScanner)
}
