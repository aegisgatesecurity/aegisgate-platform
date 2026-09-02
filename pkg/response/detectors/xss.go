// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - XSS Detection
// =========================================================================
//
// XSS detection is now delegated to the upstream scanner package which
// serves as the single source of truth for detection patterns.
//
// 11 of 12 XSS patterns are in the scanner (CategoryXSS). The 12th
// pattern (xss_polyglot) cannot be expressed in the scanner due to
// Go's backtick string limitation, so it is compiled separately in
// scanner_adapter.go as a supplemental check.
//
// Lens parity: source_xss.js v0.2.0 (12 patterns total).
// =========================================================================

package detectors

import (
	"sort"
)

// XSSPatterns is retained for backward compatibility with tests that
// reference the pattern count. The actual patterns now live in the
// upstream scanner. This slice contains only the supplemental
// xss_polyglot pattern; the remaining 11 are in the scanner.
//
// Deprecated: Use scanner.DefaultPatterns() filtered by CategoryXSS
// instead. This slice will be removed in a future release.
var XSSPatterns = []PatternDef{
	{
		Name:        "xss_polyglot",
		Severity:    SeverityHigh,
		Regex:       `(?:alert|eval|prompt|confirm|document\.write)\s*\(\s*['"` + "`" + `'][^'"` + "`" + `']{0,200}?\$\{[^}]{0,100}?\}[^'"` + "`" + `']*['"` + "`" + `']\s*\)`,
		Description: "Polyglot XSS (multi-context payload) — supplemental to scanner",
	},
}

// CompiledXSSPatterns holds the supplemental XSS regex pattern(s) not
// in the upstream scanner. The 11 primary XSS patterns are compiled
// in the scanner package.
var CompiledXSSPatterns []compiledPattern

func init() {
	CompiledXSSPatterns = compilePatterns(XSSPatterns)
}

// DetectXSS scans text for all XSS patterns and returns matches.
// It combines results from the upstream scanner (11 patterns) with
// the supplemental xss_polyglot pattern (1 pattern) for a total of
// 12 patterns — matching Lens parity.
func DetectXSS(text string) []Match {
	// Get scanner findings for CategoryXSS (11 patterns)
	scannerMatches := detectViaScanner(text, xssScanner)

	// Get supplemental polyglot matches (1 pattern not in scanner)
	polyglotMatches := detectXSSPolyglot(text)

	// Combine and sort by index
	all := append(scannerMatches, polyglotMatches...)
	sortMatchesByIndex(all)

	return all
}

// sortMatchesByIndex sorts matches by their byte offset, matching
// the behavior of the original detectWithPatterns function.
func sortMatchesByIndex(matches []Match) {
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Index < matches[j].Index
	})
}
