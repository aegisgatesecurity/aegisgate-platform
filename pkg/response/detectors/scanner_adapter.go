// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Scanner Adapter
// =========================================================================
//
// This file bridges the upstream scanner package (single source of truth
// for detection patterns) with the detectors package API used by guard.go.
//
// The upstream scanner (github.com/aegisgatesecurity/aegisgate/pkg/scanner)
// contains 200 pre-compiled patterns across 8 categories. The detectors
// package wraps the scanner to maintain backward-compatible types (Match,
// Severity) while eliminating duplicate pattern definitions.
//
// Only DetectXSS() and DetectCompliance() are called in production (by
// guard.go). The remaining detector functions (DetectSecrets, DetectPII*,
// DetectOTProtocols) are retained for test compatibility but are
// deprecated in favor of the scanner package directly.
//
// =========================================================================

package detectors

import (
	"regexp"
	"sort"

	scannerpkg "github.com/aegisgatesecurity/aegisgate/pkg/scanner"
)

// xssScanner is a scanner configured with only CategoryXSS patterns
// (11 patterns). This avoids scanning all 200 patterns when we only
// need XSS detection.
var xssScanner = newCategoryScanner(scannerpkg.CategoryXSS)

// complianceScanner is a scanner configured with only CategoryCompliance
// patterns (35 patterns). This avoids scanning all 200 patterns when we
// only need compliance detection.
var complianceScanner = newCategoryScanner(scannerpkg.CategoryCompliance)

// newCategoryScanner creates a scanner containing only patterns from
// the specified category. This is more efficient than scanning all 200
// patterns and filtering.
func newCategoryScanner(category scannerpkg.Category) *scannerpkg.Scanner {
	var patterns []*scannerpkg.Pattern
	for _, p := range scannerpkg.DefaultPatterns() {
		if p != nil && p.Category == category {
			patterns = append(patterns, p)
		}
	}
	return scannerpkg.New(&scannerpkg.Config{
		Patterns:       patterns,
		BlockThreshold: scannerpkg.Critical,
		LogFindings:    false, // disable logging in detector path
		MaxFindings:    100,
	})
}

// xssPolyglotPattern is the one XSS pattern that could not be ported to
// the upstream scanner due to Go's backtick string limitation. It is
// compiled here as a supplemental pattern checked alongside scanner
// results. The regex uses string concatenation to include backtick chars.
var xssPolyglotPattern = regexp.MustCompile(`(?:alert|eval|prompt|confirm|document\.write)\s*\(\s*[` + "`" + `'"'][^` + "`" + `'"']{0,200}?\$\{[^}]{0,100}?\}[^` + "`" + `'"']*[` + "`" + `'"']\s*\)`)

// scannerSeverityToDetectors converts a scanner.Severity (int) to a
// detectors.Severity (string).
func scannerSeverityToDetectors(s scannerpkg.Severity) Severity {
	switch s {
	case scannerpkg.Critical:
		return SeverityCritical
	case scannerpkg.High:
		return SeverityHigh
	case scannerpkg.Medium:
		return SeverityMedium
	case scannerpkg.Low:
		return SeverityLow
	default:
		return SeverityLow
	}
}

// findingsToMatches converts scanner findings to detector matches, sorted
// by index (mirroring the original detectWithPatterns behavior).
func findingsToMatches(findings []scannerpkg.Finding) []Match {
	if len(findings) == 0 {
		return nil
	}

	matches := make([]Match, len(findings))
	for i, f := range findings {
		value := f.Match
		if len(value) > 200 {
			value = value[:200] + "..."
		}
		matches[i] = Match{
			Category:   f.Pattern.Name,
			Severity:   scannerSeverityToDetectors(f.Pattern.Severity),
			Confidence: 1.0,
			Value:      value,
			Index:      f.Position,
			End:        f.Position + len(f.Match),
		}
	}

	// Sort by index (mirrors original detectWithPatterns behavior)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Index < matches[j].Index
	})

	return matches
}

// detectViaScanner scans text using the given category-specific scanner
// and returns findings as detector matches.
func detectViaScanner(text string, s *scannerpkg.Scanner) []Match {
	if len(text) == 0 || s == nil {
		return nil
	}

	findings := s.Scan(text)
	return findingsToMatches(findings)
}

// detectXSSPolyglot checks for the xss_polyglot pattern that is not in
// the upstream scanner (backtick string limitation). Returns matches
// in the same format as detectWithPatterns.
func detectXSSPolyglot(text string) []Match {
	if len(text) == 0 {
		return nil
	}

	var matches []Match
	indices := xssPolyglotPattern.FindAllStringIndex(text, -1)
	for _, idx := range indices {
		value := text[idx[0]:idx[1]]
		if len(value) > 200 {
			value = value[:200] + "..."
		}
		matches = append(matches, Match{
			Category:   "xss_polyglot",
			Severity:   SeverityHigh,
			Confidence: 1.0,
			Value:      value,
			Index:      idx[0],
			End:        idx[1],
		})
	}
	return matches
}
