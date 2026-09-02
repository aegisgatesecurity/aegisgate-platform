// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Detector Engine
// =========================================================================
//
// Shared detection engine that compiles PatternDef slices into regexp.Regexp
// and scans text for matches. This is the core runtime that all 8 detector
// packages use.
// =========================================================================

package detectors

import (
	"regexp"
	"sort"

	scannerpkg "github.com/aegisgatesecurity/aegisgate/pkg/scanner"
)

// compiledPattern holds a pre-compiled regex pattern with its metadata.
type compiledPattern struct {
	Name        string
	Severity    Severity
	Confidence  float64
	Compiled    *regexp.Regexp
	Description string
}

// compilePatterns compiles a slice of PatternDef into compiledPattern slices.
// Panics on invalid regex — all patterns must be valid at init time.
func compilePatterns(defs []PatternDef) []compiledPattern {
	patterns := make([]compiledPattern, len(defs))
	for i, def := range defs {
		re, err := regexp.Compile(def.Regex)
		if err != nil {
			panic("detectors: invalid regex for " + def.Name + ": " + err.Error())
		}
		patterns[i] = compiledPattern{
			Name:        def.Name,
			Severity:    def.Severity,
			Confidence:  1.0,
			Compiled:    re,
			Description: def.Description,
		}
	}
	return patterns
}

// DetectAll scans text with XSS and compliance patterns and returns
// combined results. The other 6 categories (secrets, PII, OT) have been
// removed — they were never called in production and are covered by the
// upstream scanner. Use the scanner package directly for those.
func DetectAll(text string) []Match {
	var all []Match
	all = append(all, DetectXSS(text)...)
	all = append(all, DetectCompliance(text)...)

	sort.Slice(all, func(i, j int) bool {
		return all[i].Index < all[j].Index
	})

	return all
}

// DetectAllWithResults scans text with all pattern categories and returns
// per-category DetectionResult structs plus the combined match list.
//
// XSS and Compliance results are sourced from the upstream scanner
// (single source of truth). The pattern counts include both scanner
// patterns and any supplemental local patterns (e.g., xss_polyglot).
func DetectAllWithResults(text string) ([]Match, []DetectionResult) {
	scannerXSSCount := 0
	scannerComplianceCount := 0
	for _, p := range scannerpkg.DefaultPatterns() {
		switch p.Category {
		case scannerpkg.CategoryXSS:
			scannerXSSCount++
		case scannerpkg.CategoryCompliance:
			scannerComplianceCount++
		}
	}

	xssMatches := DetectXSS(text)
	complianceMatches := DetectCompliance(text)

	results := []DetectionResult{
		{Category: CategoryXSS, Matches: xssMatches, PatternCount: scannerXSSCount + len(CompiledXSSPatterns), ElapsedNS: 0},
		{Category: CategoryCompliance, Matches: complianceMatches, PatternCount: scannerComplianceCount, ElapsedNS: 0},
	}

	all := DetectAll(text)
	return all, results
}
