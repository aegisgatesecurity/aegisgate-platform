// SPDX-License-Identifier: Apache-2.0
// Helper: AllCanonicalEntries returns the merged per-pattern
// canonical corpus (hand-curated + auto-generated).
//
// NOTE: This file is in pkg/lenstest/corpus/ which is a different
// package from pkg/lenstest/ (different directory = different
// compilation unit in Go, even with the same package name).
// We import the parent package to access CanonicalEntry.
package lenstest

import (
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest"
)

// Alias to avoid name collision (both packages are called "lenstest").
type CanonicalEntry = lenstest.CanonicalEntry

// AllCanonicalEntries returns the union of PerPatternCorpus()
// (hand-curated, 12 entries) and PerPatternCorpusGenerated()
// (auto-generated, 141 entries).
//
// Use this in tests that want to exercise every pattern's
// canonical example. To run only one half, call the specific
// function.
func AllCanonicalEntries() []CanonicalEntry {
	hand := PerPatternCorpus()
	gen := PerPatternCorpusGenerated()

	// De-dupe by Name (some patterns appear in both lists).
	seen := make(map[string]bool)
	out := make([]CanonicalEntry, 0, len(hand)+len(gen))
	for _, e := range hand {
		if seen[e.Name] {
			continue
		}
		seen[e.Name] = true
		out = append(out, e)
	}
	for _, e := range gen {
		if seen[e.Name] {
			continue
		}
		seen[e.Name] = true
		out = append(out, e)
	}
	return out
}
