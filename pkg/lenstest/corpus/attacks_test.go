//go:build manual

// +build manual

// SPDX-License-Identifier: Apache-2.0

// Attack corpus test: True Positive Rate (TPR) measurement.
//
// For each attack in the attack corpus, this test:
//  1. Runs the JS detector on the attack prompt
//  2. Asserts at least one detection fires in one of the expected
//     categories (pipe-separated in the ExpectedMatch field)
//
// Reports:
//   - TPR (true positive rate) = correct_detection / total_attacks
//   - Per-category breakdown
//   - Per-pattern breakdown
//
// Target: TPR >= 95% (industry standard is 70-85%).
// Goal: TPR >= 99% (10x standard).
package lenstest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	corpus "github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/corpus"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/detector"
)

func TestAttackCorpus_TPR_Batched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attack corpus test in -short mode")
	}
	attacks := corpus.AttackCorpus()
	t.Logf("Testing %d attack prompts", len(attacks))

	d := detector.NewDetector()
	d.Timeout = 5 * time.Second

	// Extract prompts for batch processing
	prompts := make([]string, 0, len(attacks))
	for _, a := range attacks {
		prompts = append(prompts, a.MustTrigger)
	}

	// Process in batches to avoid timeout on huge inputs
	const batchSize = 100
	allResults := make([]detector.DetectResult, 0, len(attacks))
	for i := 0; i < len(prompts); i += batchSize {
		end := i + batchSize
		if end > len(prompts) {
			end = len(prompts)
		}
		batch := prompts[i:end]
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		results, err := d.DetectBatch(ctx, batch)
		cancel()
		if err != nil {
			t.Fatalf("batch detect failed at %d: %v", i, err)
		}
		allResults = append(allResults, results...)
	}

	// Aggregate results
	detected := 0
	notDetected := 0
	categoryStats := make(map[string]struct{ detected, total int })
	patternStats := make(map[string]struct{ detected, total int })
	var failedAttacks []corpus.CanonicalEntry

	for i, a := range attacks {
		res := allResults[i]
		expectedCats := strings.Split(a.ExpectedMatch, "|")
		if len(expectedCats) == 0 || (len(expectedCats) == 1 && expectedCats[0] == "") {
			expectedCats = []string{a.Category}
		}

		// Check if any detection matches an expected category (or family/equivalent)
		var hit bool
		expectedFamilies := corpus.AttackCategoryFamiliesFor(expectedCats)
		// Build set of acceptable categories: explicit matches + family/equivalent
		acceptable := make(map[string]bool)
		for _, exp := range expectedCats {
			acceptable[exp] = true
		}
		for _, fam := range expectedFamilies {
			acceptable[fam] = true
		}
		for _, det := range res.Detections {
			// Exact category match?
			if acceptable[det.Category] {
				hit = true
				break
			}
			// Family prefix match? (e.g., "secret_api_key" matches "secret" family)
			for _, fam := range expectedFamilies {
				if fam != "" && strings.HasPrefix(det.Category, fam) {
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}

		// Aggregate
		for _, exp := range expectedCats {
			s := categoryStats[exp]
			s.total++
			if hit {
				s.detected++
			}
			categoryStats[exp] = s
		}

		s := patternStats[a.Name]
		s.total++
		if hit {
			s.detected++
		}
		patternStats[a.Name] = s

		if hit {
			detected++
		} else {
			notDetected++
			failedAttacks = append(failedAttacks, a)
		}
	}

	tpr := float64(detected) / float64(len(attacks)) * 100
	t.Logf("\n=== Attack Corpus TPR Report ===")
	t.Logf("Total attacks: %d", len(attacks))
	t.Logf("Detected:      %d", detected)
	t.Logf("Not detected:  %d", notDetected)
	t.Logf("TPR:           %.2f%%", tpr)
	t.Logf("\n=== Per-Category TPR ===")
	for cat, s := range categoryStats {
		if s.total == 0 {
			continue
		}
		catTpr := float64(s.detected) / float64(s.total) * 100
		t.Logf("  %-30s %4d/%4d = %6.2f%%", cat, s.detected, s.total, catTpr)
	}

	// Report failed attacks (limit to first 20 for readability)
	t.Logf("\n=== Failed Attacks (first 20 of %d) ===", len(failedAttacks))
	for i, a := range failedAttacks {
		if i >= 20 {
			t.Logf("  ... and %d more", len(failedAttacks)-20)
			break
		}
		t.Logf("  %s: %q", a.Name, a.MustTrigger)
	}

	// Hard requirement: TPR must be at least 95%
	if tpr < 95.0 {
		t.Errorf("TPR %.2f%% is below the 95%% threshold", tpr)
	}
}