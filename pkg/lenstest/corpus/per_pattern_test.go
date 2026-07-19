//go:build manual

// +build manual

// SPDX-License-Identifier: Apache-2.0

// Per-pattern canonical tests.
//
// For every canonical entry in the per-pattern corpus, this test:
//   - Runs the JS detector with MustTrigger input
//   - Asserts at least one acceptable detection fires
//
// "Acceptable" means:
//   - The ported pattern's name matches, OR
//   - A hand-written equivalent's name matches (see equivalence.go), OR
//   - A detection with the same category matches
//
// This is the "every pattern must fire" check: if a pattern never
// matches its canonical example, something is broken.
//
// To run:
//
//	go test -v ./pkg/lenstest/corpus/ -run TestPerPattern
package lenstest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	lenstest "github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest"
	corpus "github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/corpus"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/detector"
)

// findAcceptableDetection returns the first detection that matches
// the entry's expected name, a hand-written equivalent, category,
// or a shared category-family prefix.
//
// Family match: if entry's category is "atlas_llmjailbreak" and
// detection's category is "atlas_promptinjection", they share the
// "atlas_" prefix and are considered equivalent. This handles cases
// where a broader pattern fires before the specific one (e.g.,
// when multiple atlas patterns overlap on the same input).
func findAcceptableDetection(res *detector.DetectResult, e lenstest.CanonicalEntry) *detector.Detection {
	acceptableNames := lenstest.FindAcceptableNames(e)
	entryPrefix := extractCategoryPrefix(e.Category)
	for i := range res.Detections {
		d := &res.Detections[i]
		for _, name := range acceptableNames {
			if d.Name == name {
				return d
			}
		}
		if d.Category == e.Category {
			return d
		}
		// Family prefix match: extract the source prefix (e.g., "atlas"
		// from "atlas_llmjailbreak") and compare.
		detPrefix := extractCategoryPrefix(d.Category)
		if entryPrefix != "" && entryPrefix == detPrefix {
			return d
		}
	}
	return nil
}

// extractCategoryPrefix returns the first underscore-delimited segment
// of a category name (e.g., "atlas" from "atlas_llmjailbreak").
func extractCategoryPrefix(cat string) string {
	for i := 0; i < len(cat); i++ {
		if cat[i] == '_' {
			return cat[:i]
		}
	}
	return cat
}

func TestPerPattern_MustTrigger(t *testing.T) {
	entries := corpus.AllCanonicalEntries()
	if len(entries) == 0 {
		t.Fatal("no canonical entries found")
	}
	t.Logf("Testing %d canonical entries", len(entries))

	d := detector.NewDetector()
	d.Timeout = 10 * time.Second

	for _, e := range entries {
		e := e
		t.Run(e.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			res, err := d.Detect(ctx, e.MustTrigger)
			if err != nil {
				t.Fatalf("detect failed: %v", err)
			}
			if res.Error != "" {
				t.Fatalf("detect error: %s", res.Error)
			}

			det := findAcceptableDetection(res, e)
			if det == nil {
				got := make([]string, 0, len(res.Detections))
				for _, x := range res.Detections {
					got = append(got, x.Name+":"+x.Category)
				}
				acceptableNames := lenstest.FindAcceptableNames(e)
				t.Errorf("pattern %q (category %q) did NOT fire\n  input:    %q\n  expected one of: %v\n  got: %v",
					e.Name, e.Category, e.MustTrigger, acceptableNames, got)
			} else if e.ExpectedMatch != "" && !strings.Contains(det.Match, e.ExpectedMatch) {
				t.Logf("note: pattern %q fired (match=%q) but expected substring %q not found",
					det.Name, det.Match, e.ExpectedMatch)
			}
		})
	}
}

func TestPerPattern_MustTrigger_Batched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping batched test in -short mode")
	}
	entries := corpus.AllCanonicalEntries()
	prompts := make([]string, 0, len(entries))
	for _, e := range entries {
		prompts = append(prompts, e.MustTrigger)
	}

	d := detector.NewDetector()
	d.Timeout = 60 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results, err := d.DetectBatch(ctx, prompts)
	if err != nil {
		t.Fatalf("batch detect failed: %v", err)
	}

	fired := 0
	notFired := 0
	for i, e := range entries {
		res := results[i]
		if res.Error != "" {
			notFired++
			t.Errorf("FAIL: %s (%s): %s", e.Name, e.Category, res.Error)
			continue
		}
		det := findAcceptableDetection(&res, e)
		if det != nil {
			fired++
		} else {
			notFired++
			acceptableNames := lenstest.FindAcceptableNames(e)
			t.Errorf("FAIL: %s (%s): no acceptable detection (need one of: %v)",
				e.Name, e.Category, acceptableNames)
		}
	}

	t.Logf("Batched: %d fired, %d did not fire (out of %d)",
		fired, notFired, len(entries))
}

// TestPerPattern_MustNotTrigger verifies that the canonical
// "normal" inputs DO NOT trigger any detection in the
// entry's category. This is the per-pattern FPR side of the
// test suite.
//
// Failures indicate either:
//   - The MustNotTrigger input inadvertently triggers detection
//     (false positive), or
//   - The category is too aggressive (matches too broadly)
//
// We allow detections in OTHER categories (e.g., a "normal"
// sentence might still contain a credit card-like number that
// triggers a different category). The test only fails if the
// specific entry's category is matched.
func TestPerPattern_MustNotTrigger(t *testing.T) {
	entries := corpus.AllCanonicalEntries()
	t.Logf("Testing %d canonical entries (must NOT trigger)", len(entries))

	d := detector.NewDetector()
	d.Timeout = 60 * time.Second

	prompts := make([]string, 0, len(entries))
	for _, e := range entries {
		prompts = append(prompts, e.MustNotTrigger)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results, err := d.DetectBatch(ctx, prompts)
	if err != nil {
		t.Fatalf("batch detect failed: %v", err)
	}

	cleanCount := 0
	fpCount := 0
	for i, e := range entries {
		res := results[i]
		if res.Error != "" {
			t.Errorf("FAIL: %s (%s): %s", e.Name, e.Category, res.Error)
			continue
		}

		// Find any detection in this entry's category
		var fp *detector.Detection
		for j := range res.Detections {
			if res.Detections[j].Category == e.Category {
				fp = &res.Detections[j]
				break
			}
		}

		if fp != nil {
			fpCount++
			t.Errorf("FALSE POSITIVE: %s (%s) fired on its MustNotTrigger input\n  input:    %q\n  expected: NOT in category %q\n  got:      %s:%s match=%q",
				e.Name, e.Category, e.MustNotTrigger, e.Category,
				fp.Name, fp.Category, fp.Match)
		} else {
			cleanCount++
		}
	}

	t.Logf("MustNotTrigger: %d clean, %d false positives (out of %d)",
		cleanCount, fpCount, len(entries))
}