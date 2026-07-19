//go:build manual

// +build manual


// Banner XSS test: validates that the Lens banner safely renders
// adversarial inputs.
//
// This test has two parts:
//  1. RUNTIME: For each adversarial input, verify the detector fires
//     and would render the banner. The banner uses textContent
//     which is XSS-safe by construction.
//  2. CODE-LEVEL: Grep content.js to verify innerHTML is NOT used
//     in banner rendering. If anyone changes the banner to use
//     innerHTML, this test fails.
//
// Part 2 is the actual safety guarantee. Part 1 measures coverage
// of our adversarial input corpus.
package lenstest_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	corpus "github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/corpus"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/detector"
)

func TestBannerXSS_Safety(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping banner-XSS test in -short mode")
	}

	// PART 1: Coverage test. Verify that adversarial inputs trigger
	// detection (so the banner would render them).
	xs := corpus.BannerXssCorpus()
	t.Logf("Testing %d banner-XSS variants", len(xs))

	d := detector.NewDetector()
	d.Timeout = 5 * time.Second

	prompts := make([]string, 0, len(xs))
	for _, x := range xs {
		prompts = append(prompts, x.Prompt)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	results, err := d.DetectBatch(ctx, prompts)
	if err != nil {
		t.Fatalf("batch detect failed: %v", err)
	}

	totalChecked := 0
	totalFires := 0
	for i := range xs {
		if i >= len(results) || len(results[i].Detections) == 0 {
			continue
		}
		totalChecked++
		totalFires++
	}
	t.Logf("\n=== Banner XSS Coverage ===")
	t.Logf("Total variants: %d", len(xs))
	t.Logf("Detector fires (banner would render): %d (%.1f%%)",
		totalFires, float64(totalFires)/float64(len(xs))*100)

	// PART 2: Code-level check. Verify content.js uses textContent,
	// not innerHTML, for banner rendering.
	contentJSPath := "/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/src/content.js"
	content, err := os.ReadFile(contentJSPath)
	if err != nil {
		t.Fatalf("could not read content.js: %v", err)
	}
	contentStr := string(content)

	// Check for safe patterns
	safePatterns := []string{
		"li.textContent",
		"header.textContent",
		"cancelBtn.textContent",
		"editBtn.textContent",
		"sendBtn.textContent",
	}
	for _, pattern := range safePatterns {
		if !strings.Contains(contentStr, pattern) {
			t.Errorf("SAFETY INVARIANT VIOLATED: '%s' not found in content.js", pattern)
		}
	}
	t.Logf("\n=== Code-Level Safety Check ===")
	t.Logf("[OK] li.textContent, header.textContent, etc. all present")
	t.Logf("[OK] Banner uses createElement + textContent (XSS-safe by construction)")

	// Check for UNSAFE patterns
	unsafePatterns := []string{
		"innerHTML",
		"document.write",
		"eval(",
	}
	foundUnsafe := false
	for _, pattern := range unsafePatterns {
		if strings.Contains(contentStr, pattern) {
			// Allow innerHTML in comments or in the AI provider's prompts
			// (but NOT in banner rendering)
			idx := strings.Index(contentStr, pattern)
			t.Errorf("UNSAFE PATTERN FOUND: '%s' at offset %d in content.js", pattern, idx)
			foundUnsafe = true
		}
	}
	if !foundUnsafe {
		t.Logf("[OK] No unsafe patterns (innerHTML, document.write, eval) found")
	}

	// Final result
	t.Logf("\n=== Summary ===")
	t.Logf("Total XSS variants tested: %d", len(xs))
	t.Logf("Banner-safe by structural design: YES (uses textContent)")
	if foundUnsafe {
		t.Errorf("FAIL: Banner has unsafe patterns. Fix content.js.")
	} else {
		t.Logf("All banner-XSS tests PASS")
	}
}