//go:build manual

// +build manual

// SPDX-License-Identifier: Apache-2.0

// Obfuscation corpus test: evasion rate measurement.
//
// For each obfuscated attack, this test:
//  1. Runs the regex detector on the obfuscated form
//  2. Counts it as EVADED if no detection fires
//  3. Counts it as DETECTED if any detection fires
//
// Reports:
//   - Regex detection rate on obfuscated attacks (target: ≥80%)
//   - Per-technique evasion rate
//   - List of evaded obfuscations (for ML training data)
//
// Strategic context: Regex catches ~28% of obfuscated attacks.
// The remaining ~72% need the ML layer (Step K) to catch.
// This corpus IS the ML training data for evasion patterns.
package lenstest_test

import (
	"context"
	"sort"
	"testing"
	"time"

	corpus "github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/corpus"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/detector"
)

func TestObfuscation_EvasionRate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping obfuscation test in -short mode")
	}
	obfs := corpus.ObfuscationCorpus()
	t.Logf("Testing %d obfuscated attack variants", len(obfs))

	d := detector.NewDetector()
	d.Timeout = 5 * time.Second

	// Batch process
	prompts := make([]string, 0, len(obfs))
	for _, o := range obfs {
		prompts = append(prompts, o.Obfuscated)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	results, err := d.DetectBatch(ctx, prompts)
	if err != nil {
		t.Fatalf("batch detect failed: %v", err)
	}

	// Aggregate
	detected := 0
	evaded := 0
	byTechnique := make(map[string]struct{ detected, total int })

	for i, o := range obfs {
		res := results[i]
		hit := len(res.Detections) > 0

		s := byTechnique[o.Technique]
		s.total++
		if hit {
			s.detected++
			detected++
		} else {
			evaded++
		}
		byTechnique[o.Technique] = s
	}

	detectionRate := float64(detected) / float64(len(obfs)) * 100
	evasionRate := float64(evaded) / float64(len(obfs)) * 100

	t.Logf("\n=== Obfuscation Evasion Report ===")
	t.Logf("Total variants:     %d", len(obfs))
	t.Logf("Regex detected:    %d (%.1f%%)", detected, detectionRate)
	t.Logf("Regex evaded:      %d (%.1f%%)", evaded, evasionRate)
	t.Logf("\n=== Per-Technique Evasion ===")

	var techniques []string
	for tech := range byTechnique {
		techniques = append(techniques, tech)
	}
	sort.Strings(techniques)
	for _, tech := range techniques {
		s := byTechnique[tech]
		techDetectRate := float64(s.detected) / float64(s.total) * 100
		t.Logf("  %-30s %4d/%4d = %5.1f%% detected",
			tech, s.detected, s.total, techDetectRate)
	}

	// Note: This test reports the evasion rate but does NOT fail
	// at high evasion rates because the regex layer has a known
	// limitation with obfuscation. The ML layer (Step K) is
	// expected to close this gap.
	t.Logf("\n=== Strategic Note ===")
	t.Logf("Regex evasion rate of %.1f%% is expected. The ML layer", evasionRate)
	t.Logf("(Step K, trained on this corpus) is expected to detect")
	t.Logf(">=80%% of these obfuscations, bringing total detection")
	t.Logf("rate (regex + ML cascade) to >=95%%.")

	// We do NOT fail this test at high evasion rates because:
	// 1. Regex evasion of obfuscation is a known limitation
	// 2. The ML layer is the remediation (Step K, not yet built)
	// 3. This corpus IS the ML training data
	//
	// When Step K completes, add a new test TestObfuscation_CascadeEvasionRate
	// that measures regex+ML combined detection rate. Target: >=95%.
}