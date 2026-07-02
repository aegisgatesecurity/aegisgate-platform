// SPDX-License-Identifier: Apache-2.0
// Quick sanity test for goside package.
//
// Verifies that the Go-side detector can be constructed from
// the Platform source files and produces non-empty detections
// on a known-sensitive input.
package goside_test

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lenstest/goside"
)

const platformRoot = "/home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform"

func TestGoside_LoadsPatterns(t *testing.T) {
	d, err := goside.New(platformRoot)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d.Count() == 0 {
		t.Fatal("no patterns loaded")
	}
	t.Logf("Loaded %d patterns from Platform Go source files", d.Count())
}

func TestGoside_DetectsEmail(t *testing.T) {
	d, err := goside.New(platformRoot)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	input := "Please contact john.doe@example.com for details."
	dets := d.Detect(input)

	var found bool
	for _, det := range dets {
		if strings.Contains(det.Match, "john.doe@example.com") {
			found = true
			t.Logf("detected: %s (match=%q)", det.Name, det.Match)
		}
	}
	if !found {
		t.Errorf("email not detected by Go-side detector")
		for _, det := range dets {
			t.Logf("  got: %s (match=%q)", det.Name, det.Match)
		}
	}
}

func TestGoside_DetectsCreditCard(t *testing.T) {
	d, err := goside.New(platformRoot)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Luhn-valid Visa test number
	input := "Card: 4820-1275-9241-9155 exp 12/26"
	dets := d.Detect(input)

	var found bool
	for _, det := range dets {
		if strings.Contains(det.Match, "4820") {
			found = true
			t.Logf("detected: %s (match=%q)", det.Name, det.Match)
		}
	}
	if !found {
		t.Errorf("credit card not detected")
		for _, det := range dets {
			t.Logf("  got: %s (match=%q)", det.Name, det.Match)
		}
	}
}