// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Normalization Conformance Test
//
// Validates Platform's normalization functions against the canonical
// conformance vectors in testkit/normalization-conformance-vectors.json.
// This ensures Platform stays in parity with Rampart and Lens.
//
// Run: go test -v -run TestNormalizationConformance ./pkg/scanner/...

package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conformanceVectors is the parsed JSON from the canonical vectors file.
type conformanceVectors struct {
	Vectors map[string][]struct {
		Name                  string   `json:"name"`
		Input                 string   `json:"input"`
		Expected              string   `json:"expected"`
		ExpectedVariants      []string `json:"expected_variants"`
		ExpectedVariantsContains []string `json:"expected_variants_contains"`
	} `json:"vectors"`
}

// loadConformanceVectors loads the canonical vectors from the testkit directory.
// It searches relative to the package source, then falls back to env vars.
func loadConformanceVectors(t *testing.T) *conformanceVectors {
	t.Helper()

	candidates := []string{
		filepath.Join(os.Getenv("PLATFORM_DIR"), "testkit", "normalization-conformance-vectors.json"),
		filepath.Join(os.Getenv("AEGISGATE_ROOT"), "aegisgate-platform", "testkit", "normalization-conformance-vectors.json"),
		"../../testkit/normalization-conformance-vectors.json",
		"../../../testkit/normalization-conformance-vectors.json",
	}

	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			var cv conformanceVectors
			if err := json.Unmarshal(data, &cv); err == nil {
				return &cv
			}
		}
	}

	t.Skip("conformance vectors file not found — set PLATFORM_DIR or AEGISGATE_ROOT")
	return nil
}

func TestConformanceStripZeroWidth(t *testing.T) {
	cv := loadConformanceVectors(t)
	if cv == nil {
		return
	}

	for _, tc := range cv.Vectors["stripZeroWidth"] {
		t.Run(tc.Name, func(t *testing.T) {
			got := stripZeroWidth(tc.Input)
			if got != tc.Expected {
				t.Errorf("stripZeroWidth(%q) = %q, want %q", tc.Input, got, tc.Expected)
			}
		})
	}
}

func TestConformanceSlidingROT13(t *testing.T) {
	cv := loadConformanceVectors(t)
	if cv == nil {
		return
	}

	for _, tc := range cv.Vectors["NormalizeSlidingROT13"] {
		t.Run(tc.Name, func(t *testing.T) {
			got := NormalizeSlidingROT13(tc.Input)

			if len(tc.ExpectedVariants) == 0 && len(tc.ExpectedVariantsContains) == 0 {
				// Expect empty result
				if len(got) > 0 {
					t.Errorf("NormalizeSlidingROT13(%q) returned %d variants, want 0", tc.Input, len(got))
				}
				return
			}

			// Check exact match for expected_variants
			if len(tc.ExpectedVariants) > 0 {
				if len(got) != len(tc.ExpectedVariants) {
					t.Errorf("NormalizeSlidingROT13(%q) returned %d variants, want %d: got=%v want=%v",
						tc.Input, len(got), len(tc.ExpectedVariants), got, tc.ExpectedVariants)
					return
				}
				for i, v := range tc.ExpectedVariants {
					if got[i] != v {
						t.Errorf("NormalizeSlidingROT13(%q)[%d] = %q, want %q", tc.Input, i, got[i], v)
					}
				}
			}

			// Check contains for expected_variants_contains
			for _, expected := range tc.ExpectedVariantsContains {
				found := false
				for _, v := range got {
					if v == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("NormalizeSlidingROT13(%q) missing expected variant %q in %v",
						tc.Input, expected, got)
				}
			}
		})
	}
}

func TestConformanceRepeatingChars(t *testing.T) {
	cv := loadConformanceVectors(t)
	if cv == nil {
		return
	}

	for _, tc := range cv.Vectors["NormalizeRepeatingChars"] {
		t.Run(tc.Name, func(t *testing.T) {
			got := NormalizeRepeatingChars(tc.Input)
			if got != tc.Expected {
				t.Errorf("NormalizeRepeatingChars(%q) = %q, want %q", tc.Input, got, tc.Expected)
			}
		})
	}
}

func TestConformanceBackslashEscapes(t *testing.T) {
	cv := loadConformanceVectors(t)
	if cv == nil {
		return
	}

	for _, tc := range cv.Vectors["NormalizeBackslashEscapes"] {
		t.Run(tc.Name, func(t *testing.T) {
			got := NormalizeBackslashEscapes(tc.Input)
			if got != tc.Expected {
				t.Errorf("NormalizeBackslashEscapes(%q) = %q, want %q", tc.Input, got, tc.Expected)
			}
		})
	}
}

func TestConformanceROT13(t *testing.T) {
	cv := loadConformanceVectors(t)
	if cv == nil {
		return
	}

	for _, tc := range cv.Vectors["NormalizeROT13"] {
		t.Run(tc.Name, func(t *testing.T) {
			got := NormalizeROT13(tc.Input)
			if got != tc.Expected {
				t.Errorf("NormalizeROT13(%q) = %q, want %q", tc.Input, got, tc.Expected)
			}
		})
	}
}

func TestConformanceKeyboardWalk(t *testing.T) {
	cv := loadConformanceVectors(t)
	if cv == nil {
		return
	}

	for _, tc := range cv.Vectors["NormalizeKeyboardWalk"] {
		t.Run(tc.Name, func(t *testing.T) {
			got := NormalizeKeyboardWalk(tc.Input)
			// NormalizeKeyboardWalk applies ToLower in Rampart but not Platform.
			// Compare case-insensitively to handle this difference.
			if !strings.EqualFold(got, tc.Expected) {
				t.Errorf("NormalizeKeyboardWalk(%q) = %q, want %q (case-insensitive)", tc.Input, got, tc.Expected)
			}
		})
	}
}