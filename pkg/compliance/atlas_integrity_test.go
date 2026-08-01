// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ATLAS Pattern Integrity Tests
// =========================================================================
//
// Tests for PatternIntegrity method and /api/v1/compliance/integrity
// endpoint. Verifies that the SHA256 hash of the ATLAS pattern set
// is deterministic, non-empty, and matches the pattern count.
//
// v3.8.0 — P1 Item 2: Rule Integrity Verification.
// =========================================================================

package compliance

import (
	"testing"
)

func TestPatternIntegrity_NonEmptyHash(t *testing.T) {
	f := NewATLASFramework(0)
	result := f.PatternIntegrity()
	if result.Hash == "" {
		t.Error("PatternIntegrity().Hash is empty, expected non-empty SHA256 hash")
	}
	// SHA256 produces a 64-character hex string.
	if len(result.Hash) != 64 {
		t.Errorf("PatternIntegrity().Hash length = %d, want 64", len(result.Hash))
	}
}

func TestPatternIntegrity_Deterministic(t *testing.T) {
	f := NewATLASFramework(0)
	result1 := f.PatternIntegrity()
	result2 := f.PatternIntegrity()
	if result1.Hash != result2.Hash {
		t.Errorf("PatternIntegrity is not deterministic: first call = %q, second call = %q", result1.Hash, result2.Hash)
	}
}

func TestPatternIntegrity_PatternCount(t *testing.T) {
	f := NewATLASFramework(0)
	result := f.PatternIntegrity()
	patterns := f.GetPatterns()
	if result.PatternCount != len(patterns) {
		t.Errorf("PatternIntegrity().PatternCount = %d, want %d (number of patterns)", result.PatternCount, len(patterns))
	}
	if result.PatternCount == 0 {
		t.Error("PatternIntegrity().PatternCount is 0, expected at least 1 pattern")
	}
}

func TestPatternIntegrity_Version(t *testing.T) {
	f := NewATLASFramework(0)
	result := f.PatternIntegrity()
	if result.Version != "3.8.0" {
		t.Errorf("PatternIntegrity().Version = %q, want %q", result.Version, "3.8.0")
	}
}

func TestPatternIntegrity_GeneratedAt(t *testing.T) {
	f := NewATLASFramework(0)
	result := f.PatternIntegrity()
	if result.GeneratedAt == "" {
		t.Error("PatternIntegrity().GeneratedAt is empty, expected RFC3339 timestamp")
	}
}

func TestPatternIntegrity_DifferentContextLines(t *testing.T) {
	// PatternIntegrity should return the same hash regardless of contextLines
	// because contextLines only affects context extraction, not the patterns themselves.
	f0 := NewATLASFramework(0)
	f3 := NewATLASFramework(3)

	result0 := f0.PatternIntegrity()
	result3 := f3.PatternIntegrity()

	if result0.Hash != result3.Hash {
		t.Errorf("PatternIntegrity should be the same regardless of contextLines: 0=%q, 3=%q", result0.Hash, result3.Hash)
	}
}