// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
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
	if result.Version != "3.6.0" {
		t.Errorf("PatternIntegrity().Version = %q, want %q", result.Version, "3.6.0")
	}
}

func TestPatternIntegrity_GeneratedAt(t *testing.T) {
	f := NewATLASFramework(0)
	result := f.PatternIntegrity()
	if result.GeneratedAt == "" {
		t.Error("PatternIntegrity().GeneratedAt is empty, expected RFC3339 timestamp")
	}
}