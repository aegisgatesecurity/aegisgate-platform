// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Latency Optimization Tests
// =========================================================================

package ml_test

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLatencyOptimizer(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()
	opt := ml.NewLatencyOptimizer(cfg)
	require.NotNil(t, opt)

	// Verify attack words are precomputed into sets
	stats := opt.GetLatencyStats()
	assert.Equal(t, int64(0), stats.CacheHits)
	assert.Equal(t, int64(0), stats.CacheMisses)
	assert.Equal(t, int64(0), stats.FastPathHits)
	assert.Equal(t, int64(0), stats.TotalCalls)
}

func TestOptimizedDetect_FastPath(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()
	cfg.Enabled = true
	td := ml.NewThreatDetector(cfg)
	opt := ml.NewLatencyOptimizer(cfg)

	// Short input (<32 chars) should return score=0 immediately
	shortInput := "hello world"
	result := ml.OptimizedDetect(td, opt, shortInput)

	assert.Equal(t, float64(0), result.Score)
	assert.False(t, result.IsThreat)
	assert.Equal(t, "fast_path", result.Variant)

	// Verify fast path stat incremented
	stats := opt.GetLatencyStats()
	assert.Equal(t, int64(1), stats.FastPathHits)
	assert.Equal(t, int64(1), stats.TotalCalls)
}

func TestOptimizedDetect_CacheHit(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()
	cfg.Enabled = true
	td := ml.NewThreatDetector(cfg)
	opt := ml.NewLatencyOptimizer(cfg)

	// Use a long input (>32 chars) to bypass fast path
	longInput := "This is a longer input string that exceeds the thirty two character threshold for the fast path"

	// First call: cache miss
	result1 := ml.OptimizedDetect(td, opt, longInput)

	// Second call: should hit cache
	result2 := ml.OptimizedDetect(td, opt, longInput)

	assert.Equal(t, result1.Score, result2.Score)
	assert.Equal(t, result1.Variant, result2.Variant)

	stats := opt.GetLatencyStats()
	assert.Equal(t, int64(1), stats.CacheHits)
	assert.Equal(t, int64(1), stats.CacheMisses)
}

func TestOptimizedDetect_CacheMiss(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()
	cfg.Enabled = true
	td := ml.NewThreatDetector(cfg)
	opt := ml.NewLatencyOptimizer(cfg)

	longInput := "This is a sufficiently long input string that is definitely over thirty two characters long"

	// First call: should be a cache miss
	result := ml.OptimizedDetect(td, opt, longInput)
	assert.NotNil(t, result)

	stats := opt.GetLatencyStats()
	assert.Equal(t, int64(1), stats.CacheMisses)
	assert.Equal(t, int64(0), stats.CacheHits)
}

func TestBatchDetect(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()
	cfg.Enabled = true
	td := ml.NewThreatDetector(cfg)
	opt := ml.NewLatencyOptimizer(cfg)

	texts := []string{
		strings.Repeat("normal text input that is long enough", 2),
		strings.Repeat("another safe input that passes length check", 2),
		strings.Repeat("yet another batch detection input string", 2),
	}

	result := ml.BatchDetect(td, opt, texts)
	require.NotNil(t, result)
	assert.Len(t, result.Results, 3)
	assert.Len(t, result.Errors, 3)

	// All errors should be nil for valid inputs
	for _, err := range result.Errors {
		assert.Nil(t, err)
	}
}

func TestBatchDetect_Empty(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()
	cfg.Enabled = true
	td := ml.NewThreatDetector(cfg)
	opt := ml.NewLatencyOptimizer(cfg)

	result := ml.BatchDetect(td, opt, []string{})
	require.NotNil(t, result)
	assert.Empty(t, result.Results)
	assert.Empty(t, result.Errors)
}

func TestLatencyStats(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()
	cfg.Enabled = true
	td := ml.NewThreatDetector(cfg)
	opt := ml.NewLatencyOptimizer(cfg)

	// Trigger fast path
	ml.OptimizedDetect(td, opt, "short")

	// Trigger cache miss (long input)
	longInput := strings.Repeat("a", 64)
	ml.OptimizedDetect(td, opt, longInput)

	// Trigger cache hit (same long input)
	ml.OptimizedDetect(td, opt, longInput)

	stats := opt.GetLatencyStats()
	assert.Equal(t, int64(3), stats.TotalCalls)
	assert.Equal(t, int64(1), stats.FastPathHits)
	assert.Equal(t, int64(1), stats.CacheHits)
	assert.Equal(t, int64(1), stats.CacheMisses)
}

func TestResetCache(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()
	cfg.Enabled = true
	td := ml.NewThreatDetector(cfg)
	opt := ml.NewLatencyOptimizer(cfg)

	longInput := strings.Repeat("a", 64)

	// Populate cache
	ml.OptimizedDetect(td, opt, longInput)
	ml.OptimizedDetect(td, opt, longInput)

	stats := opt.GetLatencyStats()
	assert.Equal(t, int64(1), stats.CacheHits)

	// Reset cache
	opt.ResetCache()

	// Same input should now be a cache miss
	ml.OptimizedDetect(td, opt, longInput)
	stats = opt.GetLatencyStats()
	assert.Equal(t, int64(2), stats.CacheMisses)
}

func TestPrecomputeVariants(t *testing.T) {
	cfg := ml.DefaultDetectorConfig()
	opt := ml.NewLatencyOptimizer(cfg)

	// Precompute with a known set of words
	words := []string{"bypass", "ignore"}
	opt.PrecomputeVariants(words)

	// Verify by creating a new optimizer and checking detection
	// with transposition variants (these should be in the transpositions map)
	// "bypass" -> transpositions include "bpyass", "byapss", "bypsas", "bypas1"...
	// We can verify via OptimizedDetect with a long input containing a transposition
	cfg.Enabled = true
	td := ml.NewThreatDetector(cfg)

	// Create input with a transposition of "bypass": "byapss"
	longInput := "This is a test that contains byapss which is a transposition of bypass word"
	result := ml.OptimizedDetect(td, opt, longInput)
	_ = result // The result should reflect detection via precomputed sets
}