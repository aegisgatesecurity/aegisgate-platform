package anomaly

import (
	"sync"
	"time"
)

// ThresholdManager handles dynamic threshold adjustments based on observed data.
type ThresholdManager struct {
	mu sync.RWMutex

	// Current thresholds (can be adjusted based on traffic patterns)
	entropyThresholds EntropyThresholds
	scoringConfig     ScorerConfig

	// Statistics for adaptive threshold adjustment
	stats   ThresholdStats
	enabled bool

	// Adaptation settings
	windowSize       int     // Number of samples to consider
	adjustmentFactor float64 // How much to adjust per window
	minSamples       int     // Minimum samples before adapting
}

// ThresholdStats tracks statistics for threshold adaptation.
type ThresholdStats struct {
	mu              sync.RWMutex
	sampleCount     int
	anomalyCount    int
	suspiciousCount int
	totalScore      float64
	lastWindowReset time.Time
	windowScores    []float64 // Rolling window of recent scores
}

// NewThresholdManager creates a new threshold manager with default thresholds.
func NewThresholdManager() *ThresholdManager {
	return &ThresholdManager{
		entropyThresholds: DefaultEntropyThresholds(),
		scoringConfig:     DefaultScorerConfig(),
		enabled:           false, // Disabled by default
		windowSize:        100,
		adjustmentFactor:  0.05, // 5% adjustment
		minSamples:        50,
	}
}

// Enable turns on adaptive threshold management.
func (tm *ThresholdManager) Enable() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.enabled = true
}

// Disable turns off adaptive threshold management and resets to defaults.
func (tm *ThresholdManager) Disable() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.enabled = false
	tm.resetToDefaultsUnsafe()
}

// resetToDefaultsUnsafe resets thresholds to production defaults (caller must hold lock).
func (tm *ThresholdManager) resetToDefaultsUnsafe() {
	tm.entropyThresholds = DefaultEntropyThresholds()
	tm.scoringConfig = DefaultScorerConfig()
}

// GetThresholds returns the current entropy thresholds.
func (tm *ThresholdManager) GetThresholds() EntropyThresholds {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.entropyThresholds
}

// GetScorerConfig returns the current scoring configuration.
func (tm *ThresholdManager) GetScorerConfig() ScorerConfig {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.scoringConfig
}

// RecordSample records a score for threshold adaptation.
// Returns true if thresholds were adjusted.
func (tm *ThresholdManager) RecordSample(score float64) bool {
	if !tm.isEnabled() {
		return false
	}

	// Add sample to stats (don't hold main lock during stats update)
	tm.stats.mu.Lock()
	tm.stats.sampleCount++
	tm.stats.totalScore += score
	tm.stats.windowScores = append(tm.stats.windowScores, score)

	// Keep only recent window
	if len(tm.stats.windowScores) > tm.windowSize {
		tm.stats.windowScores = tm.stats.windowScores[1:]
	}

	// Count classifications
	if score >= tm.getAlertThreshold() {
		tm.stats.anomalyCount++
	} else if score >= tm.getSuspiciousThreshold() {
		tm.stats.suspiciousCount++
	}

	// Check if we should adapt
	sampleCount := tm.stats.sampleCount
	shouldAdjust := sampleCount >= tm.minSamples && sampleCount%tm.windowSize == 0
	tm.stats.mu.Unlock()

	// Call adjust without holding stats lock
	if shouldAdjust {
		return tm.adjustThresholds()
	}

	return false
}

// isEnabled checks if threshold manager is enabled (thread-safe).
func (tm *ThresholdManager) isEnabled() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.enabled
}

// getAlertThreshold returns current alert threshold (thread-safe).
func (tm *ThresholdManager) getAlertThreshold() float64 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.scoringConfig.AlertThreshold
}

// getSuspiciousThreshold returns current suspicious threshold (thread-safe).
func (tm *ThresholdManager) getSuspiciousThreshold() float64 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.scoringConfig.SuspiciousThreshold
}

// adjustThresholds adjusts thresholds based on observed data.
func (tm *ThresholdManager) adjustThresholds() bool {
	// Take stats snapshot
	tm.stats.mu.Lock()
	sampleCount := tm.stats.sampleCount
	anomalyCount := tm.stats.anomalyCount
	windowScores := make([]float64, len(tm.stats.windowScores))
	copy(windowScores, tm.stats.windowScores)
	tm.stats.mu.Unlock()

	if sampleCount == 0 {
		return false
	}

	// Calculate metrics
	recentAnomalyRate := float64(anomalyCount) / float64(sampleCount)
	var sum float64
	for _, s := range windowScores {
		sum += s
	}
	meanScore := sum / float64(len(windowScores))

	// Take main lock for threshold adjustment
	tm.mu.Lock()
	defer tm.mu.Unlock()

	adjusted := false

	// Adjust based on anomaly rate
	if recentAnomalyRate > 0.20 {
		// Too many anomalies - raise threshold
		tm.scoringConfig.AnomalyThreshold += tm.adjustmentFactor
		if tm.scoringConfig.AnomalyThreshold > 0.9 {
			tm.scoringConfig.AnomalyThreshold = 0.9
		}
		tm.scoringConfig.AlertThreshold += tm.adjustmentFactor
		if tm.scoringConfig.AlertThreshold > 0.95 {
			tm.scoringConfig.AlertThreshold = 0.95
		}
		adjusted = true
	} else if recentAnomalyRate < 0.05 && recentAnomalyRate > 0 {
		// Too few anomalies - lower threshold
		tm.scoringConfig.AnomalyThreshold -= tm.adjustmentFactor
		if tm.scoringConfig.AnomalyThreshold < 0.5 {
			tm.scoringConfig.AnomalyThreshold = 0.5
		}
		tm.scoringConfig.AlertThreshold -= tm.adjustmentFactor
		if tm.scoringConfig.AlertThreshold < 0.7 {
			tm.scoringConfig.AlertThreshold = 0.7
		}
		adjusted = true
	}

	// Adjust entropy thresholds based on mean score
	if meanScore > 0.6 && tm.entropyThresholds.Low < 2.5 {
		tm.entropyThresholds.Low += 0.1
		tm.entropyThresholds.Medium += 0.1
		adjusted = true
	} else if meanScore < 0.3 && tm.entropyThresholds.Low > 1.5 {
		tm.entropyThresholds.Low -= 0.1
		tm.entropyThresholds.Medium -= 0.1
		adjusted = true
	}

	// Reset window stats
	tm.stats.mu.Lock()
	tm.stats.anomalyCount = 0
	tm.stats.suspiciousCount = 0
	tm.stats.lastWindowReset = time.Now()
	tm.stats.mu.Unlock()

	return adjusted
}

// GetStats returns current statistics (copy to avoid mutex issues).
func (tm *ThresholdManager) GetStats() ThresholdStats {
	tm.stats.mu.RLock()
	defer tm.stats.mu.RUnlock()

	return ThresholdStats{
		sampleCount:     tm.stats.sampleCount,
		anomalyCount:    tm.stats.anomalyCount,
		suspiciousCount: tm.stats.suspiciousCount,
		totalScore:      tm.stats.totalScore,
		lastWindowReset: tm.stats.lastWindowReset,
		windowScores:    append([]float64{}, tm.stats.windowScores...),
	}
}

// ResetStats clears all statistics without locking (for use in tests).
func (tm *ThresholdManager) ResetStats() {
	// Direct assignment without mutex for test safety
	tm.stats.sampleCount = 0
	tm.stats.anomalyCount = 0
	tm.stats.suspiciousCount = 0
	tm.stats.totalScore = 0
	tm.stats.lastWindowReset = time.Time{}
	tm.stats.windowScores = make([]float64, 0, tm.windowSize)
}

// AnomalyRate returns the current anomaly rate.
func (tm *ThresholdManager) AnomalyRate() float64 {
	tm.stats.mu.RLock()
	defer tm.stats.mu.RUnlock()

	if tm.stats.sampleCount == 0 {
		return 0
	}

	return float64(tm.stats.anomalyCount) / float64(tm.stats.sampleCount)
}

// MeanScore returns the mean score of recent samples.
func (tm *ThresholdManager) MeanScore() float64 {
	tm.stats.mu.RLock()
	defer tm.stats.mu.RUnlock()

	if len(tm.stats.windowScores) == 0 {
		return 0
	}

	var sum float64
	for _, s := range tm.stats.windowScores {
		sum += s
	}
	return sum / float64(len(tm.stats.windowScores))
}

// SetWindowSize sets the size of the rolling window.
func (tm *ThresholdManager) SetWindowSize(size int) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.windowSize = size
}

// SetAdjustmentFactor sets how much to adjust thresholds.
func (tm *ThresholdManager) SetAdjustmentFactor(factor float64) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.adjustmentFactor = factor
}

// SetThresholds directly sets entropy thresholds.
func (tm *ThresholdManager) SetThresholds(thresholds EntropyThresholds) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.entropyThresholds = thresholds
}

// SetScorerConfig directly sets scoring configuration.
func (tm *ThresholdManager) SetScorerConfig(config ScorerConfig) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.scoringConfig = config
}

// IsEnabled returns whether adaptive threshold management is active.
func (tm *ThresholdManager) IsEnabled() bool {
	return tm.isEnabled()
}
