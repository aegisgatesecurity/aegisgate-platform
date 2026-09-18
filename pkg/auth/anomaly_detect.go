// =========================================================================
// AegisGate Security Platform — API Key Anomaly Detection
// =========================================================================
// v4.5.0 Enhancement P4: API Key Anomaly Detection
//
// anomaly_detect.go detects anomalous API key usage patterns that may indicate
// key compromise or abuse. It correlates auth logging with tool authorization
// data to identify:
//   - Unusual request volume spikes (burst detection)
//   - Off-hours access patterns
//   - Geographic anomalies (IP geolocation changes)
//   - Tool access pattern deviations (new tools, unexpected combinations)
//   - Rate threshold violations per key
//
// The detector maintains a rolling baseline of normal behavior per key and
// flags deviations that exceed configurable thresholds.
// =========================================================================

package auth

import (
	"math"
	"sync"
	"time"
)

// AnomalyWindow is the rolling window size for baseline calculation.
const AnomalyWindow = 24 * time.Hour

// AnomalyThreshold is the standard deviations above mean to flag as anomalous.
const AnomalyThreshold = 3.0

// MinSamplesForBaseline is the minimum data points before anomaly detection activates.
const MinSamplesForBaseline = 10

// KeyUsageRecord captures a single API key usage event.
type KeyUsageRecord struct {
	KeyID     string
	Timestamp time.Time
	ToolName  string
	SourceIP  string
	Endpoint  string
}

// KeyBaseline holds the statistical baseline for a single API key.
type KeyBaseline struct {
	KeyID        string
	SampleCount  int
	RequestCount int            // total requests in window
	HourlyCounts [24]int        // requests per hour-of-day
	ToolUsage    map[string]int // tool name → usage count
	SourceIPs    map[string]int // IP → request count
	WindowStart  time.Time
	WindowEnd    time.Time
	mu           sync.RWMutex
}

// AnomalyType classifies the kind of anomaly detected.
type AnomalyType int

const (
	AnomalyNone AnomalyType = iota
	AnomalyVolumeSpike
	AnomalyOffHours
	AnomalyGeoShift
	AnomalyNewTool
	AnomalyRateExceeded
)

// AnomalyResult is the output of an anomaly check for a single key.
type AnomalyResult struct {
	KeyID       string
	IsAnomalous bool
	Types       []AnomalyType
	Details     []string
}

// AnomalyDetector tracks API key usage and detects anomalous patterns.
type AnomalyDetector struct {
	baselines  map[string]*KeyBaseline
	mu         sync.RWMutex
	window     time.Duration
	threshold  float64
	minSamples int
}

// NewAnomalyDetector creates a new AnomalyDetector with default configuration.
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		baselines:  make(map[string]*KeyBaseline),
		window:     AnomalyWindow,
		threshold:  AnomalyThreshold,
		minSamples: MinSamplesForBaseline,
	}
}

// RecordUsage adds a usage event to the key's baseline tracking.
func (ad *AnomalyDetector) RecordUsage(rec KeyUsageRecord) {
	ad.mu.Lock()
	baseline, ok := ad.baselines[rec.KeyID]
	if !ok {
		baseline = &KeyBaseline{
			KeyID:     rec.KeyID,
			ToolUsage: make(map[string]int),
			SourceIPs: make(map[string]int),
		}
		ad.baselines[rec.KeyID] = baseline
	}
	ad.mu.Unlock()

	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now()
	}

	baseline.mu.Lock()
	defer baseline.mu.Unlock()

	baseline.SampleCount++
	baseline.RequestCount++
	baseline.HourlyCounts[rec.Timestamp.Hour()]++
	baseline.ToolUsage[rec.ToolName]++

	if rec.SourceIP != "" {
		baseline.SourceIPs[rec.SourceIP]++
	}

	if baseline.WindowStart.IsZero() {
		baseline.WindowStart = rec.Timestamp
	}
	baseline.WindowEnd = rec.Timestamp
}

// CheckAnomaly evaluates whether the latest usage for a key is anomalous
// relative to the established baseline.
func (ad *AnomalyDetector) CheckAnomaly(keyID string, rec KeyUsageRecord) AnomalyResult {
	ad.mu.RLock()
	baseline, ok := ad.baselines[keyID]
	ad.mu.RUnlock()

	result := AnomalyResult{KeyID: keyID}
	if !ok || baseline.SampleCount < ad.minSamples {
		return result
	}

	baseline.mu.RLock()
	defer baseline.mu.RUnlock()

	// Volume spike: current hourly count > mean + threshold * stddev
	mean, stddev := ad.computeHourlyStats(baseline)
	currentHour := rec.Timestamp.Hour()
	if rec.Timestamp.IsZero() {
		currentHour = time.Now().Hour()
	}
	if stddev > 0 && float64(baseline.HourlyCounts[currentHour]) > mean+ad.threshold*stddev {
		result.IsAnomalous = true
		result.Types = append(result.Types, AnomalyVolumeSpike)
		result.Details = append(result.Details, "volume spike detected")
	}

	// Off-hours: access at unusual hours (below mean - threshold * stddev)
	if stddev > 0 && float64(baseline.HourlyCounts[currentHour]) < math.Max(0, mean-ad.threshold*stddev) {
		result.IsAnomalous = true
		result.Types = append(result.Types, AnomalyOffHours)
		result.Details = append(result.Details, "off-hours access pattern")
	}

	// New tool: tool not seen in baseline
	if rec.ToolName != "" {
		if _, seen := baseline.ToolUsage[rec.ToolName]; !seen {
			result.IsAnomalous = true
			result.Types = append(result.Types, AnomalyNewTool)
			result.Details = append(result.Details, "new tool access: "+rec.ToolName)
		}
	}

	// Geo shift: new IP address
	if rec.SourceIP != "" {
		if _, seen := baseline.SourceIPs[rec.SourceIP]; !seen && len(baseline.SourceIPs) > 0 {
			result.IsAnomalous = true
			result.Types = append(result.Types, AnomalyGeoShift)
			result.Details = append(result.Details, "new source IP: "+rec.SourceIP)
		}
	}

	return result
}

// computeHourlyStats calculates mean and standard deviation of hourly request counts.
func (ad *AnomalyDetector) computeHourlyStats(baseline *KeyBaseline) (float64, float64) {
	if baseline.RequestCount == 0 {
		return 0, 0
	}

	hours := baseline.WindowEnd.Sub(baseline.WindowStart).Hours()
	if hours < 1 {
		hours = 1
	}

	mean := float64(baseline.RequestCount) / hours

	var sumSqDiff float64
	for h := 0; h < 24; h++ {
		diff := float64(baseline.HourlyCounts[h]) - mean
		sumSqDiff += diff * diff
	}
	stddev := math.Sqrt(sumSqDiff / 24)

	return mean, stddev
}

// GetBaseline returns the baseline statistics for a key.
func (ad *AnomalyDetector) GetBaseline(keyID string) (*KeyBaseline, bool) {
	ad.mu.RLock()
	defer ad.mu.RUnlock()
	b, ok := ad.baselines[keyID]
	return b, ok
}

// CleanupExpired removes baselines that haven't been updated within the window.
func (ad *AnomalyDetector) CleanupExpired() int {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	removed := 0
	for keyID, baseline := range ad.baselines {
		baseline.mu.RLock()
		expired := now.Sub(baseline.WindowEnd) > ad.window
		baseline.mu.RUnlock()
		if expired {
			delete(ad.baselines, keyID)
			removed++
		}
	}
	return removed
}
