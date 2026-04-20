// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package ml provides machine learning capabilities for anomaly detection in WAF traffic.
// This implementation uses only the Go standard library for pure statistical analysis
// without external ML dependencies.
//
// The anomaly detection system uses:
// - Moving averages for baseline establishment
// - Z-score calculation for statistical anomaly detection
// - Shannon entropy for content analysis
// - Time-series analysis for pattern detection
//
// Example usage:
//
//	config := ml.Config{
//	    Sensitivity: ml.Medium,
//	    WindowSize: 100,
//	    ZThreshold: 3.0,
//	}
//	detector := ml.New(config)
//
//	detector.RecordTraffic(ml.TrafficSample{
//	    Timestamp: time.Now(),
//	    Volume:    100,
//	    Size:      1024,
//	})
//
//	anomaly, detected := detector.AnalyzeRequest("GET", "/api/data", 2048)
package ml

import (
	"math"
	"strings"
	"sync"
	"time"
)

// Sensitivity defines how strict the anomaly detection should be.
// Higher sensitivity means more anomalies will be detected.
type Sensitivity string

const (
	// Low sensitivity - only major anomalies (>= 4 standard deviations)
	Low Sensitivity = "low"
	// Medium sensitivity - balanced detection (>= 3 standard deviations)
	Medium Sensitivity = "medium"
	// High sensitivity - detects subtle anomalies (>= 2 standard deviations)
	High Sensitivity = "high"
	// Critical sensitivity - detects very subtle anomalies (>= 1.5 standard deviations)
	Critical Sensitivity = "critical"
)

// AnomalyType categorizes the type of anomaly detected.
// These types help in understanding the nature of suspicious activity.
type AnomalyType string

const (
	// TrafficSpike indicates an unusual increase in request volume.
	// May indicate DDoS attack or sudden legitimate traffic surge.
	TrafficSpike AnomalyType = "traffic_spike"

	// TrafficDrop indicates an unusual decrease in request volume.
	// May indicate service disruption or blocked legitimate traffic.
	TrafficDrop AnomalyType = "traffic_drop"

	// SizeAnomaly indicates unusual request/response sizes.
	// May indicate data exfiltration, large uploads, or buffer overflow attempts.
	SizeAnomaly AnomalyType = "size_anomaly"

	// ViolationSpike indicates increased security rule violations.
	// May indicate attack attempts or scanning activity.
	ViolationSpike AnomalyType = "violation_spike"

	// EntropyAnomaly indicates unusual entropy in request content.
	// May indicate encoded payloads, encrypted traffic, or obfuscated attacks.
	EntropyAnomaly AnomalyType = "entropy_anomaly"

	// PatternAnomaly indicates unusual request patterns.
	// May indicate automated tools, bots, or scripted attacks.
	PatternAnomaly AnomalyType = "pattern_anomaly"

	// TimeAnomaly indicates unusual timing patterns.
	// May indicate automated requests or scheduled attack patterns.
	TimeAnomaly AnomalyType = "time_anomaly"
)

// Severity defines the importance level of an anomaly.
type Severity int

const (
	// Info severity - log only, no action needed
	Info Severity = 1
	// Low severity - minor deviation from normal
	LowSev Severity = 2
	// Medium severity - notable deviation, may need attention
	MediumSev Severity = 3
	// High severity - significant deviation, likely requires attention
	HighSev Severity = 4
	// Critical severity - extreme deviation, immediate attention required
	CriticalSev Severity = 5
)

// TrafficSample represents a data point for traffic analysis.
// Used to build baselines and detect anomalies over time.
type TrafficSample struct {
	// Timestamp when the sample was recorded
	Timestamp time.Time
	// Volume is the number of requests in the sample period
	Volume int
	// Size is the total bytes transferred
	Size int64
	// Violations count of security rule violations
	Violations int
}

// Anomaly represents a detected statistical anomaly in traffic patterns.
// Contains all details needed for evaluation and response.
type Anomaly struct {
	// Type categorizes the anomaly (traffic_spike, entropy_anomaly, etc.)
	Type AnomalyType

	// Severity indicates the importance level (1-5)
	Severity Severity

	// Score is the statistical z-score indicating how many
	// standard deviations from the mean this value is
	Score float64

	// Timestamp when the anomaly was detected
	Timestamp time.Time

	// Evidence contains additional context about the anomaly
	Evidence map[string]interface{}

	// Description provides a human-readable explanation
	Description string
}

// Baseline tracks moving averages and standard deviations for metrics.
// Uses a sliding window approach for real-time adaptation to traffic patterns.
type Baseline struct {
	// samples stores the recent values for window calculations
	samples []float64

	// windowSize defines how many samples to keep
	windowSize int

	// movingAverage is the current mean of the samples
	movingAverage float64

	// stdDev is the current standard deviation
	stdDev float64

	// sum and sumSq are cached for efficient calculation
	sum   float64
	sumSq float64

	// mu protects concurrent access to baseline
	mu sync.RWMutex
}

// Config provides configuration options for the anomaly detector.
type Config struct {
	// Sensitivity determines the z-score threshold for anomaly detection
	Sensitivity Sensitivity

	// WindowSize is the number of samples to consider for baseline
	WindowSize int

	// ZThreshold can override the default threshold based on sensitivity
	ZThreshold float64

	// MinSamples is the minimum samples needed before detecting anomalies
	MinSamples int

	// EntropyThreshold for content analysis (0-1, higher = more random)
	EntropyThreshold float64
}

// Detector is the main anomaly detection engine.
// Supports concurrent access and real-time analysis.
type Detector struct {
	// config stores the detector configuration
	config Config

	// trafficBaseline for request volume analysis
	trafficBaseline *Baseline

	// sizeBaseline for payload size analysis
	sizeBaseline *Baseline

	// violationBaseline for security violation tracking
	violationBaseline *Baseline

	// detectedAnomalies stores recent anomalies
	detectedAnomalies []Anomaly

	// anomalyMu protects the anomalies slice
	anomalyMu sync.RWMutex

	// lastRequestTime tracks timing patterns
	lastRequestTime time.Time

	// requestIntervals stores time between requests for pattern analysis
	requestIntervals []float64

	// intervalMu protects request timing data
	intervalMu sync.Mutex

	// methodCounts tracks HTTP method distribution
	methodCounts map[string]int

	// methodMu protects method counts
	methodMu sync.Mutex

	// pathPatterns tracks request path characteristics
	pathPatterns map[string]int

	// pathMu protects path pattern data
	pathMu sync.Mutex
}

// New creates a new anomaly detector with the specified configuration.
// Returns a fully initialized Detector ready for use.
func New(cfg Config) *Detector {
	// Apply default configuration values where needed
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 100
	}
	if cfg.MinSamples <= 0 {
		cfg.MinSamples = 10
	}
	if cfg.EntropyThreshold <= 0 {
		cfg.EntropyThreshold = 0.8
	}

	// Set z-score threshold based on sensitivity if not explicitly set
	if cfg.ZThreshold <= 0 {
		switch cfg.Sensitivity {
		case Low:
			cfg.ZThreshold = 4.0
		case Medium:
			cfg.ZThreshold = 3.0
		case High:
			cfg.ZThreshold = 2.0
		case Critical:
			cfg.ZThreshold = 1.5
		default:
			cfg.ZThreshold = 3.0
		}
	}

	return &Detector{
		config:            cfg,
		trafficBaseline:   newBaseline(cfg.WindowSize),
		sizeBaseline:      newBaseline(cfg.WindowSize),
		violationBaseline: newBaseline(cfg.WindowSize),
		detectedAnomalies: make([]Anomaly, 0), // Initialize to avoid nil
		requestIntervals:  make([]float64, 0, cfg.WindowSize),
		methodCounts:      make(map[string]int),
		pathPatterns:      make(map[string]int),
	}
}

// newBaseline creates a new baseline with the specified window size.
func newBaseline(windowSize int) *Baseline {
	return &Baseline{
		samples:    make([]float64, 0, windowSize),
		windowSize: windowSize,
	}
}

// RecordTraffic adds a traffic sample and updates the moving baseline.
// Returns an anomaly if the sample is statistically anomalous.
func (d *Detector) RecordTraffic(sample TrafficSample) *Anomaly {
	// Update traffic volume baseline
	volumeValue := float64(sample.Volume)
	trafficZScore := d.trafficBaseline.update(volumeValue)

	// Update size baseline
	sizeValue := float64(sample.Size)
	sizeZScore := d.sizeBaseline.update(sizeValue)

	// Update violation baseline
	violationValue := float64(sample.Violations)
	violationZScore := d.violationBaseline.update(violationValue)

	// Check for anomalies if we have enough samples
	if d.trafficBaseline.sampleCount() >= d.config.MinSamples {
		// Check for traffic spike
		if trafficZScore > d.config.ZThreshold {
			return d.addAnomaly(Anomaly{
				Type:  TrafficSpike,
				Score: trafficZScore,
				Evidence: map[string]interface{}{
					"current_volume":   sample.Volume,
					"baseline_average": d.trafficBaseline.getAverage(),
					"z_score":          trafficZScore,
				},
				Description: "Traffic volume significantly exceeds baseline",
			})
		}

		// Check for traffic drop
		if trafficZScore < -d.config.ZThreshold {
			return d.addAnomaly(Anomaly{
				Type:  TrafficDrop,
				Score: math.Abs(trafficZScore),
				Evidence: map[string]interface{}{
					"current_volume":   sample.Volume,
					"baseline_average": d.trafficBaseline.getAverage(),
					"z_score":          trafficZScore,
				},
				Description: "Traffic volume significantly below baseline",
			})
		}

		// Check for size anomaly
		if math.Abs(sizeZScore) > d.config.ZThreshold {
			return d.addAnomaly(Anomaly{
				Type:  SizeAnomaly,
				Score: math.Abs(sizeZScore),
				Evidence: map[string]interface{}{
					"current_size":     sample.Size,
					"baseline_average": d.sizeBaseline.getAverage(),
					"z_score":          sizeZScore,
				},
				Description: "Request/response size anomaly detected",
			})
		}

		// Check for violation spike
		if violationZScore > d.config.ZThreshold {
			return d.addAnomaly(Anomaly{
				Type:  ViolationSpike,
				Score: violationZScore,
				Evidence: map[string]interface{}{
					"current_violations": sample.Violations,
					"baseline_average":   d.violationBaseline.getAverage(),
					"z_score":            violationZScore,
				},
				Description: "Security violations significantly increased",
			})
		}
	}

	return nil
}

// AnalyzeRequest evaluates a single HTTP request for anomalies.
// Analyzes method, path, and size against established baselines.
func (d *Detector) AnalyzeRequest(method, path string, size int64) (Anomaly, bool) {
	now := time.Now()

	// Track HTTP method distribution
	d.methodMu.Lock()
	d.methodCounts[method]++
	totalRequests := 0
	for _, count := range d.methodCounts {
		totalRequests += count
	}

	// Check for unusual method usage
	_ = float64(d.methodCounts[method]) / float64(totalRequests) // calculated but intentionally unused
	d.methodMu.Unlock()

	// Detect time-based anomaly (irregular intervals)
	d.intervalMu.Lock()
	var timeAnomaly *Anomaly
	if !d.lastRequestTime.IsZero() {
		interval := now.Sub(d.lastRequestTime).Seconds()
		d.requestIntervals = append(d.requestIntervals, interval)

		// Keep only the configured window size
		if len(d.requestIntervals) > d.config.WindowSize {
			d.requestIntervals = d.requestIntervals[len(d.requestIntervals)-d.config.WindowSize:]
		}

		// Check for timing anomaly if we have enough samples
		if len(d.requestIntervals) >= d.config.MinSamples {
			intervalZScore := d.calculateZScore(interval, d.requestIntervals)
			if math.Abs(intervalZScore) > d.config.ZThreshold {
				timeAnomaly = &Anomaly{
					Type:  TimeAnomaly,
					Score: math.Abs(intervalZScore),
					Evidence: map[string]interface{}{
						"current_interval": interval,
						"average_interval": d.calculateMean(d.requestIntervals),
						"z_score":          intervalZScore,
					},
					Description: "Request timing pattern anomaly detected",
				}
			}
		}
	}
	d.lastRequestTime = now
	d.intervalMu.Unlock()

	// Track and analyze path patterns
	d.pathMu.Lock()
	d.pathPatterns[path]++
	pathCount := d.pathPatterns[path]
	_ = len(d.pathPatterns) // totalPaths: tracked but currently unused
	d.pathMu.Unlock()

	// Check for pattern anomaly (new or unusual paths)
	var patternAnomaly *Anomaly
	if totalRequests > d.config.MinSamples {
		// Unseen path or rarely visited path
		if pathCount == 1 || float64(pathCount)/float64(totalRequests) < 0.01 {
			patternAnomaly = &Anomaly{
				Type:  PatternAnomaly,
				Score: 2.5, // Fixed score for pattern anomalies
				Evidence: map[string]interface{}{
					"path":           path,
					"path_count":     pathCount,
					"total_requests": totalRequests,
				},
				Description: "Unusual request path pattern detected",
			}
		}
	}

	// Analyze request size
	sizeValue := float64(size)
	sizeZScore := d.sizeBaseline.update(sizeValue)

	var sizeAnomaly *Anomaly
	if d.sizeBaseline.sampleCount() >= d.config.MinSamples {
		if math.Abs(sizeZScore) > d.config.ZThreshold {
			sizeAnomaly = &Anomaly{
				Type:  SizeAnomaly,
				Score: math.Abs(sizeZScore),
				Evidence: map[string]interface{}{
					"size":             size,
					"baseline_average": d.sizeBaseline.getAverage(),
					"z_score":          sizeZScore,
				},
				Description: "Request size anomaly detected",
			}
		}
	}

	// Return the most significant anomaly found
	if timeAnomaly != nil {
		return *d.addAnomaly(*timeAnomaly), true
	}
	if patternAnomaly != nil {
		return *d.addAnomaly(*patternAnomaly), true
	}
	if sizeAnomaly != nil {
		return *d.addAnomaly(*sizeAnomaly), true
	}

	return Anomaly{}, false
}

// AnalyzeContent calculates entropy and detects anomalies in content.
// Returns the entropy value and any detected anomaly.
func (d *Detector) AnalyzeContent(content []byte) (float64, *Anomaly) {
	entropy := d.calculateEntropy(content)

	// Check for entropy anomaly (too high = likely encrypted/obfuscated)
	if entropy > d.config.EntropyThreshold {
		anomaly := d.addAnomaly(Anomaly{
			Type:  EntropyAnomaly,
			Score: entropy / d.config.EntropyThreshold, // Scale score based on threshold
			Evidence: map[string]interface{}{
				"entropy":           entropy,
				"entropy_threshold": d.config.EntropyThreshold,
				"content_length":    len(content),
			},
			Description: "High entropy content detected (possible encryption or obfuscation)",
		})
		return entropy, anomaly
	}

	return entropy, nil
}

// GetAnomalies returns all detected anomalies.
// Thread-safe access to the anomaly history.
func (d *Detector) GetAnomalies() []Anomaly {
	d.anomalyMu.RLock()
	defer d.anomalyMu.RUnlock()

	// Return a copy to prevent external modification
	result := make([]Anomaly, len(d.detectedAnomalies))
	copy(result, d.detectedAnomalies)
	return result
}

// GetRecentAnomalies returns anomalies from the specified duration.
func (d *Detector) GetRecentAnomalies(since time.Duration) []Anomaly {
	d.anomalyMu.RLock()
	defer d.anomalyMu.RUnlock()

	cutoff := time.Now().Add(-since)
	result := make([]Anomaly, 0)

	for _, anomaly := range d.detectedAnomalies {
		if anomaly.Timestamp.After(cutoff) {
			result = append(result, anomaly)
		}
	}

	return result
}

// ClearAnomalies removes all stored anomalies.
func (d *Detector) ClearAnomalies() {
	d.anomalyMu.Lock()
	defer d.anomalyMu.Unlock()

	d.detectedAnomalies = d.detectedAnomalies[:0]
}

// addAnomaly adds an anomaly to the detector's history and returns it.
// Assigns severity, timestamp, and manages storage limits.
func (d *Detector) addAnomaly(anomaly Anomaly) *Anomaly {
	// Assign severity based on z-score/anomaly score
	anomaly.Severity = d.scoreToSeverity(anomaly.Score)
	anomaly.Timestamp = time.Now()

	d.anomalyMu.Lock()
	defer d.anomalyMu.Unlock()

	d.detectedAnomalies = append(d.detectedAnomalies, anomaly)

	// Limit stored anomalies to prevent memory growth
	maxAnomalies := d.config.WindowSize * 2
	if len(d.detectedAnomalies) > maxAnomalies {
		d.detectedAnomalies = d.detectedAnomalies[len(d.detectedAnomalies)-maxAnomalies:]
	}

	// Return pointer to the stored anomaly
	return &d.detectedAnomalies[len(d.detectedAnomalies)-1]
}

// scoreToSeverity converts a z-score/anomaly score to severity level.
func (d *Detector) scoreToSeverity(score float64) Severity {
	switch {
	case score >= 5.0:
		return CriticalSev
	case score >= 4.0:
		return HighSev
	case score >= 3.0:
		return MediumSev
	case score >= 2.0:
		return LowSev
	default:
		return Info
	}
}

// update adds a new value to the baseline and returns its z-score.
// Implements sliding window average and standard deviation calculation.
func (b *Baseline) update(value float64) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Add new value
	b.samples = append(b.samples, value)
	b.sum += value
	b.sumSq += value * value

	// Remove oldest if window is full
	if len(b.samples) > b.windowSize {
		removed := b.samples[0]
		b.samples = b.samples[1:]
		b.sum -= removed
		b.sumSq -= removed * removed
	}

	// Recalculate statistics
	count := float64(len(b.samples))
	if count > 0 {
		b.movingAverage = b.sum / count
		variance := (b.sumSq / count) - (b.movingAverage * b.movingAverage)
		if variance < 0 {
			variance = 0 // Handle floating point errors
		}
		b.stdDev = math.Sqrt(variance)
	}

	// Calculate and return z-score
	return b.calculateZScore(value)
}

// calculateZScore computes the z-score for a value against this baseline.
// Z-score = (value - mean) / standard deviation
func (b *Baseline) calculateZScore(value float64) float64 {
	if b.stdDev == 0 {
		return 0 // No deviation if no variance
	}
	return (value - b.movingAverage) / b.stdDev
}

// getAverage returns the current moving average.
func (b *Baseline) getAverage() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.movingAverage
}

// sampleCount returns the number of samples in the baseline.
func (b *Baseline) sampleCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.samples)
}

// calculateZScore computes a z-score for a single value against a dataset.
func (d *Detector) calculateZScore(value float64, dataset []float64) float64 {
	if len(dataset) == 0 {
		return 0
	}

	mean := d.calculateMean(dataset)
	stdDev := d.calculateStdDev(dataset, mean)

	if stdDev == 0 {
		return 0
	}

	return (value - mean) / stdDev
}

// calculateMean computes the arithmetic mean of a dataset.
func (d *Detector) calculateMean(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}

	var sum float64
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

// calculateStdDev computes the standard deviation of a dataset.
func (d *Detector) calculateStdDev(data []float64, mean float64) float64 {
	if len(data) == 0 {
		return 0
	}

	var sumSqDiff float64
	for _, v := range data {
		diff := v - mean
		sumSqDiff += diff * diff
	}

	variance := sumSqDiff / float64(len(data))
	return math.Sqrt(variance)
}

// calculateEntropy computes Shannon entropy of byte data.
// Higher entropy indicates more randomness (e.g., encrypted data).
// Formula: H(X) = -Σ P(x) × log₂(P(x))
func (d *Detector) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	var frequencies [256]int
	for _, b := range data {
		frequencies[b]++
	}

	// Calculate Shannon entropy
	var entropy float64
	length := float64(len(data))

	for _, freq := range frequencies {
		if freq > 0 {
			probability := float64(freq) / length
			entropy -= probability * math.Log2(probability)
		}
	}

	// Normalize to 0-1 range (max entropy for bytes is 8)
	return entropy / 8.0
}

// GetBaselineStats returns current baseline statistics for debugging/monitoring.
func (d *Detector) GetBaselineStats() map[string]interface{} {
	return map[string]interface{}{
		"traffic_average":   d.trafficBaseline.getAverage(),
		"traffic_samples":   d.trafficBaseline.sampleCount(),
		"size_average":      d.sizeBaseline.getAverage(),
		"size_samples":      d.sizeBaseline.sampleCount(),
		"violation_average": d.violationBaseline.getAverage(),
		"violation_samples": d.violationBaseline.sampleCount(),
		"total_anomalies":   len(d.detectedAnomalies),
		"configured_window": d.config.WindowSize,
		"z_threshold":       d.config.ZThreshold,
	}
}

// IsReady returns true if the detector has enough samples for anomaly detection.
func (d *Detector) IsReady() bool {
	return d.trafficBaseline.sampleCount() >= d.config.MinSamples
}

// Reset clears all baselines and detected anomalies.
func (d *Detector) Reset() {
	// Reset baselines
	d.trafficBaseline = newBaseline(d.config.WindowSize)
	d.sizeBaseline = newBaseline(d.config.WindowSize)
	d.violationBaseline = newBaseline(d.config.WindowSize)

	// Clear anomalies
	d.ClearAnomalies()

	// Reset timing data
	d.intervalMu.Lock()
	d.requestIntervals = d.requestIntervals[:0]
	d.lastRequestTime = time.Time{}
	d.intervalMu.Unlock()

	// Reset method counts
	d.methodMu.Lock()
	d.methodCounts = make(map[string]int)
	d.methodMu.Unlock()

	// Reset path patterns
	d.pathMu.Lock()
	d.pathPatterns = make(map[string]int)
	d.pathMu.Unlock()
}

// GetMethodsDistribution returns the current distribution of HTTP methods.
func (d *Detector) GetMethodsDistribution() map[string]float64 {
	d.methodMu.Lock()
	defer d.methodMu.Unlock()

	total := 0
	for _, count := range d.methodCounts {
		total += count
	}

	if total == 0 {
		return map[string]float64{}
	}

	distribution := make(map[string]float64)
	for method, count := range d.methodCounts {
		distribution[method] = float64(count) / float64(total)
	}

	return distribution
}

// GetTopPaths returns the most frequently accessed paths.
func (d *Detector) GetTopPaths(n int) []struct {
	Path  string
	Count int
} {
	d.pathMu.Lock()
	defer d.pathMu.Unlock()

	// Convert map to slice for sorting
	type pathCount struct {
		Path  string
		Count int
	}

	paths := make([]pathCount, 0, len(d.pathPatterns))
	for path, count := range d.pathPatterns {
		paths = append(paths, pathCount{Path: path, Count: count})
	}

	// Simple bubble sort for top N
	for i := 0; i < len(paths); i++ {
		for j := i + 1; j < len(paths); j++ {
			if paths[j].Count > paths[i].Count {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}

	// Return top n
	if n > len(paths) {
		n = len(paths)
	}

	// Convert from []pathCount to anonymous return type
	result := make([]struct {
		Path  string
		Count int
	}, n)
	for i := 0; i < n; i++ {
		result[i].Path = paths[i].Path
		result[i].Count = paths[i].Count
	}

	return result
}

// AnalyzePatterns performs pattern-based anomaly detection on strings.
// Detects suspicious patterns like encoding sequences, special char clusters, etc.
func (d *Detector) AnalyzePatterns(input string) []Anomaly {
	anomalies := make([]Anomaly, 0)

	// Check for excessive special characters
	specialCharRatio := d.countSpecialChars(input) / float64(len(input))
	if specialCharRatio > 0.3 {
		anomalies = append(anomalies, *d.addAnomaly(Anomaly{
			Type:  PatternAnomaly,
			Score: specialCharRatio * 5, // Scale up
			Evidence: map[string]interface{}{
				"special_char_ratio": specialCharRatio,
				"input_length":       len(input),
			},
			Description: "Excessive special characters detected",
		}))
	}

	// Check for repeated characters (possible fuzzing)
	if d.hasRepeatedChars(input, 5) {
		anomalies = append(anomalies, *d.addAnomaly(Anomaly{
			Type:  PatternAnomaly,
			Score: 3.0,
			Evidence: map[string]interface{}{
				"pattern":       "repeated_characters",
				"input_preview": d.truncateString(input, 50),
			},
			Description: "Repeated character pattern detected (possible fuzzing)",
		}))
	}

	// Check for path traversal patterns
	if strings.Contains(input, "..") || strings.Contains(input, "../") {
		anomalies = append(anomalies, *d.addAnomaly(Anomaly{
			Type:  PatternAnomaly,
			Score: 4.0,
			Evidence: map[string]interface{}{
				"pattern":       "path_traversal",
				"input_preview": d.truncateString(input, 50),
			},
			Description: "Path traversal pattern detected",
		}))
	}

	return anomalies
}

// countSpecialChars returns the count of non-alphanumeric characters.
func (d *Detector) countSpecialChars(s string) float64 {
	var count float64
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' || r == '-' || r == '_') {
			count++
		}
	}
	return count
}

// hasRepeatedChars checks if a string has character repeated n or more times consecutively.
func (d *Detector) hasRepeatedChars(s string, n int) bool {
	if len(s) < n {
		return false
	}

	for i := 0; i <= len(s)-n; i++ {
		allSame := true
		for j := 1; j < n; j++ {
			if s[i] != s[i+j] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

// truncateString truncates a string to maxLen with ellipsis.
func (d *Detector) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Validate ensures the detector configuration is valid.
func (c Config) Validate() error {
	if c.WindowSize <= 0 {
		return newValidationError("WindowSize must be positive")
	}
	if c.MinSamples < 0 {
		return newValidationError("MinSamples must be non-negative")
	}
	if c.EntropyThreshold < 0 || c.EntropyThreshold > 1 {
		return newValidationError("EntropyThreshold must be between 0 and 1")
	}
	if c.ZThreshold < 0 {
		return newValidationError("ZThreshold must be non-negative")
	}
	return nil
}

// validationError represents a configuration validation error.
type validationError struct {
	msg string
}

// Error implements the error interface.
func (e *validationError) Error() string {
	return e.msg
}

// newValidationError creates a new validation error with the given message.
func newValidationError(msg string) error {
	return &validationError{msg: msg}
}
