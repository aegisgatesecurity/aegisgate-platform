// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Data Drift Monitoring (P2)
// =========================================================================
//
// drift.go implements Population Stability Index (PSI) and KL divergence
// monitoring for the benign corpus. These are standard statistical measures
// used in production ML systems to detect when input distributions shift,
// which can degrade model performance.
//
// Key concepts:
//   - PSI > 0.1: minor drift (informational)
//   - PSI > 0.25: significant drift (investigate)
//   - PSI > 0.5: major drift (retraining may be needed)
//   - KL divergence: asymmetric measure of distribution shift per feature
//
// The monitor tracks drift across multiple feature dimensions:
//   - Input length distribution
//   - Character frequency distribution
//   - Pattern category distribution
//   - Score distribution (from ML model)
//
// =========================================================================

package ml

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"
)

// DriftLevel represents the severity of data drift.
type DriftLevel string

const (
	DriftNone        DriftLevel = "none"        // PSI < 0.1
	DriftMinor       DriftLevel = "minor"       // PSI 0.1-0.25
	DriftSignificant DriftLevel = "significant" // PSI 0.25-0.5
	DriftMajor       DriftLevel = "major"       // PSI > 0.5
)

// DriftResult holds the drift analysis result for a single feature.
type DriftResult struct {
	Feature      string     `json:"feature"`
	PSI          float64    `json:"psi"`
	KLDivergence float64    `json:"kl_divergence"`
	Level        DriftLevel `json:"level"`
	BaselineN    int        `json:"baseline_n"`
	CurrentN     int        `json:"current_n"`
	Timestamp    string     `json:"timestamp"`
}

// DriftMonitorConfig configures the drift monitor.
type DriftMonitorConfig struct {
	// BinCount is the number of bins for histogram comparison.
	// Default: 10.
	BinCount int

	// CheckInterval is how often drift is automatically checked.
	// Default: 1 hour.
	CheckInterval time.Duration

	// PSIThresholds define the drift severity thresholds.
	// Keys: "minor", "significant", "major".
	PSIThresholds map[string]float64
}

// DefaultDriftMonitorConfig returns sensible defaults.
func DefaultDriftMonitorConfig() DriftMonitorConfig {
	return DriftMonitorConfig{
		BinCount:      10,
		CheckInterval: time.Hour,
		PSIThresholds: map[string]float64{
			"minor":       0.1,
			"significant": 0.25,
			"major":       0.5,
		},
	}
}

// FeatureDistribution represents a binned distribution for a feature.
type FeatureDistribution struct {
	Feature string    `json:"feature"`
	Bins    []Bin     `json:"bins"`
	Count   int       `json:"count"`
	Mean    float64   `json:"mean"`
	StdDev  float64   `json:"std_dev"`
	Updated time.Time `json:"updated"`
}

// Bin represents a single bin in a histogram distribution.
type Bin struct {
	Lower  float64 `json:"lower"`
	Upper  float64 `json:"upper"`
	Count  int     `json:"count"`
	Weight float64 `json:"weight"` // proportion (count/total)
}

// DriftMonitor monitors data drift across multiple feature dimensions.
type DriftMonitor struct {
	mu       sync.RWMutex
	config   DriftMonitorConfig
	baseline map[string]*FeatureDistribution // feature -> baseline distribution
	current  map[string]*FeatureDistribution // feature -> current distribution
	history  []DriftResult                   // history of drift checks
}

// NewDriftMonitor creates a new drift monitor with the given config.
func NewDriftMonitor(config DriftMonitorConfig) *DriftMonitor {
	if config.BinCount <= 0 {
		config.BinCount = 10
	}
	if config.PSIThresholds == nil {
		config.PSIThresholds = map[string]float64{
			"minor":       0.1,
			"significant": 0.25,
			"major":       0.5,
		}
	}
	return &DriftMonitor{
		config:   config,
		baseline: make(map[string]*FeatureDistribution),
		current:  make(map[string]*FeatureDistribution),
		history:  make([]DriftResult, 0),
	}
}

// SetBaseline sets the baseline distribution for a feature.
// This should be called with the initial benign corpus distribution.
func (dm *DriftMonitor) SetBaseline(feature string, values []float64) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dist := buildDistribution(feature, values, dm.config.BinCount)
	dm.baseline[feature] = dist
}

// Observe adds a value to the current distribution for a feature.
func (dm *DriftMonitor) Observe(feature string, value float64) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dist, ok := dm.current[feature]
	if !ok {
		dist = &FeatureDistribution{
			Feature: feature,
			Bins:    make([]Bin, dm.config.BinCount),
			Count:   0,
		}
		dm.current[feature] = dist
	}

	// Find or create bin
	binIdx := dm.findBin(dist, value)
	if binIdx >= 0 && binIdx < len(dist.Bins) {
		dist.Bins[binIdx].Count++
		dist.Count++
	}
	dist.Updated = time.Now().UTC()
}

// ObserveBatch adds multiple values to the current distribution.
func (dm *DriftMonitor) ObserveBatch(feature string, values []float64) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	for _, v := range values {
		dm.observeLocked(feature, v)
	}
}

// CheckDrift calculates PSI and KL divergence for all features.
func (dm *DriftMonitor) CheckDrift() []DriftResult {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	var results []DriftResult
	for feature := range dm.baseline {
		baseline := dm.baseline[feature]
		current, ok := dm.current[feature]
		if !ok || current.Count == 0 {
			results = append(results, DriftResult{
				Feature:   feature,
				PSI:       0,
				Level:     DriftNone,
				BaselineN: baseline.Count,
				CurrentN:  0,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			continue
		}

		psi := calculatePSI(baseline, current, dm.config.BinCount)
		klDiv := calculateKLDivergence(baseline, current, dm.config.BinCount)
		level := classifyDrift(psi, dm.config.PSIThresholds)

		result := DriftResult{
			Feature:      feature,
			PSI:          psi,
			KLDivergence: klDiv,
			Level:        level,
			BaselineN:    baseline.Count,
			CurrentN:     current.Count,
			Timestamp:    time.Now().UTC().Format(time.RFC3339),
		}

		results = append(results, result)
		dm.history = append(dm.history, result)

		// Keep last 1000 drift checks
		if len(dm.history) > 1000 {
			dm.history = dm.history[len(dm.history)-1000:]
		}
	}

	return results
}

// GetHistory returns the last N drift check results.
func (dm *DriftMonitor) GetHistory(n int) []DriftResult {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if n > len(dm.history) {
		n = len(dm.history)
	}
	if n <= 0 {
		return nil
	}

	result := make([]DriftResult, n)
	copy(result, dm.history[len(dm.history)-n:])
	return result
}

// ResetCurrent resets the current distributions (e.g., after a drift alert).
func (dm *DriftMonitor) ResetCurrent() {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.current = make(map[string]*FeatureDistribution)
}

// ServeHTTP implements http.Handler for GET /api/v1/ml/drift.
func (dm *DriftMonitor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	results := dm.CheckDrift()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"drift_results": results,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
}

// observeLocked adds a value without acquiring the lock (caller holds lock).
func (dm *DriftMonitor) observeLocked(feature string, value float64) {
	dist, ok := dm.current[feature]
	if !ok {
		dist = &FeatureDistribution{
			Feature: feature,
			Bins:    make([]Bin, dm.config.BinCount),
			Count:   0,
		}
		dm.current[feature] = dist
	}

	binIdx := dm.findBin(dist, value)
	if binIdx >= 0 && binIdx < len(dist.Bins) {
		dist.Bins[binIdx].Count++
		dist.Count++
	}
	dist.Updated = time.Now().UTC()
}

// findBin returns the bin index for a value, using baseline bounds if available.
func (dm *DriftMonitor) findBin(dist *FeatureDistribution, value float64) int {
	// If we have a baseline, use its bin boundaries
	if baseline, ok := dm.baseline[dist.Feature]; ok && len(baseline.Bins) > 0 {
		for i, bin := range baseline.Bins {
			if value >= bin.Lower && value < bin.Upper {
				return i
			}
		}
		// Value falls in the last bin (inclusive upper bound)
		if len(baseline.Bins) > 0 && value >= baseline.Bins[len(baseline.Bins)-1].Lower {
			return len(baseline.Bins) - 1
		}
	}

	// Fallback: equal-width bins based on current data range
	n := len(dist.Bins)
	if n == 0 {
		return -1
	}
	return int(value * float64(n)) // assumes normalized 0-1 range
}

// calculatePSI computes Population Stability Index between two distributions.
// PSI = sum((actual_pct - expected_pct) * ln(actual_pct / expected_pct))
func calculatePSI(baseline, current *FeatureDistribution, binCount int) float64 {
	// Rebuild both distributions with the same bin boundaries
	binWidth := 1.0 / float64(binCount)

	baselineWeights := make([]float64, binCount)
	currentWeights := make([]float64, binCount)

	baselineTotal := float64(baseline.Count)
	currentTotal := float64(current.Count)

	if baselineTotal == 0 || currentTotal == 0 {
		return 0
	}

	// Use baseline bin structure
	for i := 0; i < binCount; i++ {
		// Baseline weight
		if i < len(baseline.Bins) {
			baselineWeights[i] = float64(baseline.Bins[i].Count) / baselineTotal
		} else {
			baselineWeights[i] = binWidth
		}

		// Current weight
		if i < len(current.Bins) {
			currentWeights[i] = float64(current.Bins[i].Count) / currentTotal
		}

		// Floor both to epsilon to avoid log(0)
		epsilon := 0.0001
		if baselineWeights[i] < epsilon {
			baselineWeights[i] = epsilon
		}
		if currentWeights[i] < epsilon {
			currentWeights[i] = epsilon
		}
	}

	// PSI = sum((p_i - q_i) * ln(p_i / q_i))
	psi := 0.0
	for i := 0; i < binCount; i++ {
		psi += (currentWeights[i] - baselineWeights[i]) * math.Log(currentWeights[i]/baselineWeights[i])
	}

	return psi
}

// calculateKLDivergence computes KL(D_current || D_baseline).
// KL(P || Q) = sum(P(x) * ln(P(x) / Q(x)))
func calculateKLDivergence(baseline, current *FeatureDistribution, binCount int) float64 {
	baselineWeights := make([]float64, binCount)
	currentWeights := make([]float64, binCount)

	baselineTotal := float64(baseline.Count)
	currentTotal := float64(current.Count)

	if baselineTotal == 0 || currentTotal == 0 {
		return 0
	}

	epsilon := 0.0001

	for i := 0; i < binCount; i++ {
		if i < len(baseline.Bins) {
			baselineWeights[i] = float64(baseline.Bins[i].Count) / baselineTotal
		} else {
			baselineWeights[i] = epsilon
		}
		if i < len(current.Bins) {
			currentWeights[i] = float64(current.Bins[i].Count) / currentTotal
		} else {
			currentWeights[i] = epsilon
		}

		if baselineWeights[i] < epsilon {
			baselineWeights[i] = epsilon
		}
		if currentWeights[i] < epsilon {
			currentWeights[i] = epsilon
		}
	}

	kl := 0.0
	for i := 0; i < binCount; i++ {
		kl += currentWeights[i] * math.Log(currentWeights[i]/baselineWeights[i])
	}

	return kl
}

// classifyDrift maps a PSI value to a drift level.
func classifyDrift(psi float64, thresholds map[string]float64) DriftLevel {
	minor := thresholds["minor"]
	significant := thresholds["significant"]
	major := thresholds["major"]

	switch {
	case psi >= major:
		return DriftMajor
	case psi >= significant:
		return DriftSignificant
	case psi >= minor:
		return DriftMinor
	default:
		return DriftNone
	}
}

// buildDistribution creates a FeatureDistribution from raw values.
func buildDistribution(feature string, values []float64, binCount int) *FeatureDistribution {
	if len(values) == 0 {
		return &FeatureDistribution{
			Feature: feature,
			Bins:    make([]Bin, binCount),
			Count:   0,
		}
	}

	// Find min/max
	minVal, maxVal := values[0], values[0]
	sum, sumSq := 0.0, 0.0
	for _, v := range values {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
		sum += v
		sumSq += v * v
	}

	mean := sum / float64(len(values))
	variance := sumSq/float64(len(values)) - mean*mean
	if variance < 0 {
		variance = 0
	}

	binWidth := (maxVal - minVal) / float64(binCount)
	if binWidth == 0 {
		binWidth = 1.0 / float64(binCount)
		minVal = 0
		maxVal = 1
	}

	bins := make([]Bin, binCount)
	for i := 0; i < binCount; i++ {
		bins[i] = Bin{
			Lower: minVal + float64(i)*binWidth,
			Upper: minVal + float64(i+1)*binWidth,
			Count: 0,
		}
	}

	// Assign values to bins
	for _, v := range values {
		idx := int((v - minVal) / binWidth)
		if idx >= binCount {
			idx = binCount - 1
		}
		if idx < 0 {
			idx = 0
		}
		bins[idx].Count++
	}

	// Calculate weights
	total := float64(len(values))
	for i := range bins {
		bins[i].Weight = float64(bins[i].Count) / total
	}

	return &FeatureDistribution{
		Feature: feature,
		Bins:    bins,
		Count:   len(values),
		Mean:    mean,
		StdDev:  math.Sqrt(variance),
		Updated: time.Now().UTC(),
	}
}

// String returns a human-readable summary of a DriftResult.
func (r DriftResult) String() string {
	return fmt.Sprintf("%s: PSI=%.4f KL=%.4f level=%s (baseline=%d current=%d)",
		r.Feature, r.PSI, r.KLDivergence, r.Level, r.BaselineN, r.CurrentN)
}
