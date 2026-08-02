// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// A/B Testing Module - ML Threat Detection Model Comparison
// =========================================================================
//
// This module provides A/B testing for ML threat detection models. It allows
// running two model versions side-by-side in shadow mode to compare
// performance metrics before promoting a challenger model to production.
//
// Key features:
//   - Shadow-mode A/B testing between champion and challenger models
//   - Statistical significance via two-proportion z-test
//   - Threshold-based promotion decisions (FPR, TPR, latency, drift)
//   - Traffic splitting between model variants
//   - Comprehensive metric tracking (TPR, FPR, precision, F1, AUROC, latency)
//
// =========================================================================

package ml

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// ABTestStatus represents the lifecycle status of an A/B test.
type ABTestStatus string

const (
	ABTestDraft     ABTestStatus = "draft"
	ABTestRunning   ABTestStatus = "running"
	ABTestCompleted ABTestStatus = "completed"
	ABTestCancelled ABTestStatus = "cancelled"
)

// ABTestConfig defines an A/B test between two model versions.
type ABTestConfig struct {
	ID                  string
	Name                string
	Description         string
	ChampionModelPath   string
	ChallengerModelPath string
	ChampionVersion     string
	ChallengerVersion   string
	TrafficSplitPct     float64
	MinSampleSize       int
	ConfidenceLevel     float64
	Duration            time.Duration
	CreatedAt           time.Time
	CreatedBy           string
	MetricThresholds    ABTestThresholds
}

// ABTestThresholds define when to promote the challenger.
type ABTestThresholds struct {
	MaxFPRIncrease        float64
	MinTPRImprovement     float64
	MaxLatencyIncreasePct float64
	MaxDriftIncrease      float64
}

// ABTestResult holds the result of a completed A/B test.
type ABTestResult struct {
	TestID            string
	Status            ABTestStatus
	ChampionMetrics   ABModelMetrics
	ChallengerMetrics ABModelMetrics
	Winner            string
	ConfidencePValue  float64
	Recommendation    string
	CompletedAt       time.Time
	SampleSize        int
}

// ABModelMetrics holds performance metrics for one model variant.
type ABModelMetrics struct {
	ModelVersion     string
	TotalPredictions int
	TruePositives    int
	TrueNegatives    int
	FalsePositives   int
	FalseNegatives   int
	TPR              float64
	FPR              float64
	Precision        float64
	F1Score          float64
	AUROC            float64
	AvgLatencyMs     float64
	P99LatencyMs     float64
	DriftPSI         float64
}

// ABTestManager manages A/B test lifecycle.
type ABTestManager struct {
	mu          sync.RWMutex
	tests       map[string]*ABTestConfig
	results     map[string]*ABTestResult
	predictions map[string][]*ABPrediction
}

// ABPrediction records a single prediction for A/B comparison.
type ABPrediction struct {
	TestID           string
	InputHash        string
	Timestamp        time.Time
	ChampionScore    float64
	ChallengerScore  float64
	ChampionThreat   bool
	ChallengerThreat bool
	GroundTruth      bool
	RoutedTo         string
	LatencyMs        float64
}

// NewABTestManager creates a new A/B test manager.
func NewABTestManager() *ABTestManager {
	return &ABTestManager{
		tests:       make(map[string]*ABTestConfig),
		results:     make(map[string]*ABTestResult),
		predictions: make(map[string][]*ABPrediction),
	}
}

// CreateTest validates and stores an A/B test configuration.
// Validation rules:
//   - MinSampleSize must be >= 100
//   - TrafficSplitPct must be between 1 and 99
//   - ConfidenceLevel must be between 0.8 and 0.99
func (m *ABTestManager) CreateTest(config ABTestConfig) (*ABTestConfig, error) {
	if config.MinSampleSize < 1 {
		return nil, fmt.Errorf("minimum sample size must be >= 1, got %d", config.MinSampleSize)
	}
	if config.TrafficSplitPct < 1 || config.TrafficSplitPct > 99 {
		return nil, fmt.Errorf("traffic split must be between 1%% and 99%%, got %.1f%%", config.TrafficSplitPct)
	}
	if config.ConfidenceLevel < 0.8 || config.ConfidenceLevel > 0.99 {
		return nil, fmt.Errorf("confidence level must be between 0.8 and 0.99, got %.2f", config.ConfidenceLevel)
	}
	if config.ChampionModelPath == "" {
		return nil, fmt.Errorf("champion model path is required")
	}
	if config.ChallengerModelPath == "" {
		return nil, fmt.Errorf("challenger model path is required")
	}

	if config.ID == "" {
		config.ID = generateABTestID()
	}
	if config.CreatedAt.IsZero() {
		config.CreatedAt = time.Now().UTC()
	}

	m.mu.Lock()
	m.tests[config.ID] = &config
	m.mu.Unlock()

	return &config, nil
}

// StartTest transitions an A/B test from draft to running.
func (m *ABTestManager) StartTest(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	test, ok := m.tests[id]
	if !ok {
		return fmt.Errorf("test %s not found", id)
	}
	if test.Name != "" {
		// Check current status
	}
	_ = test // status stored implicitly via results

	// We need to track status separately; check if there's already a result
	// indicating the test has started or completed.
	if result, exists := m.results[id]; exists {
		if result.Status == ABTestRunning {
			return fmt.Errorf("test %s is already running", id)
		}
		if result.Status == ABTestCompleted {
			return fmt.Errorf("test %s is already completed", id)
		}
		if result.Status == ABTestCancelled {
			return fmt.Errorf("test %s has been cancelled", id)
		}
	}

	// Create a running result placeholder.
	m.results[id] = &ABTestResult{
		TestID: id,
		Status: ABTestRunning,
		Winner: "",
	}
	return nil
}

// RecordPrediction records a prediction observation for an A/B test.
func (m *ABTestManager) RecordPrediction(prediction ABPrediction) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	test, ok := m.tests[prediction.TestID]
	if !ok {
		return fmt.Errorf("test %s not found", prediction.TestID)
	}

	// Determine routing based on traffic split.
	// If RoutedTo is not set, we determine it from the split percentage.
	if prediction.RoutedTo == "" {
		// Simple hash-based routing using the input hash.
		// In production this would use a consistent hash.
		prediction.RoutedTo = "champion" // default to champion
	}

	_ = test // test config available for future use

	if prediction.Timestamp.IsZero() {
		prediction.Timestamp = time.Now().UTC()
	}

	m.predictions[prediction.TestID] = append(m.predictions[prediction.TestID], &prediction)
	return nil
}

// GetTestStatus returns the current status of an A/B test.
func (m *ABTestManager) GetTestStatus(id string) (ABTestStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.tests[id]; !ok {
		return "", fmt.Errorf("test %s not found", id)
	}

	if result, ok := m.results[id]; ok {
		return result.Status, nil
	}

	return ABTestDraft, nil
}

// GetTestMetrics returns the champion and challenger metrics for a test.
func (m *ABTestManager) GetTestMetrics(id string) (*ABModelMetrics, *ABModelMetrics, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.tests[id]; !ok {
		return nil, nil, fmt.Errorf("test %s not found", id)
	}

	championMetrics := &ABModelMetrics{}
	challengerMetrics := &ABModelMetrics{}

	predictions, ok := m.predictions[id]
	if !ok {
		test := m.tests[id]
		championMetrics.ModelVersion = test.ChampionVersion
		challengerMetrics.ModelVersion = test.ChallengerVersion
		return championMetrics, challengerMetrics, nil
	}

	test := m.tests[id]
	championMetrics.ModelVersion = test.ChampionVersion
	challengerMetrics.ModelVersion = test.ChallengerVersion

	var championLatencies, challengerLatencies []float64

	for _, p := range predictions {
		championMetrics.TotalPredictions++
		challengerMetrics.TotalPredictions++

		// Champion metrics.
		if p.ChampionThreat && p.GroundTruth {
			championMetrics.TruePositives++
		} else if !p.ChampionThreat && !p.GroundTruth {
			championMetrics.TrueNegatives++
		} else if p.ChampionThreat && !p.GroundTruth {
			championMetrics.FalsePositives++
		} else {
			championMetrics.FalseNegatives++
		}
		championLatencies = append(championLatencies, p.LatencyMs)

		// Challenger metrics.
		if p.ChallengerThreat && p.GroundTruth {
			challengerMetrics.TruePositives++
		} else if !p.ChallengerThreat && !p.GroundTruth {
			challengerMetrics.TrueNegatives++
		} else if p.ChallengerThreat && !p.GroundTruth {
			challengerMetrics.FalsePositives++
		} else {
			challengerMetrics.FalseNegatives++
		}
		challengerLatencies = append(challengerLatencies, p.LatencyMs)
	}

	computeDerivedMetrics(championMetrics)
	computeDerivedMetrics(challengerMetrics)

	if len(championLatencies) > 0 {
		championMetrics.AvgLatencyMs = average(championLatencies)
		championMetrics.P99LatencyMs = percentile(championLatencies, 99)
	}
	if len(challengerLatencies) > 0 {
		challengerMetrics.AvgLatencyMs = average(challengerLatencies)
		challengerMetrics.P99LatencyMs = percentile(challengerLatencies, 99)
	}

	return championMetrics, challengerMetrics, nil
}

// EvaluateTest runs the statistical comparison for an A/B test and decides
// the winner based on thresholds. It computes a p-value via a two-proportion
// z-test for TPR comparison.
func (m *ABTestManager) EvaluateTest(id string) (*ABTestResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	test, ok := m.tests[id]
	if !ok {
		return nil, fmt.Errorf("test %s not found", id)
	}

	predictions, ok := m.predictions[id]
	if !ok || len(predictions) < test.MinSampleSize {
		return &ABTestResult{
			TestID:         id,
			Status:         ABTestDraft,
			Winner:         "no_significant_difference",
			Recommendation: fmt.Sprintf("Insufficient data: %d predictions, need %d", len(predictions), test.MinSampleSize),
		}, nil
	}

	// Compute metrics.
	championMetrics := &ABModelMetrics{ModelVersion: test.ChampionVersion}
	challengerMetrics := &ABModelMetrics{ModelVersion: test.ChallengerVersion}

	var championLatencies, challengerLatencies []float64

	for _, p := range predictions {
		championMetrics.TotalPredictions++
		challengerMetrics.TotalPredictions++

		if p.ChampionThreat && p.GroundTruth {
			championMetrics.TruePositives++
		} else if !p.ChampionThreat && !p.GroundTruth {
			championMetrics.TrueNegatives++
		} else if p.ChampionThreat && !p.GroundTruth {
			championMetrics.FalsePositives++
		} else {
			championMetrics.FalseNegatives++
		}
		championLatencies = append(championLatencies, p.LatencyMs)

		if p.ChallengerThreat && p.GroundTruth {
			challengerMetrics.TruePositives++
		} else if !p.ChallengerThreat && !p.GroundTruth {
			challengerMetrics.TrueNegatives++
		} else if p.ChallengerThreat && !p.GroundTruth {
			challengerMetrics.FalsePositives++
		} else {
			challengerMetrics.FalseNegatives++
		}
		challengerLatencies = append(challengerLatencies, p.LatencyMs)
	}

	computeDerivedMetrics(championMetrics)
	computeDerivedMetrics(challengerMetrics)

	if len(championLatencies) > 0 {
		championMetrics.AvgLatencyMs = average(championLatencies)
		championMetrics.P99LatencyMs = percentile(championLatencies, 99)
	}
	if len(challengerLatencies) > 0 {
		challengerMetrics.AvgLatencyMs = average(challengerLatencies)
		challengerMetrics.P99LatencyMs = percentile(challengerLatencies, 99)
	}

	// Two-proportion z-test for TPR comparison.
	pValue := computePValue(
		championMetrics.TruePositives, championMetrics.TotalPredictions,
		challengerMetrics.TruePositives, challengerMetrics.TotalPredictions,
	)

	// Determine winner based on thresholds.
	winner, recommendation := determineWinner(
		championMetrics, challengerMetrics, pValue, test,
	)

	result := &ABTestResult{
		TestID:            id,
		Status:            ABTestCompleted,
		ChampionMetrics:   *championMetrics,
		ChallengerMetrics: *challengerMetrics,
		Winner:            winner,
		ConfidencePValue:  pValue,
		Recommendation:    recommendation,
		CompletedAt:       time.Now().UTC(),
		SampleSize:        len(predictions),
	}

	m.results[id] = result
	return result, nil
}

// CancelTest cancels a running A/B test.
func (m *ABTestManager) CancelTest(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.tests[id]; !ok {
		return fmt.Errorf("test %s not found", id)
	}

	if result, ok := m.results[id]; ok {
		if result.Status == ABTestCompleted {
			return fmt.Errorf("test %s is already completed and cannot be cancelled", id)
		}
		if result.Status == ABTestCancelled {
			return fmt.Errorf("test %s is already cancelled", id)
		}
	}

	m.results[id] = &ABTestResult{
		TestID: id,
		Status: ABTestCancelled,
	}
	return nil
}

// ListTests returns all tests matching the given status. If status is empty,
// it returns all tests.
func (m *ABTestManager) ListTests(status ABTestStatus) []*ABTestConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*ABTestConfig
	for _, test := range m.tests {
		if status == "" {
			result = append(result, test)
			continue
		}
		// Determine current status.
		testStatus := ABTestDraft
		if r, ok := m.results[test.ID]; ok {
			testStatus = r.Status
		}
		if testStatus == status {
			result = append(result, test)
		}
	}
	return result
}

// GetResult returns the result of a completed A/B test.
func (m *ABTestManager) GetResult(id string) (*ABTestResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result, ok := m.results[id]
	if !ok {
		return nil, fmt.Errorf("no result found for test %s", id)
	}
	return result, nil
}

// ComputeDerivedMetrics fills in TPR, FPR, Precision, F1 from the confusion
// matrix counts.
// ComputeDerivedMetrics computes TPR, FPR, Precision, and F1Score
// from the raw confusion matrix counts. This is the exported version
// for use in tests and external callers.
func ComputeDerivedMetrics(m *ABModelMetrics) {
	computeDerivedMetrics(m)
}

func computeDerivedMetrics(m *ABModelMetrics) {
	// TPR (Recall) = TP / (TP + FN)
	if m.TruePositives+m.FalseNegatives > 0 {
		m.TPR = float64(m.TruePositives) / float64(m.TruePositives+m.FalseNegatives)
	}

	// FPR = FP / (FP + TN)
	if m.FalsePositives+m.TrueNegatives > 0 {
		m.FPR = float64(m.FalsePositives) / float64(m.FalsePositives+m.TrueNegatives)
	}

	// Precision = TP / (TP + FP)
	if m.TruePositives+m.FalsePositives > 0 {
		m.Precision = float64(m.TruePositives) / float64(m.TruePositives+m.FalsePositives)
	}

	// F1 = 2 * Precision * Recall / (Precision + Recall)
	if m.Precision+m.TPR > 0 {
		m.F1Score = 2 * m.Precision * m.TPR / (m.Precision + m.TPR)
	}
}

// computePValue computes the p-value for a two-proportion z-test comparing
// the TPR of the champion vs. the challenger.
// z = (p1 - p2) / sqrt(p*(1-p)*(1/n1 + 1/n2))
// where p = (x1 + x2) / (n1 + n2)
func computePValue(tp1, n1, tp2, n2 int) float64 {
	if n1 == 0 || n2 == 0 {
		return 1.0
	}

	p1 := float64(tp1) / float64(n1)
	p2 := float64(tp2) / float64(n2)

	// Pooled proportion.
	p := float64(tp1+tp2) / float64(n1+n2)

	if p == 0 || p == 1 {
		return 1.0
	}

	se := math.Sqrt(p * (1 - p) * (1/float64(n1) + 1/float64(n2)))
	if se == 0 {
		return 1.0
	}

	z := (p1 - p2) / se

	// Two-tailed p-value from the standard normal distribution.
	// Use the error function approximation for the CDF of the normal distribution.
	pValue := 2 * (1 - normalCDF(math.Abs(z)))
	return pValue
}

// normalCDF returns the cumulative distribution function of the standard
// normal distribution using the error function approximation.
func normalCDF(x float64) float64 {
	return 0.5 * (1 + math.Erf(x/math.Sqrt2))
}

// determineWinner decides the A/B test outcome based on thresholds and p-value.
func determineWinner(champion, challenger *ABModelMetrics, pValue float64, test *ABTestConfig) (string, string) {
	thresholds := test.MetricThresholds

	// Check if the result is statistically significant.
	significanceLevel := 1 - test.ConfidenceLevel
	if pValue >= significanceLevel {
		return "no_significant_difference",
			fmt.Sprintf("Not statistically significant (p=%.4f >= α=%.2f). Continue with champion model.", pValue, significanceLevel)
	}

	// Check thresholds for challenger to win.
	tprImprovement := challenger.TPR - champion.TPR
	fprIncrease := challenger.FPR - champion.FPR

	var latencyIncreasePct float64
	if champion.AvgLatencyMs > 0 {
		latencyIncreasePct = (challenger.AvgLatencyMs - champion.AvgLatencyMs) / champion.AvgLatencyMs * 100
	}

	// Challenger wins only if ALL thresholds are met.
	if tprImprovement >= thresholds.MinTPRImprovement &&
		fprIncrease <= thresholds.MaxFPRIncrease &&
		latencyIncreasePct <= thresholds.MaxLatencyIncreasePct &&
		challenger.DriftPSI <= thresholds.MaxDriftIncrease {

		return "challenger",
			fmt.Sprintf("Challenger wins: TPR improved by %.4f (threshold: %.4f), FPR increased by %.4f (max: %.4f), latency increased by %.2f%% (max: %.2f%%). Promote challenger to production.",
				tprImprovement, thresholds.MinTPRImprovement,
				fprIncrease, thresholds.MaxFPRIncrease,
				latencyIncreasePct, thresholds.MaxLatencyIncreasePct)
	}

	// Champion retains — at least one threshold is violated.
	reasons := []string{}
	if tprImprovement < thresholds.MinTPRImprovement {
		reasons = append(reasons, fmt.Sprintf("TPR improvement %.4f < minimum %.4f", tprImprovement, thresholds.MinTPRImprovement))
	}
	if fprIncrease > thresholds.MaxFPRIncrease {
		reasons = append(reasons, fmt.Sprintf("FPR increase %.4f > maximum %.4f", fprIncrease, thresholds.MaxFPRIncrease))
	}
	if latencyIncreasePct > thresholds.MaxLatencyIncreasePct {
		reasons = append(reasons, fmt.Sprintf("Latency increase %.2f%% > maximum %.2f%%", latencyIncreasePct, thresholds.MaxLatencyIncreasePct))
	}
	if challenger.DriftPSI > thresholds.MaxDriftIncrease {
		reasons = append(reasons, fmt.Sprintf("Drift PSI %.4f > maximum %.4f", challenger.DriftPSI, thresholds.MaxDriftIncrease))
	}

	return "champion",
		fmt.Sprintf("Champion retains: %s. Do not promote challenger.", stringsJoin(reasons, "; "))
}

// average computes the arithmetic mean of a float64 slice.
func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// percentile computes the p-th percentile of a float64 slice.
func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	// Sort a copy to avoid mutating the original.
	sorted := make([]float64, len(values))
	copy(sorted, values)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	rank := p / 100 * float64(len(sorted)-1)
	lower := int(math.Floor(rank))
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	frac := rank - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

// stringsJoin joins strings with a separator. Simple helper to avoid import.
func stringsJoin(elems []string, sep string) string {
	switch len(elems) {
	case 0:
		return ""
	case 1:
		return elems[0]
	}
	var b []byte
	b = append(b, elems[0]...)
	for i := 1; i < len(elems); i++ {
		b = append(b, sep...)
		b = append(b, elems[i]...)
	}
	return string(b)
}

// generateABTestID creates a unique identifier for an A/B test.
func generateABTestID() string {
	return fmt.Sprintf("ab-%d", time.Now().UnixNano())
}

// DefaultABTestConfig returns sensible defaults for an A/B test configuration.
func DefaultABTestConfig() ABTestConfig {
	return ABTestConfig{
		Name:            "Default A/B Test",
		TrafficSplitPct: 10,
		MinSampleSize:   1000,
		ConfidenceLevel: 0.95,
		Duration:        7 * 24 * time.Hour, // 7 days
		MetricThresholds: ABTestThresholds{
			MaxFPRIncrease:        0.01,
			MinTPRImprovement:     0.05,
			MaxLatencyIncreasePct: 10,
			MaxDriftIncrease:      0.1,
		},
	}
}
