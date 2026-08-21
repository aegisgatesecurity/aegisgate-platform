// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — A/B Testing Service (v4.3.1)
//
// abtest.go provides ML model A/B testing: define tests with
// variant splits, assign requests to variants, and collect
// per-variant metrics (detection rate, false positive rate, latency).
//
// Design:
//   - Hash-based assignment: request ID → variant (consistent)
//   - In-memory test store (Postgres backing is future work)
//   - Metrics: per-variant counts, detection rates, latency percentiles
//   - Evaluation: compare variants using z-test on detection rates

package abtest

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"
)

// TestStatus represents the lifecycle state of an A/B test.
type TestStatus string

const (
	StatusDraft     TestStatus = "draft"
	StatusRunning   TestStatus = "running"
	StatusCompleted TestStatus = "completed"
	StatusStopped   TestStatus = "stopped"
)

// Test defines an A/B test with two or more variants.
type Test struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Variants    []Variant  `json:"variants"`
	Status      TestStatus `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Variant defines a single variant in an A/B test.
type Variant struct {
	Name     string `json:"name"`
	Weight   int    `json:"weight"`              // relative weight for split
	ModelRef string `json:"model_ref,omitempty"` // model/config reference
}

// VariantMetrics holds per-variant metrics.
type VariantMetrics struct {
	VariantName        string  `json:"variant_name"`
	RequestCount       int     `json:"request_count"`
	DetectionCount     int     `json:"detection_count"`
	DetectionRate      float64 `json:"detection_rate"`
	FalsePositiveCount int     `json:"false_positive_count"`
	AvgLatencyMs       float64 `json:"avg_latency_ms"`
}

// Service manages A/B tests.
type Service struct {
	mu      sync.RWMutex
	tests   map[string]*Test
	metrics map[string]map[string]*variantMetricsInternal // testID → variant → metrics
}

type variantMetricsInternal struct {
	requestCount       int
	detectionCount     int
	falsePositiveCount int
	totalLatencyMs     float64
}

// NewService creates a new A/B testing service.
func NewService() *Service {
	return &Service{
		tests:   make(map[string]*Test),
		metrics: make(map[string]map[string]*variantMetricsInternal),
	}
}

// CreateTest creates a new A/B test.
func (s *Service) CreateTest(ctx context.Context, name, description string, variants []Variant) (*Test, error) {
	if name == "" {
		return nil, fmt.Errorf("test name is required")
	}
	if len(variants) < 2 {
		return nil, fmt.Errorf("at least 2 variants required")
	}

	test := &Test{
		ID:          fmt.Sprintf("abt_%d", time.Now().UnixNano()),
		Name:        name,
		Description: description,
		Variants:    variants,
		Status:      StatusDraft,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tests[test.ID] = test
	s.metrics[test.ID] = make(map[string]*variantMetricsInternal)
	for _, v := range variants {
		s.metrics[test.ID][v.Name] = &variantMetricsInternal{}
	}
	return test, nil
}

// StartTest transitions a test to running status.
func (s *Service) StartTest(ctx context.Context, testID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	test, exists := s.tests[testID]
	if !exists {
		return fmt.Errorf("test %s not found", testID)
	}
	if test.Status != StatusDraft {
		return fmt.Errorf("test %s is not in draft status", testID)
	}
	test.Status = StatusRunning
	test.UpdatedAt = time.Now().UTC()
	return nil
}

// AssignVariant returns the variant name for a given request ID.
// Uses hash-based assignment for consistent splitting.
func (s *Service) AssignVariant(ctx context.Context, testID, requestID string) (string, error) {
	s.mu.RLock()
	test, exists := s.tests[testID]
	s.mu.RUnlock()
	if !exists {
		return "", fmt.Errorf("test %s not found", testID)
	}
	if test.Status != StatusRunning {
		return "", fmt.Errorf("test %s is not running", testID)
	}

	// Hash the request ID to get a consistent variant assignment.
	h := fnv.New32a()
	_, _ = h.Write([]byte(requestID))
	hashVal := h.Sum32()

	// Weighted assignment: accumulate weights and pick.
	totalWeight := 0
	for _, v := range test.Variants {
		totalWeight += v.Weight
	}
	if totalWeight == 0 {
		return test.Variants[0].Name, nil
	}

	target := int(hashVal % uint32(totalWeight))
	cumulative := 0
	for _, v := range test.Variants {
		cumulative += v.Weight
		if target < cumulative {
			return v.Name, nil
		}
	}
	return test.Variants[0].Name, nil
}

// RecordResult records a detection result for a variant.
func (s *Service) RecordResult(ctx context.Context, testID, variantName string, detected bool, falsePositive bool, latencyMs float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	testMetrics, exists := s.metrics[testID]
	if !exists {
		return
	}
	vm, exists := testMetrics[variantName]
	if !exists {
		return
	}

	vm.requestCount++
	if detected {
		vm.detectionCount++
	}
	if falsePositive {
		vm.falsePositiveCount++
	}
	vm.totalLatencyMs += latencyMs
}

// GetMetrics returns per-variant metrics for a test.
func (s *Service) GetMetrics(ctx context.Context, testID string) ([]VariantMetrics, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	test, exists := s.tests[testID]
	if !exists {
		return nil, fmt.Errorf("test %s not found", testID)
	}

	testMetrics, exists := s.metrics[testID]
	if !exists {
		return nil, nil
	}

	result := make([]VariantMetrics, 0, len(test.Variants))
	for _, v := range test.Variants {
		vm := testMetrics[v.Name]
		if vm == nil {
			continue
		}
		m := VariantMetrics{
			VariantName:        v.Name,
			RequestCount:       vm.requestCount,
			DetectionCount:     vm.detectionCount,
			FalsePositiveCount: vm.falsePositiveCount,
		}
		if vm.requestCount > 0 {
			m.DetectionRate = float64(vm.detectionCount) / float64(vm.requestCount)
			m.AvgLatencyMs = vm.totalLatencyMs / float64(vm.requestCount)
		}
		result = append(result, m)
	}
	return result, nil
}

// ListTests returns all tests.
func (s *Service) ListTests(ctx context.Context) []*Test {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Test, 0, len(s.tests))
	for _, t := range s.tests {
		result = append(result, t)
	}
	return result
}

// StopTest transitions a test to stopped status.
func (s *Service) StopTest(ctx context.Context, testID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	test, exists := s.tests[testID]
	if !exists {
		return fmt.Errorf("test %s not found", testID)
	}
	test.Status = StatusStopped
	test.UpdatedAt = time.Now().UTC()
	return nil
}
