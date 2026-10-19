// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 1: Runner — Sends scenarios through the real detection pipeline

package assessment

import (
	"context"
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ml"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
)

// Runner executes assessment scenarios through the detection pipeline.
type Runner struct {
	scanner       *scanner.Scanner
	mlDetector    *ml.ThreatDetector
	responseGuard *response.ResponseGuard
	store         *AssessmentStore
}

// RunnerConfig holds optional configuration for the assessment runner.
type RunnerConfig struct {
	// EnableML enables the ML threat detector (requires CGO + ONNX model).
	EnableML bool
	// ModelPath is the path to the ONNX model file.
	ModelPath string
	// EnableResponseGuard enables the response guard for response scenarios.
	EnableResponseGuard bool
}

// DefaultRunnerConfig returns a config with ML and response guard disabled
// (safe default — works without CGO or model files).
func DefaultRunnerConfig() *RunnerConfig {
	return &RunnerConfig{
		EnableML:            false,
		ModelPath:           "pkg/ml/models/threat_cnn_bilstm.onnx",
		EnableResponseGuard: true,
	}
}

// NewRunner creates a new assessment runner.
func NewRunner(cfg *RunnerConfig) (*Runner, error) {
	if cfg == nil {
		cfg = DefaultRunnerConfig()
	}

	r := &Runner{
		scanner: scanner.New(scanner.DefaultConfig()),
		store:   NewAssessmentStore(),
	}

	// Optionally enable ML detector
	if cfg.EnableML {
		detector := ml.NewThreatDetector(ml.DetectorConfig{
			Enabled:           true,
			ShadowMode:        false,
			Threshold:         0.50,
			ModelPath:         cfg.ModelPath,
			MaxSequenceLength: 256,
		})
		if err := detector.LoadModel(cfg.ModelPath); err != nil {
			return nil, fmt.Errorf("assessment: failed to load ML model: %w", err)
		}
		r.mlDetector = detector
	}

	// Optionally enable response guard
	if cfg.EnableResponseGuard {
		rgCfg := response.DefaultResponseGuardConfig()
		rgCfg.EnableHallucination = true // Posture Assessment: enable all detectors
		r.responseGuard = response.NewResponseGuardWithConfig(rgCfg)
	}

	return r, nil
}

// Run executes all default scenarios and returns the assessment result.
func (r *Runner) Run() (*AssessmentResult, error) {
	return r.RunScenarios(DefaultScenarios())
}

// RunScenarios executes a specific set of scenarios.
func (r *Runner) RunScenarios(scenarios []Scenario) (*AssessmentResult, error) {
	start := time.Now()
	results := make([]ScenarioResult, 0, len(scenarios))

	for _, scenario := range scenarios {
		sr := r.runScenario(scenario)
		results = append(results, sr)
	}

	duration := time.Since(start)

	// Compute summary
	blocked := 0
	for _, sr := range results {
		if sr.Blocked {
			blocked++
		}
	}
	missed := len(results) - blocked
	score := 0.0
	if len(results) > 0 {
		score = float64(blocked) / float64(len(results))
	}

	// Compute OWASP coverage
	owaspCoverage := computeOWASPCoverage(results)

	// Compute compliance posture
	compliancePosture := ComputeCompliancePosture(results)

	result := &AssessmentResult{
		ID:                fmt.Sprintf("assessment-%d", start.Unix()),
		Timestamp:         start,
		Duration:          duration,
		Total:             len(results),
		Blocked:           blocked,
		Missed:            missed,
		Score:             score,
		ScenarioResults:   results,
		OWASPCoverage:     owaspCoverage,
		CompliancePosture: compliancePosture,
	}

	r.store.Save(*result)
	return result, nil
}

// runScenario executes a single scenario through the appropriate detection pipeline.
func (r *Runner) runScenario(scenario Scenario) ScenarioResult {
	sr := ScenarioResult{
		ScenarioID: scenario.ID,
		Name:       scenario.Name,
		OWASP:      scenario.OWASP,
		Timestamp:  time.Now(),
	}

	switch scenario.Type {
	case ScenarioTypeRequest:
		r.runRequestScenario(scenario, &sr)
	case ScenarioTypeResponse:
		r.runResponseScenario(scenario, &sr)
	}

	return sr
}

// runRequestScenario sends the payload through scanner + ML.
func (r *Runner) runRequestScenario(scenario Scenario, sr *ScenarioResult) {
	// Layer 1: Regex scanner
	findings := r.scanner.Scan(scenario.Payload)
	if len(findings) > 0 {
		sr.Blocked = true
		sr.DetectionLayer = "regex"
		for _, f := range findings {
			if f.Pattern != nil {
				sr.RegexMatches = append(sr.RegexMatches, f.Pattern.Name)
			}
		}
		// Also check if it should be blocked based on severity
		if !r.scanner.ShouldBlock(findings) {
			// Findings exist but below block threshold — still detected, but not blocked
			// For assessment purposes, detection = blocked (we want to know if it was caught)
			sr.Blocked = true
			sr.DetectionLayer = "regex"
		}
		return
	}

	// Layer 2: ML detector (if enabled)
	if r.mlDetector != nil && r.mlDetector.IsEnabled() {
		score := r.mlDetector.Detect(scenario.Payload)
		sr.MLScore = score.Score
		if score.IsThreat {
			sr.Blocked = true
			sr.DetectionLayer = "ml"
			return
		}
	}

	// Not blocked by any layer
	sr.Blocked = false
	sr.DetectionLayer = "none"
}

// runResponseScenario sends the payload through the response guard.
func (r *Runner) runResponseScenario(scenario Scenario, sr *ScenarioResult) {
	if r.responseGuard == nil {
		sr.Blocked = false
		sr.DetectionLayer = "none"
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := r.responseGuard.Scan(ctx, scenario.Payload)
	if err != nil {
		sr.Blocked = false
		sr.DetectionLayer = "none"
		return
	}

	if !result.Allowed {
		sr.Blocked = true
		sr.DetectionLayer = "response"
	} else {
		// Check if any threats/PII/secrets were detected even if not blocked
		hasFindings := len(result.Threats) > 0 ||
			len(result.DetectedPII) > 0 ||
			len(result.DetectedSecrets) > 0 ||
			len(result.DetectedXSS) > 0
		if hasFindings {
			sr.Blocked = true
			sr.DetectionLayer = "response"
		} else {
			sr.Blocked = false
			sr.DetectionLayer = "none"
		}
	}
}

// Latest returns the most recent assessment result.
func (r *Runner) Latest() *AssessmentResult {
	return r.store.Latest()
}

// Get returns a specific assessment by ID.
func (r *Runner) Get(id string) *AssessmentResult {
	return r.store.Get(id)
}

// History returns paginated assessment history.
func (r *Runner) History(offset, limit int) []AssessmentResult {
	return r.store.History(offset, limit)
}

// computeOWASPCoverage groups results by OWASP category and computes coverage.
func computeOWASPCoverage(results []ScenarioResult) map[string]OWASPCategory {
	categories := make(map[string]OWASPCategory)

	for _, sr := range results {
		cat, ok := categories[sr.OWASP]
		if !ok {
			cat = OWASPCategory{Category: sr.OWASP}
		}
		cat.Total++
		if sr.Blocked {
			cat.Blocked++
		} else {
			cat.Missed++
		}
		categories[sr.OWASP] = cat
	}

	for owasp, cat := range categories {
		if cat.Total > 0 {
			cat.Coverage = float64(cat.Blocked) / float64(cat.Total)
		}
		categories[owasp] = cat
	}

	return categories
}
