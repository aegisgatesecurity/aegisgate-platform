// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 1: Core Engine — Scenario definitions, runner, results, reports

package assessment

import (
	"time"
)

// ============================================================================
// Result Types
// ============================================================================

// AssessmentResult is the complete result of a single assessment run.
type AssessmentResult struct {
	ID                string                      `json:"id"`
	Timestamp         time.Time                   `json:"timestamp"`
	Duration          time.Duration               `json:"duration_ms"`
	Total             int                         `json:"total"`
	Blocked           int                         `json:"blocked"`
	Missed            int                         `json:"missed"`
	Score             float64                     `json:"score"` // 0.0–1.0
	ScenarioResults   []ScenarioResult            `json:"scenarios"`
	OWASPCoverage     map[string]OWASPCategory    `json:"owasp_coverage"`
	CompliancePosture map[string]FrameworkPosture `json:"compliance_posture,omitempty"`
}

// ScenarioResult is the result of a single scenario.
type ScenarioResult struct {
	ScenarioID     string    `json:"scenario_id"`
	Name           string    `json:"name"`
	OWASP          string    `json:"owasp"`
	Blocked        bool      `json:"blocked"`
	DetectionLayer string    `json:"detection_layer"` // "regex", "ml", "response", "none"
	MLScoer        float64   `json:"ml_score,omitempty"`
	RegexMatches   []string  `json:"regex_matches,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

// OWASPCategory summarizes coverage for one OWASP LLM Top 10 category.
type OWASPCategory struct {
	Category string  `json:"category"`
	Total    int     `json:"total"`
	Blocked  int     `json:"blocked"`
	Missed   int     `json:"missed"`
	Coverage float64 `json:"coverage"` // 0.0–1.0
}

// FrameworkPosture summarizes compliance posture for one framework.
type FrameworkPosture struct {
	Framework     string  `json:"framework"`
	TotalControls int     `json:"total_controls"`
	Verified      int     `json:"verified"`
	AtRisk        int     `json:"at_risk"`
	Coverage      float64 `json:"coverage"`
}

// ============================================================================
// Storage (in-memory for Phase 1; persistence in Phase 2)
// ============================================================================

// AssessmentStore holds assessment history in memory.
type AssessmentStore struct {
	results []AssessmentResult
}

// NewAssessmentStore creates a new in-memory store.
func NewAssessmentStore() *AssessmentStore {
	return &AssessmentStore{
		results: make([]AssessmentResult, 0),
	}
}

// Save stores an assessment result.
func (s *AssessmentStore) Save(result AssessmentResult) {
	s.results = append(s.results, result)
}

// Latest returns the most recent assessment, or nil if none exists.
func (s *AssessmentStore) Latest() *AssessmentResult {
	if len(s.results) == 0 {
		return nil
	}
	return &s.results[len(s.results)-1]
}

// Get returns a specific assessment by ID, or nil if not found.
func (s *AssessmentStore) Get(id string) *AssessmentResult {
	for i := range s.results {
		if s.results[i].ID == id {
			return &s.results[i]
		}
	}
	return nil
}

// History returns paginated assessment history.
func (s *AssessmentStore) History(offset, limit int) []AssessmentResult {
	if offset >= len(s.results) {
		return []AssessmentResult{}
	}
	end := offset + limit
	if end > len(s.results) {
		end = len(s.results)
	}
	return s.results[offset:end]
}
