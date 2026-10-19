// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 4: Dashboard Data Structures
//
// dashboard_data.go provides JSON-friendly data structures for the
// posture assessment dashboard. These structures are consumed by the
// HTTP API (assessment_http.go) and the dashboard frontend.
//
// Dashboard widgets:
//   - Score Badge: DashboardSummary (score, status, gaps, last run)
//   - Trend Chart: TrendData (score over time)
//   - OWASP Radar: OWASPRadarData (per-category coverage)
//   - Gap Analysis: GapViewData (missed scenarios with recommendations)
//   - Compliance Table: ComplianceViewData (31 frameworks posture)
//   - Run Assessment: POST /api/v1/assessment/run

package assessment

import (
	"sort"
	"time"
)

// DashboardSummary is the data for the score badge widget.
// Shows the current posture score, status, and gap count at a glance.
type DashboardSummary struct {
	AssessmentID    string    `json:"assessment_id"`
	Score           float64   `json:"score"`         // 0.0–1.0
	ScorePercent    float64   `json:"score_percent"` // 0–100
	Status          string    `json:"status"`        // PASS, NEEDS_IMPROVEMENT, FAIL
	Total           int       `json:"total"`
	Blocked         int       `json:"blocked"`
	Missed          int       `json:"missed"`
	OWASPCategories int       `json:"owasp_categories"` // Categories with coverage
	Timestamp       time.Time `json:"timestamp"`
	Duration        string    `json:"duration"`
}

// TrendData is the data for the score trend chart.
// Each point represents one assessment run.
type TrendData struct {
	Points []TrendPoint `json:"points"`
}

// TrendPoint is a single point in the trend chart.
type TrendPoint struct {
	AssessmentID string    `json:"assessment_id"`
	Score        float64   `json:"score"`
	Timestamp    time.Time `json:"timestamp"`
	Gaps         int       `json:"gaps"`
}

// OWASPRadarData is the data for the OWASP LLM Top 10 radar chart.
// Each category has a coverage value (0–1) and blocked/total counts.
type OWASPRadarData struct {
	Categories []OWASPRadarCategory `json:"categories"`
}

// OWASPRadarCategory is one axis of the OWASP radar chart.
type OWASPRadarCategory struct {
	Category string  `json:"category"` // LLM01–LLM10
	Name     string  `json:"name"`     // Human-readable name
	Coverage float64 `json:"coverage"` // 0.0–1.0
	Total    int     `json:"total"`
	Blocked  int     `json:"blocked"`
	Missed   int     `json:"missed"`
}

// GapViewData is the data for the gap analysis view.
type GapViewData struct {
	TotalGaps int            `json:"total_gaps"`
	Gaps      []GapViewItem  `json:"gaps"`
	PerOWASP  map[string]int `json:"per_owasp"`
}

// GapViewItem is a single gap in the gap analysis view.
type GapViewItem struct {
	ScenarioID     string  `json:"scenario_id"`
	Name           string  `json:"name"`
	OWASP          string  `json:"owasp"`
	DetectionLayer string  `json:"detection_layer"`
	MLScore        float64 `json:"ml_score,omitempty"`
	Recommendation string  `json:"recommendation"`
	FixType        string  `json:"fix_type"`
	Priority       string  `json:"priority"`
}

// ComplianceViewData is the data for the compliance posture table.
type ComplianceViewData struct {
	TotalFrameworks int                  `json:"total_frameworks"`
	Frameworks      []ComplianceViewItem `json:"frameworks"`
}

// ComplianceViewItem is one framework's posture in the compliance table.
type ComplianceViewItem struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Tier          string  `json:"tier"`
	TotalControls int     `json:"total_controls"`
	Verified      int     `json:"verified"`
	AtRisk        int     `json:"at_risk"`
	Coverage      float64 `json:"coverage"`
}

// =========================================================================
// Builders — convert AssessmentResult to dashboard data
// =========================================================================

// OWASP category names for the radar chart.
var owaspCategoryNames = map[string]string{
	"LLM01": "Prompt Injection",
	"LLM02": "Sensitive Info Disclosure",
	"LLM03": "Supply Chain",
	"LLM04": "Data & Model Poisoning",
	"LLM05": "Improper Output Handling",
	"LLM06": "Excessive Agency",
	"LLM07": "System Prompt Leakage",
	"LLM08": "Vector & Embedding Weaknesses",
	"LLM09": "Misinformation & Hallucination",
	"LLM10": "Unbounded Consumption",
}

// BuildDashboardSummary creates the score badge data from an assessment result.
func BuildDashboardSummary(r *AssessmentResult) DashboardSummary {
	status := "PASS"
	if r.Score < 0.80 {
		status = "NEEDS_IMPROVEMENT"
	}
	if r.Score < 0.60 {
		status = "FAIL"
	}
	return DashboardSummary{
		AssessmentID:    r.ID,
		Score:           r.Score,
		ScorePercent:    r.Score * 100,
		Status:          status,
		Total:           r.Total,
		Blocked:         r.Blocked,
		Missed:          r.Missed,
		OWASPCategories: len(r.OWASPCoverage),
		Timestamp:       r.Timestamp,
		Duration:        r.Duration.String(),
	}
}

// BuildTrendData creates the trend chart data from assessment history.
func BuildTrendData(results []*AssessmentResult) TrendData {
	sorted := make([]*AssessmentResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	points := make([]TrendPoint, 0, len(sorted))
	for _, r := range sorted {
		points = append(points, TrendPoint{
			AssessmentID: r.ID,
			Score:        r.Score,
			Timestamp:    r.Timestamp,
			Gaps:         r.Missed,
		})
	}
	return TrendData{Points: points}
}

// BuildOWASPRadar creates the OWASP radar chart data from an assessment result.
func BuildOWASPRadar(r *AssessmentResult) OWASPRadarData {
	categories := make([]OWASPRadarCategory, 0, len(r.OWASPCoverage))

	keys := make([]string, 0, len(r.OWASPCoverage))
	for k := range r.OWASPCoverage {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		cat := r.OWASPCoverage[k]
		name := owaspCategoryNames[k]
		if name == "" {
			name = k
		}
		categories = append(categories, OWASPRadarCategory{
			Category: k,
			Name:     name,
			Coverage: cat.Coverage,
			Total:    cat.Total,
			Blocked:  cat.Blocked,
			Missed:   cat.Missed,
		})
	}
	return OWASPRadarData{Categories: categories}
}

// BuildGapView creates the gap analysis view data from an assessment result.
// If a GapAnalysisReport is provided, its recommendations are included.
func BuildGapView(r *AssessmentResult, report *GapAnalysisReport) GapViewData {
	gaps := make([]GapViewItem, 0)
	perOWASP := make(map[string]int)

	// Build a lookup from the gap analysis report (if provided).
	recLookup := make(map[string]GapRecord)
	if report != nil {
		for _, gr := range report.GapRecords {
			recLookup[gr.ScenarioID] = gr
		}
	}

	for _, sr := range r.ScenarioResults {
		if sr.Blocked {
			continue
		}
		perOWASP[sr.OWASP]++

		item := GapViewItem{
			ScenarioID:     sr.ScenarioID,
			Name:           sr.Name,
			OWASP:          sr.OWASP,
			DetectionLayer: sr.DetectionLayer,
			MLScore:        sr.MLScore,
		}

		if gr, ok := recLookup[sr.ScenarioID]; ok {
			item.Recommendation = gr.Recommendation.Suggestion
			item.FixType = gr.Recommendation.FixType
			item.Priority = string(gr.Recommendation.Priority)
		}

		gaps = append(gaps, item)
	}

	return GapViewData{
		TotalGaps: len(gaps),
		Gaps:      gaps,
		PerOWASP:  perOWASP,
	}
}

// BuildComplianceView creates the compliance posture table data from an assessment result.
func BuildComplianceView(r *AssessmentResult) ComplianceViewData {
	posture := ComputeCompliancePostureV2(r.ScenarioResults)

	frameworks := make([]ComplianceViewItem, 0, len(posture))
	for _, fi := range AllFrameworkInfo() {
		fp := posture[string(fi.ID)]
		frameworks = append(frameworks, ComplianceViewItem{
			ID:            string(fi.ID),
			Name:          fi.Name,
			Tier:          string(fi.Tier),
			TotalControls: fp.TotalControls,
			Verified:      fp.Verified,
			AtRisk:        fp.AtRisk,
			Coverage:      fp.Coverage,
		})
	}

	return ComplianceViewData{
		TotalFrameworks: len(frameworks),
		Frameworks:      frameworks,
	}
}
