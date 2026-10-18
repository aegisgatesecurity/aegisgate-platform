// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 1: Report Generation — JSON and CSV output

package assessment

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"time"
)

// ToJSON serializes an assessment result to indented JSON.
func (r *AssessmentResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToCSV serializes assessment scenario results to CSV format.
// Each row is one scenario result with columns:
// scenario_id, name, owasp, blocked, detection_layer, ml_score, regex_matches, timestamp
func (r *AssessmentResult) ToCSV() ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Header
	if err := w.Write([]string{
		"scenario_id", "name", "owasp", "blocked", "detection_layer",
		"ml_score", "regex_matches", "timestamp",
	}); err != nil {
		return nil, fmt.Errorf("csv header: %w", err)
	}

	// Rows
	for _, sr := range r.ScenarioResults {
		regexMatches := ""
		if len(sr.RegexMatches) > 0 {
			regexMatches = fmt.Sprintf("%v", sr.RegexMatches)
		}
		if err := w.Write([]string{
			sr.ScenarioID,
			sr.Name,
			sr.OWASP,
			fmt.Sprintf("%t", sr.Blocked),
			sr.DetectionLayer,
			fmt.Sprintf("%.4f", sr.MLScoer),
			regexMatches,
			sr.Timestamp.Format(time.RFC3339),
		}); err != nil {
			return nil, fmt.Errorf("csv row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("csv flush: %w", err)
	}

	return buf.Bytes(), nil
}

// ExecutiveSummary generates a 1-line human-readable summary.
func (r *AssessmentResult) ExecutiveSummary() string {
	return fmt.Sprintf(
		"Posture Assessment: %d/%d attacks blocked (%.1f%%) — %d OWASP categories covered — %s",
		r.Blocked, r.Total, r.Score*100, len(r.OWASPCoverage),
		r.Timestamp.Format("Jan 2, 2006 15:04 MST"),
	)
}

// GapReport returns a human-readable list of missed scenarios (gaps).
func (r *AssessmentResult) GapReport() string {
	var buf bytes.Buffer
	gaps := 0
	for _, sr := range r.ScenarioResults {
		if !sr.Blocked {
			gaps++
			fmt.Fprintf(&buf, "  [%s] %s — %s (layer: %s)\n",
				sr.OWASP, sr.ScenarioID, sr.Name, sr.DetectionLayer)
		}
	}
	if gaps == 0 {
		return "No gaps detected — all scenarios blocked."
	}
	return fmt.Sprintf("Gaps found (%d missed):\n%s", gaps, buf.String())
}
