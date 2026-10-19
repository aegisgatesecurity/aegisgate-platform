// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 4: Dashboard Data + HTTP API Tests

package assessment

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// =========================================================================
// Tests: Dashboard Data Builders
// =========================================================================

func TestBuildDashboardSummary(t *testing.T) {
	result := runRegexOnlyAssessment(t)
	summary := BuildDashboardSummary(result)

	if summary.Score != result.Score {
		t.Errorf("score mismatch: %.4f vs %.4f", summary.Score, result.Score)
	}
	if summary.Total != result.Total {
		t.Errorf("total mismatch: %d vs %d", summary.Total, result.Total)
	}
	if summary.Blocked != result.Blocked {
		t.Errorf("blocked mismatch: %d vs %d", summary.Blocked, result.Blocked)
	}
	if summary.Missed != result.Missed {
		t.Errorf("missed mismatch: %d vs %d", summary.Missed, result.Missed)
	}
	if summary.Status == "" {
		t.Error("status is empty")
	}
	t.Logf("Summary: score=%.1f%%, status=%s, %d/%d blocked, %d gaps",
		summary.ScorePercent, summary.Status, summary.Blocked, summary.Total, summary.Missed)
}

func TestBuildOWASPRadar(t *testing.T) {
	result := runRegexOnlyAssessment(t)
	radar := BuildOWASPRadar(result)

	if len(radar.Categories) == 0 {
		t.Fatal("radar has no categories")
	}
	for _, cat := range radar.Categories {
		if cat.Name == "" {
			t.Errorf("category %s has empty name", cat.Category)
		}
		if cat.Coverage < 0 || cat.Coverage > 1 {
			t.Errorf("category %s coverage %.2f out of range", cat.Category, cat.Coverage)
		}
		t.Logf("  %s (%s): %.0f%% (%d/%d)", cat.Category, cat.Name, cat.Coverage*100, cat.Blocked, cat.Total)
	}
}

func TestBuildGapView(t *testing.T) {
	result := runRegexOnlyAssessment(t)
	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), nil)
	report := fb.ProcessResults(result)

	gapView := BuildGapView(result, report)

	if gapView.TotalGaps != result.Missed {
		t.Errorf("gap count %d != missed %d", gapView.TotalGaps, result.Missed)
	}
	for _, gap := range gapView.Gaps {
		if gap.Recommendation == "" {
			t.Errorf("gap %s has empty recommendation", gap.ScenarioID)
		}
		if gap.Priority == "" {
			t.Errorf("gap %s has empty priority", gap.ScenarioID)
		}
		t.Logf("  [%s] %s — priority=%s, fix=%s", gap.OWASP, gap.ScenarioID, gap.Priority, gap.FixType)
	}
}

func TestBuildComplianceView(t *testing.T) {
	result := runRegexOnlyAssessment(t)
	compView := BuildComplianceView(result)

	if compView.TotalFrameworks != 31 {
		t.Errorf("expected 31 frameworks, got %d", compView.TotalFrameworks)
	}
	withControls := 0
	for _, fw := range compView.Frameworks {
		if fw.TotalControls > 0 {
			withControls++
		}
		if fw.Name == "" {
			t.Errorf("framework %s has empty name", fw.ID)
		}
		if fw.Tier == "" {
			t.Errorf("framework %s has empty tier", fw.ID)
		}
	}
	t.Logf("Compliance view: %d frameworks, %d with controls", compView.TotalFrameworks, withControls)
}

func TestBuildTrendData(t *testing.T) {
	result := runRegexOnlyAssessment(t)
	results := []*AssessmentResult{result, result, result}
	trend := BuildTrendData(results)

	if len(trend.Points) != 3 {
		t.Errorf("expected 3 trend points, got %d", len(trend.Points))
	}
}

// =========================================================================
// Tests: HTTP API
// =========================================================================

func TestAssessmentHTTP_Run(t *testing.T) {
	store := NewAssessmentStore()
	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// POST /run
	resp, err := http.Post(server.URL+"/run", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /run failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var summary DashboardSummary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	t.Logf("Run response: score=%.1f%%, %d/%d blocked", summary.ScorePercent, summary.Blocked, summary.Total)
	if summary.Total == 0 {
		t.Error("total is 0 — assessment didn't run")
	}
}

func TestAssessmentHTTP_Current(t *testing.T) {
	store := NewAssessmentStore()

	// Pre-populate with a result.
	result := runRegexOnlyAssessment(t)
	store.Save(*result)

	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// GET /current
	resp, err := http.Get(server.URL + "/current")
	if err != nil {
		t.Fatalf("GET /current failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var summary DashboardSummary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	t.Logf("Current: score=%.1f%%, status=%s", summary.ScorePercent, summary.Status)
}

func TestAssessmentHTTP_CurrentNotFound(t *testing.T) {
	store := NewAssessmentStore()
	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/current")
	if err != nil {
		t.Fatalf("GET /current failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAssessmentHTTP_Radar(t *testing.T) {
	store := NewAssessmentStore()
	result := runRegexOnlyAssessment(t)
	store.Save(*result)

	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/current/radar")
	if err != nil {
		t.Fatalf("GET /current/radar failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var radar OWASPRadarData
	if err := json.NewDecoder(resp.Body).Decode(&radar); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	t.Logf("Radar: %d categories", len(radar.Categories))
}

func TestAssessmentHTTP_Gaps(t *testing.T) {
	store := NewAssessmentStore()
	result := runRegexOnlyAssessment(t)
	store.Save(*result)

	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/current/gaps")
	if err != nil {
		t.Fatalf("GET /current/gaps failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var gapView GapViewData
	if err := json.NewDecoder(resp.Body).Decode(&gapView); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	t.Logf("Gaps: %d total", gapView.TotalGaps)
}

func TestAssessmentHTTP_Compliance(t *testing.T) {
	store := NewAssessmentStore()
	result := runRegexOnlyAssessment(t)
	store.Save(*result)

	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/current/compliance")
	if err != nil {
		t.Fatalf("GET /current/compliance failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var compView ComplianceViewData
	if err := json.NewDecoder(resp.Body).Decode(&compView); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if compView.TotalFrameworks != 31 {
		t.Errorf("expected 31 frameworks, got %d", compView.TotalFrameworks)
	}
	t.Logf("Compliance: %d frameworks", compView.TotalFrameworks)
}

func TestAssessmentHTTP_PDF(t *testing.T) {
	store := NewAssessmentStore()
	result := runRegexOnlyAssessment(t)
	store.Save(*result)

	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/current/pdf")
	if err != nil {
		t.Fatalf("GET /current/pdf failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "application/pdf" {
		t.Errorf("expected application/pdf, got %s", resp.Header.Get("Content-Type"))
	}

	// Read first 4 bytes to verify PDF magic.
	buf := make([]byte, 4)
	resp.Body.Read(buf)
	if string(buf) != "%PDF" {
		t.Errorf("expected %%PDF magic, got %q", string(buf))
	}
	t.Logf("PDF download: Content-Type=%s, Content-Disposition=%s",
		resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"))
}

func TestAssessmentHTTP_SignedPDF(t *testing.T) {
	store := NewAssessmentStore()
	result := runRegexOnlyAssessment(t)
	store.Save(*result)

	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/current/signed")
	if err != nil {
		t.Fatalf("GET /current/signed failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var envelope SignedAssessmentReport
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if envelope.Algorithm != "Ed25519" {
		t.Errorf("expected Ed25519, got %s", envelope.Algorithm)
	}
	if err := envelope.Verify(); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
	t.Logf("Signed PDF: algorithm=%s, keyFP=%s, verified=true", envelope.Algorithm, envelope.KeyFingerprint)
}

func TestAssessmentHTTP_History(t *testing.T) {
	store := NewAssessmentStore()
	result := runRegexOnlyAssessment(t)
	store.Save(*result)

	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/history")
	if err != nil {
		t.Fatalf("GET /history failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var histResp struct {
		Count   int                `json:"count"`
		Results []DashboardSummary `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&histResp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if histResp.Count != 1 {
		t.Errorf("expected count 1, got %d", histResp.Count)
	}
	t.Logf("History: %d results", histResp.Count)
}

func TestAssessmentHTTP_Trend(t *testing.T) {
	store := NewAssessmentStore()
	result := runRegexOnlyAssessment(t)
	store.Save(*result)

	handler := NewAssessmentHTTPHandler(store, nil)
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/trend")
	if err != nil {
		t.Fatalf("GET /trend failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var trend TrendData
	if err := json.NewDecoder(resp.Body).Decode(&trend); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if len(trend.Points) != 1 {
		t.Errorf("expected 1 trend point, got %d", len(trend.Points))
	}
	t.Logf("Trend: %d points", len(trend.Points))
}
