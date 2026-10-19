// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 4: Assessment HTTP API
//
// assessment_http.go provides HTTP handlers for the posture assessment
// dashboard API. These endpoints serve JSON data consumed by the
// dashboard frontend widgets.
//
// Endpoints (mounted on the dashboard mux, admin port):
//
//   POST /api/v1/assessment/run              — Run a new assessment
//   GET  /api/v1/assessment/current          — Current assessment summary (score badge)
//   GET  /api/v1/assessment/current/radar    — OWASP radar data
//   GET  /api/v1/assessment/current/gaps     — Gap analysis view
//   GET  /api/v1/assessment/current/compliance — Compliance posture (31 frameworks)
//   GET  /api/v1/assessment/current/pdf      — Download PDF report
//   GET  /api/v1/assessment/current/signed   — Download signed PDF (Ed25519)
//   GET  /api/v1/assessment/history          — Assessment history list
//   GET  /api/v1/assessment/trend            — Score trend data
//
// The "current" endpoints use the most recent assessment result stored
// in the in-memory AssessmentStore. After POST /run, the new result
// becomes "current".
//
// All endpoints return JSON except /pdf and /signed (which return
// binary content). Errors are returned as {"error": "message"}.

package assessment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// AssessmentHTTPHandler provides HTTP handlers for the assessment dashboard API.
// It wraps a Runner and AssessmentStore to serve dashboard data.
type AssessmentHTTPHandler struct {
	store    *AssessmentStore
	config   *RunnerConfig
	fbConfig IOCFeedbackConfig
}

// NewAssessmentHTTPHandler creates a handler with the given store and runner config.
func NewAssessmentHTTPHandler(store *AssessmentStore, cfg *RunnerConfig) *AssessmentHTTPHandler {
	if cfg == nil {
		cfg = DefaultRunnerConfig()
	}
	return &AssessmentHTTPHandler{
		store:    store,
		config:   cfg,
		fbConfig: DefaultIOCFeedbackConfig(),
	}
}

// Handler returns an http.Handler that routes to the assessment API endpoints.
// The base path should be "/api/v1/assessment/".
func (h *AssessmentHTTPHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/run", h.handleRun)
	mux.HandleFunc("/current", h.handleCurrent)
	mux.HandleFunc("/current/radar", h.handleRadar)
	mux.HandleFunc("/current/gaps", h.handleGaps)
	mux.HandleFunc("/current/compliance", h.handleCompliance)
	mux.HandleFunc("/current/pdf", h.handlePDF)
	mux.HandleFunc("/current/signed", h.handleSignedPDF)
	mux.HandleFunc("/history", h.handleHistory)
	mux.HandleFunc("/trend", h.handleTrend)
	return mux
}

// =========================================================================
// Handlers
// =========================================================================

func (h *AssessmentHTTPHandler) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	runner, err := NewRunner(h.config)
	if err != nil {
		jsonError(w, fmt.Sprintf("create runner: %v", err), http.StatusInternalServerError)
		return
	}
	if runner.mlDetector != nil {
		defer runner.mlDetector.Close()
	}

	result, err := runner.Run()
	if err != nil {
		jsonError(w, fmt.Sprintf("assessment failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Store the result.
	if h.store != nil {
		h.store.Save(*result)
	}

	// Return the dashboard summary.
	summary := BuildDashboardSummary(result)
	jsonOK(w, summary)
}

func (h *AssessmentHTTPHandler) handleCurrent(w http.ResponseWriter, r *http.Request) {
	result := h.currentResult()
	if result == nil {
		jsonError(w, "no assessment available — POST /api/v1/assessment/run first", http.StatusNotFound)
		return
	}
	summary := BuildDashboardSummary(result)
	jsonOK(w, summary)
}

func (h *AssessmentHTTPHandler) handleRadar(w http.ResponseWriter, r *http.Request) {
	result := h.currentResult()
	if result == nil {
		jsonError(w, "no assessment available", http.StatusNotFound)
		return
	}
	radar := BuildOWASPRadar(result)
	jsonOK(w, radar)
}

func (h *AssessmentHTTPHandler) handleGaps(w http.ResponseWriter, r *http.Request) {
	result := h.currentResult()
	if result == nil {
		jsonError(w, "no assessment available", http.StatusNotFound)
		return
	}

	// Generate gap analysis report (without IOC store — recommendations only).
	fb := NewIOCFeedbackLoop(h.fbConfig, nil)
	report := fb.ProcessResults(result)

	gapView := BuildGapView(result, report)
	jsonOK(w, gapView)
}

func (h *AssessmentHTTPHandler) handleCompliance(w http.ResponseWriter, r *http.Request) {
	result := h.currentResult()
	if result == nil {
		jsonError(w, "no assessment available", http.StatusNotFound)
		return
	}
	compView := BuildComplianceView(result)
	jsonOK(w, compView)
}

func (h *AssessmentHTTPHandler) handlePDF(w http.ResponseWriter, r *http.Request) {
	result := h.currentResult()
	if result == nil {
		jsonError(w, "no assessment available", http.StatusNotFound)
		return
	}

	pdfBytes, err := result.ToPDF()
	if err != nil {
		jsonError(w, fmt.Sprintf("PDF generation failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"assessment-%s.pdf\"", result.ID))
	w.Header().Set("Content-Length", strconv.Itoa(len(pdfBytes)))
	w.Write(pdfBytes)
}

func (h *AssessmentHTTPHandler) handleSignedPDF(w http.ResponseWriter, r *http.Request) {
	result := h.currentResult()
	if result == nil {
		jsonError(w, "no assessment available", http.StatusNotFound)
		return
	}

	envelope, err := SignPDFReport(result, SignReportConfig{})
	if err != nil {
		jsonError(w, fmt.Sprintf("signing failed: %v", err), http.StatusInternalServerError)
		return
	}

	jsonOK(w, envelope)
}

func (h *AssessmentHTTPHandler) handleHistory(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		jsonError(w, "no assessment store configured", http.StatusServiceUnavailable)
		return
	}

	results := h.store.History(0, 1000)
	summaries := make([]DashboardSummary, 0, len(results))
	for _, r := range results {
		summaries = append(summaries, BuildDashboardSummary(&r))
	}

	jsonOK(w, map[string]interface{}{
		"count":   len(summaries),
		"results": summaries,
	})
}

func (h *AssessmentHTTPHandler) handleTrend(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		jsonError(w, "no assessment store configured", http.StatusServiceUnavailable)
		return
	}

	results := h.store.History(0, 1000)
	ptrs := make([]*AssessmentResult, 0, len(results))
	for i := range results {
		ptrs = append(ptrs, &results[i])
	}
	trend := BuildTrendData(ptrs)
	jsonOK(w, trend)
}

// =========================================================================
// Helpers
// =========================================================================

func (h *AssessmentHTTPHandler) currentResult() *AssessmentResult {
	if h.store == nil {
		return nil
	}
	return h.store.Latest()
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
