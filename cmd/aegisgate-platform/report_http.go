// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Reporting HTTP endpoint (TODO-501)
//
// report_http.go wires pkg/reporting into the HTTP API as
//   - POST /api/v1/reports/pdf
//
// Tier gating: PDF generation is FREE (no gate).

package main

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/reporting"
)

// wireReportHandlers registers the /api/v1/reports/*
// HTTP routes. The PDF endpoint is free (no
// tier gate); the auth middleware just ensures the
// caller is authenticated.
func wireReportHandlers(mux *http.ServeMux, authMW *auth.Middleware) {
	mux.HandleFunc("/api/v1/reports/pdf", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleReportPDF(w, r)
	}))
}

// handleReportPDF is the HTTP handler for
// POST /api/v1/reports/pdf. The request body is a
// JSON object with the report fields:
//
//	{
//	  "title": "Daily Summary",
//	  "data":  <any JSON>
//	}
//
// The response is the PDF bytes with
// Content-Type: application/pdf.
func handleReportPDF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use POST)"})
		return
	}
	// 64KB max (small JSON request).
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "read body: " + err.Error()})
		return
	}
	var req struct {
		Title string                 `json:"title"`
		Data  map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse body: " + err.Error()})
		return
	}
	if req.Title == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "title is required"})
		return
	}
	pdfBytes, err := reporting.ExportPDFAdHoc(req.Title, req.Data)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "render: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="report.pdf"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdfBytes)
}
