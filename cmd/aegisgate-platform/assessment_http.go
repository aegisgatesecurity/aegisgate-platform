// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Posture Assessment HTTP endpoint
//
// assessment_http.go wires pkg/assessment into the HTTP API as
//   - POST /api/v1/assessment/run              — Run a new assessment
//   - GET  /api/v1/assessment/current          — Current assessment summary
//   - GET  /api/v1/assessment/current/radar    — OWASP radar data
//   - GET  /api/v1/assessment/current/gaps     — Gap analysis view
//   - GET  /api/v1/assessment/current/compliance — Compliance posture
//   - GET  /api/v1/assessment/current/pdf      — Download PDF report
//   - GET  /api/v1/assessment/current/signed   — Download signed PDF
//   - GET  /api/v1/assessment/history          — Assessment history
//   - GET  /api/v1/assessment/trend            — Score trend data
//
// Tier gating: Posture assessment is FREE (no gate); auth middleware
// ensures the caller is authenticated.

package main

import (
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/assessment"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
)

// wireAssessmentHandlers registers the /api/v1/assessment/*
// HTTP routes. The assessment endpoints are free (no tier gate);
// the auth middleware just ensures the caller is authenticated.
func wireAssessmentHandlers(mux *http.ServeMux, authMW *auth.Middleware) {
	store := assessment.NewAssessmentStore()
	cfg := assessment.DefaultRunnerConfig()
	handler := assessment.NewAssessmentHTTPHandler(store, cfg)

	mux.Handle("/api/v1/assessment/", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		http.StripPrefix("/api/v1/assessment", handler.Handler()).ServeHTTP(w, r)
	}))
}
