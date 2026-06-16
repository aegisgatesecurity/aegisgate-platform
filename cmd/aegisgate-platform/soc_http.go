// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - SOC Timeline HTTP endpoint (TODO-502)
//
// soc_http.go wires pkg/soc into the HTTP API as
//   - GET /api/v1/soc/incidents/:id/timeline
//
// Tier gating: SOC timeline is FREE (no gate). It
// is a read-only data view.

package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/soc"
)

// wireSOCHandlers registers the /api/v1/soc/* HTTP
// routes. The timeline endpoint is free (no tier
// gate); the auth middleware ensures the caller
// is authenticated.
//
// v0.1: the timeline is read from a fresh
// correlation.Engine instance. v0.2 will wire the
// platform's shared engine instance.
//
// We use Go's standard http.ServeMux pattern
// matching: the URL pattern
// /api/v1/soc/incidents/{id}/timeline is registered
// with id as a path wildcard. (Go 1.22+ mux
// supports {id} natively; we use the stdlib mux
// pattern, NOT a custom regex.)
func wireSOCHandlers(mux *http.ServeMux, authMW *auth.Middleware) {
	// Register the exact pattern. The Go 1.22+ mux
	// supports {id} as a path variable.
	mux.HandleFunc("/api/v1/soc/incidents/{id}/timeline", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		// r.PathValue("id") is the session ID.
		// Available in Go 1.22+.
		handleSOCTimeline(w, r, r.PathValue("id"))
	}))
}

// handleSOCTimeline is the HTTP handler for
// GET /api/v1/soc/incidents/:id/timeline. The
// response is the TimelineResult JSON shape.
func handleSOCTimeline(w http.ResponseWriter, r *http.Request, sessionID string) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed (use GET)"})
		return
	}
	if sessionID == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "session id is required"})
		return
	}
	// v0.1: create a fresh engine (in-memory). v0.2
	// will use the platform's shared engine.
	engine := correlation.NewEngine()
	wrapped := soc.WrapEngine(engine)
	result, err := soc.GetTimeline(context.Background(), wrapped, sessionID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "get timeline: " + err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
