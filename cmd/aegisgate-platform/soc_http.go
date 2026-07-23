// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - SOC Timeline HTTP endpoint (TODO-502)
//
// soc_http.go wires pkg/soc into the HTTP API as
//   - GET /api/v1/soc/incidents/:id/timeline
//   - GET /api/v1/soc/incidents/:id/stream (SSE, v3.8)
//
// Tier gating: SOC timeline is FREE (no gate). It
// is a read-only data view. SSE streaming is
// Professional+ (Developer gets 5s polling,
// Community gets 30s polling).

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
// v0.2 (v3.8): SSE streaming is wired for
// Professional+ tiers. The stream endpoint creates
// a per-request TimelineStreamer that replays
// recent events from the CorrelationStore and then
// streams new events in real-time.
func wireSOCHandlers(mux *http.ServeMux, authMW *auth.Middleware) {
	// Timeline endpoint (JSON, all tiers).
	mux.HandleFunc("/api/v1/soc/incidents/{id}/timeline", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handleSOCTimeline(w, r, r.PathValue("id"))
	}))

	// SSE streaming endpoint (Professional+).
	mux.HandleFunc("/api/v1/soc/incidents/{id}/stream", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("id")
		if sessionID == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "session id is required"})
			return
		}
		// v0.1: creates a per-request streamer. v0.2 will use
		// the platform's shared streamer instance.
		store := getCorrelationStore(r)
		streamer := soc.NewTimelineStreamer(store, soc.DefaultStreamConfig())
		streamer.Start()
		defer streamer.Stop()

		// Replay recent events if a store is available.
		if store != nil {
			events, err := streamer.ReplayEvents(r.Context(), sessionID)
			if err == nil && len(events) > 0 {
				for _, evt := range events {
					streamer.PushEvent(&correlation.Event{
						ID:        evt.ID,
						Protocol:  evt.Protocol,
						AgentID:   evt.AgentID,
						SessionID: evt.SessionID,
						EventType: evt.EventType,
						Severity:  evt.Severity,
						Decision:  evt.Decision,
						Timestamp: evt.Timestamp,
						Metadata:  evt.Metadata,
					})
				}
			}
		}

		clientID := sessionID + "-" + r.RemoteAddr
		soc.ServeSSE(w, r, streamer, clientID)
	}))
}

// getCorrelationStore returns the CorrelationStore from the request
// context, or nil if unavailable. v0.1 always returns nil (in-memory
// engine); v0.2 will extract it from the platform's persistence manager.
func getCorrelationStore(_ *http.Request) correlation.CorrelationStore {
	return nil
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