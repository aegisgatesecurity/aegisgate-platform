// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Legal Hold HTTP Endpoints (v4.3.1)
//
// legalhold_http.go wires pkg/legalhold into the HTTP API as:
//   - POST   /api/v1/legal-holds           (create hold)
//   - GET    /api/v1/legal-holds           (list holds)
//   - GET    /api/v1/legal-holds/{id}      (get hold)
//   - DELETE /api/v1/legal-holds/{id}      (release hold)
//   - GET    /api/v1/legal-holds/check/{entityID} (check if under hold)
//
// All endpoints require authentication. Creating/releasing holds
// requires admin role (enforced by auth middleware tier gating).

package main

import (
	"encoding/json"
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/legalhold"
)

// wireLegalHoldHandlers registers the /api/v1/legal-holds/* HTTP routes.
func wireLegalHoldHandlers(mux *http.ServeMux, authMW *auth.Middleware, svc *legalhold.Service) {
	if svc == nil {
		return
	}

	// Create hold
	mux.HandleFunc("POST /api/v1/legal-holds", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			EntityID   string `json:"entity_id"`
			EntityType string `json:"entity_type"`
			Reason     string `json:"reason"`
			IssuedBy   string `json:"issued_by"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
			return
		}
		hold, err := svc.CreateHold(r.Context(), req.EntityID, req.EntityType, req.Reason, req.IssuedBy)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(hold)
	}))

	// List holds
	mux.HandleFunc("GET /api/v1/legal-holds", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		holds := svc.ListHolds(r.Context())
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(holds)
	}))

	// Get hold by ID
	mux.HandleFunc("GET /api/v1/legal-holds/{id}", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		hold, err := svc.GetHold(r.Context(), r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(hold)
	}))

	// Release hold
	mux.HandleFunc("DELETE /api/v1/legal-holds/{id}", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := svc.ReleaseHold(r.Context(), r.PathValue("id")); err != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "released"})
	}))

	// Check if entity is under hold
	mux.HandleFunc("GET /api/v1/legal-holds/check/{entityID}", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		entityID := r.PathValue("entityID")
		underHold := svc.IsUnderHold(r.Context(), entityID)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]bool{"under_hold": underHold})
	}))
}
