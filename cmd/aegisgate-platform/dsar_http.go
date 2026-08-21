// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — DSAR HTTP Endpoints (v4.3.1)
//
// dsar_http.go provides HTTP endpoints for GDPR Articles 15-20:
//   POST /api/v1/dsar/export   — export all data for an entity
//   POST /api/v1/dsar/erase    — erase all data for an entity (blocked by legal hold)
//
// Both endpoints require admin permission.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/dsar"
)

// dsarService is a type alias so we can reference *dsar.Service without
// importing it in every file. main.go creates the service and passes it.
type dsarService = dsar.Service

// wireDSARHandlers registers DSAR HTTP endpoints on the dashboard mux.
func wireDSARHandlers(mux *http.ServeMux, amw *auth.Middleware, svc *dsarService) {
	if svc == nil {
		return
	}

	// POST /api/v1/dsar/export — export all data for an entity
	mux.HandleFunc("/api/v1/dsar/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		amw.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				EntityID string `json:"entity_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			if req.EntityID == "" {
				writeJSONError(w, http.StatusBadRequest, "entity_id is required")
				return
			}

			bundle, err := svc.Export(r.Context(), req.EntityID)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("export failed: %v", err))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"dsar-export-%s.json\"", sanitizeFilename(req.EntityID)))
			json.NewEncoder(w).Encode(bundle)
		})(w, r)
	})

	// POST /api/v1/dsar/erase — erase all data for an entity
	mux.HandleFunc("/api/v1/dsar/erase", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		amw.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				EntityID string `json:"entity_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid request body")
				return
			}
			if req.EntityID == "" {
				writeJSONError(w, http.StatusBadRequest, "entity_id is required")
				return
			}

			result, err := svc.Erase(r.Context(), req.EntityID)
			if err != nil {
				// If blocked by legal hold, return 409 Conflict
				if result != nil && result.BlockedBy == "legal_hold" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					json.NewEncoder(w).Encode(result)
					return
				}
				writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("erase failed: %v", err))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
		})(w, r)
	})
}

// writeJSONError is defined in posture_http.go — reused here.

// sanitizeFilename removes characters that are unsafe in filenames.
func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
