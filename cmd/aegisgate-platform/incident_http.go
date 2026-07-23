// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Incident Response HTTP Endpoints (v3.8)
//
// incident_http.go wires pkg/incident into the HTTP API as:
//   - GET    /api/v1/incidents             (list)
//   - GET    /api/v1/incidents/{id}        (get)
//   - POST   /api/v1/incidents             (create)
//   - PUT    /api/v1/incidents/{id}/triage  (triage)
//   - PUT    /api/v1/incidents/{id}/resolve (resolve)
//
// Tier gating: Incident response is FREE (no gate).
// Auth middleware ensures the caller is authenticated.

package main

import (
	"encoding/json"
	"net/http"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/incident"
)

// wireIncidentHandlers registers the /api/v1/incidents/* HTTP
// routes. All endpoints require authentication.
func wireIncidentHandlers(mux *http.ServeMux, authMW interface {
	RequireAuth(http.HandlerFunc) http.HandlerFunc
}, engine *incident.Engine) {
	if engine == nil {
		// If no engine is available, register a 503 handler.
		mux.HandleFunc("/api/v1/incidents", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "incident engine not available",
			})
		})
		mux.HandleFunc("/api/v1/incidents/{id}/triage", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "incident engine not available",
			})
		})
		mux.HandleFunc("/api/v1/incidents/{id}/resolve", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "incident engine not available",
			})
		})
		return
	}

	// List and Create (collection endpoints).
	mux.HandleFunc("/api/v1/incidents", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleIncidentList(w, r, engine)
		case http.MethodPost:
			handleIncidentCreate(w, r, engine)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		}
	}))

	// Get single incident.
	mux.HandleFunc("/api/v1/incidents/{id}", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
			return
		}
		handleIncidentGet(w, r, engine)
	}))

	// Triage incident.
	mux.HandleFunc("/api/v1/incidents/{id}/triage", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
			return
		}
		handleIncidentTriage(w, r, engine)
	}))

	// Resolve incident.
	mux.HandleFunc("/api/v1/incidents/{id}/resolve", authMW.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
			return
		}
		handleIncidentResolve(w, r, engine)
	}))
}

// handleIncidentList handles GET /api/v1/incidents
func handleIncidentList(w http.ResponseWriter, r *http.Request, engine *incident.Engine) {
	w.Header().Set("Content-Type", "application/json")

	query := &incident.IncidentQuery{}

	// Parse query parameters.
	if status := r.URL.Query().Get("status"); status != "" {
		for _, s := range splitCSV(status) {
			query.Status = append(query.Status, incident.IncidentStatus(s))
		}
	}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		for _, s := range splitCSV(severity) {
			query.Severity = append(query.Severity, incident.IncidentSeverity(s))
		}
	}
	if agentID := r.URL.Query().Get("agent_id"); agentID != "" {
		query.AgentID = agentID
	}
	if sessionID := r.URL.Query().Get("session_id"); sessionID != "" {
		query.SessionID = sessionID
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		var l int
		if _, err := parseInt(limit, &l); err == nil && l > 0 {
			query.Limit = l
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		var o int
		if _, err := parseInt(offset, &o); err == nil && o >= 0 {
			query.Offset = o
		}
	}

	results, err := engine.ListIncidents(r.Context(), query)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(results)
}

// handleIncidentGet handles GET /api/v1/incidents/{id}
func handleIncidentGet(w http.ResponseWriter, r *http.Request, engine *incident.Engine) {
	w.Header().Set("Content-Type", "application/json")
	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "incident id is required"})
		return
	}

	inc, err := engine.GetIncident(r.Context(), id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if inc == nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "incident not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(inc)
}

// handleIncidentCreate handles POST /api/v1/incidents
func handleIncidentCreate(w http.ResponseWriter, r *http.Request, engine *incident.Engine) {
	w.Header().Set("Content-Type", "application/json")

	var req struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Severity    string   `json:"severity"`
		Source      string   `json:"source"`
		AgentID     string   `json:"agent_id"`
		SessionID   string   `json:"session_id"`
		Tags        []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Title == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "title is required"})
		return
	}

	severity := incident.IncidentSeverity(req.Severity)
	if severity == "" {
		severity = incident.SeverityLow
	}
	source := incident.IncidentSource(req.Source)
	if source == "" {
		source = incident.SourceAPI
	}

	inc := incident.NewIncident(req.Title, req.Description, severity, source)
	inc.AgentID = req.AgentID
	inc.SessionID = req.SessionID
	if len(req.Tags) > 0 {
		inc.Tags = req.Tags
	}

	created, err := engine.CreateIncident(r.Context(), inc)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

// handleIncidentTriage handles PUT /api/v1/incidents/{id}/triage
func handleIncidentTriage(w http.ResponseWriter, r *http.Request, engine *incident.Engine) {
	w.Header().Set("Content-Type", "application/json")
	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "incident id is required"})
		return
	}

	var req struct {
		Severity string `json:"severity"`
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	severity := incident.IncidentSeverity(req.Severity)
	if severity == "" {
		severity = incident.SeverityMedium
	}
	if req.Assignee == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "assignee is required"})
		return
	}

	triaged, err := engine.TriageIncident(r.Context(), id, severity, req.Assignee)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(triaged)
}

// handleIncidentResolve handles PUT /api/v1/incidents/{id}/resolve
func handleIncidentResolve(w http.ResponseWriter, r *http.Request, engine *incident.Engine) {
	w.Header().Set("Content-Type", "application/json")
	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "incident id is required"})
		return
	}

	var req struct {
		Resolution string `json:"resolution"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	resolved, err := engine.ResolveIncident(r.Context(), id, req.Resolution)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resolved)
}

// parseInt parses a string into an int pointer.
func parseInt(s string, result *int) (bool, error) {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false, nil
		}
	}
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	*result = n
	return true, nil
}
