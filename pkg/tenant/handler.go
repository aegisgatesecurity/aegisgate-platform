// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Tenant Management HTTP Handler
// =========================================================================

package tenant

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Handler returns an http.Handler for the tenant management API.
// All methods require authentication (enforced by the caller wrapping
// with authMiddleware.RequireAuth or RequirePermission). Write operations
// (POST/PUT/DELETE) should additionally be wrapped with AdminOnly or
// RequirePermission(user:manage).
//
// Routes:
//
//	GET    /api/v1/tenants          — list all tenants
//	POST   /api/v1/tenants          — create a tenant
//	GET    /api/v1/tenants/{id}     — get a tenant by ID
//	PUT    /api/v1/tenants/{id}     — update a tenant
//	DELETE /api/v1/tenants/{id}     — delete a tenant
func (m *Manager) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		path := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants")
		path = strings.TrimPrefix(path, "/")

		switch {
		case path == "" && r.Method == http.MethodGet:
			m.handleList(w, r)
		case path == "" && r.Method == http.MethodPost:
			m.handleCreate(w, r)
		case path != "" && r.Method == http.MethodGet:
			m.handleGet(w, r, path)
		case path != "" && r.Method == http.MethodPut:
			m.handleUpdate(w, r, path)
		case path != "" && r.Method == http.MethodDelete:
			m.handleDelete(w, r, path)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		}
	})
}

func (m *Manager) handleList(w http.ResponseWriter, _ *http.Request) {
	tenants := m.List()
	if tenants == nil {
		tenants = []*Tenant{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"tenants": tenants, "count": len(tenants)})
}

func (m *Manager) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
		Email       string `json:"email"`
		LicenseTier string `json:"licenseTier"`
		MaxUsers    int    `json:"maxUsers"`
		MaxAgents   int    `json:"maxAgents"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON body"})
		return
	}
	tnt, err := m.Create(req.Name, req.DisplayName, req.Email, req.LicenseTier, req.MaxUsers, req.MaxAgents)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(tnt)
}

func (m *Manager) handleGet(w http.ResponseWriter, _ *http.Request, id string) {
	tnt, err := m.Get(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(tnt)
}

func (m *Manager) handleUpdate(w http.ResponseWriter, r *http.Request, id string) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON body"})
		return
	}
	tnt, err := m.Update(id, updates)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(tnt)
}

func (m *Manager) handleDelete(w http.ResponseWriter, _ *http.Request, id string) {
	if err := m.Delete(id); err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}