// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Tenant Management HTTP Handler
// =========================================================================

package tenant

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// writeJSON encodes v as JSON to w and logs any write errors.
// Satisfies gosec G104 (unhandled errors).
func writeJSON(w http.ResponseWriter, v interface{}) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("tenant handler: json write error: %v", err)
	}
}

// NewHandler returns an http.Handler for the tenant management API that
// works with any Store implementation (in-memory Manager or PostgresManager).
//
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
func NewHandler(s Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		path := strings.TrimPrefix(r.URL.Path, "/api/v1/tenants")
		path = strings.TrimPrefix(path, "/")

		ctx := r.Context()

		switch {
		case path == "" && r.Method == http.MethodGet:
			handlerList(ctx, w, s)
		case path == "" && r.Method == http.MethodPost:
			handlerCreate(ctx, w, r, s)
		case path != "" && r.Method == http.MethodGet:
			handlerGet(ctx, w, s, path)
		case path != "" && r.Method == http.MethodPut:
			handlerUpdate(ctx, w, r, s, path)
		case path != "" && r.Method == http.MethodDelete:
			handlerDelete(ctx, w, s, path)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			writeJSON(w, map[string]string{"error": "method not allowed"})
		}
	})
}

func handlerList(ctx context.Context, w http.ResponseWriter, s Store) {
	tenants, err := s.List(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	if tenants == nil {
		tenants = []*Tenant{}
	}
	writeJSON(w, map[string]interface{}{"tenants": tenants, "count": len(tenants)})
}

func handlerCreate(ctx context.Context, w http.ResponseWriter, r *http.Request, s Store) {
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
		writeJSON(w, map[string]string{"error": "invalid JSON body"})
		return
	}
	tnt, err := s.Create(ctx, req.Name, req.DisplayName, req.Email, req.LicenseTier, req.MaxUsers, req.MaxAgents)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, tnt)
}

func handlerGet(ctx context.Context, w http.ResponseWriter, s Store, id string) {
	tnt, err := s.Get(ctx, id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, tnt)
}

func handlerUpdate(ctx context.Context, w http.ResponseWriter, r *http.Request, s Store, id string) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid JSON body"})
		return
	}
	tnt, err := s.Update(ctx, id, updates)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, tnt)
}

func handlerDelete(ctx context.Context, w http.ResponseWriter, s Store, id string) {
	if err := s.Delete(ctx, id); err != nil {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ========================================================================
// In-memory Manager adapter for the Store interface
// ========================================================================
// The in-memory Manager has context-free methods (Create, Get, List, etc.)
// that don't match the Store interface signatures. The memStore adapter
// wraps *Manager and implements Store by ignoring the context parameter
// and delegating to the existing methods. This preserves backward
// compatibility — existing callers that use the non-context methods
// continue to work unchanged.

type memStore struct {
	m *Manager
}

func (ms *memStore) Create(_ context.Context, name, displayName, email, licenseTier string, maxUsers, maxAgents int) (*Tenant, error) {
	return ms.m.Create(name, displayName, email, licenseTier, maxUsers, maxAgents)
}

func (ms *memStore) Get(_ context.Context, id string) (*Tenant, error) {
	return ms.m.Get(id)
}

func (ms *memStore) List(_ context.Context) ([]*Tenant, error) {
	return ms.m.List(), nil
}

func (ms *memStore) Update(_ context.Context, id string, updates map[string]interface{}) (*Tenant, error) {
	return ms.m.Update(id, updates)
}

func (ms *memStore) Delete(_ context.Context, id string) error {
	return ms.m.Delete(id)
}

func (ms *memStore) Count(_ context.Context) (int, error) {
	return ms.m.Count(), nil
}

// Handler returns an http.Handler for the tenant management API.
// This is the backward-compatible method on the in-memory Manager.
// It delegates to NewHandler via the memStore adapter so the routing
// logic is shared between in-memory and PostgreSQL backends.
func (m *Manager) Handler() http.Handler {
	return NewHandler(&memStore{m: m})
}
