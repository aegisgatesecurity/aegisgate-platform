// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/aegisgatesecurity/aegisgate/pkg/tenant"
)

// TenantAPIHandler handles tenant management API requests
type TenantAPIHandler struct {
	manager     *tenant.Manager
	storagePath string
}

// NewTenantAPIHandler creates a new tenant API handler
func NewTenantAPIHandler(manager *tenant.Manager, storagePath string) *TenantAPIHandler {
	return &TenantAPIHandler{
		manager:     manager,
		storagePath: storagePath,
	}
}

// RegisterRoutes registers tenant management routes
func (h *TenantAPIHandler) RegisterRoutes(mux *http.ServeMux) {
	// Tenant CRUD
	mux.HandleFunc("POST /api/v1/tenants", h.CreateTenant)
	mux.HandleFunc("GET /api/v1/tenants", h.ListTenants)
	mux.HandleFunc("GET /api/v1/tenants/{id}", h.GetTenant)
	mux.HandleFunc("PUT /api/v1/tenants/{id}", h.UpdateTenant)
	mux.HandleFunc("DELETE /api/v1/tenants/{id}", h.DeleteTenant)

	// Tenant actions
	mux.HandleFunc("POST /api/v1/tenants/{id}/suspend", h.SuspendTenant)
	mux.HandleFunc("POST /api/v1/tenants/{id}/activate", h.ActivateTenant)

	// Tenant audit logs
	mux.HandleFunc("GET /api/v1/tenants/{id}/audit", h.GetTenantAuditLog)
	mux.HandleFunc("GET /api/v1/tenants/{id}/audit/export", h.ExportTenantAuditLog)

	// Tenant quotas
	mux.HandleFunc("GET /api/v1/tenants/{id}/quota", h.GetTenantQuota)
	mux.HandleFunc("PUT /api/v1/tenants/{id}/quota", h.UpdateTenantQuota)

	// Tenant compliance
	mux.HandleFunc("GET /api/v1/tenants/{id}/compliance", h.GetTenantCompliance)
	mux.HandleFunc("PUT /api/v1/tenants/{id}/compliance", h.UpdateTenantCompliance)
}

// CreateTenant creates a new tenant
func (h *TenantAPIHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Plan   string `json:"plan"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.Name == "" {
		http.Error(w, "ID and Name are required", http.StatusBadRequest)
		return
	}

	// Validate plan
	if req.Plan == "" {
		req.Plan = string(tenant.TenantPlanFree)
	}

	// Create tenant storage path
	tenantStoragePath := filepath.Join(h.storagePath, "tenants", req.ID)

	t, err := h.manager.CreateTenant(req.ID, req.Name, req.Domain, tenantStoragePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Set plan if specified
	if req.Plan != "" {
		t.Plan = tenant.TenantPlan(req.Plan)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}

// ListTenants lists all tenants
func (h *TenantAPIHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	tenants := h.manager.ListTenants()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tenants": tenants,
		"count":   len(tenants),
	})
}

// GetTenant gets a tenant by ID
func (h *TenantAPIHandler) GetTenant(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	t, err := h.manager.GetTenant(id)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}

// UpdateTenant updates a tenant
func (h *TenantAPIHandler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	var req struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Plan   string `json:"plan"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	t, err := h.manager.UpdateTenant(id, req.Name, req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Update plan if specified
	if req.Plan != "" {
		t.Plan = tenant.TenantPlan(req.Plan)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}

// DeleteTenant deletes a tenant
func (h *TenantAPIHandler) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	if err := h.manager.DeleteTenant(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Tenant deleted successfully",
	})
}

// SuspendTenant suspends a tenant
func (h *TenantAPIHandler) SuspendTenant(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	t, err := h.manager.GetTenant(id)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	if err := t.Suspend(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}

// ActivateTenant activates a tenant
func (h *TenantAPIHandler) ActivateTenant(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	t, err := h.manager.GetTenant(id)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	if err := t.Activate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}

// GetTenantAuditLog gets tenant audit logs
func (h *TenantAPIHandler) GetTenantAuditLog(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	t, err := h.manager.GetTenant(id)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	auditLog := t.GetAuditLog()
	if auditLog == nil {
		http.Error(w, "Audit log not available", http.StatusNotFound)
		return
	}

	entries := auditLog.GetAuditLog()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

// ExportTenantAuditLog exports tenant audit logs
func (h *TenantAPIHandler) ExportTenantAuditLog(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	t, err := h.manager.GetTenant(id)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	auditLog := t.GetAuditLog()
	if auditLog == nil {
		http.Error(w, "Audit log not available", http.StatusNotFound)
		return
	}

	data, err := auditLog.ExportForCompliance(r.Context(), format)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=audit-%s.%s", id, format))
	w.Write(data)
}

// GetTenantQuota gets tenant quota
func (h *TenantAPIHandler) GetTenantQuota(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	t, err := h.manager.GetTenant(id)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t.Quota)
}

// UpdateTenantQuota updates tenant quota
func (h *TenantAPIHandler) UpdateTenantQuota(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	t, err := h.manager.GetTenant(id)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	var quota tenant.TenantQuota
	if err := json.NewDecoder(r.Body).Decode(&quota); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	t.Quota = &quota

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t.Quota)
}

// GetTenantCompliance gets tenant compliance settings
func (h *TenantAPIHandler) GetTenantCompliance(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	t, err := h.manager.GetTenant(id)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t.Compliance)
}

// UpdateTenantCompliance updates tenant compliance settings
func (h *TenantAPIHandler) UpdateTenantCompliance(w http.ResponseWriter, r *http.Request) {
	id := extractID(r)
	if id == "" {
		http.Error(w, "Tenant ID required", http.StatusBadRequest)
		return
	}

	t, err := h.manager.GetTenant(id)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	var compliance tenant.TenantCompliance
	if err := json.NewDecoder(r.Body).Decode(&compliance); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	t.Compliance = &compliance

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t.Compliance)
}

// extractID extracts tenant ID from URL path
func extractID(r *http.Request) string {
	// URL format: /api/v1/tenants/{id}/...
	path := r.URL.Path
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "tenants" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// TenantMiddleware extracts tenant ID from request and adds to context
func TenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		parts := strings.Split(path, "/")

		// Check if path is /api/v1/tenants/{id}/...
		if len(parts) >= 4 && parts[1] == "api" && parts[2] == "tenants" {
			tenantID := parts[3]
			if tenantID != "" && !strings.Contains(tenantID, "?") {
				ctx := tenant.WithTenant(r.Context(), tenantID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
