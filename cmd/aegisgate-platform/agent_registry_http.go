// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Registry HTTP Endpoints (v5.0)
//
// agent_registry_http.go wires pkg/agentregistry into the HTTP API as:
//   - GET    /api/v1/agents               (list with optional filters)
//   - GET    /api/v1/agents/{id}          (single agent detail)
//   - POST   /api/v1/agents/{id}/lifecycle (manual status transition)
//   - GET    /api/v1/agents/dormancy      (dormancy report)
//   - GET    /api/v1/agents/drift         (AIBOM reconciliation report)
//   - GET    /api/v1/agent-policies       (list lifecycle policies)
//   - POST   /api/v1/agent-policies       (create/update policy)
//   - DELETE /api/v1/agent-policies/{id}  (delete policy)
//   - POST   /api/v1/agents/refresh       (trigger manual discovery)
//   - GET    /api/v1/agents/stream        (SSE lifecycle event stream)
//
// Permission model:
//   - Read endpoints require rbac.Permission{Resource: rbac.ResourceAgent, Action: rbac.ActionRead}
//   - Manage endpoints require rbac.Permission{Resource: rbac.ResourceAgent, Action: rbac.ActionManage}
//
// Tier gating: The entire Agent Registry feature is gated behind
// Professional tier (FeatureAgentRegistry). The tier check is
// performed at the wiring point in main.go; if the feature is not
// licensed, wireAgentRegistryHandlers registers 503 handlers.

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/agentregistry"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// wireAgentRegistryHandlers registers the /api/v1/agents/* HTTP
// routes. All endpoints require authentication. Read endpoints
// require ResourceAgent:ActionRead; manage endpoints require
// ResourceAgent:ActionManage.
//
// If registry is nil, 503 handlers are registered instead.
func wireAgentRegistryHandlers(
	mux *http.ServeMux,
	authMW *auth.Middleware,
	registry *agentregistry.Registry,
	policyEngine *agentregistry.PolicyEngine,
	dormancyEngine *agentregistry.DormancyEngine,
	broadcaster *agentregistry.EventBroadcaster,
) {
	readPerm := rbac.Permission{Resource: rbac.ResourceAgent, Action: rbac.ActionRead}
	managePerm := rbac.Permission{Resource: rbac.ResourceAgent, Action: rbac.ActionManage}

	if registry == nil {
		registerAgentRegistryUnavailable(mux)
		return
	}

	// Collection endpoint: list (read permission).
	mux.HandleFunc("GET /api/v1/agents", authMW.RequirePermission(readPerm, func(w http.ResponseWriter, r *http.Request) {
		handleAgentList(w, r, registry)
	}))

	// SSE stream endpoint.
	if broadcaster != nil {
		mux.HandleFunc("GET /api/v1/agents/stream", authMW.RequirePermission(readPerm, broadcaster.HandleSSE))
	}

	// Dormancy report.
	mux.HandleFunc("GET /api/v1/agents/dormancy", authMW.RequirePermission(readPerm, func(w http.ResponseWriter, r *http.Request) {
		handleAgentDormancy(w, r, registry, dormancyEngine)
	}))

	// Drift report.
	mux.HandleFunc("GET /api/v1/agents/drift", authMW.RequirePermission(readPerm, func(w http.ResponseWriter, r *http.Request) {
		handleAgentDrift(w, r, registry)
	}))

	// Policy collection: list (read) + create (manage).
	mux.HandleFunc("GET /api/v1/agent-policies", authMW.RequirePermission(readPerm, func(w http.ResponseWriter, r *http.Request) {
		handleAgentPolicyList(w, r, policyEngine)
	}))
	mux.HandleFunc("POST /api/v1/agent-policies", authMW.RequirePermission(managePerm, func(w http.ResponseWriter, r *http.Request) {
		handleAgentPolicyCreate(w, r, policyEngine)
	}))

	// Manual refresh (manage).
	mux.HandleFunc("POST /api/v1/agents/refresh", authMW.RequirePermission(managePerm, func(w http.ResponseWriter, r *http.Request) {
		handleAgentRefresh(w, r, registry)
	}))

	// Single agent: get (read).
	mux.HandleFunc("GET /api/v1/agents/{id}", authMW.RequirePermission(readPerm, func(w http.ResponseWriter, r *http.Request) {
		handleAgentGet(w, r, registry)
	}))

	// Lifecycle transition (manage).
	mux.HandleFunc("POST /api/v1/agents/{id}/lifecycle", authMW.RequirePermission(managePerm, func(w http.ResponseWriter, r *http.Request) {
		handleAgentLifecycle(w, r, registry)
	}))

	// Single policy: delete (manage).
	mux.HandleFunc("DELETE /api/v1/agent-policies/{id}", authMW.RequirePermission(managePerm, func(w http.ResponseWriter, r *http.Request) {
		handleAgentPolicyDelete(w, r, policyEngine)
	}))
}

// wireAgentRegistryFederationHandlers registers the federation HTTP
// routes for cross-deployment agent inventory sharing. If fedEngine
// is nil or federation is not enabled, 503 handlers are registered.
//
// Endpoints:
//   - GET  /api/v1/agents/federation/bundle  (export signed attestation bundle)
//   - POST /api/v1/agents/federation/bundle  (import peer attestation bundle)
//   - GET  /api/v1/agents/federation/drift   (cross-deployment drift report)
func wireAgentRegistryFederationHandlers(
	mux *http.ServeMux,
	authMW *auth.Middleware,
	fedEngine *agentregistry.FederationEngine,
) {
	if fedEngine == nil || !fedEngine.Enabled() {
		handler := func(w http.ResponseWriter, r *http.Request) {
			writeAgentJSONError(w, http.StatusServiceUnavailable, "agent federation not enabled")
		}
		mux.HandleFunc("GET /api/v1/agents/federation/bundle", handler)
		mux.HandleFunc("POST /api/v1/agents/federation/bundle", handler)
		mux.HandleFunc("GET /api/v1/agents/federation/drift", handler)
		return
	}

	readPerm := rbac.Permission{Resource: rbac.ResourceAgent, Action: rbac.ActionRead}
	managePerm := rbac.Permission{Resource: rbac.ResourceAgent, Action: rbac.ActionManage}

	mux.HandleFunc("GET /api/v1/agents/federation/bundle", authMW.RequirePermission(readPerm, fedEngine.ServeFederationBundle))
	mux.HandleFunc("POST /api/v1/agents/federation/bundle", authMW.RequirePermission(managePerm, fedEngine.ReceiveFederationBundle))
	mux.HandleFunc("GET /api/v1/agents/federation/drift", authMW.RequirePermission(readPerm, fedEngine.ServeCrossDeploymentReport))
}

// registerAgentRegistryUnavailable registers 503 handlers for all
// agent registry endpoints when the registry is not initialized.
func registerAgentRegistryUnavailable(mux *http.ServeMux) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		writeAgentJSONError(w, http.StatusServiceUnavailable, "agent registry not available")
	}
	patterns := []string{
		"GET /api/v1/agents",
		"GET /api/v1/agents/{id}",
		"POST /api/v1/agents/{id}/lifecycle",
		"GET /api/v1/agents/dormancy",
		"GET /api/v1/agents/drift",
		"GET /api/v1/agent-policies",
		"POST /api/v1/agent-policies",
		"DELETE /api/v1/agent-policies/{id}",
		"POST /api/v1/agents/refresh",
		"GET /api/v1/agents/stream",
	}
	for _, p := range patterns {
		mux.HandleFunc(p, handler)
	}
}

// =====================================================================
// Handler functions
// =====================================================================

// handleAgentList handles GET /api/v1/agents
func handleAgentList(w http.ResponseWriter, r *http.Request, registry *agentregistry.Registry) {
	filter := &agentregistry.ListFilter{}

	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = agentregistry.AgentStatus(status)
	}
	if protocol := r.URL.Query().Get("protocol"); protocol != "" {
		filter.Protocol = agentregistry.Protocol(protocol)
	}
	if owner := r.URL.Query().Get("owner"); owner != "" {
		filter.Owner = owner
	}
	if tenantID := r.URL.Query().Get("tenant_id"); tenantID != "" {
		filter.TenantID = tenantID
	}
	if tag := r.URL.Query().Get("tag"); tag != "" {
		filter.Tag = parseTagQuery(tag)
	}

	records, err := registry.List(filter)
	if err != nil {
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"agents": records,
		"count":  len(records),
	})
}

// handleAgentGet handles GET /api/v1/agents/{id}
func handleAgentGet(w http.ResponseWriter, r *http.Request, registry *agentregistry.Registry) {
	id := r.PathValue("id")
	if id == "" {
		writeAgentJSONError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	record, err := registry.Get(id)
	if err != nil {
		if isAgentNotFound(err) {
			writeAgentJSONError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(record)
}

// handleAgentLifecycle handles POST /api/v1/agents/{id}/lifecycle
func handleAgentLifecycle(w http.ResponseWriter, r *http.Request, registry *agentregistry.Registry) {
	id := r.PathValue("id")
	if id == "" {
		writeAgentJSONError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	var req struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAgentJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Status == "" {
		writeAgentJSONError(w, http.StatusBadRequest, "status is required")
		return
	}

	newStatus := agentregistry.AgentStatus(req.Status)
	if !isValidAgentStatus(newStatus) {
		writeAgentJSONError(w, http.StatusBadRequest, "invalid status: "+req.Status)
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "manual_transition"
	}

	if err := registry.Transition(id, newStatus, reason); err != nil {
		if isAgentNotFound(err) {
			writeAgentJSONError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	record, err := registry.Get(id)
	if err != nil {
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(record)
}

// handleAgentDormancy handles GET /api/v1/agents/dormancy
func handleAgentDormancy(w http.ResponseWriter, r *http.Request, registry *agentregistry.Registry, dormancy *agentregistry.DormancyEngine) {
	records, err := registry.List(nil)
	if err != nil {
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var report *agentregistry.DormancyReport
	if dormancy != nil {
		report = dormancy.Classify(records, nil)
	} else {
		report = buildDormancyReportFallback(records)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(report)
}

// handleAgentDrift handles GET /api/v1/agents/drift
func handleAgentDrift(w http.ResponseWriter, r *http.Request, registry *agentregistry.Registry) {
	report, err := registry.Reconcile(r.Context())
	if err != nil {
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(report)
}

// handleAgentPolicyList handles GET /api/v1/agents/policies
func handleAgentPolicyList(w http.ResponseWriter, r *http.Request, engine *agentregistry.PolicyEngine) {
	if engine == nil {
		writeAgentJSONError(w, http.StatusServiceUnavailable, "policy engine not available")
		return
	}

	policies, err := engine.ListPolicies(r.Context())
	if err != nil {
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
	})
}

// handleAgentPolicyCreate handles POST /api/v1/agents/policies
func handleAgentPolicyCreate(w http.ResponseWriter, r *http.Request, engine *agentregistry.PolicyEngine) {
	if engine == nil {
		writeAgentJSONError(w, http.StatusServiceUnavailable, "policy engine not available")
		return
	}

	var policy agentregistry.LifecyclePolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		writeAgentJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if policy.ID == "" {
		writeAgentJSONError(w, http.StatusBadRequest, "policy id is required")
		return
	}
	if policy.Name == "" {
		writeAgentJSONError(w, http.StatusBadRequest, "policy name is required")
		return
	}
	if policy.DormancyThreshold <= 0 {
		writeAgentJSONError(w, http.StatusBadRequest, "dormancy_threshold must be positive")
		return
	}

	if err := engine.AddPolicy(r.Context(), &policy); err != nil {
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(&policy)
}

// handleAgentPolicyDelete handles DELETE /api/v1/agents/policies/{id}
func handleAgentPolicyDelete(w http.ResponseWriter, r *http.Request, engine *agentregistry.PolicyEngine) {
	if engine == nil {
		writeAgentJSONError(w, http.StatusServiceUnavailable, "policy engine not available")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeAgentJSONError(w, http.StatusBadRequest, "policy id is required")
		return
	}

	if err := engine.RemovePolicy(r.Context(), id); err != nil {
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "deleted",
		"policy_id": id,
	})
}

// handleAgentRefresh handles POST /api/v1/agents/refresh
func handleAgentRefresh(w http.ResponseWriter, r *http.Request, registry *agentregistry.Registry) {
	if err := registry.Discover(r.Context()); err != nil {
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	records, err := registry.List(nil)
	if err != nil {
		writeAgentJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "refreshed",
		"count":  len(records),
	})
}

// =====================================================================
// Helpers
// =====================================================================

// writeAgentJSONError writes a JSON error response.
func writeAgentJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// isAgentNotFound returns true if the error is an agentregistry
// "not found" error.
func isAgentNotFound(err error) bool {
	return strings.Contains(err.Error(), "not found")
}

// isValidAgentStatus returns true if s is a recognized AgentStatus.
func isValidAgentStatus(s agentregistry.AgentStatus) bool {
	switch s {
	case agentregistry.StatusProvisioned,
		agentregistry.StatusActive,
		agentregistry.StatusDormant,
		agentregistry.StatusQuarantined,
		agentregistry.StatusRevoked:
		return true
	}
	return false
}

// parseTagQuery parses a "key=value" tag query parameter into a
// single-entry map. Returns nil if the format is invalid.
func parseTagQuery(s string) map[string]string {
	idx := strings.Index(s, "=")
	if idx <= 0 || idx == len(s)-1 {
		return nil
	}
	return map[string]string{
		s[:idx]: s[idx+1:],
	}
}

// buildDormancyReportFallback builds a dormancy report without a
// DormancyEngine by counting agents by their current stored status.
// This is used when the DormancyEngine is not initialized.
func buildDormancyReportFallback(records []*agentregistry.AgentRecord) *agentregistry.DormancyReport {
	report := &agentregistry.DormancyReport{
		GeneratedAt: time.Now().UTC(),
		Total:       len(records),
	}
	for _, r := range records {
		entry := agentregistry.DormancyEntry{
			AgentID:        r.ID,
			Name:           r.Name,
			Status:         r.Status,
			LastActivity:   r.LastActivity,
			Protocols:      r.Protocols,
			Owner:          r.Owner,
			ActiveSessions: r.ActiveSessions,
		}
		if !r.LastActivity.IsZero() {
			entry.DormantFor = time.Since(r.LastActivity)
		}
		report.Agents = append(report.Agents, entry)

		switch r.Status {
		case agentregistry.StatusActive:
			report.Active++
		case agentregistry.StatusDormant:
			report.Dormant++
		case agentregistry.StatusQuarantined:
			report.Quarantined++
		case agentregistry.StatusRevoked:
			report.Revoked++
		case agentregistry.StatusProvisioned:
			report.Provisioned++
		}
	}
	return report
}
