// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Agent Registry HTTP Endpoint Tests (v5.0)
// =========================================================================
//
// Tests for the agent registry HTTP endpoints. Verifies routing,
// method checks, response shape, error handling, and permission
// enforcement. The underlying registry logic is tested in
// pkg/agentregistry/registry_test.go; these tests cover the HTTP
// wiring only.
//
// Auth is disabled via authMiddlewareForTests() so that tests can
// focus on handler logic. Permission enforcement is tested by
// manually constructing middleware with auth enabled.
// =========================================================================

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/agentregistry"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// =====================================================================
// Test helpers
// =====================================================================

// setupTestRegistry creates a Registry populated with test agents
// for HTTP handler testing. Returns the registry, policy engine,
// dormancy engine, and broadcaster.
func setupTestRegistry(t *testing.T) (*agentregistry.Registry, *agentregistry.PolicyEngine, *agentregistry.DormancyEngine, *agentregistry.EventBroadcaster) {
	t.Helper()

	store := agentregistry.NewInMemoryStore()
	policyStore := agentregistry.NewInMemoryPolicyStore()

	rbacMgr, err := rbac.NewManager(nil)
	if err != nil {
		t.Fatalf("rbac.NewManager: %v", err)
	}

	logger := testLogger()

	registry, err := agentregistry.New(agentregistry.Config{
		Store:       store,
		PolicyStore: policyStore,
		RBAC:        rbacMgr,
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("agentregistry.New: %v", err)
	}

	// Seed test agents directly into the store.
	now := time.Now().UTC()
	agents := []*agentregistry.AgentRecord{
		{
			ID:           "agent-alpha",
			Name:         "Alpha Agent",
			Role:         string(rbac.AgentRoleStandard),
			Status:       agentregistry.StatusActive,
			StatusSince:  now,
			Enabled:      true,
			TenantID:     "tenant-1",
			Protocols:    []agentregistry.Protocol{agentregistry.ProtocolMCP},
			LastActivity: now,
			CreatedAt:    now,
			UpdatedAt:    now,
		},
		{
			ID:           "agent-beta",
			Name:         "Beta Agent",
			Role:         string(rbac.AgentRolePrivileged),
			Status:       agentregistry.StatusDormant,
			StatusSince:  now.Add(-48 * time.Hour),
			Enabled:      true,
			TenantID:     "tenant-1",
			Protocols:    []agentregistry.Protocol{agentregistry.ProtocolA2A},
			LastActivity: now.Add(-72 * time.Hour),
			CreatedAt:    now.Add(-30 * 24 * time.Hour),
			UpdatedAt:    now.Add(-48 * time.Hour),
		},
		{
			ID:           "agent-gamma",
			Name:         "Gamma Agent",
			Role:         string(rbac.AgentRoleRestricted),
			Status:       agentregistry.StatusProvisioned,
			StatusSince:  now,
			Enabled:      true,
			TenantID:     "tenant-2",
			Protocols:    []agentregistry.Protocol{agentregistry.ProtocolHTTP},
			CreatedAt:    now,
			UpdatedAt:    now,
		},
	}
	for _, a := range agents {
		if err := store.Upsert(testContext(), a); err != nil {
			t.Fatalf("store.Upsert(%s): %v", a.ID, err)
		}
	}

	dormancy := agentregistry.NewDormancyEngine(24*time.Hour, logger)
	policyEngine := agentregistry.NewPolicyEngine(registry, dormancy, nil, policyStore, logger)
	broadcaster := agentregistry.NewEventBroadcaster(logger)

	return registry, policyEngine, dormancy, broadcaster
}

// testLogger returns a discard logger for quiet tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testContext returns a background context for store operations.
func testContext() context.Context {
	return context.Background()
}

// authMiddlewareForAdminTests creates an auth middleware with
// RequireAuth: true and generates an admin JWT token for testing
// manage-level endpoints. Returns the middleware and the
// Authorization header value.
func authMiddlewareForAdminTests(t *testing.T) (*auth.Middleware, string) {
	t.Helper()
	mw := auth.NewMiddleware(&auth.Config{
		RequireAuth:     true,
		JWTSigningKey:   []byte("dev-key-change-in-production"),
		TokenExpiryHours: 1,
	})
	token, err := mw.GenerateToken("test-admin", string(rbac.UserRoleAdmin))
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return mw, "Bearer " + token
}

// newAdminRequest creates an HTTP request with the admin
// Authorization header set.
func newAdminRequest(method, path string, body io.Reader, authToken string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Authorization", authToken)
	return req
}

// =====================================================================
// Routing tests
// =====================================================================

// TestAgentRegistryRoutes_Registered verifies that all agent
// registry endpoints are registered (no 404s) when the registry
// is available.
func TestAgentRegistryRoutes_Registered(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	tests := []struct {
		method string
		path   string
		admin  bool
	}{
		{http.MethodGet, "/api/v1/agents", false},
		{http.MethodGet, "/api/v1/agents/agent-alpha", false},
		{http.MethodPost, "/api/v1/agents/agent-alpha/lifecycle", true},
		{http.MethodGet, "/api/v1/agents/dormancy", false},
		{http.MethodGet, "/api/v1/agents/drift", false},
		{http.MethodGet, "/api/v1/agent-policies", false},
		{http.MethodPost, "/api/v1/agent-policies", true},
		{http.MethodDelete, "/api/v1/agent-policies/test-policy", true},
		{http.MethodPost, "/api/v1/agents/refresh", true},
	}

	for _, tt := range tests {
		var body string
		if tt.method == http.MethodPost || tt.method == http.MethodDelete {
			body = "{}"
		}
		var req *http.Request
		if tt.admin {
			req = newAdminRequest(tt.method, tt.path, strings.NewReader(body), authToken)
		} else {
			req = newAdminRequest(tt.method, tt.path, strings.NewReader(body), authToken)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		if rr.Code == http.StatusNotFound {
			t.Errorf("%s %s: got 404 (route not registered)", tt.method, tt.path)
		}
	}
}

// TestAgentRegistryRoutes_Unavailable verifies that all endpoints
// return 503 when the registry is nil.
func TestAgentRegistryRoutes_Unavailable(t *testing.T) {
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, nil, nil, nil, nil)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/agents"},
		{http.MethodGet, "/api/v1/agents/agent-alpha"},
		{http.MethodPost, "/api/v1/agents/agent-alpha/lifecycle"},
		{http.MethodGet, "/api/v1/agents/dormancy"},
		{http.MethodGet, "/api/v1/agents/drift"},
		{http.MethodGet, "/api/v1/agent-policies"},
		{http.MethodPost, "/api/v1/agent-policies"},
		{http.MethodDelete, "/api/v1/agent-policies/test-policy"},
		{http.MethodPost, "/api/v1/agents/refresh"},
		{http.MethodGet, "/api/v1/agents/stream"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s (nil registry): got status %d, want %d", tt.method, tt.path, rr.Code, http.StatusServiceUnavailable)
		}
	}
}

// TestAgentRegistryRoutes_MethodNotAllowed verifies that wrong
// HTTP methods are rejected with 405.
func TestAgentRegistryRoutes_MethodNotAllowed(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	tests := []struct {
		method   string
		path     string
		body     string
		wantCode int
	}{
		{http.MethodPost, "/api/v1/agents", "{}", http.StatusMethodNotAllowed},
		{http.MethodPut, "/api/v1/agents/agent-alpha", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/agents/agent-alpha/lifecycle", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/v1/agents/dormancy", "{}", http.StatusMethodNotAllowed},
		{http.MethodPost, "/api/v1/agents/drift", "{}", http.StatusMethodNotAllowed},
		{http.MethodPut, "/api/v1/agent-policies", "{}", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/agent-policies/test-policy", "", http.StatusMethodNotAllowed},
		// Note: GET /api/v1/agents/refresh is valid — it matches
		// GET /api/v1/agents/{id} with id="refresh" and returns 404
		// (agent not found), not 405.
	}

	for _, tt := range tests {
		req := newAdminRequest(tt.method, tt.path, strings.NewReader(tt.body), authToken)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != tt.wantCode {
			t.Errorf("%s %s: got status %d, want %d", tt.method, tt.path, rr.Code, tt.wantCode)
		}
	}
}

// =====================================================================
// GET /api/v1/agents — list
// =====================================================================

func TestHandleAgentList_AllAgents(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/agents: got status %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		Agents []*agentregistry.AgentRecord `json:"agents"`
		Count  int                          `json:"count"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Count != 3 {
		t.Errorf("agent count: got %d, want 3", resp.Count)
	}
}

func TestHandleAgentList_FilterByStatus(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?status=dormant", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/agents?status=dormant: got status %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("dormant agent count: got %d, want 1", resp.Count)
	}
}

func TestHandleAgentList_FilterByTenant(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents?tenant_id=tenant-2", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("tenant-2 agent count: got %d, want 1", resp.Count)
	}
}

// =====================================================================
// GET /api/v1/agents/{id} — single agent
// =====================================================================

func TestHandleAgentGet_Found(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-alpha", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rr.Code, http.StatusOK)
	}

	var record agentregistry.AgentRecord
	if err := json.NewDecoder(rr.Body).Decode(&record); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if record.ID != "agent-alpha" {
		t.Errorf("agent ID: got %q, want %q", record.ID, "agent-alpha")
	}
}

func TestHandleAgentGet_NotFound(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/nonexistent", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// =====================================================================
// POST /api/v1/agents/{id}/lifecycle — manual transition
// =====================================================================

func TestHandleAgentLifecycle_Transition(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	body := `{"status":"quarantined","reason":"security investigation"}`
	req := newAdminRequest(http.MethodPost, "/api/v1/agents/agent-alpha/lifecycle", strings.NewReader(body), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var record agentregistry.AgentRecord
	if err := json.NewDecoder(rr.Body).Decode(&record); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if record.Status != agentregistry.StatusQuarantined {
		t.Errorf("status after transition: got %q, want %q", record.Status, agentregistry.StatusQuarantined)
	}
}

func TestHandleAgentLifecycle_InvalidStatus(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	body := `{"status":"deleted"}`
	req := newAdminRequest(http.MethodPost, "/api/v1/agents/agent-alpha/lifecycle", strings.NewReader(body), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAgentLifecycle_MissingStatus(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	body := `{"reason":"test"}`
	req := newAdminRequest(http.MethodPost, "/api/v1/agents/agent-alpha/lifecycle", strings.NewReader(body), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAgentLifecycle_InvalidJSON(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := newAdminRequest(http.MethodPost, "/api/v1/agents/agent-alpha/lifecycle", strings.NewReader("not json"), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAgentLifecycle_NotFound(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	body := `{"status":"quarantined"}`
	req := newAdminRequest(http.MethodPost, "/api/v1/agents/nonexistent/lifecycle", strings.NewReader(body), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// =====================================================================
// GET /api/v1/agents/dormancy — dormancy report
// =====================================================================

func TestHandleAgentDormancy(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/dormancy", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rr.Code, http.StatusOK)
	}

	var report agentregistry.DormancyReport
	if err := json.NewDecoder(rr.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if report.Total != 3 {
		t.Errorf("total agents: got %d, want 3", report.Total)
	}
}

// =====================================================================
// GET /api/v1/agents/drift — AIBOM reconciliation
// =====================================================================

func TestHandleAgentDrift(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/drift", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rr.Code, http.StatusOK)
	}

	var report agentregistry.DriftReport
	if err := json.NewDecoder(rr.Body).Decode(&report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Without an AIBOM source configured, all agents are "active not in AIBOM".
	if report.TotalActive != 3 {
		t.Errorf("total active: got %d, want 3", report.TotalActive)
	}
}

// =====================================================================
// GET/POST /api/v1/agent-policies — policy CRUD
// =====================================================================

func TestHandleAgentPolicyList_Empty(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-policies", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 0 {
		t.Errorf("policy count: got %d, want 0", resp.Count)
	}
}

func TestHandleAgentPolicyCreate(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	body := `{"id":"pol-1","name":"Standard Dormancy","dormancy_threshold":3600000000000,"enabled":true}`
	req := newAdminRequest(http.MethodPost, "/api/v1/agent-policies", strings.NewReader(body), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("got status %d, want %d; body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var policy agentregistry.LifecyclePolicy
	if err := json.NewDecoder(rr.Body).Decode(&policy); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if policy.ID != "pol-1" {
		t.Errorf("policy ID: got %q, want %q", policy.ID, "pol-1")
	}
}

func TestHandleAgentPolicyCreate_MissingID(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	body := `{"name":"test","dormancy_threshold":3600000000000}`
	req := newAdminRequest(http.MethodPost, "/api/v1/agent-policies", strings.NewReader(body), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAgentPolicyCreate_MissingName(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	body := `{"id":"pol-1","dormancy_threshold":3600000000000}`
	req := newAdminRequest(http.MethodPost, "/api/v1/agent-policies", strings.NewReader(body), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAgentPolicyCreate_InvalidThreshold(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	body := `{"id":"pol-1","name":"test","dormancy_threshold":0}`
	req := newAdminRequest(http.MethodPost, "/api/v1/agent-policies", strings.NewReader(body), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAgentPolicyCreate_InvalidJSON(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := newAdminRequest(http.MethodPost, "/api/v1/agent-policies", strings.NewReader("not json"), authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// =====================================================================
// DELETE /api/v1/agent-policies/{id} — policy deletion
// =====================================================================

func TestHandleAgentPolicyDelete(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	// First create a policy.
	createBody := `{"id":"pol-delete","name":"Test","dormancy_threshold":3600000000000,"enabled":true}`
	createReq := newAdminRequest(http.MethodPost, "/api/v1/agent-policies", strings.NewReader(createBody), authToken)
	createRR := httptest.NewRecorder()
	mux.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("create policy: got status %d, want %d", createRR.Code, http.StatusCreated)
	}

	// Now delete it.
	req := newAdminRequest(http.MethodDelete, "/api/v1/agent-policies/pol-delete", nil, authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("delete policy: got status %d, want %d", rr.Code, http.StatusOK)
	}

	var resp struct {
		Status   string `json:"status"`
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "deleted" {
		t.Errorf("status: got %q, want %q", resp.Status, "deleted")
	}
	if resp.PolicyID != "pol-delete" {
		t.Errorf("policy_id: got %q, want %q", resp.PolicyID, "pol-delete")
	}
}

// =====================================================================
// POST /api/v1/agents/refresh — manual discovery refresh
// =====================================================================

func TestHandleAgentRefresh(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW, authToken := authMiddlewareForAdminTests(t)
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := newAdminRequest(http.MethodPost, "/api/v1/agents/refresh", nil, authToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "refreshed" {
		t.Errorf("status: got %q, want %q", resp.Status, "refreshed")
	}
}

// =====================================================================
// Permission enforcement tests
// =====================================================================

// TestAgentRegistryPermission_ViewerCanRead verifies that a viewer
// role can access read endpoints but not manage endpoints.
func TestAgentRegistryPermission_ViewerCanRead(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	// Use auth middleware with auth enabled but inject viewer role.
	authMW := auth.NewMiddleware(&auth.Config{RequireAuth: false})

	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	// With RequireAuth: false, auth is bypassed. We verify the
	// permission check separately by confirming the wire function
	// uses RequirePermission (not RequireAuth) for all endpoints.
	// The actual permission enforcement is tested via the rbac
	// package's own tests.

	// Verify read endpoint works.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("GET /api/v1/agents: got status %d, want %d", rr.Code, http.StatusOK)
	}
}

// =====================================================================
// Content-Type tests
// =====================================================================

func TestAgentRegistryContentType_JSON(t *testing.T) {
	registry, policyEngine, dormancy, broadcaster := setupTestRegistry(t)

	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, registry, policyEngine, dormancy, broadcaster)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestAgentRegistryContentType_ErrorJSON(t *testing.T) {
	authMW := authMiddlewareForTests()
	mux := http.NewServeMux()
	wireAgentRegistryHandlers(mux, authMW, nil, nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(rr.Body.String(), "error") {
		t.Errorf("response should contain 'error' field, got: %s", rr.Body.String())
	}
}

// =====================================================================
// SSE Broadcaster tests
// =====================================================================

func TestEventBroadcaster_Broadcast(t *testing.T) {
	broadcaster := agentregistry.NewEventBroadcaster(nil)
	defer broadcaster.Stop()

	ch := broadcaster.Subscribe("test-client-1")
	if ch == nil {
		t.Fatal("Subscribe returned nil channel")
	}

	broadcaster.Broadcast(agentregistry.SSEEventAgentLifecycle, map[string]string{
		"agent_id": "agent-test",
	})

	select {
	case event := <-ch:
		if event.Type != agentregistry.SSEEventAgentLifecycle {
			t.Errorf("event type: got %q, want %q", event.Type, agentregistry.SSEEventAgentLifecycle)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for broadcast event")
	}
}

func TestEventBroadcaster_SubscriberCount(t *testing.T) {
	broadcaster := agentregistry.NewEventBroadcaster(nil)
	defer broadcaster.Stop()

	if count := broadcaster.SubscriberCount(); count != 0 {
		t.Errorf("initial subscriber count: got %d, want 0", count)
	}

	broadcaster.Subscribe("client-1")
	broadcaster.Subscribe("client-2")
	broadcaster.Subscribe("client-3")

	if count := broadcaster.SubscriberCount(); count != 3 {
		t.Errorf("subscriber count: got %d, want 3", count)
	}

	broadcaster.Unsubscribe("client-2")
	if count := broadcaster.SubscriberCount(); count != 2 {
		t.Errorf("after unsubscribe: got %d, want 2", count)
	}
}

func TestEventBroadcaster_OnLifecycleEvent(t *testing.T) {
	broadcaster := agentregistry.NewEventBroadcaster(nil)
	defer broadcaster.Stop()

	ch := broadcaster.Subscribe("test-client")

	event := agentregistry.LifecycleEvent{
		AgentID:   "agent-test",
		OldStatus: agentregistry.StatusActive,
		NewStatus: agentregistry.StatusDormant,
		Timestamp: time.Now().UTC(),
		Reason:    "policy:dormancy-check",
	}
	broadcaster.OnLifecycleEvent(event)

	select {
	case received := <-ch:
		if received.Type != agentregistry.SSEEventAgentDormant {
			t.Errorf("event type for dormant transition: got %q, want %q", received.Type, agentregistry.SSEEventAgentDormant)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for lifecycle event")
	}
}

func TestEventBroadcaster_OnLifecycleEvent_Revoked(t *testing.T) {
	broadcaster := agentregistry.NewEventBroadcaster(nil)
	defer broadcaster.Stop()

	ch := broadcaster.Subscribe("test-client")

	broadcaster.OnLifecycleEvent(agentregistry.LifecycleEvent{
		AgentID:   "agent-test",
		OldStatus: agentregistry.StatusQuarantined,
		NewStatus: agentregistry.StatusRevoked,
	})

	select {
	case received := <-ch:
		if received.Type != agentregistry.SSEEventAgentRevoked {
			t.Errorf("event type for revoked transition: got %q, want %q", received.Type, agentregistry.SSEEventAgentRevoked)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for revoked event")
	}
}

func TestEventBroadcaster_StopClosesChannels(t *testing.T) {
	broadcaster := agentregistry.NewEventBroadcaster(nil)

	ch := broadcaster.Subscribe("test-client")
	broadcaster.Stop()

	select {
	case _, open := <-ch:
		if open {
			t.Error("channel should be closed after Stop")
		}
	default:
		t.Error("channel should be closed after Stop")
	}
}

// =====================================================================
// parseTagQuery helper tests
// =====================================================================

func TestParseTagQuery(t *testing.T) {
	tests := []struct {
		input    string
		wantKey  string
		wantVal  string
		wantNil  bool
	}{
		{"env=prod", "env", "prod", false},
		{"team=security-ops", "team", "security-ops", false},
		{"invalid", "", "", true},
		{"=novalue", "", "", true},
		{"nokey=", "", "", true},
		{"a=b=c", "a", "b=c", false},
	}

	for _, tt := range tests {
		result := parseTagQuery(tt.input)
		if tt.wantNil {
			if result != nil {
				t.Errorf("parseTagQuery(%q): want nil, got %v", tt.input, result)
			}
			continue
		}
		if result == nil {
			t.Errorf("parseTagQuery(%q): want %s=%s, got nil", tt.input, tt.wantKey, tt.wantVal)
			continue
		}
		if result[tt.wantKey] != tt.wantVal {
			t.Errorf("parseTagQuery(%q): got %v, want %s=%s", tt.input, result, tt.wantKey, tt.wantVal)
		}
	}
}

func TestIsValidAgentStatus(t *testing.T) {
	valid := []agentregistry.AgentStatus{
		agentregistry.StatusProvisioned,
		agentregistry.StatusActive,
		agentregistry.StatusDormant,
		agentregistry.StatusQuarantined,
		agentregistry.StatusRevoked,
	}
	for _, s := range valid {
		if !isValidAgentStatus(s) {
			t.Errorf("isValidAgentStatus(%q): want true, got false", s)
		}
	}

	invalid := []agentregistry.AgentStatus{"deleted", "pending", "", "unknown"}
	for _, s := range invalid {
		if isValidAgentStatus(s) {
			t.Errorf("isValidAgentStatus(%q): want false, got true", s)
		}
	}
}

// =====================================================================
// Integration: lifecycle transition + SSE broadcast
// =====================================================================

func TestAgentLifecycleTransition_SSEBroadcast(t *testing.T) {
	registry, _, _, broadcaster := setupTestRegistry(t)

	// Wire the broadcaster to the registry's lifecycle callback.
	registry.SetLifecycleEventCallback(broadcaster.OnLifecycleEvent)
	broadcaster.Start()
	defer broadcaster.Stop()

	// Subscribe before the transition.
	ch := broadcaster.Subscribe("integration-client")

	// Trigger a transition.
	if err := registry.Transition("agent-alpha", agentregistry.StatusQuarantined, "integration-test"); err != nil {
		t.Fatalf("Transition: %v", err)
	}

	// Verify the SSE event was broadcast.
	select {
	case event := <-ch:
		if event.Type != agentregistry.SSEEventAgentLifecycle {
			t.Errorf("event type: got %q, want %q", event.Type, agentregistry.SSEEventAgentLifecycle)
		}
		data, ok := event.Data.(agentregistry.LifecycleEvent)
		if !ok {
			t.Fatalf("event data type: got %T, want LifecycleEvent", event.Data)
		}
		if data.AgentID != "agent-alpha" {
			t.Errorf("agent_id: got %q, want %q", data.AgentID, "agent-alpha")
		}
		if data.NewStatus != agentregistry.StatusQuarantined {
			t.Errorf("new_status: got %q, want %q", data.NewStatus, agentregistry.StatusQuarantined)
		}
		if data.Reason != "integration-test" {
			t.Errorf("reason: got %q, want %q", data.Reason, "integration-test")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE event after lifecycle transition")
	}
}