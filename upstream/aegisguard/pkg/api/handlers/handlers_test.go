// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security

// =========================================================================
//
// Unit tests for API handlers
// =========================================================================

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestManager(t *testing.T) *rbac.Manager {
	cfg := &rbac.Config{
		SessionDuration: 24 * time.Hour,
		MaxAgents:       100,
		MaxSessions:     10,
		DefaultRole:     rbac.AgentRoleStandard,
		CleanupInterval: time.Hour, // Prevent zero interval panic
	}
	manager, err := rbac.NewManager(cfg)
	require.NoError(t, err)
	return manager
}

func TestAgentHandler_CreateAgent(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewAgentHandler(manager)

	tests := []struct {
		name       string
		body       CreateAgentRequest
		wantStatus int
		wantCode   string
	}{
		{
			name: "valid agent creation",
			body: CreateAgentRequest{
				ID:   "test-agent-1",
				Name: "Test Agent",
				Role: "standard",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "missing id",
			body: CreateAgentRequest{
				Name: "Test Agent",
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "VALIDATION_ERROR",
		},
		{
			name: "missing name",
			body: CreateAgentRequest{
				ID: "test-agent-2",
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "VALIDATION_ERROR",
		},
		{
			name: "invalid role",
			body: CreateAgentRequest{
				ID:   "test-agent-3",
				Name: "Test Agent",
				Role: "invalid",
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "VALIDATION_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.HandleAgents(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantCode != "" {
				var resp APIResponse
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				require.NoError(t, err)
				assert.False(t, resp.Success)
				assert.Equal(t, tt.wantCode, resp.Error.Code)
			}
		})
	}
}

func TestAgentHandler_ListAgents(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewAgentHandler(manager)

	// Create some agents first
	agent1 := &rbac.Agent{ID: "agent-1", Name: "Agent 1", Role: rbac.AgentRoleStandard}
	agent2 := &rbac.Agent{ID: "agent-2", Name: "Agent 2", Role: rbac.AgentRolePrivileged}
	agent3 := &rbac.Agent{ID: "agent-3", Name: "Agent 3", Role: rbac.AgentRoleRestricted}

	err := manager.RegisterAgent(agent1)
	require.NoError(t, err)
	err = manager.RegisterAgent(agent2)
	require.NoError(t, err)
	err = manager.RegisterAgent(agent3)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	w := httptest.NewRecorder()

	handler.HandleAgents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotNil(t, resp.Data)

	// Check meta for pagination
	if resp.Meta != nil {
		assert.Equal(t, 3, resp.Meta.Total)
	}
}

func TestAgentHandler_GetAgent(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewAgentHandler(manager)

	// Create an agent
	agent := &rbac.Agent{ID: "get-test-agent", Name: "Get Test Agent", Role: rbac.AgentRoleStandard}
	err := manager.RegisterAgent(agent)
	require.NoError(t, err)

	t.Run("existing agent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/get-test-agent", nil)
		w := httptest.NewRecorder()

		handler.HandleAgentByID(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("non-existent agent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/non-existent", nil)
		w := httptest.NewRecorder()

		handler.HandleAgentByID(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.False(t, resp.Success)
		assert.Equal(t, "AGENT_NOT_FOUND", resp.Error.Code)
	})
}

func TestAgentHandler_UpdateAgent(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewAgentHandler(manager)

	// Create an agent
	agent := &rbac.Agent{ID: "update-test-agent", Name: "Original Name", Role: rbac.AgentRoleStandard}
	err := manager.RegisterAgent(agent)
	require.NoError(t, err)

	t.Run("valid update", func(t *testing.T) {
		updateReq := UpdateAgentRequest{
			Name: strPtr("Updated Name"),
		}
		bodyBytes, _ := json.Marshal(updateReq)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/agents/update-test-agent", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.HandleAgentByID(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("non-existent agent", func(t *testing.T) {
		updateReq := UpdateAgentRequest{
			Name: strPtr("New Name"),
		}
		bodyBytes, _ := json.Marshal(updateReq)
		req := httptest.NewRequest(http.MethodPut, "/api/v1/agents/non-existent", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.HandleAgentByID(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestAgentHandler_DeleteAgent(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewAgentHandler(manager)

	// Create an agent
	agent := &rbac.Agent{ID: "delete-test-agent", Name: "Delete Test Agent", Role: rbac.AgentRoleStandard}
	err := manager.RegisterAgent(agent)
	require.NoError(t, err)

	t.Run("delete existing agent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/delete-test-agent", nil)
		w := httptest.NewRecorder()

		handler.HandleAgentByID(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("delete non-existent agent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/non-existent", nil)
		w := httptest.NewRecorder()

		handler.HandleAgentByID(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestSessionHandler_CreateSession(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewSessionHandler(manager)

	// Create an agent first
	agent := &rbac.Agent{ID: "session-test-agent", Name: "Session Test Agent", Role: rbac.AgentRoleStandard}
	err := manager.RegisterAgent(agent)
	require.NoError(t, err)

	t.Run("valid session creation", func(t *testing.T) {
		reqBody := CreateSessionRequest{
			AgentID: "session-test-agent",
		}
		bodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.HandleSessions(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("missing agent_id", func(t *testing.T) {
		reqBody := CreateSessionRequest{}
		bodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.HandleSessions(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("non-existent agent", func(t *testing.T) {
		reqBody := CreateSessionRequest{
			AgentID: "non-existent-agent",
		}
		bodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.HandleSessions(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestAuthHandler_Authorize(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewAuthHandler(manager)

	// Create an agent with a session
	agent := &rbac.Agent{ID: "auth-test-agent", Name: "Auth Test Agent", Role: rbac.AgentRoleStandard}
	err := manager.RegisterAgent(agent)
	require.NoError(t, err)

	// Create a session
	session, err := manager.CreateSession(context.Background(), "auth-test-agent")
	require.NoError(t, err)

	t.Run("authorized tool call", func(t *testing.T) {
		reqBody := AuthorizeRequest{
			AgentID:   "auth-test-agent",
			SessionID: session.ID,
			ToolName:  "file_read",
		}
		bodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/authorize", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.HandleAuthorize(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("unauthorized tool call", func(t *testing.T) {
		reqBody := AuthorizeRequest{
			AgentID:   "auth-test-agent",
			SessionID: session.ID,
			ToolName:  "shell_command", // Restricted for standard role
		}
		bodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/authorize", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.HandleAuthorize(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("missing tool_name", func(t *testing.T) {
		reqBody := AuthorizeRequest{
			AgentID: "auth-test-agent",
		}
		bodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/authorize", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.HandleAuthorize(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestToolsHandler_GetTools(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewToolsHandler(manager)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tools", nil)
	w := httptest.NewRecorder()

	handler.HandleTools(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestRolesHandler_GetRoles(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewRolesHandler(manager)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	w := httptest.NewRecorder()

	handler.HandleRoles(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestMetricsHandler_GetMetrics(t *testing.T) {
	manager := setupTestManager(t)
	defer manager.Close()

	handler := NewMetricsHandler(manager, "0.1.0")

	// Create some agents
	agent := &rbac.Agent{ID: "metrics-test-agent", Name: "Metrics Test Agent", Role: rbac.AgentRoleStandard}
	err := manager.RegisterAgent(agent)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	w := httptest.NewRecorder()

	handler.HandleMetrics(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestCommonHelpers(t *testing.T) {
	t.Run("parseQueryInt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?page=5&per_page=20", nil)

		page := parseQueryInt(req, "page", 1)
		assert.Equal(t, 5, page)

		perPage := parseQueryInt(req, "per_page", 10)
		assert.Equal(t, 20, perPage)

		// Default value for missing param
		missing := parseQueryInt(req, "missing", 99)
		assert.Equal(t, 99, missing)
	})

	t.Run("parseQueryBool", func(t *testing.T) {
		tests := []struct {
			url      string
			key      string
			expected bool
		}{
			{"/test?enabled=true", "enabled", true},
			{"/test?enabled=false", "enabled", false},
			{"/test?enabled=1", "enabled", true},
			{"/test?enabled=0", "enabled", false},
			{"/test", "enabled", true}, // default
		}

		for _, tt := range tests {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			result := parseQueryBool(req, tt.key, true)
			assert.Equal(t, tt.expected, result, "URL: %s", tt.url)
		}
	})
}

// Helper function
func strPtr(s string) *string {
	return &s
}
