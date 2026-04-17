// Package handlers - Agent API handlers for AegisGuard
package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// AgentHandler handles agent-related API requests
type AgentHandler struct {
	manager *rbac.Manager
}

// NewAgentHandler creates a new agent handler
func NewAgentHandler(manager *rbac.Manager) *AgentHandler {
	return &AgentHandler{
		manager: manager,
	}
}

// ============================================================================
// REQUEST TYPES
// ============================================================================

// CreateAgentRequest represents agent creation request
type CreateAgentRequest struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Role        string            `json:"role,omitempty"`
	Tools       []string          `json:"tools,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// UpdateAgentRequest represents agent update request
type UpdateAgentRequest struct {
	Name        *string           `json:"name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Role        *string           `json:"role,omitempty"`
	Tools       []string          `json:"tools,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"`
}

// ============================================================================
// HANDLERS
// ============================================================================

// HandleAgents handles GET (list) and POST (create) for /api/v1/agents
func (h *AgentHandler) HandleAgents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listAgents(w, r)
	case http.MethodPost:
		h.createAgent(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Sprintf("Method %s not allowed for /agents", r.Method))
	}
}

// HandleAgentByID handles GET, PUT, DELETE for /api/v1/agents/{id}
func (h *AgentHandler) HandleAgentByID(w http.ResponseWriter, r *http.Request) {
	// Extract agent ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	// Handle trailing slash
	path = strings.TrimSuffix(path, "/")

	if path == "" {
		writeError(w, http.StatusBadRequest, "INVALID_PATH", "Agent ID is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getAgent(w, r, path)
	case http.MethodPut:
		h.updateAgent(w, r, path)
	case http.MethodDelete:
		h.deleteAgent(w, r, path)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Sprintf("Method %s not allowed for /agents/%s", r.Method, path))
	}
}

// listAgents returns all registered agents
func (h *AgentHandler) listAgents(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters for filtering
	role := r.URL.Query().Get("role")
	enabledStr := r.URL.Query().Get("enabled")
	page := parseQueryInt(r, "page", 1)
	perPage := parseQueryInt(r, "per_page", 20)

	// Get all agents
	agents := h.manager.ListAgents()

	// Apply filters
	var filtered []*rbac.Agent
	for _, agent := range agents {
		// Filter by role
		if role != "" && string(agent.Role) != role {
			continue
		}
		// Filter by enabled status
		if enabledStr != "" {
			enabled := parseQueryBool(r, "enabled", true)
			if agent.Enabled != enabled {
				continue
			}
		}
		filtered = append(filtered, agent)
	}

	// Calculate pagination
	total := len(filtered)
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}

	// Ensure page is within bounds
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	// Apply pagination
	start := (page - 1) * perPage
	end := start + perPage
	if end > total {
		end = total
	}

	var paginatedAgents []*rbac.Agent
	if start < total {
		paginatedAgents = filtered[start:end]
	}

	// Build response
	meta := &Meta{
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	}

	writeSuccessWithMeta(w, http.StatusOK, AgentsToResponse(paginatedAgents), meta)
}

// createAgent registers a new agent
func (h *AgentHandler) createAgent(w http.ResponseWriter, r *http.Request) {
	var req CreateAgentRequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Failed to parse request body", err.Error())
		return
	}

	// Validate required fields
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Agent ID is required")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Agent name is required")
		return
	}

	// Convert tools to ToolPermission
	var tools []rbac.ToolPermission
	for _, t := range req.Tools {
		tools = append(tools, rbac.ToolPermission(t))
	}

	// Validate role if provided
	role := rbac.AgentRoleRestricted
	if req.Role != "" {
		switch rbac.AgentRole(req.Role) {
		case rbac.AgentRoleRestricted, rbac.AgentRoleStandard,
			rbac.AgentRolePrivileged, rbac.AgentRoleAdmin:
			role = rbac.AgentRole(req.Role)
		default:
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				fmt.Sprintf("Invalid role: %s. Valid roles: restricted, standard, privileged, admin", req.Role))
			return
		}
	}

	// Create agent
	agent := &rbac.Agent{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Role:        role,
		Tools:       tools,
		Tags:        req.Tags,
	}

	if err := h.manager.RegisterAgent(agent); err != nil {
		// Check for specific errors
		if strings.Contains(err.Error(), "already registered") {
			writeError(w, http.StatusConflict, "AGENT_EXISTS", err.Error())
			return
		}
		if strings.Contains(err.Error(), "maximum") {
			writeError(w, http.StatusServiceUnavailable, "LIMIT_REACHED", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "REGISTRATION_FAILED", err.Error())
		return
	}

	// Return created agent
	writeSuccess(w, http.StatusCreated, AgentToResponse(agent))
}

// getAgent retrieves a single agent by ID
func (h *AgentHandler) getAgent(w http.ResponseWriter, r *http.Request, agentID string) {
	agent, err := h.manager.GetAgent(agentID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "AGENT_NOT_FOUND",
				fmt.Sprintf("Agent with ID '%s' not found", agentID))
			return
		}
		writeError(w, http.StatusInternalServerError, "GET_FAILED", err.Error())
		return
	}

	writeSuccess(w, http.StatusOK, AgentToResponse(agent))
}

// updateAgent updates an existing agent
func (h *AgentHandler) updateAgent(w http.ResponseWriter, r *http.Request, agentID string) {
	var req UpdateAgentRequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Failed to parse request body", err.Error())
		return
	}

	// Build updates
	updates := &rbac.AgentUpdates{
		Tags: req.Tags,
	}

	if req.Name != nil {
		updates.Name = *req.Name
	}
	if req.Description != nil {
		updates.Description = *req.Description
	}
	if req.Role != nil {
		// Validate role
		switch rbac.AgentRole(*req.Role) {
		case rbac.AgentRoleRestricted, rbac.AgentRoleStandard,
			rbac.AgentRolePrivileged, rbac.AgentRoleAdmin:
			updates.Role = rbac.AgentRole(*req.Role)
		default:
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR",
				fmt.Sprintf("Invalid role: %s. Valid roles: restricted, standard, privileged, admin", *req.Role))
			return
		}
	}
	if len(req.Tools) > 0 {
		for _, t := range req.Tools {
			updates.Tools = append(updates.Tools, rbac.ToolPermission(t))
		}
	}
	if req.Enabled != nil {
		updates.Enabled = *req.Enabled
	}

	if err := h.manager.UpdateAgent(agentID, updates); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "AGENT_NOT_FOUND",
				fmt.Sprintf("Agent with ID '%s' not found", agentID))
			return
		}
		writeError(w, http.StatusInternalServerError, "UPDATE_FAILED", err.Error())
		return
	}

	// Get updated agent
	agent, err := h.manager.GetAgent(agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "GET_AFTER_UPDATE_FAILED", err.Error())
		return
	}

	writeSuccess(w, http.StatusOK, AgentToResponse(agent))
}

// deleteAgent removes an agent
func (h *AgentHandler) deleteAgent(w http.ResponseWriter, r *http.Request, agentID string) {
	if err := h.manager.UnregisterAgent(agentID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "AGENT_NOT_FOUND",
				fmt.Sprintf("Agent with ID '%s' not found", agentID))
			return
		}
		writeError(w, http.StatusInternalServerError, "DELETE_FAILED", err.Error())
		return
	}

	writeSuccess(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("Agent '%s' successfully unregistered", agentID),
	})
}

// ============================================================================
// SESSION ROUTES (Delegated to SessionHandler)
// ============================================================================

// HandleAgentSessions handles GET /api/v1/agents/{id}/sessions
func (h *AgentHandler) HandleAgentSessions(w http.ResponseWriter, r *http.Request) {
	// Extract agent ID from path: /api/v1/agents/{id}/sessions
	path := r.URL.Path
	// Remove /api/v1/agents/ prefix
	path = strings.TrimPrefix(path, "/api/v1/agents/")
	// Remove /sessions suffix
	agentID := strings.TrimSuffix(path, "/sessions")
	agentID = strings.TrimSuffix(agentID, "/")

	if agentID == "" {
		writeError(w, http.StatusBadRequest, "INVALID_PATH", "Agent ID is required")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Sprintf("Method %s not allowed for /agents/%s/sessions", r.Method, agentID))
		return
	}

	// Verify agent exists
	_, err := h.manager.GetAgent(agentID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "AGENT_NOT_FOUND",
				fmt.Sprintf("Agent with ID '%s' not found", agentID))
			return
		}
		writeError(w, http.StatusInternalServerError, "GET_FAILED", err.Error())
		return
	}

	// Get sessions for agent
	sessions := h.manager.GetAgentSessions(agentID)

	writeSuccess(w, http.StatusOK, SessionsToResponse(sessions))
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

// HandleAgentHealth handles GET /api/v1/agents/health
func (h *AgentHandler) HandleAgentHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"Only GET method is allowed for /health")
		return
	}

	// Basic health check - just verify manager is responsive
	agents := h.manager.ListAgents()

	health := HealthResponse{
		Status:    "healthy",
		Service:   "aegisguard-agents",
		Version:   "0.1.0",
		Timestamp: time.Now().Format(time.RFC3339),
		Checks: map[string]string{
			"manager": "ok",
			"agents":  fmt.Sprintf("%d registered", len(agents)),
		},
	}

	writeSuccess(w, http.StatusOK, health)
}
