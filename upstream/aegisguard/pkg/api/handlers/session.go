// Package handlers - Session API handlers for AegisGuard
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// SessionHandler handles session-related API requests
type SessionHandler struct {
	manager *rbac.Manager
}

// NewSessionHandler creates a new session handler
func NewSessionHandler(manager *rbac.Manager) *SessionHandler {
	return &SessionHandler{
		manager: manager,
	}
}

// ============================================================================
// REQUEST TYPES
// ============================================================================

// CreateSessionRequest represents session creation request
type CreateSessionRequest struct {
	AgentID     string            `json:"agent_id"`
	IPAddress   string            `json:"ip_address,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	ContextHash string            `json:"context_hash,omitempty"`
}

// RefreshSessionRequest represents session refresh request
type RefreshSessionRequest struct {
	Duration string `json:"duration,omitempty"` // e.g., "24h", "1h", "30m"
}

// ============================================================================
// HANDLERS
// ============================================================================

// HandleSessions handles GET (list) and POST (create) for /api/v1/sessions
func (h *SessionHandler) HandleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listSessions(w, r)
	case http.MethodPost:
		h.createSession(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Sprintf("Method %s not allowed for /sessions", r.Method))
	}
}

// HandleSessionByID handles GET, DELETE, PATCH for /api/v1/sessions/{id}
func (h *SessionHandler) HandleSessionByID(w http.ResponseWriter, r *http.Request) {
	// Extract session ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/sessions/")
	// Handle trailing slash
	path = strings.TrimSuffix(path, "/")

	if path == "" {
		writeError(w, http.StatusBadRequest, "INVALID_PATH", "Session ID is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getSession(w, r, path)
	case http.MethodDelete:
		h.deleteSession(w, r, path)
	case http.MethodPatch:
		h.refreshSession(w, r, path)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Sprintf("Method %s not allowed for /sessions/%s", r.Method, path))
	}
}

// listSessions returns all active sessions
func (h *SessionHandler) listSessions(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	agentID := r.URL.Query().Get("agent_id")
	activeOnly := parseQueryBool(r, "active", true)
	page := parseQueryInt(r, "page", 1)
	perPage := parseQueryInt(r, "per_page", 50)

	// Get all agents to find sessions
	agents := h.manager.ListAgents()
	agentMap := make(map[string]*rbac.Agent)
	for _, agent := range agents {
		agentMap[agent.ID] = agent
	}

	// Collect all sessions
	var allSessions []*rbac.AgentSession
	for _, agent := range agents {
		sessions := h.manager.GetAgentSessions(agent.ID)
		allSessions = append(allSessions, sessions...)
	}

	// Apply filters
	var filtered []*rbac.AgentSession
	for _, session := range allSessions {
		// Filter by agent ID
		if agentID != "" && session.AgentID != agentID {
			continue
		}
		// Filter by active status
		if activeOnly && !session.Active {
			continue
		}
		filtered = append(filtered, session)
	}

	// Attach agent info to sessions
	for _, session := range filtered {
		if agent, ok := agentMap[session.AgentID]; ok {
			session.Agent = agent
		}
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

	var paginatedSessions []*rbac.AgentSession
	if start < total {
		paginatedSessions = filtered[start:end]
	}

	// Build response
	meta := &Meta{
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	}

	writeSuccessWithMeta(w, http.StatusOK, SessionsToResponse(paginatedSessions), meta)
}

// createSession creates a new session for an agent
func (h *SessionHandler) createSession(w http.ResponseWriter, r *http.Request) {
	var req CreateSessionRequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Failed to parse request body", err.Error())
		return
	}

	// Validate required fields
	if req.AgentID == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", "Agent ID is required")
		return
	}

	// Build context
	ctx := context.Background()

	// Get client IP if not provided
	ipAddress := req.IPAddress
	if ipAddress == "" {
		ipAddress = getClientIP(r)
	}

	// Build session options
	var sessionOpts []rbac.SessionOption
	if ipAddress != "" {
		sessionOpts = append(sessionOpts, rbac.WithSessionIP(ipAddress))
	}
	if req.ContextHash != "" {
		sessionOpts = append(sessionOpts, rbac.WithSessionContextHash(req.ContextHash))
	}
	if req.Tags != nil {
		sessionOpts = append(sessionOpts, rbac.WithSessionTags(req.Tags))
	}

	// Create session
	session, err := h.manager.CreateSession(ctx, req.AgentID, sessionOpts...)
	if err != nil {
		// Check for specific errors
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "AGENT_NOT_FOUND",
				fmt.Sprintf("Agent with ID '%s' not found", req.AgentID))
			return
		}
		if strings.Contains(err.Error(), "disabled") {
			writeError(w, http.StatusForbidden, "AGENT_DISABLED",
				fmt.Sprintf("Agent '%s' is disabled", req.AgentID))
			return
		}
		if strings.Contains(err.Error(), "maximum") {
			writeError(w, http.StatusServiceUnavailable, "SESSION_LIMIT_REACHED",
				"Maximum sessions reached for this agent")
			return
		}
		writeError(w, http.StatusInternalServerError, "SESSION_CREATION_FAILED", err.Error())
		return
	}

	// Get agent info for response
	agent, _ := h.manager.GetAgent(req.AgentID)
	session.Agent = agent

	writeSuccess(w, http.StatusCreated, SessionToResponse(session))
}

// getSession retrieves a session by ID
func (h *SessionHandler) getSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	session, err := h.manager.GetSession(sessionID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "SESSION_NOT_FOUND",
				fmt.Sprintf("Session with ID '%s' not found", sessionID))
			return
		}
		if strings.Contains(err.Error(), "expired") {
			writeError(w, http.StatusGone, "SESSION_EXPIRED",
				fmt.Sprintf("Session '%s' has expired", sessionID))
			return
		}
		writeError(w, http.StatusInternalServerError, "GET_FAILED", err.Error())
		return
	}

	// Get agent info
	agent, _ := h.manager.GetAgent(session.AgentID)
	session.Agent = agent

	writeSuccess(w, http.StatusOK, SessionToResponse(session))
}

// refreshSession extends a session's expiration time
func (h *SessionHandler) refreshSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	// Note: Current RBAC Manager doesn't support custom duration refresh
	// This would require extending the interface
	if err := h.manager.RefreshSession(sessionID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "SESSION_NOT_FOUND",
				fmt.Sprintf("Session with ID '%s' not found", sessionID))
			return
		}
		if strings.Contains(err.Error(), "not active") {
			writeError(w, http.StatusConflict, "SESSION_INACTIVE",
				fmt.Sprintf("Session '%s' is not active", sessionID))
			return
		}
		writeError(w, http.StatusInternalServerError, "REFRESH_FAILED", err.Error())
		return
	}

	// Get refreshed session
	session, err := h.manager.GetSession(sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "GET_AFTER_REFRESH_FAILED", err.Error())
		return
	}

	// Get agent info
	agent, _ := h.manager.GetAgent(session.AgentID)
	session.Agent = agent

	writeSuccess(w, http.StatusOK, SessionToResponse(session))
}

// deleteSession invalidates a session
func (h *SessionHandler) deleteSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	if err := h.manager.InvalidateSession(sessionID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "SESSION_NOT_FOUND",
				fmt.Sprintf("Session with ID '%s' not found", sessionID))
			return
		}
		writeError(w, http.StatusInternalServerError, "DELETE_FAILED", err.Error())
		return
	}

	writeSuccess(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("Session '%s' successfully invalidated", sessionID),
	})
}

// ============================================================================
// SESSION STATS
// ============================================================================

// HandleSessionStats handles GET /api/v1/sessions/stats
func (h *SessionHandler) HandleSessionStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"Only GET method is allowed for /sessions/stats")
		return
	}

	agents := h.manager.ListAgents()

	totalSessions := 0
	activeSessions := 0

	for _, agent := range agents {
		sessions := h.manager.GetAgentSessions(agent.ID)
		totalSessions += len(sessions)
		for _, session := range sessions {
			if session.Active && !session.IsExpired() {
				activeSessions++
			}
		}
	}

	stats := map[string]interface{}{
		"total_agents":    len(agents),
		"total_sessions":  totalSessions,
		"active_sessions": activeSessions,
		"timestamp":       time.Now().Format(time.RFC3339),
	}

	writeSuccess(w, http.StatusOK, stats)
}
