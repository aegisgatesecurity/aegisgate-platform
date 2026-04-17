// Package handlers - Common utilities for API handlers
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// ============================================================================
// RESPONSE TYPES
// ============================================================================

// APIResponse is the standard API response wrapper
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// APIError represents an API error
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Meta represents pagination metadata
type Meta struct {
	Page       int `json:"page,omitempty"`
	PerPage    int `json:"per_page,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

// AgentResponse represents agent API response
type AgentResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Role        string            `json:"role"`
	Tools       []string          `json:"tools,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Enabled     bool              `json:"enabled"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

// SessionResponse represents session API response
type SessionResponse struct {
	ID           string            `json:"id"`
	AgentID      string            `json:"agent_id"`
	AgentName    string            `json:"agent_name,omitempty"`
	Role         string            `json:"role,omitempty"`
	CreatedAt    string            `json:"created_at"`
	ExpiresAt    string            `json:"expires_at"`
	LastActivity string            `json:"last_activity"`
	TTLRemaining string            `json:"ttl_remaining"`
	Active       bool              `json:"active"`
	IPAddress    string            `json:"ip_address,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

// RoleInfo represents role information for API response
type RoleInfo struct {
	Name        string   `json:"name"`
	Level       int      `json:"level"`
	Permissions []string `json:"permissions"`
	Description string   `json:"description"`
}

// MetricsResponse represents system metrics
type MetricsResponse struct {
	AgentsCount    int    `json:"agents_count"`
	ActiveSessions int    `json:"active_sessions"`
	TotalSessions  int    `json:"total_sessions"`
	Uptime         string `json:"uptime"`
	Version        string `json:"version"`
	StartTime      string `json:"start_time"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Service   string            `json:"service"`
	Version   string            `json:"version"`
	Timestamp string            `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// writeJSON writes a JSON response with proper headers
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Server", "AegisGuard-API/0.1.0")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, `{"success":false,"error":{"code":"INTERNAL_ERROR","message":"Failed to encode response"}}`, http.StatusInternalServerError)
	}
}

// WriteJSON exports writeJSON for use by server.go
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	writeJSON(w, status, data)
}

// writeError writes a standardized error response
func writeError(w http.ResponseWriter, status int, code, message string, details ...string) {
	resp := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
		},
	}
	if len(details) > 0 {
		resp.Error.Details = details[0]
	}
	writeJSON(w, status, resp)
}

// writeSuccess writes a standardized success response
func writeSuccess(w http.ResponseWriter, status int, data interface{}) {
	writeJSON(w, status, APIResponse{
		Success: true,
		Data:    data,
	})
}

// writeSuccessWithMeta writes a success response with pagination metadata
func writeSuccessWithMeta(w http.ResponseWriter, status int, data interface{}, meta *Meta) {
	writeJSON(w, status, APIResponse{
		Success: true,
		Data:    data,
		Meta:    meta,
	})
}

// parseJSON parses JSON from request body
func parseJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// parseQueryInt parses an integer query parameter
func parseQueryInt(r *http.Request, key string, defaultVal int) int {
	val := r.URL.Query().Get(key)
	if val == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return i
}

// parseQueryBool parses a boolean query parameter
func parseQueryBool(r *http.Request, key string, defaultVal bool) bool {
	val := strings.ToLower(r.URL.Query().Get(key))
	switch val {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return defaultVal
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	ip, _, err := splitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// splitHostPort splits a host:port string
func splitHostPort(addr string) (host, port string, err error) {
	// Simple implementation - find last colon not in brackets
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", nil
}

// ============================================================================
// RESPONSE TRANSFORMERS
// ============================================================================

// AgentToResponse converts an RBAC Agent to API response format
func AgentToResponse(agent *rbac.Agent) *AgentResponse {
	if agent == nil {
		return nil
	}
	return &AgentResponse{
		ID:          agent.ID,
		Name:        agent.Name,
		Description: agent.Description,
		Role:        string(agent.Role),
		Tools:       toolsToStrings(agent.Tools),
		Tags:        agent.Tags,
		Enabled:     agent.Enabled,
		CreatedAt:   agent.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   agent.UpdatedAt.Format(time.RFC3339),
	}
}

// AgentsToResponse converts a slice of agents to API response format
func AgentsToResponse(agents []*rbac.Agent) []*AgentResponse {
	if agents == nil {
		return []*AgentResponse{}
	}
	responses := make([]*AgentResponse, len(agents))
	for i, agent := range agents {
		responses[i] = AgentToResponse(agent)
	}
	return responses
}

// SessionToResponse converts an RBAC AgentSession to API response format
func SessionToResponse(session *rbac.AgentSession) *SessionResponse {
	if session == nil {
		return nil
	}

	agentName := ""
	agentRole := ""
	if session.Agent != nil {
		agentName = session.Agent.Name
		agentRole = string(session.Agent.Role)
	}

	remaining := session.RemainingTTL()
	ttlStr := remaining.Round(time.Second).String()
	if remaining <= 0 {
		ttlStr = "expired"
	}

	return &SessionResponse{
		ID:           session.ID,
		AgentID:      session.AgentID,
		AgentName:    agentName,
		Role:         agentRole,
		CreatedAt:    session.CreatedAt.Format(time.RFC3339),
		ExpiresAt:    session.ExpiresAt.Format(time.RFC3339),
		LastActivity: session.LastActivityTime().Format(time.RFC3339),
		TTLRemaining: ttlStr,
		Active:       session.Active,
		IPAddress:    session.IPAddress,
		Tags:         session.Tags,
	}
}

// SessionsToResponse converts a slice of sessions to API response format
func SessionsToResponse(sessions []*rbac.AgentSession) []*SessionResponse {
	if sessions == nil {
		return []*SessionResponse{}
	}
	responses := make([]*SessionResponse, len(sessions))
	for i, session := range sessions {
		responses[i] = SessionToResponse(session)
	}
	return responses
}

// toolsToStrings converts tool permissions to string slice
func toolsToStrings(tools []rbac.ToolPermission) []string {
	if tools == nil {
		return []string{}
	}
	result := make([]string, len(tools))
	for i, t := range tools {
		result[i] = string(t)
	}
	return result
}
