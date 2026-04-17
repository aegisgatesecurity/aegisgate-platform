// Package handlers - Authorization, Tools, and Roles API handlers for AegisGuard
package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// AuthHandler handles authorization-related API requests
type AuthHandler struct {
	manager *rbac.Manager
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(manager *rbac.Manager) *AuthHandler {
	return &AuthHandler{
		manager: manager,
	}
}

// ============================================================================
// REQUEST TYPES
// ============================================================================

// AuthorizeRequest represents authorization check request
type AuthorizeRequest struct {
	AgentID   string `json:"agent_id"`
	SessionID string `json:"session_id,omitempty"`
	ToolName  string `json:"tool_name"`
}

// ============================================================================
// HANDLERS
// ============================================================================

// HandleAuthorize handles authorization checks
func (h *AuthHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"Only POST method is allowed for /authorize")
		return
	}

	var req AuthorizeRequest
	if err := parseJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Failed to parse request body", err.Error())
		return
	}

	// Validate required fields
	if req.AgentID == "" && req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR",
			"Either agent_id or session_id is required")
		return
	}
	if req.ToolName == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR",
			"Tool name is required")
		return
	}

	ctx := context.Background()

	// Determine session ID
	sessionID := req.SessionID

	// If session ID not provided, get first active session for agent
	if sessionID == "" && req.AgentID != "" {
		sessions := h.manager.GetAgentSessions(req.AgentID)
		for _, s := range sessions {
			if s.Active && !s.IsExpired() {
				sessionID = s.ID
				break
			}
		}
		if sessionID == "" {
			writeError(w, http.StatusNotFound, "NO_ACTIVE_SESSION",
				fmt.Sprintf("No active session found for agent '%s'", req.AgentID))
			return
		}
	}

	// Perform authorization
	result, err := h.manager.AuthorizeToolCall(ctx, sessionID, req.ToolName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "AUTHORIZATION_FAILED",
			err.Error())
		return
	}

	// Build response
	response := AuthorizationResponse{
		Allowed:          result.Allowed,
		Reason:           result.Reason,
		AgentRole:        string(result.AgentRole),
		ToolName:         result.ToolName,
		RequiresApproval: result.RequiresApproval,
	}

	if !result.Allowed {
		response.RequiredRole = string(result.RequiredRole)
	}

	writeSuccess(w, http.StatusOK, response)
}

// HandleBatchAuthorize handles batch authorization checks
func (h *AuthHandler) HandleBatchAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"Only POST method is allowed for /authorize/batch")
		return
	}

	var requests []AuthorizeRequest
	if err := parseJSON(r, &requests); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Failed to parse request body", err.Error())
		return
	}

	if len(requests) == 0 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR",
			"At least one authorization request is required")
		return
	}

	if len(requests) > 100 {
		writeError(w, http.StatusBadRequest, "VALIDATION_ERROR",
			"Maximum 100 authorization requests per batch")
		return
	}

	ctx := context.Background()
	results := make([]AuthorizationResponse, 0, len(requests))

	for _, req := range requests {
		// Validate
		if req.AgentID == "" && req.SessionID == "" {
			results = append(results, AuthorizationResponse{
				Allowed:  false,
				Reason:   "Either agent_id or session_id is required",
				ToolName: req.ToolName,
			})
			continue
		}
		if req.ToolName == "" {
			results = append(results, AuthorizationResponse{
				Allowed:  false,
				Reason:   "Tool name is required",
				ToolName: req.ToolName,
			})
			continue
		}

		// Determine session ID
		sessionID := req.SessionID
		if sessionID == "" && req.AgentID != "" {
			sessions := h.manager.GetAgentSessions(req.AgentID)
			for _, s := range sessions {
				if s.Active && !s.IsExpired() {
					sessionID = s.ID
					break
				}
			}
		}

		if sessionID == "" {
			results = append(results, AuthorizationResponse{
				Allowed:  false,
				Reason:   "No active session found",
				ToolName: req.ToolName,
			})
			continue
		}

		// Authorize
		result, err := h.manager.AuthorizeToolCall(ctx, sessionID, req.ToolName)
		if err != nil {
			results = append(results, AuthorizationResponse{
				Allowed:  false,
				Reason:   err.Error(),
				ToolName: req.ToolName,
			})
			continue
		}

		results = append(results, AuthorizationResponse{
			Allowed:          result.Allowed,
			Reason:           result.Reason,
			AgentRole:        string(result.AgentRole),
			ToolName:         result.ToolName,
			RequiresApproval: result.RequiresApproval,
		})
	}

	writeSuccess(w, http.StatusOK, map[string]interface{}{
		"results": results,
		"count":   len(results),
	})
}

// AuthorizationResponse represents authorization check response
type AuthorizationResponse struct {
	Allowed          bool   `json:"allowed"`
	Reason           string `json:"reason,omitempty"`
	AgentRole        string `json:"agent_role,omitempty"`
	ToolName         string `json:"tool_name,omitempty"`
	RequiredRole     string `json:"required_role,omitempty"`
	RequiresApproval bool   `json:"requires_approval,omitempty"`
}

// ============================================================================
// TOOLS HANDLER
// ============================================================================

// ToolsHandler handles tool-related API requests
type ToolsHandler struct {
	manager *rbac.Manager
}

// NewToolsHandler creates a new tools handler
func NewToolsHandler(manager *rbac.Manager) *ToolsHandler {
	return &ToolsHandler{
		manager: manager,
	}
}

// HandleTools handles GET /api/v1/tools
func (h *ToolsHandler) HandleTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"Only GET method is allowed for /tools")
		return
	}

	role := r.URL.Query().Get("role")

	// Define available tools
	tools := []ToolInfo{
		// File operations
		{Name: "file_read", Category: "file", RiskLevel: "low", Description: "Read files from disk"},
		{Name: "file_write", Category: "file", RiskLevel: "medium", Description: "Write files to disk"},
		{Name: "file_delete", Category: "file", RiskLevel: "high", Description: "Delete files from disk"},
		{Name: "file_exists", Category: "file", RiskLevel: "low", Description: "Check if file exists"},

		// Web operations
		{Name: "web_search", Category: "web", RiskLevel: "low", Description: "Search the web"},
		{Name: "http_request", Category: "web", RiskLevel: "medium", Description: "Make HTTP requests"},
		{Name: "json_fetch", Category: "web", RiskLevel: "low", Description: "Fetch JSON data"},

		// Shell operations
		{Name: "shell_command", Category: "shell", RiskLevel: "critical", Description: "Execute shell commands"},
		{Name: "bash", Category: "shell", RiskLevel: "critical", Description: "Execute bash commands"},
		{Name: "ping", Category: "network", RiskLevel: "low", Description: "Ping hosts"},

		// Code operations
		{Name: "code_execute_go", Category: "code", RiskLevel: "high", Description: "Execute Go code"},
		{Name: "code_execute_python", Category: "code", RiskLevel: "high", Description: "Execute Python code"},
		{Name: "code_execute_javascript", Category: "code", RiskLevel: "high", Description: "Execute JavaScript code"},
		{Name: "code_search", Category: "code", RiskLevel: "low", Description: "Search code"},

		// Database operations
		{Name: "database_query", Category: "database", RiskLevel: "critical", Description: "Execute database queries"},
		{Name: "database_list", Category: "database", RiskLevel: "medium", Description: "List databases"},
		{Name: "database_schema", Category: "database", RiskLevel: "medium", Description: "Get database schema"},
	}

	// If role specified, filter by role permissions
	if role != "" {
		agentRole := rbac.AgentRole(role)
		perms := rbac.GetPermissionsForRole(agentRole)
		permSet := make(map[string]bool)
		for _, p := range perms {
			permSet[string(p)] = true
		}

		// Also check wildcard
		_, hasAll := permSet[string(rbac.PermToolAll)]

		filtered := make([]ToolInfo, 0)
		for _, tool := range tools {
			permName := fmt.Sprintf("tool:%s", tool.Name)
			if hasAll || permSet[permName] {
				filtered = append(filtered, tool)
			}
		}
		tools = filtered
	}

	writeSuccess(w, http.StatusOK, map[string]interface{}{
		"tools": tools,
		"count": len(tools),
	})
}

// ToolInfo represents information about a tool
type ToolInfo struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	RiskLevel   string `json:"risk_level"`
	Description string `json:"description"`
}

// ============================================================================
// ROLES HANDLER
// ============================================================================

// RolesHandler handles role-related API requests
type RolesHandler struct {
	manager *rbac.Manager
}

// NewRolesHandler creates a new roles handler
func NewRolesHandler(manager *rbac.Manager) *RolesHandler {
	return &RolesHandler{
		manager: manager,
	}
}

// HandleRoles handles GET /api/v1/roles
func (h *RolesHandler) HandleRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"Only GET method is allowed for /roles")
		return
	}

	roles := []RoleInfo{
		{
			Name:        "restricted",
			Level:       1,
			Permissions: permissionToStrings(rbac.RolePermissions[rbac.AgentRoleRestricted]),
			Description: "Minimal tools (read-only, no execution)",
		},
		{
			Name:        "standard",
			Level:       2,
			Permissions: permissionToStrings(rbac.RolePermissions[rbac.AgentRoleStandard]),
			Description: "Common development tools",
		},
		{
			Name:        "privileged",
			Level:       3,
			Permissions: permissionToStrings(rbac.RolePermissions[rbac.AgentRolePrivileged]),
			Description: "Sensitive operations (may require additional approval)",
		},
		{
			Name:        "admin",
			Level:       4,
			Permissions: []string{"*"},
			Description: "Full access, all tools",
		},
	}

	writeSuccess(w, http.StatusOK, map[string]interface{}{
		"roles": roles,
		"count": len(roles),
	})
}

// HandleRoleByName handles GET /api/v1/roles/{name}
func (h *RolesHandler) HandleRoleByName(w http.ResponseWriter, r *http.Request) {
	// Extract role name from path
	roleName := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
	roleName = strings.TrimSuffix(roleName, "/")

	if roleName == "" {
		writeError(w, http.StatusBadRequest, "INVALID_PATH", "Role name is required")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			fmt.Sprintf("Method %s not allowed for /roles/%s", r.Method, roleName))
		return
	}

	role := rbac.AgentRole(roleName)
	roleLevel := map[rbac.AgentRole]int{
		rbac.AgentRoleRestricted: 1,
		rbac.AgentRoleStandard:   2,
		rbac.AgentRolePrivileged: 3,
		rbac.AgentRoleAdmin:      4,
	}

	level, ok := roleLevel[role]
	if !ok {
		writeError(w, http.StatusNotFound, "ROLE_NOT_FOUND",
			fmt.Sprintf("Role '%s' not found", roleName))
		return
	}

	perms := rbac.GetPermissionsForRole(role)

	roleInfo := RoleInfo{
		Name:        roleName,
		Level:       level,
		Permissions: permissionToStrings(perms),
		Description: getRoleDescription(role),
	}

	writeSuccess(w, http.StatusOK, roleInfo)
}

// permissionToStrings converts permissions to string slice
func permissionToStrings(perms []rbac.ToolPermission) []string {
	result := make([]string, len(perms))
	for i, p := range perms {
		result[i] = string(p)
	}
	return result
}

// getRoleDescription returns the description for a role
func getRoleDescription(role rbac.AgentRole) string {
	descriptions := map[rbac.AgentRole]string{
		rbac.AgentRoleRestricted: "Minimal tools (read-only, no execution)",
		rbac.AgentRoleStandard:   "Common development tools",
		rbac.AgentRolePrivileged: "Sensitive operations (may require additional approval)",
		rbac.AgentRoleAdmin:      "Full access, all tools",
	}
	if desc, ok := descriptions[role]; ok {
		return desc
	}
	return "Unknown role"
}

// ============================================================================
// METRICS HANDLER
// ============================================================================

// MetricsHandler handles metrics API requests
type MetricsHandler struct {
	manager   *rbac.Manager
	startTime time.Time
	version   string
}

// NewMetricsHandler creates a new metrics handler
func NewMetricsHandler(manager *rbac.Manager, version string) *MetricsHandler {
	return &MetricsHandler{
		manager:   manager,
		startTime: time.Now(),
		version:   version,
	}
}

// HandleMetrics handles GET /api/v1/metrics
func (h *MetricsHandler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED",
			"Only GET method is allowed for /metrics")
		return
	}

	// Collect metrics
	agents := h.manager.ListAgents()

	activeSessions := 0
	totalSessions := 0
	for _, agent := range agents {
		sessions := h.manager.GetAgentSessions(agent.ID)
		totalSessions += len(sessions)
		for _, s := range sessions {
			if s.Active && !s.IsExpired() {
				activeSessions++
			}
		}
	}

	uptime := time.Since(h.startTime)

	metrics := MetricsResponse{
		AgentsCount:    len(agents),
		ActiveSessions: activeSessions,
		TotalSessions:  totalSessions,
		Uptime:         uptime.Round(time.Second).String(),
		Version:        h.version,
		StartTime:      h.startTime.Format(time.RFC3339),
	}

	writeSuccess(w, http.StatusOK, metrics)
}
