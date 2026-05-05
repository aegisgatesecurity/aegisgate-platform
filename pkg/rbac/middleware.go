// SPDX-License-Identifier: Apache-2.0
// Package rbac provides HTTP middleware for RBAC-aware access control
// in the AegisGate Security Platform.
//
// The middleware suite supports:
//   - RequireRole: Enforces minimum role level for endpoints (403 on insufficient role)
//   - RequirePermission: Gates access by specific permission (403 if missing)
//   - RequireToolPermission: Gates tool execution permissions (for MCP agents)
//
// Additionally, InjectRBACContext reads session ID from request context
// and injects the Manager and session into the request context for downstream handlers.
package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// RBACMiddleware wraps a Manager and provides HTTP middleware functions
// for RBAC-aware access control.
type RBACMiddleware struct {
	manager *Manager
	logger  *slog.Logger
}

// NewRBACMiddleware creates a new RBACMiddleware that wraps the given manager.
func NewRBACMiddleware(manager *Manager) *RBACMiddleware {
	return &RBACMiddleware{
		manager: manager,
		logger:  slog.Default(),
	}
}

// RequireRole returns middleware that enforces a minimum role level.
// If the resolved session role is below the minimum, a 403 JSON error is returned.
func (rm *RBACMiddleware) RequireRole(minimumRole AgentRole) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get session from context (may have been injected by InjectRBACContext)
			session, err := GetSessionFromContext(ctx)
			if err != nil || session == nil {
				writeForbidden(w, "authentication required", "")
				return
			}

			// Check if session role meets minimum requirement
			if !session.Agent.Role.AtLeast(minimumRole) {
				writeForbidden(w, fmt.Sprintf("requires %s role or above", minimumRole), session.Agent.Role.String())
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

// RequirePermission returns middleware that enforces a specific tool permission.
// If the agent doesn't have the required permission, a 403 JSON error is returned.
func (rm *RBACMiddleware) RequirePermission(permission ToolPermission) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get session from context
			session, err := GetSessionFromContext(ctx)
			if err != nil || session == nil {
				writeForbidden(w, "authentication required", "")
				return
			}

			// Check if agent has the required permission
			if !session.Agent.HasToolPermission(permission) {
				writeForbidden(w, fmt.Sprintf("permission %s required", permission), session.Agent.Role.String())
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

// RequireToolPermission returns middleware that enforces tool execution permission.
// This is specifically for MCP agent tool execution scenarios.
func (rm *RBACMiddleware) RequireToolPermission(toolName string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get session from context
			session, err := GetSessionFromContext(ctx)
			if err != nil || session == nil {
				writeForbidden(w, "authentication required", "")
				return
			}

			// Check if agent can execute the tool
			if !session.Agent.CanExecuteTool(toolName) {
				minimumRole := getMinimumRoleForTool(toolName)
				writeForbidden(w, fmt.Sprintf("tool %s requires %s role or higher", toolName, minimumRole), session.Agent.Role.String())
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

// InjectRBACContext extracts session ID from the request context or header,
// retrieves the session from the Manager, and injects both session and agent
// into the request context for downstream handlers.
func (rm *RBACMiddleware) InjectRBACContext(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Try to get session ID from context first
		var sessionID string
		if sid, ok := ctx.Value(CtxKeySessionID).(string); ok && sid != "" {
			sessionID = sid
		}

		// If not in context, check header
		if sessionID == "" {
			sessionID = r.Header.Get("X-Session-ID")
		}

		// If still no session ID, check query parameter
		if sessionID == "" {
			sessionID = r.URL.Query().Get("session_id")
		}

		if sessionID == "" {
			// FAIL-CLOSED: No session ID means no authentication context.
			// Downstream handlers MUST have RBAC context to enforce access control.
			// Allowing through without context is a security risk — any request
			// without a session ID could bypass all role-based checks.
			rm.logger.Warn("RBAC context injection: no session ID — denying request")
			writeForbidden(w, "authentication required: session ID missing", "")
			return
		}

		// Get session from manager
		session, err := rm.manager.GetSession(sessionID)
		if err != nil {
			// FAIL-CLOSED: Invalid/expired session means the user's session is gone.
			// This covers revoked sessions, expired tokens, and corrupt session IDs.
			// Allowing through without a valid session is a security risk —
			// an attacker with a revoked session ID could bypass RBAC.
			rm.logger.Warn("RBAC context injection: session invalid — denying request",
				"error", err, "session_id", truncateID(sessionID))
			writeForbidden(w, "invalid or expired session", "")
			return
		}

		// Inject session and agent into context
		ctx = ContextWithSession(ctx, session)
		ctx = ContextWithAgent(ctx, session.Agent)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetSessionFromContext extracts an agent session from the request context.
func GetSessionFromContext(ctx context.Context) (*AgentSession, error) {
	session, ok := ctx.Value(CtxKeyAgentSession).(*AgentSession)
	if !ok || session == nil {
		return nil, fmt.Errorf("no session in context")
	}
	return session, nil
}

// GetAgentFromContext extracts an agent from the request context.
func GetAgentFromContext(ctx context.Context) (*Agent, error) {
	agent, ok := ctx.Value(CtxKeyAgent).(*Agent)
	if !ok || agent == nil {
		return nil, fmt.Errorf("no agent in context")
	}
	return agent, nil
}

// writeForbidden writes a 403 Forbidden JSON response.
func writeForbidden(w http.ResponseWriter, message, currentRole string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	resp := errorResponse{
		Error:   "forbidden",
		Message: message,
		Tier:    currentRole,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return
	}
}

// Context context keys for RBAC middleware
const (
	CtxKeySessionID    contextKey = "rbac_session_id"
	CtxKeyAgentSession contextKey = "rbac_agent_session"
	CtxKeyAgent        contextKey = "rbac_agent"
)

// ContextKey type for type-safe context keys
type contextKey string

// ContextWithSession injects an agent session into the request context.
func ContextWithSession(ctx context.Context, session *AgentSession) context.Context {
	return context.WithValue(ctx, CtxKeyAgentSession, session)
}

// ContextWithAgent injects an agent into the request context.
func ContextWithAgent(ctx context.Context, agent *Agent) context.Context {
	return context.WithValue(ctx, CtxKeyAgent, agent)
}

// errorResponse is the JSON structure for 403 error replies.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Tier    string `json:"tier,omitempty"`
}
