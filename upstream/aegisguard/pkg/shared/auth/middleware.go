// SPDX-License-Identifier: Apache-2.0
// =========================================================================

// =========================================================================

package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)

// contextKey is used for storing values in context
type contextKey string

const (
	contextKeyAgent   contextKey = "auth_agent"
	contextKeySession contextKey = "auth_session"
)

// RequireAuth middleware ensures agent is authenticated
func (m *Manager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for specific paths
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Get session from request
		session, err := m.GetSessionFromRequest(r)
		if err != nil {
			slog.Warn("Authentication required",
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
			)

			if isAPIRequest(r) {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/auth/login", http.StatusFound)
			}
			return
		}

		// Refresh session activity
		if err := m.RefreshSession(session.ID); err != nil {
			slog.Error("Failed to refresh session", "error", err)
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		// Add agent and session to context
		ctx := context.WithValue(r.Context(), contextKeyAgent, session.Agent)
		ctx = context.WithValue(ctx, contextKeySession, session)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// RequirePermission middleware checks if agent has specific permission
func (m *Manager) RequirePermission(permission Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			agent := GetAgentFromContext(r.Context())
			if agent == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			if !agent.HasPermission(permission) {
				slog.Warn("Permission denied",
					"agent", agent.ID,
					"permission", permission,
					"path", r.URL.Path,
				)
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole middleware checks if agent has specific role
func (m *Manager) RequireRole(role Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			agent := GetAgentFromContext(r.Context())
			if agent == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			if !agent.Role.AtLeast(role) {
				slog.Warn("Role required",
					"agent", agent.ID,
					"required_role", role,
					"agent_role", agent.Role,
				)
				http.Error(w, "Forbidden: insufficient role", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin middleware ensures agent is an admin
func (m *Manager) RequireAdmin(next http.Handler) http.Handler {
	return m.RequireRole(RoleAdmin)(next)
}

// OptionalAuth middleware adds agent to context if authenticated
func (m *Manager) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := m.GetSessionFromRequest(r)
		if err == nil {
			ctx := context.WithValue(r.Context(), contextKeyAgent, session.Agent)
			ctx = context.WithValue(ctx, contextKeySession, session)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// GetAgentFromContext retrieves agent from request context
func GetAgentFromContext(ctx context.Context) *Agent {
	if agent, ok := ctx.Value(contextKeyAgent).(*Agent); ok {
		return agent
	}
	return nil
}

// GetSessionFromContext retrieves session from request context
func GetSessionFromContext(ctx context.Context) *Session {
	if session, ok := ctx.Value(contextKeySession).(*Session); ok {
		return session
	}
	return nil
}

// isPublicPath checks if path doesn't require authentication
func isPublicPath(path string) bool {
	publicPaths := []string{
		"/auth/login",
		"/auth/logout",
		"/health",
		"/api/health",
	}

	for _, public := range publicPaths {
		if strings.HasPrefix(path, public) {
			return true
		}
	}

	return false
}

// isAPIRequest checks if request is an API call
func isAPIRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		return true
	}

	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}

	return false
}
