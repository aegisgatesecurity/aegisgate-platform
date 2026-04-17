// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package auth

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// contextKey is used for storing values in context
type contextKey string

const (
	// Context keys
	contextKeyUser    contextKey = "auth_user"
	contextKeySession contextKey = "auth_session"
)

// RequireAuth middleware ensures user is authenticated
func (m *Manager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for specific paths
		if m.isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Get session from request
		session, err := m.GetSessionFromRequest(r)
		if err != nil {
			slog.Warn("Authentication required",
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
				"error", err,
			)

			// Return 401 or redirect to login
			if m.isAPIRequest(r) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "Authentication required", http.StatusUnauthorized)
			} else {
				m.redirectToLogin(w, r)
			}
			return
		}

		// Refresh session activity
		if err := m.RefreshSession(session.ID); err != nil {
			slog.Error("Failed to refresh session", "error", err)
			m.clearSessionCookie(w)
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		// Add user and session to context
		ctx := context.WithValue(r.Context(), contextKeyUser, session.User)
		ctx = context.WithValue(ctx, contextKeySession, session)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// RequirePermission middleware checks if user has specific permission
func (m *Manager) RequirePermission(permission Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := m.GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			if !user.HasPermission(permission) {
				slog.Warn("Permission denied",
					"user", user.Email,
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

// RequireRole middleware checks if user has specific role
func (m *Manager) RequireRole(role Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := m.GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			if user.Role != role && user.Role != RoleAdmin {
				// Admin can access everything, otherwise check exact role
				slog.Warn("Role required",
					"user", user.Email,
					"required_role", role,
					"user_role", user.Role,
				)
				http.Error(w, "Forbidden: insufficient role", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin middleware ensures user is an admin
func (m *Manager) RequireAdmin(next http.Handler) http.Handler {
	return m.RequireRole(RoleAdmin)(next)
}

// OptionalAuth middleware adds user to context if authenticated, but doesn't require it
func (m *Manager) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := m.GetSessionFromRequest(r)
		if err == nil {
			// User is authenticated, add to context
			ctx := context.WithValue(r.Context(), contextKeyUser, session.User)
			ctx = context.WithValue(ctx, contextKeySession, session)
			r = r.WithContext(ctx)
		}
		// Continue regardless of auth status
		next.ServeHTTP(w, r)
	})
}

// GetUserFromContext retrieves user from request context
func (m *Manager) GetUserFromContext(ctx context.Context) *User {
	if user, ok := ctx.Value(contextKeyUser).(*User); ok {
		return user
	}
	return nil
}

// GetSessionFromContext retrieves session from request context
func (m *Manager) GetSessionFromContext(ctx context.Context) *Session {
	if session, ok := ctx.Value(contextKeySession).(*Session); ok {
		return session
	}
	return nil
}

// isPublicPath checks if path doesn't require authentication
func (m *Manager) isPublicPath(path string) bool {
	publicPaths := []string{
		"/auth/login",
		"/auth/logout",
		"/auth/callback",
		"/auth/local/login",
		"/health",
		"/api/health",
	}

	for _, public := range publicPaths {
		if strings.HasPrefix(path, public) {
			return true
		}
	}

	// Static assets
	if strings.HasPrefix(path, "/static/") ||
		strings.HasPrefix(path, "/assets/") {
		return true
	}

	return false
}

// isAPIRequest checks if request is an API call
func (m *Manager) isAPIRequest(r *http.Request) bool {
	// Check Accept header
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}

	// Check content type
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		return true
	}

	// Check X-Requested-With header (AJAX)
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return true
	}

	// Check if path starts with /api/
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}

	return false
}

// redirectToLogin redirects to appropriate login page
func (m *Manager) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	var loginURL string

	switch m.config.Provider {
	case ProviderLocal:
		loginURL = "/auth/login"
	case ProviderGoogle, ProviderMicrosoft, ProviderGitHub, ProviderOkta, ProviderAuth0, ProviderGeneric:
		loginURL = "/auth/oauth/login"
	case ProviderSAMLGeneric, ProviderSAMLAzure, ProviderSALMOkta:
		loginURL = "/auth/saml/login"
	default:
		loginURL = "/auth/login"
	}

	// Add redirect parameter
	redirectParam := url.QueryEscape(r.URL.RequestURI())
	loginURL = loginURL + "?redirect=" + redirectParam

	http.Redirect(w, r, loginURL, http.StatusFound)
}
