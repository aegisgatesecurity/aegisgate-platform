// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Handler returns HTTP handlers for authentication
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()

	// OAuth endpoints
	mux.HandleFunc("/auth/oauth/login", m.handleOAuthLogin)
	mux.HandleFunc("/auth/oauth/callback", m.handleOAuthCallback)

	// Local auth endpoints
	mux.HandleFunc("/auth/local/login", m.handleLocalLogin)

	// General auth endpoints
	mux.HandleFunc("/auth/login", m.handleLogin)
	mux.HandleFunc("/auth/logout", m.handleLogout)
	mux.HandleFunc("/auth/status", m.handleAuthStatus)
	mux.HandleFunc("/auth/user", m.handleGetUser)

	return mux
}

// handleLogin redirects to appropriate login flow
func (m *Manager) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch m.config.Provider {
	case ProviderLocal:
		http.Redirect(w, r, "/auth/local/login", http.StatusFound)
	case ProviderGoogle, ProviderMicrosoft, ProviderGitHub, ProviderOkta, ProviderAuth0, ProviderGeneric:
		m.InitOAuthFlow(w, r)
	default:
		http.Error(w, "Authentication not configured", http.StatusInternalServerError)
	}
}

// handleOAuthLogin initiates OAuth flow
func (m *Manager) handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	m.InitOAuthFlow(w, r)
}

// handleOAuthCallback handles OAuth callback
func (m *Manager) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	m.HandleOAuthCallback(w, r)
}

// handleLocalLogin handles local authentication
func (m *Manager) handleLocalLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(m.localLoginFormHTML()))
		return
	}

	if r.Method == http.MethodPost {
		m.LocalLogin(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleLogout handles user logout
func (m *Manager) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := m.Logout(w, r); err != nil {
		slog.Warn("Logout failed", "error", err)
	}

	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound) // lgtm[go/unvalidated-url-redirection] — redirect defaults to "/" when empty; production uses SSO/OIDC
}

// handleAuthStatus returns authentication status
func (m *Manager) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	session, err := m.GetSessionFromRequest(r)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": false,
			"provider":      m.config.Provider,
		})
		return
	}

	user := session.User
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"user": map[string]interface{}{
			"id":       user.ID,
			"email":    user.Email,
			"name":     user.Name,
			"role":     user.Role,
			"provider": user.Provider,
		},
	})
}

// handleGetUser returns current user information
func (m *Manager) handleGetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	session, err := m.GetSessionFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "Not authenticated",
		})
		return
	}

	user := session.User
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          user.ID,
		"email":       user.Email,
		"name":        user.Name,
		"role":        user.Role,
		"permissions": user.Permissions,
		"provider":    user.Provider,
	})
}

// localLoginFormHTML returns simple login form
func (m *Manager) localLoginFormHTML() string {
	return `<!DOCTYPE html>
<html>
<head>
<title>AegisGate Login</title>
<style>
body{font-family:Arial,sans-serif;max-width:400px;margin:50px auto;padding:20px}
h1{color:#333}
input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px}
button{width:100%;padding:10px;background:#0066cc;color:white;border:none;border-radius:4px;cursor:pointer}
button:hover{background:#0052a3}
</style>
</head>
<body>
<h1>AegisGate Login</h1>
<form method="POST" action="/auth/local/login">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
</body>
</html>`
}
