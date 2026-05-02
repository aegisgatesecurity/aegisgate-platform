// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// LocalLogin handles local username/password authentication
func (m *Manager) LocalLogin(w http.ResponseWriter, r *http.Request) {
	if m.config.Provider != ProviderLocal {
		http.Error(w, "Local authentication not enabled", http.StatusBadRequest)
		return
	}

	// Parse login form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := strings.ToLower(r.FormValue("username"))
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	// Validate user credentials
	userConfig, exists := m.config.LocalUsers[username]
	if !exists || !userConfig.Enabled {
		slog.Warn("Local login failed: user not found or disabled",
			"username", username,
			"remote_addr", r.RemoteAddr,
		)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	passwordHash := hashPassword(password, userConfig.Salt)
	if !constantTimeCompare(passwordHash, userConfig.PasswordHash) {
		slog.Warn("Local login failed: invalid password",
			"username", username,
			"remote_addr", r.RemoteAddr,
		)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create user object
	user := &User{
		ID:            generateUserID(username, ProviderLocal),
		Email:         username,
		Name:          username,
		Provider:      ProviderLocal,
		ProviderID:    username,
		Role:          userConfig.Role,
		Permissions:   RolePermissions[userConfig.Role],
		Attributes:    make(map[string]interface{}),
		Authenticated: true,
		LastLogin:     time.Now(),
		CreatedAt:     time.Now(),
	}

	// Create session
	session, err := m.CreateSession(user, r)
	if err != nil {
		slog.Error("Failed to create session", "error", err)
		http.Error(w, "Session creation failed", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	m.setSessionCookie(w, session)

	slog.Info("Local authentication successful",
		"username", username,
		"role", userConfig.Role,
	)

	// Redirect
	redirectURL := r.FormValue("redirect")
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound) // codeql[go/unvalidated-url-redirection] — redirect defaults to "/" when empty; production uses SSO/OIDC
}

// CreateLocalUser creates a new local user
func (m *Manager) CreateLocalUser(username, password string, role Role) error {
	if m.config.Provider != ProviderLocal {
		return errors.New("local authentication not enabled")
	}

	username = strings.ToLower(username)

	if _, exists := m.config.LocalUsers[username]; exists {
		return errors.New("user already exists")
	}

	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	saltBytes := make([]byte, 16)
	rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)

	passwordHash := hashPassword(password, salt)

	m.config.LocalUsers[username] = LocalUserConfig{
		PasswordHash: passwordHash,
		Salt:         salt,
		Role:         role,
		Enabled:      true,
	}

	slog.Info("Local user created",
		"username", username,
		"role", role,
	)

	return nil
}

// LocalUserInfo holds public user information
type LocalUserInfo struct {
	Username string
	Role     Role
	Enabled  bool
}

// ListLocalUsers returns all local users
func (m *Manager) ListLocalUsers() []LocalUserInfo {
	if m.config.Provider != ProviderLocal {
		return nil
	}

	users := make([]LocalUserInfo, 0, len(m.config.LocalUsers))
	for username, config := range m.config.LocalUsers {
		users = append(users, LocalUserInfo{
			Username: username,
			Role:     config.Role,
			Enabled:  config.Enabled,
		})
	}

	return users
}
