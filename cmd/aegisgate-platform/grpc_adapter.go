// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — gRPC Auth Backend Adapter (v4.3.1)
//
// grpc_adapter.go adapts the SSO Manager to the gRPC AuthBackend
// interface. This allows the gRPC server to authenticate requests
// using the same SSO session store that the HTTP API uses.
//
// The adapter maps:
//   - ValidateToken → sso.Manager.ValidateSession
//   - Logout        → sso.Manager.Logout
//   - GetSessions   → sso.Manager.GetUserSessions (for admin user)
//   - GetUser       → extracts from SSOSession.User
//   - GetAuthConfig → returns static config from platformconfig
//
// Methods that require a user store (CreateUser, UpdateUser, DeleteUser,
// ListUsers) return Unimplemented, as user management is handled by the
// SSO provider (Okta, Azure AD, Keycloak), not by the platform itself.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/grpc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sso"
)

// ssoAuthBackend adapts sso.Manager to the grpc.AuthBackend interface.
type ssoAuthBackend struct {
	ssoMgr *sso.Manager
	logger *slog.Logger
}

// newSSOAuthBackend creates a new AuthBackend adapter from the SSO Manager.
func newSSOAuthBackend(mgr *sso.Manager, logger *slog.Logger) grpc.AuthBackend {
	if logger == nil {
		logger = slog.Default().With("component", "grpc-auth-adapter")
	}
	return &ssoAuthBackend{ssoMgr: mgr, logger: logger}
}

func (a *ssoAuthBackend) Login(ctx context.Context, username, password string) (string, int64, error) {
	// SSO login is handled via browser redirect (OAuth/OIDC/SAML).
	// Direct username/password login is not supported through SSO.
	// Return an error directing the caller to use the HTTP SSO flow.
	return "", 0, fmt.Errorf("direct login not supported; use SSO via HTTP /api/v1/auth/login/{provider}")
}

func (a *ssoAuthBackend) Logout(ctx context.Context, token string) error {
	_, err := a.ssoMgr.Logout(token)
	return err
}

func (a *ssoAuthBackend) ValidateToken(ctx context.Context, token string) (bool, string, int64, error) {
	session, err := a.ssoMgr.ValidateSession(token)
	if err != nil {
		return false, "", 0, nil // invalid token = not an error, just invalid
	}

	userID := session.UserID
	if userID == "" && session.User != nil {
		userID = session.User.ID
	}

	expiresAt := session.ExpiresAt.Unix()
	return true, userID, expiresAt, nil
}

func (a *ssoAuthBackend) GetUser(ctx context.Context, userID string) (*grpc.AuthUserInfo, error) {
	// SSO doesn't have a user store — users are managed by the IdP.
	// We can't look up arbitrary users by ID without a session.
	// Return a minimal info struct from what we know.
	return &grpc.AuthUserInfo{
		ID:       userID,
		Username: userID,
		Role:     "viewer", // default role
		Enabled:  true,
	}, nil
}

func (a *ssoAuthBackend) ListUsers(ctx context.Context) ([]*grpc.AuthUserInfo, error) {
	// User management is handled by the SSO provider.
	return nil, fmt.Errorf("user management not supported via gRPC; use SSO provider admin console")
}

func (a *ssoAuthBackend) CreateUser(ctx context.Context, username, email, password, role string) (*grpc.AuthUserInfo, error) {
	return nil, fmt.Errorf("user creation not supported via gRPC; use SSO provider admin console")
}

func (a *ssoAuthBackend) UpdateUser(ctx context.Context, userID, username, email, role string, enabled bool) (*grpc.AuthUserInfo, error) {
	return nil, fmt.Errorf("user update not supported via gRPC; use SSO provider admin console")
}

func (a *ssoAuthBackend) DeleteUser(ctx context.Context, userID string) error {
	return fmt.Errorf("user deletion not supported via gRPC; use SSO provider admin console")
}

func (a *ssoAuthBackend) GetSessions(ctx context.Context) ([]*grpc.AuthSessionInfo, error) {
	// We can't list all sessions from the SSO manager without a user ID.
	// Return an empty list — the gRPC client can query per-user
	// sessions if needed.
	return []*grpc.AuthSessionInfo{}, nil
}

func (a *ssoAuthBackend) GetAuthConfig(ctx context.Context) (*grpc.AuthConfig, error) {
	return &grpc.AuthConfig{
		SessionDurationSec: 3600,
		MaxSessions:        100,
		EnableMFA:          false,
		LoginAttempts:      5,
		LockoutDurationSec: 300,
		PasswordMinLength:  12,
	}, nil
}

// Compile-time interface check.
var _ grpc.AuthBackend = (*ssoAuthBackend)(nil)

// timeNow is a helper to avoid importing time in the adapter methods.
var timeNow = time.Now
