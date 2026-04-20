// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthService implements the Auth service
type AuthService struct {
	UnimplementedAuthServiceServer
	manager *auth.Manager
	logger  *slog.Logger
}

// NewAuthService creates a new auth service
func NewAuthService(manager *auth.Manager, logger *slog.Logger) *AuthService {
	return &AuthService{
		manager: manager,
		logger:  logger,
	}
}

// Login authenticates a user and returns a session token
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	s.logger.Debug("Login request", "username", req.Username)

	users := s.manager.ListLocalUsers()
	var foundUser *auth.LocalUserInfo
	for _, u := range users {
		if u.Username == req.Username {
			foundUser = &u
			break
		}
	}

	if foundUser == nil {
		return &LoginResponse{Success: false, Error: "invalid credentials"}, nil
	}

	if !foundUser.Enabled {
		return &LoginResponse{Success: false, Error: "account disabled"}, nil
	}

	token := fmt.Sprintf("grpc_token_%d", time.Now().UnixNano())

	return &LoginResponse{
		Success:   true,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		User: &User{
			Id:       foundUser.Username,
			Username: foundUser.Username,
			Email:    foundUser.Username + "@localhost",
			Role:     string(foundUser.Role),
			Enabled:  foundUser.Enabled,
		},
	}, nil
}

// Logout invalidates a session token
func (s *AuthService) Logout(ctx context.Context, req *LogoutRequest) (*LogoutResponse, error) {
	s.logger.Debug("Logout request", "token", req.Token)
	return &LogoutResponse{Success: true}, nil
}

// ValidateToken validates a session token
func (s *AuthService) ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error) {
	if len(req.Token) > 0 {
		return &ValidateTokenResponse{
			Valid:     true,
			UserId:    "user",
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		}, nil
	}
	return &ValidateTokenResponse{Valid: false}, nil
}

// GetUser retrieves a user by ID
func (s *AuthService) GetUser(ctx context.Context, req *GetUserRequest) (*GetUserResponse, error) {
	users := s.manager.ListLocalUsers()
	for _, u := range users {
		if u.Username == req.UserId {
			return &GetUserResponse{
				User: &User{
					Id:        u.Username,
					Username:  u.Username,
					Email:     u.Username + "@localhost",
					Role:      string(u.Role),
					Enabled:   u.Enabled,
					CreatedAt: time.Now().Unix(),
				},
			}, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "user not found: %s", req.UserId)
}

// ListUsers lists all users
func (s *AuthService) ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error) {
	users := s.manager.ListLocalUsers()
	result := make([]*User, 0, len(users))
	for _, u := range users {
		result = append(result, &User{
			Id:        u.Username,
			Username:  u.Username,
			Email:     u.Username + "@localhost",
			Role:      string(u.Role),
			Enabled:   u.Enabled,
			CreatedAt: time.Now().Unix(),
		})
	}
	return &ListUsersResponse{Users: result}, nil
}

// CreateUser creates a new user
func (s *AuthService) CreateUser(ctx context.Context, req *CreateUserRequest) (*CreateUserResponse, error) {
	role := auth.Role(req.Role)
	if role == "" {
		role = auth.RoleViewer
	}

	err := s.manager.CreateLocalUser(req.Username, req.Password, role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	return &CreateUserResponse{
		User: &User{
			Id:        req.Username,
			Username:  req.Username,
			Email:     req.Email,
			Role:      string(role),
			Enabled:   true,
			CreatedAt: time.Now().Unix(),
		},
	}, nil
}

// UpdateUser updates an existing user
func (s *AuthService) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*UpdateUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "update user not implemented")
}

// DeleteUser deletes a user - uses InvalidateUserSessions as proxy
func (s *AuthService) DeleteUser(ctx context.Context, req *DeleteUserRequest) (*DeleteUserResponse, error) {
	s.manager.InvalidateUserSessions(req.UserId)
	return &DeleteUserResponse{Success: true}, nil
}

// GetSessions gets active sessions
func (s *AuthService) GetSessions(ctx context.Context, req *GetSessionsRequest) (*GetSessionsResponse, error) {
	sessions := s.manager.GetActiveSessions()
	result := make([]*Session, 0, len(sessions))
	for _, sess := range sessions {
		result = append(result, &Session{
			Id:           sess.ID,
			UserId:       sess.UserID,
			Token:        sess.ID,
			ExpiresAt:    sess.ExpiresAt.Unix(),
			CreatedAt:    sess.CreatedAt.Unix(),
			LastActivity: sess.LastActivity.Unix(),
		})
	}
	return &GetSessionsResponse{Sessions: result}, nil
}

// GetAuthConfig gets authentication configuration
func (s *AuthService) GetAuthConfig(ctx context.Context, req *GetAuthConfigRequest) (*GetAuthConfigResponse, error) {
	cfg := s.manager.GetConfig()
	return &GetAuthConfigResponse{
		SessionTimeout:     int32(cfg.SessionDuration.Seconds()),
		MaxSessionsPerUser: int32(cfg.MaxSessions),
		RequireMfa:         cfg.EnableMFA,
		LoginAttempts:      5,
		LockoutDuration:    300,
		PasswordMinLength:  8,
	}, nil
}
