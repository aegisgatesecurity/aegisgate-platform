// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Auth Service Implementation
// =========================================================================

package grpc

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthService implements AuthServiceServer using an AuthBackend.
type AuthService struct {
	UnimplementedAuthServiceServer
	backend AuthBackend
	logger  *slog.Logger
}

// NewAuthService creates a new AuthService with the given backend.
func NewAuthService(backend AuthBackend, logger *slog.Logger) *AuthService {
	return &AuthService{backend: backend, logger: logger}
}

// Login authenticates a user and returns a session token.
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}

	token, expiresAt, err := s.backend.Login(ctx, req.Username, req.Password)
	if err != nil {
		s.logger.Error("gRPC auth login failed", "username", req.Username, "error", err)
		return &LoginResponse{Success: false, Error: err.Error()}, nil
	}

	// Fetch user details for the response.
	userInfo, err := s.backend.GetUser(ctx, req.Username)
	if err != nil {
		// Login succeeded but user lookup failed — return minimal response.
		return &LoginResponse{
			Success:   true,
			Token:     token,
			ExpiresAt: expiresAt,
		}, nil
	}

	return &LoginResponse{
		Success:   true,
		Token:     token,
		ExpiresAt: expiresAt,
		User:      userInfoToProto(userInfo),
	}, nil
}

// Logout invalidates a session token.
func (s *AuthService) Logout(ctx context.Context, req *LogoutRequest) (*LogoutResponse, error) {
	if req.Token == "" {
		return &LogoutResponse{Success: false, Error: "token is required"}, nil
	}

	if err := s.backend.Logout(ctx, req.Token); err != nil {
		s.logger.Error("gRPC auth logout failed", "error", err)
		return &LogoutResponse{Success: false, Error: err.Error()}, nil
	}

	return &LogoutResponse{Success: true}, nil
}

// ValidateToken validates a session token.
func (s *AuthService) ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error) {
	if req.Token == "" {
		return &ValidateTokenResponse{Valid: false}, nil
	}

	valid, userID, expiresAt, err := s.backend.ValidateToken(ctx, req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "token validation failed: %v", err)
	}

	return &ValidateTokenResponse{
		Valid:     valid,
		UserId:    userID,
		ExpiresAt: expiresAt,
	}, nil
}

// GetUser retrieves a user by ID.
func (s *AuthService) GetUser(ctx context.Context, req *GetUserRequest) (*GetUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user_id is required")
	}

	userInfo, err := s.backend.GetUser(ctx, req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "user not found: %s", req.UserId)
	}

	return &GetUserResponse{User: userInfoToProto(userInfo)}, nil
}

// ListUsers lists all users.
func (s *AuthService) ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error) {
	users, err := s.backend.ListUsers(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list users: %v", err)
	}

	result := make([]*User, 0, len(users))
	for _, u := range users {
		result = append(result, userInfoToProto(u))
	}

	return &ListUsersResponse{Users: result}, nil
}

// CreateUser creates a new user.
func (s *AuthService) CreateUser(ctx context.Context, req *CreateUserRequest) (*CreateUserResponse, error) {
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.Password == "" {
		return nil, status.Errorf(codes.InvalidArgument, "password is required")
	}

	role := req.Role
	if role == "" {
		role = "viewer"
	}

	userInfo, err := s.backend.CreateUser(ctx, req.Username, req.Email, req.Password, role)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	return &CreateUserResponse{User: userInfoToProto(userInfo)}, nil
}

// UpdateUser updates an existing user.
func (s *AuthService) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*UpdateUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user_id is required")
	}

	userInfo, err := s.backend.UpdateUser(ctx, req.UserId, req.Username, req.Email, req.Role, req.Enabled)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
	}

	return &UpdateUserResponse{User: userInfoToProto(userInfo)}, nil
}

// DeleteUser deletes a user.
func (s *AuthService) DeleteUser(ctx context.Context, req *DeleteUserRequest) (*DeleteUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user_id is required")
	}

	if err := s.backend.DeleteUser(ctx, req.UserId); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user: %v", err)
	}

	return &DeleteUserResponse{Success: true}, nil
}

// GetSessions returns active sessions.
func (s *AuthService) GetSessions(ctx context.Context, req *GetSessionsRequest) (*GetSessionsResponse, error) {
	sessions, err := s.backend.GetSessions(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get sessions: %v", err)
	}

	result := make([]*Session, 0, len(sessions))
	for _, sess := range sessions {
		result = append(result, &Session{
			Id:           sess.ID,
			UserId:       sess.UserID,
			Token:        sess.Token,
			ExpiresAt:    sess.ExpiresAt,
			CreatedAt:    sess.CreatedAt,
			LastActivity: sess.LastActivity,
			IpAddress:    sess.IPAddress,
		})
	}

	return &GetSessionsResponse{Sessions: result}, nil
}

// GetAuthConfig returns authentication configuration.
func (s *AuthService) GetAuthConfig(ctx context.Context, req *GetAuthConfigRequest) (*GetAuthConfigResponse, error) {
	cfg, err := s.backend.GetAuthConfig(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get auth config: %v", err)
	}

	return &GetAuthConfigResponse{
		SessionTimeout:     cfg.SessionDurationSec,
		MaxSessionsPerUser: cfg.MaxSessions,
		RequireMfa:         cfg.EnableMFA,
		LoginAttempts:      cfg.LoginAttempts,
		LockoutDuration:    cfg.LockoutDurationSec,
		PasswordMinLength:  cfg.PasswordMinLength,
	}, nil
}

// userInfoToProto converts an AuthUserInfo to a gRPC User message.
func userInfoToProto(u *AuthUserInfo) *User {
	if u == nil {
		return nil
	}
	return &User{
		Id:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		Role:      u.Role,
		Enabled:   u.Enabled,
		CreatedAt: u.CreatedAt,
	}
}

// FormatToken generates a display token identifier (does not expose real tokens).
func FormatToken(token string) string {
	if len(token) <= 8 {
		return fmt.Sprintf("***%s", token)
	}
	return fmt.Sprintf("***%s", token[len(token)-4:])
}
