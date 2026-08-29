// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — gRPC Auth Interceptor
// =========================================================================
//
// Provides authentication interceptors for gRPC server. Extracts bearer
// tokens from the "authorization" gRPC metadata header and validates
// them via the AuthBackend interface.
//
// The AuthService.Login and health check endpoints are exempt from
// authentication (they must be callable without a token).
//
// Fail-closed: if no AuthBackend is configured, all authenticated
// endpoints return codes.Unauthenticated.
// =========================================================================

package grpc

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// authExemptMethods lists gRPC methods that do NOT require authentication.
// These are methods that must be callable before the caller has a token
// (e.g., login) or are infrastructure endpoints (health checks).
var authExemptMethods = map[string]bool{
	"/grpc.AuthService/Login":      true,
	"/grpc.health.v1.Health/Check": true,
	"/grpc.health.v1.Health/Watch": true,
}

// contextKey is a private type for context keys in this package.
type contextKey string

const (
	// ctxKeyUserID stores the authenticated user ID in the context.
	ctxKeyUserID contextKey = "grpc_auth_user_id"
	// ctxKeyToken stores the validated token in the context.
	//nolint:gosec // G101: this is a context key name, not a credential
	ctxKeyToken contextKey = "grpc_auth_token"
)

// unaryAuthInterceptor validates bearer tokens on unary RPCs.
// Requests without a valid token are rejected with codes.Unauthenticated,
// except for methods listed in authExemptMethods.
func unaryAuthInterceptor(logger *slog.Logger, auth AuthBackend) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip auth for exempt methods.
		if authExemptMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// If no auth backend is configured, fail-closed.
		if auth == nil {
			logger.Warn("gRPC auth: no backend configured, denying request",
				"method", info.FullMethod)
			return nil, status.Error(codes.Unauthenticated, "authentication required but no auth backend configured")
		}

		// Extract token from metadata.
		token, err := extractBearerToken(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// Validate token.
		valid, userID, _, err := auth.ValidateToken(ctx, token)
		if err != nil || !valid {
			logger.Warn("gRPC auth: token validation failed",
				"method", info.FullMethod, "error", err)
			return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
		}

		// Add user ID to context for downstream handlers.
		ctx = context.WithValue(ctx, ctxKeyUserID, userID)
		ctx = context.WithValue(ctx, ctxKeyToken, token)

		logger.Debug("gRPC auth: token validated",
			"method", info.FullMethod, "user_id", userID)

		return handler(ctx, req)
	}
}

// streamAuthInterceptor validates bearer tokens on streaming RPCs.
func streamAuthInterceptor(logger *slog.Logger, auth AuthBackend) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip auth for exempt methods.
		if authExemptMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// If no auth backend is configured, fail-closed.
		if auth == nil {
			logger.Warn("gRPC auth: no backend configured, denying stream",
				"method", info.FullMethod)
			return status.Error(codes.Unauthenticated, "authentication required but no auth backend configured")
		}

		// Extract token from metadata.
		token, err := extractBearerToken(ss.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}

		// Validate token.
		valid, userID, _, err := auth.ValidateToken(ss.Context(), token)
		if err != nil || !valid {
			logger.Warn("gRPC auth: stream token validation failed",
				"method", info.FullMethod, "error", err)
			return status.Error(codes.Unauthenticated, "invalid or expired token")
		}

		// Wrap the stream with the user ID in context.
		wrapped := &authStream{ServerStream: ss, ctx: context.WithValue(ss.Context(), ctxKeyUserID, userID)}

		logger.Debug("gRPC auth: stream token validated",
			"method", info.FullMethod, "user_id", userID)

		return handler(srv, wrapped)
	}
}

// extractBearerToken extracts a bearer token from gRPC metadata.
// It looks for the "authorization" header in the format "Bearer <token>".
func extractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no metadata in request")
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", status.Error(codes.Unauthenticated, "no authorization header")
	}

	token := authHeaders[0]
	if strings.HasPrefix(token, "Bearer ") {
		return strings.TrimPrefix(token, "Bearer "), nil
	}
	if strings.HasPrefix(token, "bearer ") {
		return strings.TrimPrefix(token, "bearer "), nil
	}

	// Some gRPC clients send the raw token without the "Bearer" prefix.
	if token != "" {
		return token, nil
	}

	return "", status.Error(codes.Unauthenticated, "empty authorization header")
}

// authStream wraps a gRPC ServerStream to inject an authenticated context.
type authStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the authenticated context.
func (a *authStream) Context() context.Context {
	return a.ctx
}

// UserIDFromContext extracts the authenticated user ID from a gRPC context.
// Returns empty string if not authenticated.
func UserIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyUserID).(string); ok {
		return v
	}
	return ""
}
