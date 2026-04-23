// =========================================================================
// AegisGate Security Platform — Authentication Middleware
// =========================================================================
// Provides JWT and API token authentication for dashboard API endpoints.
// Two-tier auth: Bearer JWT for user sessions, X-API-Token for service auth.
// =========================================================================

package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/golang-jwt/jwt/v5"
)

// Context keys for request-scoped auth data
type contextKey string

const (
	ContextKeyUserID      contextKey = "auth_user_id"
	ContextKeyTier        contextKey = "auth_tier"
	ContextKeyAuthType    contextKey = "auth_type"
	ContextKeyUserRole    contextKey = "auth_user_role"
	ContextKeyPermissions contextKey = "auth_permissions"
	AuthTypeJWT           string     = "jwt"
	AuthTypeAPIToken      string     = "api_token"
)

// Config holds authentication configuration
type Config struct {
	JWTSigningKey    []byte
	APIAuthToken     string
	TokenExpiryHours int
	RequireAuth      bool
}

// DefaultConfig returns development-safe config (RequireAuth=false)
func DefaultConfig() *Config {
	return &Config{
		JWTSigningKey:    []byte("dev-key-change-in-production"),
		APIAuthToken:     "dev-token-change-in-production",
		TokenExpiryHours: 24,
		RequireAuth:      false, // Default to false for backward compatibility
	}
}

// ConfigFromEnv creates config from environment variables
func ConfigFromEnv() *Config {
	cfg := DefaultConfig()

	if key := os.Getenv("JWT_SIGNING_KEY"); key != "" {
		cfg.JWTSigningKey = []byte(key)
	}
	if token := os.Getenv("API_AUTH_TOKEN"); token != "" {
		cfg.APIAuthToken = token
	}
	if strings.ToLower(os.Getenv("REQUIRE_AUTH")) == "true" {
		cfg.RequireAuth = true
	}

	return cfg
}

// Claims represents JWT claims
type Claims struct {
	UserID string `json:"user_id"`
	Tier   string `json:"tier"`
	jwt.RegisteredClaims
}

// Middleware provides HTTP auth middleware
type Middleware struct {
	config *Config
}

// NewMiddleware creates auth middleware
func NewMiddleware(cfg *Config) *Middleware {
	return &Middleware{config: cfg}
}

// RequireAuth wraps handlers requiring authentication
func (m *Middleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !m.config.RequireAuth {
			// Auth not required, inject dev context with viewer role
			ctx := context.WithValue(r.Context(), ContextKeyUserID, "dev-user")
			ctx = context.WithValue(ctx, ContextKeyTier, "community")
			ctx = context.WithValue(ctx, ContextKeyAuthType, "none")
			ctx = SetUserRole(ctx, rbac.UserRoleViewer)
			ctx = SetPermissions(ctx, rbac.GetPermissionsForUserRole(rbac.UserRoleViewer))
			next(w, r.WithContext(ctx))
			return
		}

		// Extract and validate auth header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.unauthorized(w, "missing authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			m.unauthorized(w, "invalid authorization header format")
			return
		}

		scheme := strings.ToLower(parts[0])
		token := parts[1]

		switch scheme {
		case "bearer":
			m.handleJWT(w, r, token, next)
		case "token":
			m.handleAPIToken(w, r, token, next)
		default:
			m.unauthorized(w, "unsupported authorization scheme")
		}
	}
}

// handleJWT validates JWT tokens
func (m *Middleware) handleJWT(w http.ResponseWriter, r *http.Request, tokenString string, next http.HandlerFunc) {
	// Decode base64 if it's base64 encoded (handles env var encoding)
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenString)
	if err != nil {
		tokenBytes = []byte(tokenString) // Not base64, use as-is
	}

	token, err := jwt.ParseWithClaims(string(tokenBytes), &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.config.JWTSigningKey, nil
	})

	if err != nil || !token.Valid {
		m.unauthorized(w, "invalid or expired token")
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		m.unauthorized(w, "invalid token claims")
		return
	}

	ctx := context.WithValue(r.Context(), ContextKeyUserID, claims.UserID)
	ctx = context.WithValue(ctx, ContextKeyTier, claims.Tier)
	ctx = context.WithValue(ctx, ContextKeyAuthType, AuthTypeJWT)
	
	// Set RBAC role and permissions from JWT claims
	userRole := rbac.ParseUserRole(claims.Tier)
	ctx = SetUserRole(ctx, userRole)
	ctx = SetPermissions(ctx, rbac.GetPermissionsForUserRole(userRole))
	
	next(w, r.WithContext(ctx))
}

// handleAPIToken validates static API tokens
func (m *Middleware) handleAPIToken(w http.ResponseWriter, r *http.Request, token string, next http.HandlerFunc) {
	// Use constant-time comparison to prevent timing attacks
	expectedToken := m.config.APIAuthToken

	// Try base64 decoding in case token is base64 encoded
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err == nil {
		token = string(decoded)
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
		m.unauthorized(w, "invalid api token")
		return
	}

	ctx := context.WithValue(r.Context(), ContextKeyUserID, "api-service")
	ctx = context.WithValue(ctx, ContextKeyTier, "enterprise")
	ctx = context.WithValue(ctx, ContextKeyAuthType, AuthTypeAPIToken)
	
	// API tokens get admin role with full permissions
	ctx = SetUserRole(ctx, rbac.UserRoleAdmin)
	ctx = SetPermissions(ctx, rbac.GetPermissionsForUserRole(rbac.UserRoleAdmin))
	
	next(w, r.WithContext(ctx))
}

// unauthorized returns 401 response
func (m *Middleware) unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer, Token`)
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"error":"unauthorized","message":"%s"}`, message)
}

// GenerateToken creates a new JWT token for a user
func (m *Middleware) GenerateToken(userID, tier string) (string, error) {
	claims := Claims{
		UserID: userID,
		Tier:   tier,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(m.config.TokenExpiryHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "aegisgate-platform",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.config.JWTSigningKey)
}

// GetUserID retrieves user ID from context
func GetUserID(ctx context.Context) string {
	if v := ctx.Value(ContextKeyUserID); v != nil {
		return v.(string)
	}
	return ""
}

// GetTier retrieves tier from context
func GetTier(ctx context.Context) string {
	if v := ctx.Value(ContextKeyTier); v != nil {
		return v.(string)
	}
	return "community"
}

// GetAuthType retrieves auth type from context
func GetAuthType(ctx context.Context) string {
	if v := ctx.Value(ContextKeyAuthType); v != nil {
		return v.(string)
	}
	return ""
}

// ReadOnlyMiddleware returns middleware for read-only endpoints (GET/HEAD)
func (m *Middleware) ReadOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			// Read operations allowed
			next(w, r)
		default:
			m.unauthorized(w, "write operations require authentication")
		}
	}
}

// AdminOnly allows only admin/enterprise tier users
func (m *Middleware) AdminOnly(next http.HandlerFunc) http.HandlerFunc {
	return m.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		tier := GetTier(r.Context())
		if tier != "enterprise" && tier != "professional" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"error":"forbidden","message":"admin access required"}`)
			return
		}
		next(w, r)
	})
}

// RequireRole wraps handlers requiring a minimum user role
func (m *Middleware) RequireRole(required rbac.UserRole, next http.HandlerFunc) http.HandlerFunc {
	return m.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		userRole := GetUserRole(r.Context())
		if userRole == "" {
			// Default to viewer if no role set
			userRole = rbac.UserRoleViewer
		}
		
		if !userRole.AtLeast(required) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"error":"forbidden","message":"role %s required, got %s", "required": "%s", "current": "%s"}`, required, userRole, required, userRole)
			return
		}
		next(w, r)
	})
}

// RequirePermission wraps handlers requiring a specific RBAC permission
func (m *Middleware) RequirePermission(perm rbac.Permission, next http.HandlerFunc) http.HandlerFunc {
	return m.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		permissions := GetPermissions(r.Context())
		if permissions == nil {
			// Load default permissions for user's role
			userRole := GetUserRole(r.Context())
			if userRole == "" {
				userRole = rbac.UserRoleViewer
			}
			permissions = rbac.GetPermissionsForUserRole(userRole)
		}
		
		hasPerm := false
		for _, p := range permissions {
			if p == perm {
				hasPerm = true
				break
			}
			// Check resource wildcard
			if p.Resource == perm.Resource && p.Action == "*" {
				hasPerm = true
				break
			}
			// Check action wildcard
			if p.Resource == "*" && p.Action == perm.Action {
				hasPerm = true
				break
			}
			// Check full wildcard
			if p.Resource == "*" && p.Action == "*" {
				hasPerm = true
				break
			}
		}
		
		if !hasPerm {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"error":"forbidden","message":"permission %s required"}`, perm.String())
			return
		}
		next(w, r)
	})
}

// GetUserRole retrieves user role from context
func GetUserRole(ctx context.Context) rbac.UserRole {
	if v := ctx.Value(ContextKeyUserRole); v != nil {
		if role, ok := v.(rbac.UserRole); ok {
			return role
		}
	}
	return ""
}

// GetPermissions retrieves permissions from context
func GetPermissions(ctx context.Context) []rbac.Permission {
	if v := ctx.Value(ContextKeyPermissions); v != nil {
		if perms, ok := v.([]rbac.Permission); ok {
			return perms
		}
	}
	return nil
}

// SetUserRole sets user role in context
func SetUserRole(ctx context.Context, role rbac.UserRole) context.Context {
	return context.WithValue(ctx, ContextKeyUserRole, role)
}

// SetPermissions sets permissions in context
func SetPermissions(ctx context.Context, perms []rbac.Permission) context.Context {
	return context.WithValue(ctx, ContextKeyPermissions, perms)
}
