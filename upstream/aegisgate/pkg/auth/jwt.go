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
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
)

// JWTAlgorithm represents the JWT signing algorithm
type JWTAlgorithm string

const (
	AlgorithmHS256 JWTAlgorithm = "HS256"
	AlgorithmHS384 JWTAlgorithm = "HS384"
	AlgorithmHS512 JWTAlgorithm = "HS512"
	AlgorithmRS256 JWTAlgorithm = "RS256"
	AlgorithmRS384 JWTAlgorithm = "RS384"
	AlgorithmRS512 JWTAlgorithm = "RS512"
	AlgorithmNone  JWTAlgorithm = "none"
)

// JWTClaims represents the standard JWT claims
type JWTClaims struct {
	Issuer           string                 `json:"iss,omitempty"`
	Subject          string                 `json:"sub,omitempty"`
	Audience         string                 `json:"aud,omitempty"`
	ExpiresAt        int64                  `json:"exp,omitempty"`
	NotBefore        int64                  `json:"nbf,omitempty"`
	IssuedAt         int64                  `json:"iat,omitempty"`
	JWTID            string                 `json:"jti,omitempty"`
	Name             string                 `json:"name,omitempty"`
	Email            string                 `json:"email,omitempty"`
	Role             Role                   `json:"role,omitempty"`
	Permissions      []Permission           `json:"permissions,omitempty"`
	Scopes           []APIKeyScope          `json:"scopes,omitempty"`
	TenantID         string                 `json:"tenant_id,omitempty"`
	SessionID        string                 `json:"session_id,omitempty"`
	DeviceID         string                 `json:"device_id,omitempty"`
	MFAVerified      bool                   `json:"mfa_verified,omitempty"`
	RefreshTokenHash string                 `json:"-"`
	Custom           map[string]interface{} `json:"custom,omitempty"`
}

// TokenPair represents an access token and refresh token pair
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// JWTToken represents a parsed JWT token
type JWTToken struct {
	Claims       *JWTClaims
	RawHeader    string
	RawPayload   string
	RawSignature string
	Signature    []byte
	Valid        bool
	Errors       []error
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Algorithm          JWTAlgorithm
	Secret             []byte
	PrivateKey         *rsa.PrivateKey
	PublicKey          *rsa.PublicKey
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
	Audience           string
	ValidateIssuer     bool
	ValidateAudience   bool
	RequireMFA         bool
	MaxTokensPerUser   int
}

// DefaultJWTConfig returns default JWT configuration
func DefaultJWTConfig() *JWTConfig {
	return &JWTConfig{
		Algorithm:          AlgorithmHS256,
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		Issuer:             "aegisgate",
		Audience:           "aegisgate/api",
		ValidateIssuer:     true,
		ValidateAudience:   true,
		RequireMFA:         false,
		MaxTokensPerUser:   10,
	}
}

// JWTService handles JWT token operations
type JWTService struct {
	config        *JWTConfig
	auditLogger   *opsec.SecureAuditLog
	revokedTokens map[string]*revocationEntry
	revokedMu     sync.RWMutex
	activeTokens  map[string]*TokenPair
	activeMu      sync.RWMutex
}

// revocationEntry tracks revoked tokens
type revocationEntry struct {
	ExpiresAt time.Time
	Reason    string
}

// NewJWTService creates a new JWT service
func NewJWTService(config *JWTConfig, auditLogger *opsec.SecureAuditLog) (*JWTService, error) {
	if config == nil {
		config = DefaultJWTConfig()
	}

	if config.Secret == nil && config.PrivateKey == nil {
		return nil, errors.New("either secret or private key must be provided")
	}

	svc := &JWTService{
		config:        config,
		auditLogger:   auditLogger,
		revokedTokens: make(map[string]*revocationEntry),
		activeTokens:  make(map[string]*TokenPair),
	}

	go svc.cleanupLoop()

	return svc, nil
}

// cleanupLoop periodically cleans up expired revoked tokens
func (s *JWTService) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanup()
	}
}

// cleanup removes expired entries from revocation list
func (s *JWTService) cleanup() {
	now := time.Now()

	s.revokedMu.Lock()
	for jti, entry := range s.revokedTokens {
		if now.After(entry.ExpiresAt) {
			delete(s.revokedTokens, jti)
		}
	}
	s.revokedMu.Unlock()
}

// GenerateTokenPair generates access and refresh tokens for a user
func (s *JWTService) GenerateTokenPair(user *User, customClaims map[string]interface{}) (*TokenPair, error) {
	now := time.Now()

	accessJWTID := generateTokenID()
	refreshJWTID := generateTokenID()

	accessClaims := &JWTClaims{
		Issuer:      s.config.Issuer,
		Subject:     user.ID,
		Audience:    s.config.Audience,
		ExpiresAt:   now.Add(s.config.AccessTokenExpiry).Unix(),
		NotBefore:   now.Unix(),
		IssuedAt:    now.Unix(),
		JWTID:       accessJWTID,
		Name:        user.Name,
		Email:       user.Email,
		Role:        user.Role,
		Permissions: user.Permissions,
		TenantID:    getUserTenantID(user),
		SessionID:   user.SessionID,
		MFAVerified: true,
		Custom:      customClaims,
	}

	accessToken, err := s.signToken(accessClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	refreshClaims := &JWTClaims{
		Issuer:           s.config.Issuer,
		Subject:          user.ID,
		Audience:         s.config.Audience,
		ExpiresAt:        now.Add(s.config.RefreshTokenExpiry).Unix(),
		NotBefore:        now.Unix(),
		IssuedAt:         now.Unix(),
		JWTID:            refreshJWTID,
		MFAVerified:      true,
		RefreshTokenHash: s.hashToken(refreshJWTID),
	}

	refreshToken, err := s.signToken(refreshClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	s.activeMu.Lock()
	s.activeTokens[user.ID] = &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.AccessTokenExpiry.Seconds()),
		ExpiresAt:    now.Add(s.config.AccessTokenExpiry),
	}
	s.activeMu.Unlock()

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.AccessTokenExpiry.Seconds()),
		ExpiresAt:    now.Add(s.config.AccessTokenExpiry),
	}, nil
}

// GenerateAPIToken generates a token for API key authentication
func (s *JWTService) GenerateAPIToken(apiKey *APIKey) (string, error) {
	now := time.Now()
	jwtID := generateTokenID()

	claims := &JWTClaims{
		Issuer:    s.config.Issuer,
		Subject:   apiKey.UserID,
		Audience:  s.config.Audience,
		ExpiresAt: now.Add(s.config.AccessTokenExpiry).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		JWTID:     jwtID,
		Scopes:    apiKey.Scopes,
		Custom: map[string]interface{}{
			"api_key_id":   apiKey.ID,
			"api_key_name": apiKey.Name,
		},
	}

	return s.signToken(claims)
}

// ValidateToken validates a JWT token and returns the claims
func (s *JWTService) ValidateToken(tokenString string) (*JWTToken, error) {
	token, err := s.parseToken(tokenString)
	if err != nil {
		if s.auditLogger != nil {
			s.auditLogger.LogAuditWithLevel(opsec.AuditLevelWarning, "JWT token validation failed - parse error",
				map[string]interface{}{"error": err.Error()})
		}
		return nil, fmt.Errorf("invalid token format: %w", err)
	}

	s.revokedMu.RLock()
	if entry, exists := s.revokedTokens[token.Claims.JWTID]; exists {
		s.revokedMu.RUnlock()
		if s.auditLogger != nil {
			s.auditLogger.LogAuditWithLevel(opsec.AuditLevelWarning, "JWT token validation failed - token revoked",
				map[string]interface{}{"jti": token.Claims.JWTID, "reason": entry.Reason})
		}
		return nil, errors.New("token has been revoked")
	}
	s.revokedMu.RUnlock()

	if err := s.verifySignature(token); err != nil {
		if s.auditLogger != nil {
			s.auditLogger.LogAuditWithLevel(opsec.AuditLevelWarning, "JWT token validation failed - invalid signature",
				map[string]interface{}{"error": err.Error()})
		}
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	if err := s.validateClaims(token.Claims); err != nil {
		if s.auditLogger != nil {
			s.auditLogger.LogAuditWithLevel(opsec.AuditLevelWarning, "JWT token validation failed - invalid claims",
				map[string]interface{}{"error": err.Error()})
		}
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	token.Valid = true
	return token, nil
}

// RefreshTokenPair refreshes an access token using a refresh token
func (s *JWTService) RefreshTokenPair(refreshTokenString string) (*TokenPair, error) {
	token, err := s.ValidateToken(refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if token.Claims.RefreshTokenHash == "" {
		return nil, errors.New("not a refresh token")
	}

	userID := token.Claims.Subject

	s.activeMu.RLock()
	pair, exists := s.activeTokens[userID]
	s.activeMu.RUnlock()

	if !exists || pair.RefreshToken != refreshTokenString {
		return nil, errors.New("refresh token no longer valid")
	}

	user := &User{
		ID:            userID,
		Email:         token.Claims.Email,
		Name:          token.Claims.Name,
		Role:          token.Claims.Role,
		Authenticated: true,
	}

	return s.GenerateTokenPair(user, token.Claims.Custom)
}

// RevokeToken revokes a token
func (s *JWTService) RevokeToken(tokenString, reason string) error {
	token, err := s.parseToken(tokenString)
	if err != nil {
		return err
	}

	jti := token.Claims.JWTID
	expiresAt := time.Unix(token.Claims.ExpiresAt, 0)

	s.revokedMu.Lock()
	s.revokedTokens[jti] = &revocationEntry{
		ExpiresAt: expiresAt,
		Reason:    reason,
	}
	s.revokedMu.Unlock()

	if token.Claims.RefreshTokenHash != "" {
		s.activeMu.Lock()
		delete(s.activeTokens, token.Claims.Subject)
		s.activeMu.Unlock()
	}

	return nil
}

// RevokeAllUserTokens revokes all tokens for a user
func (s *JWTService) RevokeAllUserTokens(userID, reason string) error {
	s.activeMu.Lock()
	pair, exists := s.activeTokens[userID]
	if exists {
		s.revokedMu.Lock()

		accessToken, _ := s.parseToken(pair.AccessToken)
		if accessToken != nil {
			s.revokedTokens[accessToken.Claims.JWTID] = &revocationEntry{
				ExpiresAt: time.Unix(accessToken.Claims.ExpiresAt, 0),
				Reason:    reason,
			}
		}

		refreshToken, _ := s.parseToken(pair.RefreshToken)
		if refreshToken != nil {
			s.revokedTokens[refreshToken.Claims.JWTID] = &revocationEntry{
				ExpiresAt: time.Unix(refreshToken.Claims.ExpiresAt, 0),
				Reason:    reason,
			}
		}

		s.revokedMu.Unlock()
		delete(s.activeTokens, userID)
	}
	s.activeMu.Unlock()

	return nil
}

// GetActiveTokenInfo returns information about an active token
func (s *JWTService) GetActiveTokenInfo(userID string) (*TokenPair, bool) {
	s.activeMu.RLock()
	defer s.activeMu.RUnlock()

	pair, exists := s.activeTokens[userID]
	return pair, exists
}

// signToken creates a signed JWT token
func (s *JWTService) signToken(claims *JWTClaims) (string, error) {
	header := JWTHeader{
		Algorithm: string(s.config.Algorithm),
		Type:      "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signature, err := s.sign([]byte(headerB64 + "." + payloadB64))
	if err != nil {
		return "", err
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(signature)
	return headerB64 + "." + payloadB64 + "." + sigB64, nil
}

// parseToken parses a JWT token string
func (s *JWTService) parseToken(tokenString string) (*JWTToken, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format: expected 3 parts")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &JWTToken{
		Claims:       &claims,
		RawHeader:    parts[0],
		RawPayload:   parts[1],
		RawSignature: parts[2],
		Signature:    signature,
	}, nil
}

// sign signs data using the configured algorithm
func (s *JWTService) sign(data []byte) ([]byte, error) {
	switch s.config.Algorithm {
	case AlgorithmHS256, AlgorithmHS384, AlgorithmHS512:
		return s.hmacSHA(data)
	case AlgorithmRS256, AlgorithmRS384, AlgorithmRS512:
		if s.config.PrivateKey == nil {
			return nil, errors.New("RSA private key not configured")
		}
		hash := sha256.Sum256(data)
		return rsa.SignPKCS1v15(nil, s.config.PrivateKey, 0, hash[:])
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", s.config.Algorithm)
	}
}

// verifySignature verifies the token signature
func (s *JWTService) verifySignature(token *JWTToken) error {
	data := token.RawHeader + "." + token.RawPayload

	switch s.config.Algorithm {
	case AlgorithmHS256, AlgorithmHS384, AlgorithmHS512:
		if s.config.Secret == nil {
			return errors.New("secret not configured")
		}
		expectedSig, err := s.sign([]byte(data))
		if err != nil {
			return err
		}
		if string(expectedSig) != string(token.Signature) {
			return errors.New("signature mismatch")
		}
		return nil
	case AlgorithmRS256, AlgorithmRS384, AlgorithmRS512:
		if s.config.PublicKey == nil {
			return errors.New("RSA public key not configured")
		}
		hash := sha256.Sum256([]byte(data))
		return rsa.VerifyPKCS1v15(s.config.PublicKey, 0, hash[:], token.Signature)
	default:
		return fmt.Errorf("unsupported algorithm: %s", s.config.Algorithm)
	}
}

// validateClaims validates the token claims
func (s *JWTService) validateClaims(claims *JWTClaims) error {
	now := time.Now().Unix()

	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return errors.New("token has expired")
	}

	if claims.NotBefore > 0 && now < claims.NotBefore {
		return errors.New("token not yet valid")
	}

	if s.config.ValidateIssuer && claims.Issuer != s.config.Issuer {
		return fmt.Errorf("invalid issuer: expected %s, got %s", s.config.Issuer, claims.Issuer)
	}

	if s.config.ValidateAudience && claims.Audience != s.config.Audience {
		return fmt.Errorf("invalid audience: expected %s, got %s", s.config.Audience, claims.Audience)
	}

	if s.config.RequireMFA && !claims.MFAVerified {
		return errors.New("MFA verification required")
	}

	return nil
}

// hmacSHA creates an HMAC signature
func (s *JWTService) hmacSHA(data []byte) ([]byte, error) {
	h := hmac.New(sha256.New, s.config.Secret)
	h.Write(data)
	return h.Sum(nil), nil
}

// hashToken creates a hash of a token for storage
func (s *JWTService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// JWTHeader represents the JWT header
type JWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// generateTokenID generates a unique token ID
func generateTokenID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("tok_%x", bytes)
}

// getUserTenantID extracts tenant ID from user
func getUserTenantID(user *User) string {
	if user.Attributes == nil {
		return ""
	}
	if tid, ok := user.Attributes["tenant_id"].(string); ok {
		return tid
	}
	return ""
}

// JWTMiddleware creates middleware for JWT authentication
func JWTMiddleware(jwtService *JWTService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token, err := jwtService.ValidateToken(parts[1])
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		user := &User{
			ID:            token.Claims.Subject,
			Name:          token.Claims.Name,
			Email:         token.Claims.Email,
			Role:          token.Claims.Role,
			Permissions:   token.Claims.Permissions,
			Authenticated: true,
		}

		ctx := context.WithValue(r.Context(), "user", user)
		ctx = context.WithValue(ctx, "claims", token.Claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserFromContext retrieves the user from the request context
func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value("user").(*User)
	return user, ok
}

// GetClaimsFromContext retrieves the JWT claims from the request context
func GetClaimsFromContext(ctx context.Context) (*JWTClaims, bool) {
	claims, ok := ctx.Value("claims").(*JWTClaims)
	return claims, ok
}

// RequireScope creates middleware that requires specific scopes
func RequireScope(jwtService *JWTService, scopes ...APIKeyScope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaimsFromContext(r.Context())
			if !ok {
				http.Error(w, "No token claims found", http.StatusUnauthorized)
				return
			}

			if claims.Role == RoleAdmin {
				next.ServeHTTP(w, r)
				return
			}

			for _, requiredScope := range scopes {
				if !HasScope(claims.Scopes, requiredScope) {
					http.Error(w, "Insufficient permissions", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole creates middleware that requires specific roles
func RequireRole(roles ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaimsFromContext(r.Context())
			if !ok {
				http.Error(w, "No token claims found", http.StatusUnauthorized)
				return
			}

			for _, requiredRole := range roles {
				if claims.Role == requiredRole {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Insufficient role privileges", http.StatusForbidden)
			return
		})
	}
}
