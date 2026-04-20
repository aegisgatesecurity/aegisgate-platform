// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
)

// APIKeyScope defines the scope of access for an API key
type APIKeyScope string

const (
	ScopeRead     APIKeyScope = "read"
	ScopeWrite    APIKeyScope = "write"
	ScopeAdmin    APIKeyScope = "admin"
	ScopeMetrics  APIKeyScope = "metrics:read"
	ScopeProxy    APIKeyScope = "proxy:manage"
	ScopeReports  APIKeyScope = "reports:read"
	ScopePolicies APIKeyScope = "policies:manage"
	ScopeUsers    APIKeyScope = "users:manage"
	ScopeCerts    APIKeyScope = "certificates:manage"
	ScopeWebhooks APIKeyScope = "webhooks:manage"
)

// ValidScopes returns all valid API key scopes
func ValidScopes() []APIKeyScope {
	return []APIKeyScope{
		ScopeRead, ScopeWrite, ScopeAdmin, ScopeMetrics,
		ScopeProxy, ScopeReports, ScopePolicies, ScopeUsers,
		ScopeCerts, ScopeWebhooks,
	}
}

// HasScope checks if the scope list contains a specific scope
func HasScope(scopes []APIKeyScope, target APIKeyScope) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	KeyPrefix      string                 `json:"key_prefix"` // First 8 chars for identification
	KeyHash        string                 `json:"-"`          // Never exposed
	UserID         string                 `json:"user_id"`
	Scopes         []APIKeyScope          `json:"scopes"`
	ExpiresAt      *time.Time             `json:"expires_at,omitempty"`
	LastUsedAt     *time.Time             `json:"last_used_at,omitempty"`
	RateLimit      int                    `json:"rate_limit"` // Requests per minute
	RateLimitCurr  int                    `json:"-"`
	RateLimitReset time.Time              `json:"-"`
	Active         bool                   `json:"active"`
	Revoked        bool                   `json:"revoked"`
	RevokedAt      *time.Time             `json:"revoked_at,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// IsExpired checks if the API key has expired
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// IsValid checks if the API key is valid for use
func (k *APIKey) IsValid() bool {
	return k.Active && !k.Revoked && !k.IsExpired()
}

// CanAccess checks if the key has the required scope
func (k *APIKey) CanAccess(scope APIKeyScope) bool {
	if !k.IsValid() {
		return false
	}

	// Admin has access to everything
	if HasScope(k.Scopes, ScopeAdmin) {
		return true
	}

	return HasScope(k.Scopes, scope)
}

// APIKeyRequest represents a request to create an API key
type APIKeyRequest struct {
	Name      string                 `json:"name"`
	Scopes    []APIKeyScope          `json:"scopes"`
	ExpiresIn time.Duration          `json:"expires_in,omitempty"` // 0 = no expiration
	RateLimit int                    `json:"rate_limit,omitempty"` // 0 = use default
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// APIKeyResponse represents the response when creating an API key
// The actual key is only shown once at creation time
type APIKeyResponse struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Key       string                 `json:"key,omitempty"` // Only present on creation
	KeyPrefix string                 `json:"key_prefix"`
	Scopes    []APIKeyScope          `json:"scopes"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	RateLimit int                    `json:"rate_limit"`
	CreatedAt time.Time              `json:"created_at"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// MarshalJSON implements custom JSON marshaling to hide sensitive data
func (k *APIKey) MarshalJSON() ([]byte, error) {
	type Alias APIKey
	return json.Marshal(&struct {
		*Alias
		KeyHash string `json:"-"`
	}{
		Alias: (*Alias)(k),
	})
}

// APIKeyService handles API key management
type APIKeyService struct {
	db               *sql.DB
	auditLogger      *opsec.SecureAuditLog
	keyPrefix        string
	maxKeysPerUser   int
	defaultRateLimit int
	keys             map[string]*APIKey // In-memory cache for validation
	keysMu           sync.RWMutex
}

// NewAPIKeyService creates a new API key service
func NewAPIKeyService(db *sql.DB, auditLogger *opsec.SecureAuditLog, opts ...APIKeyOption) (*APIKeyService, error) {
	svc := &APIKeyService{
		db:               db,
		auditLogger:      auditLogger,
		keyPrefix:        "sk_live_",
		maxKeysPerUser:   10,
		defaultRateLimit: 60,
		keys:             make(map[string]*APIKey),
	}

	for _, opt := range opts {
		opt(svc)
	}

	// Initialize schema if needed
	if err := svc.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize API key schema: %w", err)
	}

	// Load keys into memory
	if err := svc.loadKeys(); err != nil {
		return nil, fmt.Errorf("failed to load API keys: %w", err)
	}

	return svc, nil
}

// APIKeyOption configures the API key service
type APIKeyOption func(*APIKeyService)

// WithKeyPrefix sets the key prefix
func WithKeyPrefix(prefix string) APIKeyOption {
	return func(s *APIKeyService) {
		s.keyPrefix = prefix
	}
}

// WithMaxKeysPerUser sets the maximum keys per user
func WithMaxKeysPerUser(max int) APIKeyOption {
	return func(s *APIKeyService) {
		s.maxKeysPerUser = max
	}
}

// WithDefaultRateLimit sets the default rate limit
func WithDefaultRateLimit(limit int) APIKeyOption {
	return func(s *APIKeyService) {
		s.defaultRateLimit = limit
	}
}

// initSchema creates the database schema for API keys
func (s *APIKeyService) initSchema() error {
	if s.db == nil {
		return nil // In-memory only mode
	}

	schema := `
	CREATE TABLE IF NOT EXISTS api_keys (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		key_hash TEXT NOT NULL,
		user_id TEXT NOT NULL,
		scopes TEXT NOT NULL,
		expires_at TIMESTAMP,
		last_used_at TIMESTAMP,
		rate_limit INTEGER DEFAULT 60,
		active BOOLEAN DEFAULT true,
		revoked BOOLEAN DEFAULT false,
		revoked_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL,
		metadata TEXT,
		UNIQUE(user_id, name)
	);
	CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
	CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
	CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(active);
	`

	_, err := s.db.Exec(schema)
	return err
}

// loadKeys loads all active keys into memory
func (s *APIKeyService) loadKeys() error {
	if s.db == nil {
		return nil
	}

	rows, err := s.db.Query(`
		SELECT id, name, key_hash, user_id, scopes, expires_at, last_used_at,
		       rate_limit, active, revoked, revoked_at, created_at, updated_at, metadata
		FROM api_keys
		WHERE active = true AND revoked = false
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var key APIKey
		var scopesJSON string
		var metadataJSON sql.NullString
		var expiresAt, lastUsedAt, revokedAt sql.NullTime

		err := rows.Scan(
			&key.ID, &key.Name, &key.KeyHash, &key.UserID, &scopesJSON,
			&expiresAt, &lastUsedAt, &key.RateLimit, &key.Active, &key.Revoked,
			&revokedAt, &key.CreatedAt, &key.UpdatedAt, &metadataJSON,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(scopesJSON), &key.Scopes)

		if expiresAt.Valid {
			key.ExpiresAt = &expiresAt.Time
		}
		if lastUsedAt.Valid {
			key.LastUsedAt = &lastUsedAt.Time
		}
		if revokedAt.Valid {
			key.RevokedAt = &revokedAt.Time
		}
		if metadataJSON.Valid {
			json.Unmarshal([]byte(metadataJSON.String), &key.Metadata)
		}

		s.keys[key.KeyHash] = &key
	}

	return nil
}

// GenerateKey generates a new API key
func (s *APIKeyService) GenerateKey(req *APIKeyRequest) (*APIKeyResponse, error) {
	if req.Name == "" {
		return nil, errors.New("key name is required")
	}

	if len(req.Scopes) == 0 {
		return nil, errors.New("at least one scope is required")
	}

	// Validate scopes
	for _, scope := range req.Scopes {
		if !isValidScope(scope) {
			return nil, fmt.Errorf("invalid scope: %s", scope)
		}
	}

	// Check max keys per user (if user specified)
	if req.Metadata != nil {
		if userID, ok := req.Metadata["user_id"].(string); ok {
			count, err := s.countKeysForUser(userID)
			if err != nil {
				return nil, err
			}
			if count >= s.maxKeysPerUser {
				return nil, fmt.Errorf("maximum number of API keys (%d) reached", s.maxKeysPerUser)
			}
		}
	}

	// Generate cryptographically secure random key (32 bytes = 256 bits)
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create full key with prefix
	fullKey := s.keyPrefix + base64.URLEncoding.EncodeToString(keyBytes)
	keyHash := s.hashKey(fullKey)

	// Generate key ID
	id := generateID()

	// Set expiration
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		expTime := time.Now().Add(req.ExpiresIn)
		expiresAt = &expTime
	}

	// Set rate limit
	rateLimit := req.RateLimit
	if rateLimit <= 0 {
		rateLimit = s.defaultRateLimit
	}

	// Create API key
	apiKey := &APIKey{
		ID:        id,
		Name:      req.Name,
		KeyPrefix: fullKey[:len(s.keyPrefix)+8],
		KeyHash:   keyHash,
		UserID:    getUserIDFromMetadata(req.Metadata),
		Scopes:    req.Scopes,
		ExpiresAt: expiresAt,
		RateLimit: rateLimit,
		Active:    true,
		Revoked:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  req.Metadata,
	}

	// Store in database
	if err := s.storeKey(apiKey); err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	// Add to memory cache
	s.keysMu.Lock()
	s.keys[keyHash] = apiKey
	s.keysMu.Unlock()

	// Audit log
	if s.auditLogger != nil {
		s.auditLogger.LogAuditWithLevel(
			opsec.AuditLevelInfo,
			"API key created",
			map[string]interface{}{
				"key_id":     apiKey.ID,
				"key_name":   apiKey.Name,
				"key_prefix": apiKey.KeyPrefix,
				"user_id":    apiKey.UserID,
				"scopes":     apiKey.Scopes,
				"expires_at": apiKey.ExpiresAt,
			},
		)
	}

	return &APIKeyResponse{
		ID:        apiKey.ID,
		Name:      apiKey.Name,
		Key:       fullKey, // Only returned once!
		KeyPrefix: apiKey.KeyPrefix,
		Scopes:    apiKey.Scopes,
		ExpiresAt: apiKey.ExpiresAt,
		RateLimit: apiKey.RateLimit,
		CreatedAt: apiKey.CreatedAt,
		Metadata:  apiKey.Metadata,
	}, nil
}

// hashKey creates a SHA-256 hash of the key
func (s *APIKeyService) hashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// ValidateKey validates an API key and returns the associated key object
func (s *APIKeyService) ValidateKey(fullKey string) (*APIKey, error) {
	// Verify key prefix
	if !strings.HasPrefix(fullKey, s.keyPrefix) {
		return nil, errors.New("invalid key format")
	}

	keyHash := s.hashKey(fullKey)

	s.keysMu.RLock()
	apiKey, exists := s.keys[keyHash]
	s.keysMu.RUnlock()

	if !exists {
		// Try database lookup
		key, err := s.getKeyByHash(keyHash)
		if err != nil {
			return nil, errors.New("invalid API key")
		}
		apiKey = key
	}

	if apiKey == nil {
		return nil, errors.New("invalid API key")
	}

	// Check if revoked
	if apiKey.Revoked {
		return nil, errors.New("API key has been revoked")
	}

	// Check if active
	if !apiKey.Active {
		return nil, errors.New("API key is not active")
	}

	// Check expiration
	if apiKey.IsExpired() {
		return nil, errors.New("API key has expired")
	}

	// Check rate limit
	if !s.checkRateLimit(apiKey) {
		return nil, errors.New("rate limit exceeded")
	}

	// Update last used
	if err := s.updateLastUsed(apiKey.ID); err != nil {
		// Log but don't fail
		s.auditLogger.LogAuditWithLevel(
			opsec.AuditLevelWarning,
			"Failed to update last used timestamp",
			map[string]interface{}{"key_id": apiKey.ID, "error": err.Error()},
		)
	}

	return apiKey, nil
}

// checkRateLimit checks and updates rate limit for a key
func (s *APIKeyService) checkRateLimit(key *APIKey) bool {
	now := time.Now()

	// Reset if window expired
	if now.After(key.RateLimitReset) {
		key.RateLimitCurr = 0
		key.RateLimitReset = now.Add(time.Minute)
	}

	// Check limit
	if key.RateLimitCurr >= key.RateLimit {
		return false
	}

	key.RateLimitCurr++
	return true
}

// Get gets an API key by ID (without the actual key)
func (s *APIKeyService) Get(id string) (*APIKey, error) {
	return s.getKeyByID(id)
}

// List lists all API keys for a user
func (s *APIKeyService) List(userID string) ([]*APIKey, error) {
	return s.getKeysForUser(userID)
}

// Revoke revokes an API key
func (s *APIKeyService) Revoke(id, userID string) error {
	key, err := s.getKeyByID(id)
	if err != nil {
		return err
	}

	// Verify ownership
	if key.UserID != userID {
		return errors.New("unauthorized")
	}

	now := time.Now()
	key.Revoked = true
	key.RevokedAt = &now
	key.Active = false
	key.UpdatedAt = now

	// Update database
	if err := s.markRevoked(id); err != nil {
		return err
	}

	// Remove from memory
	s.keysMu.Lock()
	for hash, k := range s.keys {
		if k.ID == id {
			delete(s.keys, hash)
		}
	}
	s.keysMu.Unlock()

	// Audit log
	if s.auditLogger != nil {
		s.auditLogger.LogAuditWithLevel(
			opsec.AuditLevelInfo,
			"API key revoked",
			map[string]interface{}{
				"key_id":   key.ID,
				"key_name": key.Name,
				"user_id":  userID,
			},
		)
	}

	return nil
}

// HasScope checks if a key has a specific scope
func (s *APIKeyService) HasScope(key *APIKey, scope APIKeyScope) bool {
	return key.CanAccess(scope)
}

// Database operations (placeholder implementations - implement with actual DB)

// storeKey stores a new API key in the database
func (s *APIKeyService) storeKey(key *APIKey) error {
	if s.db == nil {
		return nil
	}

	scopesJSON, _ := json.Marshal(key.Scopes)
	metadataJSON, _ := json.Marshal(key.Metadata)

	_, err := s.db.Exec(`
		INSERT INTO api_keys (id, name, key_hash, user_id, scopes, expires_at,
		                     rate_limit, active, revoked, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, key.ID, key.Name, key.KeyHash, key.UserID, scopesJSON, key.ExpiresAt,
		key.RateLimit, key.Active, key.Revoked, key.CreatedAt, key.UpdatedAt, metadataJSON)

	return err
}

// getKeyByHash retrieves a key by its hash
func (s *APIKeyService) getKeyByHash(hash string) (*APIKey, error) {
	if s.db == nil {
		return nil, nil
	}

	var key APIKey
	var scopesJSON string
	var metadataJSON sql.NullString
	var expiresAt, lastUsedAt, revokedAt sql.NullTime

	err := s.db.QueryRow(`
		SELECT id, name, key_hash, user_id, scopes, expires_at, last_used_at,
		       rate_limit, active, revoked, revoked_at, created_at, updated_at, metadata
		FROM api_keys WHERE key_hash = $1
	`, hash).Scan(
		&key.ID, &key.Name, &key.KeyHash, &key.UserID, &scopesJSON,
		&expiresAt, &lastUsedAt, &key.RateLimit, &key.Active, &key.Revoked,
		&revokedAt, &key.CreatedAt, &key.UpdatedAt, &metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(scopesJSON), &key.Scopes)
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	if revokedAt.Valid {
		key.RevokedAt = &revokedAt.Time
	}
	if metadataJSON.Valid {
		json.Unmarshal([]byte(metadataJSON.String), &key.Metadata)
	}

	return &key, nil
}

// getKeyByID retrieves a key by its ID
func (s *APIKeyService) getKeyByID(id string) (*APIKey, error) {
	// Check memory cache first
	s.keysMu.RLock()
	for _, key := range s.keys {
		if key.ID == id {
			s.keysMu.RUnlock()
			return key, nil
		}
	}
	s.keysMu.RUnlock()

	if s.db == nil {
		return nil, nil
	}

	var key APIKey
	var scopesJSON string
	var metadataJSON sql.NullString
	var expiresAt, lastUsedAt, revokedAt sql.NullTime

	err := s.db.QueryRow(`
		SELECT id, name, key_hash, user_id, scopes, expires_at, last_used_at,
		       rate_limit, active, revoked, revoked_at, created_at, updated_at, metadata
		FROM api_keys WHERE id = $1
	`, id).Scan(
		&key.ID, &key.Name, &key.KeyHash, &key.UserID, &scopesJSON,
		&expiresAt, &lastUsedAt, &key.RateLimit, &key.Active, &key.Revoked,
		&revokedAt, &key.CreatedAt, &key.UpdatedAt, &metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("key not found")
	}
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(scopesJSON), &key.Scopes)
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	if revokedAt.Valid {
		key.RevokedAt = &revokedAt.Time
	}
	if metadataJSON.Valid {
		json.Unmarshal([]byte(metadataJSON.String), &key.Metadata)
	}

	key.KeyPrefix = s.keyPrefix + "########" // Placeholder

	return &key, nil
}

// getKeysForUser retrieves all keys for a user
func (s *APIKeyService) getKeysForUser(userID string) ([]*APIKey, error) {
	if s.db == nil {
		return nil, nil
	}

	rows, err := s.db.Query(`
		SELECT id, name, key_hash, user_id, scopes, expires_at, last_used_at,
		       rate_limit, active, revoked, revoked_at, created_at, updated_at, metadata
		FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*APIKey
	for rows.Next() {
		var key APIKey
		var scopesJSON string
		var metadataJSON sql.NullString
		var expiresAt, lastUsedAt, revokedAt sql.NullTime

		err := rows.Scan(
			&key.ID, &key.Name, &key.KeyHash, &key.UserID, &scopesJSON,
			&expiresAt, &lastUsedAt, &key.RateLimit, &key.Active, &key.Revoked,
			&revokedAt, &key.CreatedAt, &key.UpdatedAt, &metadataJSON,
		)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(scopesJSON), &key.Scopes)
		if expiresAt.Valid {
			key.ExpiresAt = &expiresAt.Time
		}
		if lastUsedAt.Valid {
			key.LastUsedAt = &lastUsedAt.Time
		}
		if revokedAt.Valid {
			key.RevokedAt = &revokedAt.Time
		}
		if metadataJSON.Valid {
			json.Unmarshal([]byte(metadataJSON.String), &key.Metadata)
		}

		key.KeyPrefix = s.keyPrefix + "########" // Hide actual prefix
		keys = append(keys, &key)
	}

	return keys, nil
}

// updateLastUsed updates the last used timestamp
func (s *APIKeyService) updateLastUsed(id string) error {
	if s.db == nil {
		return nil
	}

	_, err := s.db.Exec(`
		UPDATE api_keys SET last_used_at = $1, updated_at = $1 WHERE id = $2
	`, time.Now(), id)
	return err
}

// markRevoked marks a key as revoked
func (s *APIKeyService) markRevoked(id string) error {
	if s.db == nil {
		return nil
	}

	_, err := s.db.Exec(`
		UPDATE api_keys SET revoked = true, revoked_at = $1, active = false, updated_at = $1
		WHERE id = $2
	`, time.Now(), id)
	return err
}

// countKeysForUser counts keys for a user
func (s *APIKeyService) countKeysForUser(userID string) (int, error) {
	if s.db == nil {
		return 0, nil
	}

	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, userID).Scan(&count)
	return count, err
}

// Helper functions

// generateID generates a unique ID
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("key_%x", bytes)
}

// getUserIDFromMetadata extracts user ID from metadata
func getUserIDFromMetadata(metadata map[string]interface{}) string {
	if metadata == nil {
		return ""
	}
	if uid, ok := metadata["user_id"].(string); ok {
		return uid
	}
	return ""
}

// validateScopes validates a list of scopes
func validateScopes(scopes []APIKeyScope) error {
	for _, scope := range scopes {
		if !isValidScope(scope) {
			return fmt.Errorf("invalid scope: %s", scope)
		}
	}
	return nil
}

// isValidScope checks if a scope is valid
func isValidScope(scope APIKeyScope) bool {
	for _, valid := range ValidScopes() {
		if scope == valid {
			return true
		}
	}
	return false
}

// ConstantTimeCompare performs constant-time comparison to prevent timing attacks
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
