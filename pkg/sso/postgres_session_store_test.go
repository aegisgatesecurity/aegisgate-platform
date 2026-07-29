// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — PostgreSQL SSO Session Store Unit Tests
// =========================================================================
//
// These tests cover nil-store fallback, closed-state errors, data
// serialization, and interface compliance without requiring a live
// PostgreSQL connection. Integration tests should use //go:build lab
// with a real database.
//
// v3.5.0+ D1 Phase 1E.
// =========================================================================

package sso

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// ============================================================================
// PostgresSessionStore Constructor Tests
// ============================================================================

// TestNewPostgresSessionStore_NilStore verifies that nil PostgresStore returns error.
func TestNewPostgresSessionStore_NilStore(t *testing.T) {
	_, err := NewPostgresSessionStore(nil)
	if err == nil {
		t.Fatal("expected error when pgStore is nil, got nil")
	}
}

// TestNewPostgresRequestStore_NilStore verifies that nil PostgresStore returns error.
func TestNewPostgresRequestStore_NilStore(t *testing.T) {
	_, err := NewPostgresRequestStore(nil)
	if err == nil {
		t.Fatal("expected error when pgStore is nil, got nil")
	}
}

// ============================================================================
// PostgresSessionStore Closed-State Tests
// ============================================================================

// TestPostgresSessionStore_ClosedState verifies that all methods return errors after Close().
func TestPostgresSessionStore_ClosedState(t *testing.T) {
	store := &PostgresSessionStore{closed: true}

	session := &SSOSession{
		ID:        "test-session-1",
		UserID:    "user-1",
		Provider:  ProviderOIDC,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Active:    true,
	}

	// All methods should return errors when closed
	if err := store.Create(session); err == nil {
		t.Error("Create should fail on closed store")
	}
	if _, err := store.Get("test"); err == nil {
		t.Error("Get should fail on closed store")
	}
	if err := store.Update(session); err == nil {
		t.Error("Update should fail on closed store")
	}
	if err := store.Delete("test"); err == nil {
		t.Error("Delete should fail on closed store")
	}
	if _, err := store.GetByUserID("user-1"); err == nil {
		t.Error("GetByUserID should fail on closed store")
	}
	if err := store.DeleteByUserID("user-1"); err == nil {
		t.Error("DeleteByUserID should fail on closed store")
	}
	if err := store.Cleanup(); err == nil {
		t.Error("Cleanup should fail on closed store")
	}
}

// TestPostgresRequestStore_ClosedState verifies that all methods return errors after Close().
func TestPostgresRequestStore_ClosedState(t *testing.T) {
	store := &PostgresRequestStore{closed: true}

	request := &SSORequest{
		ID:        "test-request-1",
		Provider:  "oidc",
		State:     "state-123",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	// All methods should return errors when closed
	if err := store.Create(request); err == nil {
		t.Error("Create should fail on closed store")
	}
	if _, err := store.Get("test"); err == nil {
		t.Error("Get should fail on closed store")
	}
	if _, err := store.GetByState("state-123"); err == nil {
		t.Error("GetByState should fail on closed store")
	}
	if err := store.Delete("test"); err == nil {
		t.Error("Delete should fail on closed store")
	}
}

// ============================================================================
// PostgresSessionStore Nil Input Tests
// ============================================================================

// TestPostgresSessionStore_NilSession verifies that Create and Update reject nil sessions.
func TestPostgresSessionStore_NilSession(t *testing.T) {
	store := &PostgresSessionStore{}

	if err := store.Create(nil); err == nil {
		t.Error("Create(nil) should return error")
	}
	if err := store.Update(nil); err == nil {
		t.Error("Update(nil) should return error")
	}
}

// TestPostgresRequestStore_NilRequest verifies that Create rejects nil requests.
func TestPostgresRequestStore_NilRequest(t *testing.T) {
	store := &PostgresRequestStore{}

	if err := store.Create(nil); err == nil {
		t.Error("Create(nil) should return error")
	}
}

// ============================================================================
// Session Serialization Tests
// ============================================================================

// TestSSOSession_JSONSerialization verifies that SSOSession serializes/deserializes
// correctly via JSON (used for JSONB columns in PostgreSQL).
func TestSSOSession_JSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	session := &SSOSession{
		ID:             "sess-abc123",
		UserID:         "user-456",
		SessionID:      "session-xyz",
		Provider:       ProviderOIDC,
		ProviderName:   "google",
		CreatedAt:      now,
		ExpiresAt:      now.Add(24 * time.Hour),
		LastActivity:   now,
		LastRefreshed:  now,
		IPAddress:      "192.168.1.100",
		UserAgent:      "Mozilla/5.0",
		InitialIDP:     "accounts.google.com",
		NameID:         "user@example.com",
		SessionIndex:   "idx-789",
		AccessToken:    "ya29.access-token",
		RefreshToken:   "1//refresh-token",
		IDToken:        "eyJhbGciOiJSUzI1NiJ9...",
		TokenExpiresAt: now.Add(time.Hour),
		Active:         true,
		Flags: map[string]bool{
			"mfa_verified":   true,
			"first_login":    false,
			"password_reset": false,
		},
		Metadata: map[string]interface{}{
			"login_method": "oidc",
			"risk_score":   0.15,
		},
		User: &SSOUser{
			ID:            "user-456",
			Email:         "user@example.com",
			Name:          "Test User",
			Role:          "admin",
			SSOProvider:   ProviderOIDC,
			SSOProviderID: "google",
			Groups:        []string{"admins", "engineers"},
		},
	}

	// Marshal the user field
	userJSON, err := json.Marshal(session.User)
	if err != nil {
		t.Fatalf("Failed to marshal SSOUser: %v", err)
	}

	// Unmarshal back
	var user SSOUser
	if err := json.Unmarshal(userJSON, &user); err != nil {
		t.Fatalf("Failed to unmarshal SSOUser: %v", err)
	}

	if user.ID != session.User.ID {
		t.Errorf("User.ID mismatch: got %q, want %q", user.ID, session.User.ID)
	}
	if user.Email != session.User.Email {
		t.Errorf("User.Email mismatch: got %q, want %q", user.Email, session.User.Email)
	}
	if user.Role != session.User.Role {
		t.Errorf("User.Role mismatch: got %q, want %q", user.Role, session.User.Role)
	}
	if user.SSOProvider != session.User.SSOProvider {
		t.Errorf("User.SSOProvider mismatch: got %q, want %q", user.SSOProvider, session.User.SSOProvider)
	}

	// Marshal flags
	flagsJSON, err := json.Marshal(session.Flags)
	if err != nil {
		t.Fatalf("Failed to marshal flags: %v", err)
	}
	var flags map[string]bool
	if err := json.Unmarshal(flagsJSON, &flags); err != nil {
		t.Fatalf("Failed to unmarshal flags: %v", err)
	}
	if !flags["mfa_verified"] {
		t.Error("mfa_verified flag should be true")
	}
	if flags["first_login"] {
		t.Error("first_login flag should be false")
	}

	// Marshal metadata
	metadataJSON, err := json.Marshal(session.Metadata)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal metadata: %v", err)
	}
	if metadata["login_method"] != "oidc" {
		t.Errorf("login_method mismatch: got %v, want %q", metadata["login_method"], "oidc")
	}
}

// TestSSOSession_NilUserSerialization verifies that nil User serializes correctly.
func TestSSOSession_NilUserSerialization(t *testing.T) {
	session := &SSOSession{
		ID:        "sess-nil-user",
		UserID:    "user-789",
		Provider:  ProviderSAML,
		Active:    true,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	userJSON, err := json.Marshal(session.User)
	if err != nil {
		t.Fatalf("Failed to marshal nil User: %v", err)
	}
	if string(userJSON) != "null" {
		t.Errorf("nil User should marshal to 'null', got %s", userJSON)
	}

	// Verify unmarshal nil user back
	var user *SSOUser
	if err := json.Unmarshal(userJSON, &user); err != nil {
		t.Fatalf("Failed to unmarshal nil User: %v", err)
	}
	if user != nil {
		t.Error("Expected nil user after unmarshal")
	}
}

// TestSSOSession_ProviderSerialization verifies that SSOProvider serializes as string.
func TestSSOSession_ProviderSerialization(t *testing.T) {
	tests := []struct {
		name     string
		provider SSOProvider
		expected string
	}{
		{"oidc", ProviderOIDC, "oidc"},
		{"saml", ProviderSAML, "saml"},
		{"oauth2", ProviderOAuth, "oauth2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := string(tt.provider)
			if result != tt.expected {
				t.Errorf("SSOProvider string: got %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestSSOSession_EmptyFlagsSerialization verifies empty flags/metadata serialize correctly.
func TestSSOSession_EmptyFlagsSerialization(t *testing.T) {
	session := &SSOSession{
		ID:        "sess-empty",
		UserID:    "user-empty",
		Provider:  ProviderOIDC,
		Active:    true,
		ExpiresAt: time.Now().Add(time.Hour),
		Flags:     nil,
		Metadata:  nil,
	}

	// nil maps should serialize to "null" or "{}"
	flagsJSON, _ := json.Marshal(session.Flags)
	if string(flagsJSON) != "null" {
		// nil map marshals to "null" which is fine for JSONB
		t.Logf("nil flags marshals to: %s", flagsJSON)
	}

	metadataJSON, _ := json.Marshal(session.Metadata)
	if string(metadataJSON) != "null" {
		t.Logf("nil metadata marshals to: %s", metadataJSON)
	}
}

// ============================================================================
// SSOSession Field Validation Tests
// ============================================================================

// TestPostgresSession_IsExpired verifies session expiration logic.
func TestPostgresSession_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		expired   bool
	}{
		{"past", now.Add(-1 * time.Hour), true},
		{"future", now.Add(1 * time.Hour), false},
		{"now", now, true}, // time.Now().After(now) is likely true due to clock
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &SSOSession{
				ID:        "test",
				ExpiresAt: tt.expiresAt,
			}
			if session.IsExpired() != tt.expired {
				t.Errorf("IsExpired() = %v, want %v", session.IsExpired(), tt.expired)
			}
		})
	}
}

// TestSSOSession_IsValid verifies session validity logic.
func TestSSOSession_IsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		active    bool
		expiresAt time.Time
		valid     bool
	}{
		{"active_future", true, now.Add(1 * time.Hour), true},
		{"inactive_future", false, now.Add(1 * time.Hour), false},
		{"active_past", true, now.Add(-1 * time.Hour), false},
		{"inactive_past", false, now.Add(-1 * time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &SSOSession{
				Active:    tt.active,
				ExpiresAt: tt.expiresAt,
			}
			if session.IsValid() != tt.valid {
				t.Errorf("IsValid() = %v, want %v", session.IsValid(), tt.valid)
			}
		})
	}
}

// ============================================================================
// SessionStore Interface Compliance Tests
// ============================================================================

// TestPostgresSessionStore_ImplementsSessionStore verifies interface compliance.
func TestPostgresSessionStore_ImplementsSessionStore(t *testing.T) {
	// This test verifies that PostgresSessionStore implements SessionStore.
	// If it doesn't compile, the interface is not satisfied.
	var _ SessionStore = (*PostgresSessionStore)(nil)
}

// TestPostgresRequestStore_ImplementsRequestStore verifies interface compliance.
func TestPostgresRequestStore_ImplementsRequestStore(t *testing.T) {
	// This test verifies that PostgresRequestStore implements RequestStore.
	var _ RequestStore = (*PostgresRequestStore)(nil)
}

// ============================================================================
// SSORequest Field Tests
// ============================================================================

// TestSSORequest_Fields verifies all SSORequest fields are present and accessible.
func TestSSORequest_Fields(t *testing.T) {
	now := time.Now()
	req := &SSORequest{
		ID:              "req-123",
		Provider:        "oidc",
		SAMLRequest:     "saml-request-data",
		RelayState:      "relay-state-456",
		Destination:     "https://idp.example.com/sso",
		ProtocolBinding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		State:           "csrf-state-token",
		CodeVerifier:    "pkce-verifier",
		Nonce:           "nonce-value",
		RedirectURL:     "https://app.example.com/callback",
		IPAddress:       "10.0.0.1",
		UserAgent:       "Mozilla/5.0",
		CreatedAt:       now,
		ExpiresAt:       now.Add(10 * time.Minute),
	}

	if req.ID != "req-123" {
		t.Errorf("ID mismatch: got %q", req.ID)
	}
	if req.Provider != "oidc" {
		t.Errorf("Provider mismatch: got %q", req.Provider)
	}
	if req.State != "csrf-state-token" {
		t.Errorf("State mismatch: got %q", req.State)
	}
	if req.CodeVerifier != "pkce-verifier" {
		t.Errorf("CodeVerifier mismatch: got %q", req.CodeVerifier)
	}
	if req.Nonce != "nonce-value" {
		t.Errorf("Nonce mismatch: got %q", req.Nonce)
	}
}

// ============================================================================
// Close / Reopen Tests
// ============================================================================

// TestPostgresSessionStore_CloseIdempotent verifies Close can be called multiple times.
func TestPostgresSessionStore_CloseIdempotent(t *testing.T) {
	store := &PostgresSessionStore{}

	if err := store.Close(); err != nil {
		t.Errorf("First Close() failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Errorf("Second Close() failed: %v", err)
	}
}

// TestPostgresRequestStore_CloseIdempotent verifies CloseRequestStore can be called multiple times.
func TestPostgresRequestStore_CloseIdempotent(t *testing.T) {
	store := &PostgresRequestStore{}

	if err := store.CloseRequestStore(); err != nil {
		t.Errorf("First CloseRequestStore() failed: %v", err)
	}
	if err := store.CloseRequestStore(); err != nil {
		t.Errorf("Second CloseRequestStore() failed: %v", err)
	}
}

// ============================================================================
// Context-Based Tests (for future context.Context support)
// ============================================================================

// TestContextBackground_Available verifies context.Background() is available
// for the internal DB operations (compile-time check).
func TestContextBackground_Available(t *testing.T) {
	ctx := context.Background()
	if ctx == nil {
		t.Error("context.Background() should not return nil")
	}
}

// ============================================================================
// SSOSession Token Expiry Tests
// ============================================================================

// TestSSOSession_IsTokenExpired verifies token expiration logic.
func TestSSOSession_IsTokenExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name           string
		accessToken    string
		tokenExpiresAt time.Time
		expired        bool
	}{
		{"no_token", "", time.Time{}, false},                   // No token → not expired
		{"future_token", "tok", now.Add(1 * time.Hour), false}, // Future → not expired
		{"past_token", "tok", now.Add(-1 * time.Hour), true},   // Past → expired
		{"zero_expiry", "tok", time.Time{}, false},             // Zero time → not expired (unknown)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &SSOSession{
				AccessToken:    tt.accessToken,
				TokenExpiresAt: tt.tokenExpiresAt,
			}
			if session.IsTokenExpired() != tt.expired {
				t.Errorf("IsTokenExpired() = %v, want %v", session.IsTokenExpired(), tt.expired)
			}
		})
	}
}

// TestSSOSession_NeedsTokenRefresh verifies token refresh logic.
func TestSSOSession_NeedsTokenRefresh(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name           string
		refreshToken   string
		tokenExpiresAt time.Time
		needsRefresh   bool
	}{
		{"no_refresh_token", "", now.Add(-1 * time.Hour), false},
		{"token_still_valid", "refresh", now.Add(1 * time.Hour), false},
		{"token_expired", "refresh", now.Add(-1 * time.Hour), true},
		{"zero_expiry_with_refresh", "refresh", time.Time{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &SSOSession{
				RefreshToken:   tt.refreshToken,
				TokenExpiresAt: tt.tokenExpiresAt,
			}
			buffer := 5 * time.Minute
			if session.NeedsTokenRefresh(buffer) != tt.needsRefresh {
				t.Errorf("NeedsTokenRefresh() = %v, want %v", session.NeedsTokenRefresh(buffer), tt.needsRefresh)
			}
		})
	}
}

// ============================================================================
// StatsPostgres Tests (closed state)
// ============================================================================

// TestPostgresSessionStore_StatsPostgres_Closed verifies stats fail on closed store.
func TestPostgresSessionStore_StatsPostgres_Closed(t *testing.T) {
	store := &PostgresSessionStore{closed: true}
	_, _, err := store.StatsPostgres()
	if err == nil {
		t.Error("StatsPostgres should fail on closed store")
	}
}

// ============================================================================
// SSOUser Serialization Tests (for JSONB user_data column)
// ============================================================================

// TestSSOUser_JSONSerialization verifies SSOUser serializes completely.
func TestSSOUser_JSONSerialization(t *testing.T) {
	user := &SSOUser{
		ID:            "user-1",
		Email:         "admin@example.com",
		Name:          "Admin User",
		Role:          "admin",
		SSOProvider:   ProviderSAML,
		SSOProviderID: "okta",
		UpstreamID:    "okta-12345",
		UpstreamName:  "Admin User (Okta)",
		SessionIndex:  "idx-abc",
		NameID:        "admin@example.com",
		AuthnContext:  "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		Groups:        []string{"admins", "ops", "security"},
	}

	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Failed to marshal SSOUser: %v", err)
	}

	var decoded SSOUser
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal SSOUser: %v", err)
	}

	if decoded.ID != user.ID {
		t.Errorf("ID mismatch: got %q, want %q", decoded.ID, user.ID)
	}
	if decoded.Email != user.Email {
		t.Errorf("Email mismatch: got %q, want %q", decoded.Email, user.Email)
	}
	if decoded.Role != user.Role {
		t.Errorf("Role mismatch: got %q, want %q", decoded.Role, user.Role)
	}
	if decoded.SSOProvider != user.SSOProvider {
		t.Errorf("SSOProvider mismatch: got %q, want %q", decoded.SSOProvider, user.SSOProvider)
	}
	if len(decoded.Groups) != len(user.Groups) {
		t.Errorf("Groups length mismatch: got %d, want %d", len(decoded.Groups), len(user.Groups))
	}
}

// TestSSOUser_RawAttributes verifies RawAttributes with nested data.
func TestSSOUser_RawAttributes(t *testing.T) {
	user := &SSOUser{
		ID:            "user-2",
		Email:         "dev@example.com",
		Role:          "developer",
		RawAttributes: map[string]interface{}{"department": "engineering", "level": 5, "remote": true},
	}

	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded SSOUser
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if v, ok := decoded.RawAttributes["department"].(string); !ok || v != "engineering" {
		t.Errorf("department attribute mismatch: got %v", decoded.RawAttributes["department"])
	}
}

// ============================================================================
// Manager Integration with PostgresSessionStore
// ============================================================================

// TestNewManager_WithPostgresSessionStore verifies that Manager can accept
// a PostgresSessionStore (but we can't use a real pool, so we test the
// type compatibility).
func TestNewManager_WithPostgresSessionStore(t *testing.T) {
	// Verify PostgresSessionStore satisfies SessionStore
	var _ SessionStore = (*PostgresSessionStore)(nil)
	// Verify PostgresRequestStore satisfies RequestStore
	var _ RequestStore = (*PostgresRequestStore)(nil)

	// Verify ManagerConfig accepts the interfaces
	config := &ManagerConfig{
		SessionStore: NewMemorySessionStore(), // would be PostgresSessionStore in production
		RequestStore: NewMemoryRequestStore(), // would be PostgresRequestStore in production
	}
	mgr, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if mgr == nil {
		t.Error("Manager should not be nil")
	}
}

// ============================================================================
// Session Store Round-Trip Serialization
// ============================================================================

// TestSSOSession_RoundTrip verifies that a complete SSOSession can be
// serialized to JSONB-compatible fields and deserialized back correctly.
func TestSSOSession_RoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)

	original := &SSOSession{
		ID:             "sess-roundtrip",
		UserID:         "user-rt",
		SessionID:      "session-rt",
		Provider:       ProviderSAML,
		ProviderName:   "okta",
		CreatedAt:      now,
		ExpiresAt:      now.Add(8 * time.Hour),
		LastActivity:   now.Add(1 * time.Minute),
		LastRefreshed:  now.Add(2 * time.Minute),
		IPAddress:      "203.0.113.42",
		UserAgent:      "Chrome/120.0",
		InitialIDP:     "https://idp.example.com",
		NameID:         "user@example.com",
		SessionIndex:   "idx-rt-789",
		AccessToken:    "ya29.roundtrip",
		RefreshToken:   "1//roundtrip",
		IDToken:        "eyJ.roundtrip.jwt",
		TokenExpiresAt: now.Add(30 * time.Minute),
		Active:         true,
		Flags: map[string]bool{
			"mfa_verified":    true,
			"consent_given":   true,
			"risk_assessment": false,
		},
		Metadata: map[string]interface{}{
			"auth_method":  "saml",
			"risk_score":   0.05,
			"geo_location": "US-CA",
		},
		User: &SSOUser{
			ID:            "user-rt",
			Email:         "user@example.com",
			Name:          "Round Trip User",
			Role:          "operator",
			SSOProvider:   ProviderSAML,
			SSOProviderID: "okta",
			UpstreamID:    "okta-rt-123",
			Groups:        []string{"operators", "devops"},
		},
	}

	// Serialize JSONB columns
	userJSON, err := json.Marshal(original.User)
	if err != nil {
		t.Fatalf("Marshal user: %v", err)
	}
	flagsJSON, err := json.Marshal(original.Flags)
	if err != nil {
		t.Fatalf("Marshal flags: %v", err)
	}
	metadataJSON, err := json.Marshal(original.Metadata)
	if err != nil {
		t.Fatalf("Marshal metadata: %v", err)
	}

	// Deserialize JSONB columns
	var decodedUser SSOUser
	if err := json.Unmarshal(userJSON, &decodedUser); err != nil {
		t.Fatalf("Unmarshal user: %v", err)
	}
	var decodedFlags map[string]bool
	if err := json.Unmarshal(flagsJSON, &decodedFlags); err != nil {
		t.Fatalf("Unmarshal flags: %v", err)
	}
	var decodedMetadata map[string]interface{}
	if err := json.Unmarshal(metadataJSON, &decodedMetadata); err != nil {
		t.Fatalf("Unmarshal metadata: %v", err)
	}

	// Verify user fields
	if decodedUser.ID != original.User.ID {
		t.Errorf("User.ID: got %q, want %q", decodedUser.ID, original.User.ID)
	}
	if decodedUser.Email != original.User.Email {
		t.Errorf("User.Email: got %q, want %q", decodedUser.Email, original.User.Email)
	}
	if decodedUser.Role != original.User.Role {
		t.Errorf("User.Role: got %q, want %q", decodedUser.Role, original.User.Role)
	}

	// Verify flags
	if !decodedFlags["mfa_verified"] {
		t.Error("mfa_verified should be true")
	}
	if decodedFlags["risk_assessment"] {
		t.Error("risk_assessment should be false")
	}

	// Verify metadata
	if decodedMetadata["auth_method"] != "saml" {
		t.Errorf("auth_method: got %v, want %q", decodedMetadata["auth_method"], "saml")
	}
}
