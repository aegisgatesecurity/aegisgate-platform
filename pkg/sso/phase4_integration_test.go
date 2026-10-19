// SPDX-License-Identifier: Apache-2.0
//go:build integration

// Phase 4 integration tests for SSO PostgreSQL session and request stores.
// Uses testcontainers to spin up an ephemeral PostgreSQL container.
// Run with: go test -tags=integration -count=1 ./pkg/sso/...

package sso

import (
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
)

func setupSessionStore(t *testing.T) (*PostgresSessionStore, func()) {
	t.Helper()
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	store, err := NewPostgresSessionStore(pgStore)
	if err != nil {
		dbCleanup()
		t.Fatalf("NewPostgresSessionStore: %v", err)
	}
	cleanup := func() {
		store.Close()
		dbCleanup()
	}
	return store, cleanup
}

func setupRequestStore(t *testing.T) (*PostgresRequestStore, func()) {
	t.Helper()
	pgStore, dbCleanup := testdb.SetupTestDB(t)
	store, err := NewPostgresRequestStore(pgStore)
	if err != nil {
		dbCleanup()
		t.Fatalf("NewPostgresRequestStore: %v", err)
	}
	cleanup := func() {
		store.CloseRequestStore()
		dbCleanup()
	}
	return store, cleanup
}

func makeTestSession(id, userID string) *SSOSession {
	now := time.Now().UTC()
	return &SSOSession{
		ID:           id,
		UserID:       userID,
		SessionID:    "session-" + id,
		Provider:     ProviderOIDC,
		ProviderName: "test-oidc",
		CreatedAt:    now,
		ExpiresAt:    now.Add(1 * time.Hour),
		LastActivity: now,
		Active:       true,
		IPAddress:    "10.0.0.1",
		UserAgent:    "test-agent",
		AccessToken:  "access-token-" + id,
		RefreshToken: "refresh-token-" + id,
		IDToken:      "id-token-" + id,
		Flags:        map[string]bool{"mfa": true},
		Metadata:     map[string]interface{}{"key": "value"},
	}
}

func makeTestRequest(id, state string) *SSORequest {
	now := time.Now().UTC()
	return &SSORequest{
		ID:          id,
		Provider:    "oidc",
		State:       state,
		Nonce:       "nonce-" + id,
		CreatedAt:   now,
		ExpiresAt:   now.Add(10 * time.Minute),
		RedirectURL: "https://example.com/callback",
		IPAddress:   "10.0.0.1",
		UserAgent:   "test-agent",
	}
}

// --- PostgresSessionStore Create + Get ---

func TestPhase4_SessionStore_CreateAndGet(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	session := makeTestSession("sess-1", "user-1")
	if err := store.Create(session); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get("sess-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil session")
	}
	if got.ID != "sess-1" {
		t.Errorf("ID: got %q, want %q", got.ID, "sess-1")
	}
	if got.UserID != "user-1" {
		t.Errorf("UserID: got %q, want %q", got.UserID, "user-1")
	}
	if got.Provider != ProviderOIDC {
		t.Errorf("Provider: got %q, want %q", got.Provider, ProviderOIDC)
	}
	if got.ProviderName != "test-oidc" {
		t.Errorf("ProviderName: got %q, want %q", got.ProviderName, "test-oidc")
	}
	if got.AccessToken != "access-token-sess-1" {
		t.Errorf("AccessToken: got %q, want %q", got.AccessToken, "access-token-sess-1")
	}
	if !got.Active {
		t.Error("expected active session")
	}
	if got.Flags == nil || !got.Flags["mfa"] {
		t.Error("expected mfa flag to be set")
	}
}

func TestPhase4_SessionStore_Get_NotFound(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	got, err := store.Get("nonexistent")
	if err != nil {
		t.Fatalf("Get not found should return nil, nil: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil session for nonexistent ID")
	}
}

func TestPhase4_SessionStore_Create_NilSession(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	if err := store.Create(nil); err == nil {
		t.Fatal("expected error for nil session")
	}
}

// --- PostgresSessionStore Update ---

func TestPhase4_SessionStore_Update(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	session := makeTestSession("sess-update", "user-update")
	_ = store.Create(session)

	// Modify and update
	session.Active = false
	session.AccessToken = "new-access-token"
	session.LastActivity = time.Now().UTC()

	if err := store.Update(session); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := store.Get("sess-update")
	if got == nil {
		t.Fatal("session not found after update")
	}
	if got.Active {
		t.Error("expected active=false after update")
	}
	if got.AccessToken != "new-access-token" {
		t.Errorf("AccessToken: got %q, want %q", got.AccessToken, "new-access-token")
	}
}

func TestPhase4_SessionStore_Update_NotFound(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	session := makeTestSession("nonexistent-update", "user-x")
	if err := store.Update(session); err == nil {
		t.Fatal("expected error for updating nonexistent session")
	}
}

func TestPhase4_SessionStore_Update_NilSession(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	if err := store.Update(nil); err == nil {
		t.Fatal("expected error for nil session")
	}
}

// --- PostgresSessionStore Delete ---

func TestPhase4_SessionStore_Delete(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	session := makeTestSession("sess-delete", "user-delete")
	_ = store.Create(session)

	if err := store.Delete("sess-delete"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, _ := store.Get("sess-delete")
	if got != nil {
		t.Fatal("session should not exist after delete")
	}
}

// --- PostgresSessionStore GetByUserID ---

func TestPhase4_SessionStore_GetByUserID(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	_ = store.Create(makeTestSession("sess-u1", "user-multi"))
	_ = store.Create(makeTestSession("sess-u2", "user-multi"))
	_ = store.Create(makeTestSession("sess-u3", "user-other"))

	sessions, err := store.GetByUserID("user-multi")
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestPhase4_SessionStore_GetByUserID_Empty(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	sessions, err := store.GetByUserID("user-nonexistent")
	if err != nil {
		t.Fatalf("GetByUserID: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestPhase4_SessionStore_GetByUserID_ExcludesInactive(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	active := makeTestSession("sess-active", "user-filter")
	_ = store.Create(active)

	inactive := makeTestSession("sess-inactive", "user-filter")
	inactive.Active = false
	_ = store.Create(inactive)

	sessions, _ := store.GetByUserID("user-filter")
	if len(sessions) != 1 {
		t.Fatalf("expected 1 active session, got %d", len(sessions))
	}
	if sessions[0].ID != "sess-active" {
		t.Errorf("expected active session, got %q", sessions[0].ID)
	}
}

// --- PostgresSessionStore DeleteByUserID ---

func TestPhase4_SessionStore_DeleteByUserID(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	_ = store.Create(makeTestSession("sess-d1", "user-del-all"))
	_ = store.Create(makeTestSession("sess-d2", "user-del-all"))
	_ = store.Create(makeTestSession("sess-d3", "user-keep"))

	if err := store.DeleteByUserID("user-del-all"); err != nil {
		t.Fatalf("DeleteByUserID: %v", err)
	}

	sessions, _ := store.GetByUserID("user-del-all")
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions after delete, got %d", len(sessions))
	}

	// Other user's sessions should remain
	sessions, _ = store.GetByUserID("user-keep")
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session for other user, got %d", len(sessions))
	}
}

// --- PostgresSessionStore Cleanup ---

func TestPhase4_SessionStore_Cleanup_Expired(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	// Create an expired session
	expired := makeTestSession("sess-expired", "user-exp")
	expired.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour) // expired
	_ = store.Create(expired)

	// Create an active session
	active := makeTestSession("sess-active-cleanup", "user-active")
	_ = store.Create(active)

	// Cleanup should remove expired sessions
	if err := store.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	// Expired session should be gone
	got, _ := store.Get("sess-expired")
	if got != nil {
		t.Fatal("expired session should be cleaned up")
	}

	// Active session should remain
	got, _ = store.Get("sess-active-cleanup")
	if got == nil {
		t.Fatal("active session should remain after cleanup")
	}
}

func TestPhase4_SessionStore_Cleanup_Inactive(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	// Create an inactive session
	inactive := makeTestSession("sess-inactive-cleanup", "user-inact")
	inactive.Active = false
	_ = store.Create(inactive)

	if err := store.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	got, _ := store.Get("sess-inactive-cleanup")
	if got != nil {
		t.Fatal("inactive session should be cleaned up")
	}
}

// --- PostgresSessionStore StatsPostgres ---

func TestPhase4_SessionStore_StatsPostgres(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	// Create active sessions
	_ = store.Create(makeTestSession("stat-1", "user-stat-1"))
	_ = store.Create(makeTestSession("stat-2", "user-stat-2"))

	// Create inactive session
	inactive := makeTestSession("stat-3", "user-stat-3")
	inactive.Active = false
	_ = store.Create(inactive)

	active, total, err := store.StatsPostgres()
	if err != nil {
		t.Fatalf("StatsPostgres: %v", err)
	}
	if active != 2 {
		t.Errorf("active: got %d, want 2", active)
	}
	if total != 3 {
		t.Errorf("total: got %d, want 3", total)
	}
}

// --- PostgresSessionStore Close ---

func TestPhase4_SessionStore_Close(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	// Close the store
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Operations after close should return error
	if err := store.Create(makeTestSession("closed", "user")); err == nil {
		t.Fatal("expected error after Close")
	}

	if _, err := store.Get("any"); err == nil {
		t.Fatal("expected error after Close")
	}

	if err := store.Delete("any"); err == nil {
		t.Fatal("expected error after Close")
	}

	if _, err := store.GetByUserID("any"); err == nil {
		t.Fatal("expected error after Close")
	}

	if err := store.DeleteByUserID("any"); err == nil {
		t.Fatal("expected error after Close")
	}

	if err := store.Cleanup(); err == nil {
		t.Fatal("expected error after Close")
	}

	if _, _, err := store.StatsPostgres(); err == nil {
		t.Fatal("expected error after Close")
	}

	// Double close should be safe
	if err := store.Close(); err != nil {
		t.Fatalf("double Close should be safe: %v", err)
	}
}

// --- PostgresRequestStore Create + Get ---

func TestPhase4_RequestStore_CreateAndGet(t *testing.T) {
	store, cleanup := setupRequestStore(t)
	defer cleanup()

	req := makeTestRequest("req-1", "state-1")
	if err := store.Create(req); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get("req-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil request")
	}
	if got.ID != "req-1" {
		t.Errorf("ID: got %q, want %q", got.ID, "req-1")
	}
	if got.State != "state-1" {
		t.Errorf("State: got %q, want %q", got.State, "state-1")
	}
	if got.Provider != "oidc" {
		t.Errorf("Provider: got %q, want %q", got.Provider, "oidc")
	}
}

func TestPhase4_RequestStore_Get_NotFound(t *testing.T) {
	store, cleanup := setupRequestStore(t)
	defer cleanup()

	got, err := store.Get("nonexistent")
	if err != nil {
		t.Fatalf("Get not found should return nil, nil: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil request for nonexistent ID")
	}
}

func TestPhase4_RequestStore_Create_NilRequest(t *testing.T) {
	store, cleanup := setupRequestStore(t)
	defer cleanup()

	if err := store.Create(nil); err == nil {
		t.Fatal("expected error for nil request")
	}
}

// --- PostgresRequestStore GetByState ---

func TestPhase4_RequestStore_GetByState(t *testing.T) {
	store, cleanup := setupRequestStore(t)
	defer cleanup()

	req := makeTestRequest("req-state", "unique-state-123")
	_ = store.Create(req)

	got, err := store.GetByState("unique-state-123")
	if err != nil {
		t.Fatalf("GetByState: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil request")
	}
	if got.ID != "req-state" {
		t.Errorf("ID: got %q, want %q", got.ID, "req-state")
	}
}

func TestPhase4_RequestStore_GetByState_NotFound(t *testing.T) {
	store, cleanup := setupRequestStore(t)
	defer cleanup()

	got, err := store.GetByState("nonexistent-state")
	if err != nil {
		t.Fatalf("GetByState not found should return nil, nil: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil request for nonexistent state")
	}
}

// --- PostgresRequestStore Delete ---

func TestPhase4_RequestStore_Delete(t *testing.T) {
	store, cleanup := setupRequestStore(t)
	defer cleanup()

	req := makeTestRequest("req-delete", "state-delete")
	_ = store.Create(req)

	if err := store.Delete("req-delete"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, _ := store.Get("req-delete")
	if got != nil {
		t.Fatal("request should not exist after delete")
	}
}

// --- PostgresRequestStore Close ---

func TestPhase4_RequestStore_Close(t *testing.T) {
	store, cleanup := setupRequestStore(t)
	defer cleanup()

	if err := store.CloseRequestStore(); err != nil {
		t.Fatalf("CloseRequestStore: %v", err)
	}

	if err := store.Create(makeTestRequest("closed", "state")); err == nil {
		t.Fatal("expected error after Close")
	}

	if _, err := store.Get("any"); err == nil {
		t.Fatal("expected error after Close")
	}

	if _, err := store.GetByState("any"); err == nil {
		t.Fatal("expected error after Close")
	}

	if err := store.Delete("any"); err == nil {
		t.Fatal("expected error after Close")
	}

	// Double close should be safe
	if err := store.CloseRequestStore(); err != nil {
		t.Fatalf("double Close should be safe: %v", err)
	}
}

// --- Session with SSOUser (scanSession with user data) ---

func TestPhase4_SessionStore_WithUser(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	session := makeTestSession("sess-user", "user-with-attrs")
	session.User = &SSOUser{
		ID:            "user-with-attrs",
		Email:         "test@example.com",
		Name:          "Test User",
		Role:          "admin",
		SSOProvider:   ProviderOIDC,
		SSOProviderID: "test-oidc",
		Groups:        []string{"admins", "users"},
	}
	session.User.RawAttributes = map[string]interface{}{"department": "engineering"}

	if err := store.Create(session); err != nil {
		t.Fatalf("Create with user: %v", err)
	}

	got, err := store.Get("sess-user")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil session")
	}
	if got.User == nil {
		t.Fatal("expected non-nil user")
	}
	if got.User.Email != "test@example.com" {
		t.Errorf("Email: got %q, want %q", got.User.Email, "test@example.com")
	}
	if got.User.Name != "Test User" {
		t.Errorf("Name: got %q, want %q", got.User.Name, "Test User")
	}
	if got.User.Role != "admin" {
		t.Errorf("Role: got %q, want %q", got.User.Role, "admin")
	}
}

// --- Session with SAML provider ---

func TestPhase4_SessionStore_SAMLProvider(t *testing.T) {
	store, cleanup := setupSessionStore(t)
	defer cleanup()

	session := makeTestSession("sess-saml", "user-saml")
	session.Provider = ProviderSAML
	session.ProviderName = "test-saml"
	session.NameID = "user-saml@example.com"
	session.SessionIndex = "saml-session-index"

	if err := store.Create(session); err != nil {
		t.Fatalf("Create SAML session: %v", err)
	}

	got, _ := store.Get("sess-saml")
	if got == nil {
		t.Fatal("session not found")
	}
	if got.Provider != ProviderSAML {
		t.Errorf("Provider: got %q, want %q", got.Provider, ProviderSAML)
	}
	if got.NameID != "user-saml@example.com" {
		t.Errorf("NameID: got %q, want %q", got.NameID, "user-saml@example.com")
	}
	if got.SessionIndex != "saml-session-index" {
		t.Errorf("SessionIndex: got %q, want %q", got.SessionIndex, "saml-session-index")
	}
}

// --- Request store upsert (ON CONFLICT) ---

func TestPhase4_RequestStore_Upsert(t *testing.T) {
	store, cleanup := setupRequestStore(t)
	defer cleanup()

	req := makeTestRequest("req-upsert", "state-upsert")
	req.Provider = "saml"
	_ = store.Create(req)

	// Upsert with different provider
	req2 := makeTestRequest("req-upsert", "state-upsert")
	req2.Provider = "oidc"
	if err := store.Create(req2); err != nil {
		t.Fatalf("Create (upsert): %v", err)
	}

	got, _ := store.Get("req-upsert")
	if got == nil {
		t.Fatal("request not found")
	}
	if got.Provider != "oidc" {
		t.Errorf("Provider after upsert: got %q, want %q", got.Provider, "oidc")
	}
}
