// SPDX-License-Identifier: Apache-2.0
// package sso — coverage tests for Manager session-store methods

package sso

import (
	"testing"
	"time"
)

func makeManager(t *testing.T) *Manager {
	t.Helper()
	mgr, err := NewManager(&ManagerConfig{})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

func registerMock(t *testing.T, mgr *Manager, name string) *mockProvider {
	t.Helper()
	mp := &mockProvider{name: name, typ: ProviderOIDC, userID: "u1"}
	cfg := &SSOConfig{Provider: ProviderOIDC, Name: name, Enabled: true, SessionDuration: time.Hour}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.configs[mp.name] = cfg
	mgr.mu.Unlock()
	return mp
}

// ---------- GetSession ----------

func TestManager_GetSession_Found(t *testing.T) {
	mgr := makeManager(t)
	sess := &SSOSession{
		ID: "s1", UserID: "u1", Provider: ProviderOIDC, ProviderName: "mock",
		Active: true, ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := mgr.sessions.Create(sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := mgr.GetSession("s1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != "s1" {
		t.Errorf("got ID %s, want s1", got.ID)
	}
}

func TestManager_GetSession_NotFound(t *testing.T) {
	mgr := makeManager(t)
	_, err := mgr.GetSession("nonexistent")
	if err == nil {
		t.Error("expected error for missing session")
	}
}

// ---------- GetUserSessions ----------

func TestManager_GetUserSessions(t *testing.T) {
	mgr := makeManager(t)
	s1 := &SSOSession{ID: "s1", UserID: "u1", Provider: ProviderOIDC, Active: true, ExpiresAt: time.Now().Add(time.Hour)}
	s2 := &SSOSession{ID: "s2", UserID: "u1", Provider: ProviderOIDC, Active: true, ExpiresAt: time.Now().Add(time.Hour)}
	s3 := &SSOSession{ID: "s3", UserID: "u2", Provider: ProviderOIDC, Active: true, ExpiresAt: time.Now().Add(time.Hour)}
	_ = mgr.sessions.Create(s1)
	_ = mgr.sessions.Create(s2)
	_ = mgr.sessions.Create(s3)

	sessions, err := mgr.GetUserSessions("u1")
	if err != nil {
		t.Fatalf("GetUserSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("got %d sessions, want 2", len(sessions))
	}
}

// ---------- TerminateUserSessions ----------

func TestManager_TerminateUserSessions(t *testing.T) {
	mgr := makeManager(t)
	s1 := &SSOSession{ID: "s1", UserID: "u1", Provider: ProviderOIDC, Active: true, ExpiresAt: time.Now().Add(time.Hour)}
	s2 := &SSOSession{ID: "s2", UserID: "u1", Provider: ProviderOIDC, Active: true, ExpiresAt: time.Now().Add(time.Hour)}
	_ = mgr.sessions.Create(s1)
	_ = mgr.sessions.Create(s2)

	if err := mgr.TerminateUserSessions("u1"); err != nil {
		t.Fatalf("TerminateUserSessions: %v", err)
	}

	got, _ := mgr.sessions.Get("s1")
	if got.Active {
		t.Error("session s1 should be inactive")
	}
	got2, _ := mgr.sessions.Get("s2")
	if got2.Active {
		t.Error("session s2 should be inactive")
	}
}

func TestManager_TerminateUserSessions_NotFound(t *testing.T) {
	mgr := makeManager(t)
	// should not error for missing user
	if err := mgr.TerminateUserSessions("nobody"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// ---------- RefreshSession ----------

func TestManager_RefreshSession_NonOIDC(t *testing.T) {
	mgr := makeManager(t)
	mp := &mockProvider{name: "saml-mock", typ: ProviderSAML, userID: "u1"}
	cfg := &SSOConfig{Provider: ProviderSAML, Name: "saml-mock", Enabled: true, SessionDuration: time.Hour}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.configs[mp.name] = cfg
	mgr.mu.Unlock()

	sess := &SSOSession{
		ID: "s1", UserID: "u1", Provider: ProviderSAML, ProviderName: "saml-mock",
		Active: true, ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = mgr.sessions.Create(sess)

	_, err := mgr.RefreshSession("s1")
	if err == nil {
		t.Error("expected error for non-OIDC refresh")
	}
}

func TestManager_RefreshSession_NoRefreshToken(t *testing.T) {
	mgr := makeManager(t)
	mp := &mockProvider{name: "oidc-mock", typ: ProviderOIDC, userID: "u1"}
	cfg := &SSOConfig{Provider: ProviderOIDC, Name: "oidc-mock", Enabled: true, SessionDuration: time.Hour}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.configs[mp.name] = cfg
	mgr.mu.Unlock()

	sess := &SSOSession{
		ID: "s1", UserID: "u1", Provider: ProviderOIDC, ProviderName: "oidc-mock",
		Active: true, ExpiresAt: time.Now().Add(time.Hour), RefreshToken: "",
	}
	_ = mgr.sessions.Create(sess)

	_, err := mgr.RefreshSession("s1")
	if err == nil {
		t.Error("expected error for empty refresh token")
	}
}

func TestManager_RefreshSession_SessionNotFound(t *testing.T) {
	mgr := makeManager(t)
	_, err := mgr.RefreshSession("nonexistent")
	if err == nil {
		t.Error("expected error for missing session")
	}
}

func TestManager_RefreshSession_ProviderNotOIDC(t *testing.T) {
	mgr := makeManager(t)
	mp := &mockProvider{name: "saml-mock", typ: ProviderSAML, userID: "u1"}
	cfg := &SSOConfig{Provider: ProviderSAML, Name: "saml-mock", Enabled: true, SessionDuration: time.Hour}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.configs[mp.name] = cfg
	mgr.mu.Unlock()

	sess := &SSOSession{
		ID: "s1", UserID: "u1", Provider: ProviderSAML, ProviderName: "saml-mock",
		Active: true, ExpiresAt: time.Now().Add(time.Hour), RefreshToken: "rt",
	}
	_ = mgr.sessions.Create(sess)
	_, err := mgr.RefreshSession("s1")
	if err == nil {
		t.Error("expected error: provider does not support token refresh")
	}
}

// ---------- MemorySessionStore.DeleteByUserID ----------

func TestMemorySessionStore_DeleteByUserID(t *testing.T) {
	store := NewMemorySessionStore()
	s1 := &SSOSession{ID: "s1", UserID: "u1", Active: true, ExpiresAt: time.Now().Add(time.Hour)}
	s2 := &SSOSession{ID: "s2", UserID: "u1", Active: true, ExpiresAt: time.Now().Add(time.Hour)}
	s3 := &SSOSession{ID: "s3", UserID: "u2", Active: true, ExpiresAt: time.Now().Add(time.Hour)}
	_ = store.Create(s1)
	_ = store.Create(s2)
	_ = store.Create(s3)

	if err := store.DeleteByUserID("u1"); err != nil {
		t.Fatalf("DeleteByUserID: %v", err)
	}

	if _, err := store.Get("s1"); err == nil {
		t.Error("s1 should be deleted")
	}
	if _, err := store.Get("s2"); err == nil {
		t.Error("s2 should be deleted")
	}
	if _, err := store.Get("s3"); err != nil {
		t.Error("s3 should still exist")
	}
}

func TestMemorySessionStore_DeleteByUserID_Empty(t *testing.T) {
	store := NewMemorySessionStore()
	if err := store.DeleteByUserID("nobody"); err != nil {
		t.Fatalf("DeleteByUserID on empty store: %v", err)
	}
}

// ---------- Manager.ValidateSession edge cases ----------

func TestManager_ValidateSession_Inactive(t *testing.T) {
	mgr := makeManager(t)
	mp := registerMock(t, mgr, "mock")
	_ = mp // mock provider exists for validation
	sess := &SSOSession{
		ID: "s1", UserID: "u1", Provider: ProviderOIDC, ProviderName: "mock",
		Active: false, ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = mgr.sessions.Create(sess)
	_, err := mgr.ValidateSession("s1")
	if err == nil {
		t.Error("expected error for inactive session")
	}
}

func TestManager_ValidateSession_Expired(t *testing.T) {
	mgr := makeManager(t)
	_ = registerMock(t, mgr, "mock")
	sess := &SSOSession{
		ID: "s1", UserID: "u1", Provider: ProviderOIDC, ProviderName: "mock",
		Active: true, ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	_ = mgr.sessions.Create(sess)
	_, err := mgr.ValidateSession("s1")
	if err == nil {
		t.Error("expected error for expired session")
	}
}

func TestManager_ValidateSession_NotFound(t *testing.T) {
	mgr := makeManager(t)
	_, err := mgr.ValidateSession("nonexistent")
	if err == nil {
		t.Error("expected error for missing session")
	}
}

// ---------- Manager.Logout edge cases ----------

func TestManager_Logout_SessionNotFound(t *testing.T) {
	mgr := makeManager(t)
	_, err := mgr.Logout("nonexistent")
	if err == nil {
		t.Error("expected error for missing session")
	}
}

func TestManager_Logout_ProviderNotFound(t *testing.T) {
	mgr := makeManager(t)
	sess := &SSOSession{
		ID: "s1", UserID: "u1", Provider: ProviderOIDC, ProviderName: "unknown",
		Active: true, ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = mgr.sessions.Create(sess)
	// Provider not registered — should still succeed (local session delete)
	logoutURL, err := mgr.Logout("s1")
	if err != nil {
		t.Fatalf("expected nil error when provider not found, got %v", err)
	}
	if logoutURL != "" {
		t.Errorf("expected empty logout URL, got %s", logoutURL)
	}
}

// ---------- Manager.HandleCallback edge cases ----------

func TestManager_HandleCallback_MissingState(t *testing.T) {
	mgr := makeManager(t)
	_ = registerMock(t, mgr, "mock")
	_, err := mgr.HandleCallback("mock", map[string]string{"code": "abc"})
	if err == nil {
		t.Error("expected error for missing state parameter")
	}
}

func TestManager_HandleCallback_StateMismatch(t *testing.T) {
	mgr := makeManager(t)
	_ = registerMock(t, mgr, "mock")
	// Create a request with a different state
	req := &SSORequest{ID: "r1", Provider: "mock", State: "original-state", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute)}
	_ = mgr.requests.Create(req)
	_, err := mgr.HandleCallback("mock", map[string]string{"state": "wrong-state", "code": "abc"})
	if err == nil {
		t.Error("expected error for state mismatch")
	}
}

func TestManager_HandleCallback_ProviderMismatch(t *testing.T) {
	mgr := makeManager(t)
	_ = registerMock(t, mgr, "mock")
	req := &SSORequest{ID: "r1", Provider: "other-provider", State: "state123", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute)}
	_ = mgr.requests.Create(req)
	_, err := mgr.HandleCallback("mock", map[string]string{"state": "state123"})
	if err == nil {
		t.Error("expected error for provider mismatch")
	}
}

func TestManager_HandleCallback_CallbackError(t *testing.T) {
	mgr := makeManager(t)
	mp := &mockProvider{name: "mock", typ: ProviderOIDC, userID: "u1", failCallback: true}
	cfg := &SSOConfig{Provider: ProviderOIDC, Name: "mock", Enabled: true, SessionDuration: time.Hour}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.configs[mp.name] = cfg
	mgr.mu.Unlock()

	// Initiate a login so state matches
	_, ssoReq, err := mgr.InitiateLogin("mock")
	if err != nil {
		t.Fatalf("InitiateLogin: %v", err)
	}
	_, err = mgr.HandleCallback("mock", map[string]string{"state": ssoReq.State})
	if err == nil {
		t.Error("expected callback error from mock")
	}
}

// ---------- Manager.RegisterProvider edge cases ----------

func TestManager_RegisterProvider_NilConfig(t *testing.T) {
	mgr := makeManager(t)
	if err := mgr.RegisterProvider(nil); err == nil {
		t.Error("expected error for nil config")
	}
}

func TestManager_RegisterProvider_InvalidProviderType(t *testing.T) {
	mgr := makeManager(t)
	cfg := &SSOConfig{Provider: "unknown", Name: "bad"}
	if err := mgr.RegisterProvider(cfg); err == nil {
		t.Error("expected error for unknown provider type")
	}
}

// ---------- Manager.GetProviderMetadata ----------

func TestManager_GetProviderMetadata_NotFound(t *testing.T) {
	mgr := makeManager(t)
	_, err := mgr.GetProviderMetadata("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
}

// ---------- Manager.CheckDomainAccess - NoAllowedRestricted ----------

func TestManager_CheckDomainAccess_NoAllowedDomains(t *testing.T) {
	mgr := makeManager(t)
	cfg := &SSOConfig{Provider: ProviderOIDC, Name: "open", Enabled: true, AllowedDomains: nil, BlockedDomains: nil}
	mp := &mockProvider{name: "open", typ: ProviderOIDC}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.configs[mp.name] = cfg
	mgr.mu.Unlock()
	// With no allowed or blocked domains, any email should pass
	if err := mgr.CheckDomainAccess("open", "user@any.com"); err != nil {
		t.Errorf("expected success for open provider, got %v", err)
	}
}

func TestManager_CheckDomainAccess_ProviderNotFound(t *testing.T) {
	mgr := makeManager(t)
	err := mgr.CheckDomainAccess("nonexistent", "user@example.com")
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
}

// ---------- applyRoleMappings edge cases ----------

func TestManager_ApplyRoleMappings_NilConfig(t *testing.T) {
	mgr := makeManager(t)
	user := &SSOUser{ID: "u1", Groups: []string{"g1"}}
	// Should not panic with nil config
	mgr.applyRoleMappings(user, nil)
}

func TestManager_ApplyRoleMappings_NoRoleMappings(t *testing.T) {
	mgr := makeManager(t)
	cfg := &SSOConfig{RoleMappings: nil}
	user := &SSOUser{ID: "u1", Groups: []string{"g1"}}
	mgr.applyRoleMappings(user, cfg)
	if user.Role != "" {
		t.Error("expected no role change with empty mappings")
	}
}
