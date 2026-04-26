package sso

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// mockProvider implements SSOProviderInterface for testing.
type mockProvider struct {
	name string
	typ  SSOProvider
	// controls behavior of methods
	failInit     bool
	failCallback bool
	failValidate bool
	failLogout   bool
	metadata     []byte
	userID       string
}

func (m *mockProvider) Name() string      { return m.name }
func (m *mockProvider) Type() SSOProvider { return m.typ }
func (m *mockProvider) InitiateLogin(state string) (string, *SSORequest, error) {
	if m.failInit {
		return "", nil, errors.New("init error")
	}
	req := &SSORequest{ID: "req1", Provider: m.name, State: state}
	return "https://example.com/login?state=" + state, req, nil
}
func (m *mockProvider) HandleCallback(req *SSORequest, params map[string]string) (*SSOResponse, error) {
	if m.failCallback {
		return nil, errors.New("callback error")
	}
	user := &SSOUser{ID: m.userID, SSOProvider: m.typ, Groups: []string{"g1"}}
	sess := &SSOSession{ID: "sess1", UserID: m.userID, Provider: m.typ, ProviderName: m.name, Active: true, ExpiresAt: time.Now().Add(1 * time.Hour)}
	return &SSOResponse{Success: true, User: user, Session: sess}, nil
}
func (m *mockProvider) ValidateSession(sess *SSOSession) error {
	if m.failValidate {
		return errors.New("validate error")
	}
	return nil
}
func (m *mockProvider) Logout(sess *SSOSession) (string, error) {
	if m.failLogout {
		return "", errors.New("logout error")
	}
	return "https://example.com/logout", nil
}
func (m *mockProvider) Metadata() ([]byte, error) {
	if m.metadata == nil {
		return []byte("{\"info\":\"mock\"}"), nil
	}
	return m.metadata, nil
}

func TestManagerBasicFlow(t *testing.T) {
	mgr, err := NewManager(&ManagerConfig{})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	// Register mock provider directly (skip RegisterProvider validation)
	mp := &mockProvider{name: "mock", typ: ProviderOIDC, userID: "u1"}
	cfg := &SSOConfig{Provider: ProviderOIDC, Name: "mock", Enabled: true}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.configs[mp.name] = cfg
	mgr.mu.Unlock()

	// InitiateLogin
	loginURL, req, err := mgr.InitiateLogin("mock")
	if err != nil {
		t.Fatalf("InitiateLogin error: %v", err)
	}
	if loginURL == "" || req == nil {
		t.Fatalf("unexpected loginURL or request nil")
	}
	// Simulate callback parameters
	params := map[string]string{"state": req.State}
	resp, err := mgr.HandleCallback("mock", params)
	if err != nil {
		t.Fatalf("HandleCallback error: %v", err)
	}
	if resp.User == nil || resp.Session == nil {
		t.Fatalf("callback missing user or session")
	}
	// Validate session
	sess, err := mgr.ValidateSession(resp.Session.ID)
	if err != nil {
		t.Fatalf("ValidateSession error: %v", err)
	}
	if sess.ID != resp.Session.ID {
		t.Fatalf("session ID mismatch")
	}
	// Logout
	logoutURL, err := mgr.Logout(sess.ID)
	if err != nil {
		t.Fatalf("Logout error: %v", err)
	}
	if logoutURL == "" {
		t.Fatalf("logout URL empty")
	}
}

func TestCheckDomainAccess(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})
	cfg := &SSOConfig{Provider: ProviderOIDC, Name: "domainMock", Enabled: true, AllowedDomains: []string{"example.com"}, BlockedDomains: []string{"blocked.com"}}
	mp := &mockProvider{name: "domainMock", typ: ProviderOIDC}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.configs[mp.name] = cfg
	mgr.mu.Unlock()
	// allowed
	if err := mgr.CheckDomainAccess("domainMock", "user@example.com"); err != nil {
		t.Fatalf("expected allowed domain, got %v", err)
	}
	// blocked
	if err := mgr.CheckDomainAccess("domainMock", "user@blocked.com"); err == nil {
		t.Fatalf("expected blocked domain error")
	}
	// not in allowed list (should reject)
	if err := mgr.CheckDomainAccess("domainMock", "user@other.com"); err == nil {
		t.Fatalf("expected disallowed domain error")
	}
}

func TestApplyRoleMappings(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})
	cfg := &SSOConfig{Provider: ProviderOIDC, Name: "roleMock", Enabled: true, RoleMappings: []RoleMapping{{IdPRole: "g1", AppRole: "admin"}}}
	mp := &mockProvider{name: "roleMock", typ: ProviderOIDC, userID: "u2"}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.configs[mp.name] = cfg
	mgr.mu.Unlock()
	// User with matching group
	user := &SSOUser{ID: "u2", Groups: []string{"g1"}}
	mgr.applyRoleMappings(user, cfg)
	if user.Role != "admin" {
		t.Fatalf("expected role Admin, got %v", user.Role)
	}
	// User without matching group
	user2 := &SSOUser{ID: "u3", Groups: []string{"g2"}}
	mgr.applyRoleMappings(user2, cfg)
	if user2.Role != "" {
		t.Fatalf("expected no role, got %v", user2.Role)
	}
}

func TestGetProviderMetadata(t *testing.T) {
	mgr, _ := NewManager(&ManagerConfig{})
	mp := &mockProvider{name: "metaMock", typ: ProviderOIDC, metadata: []byte(`{"meta":"data"}`)}
	mgr.mu.Lock()
	mgr.providers[mp.name] = mp
	mgr.mu.Unlock()
	meta, err := mgr.GetProviderMetadata("metaMock")
	if err != nil {
		t.Fatalf("metadata error: %v", err)
	}
	if string(meta) != `{"meta":"data"}` {
		t.Fatalf("unexpected metadata: %s", string(meta))
	}
}

func TestGenerateState(t *testing.T) {
	s := generateState()
	if s == "" {
		t.Fatalf("generateState returned empty string")
	}
}

func TestDomainMatches_Manager(t *testing.T) {
	if !domainMatches("user@example.com", "example.com") {
		t.Fatalf("domain should match")
	}
	if domainMatches("user@sub.example.com", "example.com") {
		t.Fatalf("subdomain should not be considered equal")
	}
	if domainMatches("invalid", "example.com") {
		t.Fatalf("invalid email should not match")
	}
}

// =============================================================================
// Additional Manager Tests for Coverage
// =============================================================================

func TestManagerRefreshSessionFull(t *testing.T) {
	manager, _ := NewManager(nil)

	// Test with session that has refresh token but OIDC provider doesn't exist
	session := &SSOSession{
		ID:           "test-session",
		UserID:       "test-user",
		Provider:     ProviderOIDC,
		RefreshToken: "refresh-token",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired
		Active:       true,
	}
	// Create via NewMemorySessionStore
	store := NewMemorySessionStore()
	store.Create(session)

	_, err := manager.RefreshSession("test-session")
	// Should fail because provider doesn't exist
	if err == nil {
		t.Error("RefreshSession should fail without OIDC provider")
	}
}

func TestManagerLogoutNoProvider(t *testing.T) {
	// Create manager with store
	store := NewMemorySessionStore()
	manager, _ := NewManager(&ManagerConfig{
		SessionStore: store,
	})

	session := &SSOSession{
		ID:        "test-session",
		UserID:    "test-user",
		Provider:  ProviderOIDC,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Active:    true,
	}
	store.Create(session)

	// Should return empty string when no provider is registered
	redirectURL, err := manager.Logout("test-session")
	if err != nil {
		t.Errorf("Logout() error: %v", err)
	}
	// No provider registered, so no redirect URL
	_ = redirectURL
}

// Test Manager cleanup
func TestManagerCleanup(t *testing.T) {
	store := NewMemorySessionStore()
	manager, _ := NewManager(&ManagerConfig{
		SessionStore: store,
	})

	// Create some expired sessions
	for i := 0; i < 3; i++ {
		session := &SSOSession{
			ID:        fmt.Sprintf("expired-%d", i),
			UserID:    "user",
			CreatedAt: time.Now().Add(-2 * time.Hour),
			ExpiresAt: time.Now().Add(-1 * time.Hour),
			Active:    true,
		}
		store.Create(session)
	}

	err := manager.CleanupSessions()
	if err != nil {
		t.Errorf("CleanupSessions() error: %v", err)
	}
}
