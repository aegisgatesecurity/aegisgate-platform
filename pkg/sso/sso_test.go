package sso

import (
	"context"
	"testing"
	"time"
)

func TestSSOConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *SSOConfig
		wantErr bool
	}{
		{
			name: "valid OIDC config",
			config: &SSOConfig{
				Provider:        ProviderOIDC,
				Name:            "test-oidc",
				SessionDuration: 24 * time.Hour,
				OIDC: &OIDCConfig{
					ClientID:     "test-client",
					ClientSecret: "test-secret",
					RedirectURL:  "http://localhost/callback",
					IssuerURL:    "https://accounts.google.com",
				},
			},
			wantErr: false,
		},
		{
			name: "valid SAML config",
			config: &SSOConfig{
				Provider:        ProviderSAML,
				Name:            "test-saml",
				SessionDuration: 24 * time.Hour,
				SAML: &SAMLConfig{
					EntityID:    "https://sp.example.com",
					ACSURL:      "https://sp.example.com/acs",
					IDPEntityID: "https://idp.example.com",
				},
			},
			wantErr: false,
		},
		{
			name: "missing provider type",
			config: &SSOConfig{
				Name: "test",
			},
			wantErr: true,
		},
		{
			name: "missing provider name",
			config: &SSOConfig{
				Provider: ProviderOIDC,
			},
			wantErr: true,
		},
		{
			name: "missing OIDC config",
			config: &SSOConfig{
				Provider: ProviderOIDC,
				Name:     "test",
			},
			wantErr: true,
		},
		{
			name: "missing SAML config",
			config: &SSOConfig{
				Provider: ProviderSAML,
				Name:     "test",
			},
			wantErr: true,
		},
		{
			name: "OIDC missing client ID",
			config: &SSOConfig{
				Provider: ProviderOIDC,
				Name:     "test",
				OIDC: &OIDCConfig{
					RedirectURL: "http://localhost/callback",
					IssuerURL:   "https://accounts.google.com",
				},
			},
			wantErr: true,
		},
		{
			name: "SAML missing entity ID",
			config: &SSOConfig{
				Provider: ProviderSAML,
				Name:     "test",
				SAML: &SAMLConfig{
					ACSURL:      "https://sp.example.com/acs",
					IDPEntityID: "https://idp.example.com",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("SSOConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultSSOConfig(t *testing.T) {
	config := DefaultSSOConfig()

	if config == nil {
		t.Fatal("DefaultSSOConfig() returned nil")
	}

	if config.SessionDuration != 24*time.Hour {
		t.Errorf("Default session duration = %v, want %v", config.SessionDuration, 24*time.Hour)
	}

	if config.CookieName != "sso_session" {
		t.Errorf("Default cookie name = %v, want sso_session", config.CookieName)
	}

	if !config.CookieSecure {
		t.Error("Default cookie secure = false, want true")
	}

	if !config.CookieHTTPOnly {
		t.Error("Default cookie HTTP only = false, want true")
	}
}

func TestSSOSession(t *testing.T) {
	tests := []struct {
		name     string
		session  *SSOSession
		expired  bool
		tokenExp bool
		valid    bool
	}{
		{
			name: "valid session",
			session: &SSOSession{
				ID:        "test-id",
				UserID:    "user-1",
				Active:    true,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
				Provider:  ProviderOIDC,
			},
			expired:  false,
			tokenExp: false,
			valid:    true,
		},
		{
			name: "expired session",
			session: &SSOSession{
				ID:        "test-id",
				UserID:    "user-1",
				Active:    true,
				CreatedAt: time.Now().Add(-2 * time.Hour),
				ExpiresAt: time.Now().Add(-1 * time.Hour),
				Provider:  ProviderOIDC,
			},
			expired:  true,
			tokenExp: false, // No AccessToken set, so IsTokenExpired returns false
			valid:    false,
		},
		{
			name: "inactive session",
			session: &SSOSession{
				ID:        "test-id",
				UserID:    "user-1",
				Active:    false,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
				Provider:  ProviderOIDC,
			},
			expired:  false,
			tokenExp: false,
			valid:    false,
		},
		{
			name: "token needs refresh",
			session: &SSOSession{
				ID:             "test-id",
				UserID:         "user-1",
				Active:         true,
				CreatedAt:      time.Now(),
				ExpiresAt:      time.Now().Add(1 * time.Hour),
				TokenExpiresAt: time.Now().Add(5 * time.Minute),
				RefreshToken:   "refresh-token",
				Provider:       ProviderOIDC,
			},
			expired:  false,
			tokenExp: false,
			valid:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.session.IsExpired(); got != tt.expired {
				t.Errorf("SSOSession.IsExpired() = %v, want %v", got, tt.expired)
			}

			if got := tt.session.IsTokenExpired(); got != tt.tokenExp {
				t.Errorf("SSOSession.IsTokenExpired() = %v, want %v", got, tt.tokenExp)
			}

			if got := tt.session.IsValid(); got != tt.valid {
				t.Errorf("SSOSession.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestSSOSessionRefresh(t *testing.T) {
	session := &SSOSession{
		ID:        "test-id",
		UserID:    "user-1",
		Active:    true,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Provider:  ProviderOIDC,
	}

	originalExpiry := session.ExpiresAt
	session.Refresh(2 * time.Hour)

	if session.ExpiresAt.Before(originalExpiry) {
		t.Error("Refresh() should extend expiry time")
	}

	if session.LastActivity.IsZero() {
		t.Error("Refresh() should update LastActivity")
	}
}

func TestSSOSessionNeedsTokenRefresh(t *testing.T) {
	tests := []struct {
		name    string
		session *SSOSession
		buffer  time.Duration
		want    bool
	}{
		{
			name: "no refresh token",
			session: &SSOSession{
				RefreshToken:   "",
				TokenExpiresAt: time.Now().Add(5 * time.Minute),
			},
			buffer: 10 * time.Minute,
			want:   false,
		},
		{
			name: "token expires within buffer",
			session: &SSOSession{
				RefreshToken:   "refresh-token",
				TokenExpiresAt: time.Now().Add(5 * time.Minute),
			},
			buffer: 10 * time.Minute,
			want:   true,
		},
		{
			name: "token not expiring soon",
			session: &SSOSession{
				RefreshToken:   "refresh-token",
				TokenExpiresAt: time.Now().Add(1 * time.Hour),
			},
			buffer: 10 * time.Minute,
			want:   false,
		},
		{
			name: "zero token expiry",
			session: &SSOSession{
				RefreshToken:   "refresh-token",
				TokenExpiresAt: time.Time{},
			},
			buffer: 10 * time.Minute,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.session.NeedsTokenRefresh(tt.buffer); got != tt.want {
				t.Errorf("SSOSession.NeedsTokenRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSSOError(t *testing.T) {
	tests := []struct {
		name    string
		err     *SSOError
		wantStr string
	}{
		{
			name:    "simple error",
			err:     NewSSOError(ErrInvalidRequest, "test error"),
			wantStr: "invalid_request: test error",
		},
		{
			name:    "error with cause",
			err:     NewSSOError(ErrInvalidToken, "token error").WithCause(context.DeadlineExceeded),
			wantStr: "invalid_token: token error - context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantStr {
				t.Errorf("SSOError.Error() = %v, want %v", got, tt.wantStr)
			}
		})
	}
}

func TestMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore()

	session := &SSOSession{
		ID:        "test-session-id",
		UserID:    "user-1",
		Provider:  ProviderOIDC,
		Active:    true,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		User: &SSOUser{
			ID:    "testuser",
			Email: "test@example.com",
		},
	}

	// Test Create
	if err := store.Create(session); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Test Get
	got, err := store.Get("test-session-id")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("Get() ID = %v, want %v", got.ID, session.ID)
	}

	// Test GetByUserID
	sessions, err := store.GetByUserID("user-1")
	if err != nil {
		t.Fatalf("GetByUserID() error = %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("GetByUserID() returned %d sessions, want 1", len(sessions))
	}

	// Test Update
	session.Active = false
	if err := store.Update(session); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	got, _ = store.Get("test-session-id")
	if got.Active {
		t.Error("Update() did not update Active field")
	}

	// Test Delete
	if err := store.Delete("test-session-id"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = store.Get("test-session-id")
	if err == nil {
		t.Error("Get() should return error after Delete()")
	}
}

func TestMemoryRequestStore(t *testing.T) {
	store := NewMemoryRequestStore()

	request := &SSORequest{
		ID:        "test-request-id",
		Provider:  "test-provider",
		State:     "test-state",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// Test Create
	if err := store.Create(request); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Test Get
	got, err := store.Get("test-request-id")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ID != request.ID {
		t.Errorf("Get() ID = %v, want %v", got.ID, request.ID)
	}

	// Test GetByState
	got, err = store.GetByState("test-state")
	if err != nil {
		t.Fatalf("GetByState() error = %v", err)
	}
	if got.State != request.State {
		t.Errorf("GetByState() State = %v, want %v", got.State, request.State)
	}

	// Test Delete
	if err := store.Delete("test-request-id"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = store.Get("test-request-id")
	if err == nil {
		t.Error("Get() should return error after Delete()")
	}

	_, err = store.GetByState("test-state")
	if err == nil {
		t.Error("GetByState() should return error after Delete()")
	}
}

func TestNewManager(t *testing.T) {
	tests := []struct {
		name    string
		config  *ManagerConfig
		wantErr bool
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name: "custom config",
			config: &ManagerConfig{
				SessionStore:  NewMemorySessionStore(),
				RequestStore:  NewMemoryRequestStore(),
				DefaultConfig: DefaultSSOConfig(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewManager() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && manager == nil {
				t.Error("NewManager() returned nil manager")
			}
		})
	}
}

func TestManagerRegisterProvider(t *testing.T) {
	manager, _ := NewManager(nil)

	// Test registering OIDC provider
	err := manager.RegisterProvider(&SSOConfig{
		Provider: ProviderOIDC,
		Name:     "test-oidc",
		Enabled:  true,
		OIDC: &OIDCConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			IssuerURL:    "https://accounts.google.com",
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			UserInfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		},
	})
	if err != nil {
		t.Fatalf("RegisterProvider() error = %v", err)
	}

	// Test listing providers
	providers := manager.ListProviders()
	if len(providers) != 1 {
		t.Errorf("ListProviders() returned %d providers, want 1", len(providers))
	}

	// Test getting provider
	_, err = manager.GetProvider("test-oidc")
	if err != nil {
		t.Errorf("GetProvider() error = %v", err)
	}

	// Test unregistering
	err = manager.UnregisterProvider("test-oidc")
	if err != nil {
		t.Errorf("UnregisterProvider() error = %v", err)
	}

	// Verify provider is gone
	_, err = manager.GetProvider("test-oidc")
	if err == nil {
		t.Error("GetProvider() should return error after UnregisterProvider()")
	}
}

func TestAttributeMapping(t *testing.T) {
	t.Run("default mapping", func(t *testing.T) {
		mapping := DefaultAttributeMapping()
		if mapping.IDAttribute != "sub" {
			t.Errorf("IDAttribute = %v, want sub", mapping.IDAttribute)
		}
		if mapping.EmailAttribute != "email" {
			t.Errorf("EmailAttribute = %v, want email", mapping.EmailAttribute)
		}
	})

	t.Run("SAML mapping", func(t *testing.T) {
		mapping := SAMLAttributeMapping()
		if mapping.IDAttribute != "nameID" {
			t.Errorf("IDAttribute = %v, want nameID", mapping.IDAttribute)
		}
		if mapping.EmailAttribute != "urn:oid:0.9.2342.19200300.100.1.3" {
			t.Errorf("EmailAttribute = %v, want urn:oid:0.9.2342.19200300.100.1.3", mapping.EmailAttribute)
		}
	})
}

func TestDomainMatches(t *testing.T) {
	tests := []struct {
		email   string
		domain  string
		matches bool
	}{
		{"user@example.com", "example.com", true},
		{"user@example.com", "other.com", false},
		{"user@sub.example.com", "example.com", false},
		{"user@sub.example.com", "sub.example.com", true},
		{"invalid-email", "example.com", false},
		{"", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.email+"_"+tt.domain, func(t *testing.T) {
			if got := domainMatches(tt.email, tt.domain); got != tt.matches {
				t.Errorf("domainMatches(%v, %v) = %v, want %v", tt.email, tt.domain, got, tt.matches)
			}
		})
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	session := &SSOSession{
		ID:     "test-id",
		UserID: "user-1",
	}
	user := &SSOUser{
		ID: "testuser",
	}

	// Test session context
	ctxWithSession := ContextWithSession(ctx, session)
	gotSession := SessionFromContext(ctxWithSession)
	if gotSession == nil {
		t.Error("SessionFromContext() returned nil")
	} else if gotSession.ID != session.ID {
		t.Errorf("SessionFromContext() ID = %v, want %v", gotSession.ID, session.ID)
	}

	// Test user context
	ctxWithUser := ContextWithUser(ctx, user)
	gotUser := UserFromContext(ctxWithUser)
	if gotUser == nil {
		t.Error("UserFromContext() returned nil")
	} else if gotUser.ID != user.ID {
		t.Errorf("UserFromContext() ID = %v, want %v", gotUser.ID, user.ID)
	}

	// Test nil returns
	if got := SessionFromContext(ctx); got != nil {
		t.Error("SessionFromContext(empty) should return nil")
	}
	if got := UserFromContext(ctx); got != nil {
		t.Error("UserFromContext(empty) should return nil")
	}
}

func TestMemorySessionStoreCleanup(t *testing.T) {
	store := NewMemorySessionStore()

	// Add expired and active sessions
	expiredSession := &SSOSession{
		ID:        "expired-id",
		UserID:    "user-1",
		Active:    true,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	activeSession := &SSOSession{
		ID:        "active-id",
		UserID:    "user-2",
		Active:    true,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	_ = store.Create(expiredSession)
	_ = store.Create(activeSession)

	// Cleanup
	if err := store.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	// Verify expired session is gone
	_, err := store.Get("expired-id")
	if err == nil {
		t.Error("Expired session should be removed by Cleanup()")
	}

	// Verify active session remains
	_, err = store.Get("active-id")
	if err != nil {
		t.Error("Active session should still exist after Cleanup()")
	}
}

func TestManagerStats(t *testing.T) {
	manager, _ := NewManager(nil)

	// Register a provider
	_ = manager.RegisterProvider(&SSOConfig{
		Provider: ProviderOIDC,
		Name:     "test-oidc",
		Enabled:  true,
		OIDC: &OIDCConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			IssuerURL:    "https://accounts.google.com",
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			UserInfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		},
	})

	stats, err := manager.Stats()
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}

	if stats.Providers != 1 {
		t.Errorf("Stats() Providers = %v, want 1", stats.Providers)
	}
}
