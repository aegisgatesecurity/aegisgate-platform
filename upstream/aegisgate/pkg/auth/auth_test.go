package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDefaultConfig tests default configuration
func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.SessionDuration != 24*time.Hour {
		t.Errorf("Expected session duration 24h, got %v", config.SessionDuration)
	}

	if config.CookieName != "aegisgate_session" {
		t.Errorf("Expected cookie name 'aegisgate_session', got %s", config.CookieName)
	}

	if !config.CookieSecure {
		t.Error("Expected CookieSecure to be true")
	}

	if !config.CookieHTTPOnly {
		t.Error("Expected CookieHTTPOnly to be true")
	}

	if config.MaxSessions != 1000 {
		t.Errorf("Expected max sessions 1000, got %d", config.MaxSessions)
	}
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	// Test empty provider
	config := &Config{}
	if err := config.Validate(); err == nil {
		t.Error("Expected error for empty provider")
	}

	// Test local auth without users
	config.Provider = ProviderLocal
	if err := config.Validate(); err == nil {
		t.Error("Expected error for local auth without users")
	}

	// Test local auth with users
	config.LocalUsers = map[string]LocalUserConfig{
		"admin": {PasswordHash: "hash", Salt: "salt", Role: RoleAdmin, Enabled: true},
	}
	if err := config.Validate(); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test OAuth without credentials
	config.Provider = ProviderGoogle
	config.LocalUsers = nil
	if err := config.Validate(); err == nil {
		t.Error("Expected error for OAuth without client ID")
	}

	// Test OAuth with credentials
	config.ClientID = "test-id"
	config.ClientSecret = "test-secret"
	config.RedirectURL = "http://localhost/callback"
	if err := config.Validate(); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestNewManager tests manager creation
func TestNewManager(t *testing.T) {
	config := &Config{
		Provider: ProviderLocal,
		LocalUsers: map[string]LocalUserConfig{
			"test": {
				PasswordHash: hashPassword("password", "salt"),
				Salt:         "salt",
				Role:         RoleAdmin,
				Enabled:      true,
			},
		},
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Close()

	if manager == nil {
		t.Fatal("Manager is nil")
	}

	if manager.GetConfig().Provider != ProviderLocal {
		t.Error("Manager has wrong provider")
	}
}

// TestSessionManagement tests session creation and retrieval
func TestSessionManagement(t *testing.T) {
	config := &Config{
		Provider:        ProviderLocal,
		SessionDuration: 1 * time.Hour,
		CookieName:      "test_session",
		MaxSessions:     100,
		LocalUsers: map[string]LocalUserConfig{
			"test": {PasswordHash: "hash", Salt: "salt", Role: RoleViewer, Enabled: true},
		},
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Close()

	// Create a user
	user := &User{
		ID:            "user_123",
		Email:         "test@example.com",
		Name:          "Test User",
		Provider:      ProviderLocal,
		ProviderID:    "test",
		Role:          RoleViewer,
		Authenticated: true,
	}

	// Create a request
	req := httptest.NewRequest("GET", "/", nil)

	// Create session
	session, err := manager.CreateSession(user, req)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if session.ID == "" {
		t.Error("Session ID is empty")
	}

	if session.UserID != user.ID {
		t.Error("Session user ID mismatch")
	}

	// Retrieve session
	retrieved, err := manager.GetSession(session.ID)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrieved.ID != session.ID {
		t.Error("Retrieved session ID mismatch")
	}

	// Test IsValid
	if !session.IsValid() {
		t.Error("Session should be valid")
	}

	// Test GetActiveSessions
	active := manager.GetActiveSessions()
	if len(active) != 1 {
		t.Errorf("Expected 1 active session, got %d", len(active))
	}
}

// TestLocalLogin tests local authentication
func TestLocalLogin(t *testing.T) {
	config := DefaultConfig()
	config.Provider = ProviderLocal
	config.MaxSessions = 100
	config.LocalUsers = map[string]LocalUserConfig{
		"admin": {
			PasswordHash: hashPassword("secret123", "salt"),
			Salt:         "salt",
			Role:         RoleAdmin,
			Enabled:      true,
		},
	}

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Close()

	// Test successful login
	formData := strings.NewReader("username=admin&password=secret123")
	req := httptest.NewRequest("POST", "/auth/local/login", formData)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	manager.LocalLogin(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect (302), got %d", w.Code)
	}

	// Check for session cookie in response header (httptest.ResponseRecorder doesn't capture cookies from redirect properly)
	cookieHeader := w.Header().Get("Set-Cookie")
	if cookieHeader == "" {
		t.Error("Expected session cookie in Set-Cookie header")
	}
	if !strings.Contains(cookieHeader, "aegisgate_session") {
		t.Errorf("Expected cookie name 'aegisgate_session', got: %s", cookieHeader)
	}
}

// TestUserPermissions tests role-based permissions
func TestUserPermissions(t *testing.T) {
	admin := &User{
		Role:        RoleAdmin,
		Permissions: RolePermissions[RoleAdmin],
	}

	if !admin.HasPermission(PermManageUsers) {
		t.Error("Admin should have manage:users permission")
	}

	if !admin.HasPermission(PermSystemConfig) {
		t.Error("Admin should have system:config permission")
	}

	viewer := &User{
		Role:        RoleViewer,
		Permissions: RolePermissions[RoleViewer],
	}

	if viewer.HasPermission(PermManageUsers) {
		t.Error("Viewer should NOT have manage:users permission")
	}

	if !viewer.HasPermission(PermViewDashboard) {
		t.Error("Viewer should have view:dashboard permission")
	}
}

// TestPasswordHashing tests password hashing
func TestPasswordHashing(t *testing.T) {
	password := "mysecretpassword"
	salt := "randomsalt"

	hash1 := hashPassword(password, salt)
	hash2 := hashPassword(password, salt)

	if hash1 != hash2 {
		t.Error("Same password and salt should produce same hash")
	}

	hash3 := hashPassword(password, "differentsalt")
	if hash1 == hash3 {
		t.Error("Different salt should produce different hash")
	}

	// Test constant time compare
	if !constantTimeCompare(hash1, hash2) {
		t.Error("Constant time compare should return true for equal hashes")
	}

	if constantTimeCompare(hash1, hash3) {
		t.Error("Constant time compare should return false for different hashes")
	}
}

// TestEmailValidation tests email validation
func TestEmailValidation(t *testing.T) {
	validEmails := []string{
		"user@example.com",
		"test.user@domain.co.uk",
		"user+tag@example.org",
	}

	for _, email := range validEmails {
		if !validateEmail(email) {
			t.Errorf("Expected %s to be valid", email)
		}
	}

	invalidEmails := []string{
		"notanemail",
		"@example.com",
		"user@",
		"user@.com",
	}

	for _, email := range invalidEmails {
		if validateEmail(email) {
			t.Errorf("Expected %s to be invalid", email)
		}
	}
}

// TestExtractDomain tests domain extraction from email
func TestExtractDomain(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"user@example.com", "example.com"},
		{"test@sub.domain.co.uk", "sub.domain.co.uk"},
		{"invalid", ""},
		{"@nodomain.com", ""},
	}

	for _, test := range tests {
		result := extractDomain(test.email)
		if result != test.expected {
			t.Errorf("extractDomain(%s) = %s, expected %s", test.email, result, test.expected)
		}
	}
}

// TestSessionExpiration tests session expiration
func TestSessionExpiration(t *testing.T) {
	// Create an expired session
	session := &Session{
		ID:        "test",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		Active:    true,
	}

	if !session.IsExpired() {
		t.Error("Session should be expired")
	}

	if session.IsValid() {
		t.Error("Expired session should not be valid")
	}

	// Create a valid session
	session2 := &Session{
		ID:        "test2",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Active:    true,
	}

	if session2.IsExpired() {
		t.Error("Session should not be expired")
	}

	if !session2.IsValid() {
		t.Error("Valid session should be valid")
	}

	// Test inactive session
	session2.Active = false
	if session2.IsValid() {
		t.Error("Inactive session should not be valid")
	}
}

// TestDomainAllowlist tests domain filtering
func TestDomainAllowlist(t *testing.T) {
	config := &Config{
		Provider:       ProviderGoogle,
		ClientID:       "test",
		ClientSecret:   "test",
		RedirectURL:    "http://localhost/callback",
		AllowedDomains: []string{"example.com", "company.org"},
		BlockedDomains: []string{"blocked.com"},
	}

	manager, _ := NewManager(config)
	defer manager.Close()

	// Test allowed domain
	if !manager.isAllowedDomain("user@example.com") {
		t.Error("example.com should be allowed")
	}

	// Test blocked domain
	if manager.isAllowedDomain("user@blocked.com") {
		t.Error("blocked.com should be blocked")
	}

	// Test unknown domain (should be blocked when allowlist is set)
	if manager.isAllowedDomain("user@other.com") {
		t.Error("other.com should be blocked when allowlist is set")
	}
}

// TestPKCE tests PKCE generation
func TestPKCE(t *testing.T) {
	verifier, err := generatePKCEVerifier()
	if err != nil {
		t.Fatalf("Failed to generate PKCE verifier: %v", err)
	}

	if verifier == "" {
		t.Error("PKCE verifier should not be empty")
	}

	challenge := generatePKCEChallenge(verifier)
	if challenge == "" {
		t.Error("PKCE challenge should not be empty")
	}

	// Same verifier should produce same challenge
	challenge2 := generatePKCEChallenge(verifier)
	if challenge != challenge2 {
		t.Error("Same verifier should produce same challenge")
	}

	// Different verifier should produce different challenge
	verifier2, _ := generatePKCEVerifier()
	challenge3 := generatePKCEChallenge(verifier2)
	if challenge == challenge3 {
		t.Error("Different verifiers should produce different challenges")
	}
}
