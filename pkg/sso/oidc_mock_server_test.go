package sso

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test mock server context functionality
func TestMockOIDCServerContext(t *testing.T) {
	server := NewMockOIDCServer()
	defer server.Close()

	ctx := server.Context()
	if ctx == nil {
		t.Error("Context() returned nil")
	}
}

// Test CreateValidTokenResponse
func TestMockOIDCServerCreateValidTokenResponse(t *testing.T) {
	server := NewMockOIDCServer()
	defer server.Close()

	resp := server.CreateValidTokenResponse()
	if resp == nil {
		t.Error("CreateValidTokenResponse() returned nil")
	}
}

// Test handleJWKS - verify JWKS endpoint works
func TestMockOIDCServerHandleJWKS(t *testing.T) {
	server := NewMockOIDCServer()
	defer server.Close()

	// Make HTTP request to JWKS endpoint
	req := httptest.NewRequest("GET", server.Server.URL+"/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()

	// Call the mux directly
	server.Server.Config.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("JWKS returned %d, want 200", rr.Code)
	}
}

// Test handleAuthorize - verify authorize endpoint works
func TestMockOIDCServerHandleAuthorize(t *testing.T) {
	server := NewMockOIDCServer()
	defer server.Close()

	// Make HTTP request to authorize endpoint with params
	req := httptest.NewRequest("GET", server.AuthURL+"?client_id=test&redirect_uri=http://localhost/callback&response_type=code&state=test", nil)
	rr := httptest.NewRecorder()

	server.Server.Config.Handler.ServeHTTP(rr, req)

	// Should redirect or return auth code
	if rr.Code != http.StatusFound && rr.Code != http.StatusOK {
		t.Errorf("Authorize returned %d, want 302 or 200", rr.Code)
	}
}

func TestMockOIDCServerHandleTokenBasic(t *testing.T) {
	server := NewMockOIDCServer()
	defer server.Close()

	// Test with POST to token endpoint
	req := httptest.NewRequest("POST", server.Server.URL+"/token", nil)
	rr := httptest.NewRecorder()
	server.handleToken(rr, req)

	// Just verify it doesn't panic
	t.Logf("handleToken returned status: %d", rr.Code)
}
