package sso

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test SAML mock server creation
func TestMockSAMLServerCreation(t *testing.T) {
	server, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("NewMockSAMLServer() error: %v", err)
	}
	defer server.Close()

	if server == nil {
		t.Fatal("NewMockSAMLServer() returned nil")
	}
	if server.EntityID == "" {
		t.Error("EntityID should not be empty")
	}
	if server.SLOURL == "" {
		t.Error("SLOURL should not be empty")
	}
	if server.Certificate == nil {
		t.Error("Certificate should not be nil")
	}
}

// Test SAML mock server SLO endpoint via direct handler
func TestMockSAMLServerHandleSLO(t *testing.T) {
	server, err := NewMockSAMLServer()
	if err != nil {
		t.Fatalf("NewMockSAMLServer() error: %v", err)
	}
	defer server.Close()

	// Make direct request to SLO endpoint
	req := httptest.NewRequest("GET", server.SLOURL, nil)
	rr := httptest.NewRecorder()

	// Access the handler via mux
	server.Server.Config.Handler.ServeHTTP(rr, req)

	// SLO should return 302 redirect
	if rr.Code != http.StatusFound && rr.Code != http.StatusOK {
		t.Errorf("SLO returned %d, want 302", rr.Code)
	}
}
