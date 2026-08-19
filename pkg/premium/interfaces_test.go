// SPDX-License-Identifier: Apache-2.0
package premium

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoopSIEMFactory(t *testing.T) {
	f := SIEMDispatcherFactoryInstance()
	disp, err := f.New(SIEMDispatcherConfig{})
	if err == nil {
		t.Fatal("expected ErrEnterpriseOnly, got nil")
	}
	if disp != nil {
		t.Fatal("expected nil dispatcher in community edition")
	}
	if err.Error() == "" {
		t.Fatal("error should have a message")
	}
}

func TestErrEnterpriseOnly(t *testing.T) {
	if ErrEnterpriseOnly.Error() == "" {
		t.Fatal("ErrEnterpriseOnly should have a message")
	}
	expected := "feature requires enterprise license — see https://aegisgate.dev/pricing for details"
	if ErrEnterpriseOnly.Error() != expected {
		t.Fatalf("error message = %q, want %q", ErrEnterpriseOnly.Error(), expected)
	}
}

func TestNoopTrustProvider(t *testing.T) {
	p := TrustProviderInstance()
	mgr, err := p.NewManager(nil)
	if err == nil {
		t.Fatal("expected ErrEnterpriseOnly, got nil")
	}
	if mgr != nil {
		t.Fatal("expected nil manager in community edition")
	}
}

func TestNoopTrustManager(t *testing.T) {
	// Verify the noopTrustManager methods all return errors
	var mgr TrustManager = noopTrustManager{}

	_, err := mgr.StartSession(context.Background(), "agent-1")
	if err == nil {
		t.Fatal("StartSession should fail in community edition")
	}

	_, err = mgr.GetSession("sess-1")
	if err == nil {
		t.Fatal("GetSession should fail in community edition")
	}

	err = mgr.RecordEvent(context.Background(), "sess-1", "test", nil)
	if err == nil {
		t.Fatal("RecordEvent should fail in community edition")
	}

	_, err = mgr.AgentScore("agent-1")
	if err == nil {
		t.Fatal("AgentScore should fail in community edition")
	}

	err = mgr.Close()
	if err != nil {
		t.Fatalf("Close should succeed, got %v", err)
	}
}

func TestNoopTrustPortalHandler(t *testing.T) {
	h := TrustPortalHandlerInstance()

	mux := http.NewServeMux()
	h.Wire(mux)

	req := httptest.NewRequest("GET", "/trust", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "enterprise_required" {
		t.Fatalf("status = %q, want %q", resp["status"], "enterprise_required")
	}
}

func TestRegistration(t *testing.T) {
	// Save originals
	origSIEM := siemDispatcherFactory
	origTrust := trustProvider
	origPortal := trustPortalHandler
	defer func() {
		siemDispatcherFactory = origSIEM
		trustProvider = origTrust
		trustPortalHandler = origPortal
	}()

	// Register custom factory
	custom := customSIEMFactory{}
	RegisterSIEMDispatcherFactory(custom)

	if SIEMDispatcherFactoryInstance() != custom {
		t.Fatal("custom factory not registered")
	}

	// Register custom trust provider
	customTrust := customTrustProvider{}
	RegisterTrustProvider(customTrust)

	if TrustProviderInstance() != customTrust {
		t.Fatal("custom trust provider not registered")
	}

	// Register custom portal handler
	customPortal := customPortalHandler{}
	RegisterTrustPortalHandler(customPortal)

	if TrustPortalHandlerInstance() != customPortal {
		t.Fatal("custom portal handler not registered")
	}
}

// Test types for registration test

type customSIEMFactory struct{}

func (customSIEMFactory) New(SIEMDispatcherConfig) (SIEMDispatcher, error) {
	return noopSIEMDispatcher{}, nil
}

type customTrustProvider struct{}

func (customTrustProvider) NewManager(interface{}) (TrustManager, error) {
	return noopTrustManager{}, nil
}

type customPortalHandler struct{}

func (customPortalHandler) Wire(*http.ServeMux) {}
