// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — RBAC Middleware Tests (Chunk 1)

package rbac

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testMiddleware(t *testing.T) (*Manager, *RBACMiddleware) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.SessionDuration = 1 * time.Hour
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	m.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	rm := NewRBACMiddleware(m)
	rm.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return m, rm
}

func registerAgentAndSession(m *Manager, role AgentRole, t *testing.T) (*Agent, *AgentSession) {
	t.Helper()
	a := &Agent{
		ID:      "mid-agent",
		Name:    "Middleware Agent",
		Role:    role,
		Enabled: true,
		Tools:   GetPermissionsForRole(role),
		Tags:    map[string]string{},
	}
	if err := m.RegisterAgent(a); err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	s, err := m.CreateSession(context.Background(), a.ID)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return a, s
}

func TestNewRBACMiddleware(t *testing.T) {
	m, rm := testMiddleware(t)
	defer m.Close()

	if rm.manager != m {
		t.Error("RBACMiddleware.manager not set correctly")
	}
	if rm.logger == nil {
		t.Error("RBACMiddleware.logger is nil")
	}
}

func TestRBACMiddleware_RequireRole(t *testing.T) {
	m, rm := testMiddleware(t)
	defer m.Close()
	_, s := registerAgentAndSession(m, AgentRoleStandard, t)

	pass := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}

	// Authorized
	handler := rm.RequireRole(AgentRoleRestricted)(pass)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	r = r.WithContext(ContextWithSession(r.Context(), s))
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("RequireRole allowed = %d, want 200", w.Code)
	}

	// Insufficient role
	handler2 := rm.RequireRole(AgentRolePrivileged)(pass)
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	r2 = r2.WithContext(ContextWithSession(r2.Context(), s))
	handler2.ServeHTTP(w2, r2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("RequireRole denied = %d, want 403", w2.Code)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(w2.Body.Bytes(), &body)
	if body["error"] != "forbidden" {
		t.Errorf("error key = %v, want forbidden", body["error"])
	}

	// No session in context
	handler3 := rm.RequireRole(AgentRoleRestricted)(pass)
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	w3 := httptest.NewRecorder()
	handler3.ServeHTTP(w3, r3)
	if w3.Code != http.StatusForbidden {
		t.Errorf("RequireRole no session = %d, want 403", w3.Code)
	}
}

func TestRBACMiddleware_RequirePermission(t *testing.T) {
	m, rm := testMiddleware(t)
	defer m.Close()
	_, s := registerAgentAndSession(m, AgentRoleStandard, t)

	pass := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// Has permission
	handler := rm.RequirePermission(PermToolFileRead)(pass)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	r = r.WithContext(ContextWithSession(r.Context(), s))
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("RequirePermission allowed = %d, want 200", w.Code)
	}

	// Missing permission
	handler2 := rm.RequirePermission(PermToolShellCommand)(pass)
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	r2 = r2.WithContext(ContextWithSession(r2.Context(), s))
	handler2.ServeHTTP(w2, r2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("RequirePermission denied = %d, want 403", w2.Code)
	}

	// No session
	handler3 := rm.RequirePermission(PermToolFileRead)(pass)
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	w3 := httptest.NewRecorder()
	handler3.ServeHTTP(w3, r3)
	if w3.Code != http.StatusForbidden {
		t.Errorf("RequirePermission no session = %d, want 403", w3.Code)
	}
}

func TestRBACMiddleware_RequireToolPermission(t *testing.T) {
	m, rm := testMiddleware(t)
	defer m.Close()
	_, s := registerAgentAndSession(m, AgentRoleStandard, t)

	pass := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// Allowed
	handler := rm.RequireToolPermission("file_write")(pass)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	r = r.WithContext(ContextWithSession(r.Context(), s))
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("RequireToolPermission allowed = %d, want 200", w.Code)
	}

	// Denied
	handler2 := rm.RequireToolPermission("shell_command")(pass)
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	r2 = r2.WithContext(ContextWithSession(r2.Context(), s))
	handler2.ServeHTTP(w2, r2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("RequireToolPermission denied = %d, want 403", w2.Code)
	}

	// No session
	handler3 := rm.RequireToolPermission("file_read")(pass)
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	w3 := httptest.NewRecorder()
	handler3.ServeHTTP(w3, r3)
	if w3.Code != http.StatusForbidden {
		t.Errorf("RequireToolPermission no session = %d, want 403", w3.Code)
	}
}

func TestRBACMiddleware_InjectRBACContext(t *testing.T) {
	m, rm := testMiddleware(t)
	defer m.Close()
	_, s := registerAgentAndSession(m, AgentRoleStandard, t)

	pass := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	// a) Session ID in context
	handler := rm.InjectRBACContext(pass)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ctx := context.WithValue(r.Context(), CtxKeySessionID, s.ID)
	handler.ServeHTTP(w, r.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Errorf("InjectRBACContext context = %d, want 200", w.Code)
	}

	// b) Session ID in header
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Session-ID", s.ID)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("InjectRBACContext header = %d, want 200", w2.Code)
	}

	// c) Session ID in query param
	r3 := httptest.NewRequest(http.MethodGet, "/?session_id="+s.ID, nil)
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, r3)
	if w3.Code != http.StatusOK {
		t.Errorf("InjectRBACContext query = %d, want 200", w3.Code)
	}

	// d) No session ID anywhere
	r4 := httptest.NewRequest(http.MethodGet, "/", nil)
	w4 := httptest.NewRecorder()
	handler.ServeHTTP(w4, r4)
	if w4.Code != http.StatusOK {
		t.Errorf("InjectRBACContext none = %d, want 200", w4.Code)
	}

	// e) Session ID present but not found
	r5 := httptest.NewRequest(http.MethodGet, "/", nil)
	r5.Header.Set("X-Session-ID", "nonexistent")
	w5 := httptest.NewRecorder()
	handler.ServeHTTP(w5, r5)
	if w5.Code != http.StatusOK {
		t.Errorf("InjectRBACContext notfound = %d, want 200", w5.Code)
	}
}

func TestGetSessionFromContext(t *testing.T) {
	s := &AgentSession{ID: "s1"}
	ctx := ContextWithSession(context.Background(), s)
	got, err := GetSessionFromContext(ctx)
	if err != nil {
		t.Fatalf("GetSessionFromContext: %v", err)
	}
	if got.ID != s.ID {
		t.Errorf("session ID = %v, want %v", got.ID, s.ID)
	}

	_, err = GetSessionFromContext(context.Background())
	if err == nil {
		t.Error("GetSessionFromContext should error when missing")
	}
}

func TestGetAgentFromContext(t *testing.T) {
	a := &Agent{ID: "a1"}
	ctx := ContextWithAgent(context.Background(), a)
	got, err := GetAgentFromContext(ctx)
	if err != nil {
		t.Fatalf("GetAgentFromContext: %v", err)
	}
	if got.ID != a.ID {
		t.Errorf("agent ID = %v, want %v", got.ID, a.ID)
	}

	_, err = GetAgentFromContext(context.Background())
	if err == nil {
		t.Error("GetAgentFromContext should error when missing")
	}
}

func TestContextWithSession(t *testing.T) {
	s := &AgentSession{ID: "s2"}
	ctx := ContextWithSession(context.Background(), s)
	got, ok := ctx.Value(CtxKeyAgentSession).(*AgentSession)
	if !ok || got.ID != s.ID {
		t.Error("ContextWithSession did not store session correctly")
	}
}

func TestContextWithAgent(t *testing.T) {
	a := &Agent{ID: "a2"}
	ctx := ContextWithAgent(context.Background(), a)
	got, ok := ctx.Value(CtxKeyAgent).(*Agent)
	if !ok || got.ID != a.ID {
		t.Error("ContextWithAgent did not store agent correctly")
	}
}

func Test_writeForbidden(t *testing.T) {
	w := httptest.NewRecorder()
	writeForbidden(w, "nope", "viewer")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %v, want application/json", ct)
	}
	var body errorResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error != "forbidden" {
		t.Errorf("error = %v, want forbidden", body.Error)
	}
	if body.Message != "nope" {
		t.Errorf("message = %v, want nope", body.Message)
	}
	if body.Tier != "viewer" {
		t.Errorf("tier = %v, want viewer", body.Tier)
	}
}
