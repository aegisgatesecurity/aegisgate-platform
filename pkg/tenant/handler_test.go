// SPDX-License-Identifier: Apache-2.0

package tenant

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerList(t *testing.T) {
	m := NewManager()
	m.Create("A", "A Co", "", "community", 1, 1)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	var resp map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&resp)
	if int(resp["count"].(float64)) != 1 {
		t.Errorf("count: got %v, want 1", resp["count"])
	}
}

func TestHandlerCreate(t *testing.T) {
	m := NewManager()
	body := `{"name":"Test","displayName":"Test Co","licenseTier":"professional","maxUsers":50}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/tenants", strings.NewReader(body))
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != 201 {
		t.Fatalf("status: got %d, want 201", rec.Code)
	}
	var tnt Tenant
	json.NewDecoder(rec.Body).Decode(&tnt)
	if tnt.Name != "Test" {
		t.Errorf("name: got %q, want %q", tnt.Name, "Test")
	}
}

func TestHandlerCreateInvalidJSON(t *testing.T) {
	m := NewManager()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/tenants", strings.NewReader("bad json"))
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("status: got %d, want 400", rec.Code)
	}
}

func TestHandlerGet(t *testing.T) {
	m := NewManager()
	tnt, _ := m.Create("Test", "Test Co", "", "", 0, 0)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/tenants/"+tnt.ID, nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	var got Tenant
	json.NewDecoder(rec.Body).Decode(&got)
	if got.ID != tnt.ID {
		t.Errorf("ID: got %q, want %q", got.ID, tnt.ID)
	}
}

func TestHandlerGetNotFound(t *testing.T) {
	m := NewManager()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/tenants/bogus", nil)
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("status: got %d, want 404", rec.Code)
	}
}

func TestHandlerUpdate(t *testing.T) {
	m := NewManager()
	tnt, _ := m.Create("Old", "Old Name", "", "", 0, 0)
	body := `{"name":"New","active":false}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/v1/tenants/"+tnt.ID, strings.NewReader(body))
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	var got Tenant
	json.NewDecoder(rec.Body).Decode(&got)
	if got.Name != "New" {
		t.Errorf("name: got %q, want %q", got.Name, "New")
	}
	if got.Active {
		t.Error("expected active=false")
	}
}

func TestHandlerDelete(t *testing.T) {
	m := NewManager()
	tnt, _ := m.Create("Delete", "Delete Me", "", "", 0, 0)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/api/v1/tenants/"+tnt.ID, nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != 204 {
		t.Fatalf("status: got %d, want 204", rec.Code)
	}
	if m.Count() != 0 {
		t.Errorf("expected 0 tenants, got %d", m.Count())
	}
}

func TestHandlerMethodNotAllowed(t *testing.T) {
	m := NewManager()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PATCH", "/api/v1/tenants", nil)
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != 405 {
		t.Fatalf("status: got %d, want 405", rec.Code)
	}
}
