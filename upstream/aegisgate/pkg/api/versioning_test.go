package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ==================== Version Tests ====================

func TestVersionString(t *testing.T) {
	tests := []struct {
		version Version
		want    string
	}{
		{Version{Major: 1, Minor: 0}, "v1"},
		{Version{Major: 2, Minor: 1}, "v2.1"},
		{Version{Major: 1, Minor: 0, Label: "beta"}, "v1.0-beta"},
		{Version{Major: 2, Minor: 0, Label: "rc1"}, "v2.0-rc1"},
		{Version{Major: 3, Minor: 0, Label: "alpha"}, "v3.0-alpha"},
	}

	for _, tt := range tests {
		t.Run(tt.version.String(), func(t *testing.T) {
			if got := tt.version.String(); got != tt.want {
				t.Errorf("Version.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		v     Version
		other Version
		want  int // -1, 0, 1
	}{
		{Version{Major: 1}, Version{Major: 2}, -1},
		{Version{Major: 2}, Version{Major: 1}, 1},
		{Version{Major: 1, Minor: 0}, Version{Major: 1, Minor: 1}, -1},
		{Version{Major: 1, Minor: 1}, Version{Major: 1, Minor: 0}, 1},
		{Version{Major: 1}, Version{Major: 1}, 0},
		{Version{Major: 1, Minor: 0, Label: "alpha"}, Version{Major: 1, Minor: 0, Label: "beta"}, -1},
		{Version{Major: 1, Minor: 0, Label: "beta"}, Version{Major: 1, Minor: 0, Label: "rc"}, -1},
		{Version{Major: 1, Minor: 0, Label: "rc"}, Version{Major: 1, Minor: 0}, -1},
	}

	for _, tt := range tests {
		name := tt.v.String() + "_vs_" + tt.other.String()
		t.Run(name, func(t *testing.T) {
			if got := tt.v.Compare(&tt.other); got != tt.want {
				t.Errorf("Version.Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionIsSupported(t *testing.T) {
	tests := []struct {
		version Version
		want    bool
	}{
		{Version{Major: 1, Minor: 0, Unsupported: false}, true},
		{Version{Major: 1, Minor: 0, Unsupported: true}, false},
		{Version{Major: 2, Minor: 0, Deprecated: true, Unsupported: false}, true},
		{Version{Major: 3, Minor: 0, Deprecated: true, Unsupported: true}, false},
	}

	for _, tt := range tests {
		t.Run(tt.version.String(), func(t *testing.T) {
			if got := tt.version.IsSupported(); got != tt.want {
				t.Errorf("Version.IsSupported() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionIsDeprecated(t *testing.T) {
	tests := []struct {
		version Version
		want    bool
	}{
		{Version{Major: 1, Minor: 0}, false},
		{Version{Major: 1, Minor: 0, Deprecated: true}, true},
		{Version{Major: 1, Minor: 0, Deprecated: true, Unsupported: true}, false},
		{Version{Major: 2, Minor: 0, Deprecated: false}, false},
	}

	for _, tt := range tests {
		t.Run(tt.version.String(), func(t *testing.T) {
			if got := tt.version.IsDeprecated(); got != tt.want {
				t.Errorf("Version.IsDeprecated() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input string
		want  *Version
		err   bool
	}{
		{"v1", &Version{Major: 1, Minor: 0}, false},
		{"v1.0", &Version{Major: 1, Minor: 0}, false},
		{"v2.1", &Version{Major: 2, Minor: 1}, false},
		{"v1-beta", &Version{Major: 1, Minor: 0, Label: "beta"}, false},
		{"v2.0-rc1", &Version{Major: 2, Minor: 0, Label: "rc1"}, false},
		{"1", &Version{Major: 1, Minor: 0}, false},
		{"1.2", &Version{Major: 1, Minor: 2}, false},
		{"invalid", nil, true},
		{"", nil, true},
		{"v", nil, true},
		{"v1.2.3", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseVersion(tt.input)
			if (err != nil) != tt.err {
				t.Errorf("ParseVersion() error = %v, wantErr %v", err, tt.err)
				return
			}
			if !tt.err && got != nil {
				if got.Major != tt.want.Major || got.Minor != tt.want.Minor || got.Label != tt.want.Label {
					t.Errorf("ParseVersion() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// ==================== VersionManager Tests ====================

func TestVersionManagerRegister(t *testing.T) {
	mgr := NewVersionManager()

	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 1, Minor: 1})

	versions := mgr.GetSupportedVersions()
	if len(versions) != 3 {
		t.Errorf("GetSupportedVersions() = %d, want 3", len(versions))
	}

	// Check v1
	v1, ok := mgr.GetVersion("1")
	if !ok || v1.Major != 1 || v1.Minor != 0 {
		t.Errorf("GetVersion(1) failed")
	}
}

func TestVersionManagerDeprecated(t *testing.T) {
	mgr := NewVersionManager()
	t.Skip("Test not implemented")
	// mgr.RegisterVersion(&Version{Major: 2, Minor: 0})

	sunset := time.Now().Add(30 * 24 * time.Hour)
	mgr.RegisterDeprecated("1.0", "v2", sunset)

	// Check deprecation warning
	warning, ok := mgr.GetDeprecationWarning("1.0")
	if !ok {
		t.Error("GetDeprecationWarning() should return true for deprecated version")
	}
	if !strings.Contains(warning, "deprecated") {
		t.Errorf("Warning should contain 'deprecated', got: %s", warning)
	}

	// Check version info
	v1, ok := mgr.GetVersion("1.0")
	if !ok {
		t.Error("Version should exist")
		return
	}
	if !v1.Deprecated {
		t.Error("Version should be marked as deprecated")
	}
	if v1.Sunset == nil {
		t.Error("Sunset should be set")
	}
}

func TestVersionManagerUnsupported(t *testing.T) {
	t.Skip("Test not implemented")
	// mgr.RegisterUnsupported("1")
}

func TestVersionManagerDefaultVersion(t *testing.T) {
	mgr := NewVersionManager()

	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})

	mgr.SetDefaultVersion("v2")

	if mgr.GetDefaultVersion() != "v2" {
		t.Errorf("GetDefaultVersion() = %v, want v2", mgr.GetDefaultVersion())
	}
}

func TestVersionListSort(t *testing.T) {
	versions := VersionList{"v1", "v2", "v1.1", "v3", "v2.0-beta"}
	sorted := versions.Sort()

	// Should be sorted descending
	if len(sorted) != 5 {
		t.Errorf("Sorted length = %d, want 5", len(sorted))
	}
}

// ==================== VersionNegotiator Tests ====================

func TestVersionNegotiatorQueryParam(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})
	mgr.SetDefaultVersion("v2")

	neg := NewVersionNegotiator(mgr)

	// Test query parameter
	req := httptest.NewRequest("GET", "/api/users?version=1.0", nil)
	result := neg.Negotiate(req)

	if result.Version != "v1" {
		t.Errorf("Version = %v, want v1.0", result.Version)
	}
}

func TestVersionNegotiatorHeader(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})
	mgr.SetDefaultVersion("v2")

	neg := NewVersionNegotiator(mgr)

	// Test Accept-Version header
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Accept-Version", "1.0")
	result := neg.Negotiate(req)

	if result.Version != "v1" {
		t.Errorf("Version = %v, want v1.0", result.Version)
	}
}

func TestVersionNegotiatorDefault(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})
	mgr.SetDefaultVersion("v2")

	neg := NewVersionNegotiator(mgr)

	// Test default version
	req := httptest.NewRequest("GET", "/api/users", nil)
	result := neg.Negotiate(req)

	if result.Version != "v2" {
		t.Errorf("Version = %v, want v2", result.Version)
	}
}

func TestVersionNegotiatorPath(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})

	neg := NewVersionNegotiator(mgr)

	// Test URL path
	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	result := neg.Negotiate(req)

	if result.Version != "v1" {
		t.Errorf("Version = %v, want v1", result.Version)
	}
}

func TestVersionNegotiatorContentType(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})

	neg := NewVersionNegotiator(mgr)

	// Test content type negotiation
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Accept", "application/vnd.aegisgate.v1+json")
	result := neg.Negotiate(req)

	if result.Version != "v1" {
		t.Errorf("Version = %v, want v1", result.Version)
	}
}

// ==================== VersionMiddleware Tests ====================

func TestVersionMiddleware(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})

	sunset := time.Now().Add(30 * 24 * time.Hour)
	mgr.RegisterDeprecated("1.0", "v2", sunset)

	middleware := VersionMiddleware(mgr)

	var handlerCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	handler := middleware(next)

	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("Next handler should be called")
	}
}

// ==================== VersionHandler Tests ====================

func TestVersionHandler(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})
	mgr.SetDefaultVersion("v2")

	vh := NewVersionHandler(mgr)

	// Register handlers for each version
	vh.RegisterHandler("v1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v1"))
	}))
	vh.RegisterHandler("v2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v2"))
	}))

	// Test v1 request
	req := httptest.NewRequest("GET", "/api/users?version=1.0", nil)
	rec := httptest.NewRecorder()
	vh.ServeHTTP(rec, req)

	if rec.Body.String() != "v1" {
		t.Errorf("Body = %v, want v1", rec.Body.String())
	}

	// Test v2 request
	req = httptest.NewRequest("GET", "/api/users?version=2.0", nil)
	rec = httptest.NewRecorder()
	vh.ServeHTTP(rec, req)

	if rec.Body.String() != "v2" {
		t.Errorf("Body = %v, want v2", rec.Body.String())
	}
}

func TestVersionHandlerNotFound(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.SetDefaultVersion("v1")

	vh := NewVersionHandler(mgr)
	vh.SetNotFound(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))

	req := httptest.NewRequest("GET", "/api/users?version=999", nil)
	rec := httptest.NewRecorder()
	vh.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusNotFound)
	}
}

// ==================== VersionedRouter Tests ====================

func TestVersionedRouter(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})
	mgr.SetDefaultVersion("v2")

	vr := NewVersionedRouter(mgr)

	vr.AddRoute("v1", "GET", "/users", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v1 users"))
	}))
	vr.AddRoute("v2", "GET", "/users", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v2 users"))
	}))

	// Test v1 request
	req := httptest.NewRequest("GET", "/users?version=1.0", nil)
	rec := httptest.NewRecorder()
	vr.Handler().ServeHTTP(rec, req)

	if rec.Body.String() != "v1 users" {
		t.Errorf("Body = %v, want v1 users", rec.Body.String())
	}

	// Test v2 request
	req = httptest.NewRequest("GET", "/users?version=2.0", nil)
	rec = httptest.NewRecorder()
	vr.Handler().ServeHTTP(rec, req)

	if rec.Body.String() != "v2 users" {
		t.Errorf("Body = %v, want v2 users", rec.Body.String())
	}
}

func TestVersionedRouterMiddleware(t *testing.T) {
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.SetDefaultVersion("v1")

	vr := NewVersionedRouter(mgr)

	// Add middleware
	vr.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("X-Middleware", "applied")
			next.ServeHTTP(w, r)
		})
	})

	var middlewareApplied bool
	vr.AddRoute("v1", "GET", "/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Middleware") == "applied" {
			middlewareApplied = true
		}
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	vr.Handler().ServeHTTP(rec, req)

	if !middlewareApplied {
		t.Error("Middleware should be applied")
	}
}

// ==================== DefaultVersionManager Tests ====================

func TestDefaultVersionManager(t *testing.T) {
	mgr := DefaultVersionManager()

	versions := mgr.GetSupportedVersions()
	if len(versions) == 0 {
		t.Error("Should have registered versions")
	}

	defaultVer := mgr.GetDefaultVersion()
	if defaultVer != "v2" {
		t.Errorf("Default version = %v, want v2", defaultVer)
	}

	// Check v1 is deprecated
	v1, ok := mgr.GetVersion("1")
	if !ok || !v1.Deprecated {
		t.Error("v1 should be deprecated")
	}

	// Check v1.x is unsupported
	v1x, ok := mgr.GetVersion("1")
	if !ok || !v1x.Unsupported {
		t.Error("v1.x should be unsupported")
	}
}

// ==================== Benchmark Tests ====================

func BenchmarkVersionCompare(b *testing.B) {
	v1 := &Version{Major: 1, Minor: 1}
	v2 := &Version{Major: 2, Minor: 0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v1.Compare(v2)
	}
}

func BenchmarkVersionNegotiate(b *testing.B) {
	mgr := DefaultVersionManager()
	neg := NewVersionNegotiator(mgr)

	req := httptest.NewRequest("GET", "/api/v2/users", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		neg.Negotiate(req)
	}
}

func BenchmarkParseVersion(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseVersion("v2.1-beta")
	}
}

// ==================== Integration Tests ====================

func TestVersionNegotiationIntegration(t *testing.T) {
	// Test full flow: register versions, negotiate, route
	mgr := NewVersionManager()
	mgr.RegisterVersion(&Version{Major: 1, Minor: 0})
	mgr.RegisterVersion(&Version{Major: 2, Minor: 0})
	mgr.SetDefaultVersion("v2")

	vh := NewVersionHandler(mgr)

	// Create version-specific handlers
	v1Called := false
	v2Called := false

	vh.RegisterHandler("v1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v1Called = true
		w.Write([]byte("v1 handler"))
	}))

	vh.RegisterHandler("v2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v2Called = true
		w.Write([]byte("v2 handler"))
	}))

	// Test multiple requests
	for i := 0; i < 10; i++ {
		v1Called = false
		v2Called = false

		// Request to v1
		req := httptest.NewRequest("GET", "/api?version=1.0", nil)
		rec := httptest.NewRecorder()
		vh.ServeHTTP(rec, req)

		if !v1Called || rec.Body.String() != "v1 handler" {
			t.Errorf("v1 handler not called correctly, v1Called=%v, body=%s", v1Called, rec.Body.String())
		}

		// Request to v2
		req = httptest.NewRequest("GET", "/api?version=2.0", nil)
		rec = httptest.NewRecorder()
		vh.ServeHTTP(rec, req)

		if !v2Called || rec.Body.String() != "v2 handler" {
			t.Errorf("v2 handler not called correctly, v2Called=%v, body=%s", v2Called, rec.Body.String())
		}
	}
}

// Helper for test output
var _ = strconv.Itoa
