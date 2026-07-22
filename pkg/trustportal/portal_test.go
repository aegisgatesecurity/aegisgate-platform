// SPDX-License-Identifier: Apache-2.0
// Tests for the trust portal HTTP handlers and data adapters.

package trustportal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubSource is a test Source that returns canned data and counts
// how many times each method is called (so we can verify the
// cache is doing its job).
type stubSource struct {
	postureCalls    atomic.Int32
	frameworksCalls atomic.Int32
	uptimeCalls     atomic.Int32

	postureSnap    *PostureSnapshot
	frameworksSnap *FrameworksSnapshot
	uptimeSnap     *UptimeSnapshot

	postureErr    error
	frameworksErr error
	uptimeErr     error
}

func (s *stubSource) Posture() (*PostureSnapshot, error) {
	s.postureCalls.Add(1)
	return s.postureSnap, s.postureErr
}

func (s *stubSource) Frameworks() (*FrameworksSnapshot, error) {
	s.frameworksCalls.Add(1)
	return s.frameworksSnap, s.frameworksErr
}

func (s *stubSource) Uptime() (*UptimeSnapshot, error) {
	s.uptimeCalls.Add(1)
	return s.uptimeSnap, s.uptimeErr
}

func newStubSource() *stubSource {
	return &stubSource{
		postureSnap: &PostureSnapshot{
			GeneratedAt: time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC),
			Version:     "v3.4.0-beta.1",
			Mode:        "production",
			Overall:     "healthy",
			Uptime:      "3d 4h 12m",
			License: LicenseInfo{
				Tier:        "professional",
				DisplayName: "Professional",
				Valid:       true,
				ExpiresAt:   time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			Subsystems: []SubInfo{
				{Name: "license", Status: "healthy", Summary: "license valid"},
				{Name: "compliance", Status: "healthy", Summary: "2 frameworks enforced"},
			},
		},
		frameworksSnap: &FrameworksSnapshot{
			GeneratedAt: time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC),
			TotalCount:  3,
			Tier1Count:  2,
			Frameworks: []FrameworkInfo{
				{Key: "soc2", DisplayName: "SOC 2 Type II", Tier1: true, Enforced: true, HasImplementation: true},
				{Key: "iso27001", DisplayName: "ISO 27001:2022", Tier1: true, Enforced: true, HasImplementation: true},
				{Key: "nist_ai_rmf", DisplayName: "NIST AI RMF 1.0", Tier1: false, Enforced: false, HasImplementation: false},
			},
		},
		uptimeSnap: &UptimeSnapshot{
			GeneratedAt:     time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC),
			ProcessUptime:   "3d 4h 12m",
			UptimeBadge:     "good",
			BadgeDisclaimer: "Process uptime since last restart.",
		},
	}
}

// =====================================================================
// HTTP handler tests
// =====================================================================

func TestPortal_IndexPage(t *testing.T) {
	p := NewPortal(newStubSource())
	req := httptest.NewRequest(http.MethodGet, "/trust", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rr.Body.String()
	// The page must contain key elements
	mustContain := []string{
		"AegisGate Trust Portal",
		"support@aegisgatesecurity.io", // locked contact decision
		"/trust/api/posture",           // JS fetch URL
		"/trust/api/frameworks",        // JS fetch URL
		"/trust/api/uptime",            // JS fetch URL
		"60 seconds",                   // refresh interval
	}
	for _, s := range mustContain {
		if !strings.Contains(body, s) {
			t.Errorf("HTML page is missing required string: %q", s)
		}
	}
}

func TestPortal_IndexPageTrailingSlash(t *testing.T) {
	// /trust/ should also serve the page (the route strips the
	// /trust prefix, leaving "/" which is mapped to "/index").
	p := NewPortal(newStubSource())
	req := httptest.NewRequest(http.MethodGet, "/trust/", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("/trust/ status = %d, want 200", rr.Code)
	}
}

func TestPortal_PostureRoute(t *testing.T) {
	src := newStubSource()
	p := NewPortal(src)
	req := httptest.NewRequest(http.MethodGet, "/trust/api/posture", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var snap PostureSnapshot
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if snap.Overall != "healthy" {
		t.Errorf("overall = %q, want healthy", snap.Overall)
	}
	if snap.Version != "v3.4.0-beta.1" {
		t.Errorf("version = %q, want v3.4.0-beta.1", snap.Version)
	}
	if snap.License.Tier != "professional" {
		t.Errorf("license.tier = %q, want professional", snap.License.Tier)
	}
}

func TestPortal_FrameworksRoute(t *testing.T) {
	src := newStubSource()
	p := NewPortal(src)
	req := httptest.NewRequest(http.MethodGet, "/trust/api/frameworks", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var snap FrameworksSnapshot
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if snap.TotalCount != 3 {
		t.Errorf("total = %d, want 3", snap.TotalCount)
	}
	if snap.Tier1Count != 2 {
		t.Errorf("tier1 = %d, want 2", snap.Tier1Count)
	}
	if len(snap.Frameworks) != 3 {
		t.Errorf("len(frameworks) = %d, want 3", len(snap.Frameworks))
	}
}

func TestPortal_UptimeRoute(t *testing.T) {
	src := newStubSource()
	p := NewPortal(src)
	req := httptest.NewRequest(http.MethodGet, "/trust/api/uptime", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var snap UptimeSnapshot
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if snap.UptimeBadge != "good" {
		t.Errorf("badge = %q, want good", snap.UptimeBadge)
	}
}

func TestPortal_CacheIsUsed(t *testing.T) {
	// Hit /api/posture 3 times; the source should only be called
	// once (the cache serves the next two).
	src := newStubSource()
	p := NewPortal(src)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/trust/api/posture", nil)
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("iter %d: status = %d", i, rr.Code)
		}
	}
	if got := src.postureCalls.Load(); got != 1 {
		t.Errorf("Posture() called %d times, want 1 (cache should serve the next 2)", got)
	}
}

func TestPortal_PostureError(t *testing.T) {
	src := newStubSource()
	src.postureErr = errStubPosture
	p := NewPortal(src)
	req := httptest.NewRequest(http.MethodGet, "/trust/api/posture", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

func TestPortal_UnknownRoute(t *testing.T) {
	p := NewPortal(newStubSource())
	req := httptest.NewRequest(http.MethodGet, "/trust/api/unknown", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestPortal_MethodNotAllowed(t *testing.T) {
	p := NewPortal(newStubSource())
	req := httptest.NewRequest(http.MethodPost, "/trust/api/posture", nil)
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

func TestPortal_InvalidateCaches(t *testing.T) {
	src := newStubSource()
	p := NewPortal(src)
	// First call caches
	{
		req := httptest.NewRequest(http.MethodGet, "/trust/api/posture", nil)
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
	}
	if src.postureCalls.Load() != 1 {
		t.Fatalf("setup: posture calls = %d, want 1", src.postureCalls.Load())
	}
	// Invalidate
	p.InvalidateCaches()
	// Next call should re-fetch
	{
		req := httptest.NewRequest(http.MethodGet, "/trust/api/posture", nil)
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
	}
	if got := src.postureCalls.Load(); got != 2 {
		t.Errorf("after invalidate: Posture() called %d times, want 2", got)
	}
}

// errStubPosture is a sentinel error for the source-error tests.
var errStubPosture = &stubError{msg: "stub posture error"}

// stubError is a test error type.
type stubError struct{ msg string }

func (e *stubError) Error() string { return e.msg }

// =====================================================================
// Cache tests
// =====================================================================

func TestCache_GetSet(t *testing.T) {
	c := NewCache[int](60 * time.Second)
	if _, ok := c.Get(); ok {
		t.Error("fresh cache should return ok=false")
	}
	c.Set(42)
	got, ok := c.Get()
	if !ok {
		t.Fatal("after Set, Get should return ok=true")
	}
	if got != 42 {
		t.Errorf("Get = %d, want 42", got)
	}
}

func TestCache_TTL(t *testing.T) {
	c := NewCache[string](100 * time.Millisecond)
	c.Set("hello")
	// Inject a clock that pretends 200ms have passed.
	now := time.Now()
	c.setNow(func() time.Time { return now.Add(200 * time.Millisecond) })
	if _, ok := c.Get(); ok {
		t.Error("after TTL expiry, Get should return ok=false")
	}
}

func TestCache_Invalidate(t *testing.T) {
	c := NewCache[int](60 * time.Second)
	c.Set(99)
	c.Invalidate()
	if _, ok := c.Get(); ok {
		t.Error("after Invalidate, Get should return ok=false")
	}
}

// =====================================================================
// Uptime parser tests
// =====================================================================

func TestParseUptimeDuration(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"3d 4h 12m", 3*24*time.Hour + 4*time.Hour + 12*time.Minute, false},
		{"12m 5s", 12*time.Minute + 5*time.Second, false},
		{"45s", 45 * time.Second, false},
		{"1d", 24 * time.Hour, false},
		{"", 0, true},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseUptimeDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestBuildUptimeSnapshot_Badges(t *testing.T) {
	tests := []struct {
		uptime string
		badge  string
	}{
		{"30d 4h 12m", "good"}, // >= 24h
		{"12h 30m", "fair"},    // 1-24h
		{"5m 30s", "new"},      // < 1h
		{"", "unknown"},        // unparseable
		{"abc", "unknown"},     // unparseable
	}
	for _, tt := range tests {
		t.Run(tt.uptime, func(t *testing.T) {
			snap := BuildUptimeSnapshot(tt.uptime)
			if snap.UptimeBadge != tt.badge {
				t.Errorf("uptime %q -> badge %q, want %q", tt.uptime, snap.UptimeBadge, tt.badge)
			}
		})
	}
}
