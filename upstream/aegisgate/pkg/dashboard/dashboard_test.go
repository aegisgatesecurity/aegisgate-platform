package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDefaultConfig tests the default configuration
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != 8080 {
		t.Errorf("DefaultConfig().Port = %d, want 8080", cfg.Port)
	}
	if cfg.StaticDir != "./static" {
		t.Errorf("DefaultConfig().StaticDir = %s, want ./static", cfg.StaticDir)
	}
	if !cfg.CORSEnabled {
		t.Error("DefaultConfig().CORSEnabled should be true")
	}
	if cfg.RateLimitRequests != 100 {
		t.Errorf("DefaultConfig().RateLimitRequests = %d, want 100", cfg.RateLimitRequests)
	}
	if cfg.RateLimitBurst != 150 {
		t.Errorf("DefaultConfig().RateLimitBurst = %d, want 150", cfg.RateLimitBurst)
	}
}

// TestNewDashboard tests dashboard creation
func TestNewDashboard(t *testing.T) {
	cfg := DefaultConfig()
	d := New(cfg)

	if d == nil {
		t.Fatal("New() returned nil")
	}

	if d.config.Port != cfg.Port {
		t.Errorf("Dashboard config.Port = %d, want %d", d.config.Port, cfg.Port)
	}
}

// TestRateLimiter tests the rate limiter
func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10, 150)

	// First request should be allowed
	if !rl.Allow("192.168.1.1") {
		t.Error("First request should be allowed")
	}

	// Multiple requests should be allowed up to burst
	for i := 0; i < 10; i++ {
		rl.Allow("192.168.1.1")
	}
}

// TestRateLimiterDifferentClients tests rate limiting for different clients
func TestRateLimiterDifferentClients(t *testing.T) {
	rl := NewRateLimiter(10, 150)

	// Each client should have separate limits
	if !rl.Allow("client1") {
		t.Error("Client1 first request should be allowed")
	}
	if !rl.Allow("client2") {
		t.Error("Client2 first request should be allowed")
	}
	if !rl.Allow("client3") {
		t.Error("Client3 first request should be allowed")
	}
}

// TestDashboardStartStop tests starting and stopping the dashboard
func TestDashboardStartStop(t *testing.T) {
	cfg := Config{
		Port:              0, // Use any available port
		StaticDir:         "./static",
		CORSEnabled:       true,
		RateLimitRequests: 100,
		RateLimitBurst:    150,
	}

	d := New(cfg)

	// Start the server
	err := d.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Stop the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

// TestStopNilServer tests stopping when server is nil
func TestStopNilServer(t *testing.T) {
	d := &Dashboard{
		server: nil,
	}

	ctx := context.Background()
	err := d.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() with nil server should return nil, got %v", err)
	}
}

// TestAPIResponse tests the API response structure
func TestAPIResponse(t *testing.T) {
	resp := APIResponse{
		Success:   true,
		Data:      map[string]string{"test": "value"},
		Timestamp: time.Now(),
	}

	if !resp.Success {
		t.Error("APIResponse.Success should be true")
	}
	if resp.Error != "" {
		t.Error("APIResponse.Error should be empty for success response")
	}
}

// TestStatsFilter tests stats filter creation
func TestStatsFilter(t *testing.T) {
	filter := StatsFilter{
		Severity:    "HIGH",
		Limit:       50,
		PatternType: "injection",
	}

	if filter.Severity != "HIGH" {
		t.Errorf("StatsFilter.Severity = %s, want HIGH", filter.Severity)
	}
	if filter.Limit != 50 {
		t.Errorf("StatsFilter.Limit = %d, want 50", filter.Limit)
	}
}

// TestRoute tests route configuration
func TestRoute(t *testing.T) {
	route := Route{
		Path:        "/api/test",
		Method:      http.MethodGet,
		Handler:     func(w http.ResponseWriter, r *http.Request) error { return nil },
		RequireAuth: true,
		RateLimited: true,
	}

	if route.Path != "/api/test" {
		t.Errorf("Route.Path = %s, want /api/test", route.Path)
	}
	if route.Method != http.MethodGet {
		t.Errorf("Route.Method = %s, want GET", route.Method)
	}
	if !route.RequireAuth {
		t.Error("Route.RequireAuth should be true")
	}
	if !route.RateLimited {
		t.Error("Route.RateLimited should be true")
	}
}

// TestDashboardData tests dashboard data structure
func TestDashboardData(t *testing.T) {
	data := DashboardData{
		Version:      "1.0.0",
		ServerTime:   time.Now(),
		Uptime:       time.Hour,
		WebSocketURL: "ws://localhost:8080/events",
	}

	if data.Version != "1.0.0" {
		t.Errorf("DashboardData.Version = %s, want 1.0.0", data.Version)
	}
	if data.Uptime != time.Hour {
		t.Errorf("DashboardData.Uptime = %v, want 1 hour", data.Uptime)
	}
}

// TestParseStatsFilter tests parsing stats filters from request
func TestParseStatsFilter(t *testing.T) {
	d := New(DefaultConfig())

	// Test with query parameters
	req := httptest.NewRequest(http.MethodGet, "/api/stats?severity=HIGH&limit=500", nil)
	filter := d.parseStatsFilter(req)

	if filter.Severity != "HIGH" {
		t.Errorf("parseStatsFilter().Severity = %s, want HIGH", filter.Severity)
	}
	if filter.Limit != 500 {
		t.Errorf("parseStatsFilter().Limit = %d, want 500", filter.Limit)
	}
}

// TestParseStatsFilterDefault tests default stats filter values
func TestParseStatsFilterDefault(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	filter := d.parseStatsFilter(req)

	if filter.Limit != 100 {
		t.Errorf("parseStatsFilter() default Limit = %d, want 100", filter.Limit)
	}
}

// TestParseStatsFilterMaxLimit tests maximum limit enforcement
func TestParseStatsFilterMaxLimit(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/stats?limit=9999", nil)
	filter := d.parseStatsFilter(req)

	if filter.Limit > 1000 {
		t.Errorf("parseStatsFilter() Limit = %d, should be capped at 1000", filter.Limit)
	}
}

// TestParseHistoryFilter tests parsing history filters
func TestParseHistoryFilter(t *testing.T) {
	d := New(DefaultConfig())

	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)

	req := httptest.NewRequest(http.MethodGet, "/api/history?severity=HIGH&type=request&since="+since+"&until="+until, nil)
	filter := d.parseHistoryFilter(req)

	if filter.Severity != "HIGH" {
		t.Errorf("parseHistoryFilter().Severity = %s, want HIGH", filter.Severity)
	}
	if filter.PatternType != "request" {
		t.Errorf("parseHistoryFilter().PatternType = %s, want request", filter.PatternType)
	}
	if filter.Since.IsZero() {
		t.Error("parseHistoryFilter().Since should be set")
	}
	if filter.Until.IsZero() {
		t.Error("parseHistoryFilter().Until should be set")
	}
}

// TestHandleAPIHealth tests the health endpoint
func TestHandleAPIHealth(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()

	err := d.handleAPIHealth(w, req)
	if err != nil {
		t.Errorf("handleAPIHealth() error = %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("handleAPIHealth() status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleAPIVersion tests the version endpoint
func TestHandleAPIVersion(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	w := httptest.NewRecorder()

	err := d.handleAPIVersion(w, req)
	if err != nil {
		t.Errorf("handleAPIVersion() error = %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("handleAPIVersion() status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleAPIStats tests the stats endpoint
func TestHandleAPIStats(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()

	err := d.handleAPIStats(w, req)
	if err != nil {
		t.Errorf("handleAPIStats() error = %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("handleAPIStats() status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleAPIViolations tests the violations endpoint
func TestHandleAPIViolations(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/violations", nil)
	w := httptest.NewRecorder()

	err := d.handleAPIViolations(w, req)
	if err != nil {
		t.Errorf("handleAPIViolations() error = %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("handleAPIViolations() status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleAPIPatterns tests the patterns endpoint
func TestHandleAPIPatterns(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/patterns", nil)
	w := httptest.NewRecorder()

	err := d.handleAPIPatterns(w, req)
	if err != nil {
		t.Errorf("handleAPIPatterns() error = %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("handleAPIPatterns() status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleAPIConfig tests the config endpoint
func TestHandleAPIConfig(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	w := httptest.NewRecorder()

	err := d.handleAPIConfig(w, req)
	if err != nil {
		t.Errorf("handleAPIConfig() error = %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("handleAPIConfig() status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHandleAPIHistory tests the history endpoint
func TestHandleAPIHistory(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/api/history", nil)
	w := httptest.NewRecorder()

	err := d.handleAPIHistory(w, req)
	if err != nil {
		t.Errorf("handleAPIHistory() error = %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("handleAPIHistory() status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestCheckAuth tests authentication checking
func TestCheckAuth(t *testing.T) {
	t.Run("no auth token configured", func(t *testing.T) {
		d := New(DefaultConfig())
		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)

		if !d.checkAuth(req) {
			t.Error("checkAuth() should return true when no auth token configured")
		}
	})

	t.Run("valid bearer token", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.AuthToken = "test-token"
		d := New(cfg)

		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
		req.Header.Set("Authorization", "Bearer test-token")

		if !d.checkAuth(req) {
			t.Error("checkAuth() should return true for valid bearer token")
		}
	})

	t.Run("invalid bearer token", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.AuthToken = "test-token"
		d := New(cfg)

		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")

		if d.checkAuth(req) {
			t.Error("checkAuth() should return false for invalid token")
		}
	})

	t.Run("missing auth header", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.AuthToken = "test-token"
		d := New(cfg)

		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)

		if d.checkAuth(req) {
			t.Error("checkAuth() should return false when auth header missing")
		}
	})

	t.Run("direct token", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.AuthToken = "test-token"
		d := New(cfg)

		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
		req.Header.Set("Authorization", "test-token")

		if !d.checkAuth(req) {
			t.Error("checkAuth() should return true for direct token")
		}
	})
}

// TestHandleCORS tests CORS handling
func TestHandleCORS(t *testing.T) {
	t.Run("wildcard origin", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.CORSOrigins = []string{"*"}
		cfg.CORSEnabled = true
		d := New(cfg)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		d.handleCORS(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
			t.Errorf("CORS origin = %s, want http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("specific origin", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.CORSOrigins = []string{"http://allowed.com", "http://example.com"}
		cfg.CORSEnabled = true
		d := New(cfg)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		d.handleCORS(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "http://example.com" {
			t.Errorf("CORS origin = %s, want http://example.com", w.Header().Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("options request", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.CORSEnabled = true
		d := New(cfg)

		req := httptest.NewRequest(http.MethodOptions, "/api/test", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()

		d.handleCORS(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("OPTIONS response code = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

// TestServeStaticPathTraversal tests path traversal prevention
func TestServeStaticPathTraversal(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/static/../secret/file.txt", nil)
	w := httptest.NewRecorder()

	d.serveStatic(w, req)

	// Should return 404 for path traversal attempt
	if w.Code != http.StatusNotFound && w.Code != http.StatusBadRequest {
		t.Errorf("serveStatic() status = %d, want 404 or 400", w.Code)
	}
}

// TestMinFunction tests the min helper
func TestMinFunction(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{5, 5, 5},
		{0, 10, 0},
		{-1, 1, -1},
	}

	for _, tt := range tests {
		got := min(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// TestSetupRoutes tests route setup
func TestSetupRoutes(t *testing.T) {
	d := New(DefaultConfig())
	d.setupRoutes()

	if len(d.routes) == 0 {
		t.Error("setupRoutes() did not add any routes")
	}

	// Check for expected routes
	expectedRoutes := []string{"/api/stats", "/api/history", "/api/violations", "/api/patterns", "/api/health", "/api/version"}
	routePaths := make(map[string]bool)
	for _, route := range d.routes {
		routePaths[route.Path] = true
	}

	for _, path := range expectedRoutes {
		if !routePaths[path] {
			t.Errorf("Expected route %s not found", path)
		}
	}
}

// TestWriteJSON tests JSON writing
func TestWriteJSON(t *testing.T) {
	d := New(DefaultConfig())

	data := map[string]string{"message": "test"}
	w := httptest.NewRecorder()

	d.writeJSON(w, http.StatusOK, data)

	if w.Code != http.StatusOK {
		t.Errorf("writeJSON() status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("writeJSON() Content-Type = %s, want application/json", contentType)
	}
}

// TestErrorResponse tests error response
func TestErrorResponse(t *testing.T) {
	d := New(DefaultConfig())

	w := httptest.NewRecorder()
	d.errorResponse(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("errorResponse() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestServeIndex tests index page serving
func TestServeIndex(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	err := d.serveIndex(w, req)
	if err != nil {
		t.Errorf("serveIndex() error = %v", err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("serveIndex() status = %d, want %d", w.Code, http.StatusOK)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("serveIndex() Content-Type = %s, want text/html; charset=utf-8", contentType)
	}
}

// TestServeIndexNotFound tests index page for non-root paths
func TestServeIndexNotFound(t *testing.T) {
	d := New(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()

	err := d.serveIndex(w, req)
	if err != nil {
		t.Errorf("serveIndex() error = %v", err)
	}

	// Should return 404 for non-root paths
	if w.Code != http.StatusNotFound {
		t.Errorf("serveIndex() status = %d, want %d", w.Code, http.StatusNotFound)
	}
}
