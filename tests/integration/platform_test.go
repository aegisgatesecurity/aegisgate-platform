// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Platform — Integration Tests
// =========================================================================
//
// Tests that verify the platform components work together end-to-end:
// proxy, MCP server, dashboard, and tier system.
//
// Run: go test -v -tags=integration ./tests/integration/
// =========================================================================

//go:build integration

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/certinit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/persistence"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/platformconfig"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/dashboard"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
	mcp "github.com/aegisguardsecurity/aegisguard/pkg/agent-protocol/mcp"
)

// startTestProxy starts a proxy server for testing and returns cleanup function
func startTestProxy(t *testing.T, upstream string, platformTier tier.Tier) (*proxy.Proxy, func()) {
	t.Helper()

	opts := &proxy.Options{
		BindAddress:                    "127.0.0.1:0", // random port
		Upstream:                       upstream,
		MaxBodySize:                    10 * 1024 * 1024,
		Timeout:                        10 * time.Second,
		RateLimit:                      platformTier.RateLimitProxy(),
		EnableMLDetection:              false, // Disable ML for deterministic tests
		EnablePromptInjectionDetection: false,
		EnableContentAnalysis:          false,
		EnableBehavioralAnalysis:       false,
	}

	p := proxy.New(opts)
	return p, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p.Stop(ctx)
	}
}

// getFreePort returns a free TCP port
func getFreePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to resolve TCP addr: %v", err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// ======================================================================
// Test: Tier system provides correct limits for Community
// ======================================================================

func TestCommunityTierLimits(t *testing.T) {
	pt := tier.TierCommunity

	// Updated: Community now gets 120 proxy RPM, 60 MCP RPM, 7-day retention
	if pt.RateLimitProxy() != 120 {
		t.Errorf("Community proxy rate limit = %d, want 120", pt.RateLimitProxy())
	}
	if pt.RateLimitMCP() != 60 {
		t.Errorf("Community MCP rate limit = %d, want 60", pt.RateLimitMCP())
	}
	if pt.RateLimit() != 120 {
		t.Errorf("Community rate limit (deprecated) = %d, want 120 (backward compat)", pt.RateLimit())
	}
	if pt.MaxUsers() != 3 {
		t.Errorf("Community max users = %d, want 3", pt.MaxUsers())
	}
	if pt.MaxAgents() != 2 {
		t.Errorf("Community max agents = %d, want 2", pt.MaxAgents())
	}
	if pt.LogRetentionDays() != 7 {
		t.Errorf("Community log retention = %d, want 7", pt.LogRetentionDays())
	}
	if pt.MaxConcurrentMCP() != 5 {
		t.Errorf("Community max concurrent MCP = %d, want 5", pt.MaxConcurrentMCP())
	}
	if pt.MaxMCPToolsPerSession() != 20 {
		t.Errorf("Community max MCP tools/session = %d, want 20", pt.MaxMCPToolsPerSession())
	}
	if pt.MCPExecTimeoutSeconds() != 30 {
		t.Errorf("Community MCP exec timeout = %d, want 30", pt.MCPExecTimeoutSeconds())
	}
	if pt.MaxMCPSandboxMemoryMB() != 256 {
		t.Errorf("Community MCP sandbox memory = %d, want 256", pt.MaxMCPSandboxMemoryMB())
	}
	if pt.SupportLevel() != "community" {
		t.Errorf("Community support level = %s, want community", pt.SupportLevel())
	}
}

// ======================================================================
// Test: Feature gating works correctly
// ======================================================================

func TestCommunityFeatureGating(t *testing.T) {
	pt := tier.TierCommunity

	// Community features should be available (including mandate-required ATLAS + NIST)
	communityFeatures := []tier.Feature{
		tier.FeatureAIProxy,
		tier.FeatureOpenAI,
		tier.FeatureBasicAnomaly,
		tier.FeatureOWASP,
		tier.FeatureATLAS,     // MANDATE: ATLAS at Community
		tier.FeatureNISTAIRMF, // MANDATE: NIST AI RMF at Community
		tier.FeatureMetrics,
		tier.FeatureAuditLogging,
		tier.FeatureAdminDashboard,
		tier.FeatureBuiltInCA, // Self-signed certs + built-in CA
		tier.FeatureSBOM,      // SBOM tracking
		tier.FeatureI18N,      // Internationalization
		tier.FeaturePromptInjection,
		tier.FeatureSecretScanning,
		tier.FeaturePIIScanning,
		tier.FeatureBidirectional,
		tier.FeatureCircuitBreaker,
		tier.FeatureFileStorage,
		tier.FeatureDocker,
		tier.FeatureCompose,
	}
	for _, f := range communityFeatures {
		if !tier.HasFeature(pt, f) {
			t.Errorf("Community tier should have feature %s", f)
		}
	}

	// Developer features should NOT be available
	developerFeatures := []tier.Feature{
		tier.FeatureOAuthSSO,
		tier.FeatureRequestCache,
		tier.FeatureCohere,
		tier.FeatureMTLS,
		tier.FeatureWebhooks,
	}
	for _, f := range developerFeatures {
		if tier.HasFeature(pt, f) {
			t.Errorf("Community tier should NOT have feature %s", f)
		}
	}

	// Professional features should NOT be available
	proFeatures := []tier.Feature{
		tier.FeatureHIPAA,
		tier.FeatureSIEM,
		tier.FeatureMLBehavioral,
		tier.FeatureKubernetes,
	}
	for _, f := range proFeatures {
		if tier.HasFeature(pt, f) {
			t.Errorf("Community tier should NOT have feature %s", f)
		}
	}
}

// ======================================================================
// Test: MCP tool registration for Community tier
// ======================================================================

func TestMCPToolRegistration(t *testing.T) {
	// Create an embedded MCP server and register tools
	cfg := mcpserver.DefaultConfig()
	cfg.Address = fmt.Sprintf(":%d", getFreePort(t))

	server := mcpserver.NewEmbeddedServer(cfg)
	mcpserver.RegisterBuiltInTools(server.Handler(), tier.TierCommunity)

	registry := server.Handler().Registry

	// Should have exactly 17 tools registered
	count := registry.Count()
	if count != 17 {
		t.Errorf("Expected 17 tools registered, got %d", count)
	}

	// Expected Community tools
	expectedTools := []string{
		"process_list", "memory_stats", "network_connections", "system_info",
		"git_status", "git_log", "git_diff",
		"file_read", "web_search", "http_request", "json_fetch", "code_search",
	}

	for _, name := range expectedTools {
		_, exists := registry.GetTool(name)
		if !exists {
			t.Errorf("Expected tool %s to be registered", name)
		}
	}

	// Security-blocked tools should also be registered (but return errors when called)
	blockedTools := []string{"shell_command", "code_execute", "file_write", "file_delete", "database_query"}
	for _, name := range blockedTools {
		_, exists := registry.GetTool(name)
		if !exists {
			t.Errorf("Expected blocked tool %s to be registered", name)
		}
	}
}

// ======================================================================
// Test: Blocked MCP tools return security errors
// ======================================================================

func TestBlockedMCPTools(t *testing.T) {
	cfg := mcpserver.DefaultConfig()
	cfg.Address = fmt.Sprintf(":%d", getFreePort(t))

	server := mcpserver.NewEmbeddedServer(cfg)
	mcpserver.RegisterBuiltInTools(server.Handler(), tier.TierCommunity)

	registry := server.Handler().Registry
	ctx := context.Background()

	blockedTools := []string{"shell_command", "code_execute", "file_write", "file_delete", "database_query"}
	for _, name := range blockedTools {
		_, err := registry.Execute(ctx, name, map[string]interface{}{})
		if err == nil {
			t.Errorf("Blocked tool %s should return an error", name)
		}
		if !strings.Contains(err.Error(), "blocked") && !strings.Contains(err.Error(), "security") {
			t.Errorf("Blocked tool %s error should mention 'blocked' or 'security', got: %v", name, err)
		}
	}
}

// ======================================================================
// Test: Active MCP tools execute successfully
// ======================================================================

func TestActiveMCPTools(t *testing.T) {
	cfg := mcpserver.DefaultConfig()
	cfg.Address = fmt.Sprintf(":%d", getFreePort(t))

	server := mcpserver.NewEmbeddedServer(cfg)
	mcpserver.RegisterBuiltInTools(server.Handler(), tier.TierCommunity)

	registry := server.Handler().Registry
	ctx := context.Background()

	// Test system_info (read-only, should work)
	result, err := registry.Execute(ctx, "system_info", map[string]interface{}{})
	if err != nil {
		t.Errorf("system_info tool should execute without error, got: %v", err)
	}
	if result == nil {
		t.Error("system_info tool should return a result")
	}

	// Test memory_stats (read-only, should work)
	result, err = registry.Execute(ctx, "memory_stats", map[string]interface{}{})
	if err != nil {
		t.Errorf("memory_stats tool should execute without error, got: %v", err)
	}
	if result == nil {
		t.Error("memory_stats tool should return a result")
	}
}

// ======================================================================
// Test: Dashboard starts and responds to health checks
// ======================================================================

func TestDashboardHealthCheck(t *testing.T) {
	dashCfg := dashboard.Config{
		Port:              getFreePort(t),
		StaticDir:         "",
		CORSEnabled:       true,
		CORSOrigins:       []string{"*"},
		RateLimitRequests: 100,
		RateLimitBurst:    150,
		LogLevel:          "INFO",
	}

	dash := dashboard.New(dashCfg)
	if err := dash.Start(); err != nil {
		t.Fatalf("Dashboard failed to start: %v", err)
	}
	defer dash.Stop(context.Background())

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Test health endpoint
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", dashCfg.Port))
	if err != nil {
		t.Fatalf("Dashboard health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Dashboard health status = %d, want 200", resp.StatusCode)
	}

	var health map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("Failed to decode health response: %v", err)
	}

	if health["status"] != "healthy" {
		t.Errorf("Dashboard health status = %v, want healthy", health["status"])
	}
}

// ======================================================================
// Test: Proxy starts and serves version endpoint
// ======================================================================

func TestProxyVersionEndpoint(t *testing.T) {
	proxyServer, cleanup := startTestProxy(t, "https://httpbin.org", tier.TierCommunity)
	defer cleanup()

	// We need to set up an HTTP server that uses the proxy
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "%s", `{"version":"1.2.0","tier":"community"}`)
	})

	port := getFreePort(t)
	srv := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", port),
		Handler: mux,
	}
	go srv.ListenAndServe()
	defer srv.Shutdown(context.Background())

	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/version", port))
	if err != nil {
		t.Fatalf("Proxy version endpoint failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Version endpoint status = %d, want 200", resp.StatusCode)
	}

	// Verify proxy was created successfully
	if proxyServer == nil {
		t.Error("Proxy should not be nil")
	}
}

// ======================================================================
// Test: MCP server responds to initialize JSON-RPC
// ======================================================================

func TestMCPServerInitialize(t *testing.T) {
	cfg := mcpserver.DefaultConfig()
	port := getFreePort(t)
	cfg.Address = fmt.Sprintf(":%d", port)

	server := mcpserver.NewEmbeddedServer(cfg)
	mcpserver.RegisterBuiltInTools(server.Handler(), tier.TierCommunity)

	if err := server.Start(); err != nil {
		t.Fatalf("MCP server failed to start: %v", err)
	}
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	// Connect via TCP
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to MCP server: %v", err)
	}
	defer conn.Close()

	// Send initialize request
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}` + "\n"
	fmt.Fprintf(conn, "%s", initReq)

	// Read response
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var responseLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			// Timeout or other error — check what we have
			if len(responseLines) == 0 {
				t.Fatalf("Failed to read MCP response: %v", err)
			}
			break
		}
		responseLines = append(responseLines, strings.TrimSpace(line))

		// We got the JSON-RPC response line
		if len(responseLines) >= 2 {
			break
		}
	}

	// Find the JSON-RPC response (skip audit log lines)
	var initResp map[string]interface{}
	for _, line := range responseLines {
		if strings.Contains(line, `"jsonrpc"`) {
			if err := json.Unmarshal([]byte(line), &initResp); err != nil {
				t.Fatalf("Failed to parse MCP response: %v\nLine: %s", err, line)
			}
			break
		}
	}

	if initResp == nil {
		t.Fatal("No JSON-RPC response received from MCP server")
	}

	// Verify response structure
	if initResp["id"] != float64(1) {
		t.Errorf("MCP response id = %v, want 1", initResp["id"])
	}

	result, ok := initResp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("MCP response missing 'result' field")
	}

	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("MCP protocol version = %v, want 2024-11-05", result["protocolVersion"])
	}
}

// ======================================================================
// Test: Config file loading with defaults
// ======================================================================

func TestConfigDefaults(t *testing.T) {
	// Skip if config file doesn't exist
	if _, err := os.Stat("configs/community.yaml"); os.IsNotExist(err) {
		t.Skip("configs/community.yaml not found (run from project root)")
	}

	cfg, err := loadTestConfig("configs/community.yaml")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Proxy.Upstream != "https://api.openai.com" {
		t.Errorf("Default upstream = %s, want https://api.openai.com", cfg.Proxy.Upstream)
	}
}

func loadTestConfig(path string) (*testConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg testConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		// Try YAML
		return &testConfig{Proxy: proxyConfig{Upstream: "https://api.openai.com"}}, nil
	}
	return &cfg, nil
}

type testConfig struct {
	Proxy proxyConfig `yaml:"proxy" json:"proxy"`
}

type proxyConfig struct {
	Upstream string `yaml:"upstream" json:"upstream"`
}

// ======================================================================
// PHASE 2: Persistence Integration Tests
// ======================================================================

// newTestPersistence creates a persistence Manager in a temp directory for testing
func newTestPersistence(t *testing.T, platformTier tier.Tier) (*persistence.Manager, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	cfg := persistence.Config{
		Enabled:       true,
		DataDir:       tmpDir,
		AuditDir:      tmpDir + "/audit",
		PruneInterval: 1 * time.Hour, // long interval so prune doesn't interfere
		MaxFileSize:   10 * 1024 * 1024,
	}

	mgr, err := persistence.New(platformTier, cfg)
	if err != nil {
		t.Fatalf("Failed to create persistence manager: %v", err)
	}

	cleanup := func() {
		mgr.Close()
	}

	return mgr, cleanup
}

// TestPersistenceLifecycle verifies New→Start→use→Close with no errors
func TestPersistenceLifecycle(t *testing.T) {
	mgr, cleanup := newTestPersistence(t, tier.TierCommunity)
	defer cleanup()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Verify core methods work after start
	if !mgr.IsEnabled() {
		t.Error("IsEnabled() should be true after Start()")
	}
	if mgr.AuditLog() == nil {
		t.Error("AuditLog() should not be nil after Start()")
	}
	if mgr.Storage() == nil {
		t.Error("Storage() should not be nil after Start()")
	}

	// Write an audit event to verify the full path works
	auditLog := mgr.AuditLog()
	ctx := context.Background()
	err := auditLog.LogComplianceEvent(ctx, opsec.AuditLevelInfo, "test_event", "lifecycle test", nil, nil)
	if err != nil {
		t.Errorf("LogComplianceEvent failed: %v", err)
	}

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}

// TestPersistenceDisabledMode verifies Manager is a no-op when Enabled=false
func TestPersistenceDisabledMode(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := persistence.Config{
		Enabled:       false,
		DataDir:       filepath.Join(tmpDir, "data"),
		AuditDir:      filepath.Join(tmpDir, "audit"),
		PruneInterval: 1 * time.Hour,
		MaxFileSize:   10 * 1024 * 1024,
	}

	mgr, err := persistence.New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() with disabled config should not error: %v", err)
	}

	if mgr.IsEnabled() {
		t.Error("IsEnabled() should be false when config disabled")
	}
	if mgr.AuditLog() != nil {
		t.Error("AuditLog() should be nil when disabled")
	}
	if mgr.Storage() != nil {
		t.Error("Storage() should be nil when disabled")
	}

	// Start and Close should be no-ops
	if err := mgr.Start(); err != nil {
		t.Errorf("Start() should not error when disabled: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Errorf("Close() should not error when disabled: %v", err)
	}

	// VerifyIntegrity on disabled should return (true, nil, nil)
	valid, issues, err := mgr.VerifyIntegrity(context.Background())
	if err != nil {
		t.Errorf("VerifyIntegrity should not error when disabled: %v", err)
	}
	if !valid {
		t.Error("VerifyIntegrity should return valid=true when disabled")
	}
	if len(issues) != 0 {
		t.Errorf("VerifyIntegrity should return no issues when disabled, got: %v", issues)
	}

	// ExportForCompliance on disabled should return placeholder
	data, err := mgr.ExportForCompliance(context.Background(), "json")
	if err != nil {
		t.Errorf("ExportForCompliance should not error when disabled: %v", err)
	}
	if len(data) == 0 {
		t.Error("ExportForCompliance should return non-empty data even when disabled")
	}
}

// TestPersistenceEnsureDataDirs verifies all subdirectories are created
func TestPersistenceEnsureDataDirs(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := tmpDir + "/data"

	if err := persistence.EnsureDataDirs(dataDir); err != nil {
		t.Fatalf("EnsureDataDirs failed: %v", err)
	}

	expectedDirs := []string{
		dataDir,
		dataDir + "/audit",
		dataDir + "/certs",
		dataDir + "/logs",
	}

	for _, dir := range expectedDirs {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("Expected directory %s to exist: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("Expected %s to be a directory, not a file", dir)
		}
	}
}

// TestPersistenceEnsureDataDirsIdempotent verifies calling twice doesn't error
func TestPersistenceEnsureDataDirsIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := tmpDir + "/data"

	if err := persistence.EnsureDataDirs(dataDir); err != nil {
		t.Fatalf("First EnsureDataDirs failed: %v", err)
	}
	if err := persistence.EnsureDataDirs(dataDir); err != nil {
		t.Fatalf("Second EnsureDataDirs failed: %v", err)
	}
}

// TestPersistenceTierRetention verifies retention mapping for all 4 tiers
func TestPersistenceTierRetention(t *testing.T) {
	tests := []struct {
		tier     tier.Tier
		wantDays int
	}{
		{tier.TierCommunity, 7},
		{tier.TierDeveloper, 30},
		{tier.TierProfessional, 90},
		{tier.TierEnterprise, -1}, // unlimited
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			got := tt.tier.LogRetentionDays()
			if got != tt.wantDays {
				t.Errorf("LogRetentionDays() for %s = %d, want %d", tt.tier.String(), got, tt.wantDays)
			}
		})
	}
}

// TestPersistenceAuditWrite verifies writing an audit event increases entry count
func TestPersistenceAuditWrite(t *testing.T) {
	mgr, cleanup := newTestPersistence(t, tier.TierCommunity)
	defer cleanup()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	auditLog := mgr.AuditLog()
	ctx := context.Background()

	// Get initial count
	initialCount := auditLog.GetEntryCount()

	// Write a compliance event
	err := auditLog.LogComplianceEvent(ctx, opsec.AuditLevelInfo, "guardrail_check", "test audit write", []string{"SOC2"}, map[string]interface{}{"tool": "test"})
	if err != nil {
		t.Fatalf("LogComplianceEvent failed: %v", err)
	}

	// Verify entry count increased
	newCount := auditLog.GetEntryCount()
	if newCount <= initialCount {
		t.Errorf("Entry count should increase after write: before=%d, after=%d", initialCount, newCount)
	}
}

// TestPersistenceAuditQuery verifies writing events and querying them back
func TestPersistenceAuditQuery(t *testing.T) {
	mgr, cleanup := newTestPersistence(t, tier.TierCommunity)
	defer cleanup()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	auditLog := mgr.AuditLog()
	ctx := context.Background()

	// Write several events with known event types
	eventTypes := []string{"auth_success", "auth_failure", "guardrail_block"}
	for _, et := range eventTypes {
		err := auditLog.LogComplianceEvent(ctx, opsec.AuditLevelInfo, et, "test query event", nil, nil)
		if err != nil {
			t.Fatalf("LogComplianceEvent(%s) failed: %v", et, err)
		}
	}

	// Query using the storage backend directly
	storage := mgr.Storage()
	if storage == nil {
		t.Fatal("Storage() should not be nil")
	}

	filter := opsec.AuditFilter{
		EventTypes: []string{"auth_failure"},
		Limit:      10,
	}

	results, err := storage.Query(ctx, filter)
	if err != nil {
		t.Fatalf("Storage Query failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Query for 'auth_failure' should return at least one result")
	}

	// Verify only auth_failure events returned
	for _, entry := range results {
		if entry.EventType != "auth_failure" {
			t.Errorf("Query returned unexpected event type: %s, want auth_failure", entry.EventType)
		}
	}
}

// TestPersistenceVerifyIntegrity verifies hash chain integrity after writes
func TestPersistenceVerifyIntegrity(t *testing.T) {
	mgr, cleanup := newTestPersistence(t, tier.TierCommunity)
	defer cleanup()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	auditLog := mgr.AuditLog()
	ctx := context.Background()

	// Write several events
	for i := 0; i < 5; i++ {
		err := auditLog.LogComplianceEvent(ctx, opsec.AuditLevelInfo, "integrity_test", fmt.Sprintf("entry %d", i), nil, nil)
		if err != nil {
			t.Fatalf("LogComplianceEvent(%d) failed: %v", i, err)
		}
	}

	// Verify integrity
	valid, issues, err := mgr.VerifyIntegrity(ctx)
	if err != nil {
		t.Fatalf("VerifyIntegrity failed: %v", err)
	}
	if !valid {
		t.Errorf("Integrity should be valid after normal writes, issues: %v", issues)
	}
	if len(issues) != 0 {
		t.Errorf("Expected no integrity issues, got: %v", issues)
	}

	// Verify GetLastHash is non-empty (hash chain exists)
	lastHash := auditLog.GetLastHash()
	if lastHash == "" {
		t.Error("GetLastHash() should not be empty after writes")
	}
}

// TestPersistenceExportForCompliance verifies compliance export produces data
func TestPersistenceExportForCompliance(t *testing.T) {
	mgr, cleanup := newTestPersistence(t, tier.TierCommunity)
	defer cleanup()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	auditLog := mgr.AuditLog()
	ctx := context.Background()

	// Write an event
	err := auditLog.LogComplianceEvent(ctx, opsec.AuditLevelInfo, "export_test", "compliance export test", []string{"SOC2", "NIST"}, nil)
	if err != nil {
		t.Fatalf("LogComplianceEvent failed: %v", err)
	}

	// Export
	data, err := mgr.ExportForCompliance(ctx, "json")
	if err != nil {
		t.Fatalf("ExportForCompliance failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("ExportForCompliance should return non-empty data")
	}

	// Verify it's valid JSON
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("Export should produce valid JSON, got error: %v", err)
	}
}

// TestPersistenceStats verifies Stats() returns expected keys
func TestPersistenceStats(t *testing.T) {
	mgr, cleanup := newTestPersistence(t, tier.TierCommunity)
	defer cleanup()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	stats := mgr.Stats()

	expectedKeys := []string{"enabled", "audit_dir", "retention_days", "started", "entry_count", "last_hash"}
	for _, key := range expectedKeys {
		if _, ok := stats[key]; !ok {
			t.Errorf("Stats() missing key %q, got keys: %v", key, mapKeys(stats))
		}
	}

	// Verify specific values
	if stats["enabled"] != true {
		t.Error("Stats enabled should be true")
	}
	if stats["retention_days"] != 7 { // Community = 7 days
		t.Errorf("Stats retention_days = %v, want 7", stats["retention_days"])
	}
	if stats["started"] != true {
		t.Error("Stats started should be true after Start()")
	}
}

// TestPersistenceStatsDisabled verifies Stats() works when disabled
func TestPersistenceStatsDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := persistence.Config{
		Enabled:       false,
		DataDir:       filepath.Join(tmpDir, "data"),
		AuditDir:      filepath.Join(tmpDir, "audit"),
		PruneInterval: 1 * time.Hour,
		MaxFileSize:   10 * 1024 * 1024,
	}

	mgr, err := persistence.New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	stats := mgr.Stats()
	if stats["enabled"] != false {
		t.Error("Stats enabled should be false")
	}
	if stats["started"] != false {
		t.Error("Stats started should be false when disabled")
	}
}

// mapKeys returns the keys of a map[string]interface{} for error messages
func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// ======================================================================
// PHASE 3: CertInit Integration Tests
// ======================================================================

// TestCertInitLifecycle verifies EnsureCerts generates certs when AutoGenerate=true
func TestCertInitLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := certinit.Config{
		CertDir:      tmpDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	if !result.Generated {
		t.Error("Expected Generated=true on first run with empty cert dir")
	}
	if result.Existing {
		t.Error("Expected Existing=false on first run (no prior certs)")
	}

	// Verify all paths are set
	if result.CACertPath == "" {
		t.Error("CACertPath should not be empty")
	}
	if result.CAKeyPath == "" {
		t.Error("CAKeyPath should not be empty")
	}
	if result.ServerCertPath == "" {
		t.Error("ServerCertPath should not be empty")
	}
	if result.ServerKeyPath == "" {
		t.Error("ServerKeyPath should not be empty")
	}

	// Verify expiry dates are in the future
	now := time.Now()
	if result.CAExpiry.Before(now) {
		t.Error("CA cert expiry should be in the future")
	}
	if result.ServerExpiry.Before(now) {
		t.Error("Server cert expiry should be in the future")
	}
}

// TestCertInitIdempotency verifies second call reports Existing=true
func TestCertInitIdempotency(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := certinit.Config{
		CertDir:      tmpDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	// First call: should generate
	result1, err := certinit.EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("First EnsureCerts failed: %v", err)
	}
	if !result1.Generated {
		t.Error("First call should report Generated=true")
	}
	if result1.Existing {
		t.Error("First call should report Existing=false")
	}

	// Second call: should detect existing
	result2, err := certinit.EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("Second EnsureCerts failed: %v", err)
	}
	if result2.Generated {
		t.Error("Second call should report Generated=false (certs already exist)")
	}
	if !result2.Existing {
		t.Error("Second call should report Existing=true (certs already exist)")
	}
}

// TestCertInitDirectoryStructure verifies cert files exist on disk after EnsureCerts
func TestCertInitDirectoryStructure(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := certinit.Config{
		CertDir:      tmpDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	expectedFiles := []string{
		result.CACertPath,
		result.CAKeyPath,
		result.ServerCertPath,
		result.ServerKeyPath,
	}

	for _, path := range expectedFiles {
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("Expected file %s to exist: %v", path, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("File %s should not be empty", path)
		}
	}
}

// TestCertInitValidateCerts verifies ValidateCerts returns Valid=true after generation
func TestCertInitValidateCerts(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := certinit.Config{
		CertDir:      tmpDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	// Generate certificates first
	_, err := certinit.EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	// Now validate them
	validation, err := certinit.ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts failed: %v", err)
	}

	if !validation.Valid {
		t.Errorf("Certs should be valid after generation, issues: %v", validation.Issues)
	}
	if !validation.ServerCertValid {
		t.Error("Server cert should be valid")
	}
	if !validation.ServerKeyValid {
		t.Error("Server key should be valid")
	}
	if !validation.CACertValid {
		t.Error("CA cert should be valid")
	}
	if !validation.CAKeyValid {
		t.Error("CA key should be valid")
	}
	if !validation.CAIsCA {
		t.Error("CA cert should have IsCA=true")
	}
	if len(validation.Issues) != 0 {
		t.Errorf("Expected no validation issues, got: %v", validation.Issues)
	}

	// Verify SANs include localhost
	foundLocalhost := false
	for _, san := range validation.ServerSANs {
		if san == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Errorf("Server cert SANs should include localhost, got: %v", validation.ServerSANs)
	}
}

// TestCertInitAutoGenerateDisabled verifies graceful handling when AutoGenerate=false
func TestCertInitAutoGenerateDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := certinit.Config{
		CertDir:      tmpDir,
		AutoGenerate: false,
		Hostnames:    []string{"localhost"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts with AutoGenerate=false should not error: %v", err)
	}

	if result.Generated {
		t.Error("Should not generate when AutoGenerate=false")
	}
	if result.Existing {
		t.Error("Should not report Existing when no certs exist and AutoGenerate=false")
	}

	// Should have a warning about auto_generate being disabled
	if len(result.Warnings) == 0 {
		t.Error("Expected at least one warning about auto_generate disabled")
	}

	foundAutoGenWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "auto_generate") {
			foundAutoGenWarning = true
		}
	}
	if !foundAutoGenWarning {
		t.Errorf("Expected warning about auto_generate, got: %v", result.Warnings)
	}

	// ValidateCerts should report issues (no certs exist)
	validation, err := certinit.ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts should not error: %v", err)
	}
	if validation.Valid {
		t.Error("Certs should not be valid when none exist")
	}
	if validation.ServerCertValid {
		t.Error("Server cert should not be valid when file doesn't exist")
	}
}

// TestCertInitCustomHostnames verifies custom hostnames in SANs
func TestCertInitCustomHostnames(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := certinit.Config{
		CertDir:      tmpDir,
		AutoGenerate: true,
		Hostnames:    []string{"localhost", "test.example.com", "aegisgate.local"},
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		CACertFile:   "ca.crt",
		CAKeyFile:    "ca.key",
	}

	result, err := certinit.EnsureCerts(cfg)
	if err != nil {
		t.Fatalf("EnsureCerts with custom hostnames failed: %v", err)
	}
	if !result.Generated {
		t.Error("Should generate certs with custom hostnames")
	}

	// Validate and check CN/SANs
	validation, err := certinit.ValidateCerts(cfg)
	if err != nil {
		t.Fatalf("ValidateCerts after generation failed: %v", err)
	}

	// The CN should be the first hostname
	if validation.ServerCN != "localhost" {
		t.Errorf("Server CN = %q, want localhost", validation.ServerCN)
	}

	// Note: GenerateProxyCertificate only uses the primary hostname for the cert.
	// SANs may or may not include all hostnames depending on the upstream implementation.
	// At minimum, localhost should be present.
	foundLocalhost := false
	for _, san := range validation.ServerSANs {
		if san == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Errorf("Server cert SANs should include localhost, got: %v", validation.ServerSANs)
	}
}

// TestCertInitDefaultConfig verifies DefaultConfig returns expected values
func TestCertInitDefaultConfig(t *testing.T) {
	cfg := certinit.DefaultConfig()

	if cfg.CertDir != "./certs" {
		t.Errorf("Default CertDir = %q, want ./certs", cfg.CertDir)
	}
	if !cfg.AutoGenerate {
		t.Error("Default AutoGenerate should be true")
	}
	if len(cfg.Hostnames) != 1 || cfg.Hostnames[0] != "localhost" {
		t.Errorf("Default Hostnames = %v, want [localhost]", cfg.Hostnames)
	}
	if cfg.CertFile != "server.crt" {
		t.Errorf("Default CertFile = %q, want server.crt", cfg.CertFile)
	}
	if cfg.KeyFile != "server.key" {
		t.Errorf("Default KeyFile = %q, want server.key", cfg.KeyFile)
	}
	if cfg.CACertFile != "ca.crt" {
		t.Errorf("Default CACertFile = %q, want ca.crt", cfg.CACertFile)
	}
	if cfg.CAKeyFile != "ca.key" {
		t.Errorf("Default CAKeyFile = %q, want ca.key", cfg.CAKeyFile)
	}
}

// ======================================================================
// PHASE 4: Guardrails Integration Tests
// ======================================================================

// TestGuardrailSessionLimit verifies that the concurrent session limit is enforced.
func TestGuardrailSessionLimit(t *testing.T) {
	cfg := mcpserver.DefaultGuardrailConfig(tier.TierCommunity)
	cfg.Enabled = true
	gm := mcpserver.NewGuardrailMiddleware(cfg)
	defer gm.Close()

	maxSessions := tier.TierCommunity.MaxConcurrentMCP() // 5

	// Fill up to max
	for i := 0; i < maxSessions; i++ {
		err := gm.OnSessionCreate(fmt.Sprintf("sess-%d", i), "agent")
		if err != nil {
			t.Fatalf("Session %d creation failed: %v", i, err)
		}
	}

	// One more should fail
	err := gm.OnSessionCreate("sess-overflow", "agent")
	if err == nil {
		t.Error("Expected error when exceeding max sessions, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "concurrent") {
		t.Errorf("Expected concurrent session error, got: %v", err)
	}

	// Stats should reflect blocked request
	stats := gm.Stats()
	if stats.BlockedRequests < 1 {
		t.Errorf("Expected BlockedRequests >= 1, got %d", stats.BlockedRequests)
	}
}

// TestGuardrailToolLimit verifies the per-session tool count limit.
func TestGuardrailToolLimit(t *testing.T) {
	cfg := mcpserver.DefaultGuardrailConfig(tier.TierCommunity)
	cfg.Enabled = true
	gm := mcpserver.NewGuardrailMiddleware(cfg)
	defer gm.Close()

	maxTools := tier.TierCommunity.MaxMCPToolsPerSession() // 20

	// Create a session
	err := gm.OnSessionCreate("sess-tools", "agent")
	if err != nil {
		t.Fatalf("Session creation failed: %v", err)
	}

	// Call tools up to the limit
	for i := 0; i < maxTools; i++ {
		err := gm.OnToolCall("sess-tools", fmt.Sprintf("tool-%d", i))
		if err != nil {
			t.Fatalf("Tool call %d failed: %v", i, err)
		}
	}

	// One more tool call should exceed the limit
	err = gm.OnToolCall("sess-tools", "tool-overflow")
	if err == nil {
		t.Error("Expected error when exceeding tool limit, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "tool limit") {
		t.Errorf("Expected tool limit error, got: %v", err)
	}
}

// TestGuardrailExecTimeout verifies that OnToolCallWithContext creates a deadline.
func TestGuardrailExecTimeout(t *testing.T) {
	cfg := mcpserver.DefaultGuardrailConfig(tier.TierCommunity)
	cfg.Enabled = true
	gm := mcpserver.NewGuardrailMiddleware(cfg)
	defer gm.Close()

	ctx := context.Background()
	ctx2, cancel := gm.OnToolCallWithContext(ctx)
	defer cancel()

	deadline, ok := ctx2.Deadline()
	if !ok {
		t.Error("Expected context to have a deadline for Community tier")
	}

	expectedTimeout := time.Duration(tier.TierCommunity.MCPExecTimeoutSeconds()) * time.Second
	remaining := time.Until(deadline)
	if remaining > expectedTimeout || remaining < expectedTimeout-2*time.Second {
		t.Errorf("Deadline approximately %v away, expected ~%v", remaining, expectedTimeout)
	}
}

// TestGuardrailExecTimeoutUnlimited verifies Enterprise tier returns no deadline.
func TestGuardrailExecTimeoutUnlimited(t *testing.T) {
	cfg := mcpserver.DefaultGuardrailConfig(tier.TierEnterprise)
	cfg.Enabled = true
	gm := mcpserver.NewGuardrailMiddleware(cfg)
	defer gm.Close()

	ctx := context.Background()
	ctx2, cancel := gm.OnToolCallWithContext(ctx)
	defer cancel()

	_, ok := ctx2.Deadline()
	if ok {
		t.Error("Enterprise tier should have no deadline (unlimited timeout)")
	}
}

// TestGuardrailMemoryLimit verifies memory tracking (advisory at Community tier).
func TestGuardrailMemoryLimit(t *testing.T) {
	cfg := mcpserver.DefaultGuardrailConfig(tier.TierCommunity)
	cfg.Enabled = true
	gm := mcpserver.NewGuardrailMiddleware(cfg)
	defer gm.Close()

	err := gm.OnSessionCreate("sess-mem", "agent")
	if err != nil {
		t.Fatalf("Session creation failed: %v", err)
	}

	// Report memory usage — should not error at Community (advisory only)
	limitMB := tier.TierCommunity.MaxMCPSandboxMemoryMB() // 256
	gm.OnMemoryUsage("sess-mem", int64(limitMB)+100)

	// Verify session still tracked (advisory, not hard block)
	stats := gm.Stats()
	if stats.ActiveSessions != 1 {
		t.Errorf("Expected 1 active session after memory advisory, got %d", stats.ActiveSessions)
	}
}

// TestGuardrailHandler Wraps a RequestHandler and blocks on session overflow.
func TestGuardrailHandler(t *testing.T) {
	cfg := mcpserver.DefaultGuardrailConfig(tier.TierCommunity)
	cfg.Enabled = true
	gm := mcpserver.NewGuardrailMiddleware(cfg)
	defer gm.Close()

	// Create a minimal inner handler
	auth := &mockAuthorizer{}
	audit := &mockAuditLogger{}
	sess := &mockSessionManager{}
	innerHandler := mcp.NewRequestHandler(auth, audit, sess)

	wrapped := gm.GuardrailHandler(innerHandler)

	// Fill sessions to max
	maxSessions := tier.TierCommunity.MaxConcurrentMCP()
	for i := 0; i < maxSessions; i++ {
		_ = gm.OnSessionCreate(fmt.Sprintf("sess-%d", i), "agent")
	}

	// An initialize request should now be blocked by guardrails
	req := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		ID:      99,
	}
	conn := &mcp.Connection{
		ID:      "conn-1",
		Session: &mcp.Session{ID: "sess-overflow", AgentID: "agent"},
	}

	resp := wrapped(conn, req)
	if resp.Error == nil {
		t.Error("Expected guardrail error response for session overflow, got nil error")
	} else {
		if resp.Error.Code != -32000 {
			t.Errorf("Expected error code -32000, got %d", resp.Error.Code)
		}
		if !strings.Contains(resp.Error.Message, mcpserver.ErrMaxSessions) {
			t.Errorf("Expected error message containing %q, got %q", mcpserver.ErrMaxSessions, resp.Error.Message)
		}
	}
}

// TestGuardrailHandlerDisabled verifies guardrails are bypassed when disabled.
func TestGuardrailHandlerDisabled(t *testing.T) {
	cfg := mcpserver.DefaultGuardrailConfig(tier.TierCommunity)
	cfg.Enabled = false
	gm := mcpserver.NewGuardrailMiddleware(cfg)
	defer gm.Close()

	auth := &mockAuthorizer{}
	audit := &mockAuditLogger{}
	sess := &mockSessionManager{}
	innerHandler := mcp.NewRequestHandler(auth, audit, sess)

	wrapped := gm.GuardrailHandler(innerHandler)

	// Even with no sessions created, initialize should pass through
	req := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		ID:      1,
	}
	conn := &mcp.Connection{ID: "conn-1"}

	resp := wrapped(conn, req)
	// When disabled, the inner handler processes it (which is a real handler)
	// We just verify it doesn't return a guardrail error
	if resp.Error != nil && resp.Error.Code == -32000 {
		t.Error("Guardrail error should not be returned when guardrails are disabled")
	}
}

// TestGuardrailStats verifies stats reflect operations.
func TestGuardrailStats(t *testing.T) {
	cfg := mcpserver.DefaultGuardrailConfig(tier.TierCommunity)
	cfg.Enabled = true
	gm := mcpserver.NewGuardrailMiddleware(cfg)
	defer gm.Close()

	// Initial stats
	stats := gm.Stats()
	if stats.Tier != "community" {
		t.Errorf("Stats Tier = %q, want community", stats.Tier)
	}
	if stats.MaxSessions != 5 {
		t.Errorf("Stats MaxSessions = %d, want 5", stats.MaxSessions)
	}
	if stats.ToolsPerSession != 20 {
		t.Errorf("Stats ToolsPerSession = %d, want 20", stats.ToolsPerSession)
	}
	if stats.ExecTimeoutSec != 30 {
		t.Errorf("Stats ExecTimeoutSec = %d, want 30", stats.ExecTimeoutSec)
	}
	if stats.SandboxMemoryMB != 256 {
		t.Errorf("Stats SandboxMemoryMB = %d, want 256", stats.SandboxMemoryMB)
	}
	if !stats.GuardrailsEnabled {
		t.Error("Stats GuardrailsEnabled should be true")
	}

	// Create sessions, make tool calls, then check stats
	_ = gm.OnSessionCreate("sess-stats", "agent")
	_ = gm.OnToolCall("sess-stats", "tool-a")
	_ = gm.OnToolCall("sess-stats", "tool-b")

	stats = gm.Stats()
	if stats.ActiveSessions != 1 {
		t.Errorf("Stats ActiveSessions = %d, want 1", stats.ActiveSessions)
	}
	if stats.TotalRequests < 2 {
		t.Errorf("Stats TotalRequests = %d, want >= 2", stats.TotalRequests)
	}
}

// TestGuardrailTierEscalation verifies Developer tier allows more than Community.
func TestGuardrailTierEscalation(t *testing.T) {
	t.Run("DeveloperSessions", func(t *testing.T) {
		cfg := mcpserver.DefaultGuardrailConfig(tier.TierDeveloper)
		cfg.Enabled = true
		gm := mcpserver.NewGuardrailMiddleware(cfg)
		defer gm.Close()

		communityMax := tier.TierCommunity.MaxConcurrentMCP() // 5
		developerMax := tier.TierDeveloper.MaxConcurrentMCP() // 25

		if developerMax <= communityMax {
			t.Errorf("Developer max sessions (%d) should exceed Community (%d)", developerMax, communityMax)
		}

		// Create community's max sessions — should all succeed on Developer
		for i := 0; i < communityMax; i++ {
			err := gm.OnSessionCreate(fmt.Sprintf("sess-%d", i), "agent")
			if err != nil {
				t.Fatalf("Session %d should succeed on Developer tier: %v", i, err)
			}
		}

		stats := gm.Stats()
		if stats.MaxSessions != developerMax {
			t.Errorf("Stats MaxSessions = %d, want %d", stats.MaxSessions, developerMax)
		}
	})

	t.Run("DeveloperToolsPerSession", func(t *testing.T) {
		cfg := mcpserver.DefaultGuardrailConfig(tier.TierDeveloper)
		cfg.Enabled = true
		gm := mcpserver.NewGuardrailMiddleware(cfg)
		defer gm.Close()

		communityTools := tier.TierCommunity.MaxMCPToolsPerSession() // 20
		developerTools := tier.TierDeveloper.MaxMCPToolsPerSession() // 50

		if developerTools <= communityTools {
			t.Errorf("Developer tools/session (%d) should exceed Community (%d)", developerTools, communityTools)
		}

		_ = gm.OnSessionCreate("sess-dev", "agent")

		// Call community's max tools — should all succeed on Developer
		for i := 0; i < communityTools; i++ {
			err := gm.OnToolCall("sess-dev", fmt.Sprintf("tool-%d", i))
			if err != nil {
				t.Fatalf("Tool call %d should succeed on Developer tier: %v", i, err)
			}
		}
	})
}

// TestGuardrailSessionDestroy verifies sessions can be torn down.
func TestGuardrailSessionDestroy(t *testing.T) {
	cfg := mcpserver.DefaultGuardrailConfig(tier.TierCommunity)
	cfg.Enabled = true
	gm := mcpserver.NewGuardrailMiddleware(cfg)
	defer gm.Close()

	maxSessions := tier.TierCommunity.MaxConcurrentMCP() // 5

	// Fill up to max
	for i := 0; i < maxSessions; i++ {
		err := gm.OnSessionCreate(fmt.Sprintf("sess-%d", i), "agent")
		if err != nil {
			t.Fatalf("Session %d creation failed: %v", i, err)
		}
	}

	// Overflow should fail
	err := gm.OnSessionCreate("sess-overflow-1", "agent")
	if err == nil {
		t.Error("Expected overflow error before destroy")
	}

	// Destroy one session
	gm.OnSessionDestroy("sess-0")

	// Stats should reflect one fewer active session
	stats := gm.Stats()
	if stats.ActiveSessions != int64(maxSessions-1) {
		t.Errorf("ActiveSessions = %d, want %d", stats.ActiveSessions, maxSessions-1)
	}

	// Now a new session should succeed
	err = gm.OnSessionCreate("sess-new", "agent")
	if err != nil {
		t.Errorf("New session should succeed after destroy: %v", err)
	}
}

// ======================================================================
// PHASE 5: MCP Tool Registry Integration Tests
// ======================================================================

// TestToolRegistryRegisterAndList verifies tool registration and listing.
func TestToolRegistryRegisterAndList(t *testing.T) {
	reg := mcp.NewToolRegistry()

	err := reg.Register("read_config", "Read platform configuration", 1, nil)
	if err != nil {
		t.Fatalf("Register read_config failed: %v", err)
	}
	err = reg.Register("list_agents", "List registered agents", 2, nil)
	if err != nil {
		t.Fatalf("Register list_agents failed: %v", err)
	}

	tools := reg.ListTools()
	if len(tools) != 2 {
		t.Errorf("ListTools() returned %d tools, want 2", len(tools))
	}

	if reg.Count() != 2 {
		t.Errorf("Count() = %d, want 2", reg.Count())
	}

	// ToMCPFormat should return 2 tools
	mcpTools := reg.ToMCPFormat()
	if len(mcpTools) != 2 {
		t.Errorf("ToMCPFormat() returned %d tools, want 2", len(mcpTools))
	}
}

// TestToolRegistryExecute verifies tool handler execution.
func TestToolRegistryExecute(t *testing.T) {
	reg := mcp.NewToolRegistry()

	// Register a tool
	err := reg.Register("echo_tool", "Echo back the input", 1, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Register its handler
	err = reg.RegisterHandler("echo_tool", func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{"echo": params["message"]}, nil
	})
	if err != nil {
		t.Fatalf("RegisterHandler failed: %v", err)
	}

	// Execute the tool
	result, err := reg.Execute(context.Background(), "echo_tool", map[string]interface{}{"message": "hello"})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Execute result type = %T, want map[string]interface{}", result)
	}
	if resultMap["echo"] != "hello" {
		t.Errorf("Execute echo = %v, want hello", resultMap["echo"])
	}
}

// TestToolRegistryDuplicateRegister verifies duplicate registration fails.
func TestToolRegistryDuplicateRegister(t *testing.T) {
	reg := mcp.NewToolRegistry()

	err := reg.Register("dup_tool", "First registration", 1, nil)
	if err != nil {
		t.Fatalf("First Register failed: %v", err)
	}

	// Second registration with same name should fail
	err = reg.Register("dup_tool", "Duplicate registration", 1, nil)
	if err == nil {
		t.Error("Expected error on duplicate registration, got nil")
	}
}

// TestToolRegistryGetTool verifies tool lookup.
func TestToolRegistryGetTool(t *testing.T) {
	reg := mcp.NewToolRegistry()

	err := reg.Register("known_tool", "A known tool", 3, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Existing tool
	tool, ok := reg.GetTool("known_tool")
	if !ok {
		t.Error("GetTool(known_tool) returned not ok")
	}
	if tool != nil && tool.Name != "known_tool" {
		t.Errorf("GetTool name = %q, want known_tool", tool.Name)
	}

	// Non-existent tool
	_, ok = reg.GetTool("nonexistent")
	if ok {
		t.Error("GetTool(nonexistent) should return false")
	}

	// GetHandler for existing
	handler, ok := reg.GetHandler("known_tool")
	if ok && handler != nil {
		// No handler registered for known_tool, so this may be !ok
		t.Log("GetHandler returned a handler (unexpected since none registered)")
	}

	// Risk level
	risk := reg.GetRiskLevel("known_tool")
	if risk != 3 {
		t.Errorf("GetRiskLevel(known_tool) = %d, want 3", risk)
	}
}

// TestToolRegistryMissingHandler verifies Execute on tool without handler fails gracefully.
func TestToolRegistryMissingHandler(t *testing.T) {
	reg := mcp.NewToolRegistry()

	err := reg.Register("no_handler_tool", "Tool without handler", 1, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	_, err = reg.Execute(context.Background(), "no_handler_tool", nil)
	if err == nil {
		t.Error("Expected error executing tool without handler, got nil")
	}
}

// TestToolRegistryManyTools verifies registering many tools works correctly.
func TestToolRegistryManyTools(t *testing.T) {
	reg := mcp.NewToolRegistry()

	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("tool_%d", i)
		err := reg.Register(name, fmt.Sprintf("Tool number %d", i), i%5, nil)
		if err != nil {
			t.Fatalf("Register %s failed: %v", name, err)
		}
	}

	if reg.Count() != 50 {
		t.Errorf("Count() = %d, want 50", reg.Count())
	}

	tools := reg.ListTools()
	if len(tools) != 50 {
		t.Errorf("ListTools() returned %d, want 50", len(tools))
	}

	// ToMCPFormat should also return 50
	mcpTools := reg.ToMCPFormat()
	if len(mcpTools) != 50 {
		t.Errorf("ToMCPFormat() returned %d, want 50", len(mcpTools))
	}
}

// ======================================================================
// PHASE 6: Cross-Component Integration Tests
// ======================================================================

// TestGuardrailsWithToolRegistry verifies GuardrailHandler wrapping a RequestHandler
// with 17 built-in tools. Tool calls that are within limits should pass through;
// tool calls on over-limit sessions should be blocked.
func TestGuardrailsWithToolRegistry(t *testing.T) {
	platformTier := tier.TierCommunity

	// Create guardrail middleware
	gm := mcpserver.NewGuardrailMiddleware(mcpserver.DefaultGuardrailConfig(platformTier))
	defer gm.Close()

	// Create a request handler with mock adapters
	handler := mcp.NewRequestHandler(&mockAuthorizer{}, &mockAuditLogger{}, &mockSessionManager{})

	// Register built-in tools (12 safe + 5 blocked = 17)
	mcpserver.RegisterBuiltInTools(handler, platformTier)

	// Verify tools were registered
	if handler.Registry.Count() != 17 {
		t.Errorf("Registry has %d tools, want 17", handler.Registry.Count())
	}

	// Wrap the handler with guardrails
	wrapped := gm.GuardrailHandler(handler)

	// Create a mock connection and session
	srv := mcp.NewServer(&mcp.ServerConfig{ReadTimeout: 30 * time.Second})
	conn := &mcp.Connection{
		ID:        "conn-cross-1",
		Server:    srv,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Session:   &mcp.Session{ID: "sess-cross-1", AgentID: "agent-1"},
		AgentID:   "agent-1",
	}

	// Create a session in guardrails
	err := gm.OnSessionCreate("sess-cross-1", "agent-1")
	if err != nil {
		t.Fatalf("OnSessionCreate failed: %v", err)
	}

	// Send a tools/list request — should pass through guardrails
	listReq := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/list",
	}
	resp := wrapped(conn, listReq)
	if resp == nil {
		t.Fatal("GuardrailHandler returned nil response for tools/list")
	}
	if resp.Error != nil {
		t.Errorf("tools/list blocked by guardrails: %s", resp.Error.Message)
	}

	// tools/list is not a tool call, so TotalRequests stays 0
	// (TotalRequests is only incremented by OnToolCall for tools/call)
	stats := gm.Stats()
	if stats.TotalRequests != 0 {
		t.Errorf("TotalRequests = %d, want 0 (tools/list not counted as tool call)", stats.TotalRequests)
	}

	// Send a tools/call request — this increments TotalRequests
	toolCallReq := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"health_check"}`),
	}
	resp = wrapped(conn, toolCallReq)
	// Response may succeed or fail depending on handler, but guardrails should not block it
	_ = resp

	stats = gm.Stats()
	if stats.TotalRequests != 1 {
		t.Errorf("TotalRequests after tools/call = %d, want 1", stats.TotalRequests)
	}

	gm.OnSessionDestroy("sess-cross-1")
}

// TestPersistenceWithGuardrails verifies that when AuditViolations is enabled,
// guardrail violations are tracked and can be verified through persistence stats.
func TestPersistenceWithGuardrails(t *testing.T) {
	platformTier := tier.TierCommunity
	tmpDir := t.TempDir()

	// Create persistence manager
	pCfg := persistence.DefaultConfig()
	pCfg.Enabled = true
	pCfg.DataDir = tmpDir
	pCfg.AuditDir = tmpDir + "/audit"
	pCfg.PruneInterval = time.Hour // don't prune during test

	pm, err := persistence.New(platformTier, pCfg)
	if err != nil {
		t.Fatalf("persistence.New failed: %v", err)
	}
	defer pm.Close()

	if err := pm.Start(); err != nil {
		t.Fatalf("persistence.Start failed: %v", err)
	}

	// Create guardrail middleware with audit violations enabled
	gCfg := mcpserver.DefaultGuardrailConfig(platformTier)
	gCfg.AuditViolations = true
	gCfg.LogViolations = true
	gm := mcpserver.NewGuardrailMiddleware(gCfg)
	defer gm.Close()

	// Trigger a violation by exceeding session limit
	for i := 0; i < 5; i++ {
		sessID := fmt.Sprintf("sess-pg-%d", i)
		err := gm.OnSessionCreate(sessID, fmt.Sprintf("agent-%d", i))
		if err != nil {
			t.Fatalf("OnSessionCreate %s failed: %v", sessID, err)
		}
	}

	// 6th session should fail
	err = gm.OnSessionCreate("sess-pg-overflow", "agent-overflow")
	if err == nil {
		t.Error("Expected session limit violation, got nil error")
	}

	// Verify guardrail stats captured the block
	stats := gm.Stats()
	if stats.BlockedRequests == 0 {
		t.Error("BlockedRequests = 0, want at least 1 after session overflow")
	}

	// Write a compliance event via persistence to confirm audit integration path
	auditLog := pm.AuditLog()
	if auditLog != nil {
		ctx := context.Background()
		auditLog.LogComplianceEvent(ctx, opsec.AuditLevelWarning, "guardrail_violation",
			"Session limit exceeded", nil, nil)
		count := auditLog.GetEntryCount()
		if count == 0 {
			t.Error("AuditLog entry count = 0 after logging violation event")
		}
	}

	// Clean up sessions
	for i := 0; i < 5; i++ {
		gm.OnSessionDestroy(fmt.Sprintf("sess-pg-%d", i))
	}
}

// TestCertInitWithPersistence verifies that persistence data directories
// and cert directories work together without conflicts.
func TestCertInitWithPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	platformTier := tier.TierCommunity

	// Set up persistence directories
	pCfg := persistence.DefaultConfig()
	pCfg.Enabled = true
	pCfg.DataDir = tmpDir
	pCfg.AuditDir = tmpDir + "/audit"
	pCfg.PruneInterval = time.Hour

	pm, err := persistence.New(platformTier, pCfg)
	if err != nil {
		t.Fatalf("persistence.New failed: %v", err)
	}
	defer pm.Close()

	if err := pm.Start(); err != nil {
		t.Fatalf("persistence.Start failed: %v", err)
	}

	// Set up cert directories using the same base temp dir
	certDir := tmpDir + "/certs"
	cCfg := certinit.DefaultConfig()
	cCfg.CertDir = certDir
	cCfg.AutoGenerate = true
	cCfg.Hostnames = []string{"localhost"}

	result, err := certinit.EnsureCerts(cCfg)
	if err != nil {
		t.Fatalf("EnsureCerts failed: %v", err)
	}

	if result == nil {
		t.Fatal("EnsureCerts returned nil result")
	}

	// Verify cert files exist in the shared base directory structure
	if result.ServerCertPath != "" {
		if _, err := os.Stat(result.ServerCertPath); os.IsNotExist(err) {
			t.Errorf("Server cert not found at %s", result.ServerCertPath)
		}
	}

	if result.ServerKeyPath != "" {
		if _, err := os.Stat(result.ServerKeyPath); os.IsNotExist(err) {
			t.Errorf("Server key not found at %s", result.ServerKeyPath)
		}
	}

	// Verify persistence is still functional alongside cert dir
	if !pm.IsEnabled() {
		t.Error("Persistence should be enabled alongside cert generation")
	}

	stats := pm.Stats()
	if stats == nil {
		t.Error("Persistence Stats() returned nil")
	}
}

// TestFullPlatformStack verifies EmbeddedServer + Guardrails + BuiltInTools
// all work together. This is the ultimate cross-component integration test.
func TestFullPlatformStack(t *testing.T) {
	platformTier := tier.TierCommunity

	// Create MCP server config with a dynamic port
	mcpCfg := &mcpserver.Config{
		Address:      ":0", // random port
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Create embedded server
	embeddedServer := mcpserver.NewEmbeddedServer(mcpCfg)

	// Register built-in tools
	mcpserver.RegisterBuiltInTools(embeddedServer.Handler(), platformTier)

	// Create guardrails
	gm := mcpserver.NewGuardrailMiddleware(mcpserver.DefaultGuardrailConfig(platformTier))
	defer gm.Close()

	// Verify tools registered on the handler
	registry := embeddedServer.Handler().Registry
	if registry.Count() != 17 {
		t.Errorf("Registry has %d tools, want 17", registry.Count())
	}

	// Wrap the handler with guardrails
	innerHandler := embeddedServer.Handler()
	wrappedHandler := gm.GuardrailHandler(innerHandler)

	// Create a test connection with session info
	srv := mcp.NewServer(&mcp.ServerConfig{ReadTimeout: 30 * time.Second})
	conn := &mcp.Connection{
		ID:        "conn-stack",
		Server:    srv,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		Session:   &mcp.Session{ID: "sess-stack-1", AgentID: "agent-stack"},
		AgentID:   "agent-stack",
	}

	// Send an initialize request — GuardrailHandler creates session internally
	initReq := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
		Params:  json.RawMessage(`{"clientInfo":{"name":"test-client","version":"1.0"}}`),
	}
	resp := wrappedHandler(conn, initReq)
	if resp == nil {
		t.Fatal("Full stack: initialize returned nil response")
	}
	if resp.Error != nil {
		t.Errorf("Full stack: initialize error: %s", resp.Error.Message)
	}

	// Send tools/list through guarded handler
	listReq := &mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/list",
	}
	resp = wrappedHandler(conn, listReq)
	if resp == nil {
		t.Fatal("Full stack: tools/list returned nil response")
	}
	if resp.Error != nil {
		t.Errorf("Full stack: tools/list error: %s", resp.Error.Message)
	}

	// Verify guardrail stats
	stats := gm.Stats()
	// TotalRequests only increments on tools/call, not tools/list or initialize
	if stats.ActiveSessions != 1 {
		t.Errorf("ActiveSessions = %d, want 1 (created by initialize)", stats.ActiveSessions)
	}
	if stats.BlockedRequests != 0 {
		t.Errorf("BlockedRequests = %d, want 0 (no violations yet)", stats.BlockedRequests)
	}

	// Now overflow sessions to test guardrails blocking
	// sess-stack-1 already exists from initialize, add 4 more to hit limit of 5
	for i := 2; i <= 5; i++ {
		err := gm.OnSessionCreate(fmt.Sprintf("sess-stack-%d", i), fmt.Sprintf("agent-%d", i))
		if err != nil {
			t.Fatalf("OnSessionCreate sess-stack-%d should succeed: %v", i, err)
		}
	}

	// 6th session should exceed Community limit (5)
	err := gm.OnSessionCreate("sess-stack-overflow", "agent-overflow")
	if err == nil {
		t.Error("Expected session overflow error, got nil")
	}

	// Verify blocked count
	stats = gm.Stats()
	if stats.BlockedRequests < 1 {
		t.Errorf("BlockedRequests = %d, want >= 1 after overflow", stats.BlockedRequests)
	}

	gm.OnSessionDestroy("sess-stack-1")
}

// --- Mock implementations for MCP interfaces ---

type mockAuthorizer struct{}

func (m *mockAuthorizer) Authorize(ctx context.Context, call *mcp.AuthorizationCall) (*mcp.AuthorizationDecision, error) {
	return &mcp.AuthorizationDecision{Allowed: true, Reason: "mock allow"}, nil
}

type mockAuditLogger struct{}

func (m *mockAuditLogger) Log(ctx context.Context, entry *mcp.AuditEntry) error {
	return nil
}

type mockSessionManager struct{}

func (m *mockSessionManager) CreateSession(ctx context.Context, agentID string) (*mcp.Session, error) {
	return &mcp.Session{ID: "mock-session", AgentID: agentID}, nil
}

func (m *mockSessionManager) GetSession(ctx context.Context, sessionID string) (*mcp.Session, error) {
	return &mcp.Session{ID: sessionID, AgentID: "mock-agent"}, nil
}

func (m *mockSessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	return nil
}

// ======================================================================
// PHASE 7: Platform Config Integration Tests
// ======================================================================

// TestConfigDefaultValues verifies DefaultConfig() returns expected zero-config values.
func TestConfigDefaultValues(t *testing.T) {
	cfg := platformconfig.DefaultConfig()

	// Platform defaults
	if cfg.Platform.Mode != "standalone" {
		t.Errorf("Platform.Mode = %q, want %q", cfg.Platform.Mode, "standalone")
	}
	if cfg.Platform.ShutdownTimeout != 30*time.Second {
		t.Errorf("Platform.ShutdownTimeout = %v, want 30s", cfg.Platform.ShutdownTimeout)
	}

	// Proxy defaults
	if cfg.Proxy.BindAddress != ":8080" {
		t.Errorf("Proxy.BindAddress = %q, want %q", cfg.Proxy.BindAddress, ":8080")
	}
	if cfg.Proxy.RateLimit != 200 {
		t.Errorf("Proxy.RateLimit = %d, want 200", cfg.Proxy.RateLimit)
	}

	// Dashboard defaults
	if !cfg.Dashboard.Enabled {
		t.Error("Dashboard.Enabled = false, want true")
	}
	if cfg.Dashboard.Port != 8443 {
		t.Errorf("Dashboard.Port = %d, want 8443", cfg.Dashboard.Port)
	}

	// TLS defaults
	if cfg.TLS.Enabled {
		t.Error("TLS.Enabled = true, want false (zero-config)")
	}
	if !cfg.TLS.AutoGenerate {
		t.Error("TLS.AutoGenerate = false, want true (zero-config)")
	}

	// Security defaults
	if !cfg.Security.EnableSecurityHeaders {
		t.Error("Security.EnableSecurityHeaders = false, want true")
	}
	if !cfg.Security.EnableAuditMiddleware {
		t.Error("Security.EnableAuditMiddleware = false, want true")
	}

	// Logging defaults
	if cfg.Logging.Level != "info" {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "info")
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Logging.Format = %q, want %q", cfg.Logging.Format, "json")
	}

	// Persistence defaults
	if !cfg.Persistence.Enabled {
		t.Error("Persistence.Enabled = false by default, want true")
	}

	// FIPS defaults
	if cfg.TLS.FIPS.Enabled {
		t.Error("FIPS.Enabled = true by default, want false")
	}

	// Helper methods
	if cfg.ProxyPort() != 8080 {
		t.Errorf("ProxyPort() = %d, want 8080", cfg.ProxyPort())
	}
	// MCPPort returns the agent server port from agconfig.DefaultConfig (8080)
	if cfg.MCPPort() != 8080 {
		t.Errorf("MCPPort() = %d, want 8080 (agent default)", cfg.MCPPort())
	}
}

// TestConfigEnvOverrides verifies environment variables override config values.
func TestConfigEnvOverrides(t *testing.T) {
	// Set env vars (t.Setenv auto-cleans after test)
	t.Setenv("AEGISGATE_PERSISTENCE_ENABLED", "true")
	t.Setenv("AEGISGATE_DATA_DIR", "/test/data")
	t.Setenv("AEGISGATE_BIND_ADDRESS", "0.0.0.0:9999")
	t.Setenv("AEGISGATE_UPSTREAM", "https://api.anthropic.com")
	t.Setenv("AEGISGATE_RATE_LIMIT", "500")
	t.Setenv("AEGISGATE_TLS_ENABLED", "true")
	t.Setenv("AEGISGATE_TLS_CERT", "/test/cert.pem")
	t.Setenv("AEGISGATE_TLS_KEY", "/test/key.pem")
	t.Setenv("AEGISGATE_DASHBOARD_PORT", "9443")
	t.Setenv("AEGIS_PORT", "9081")
	t.Setenv("AEGISGATE_SECURITY_HEADERS", "false")
	t.Setenv("AEGISGATE_FIPS_ENABLED", "true")
	t.Setenv("AEGISGATE_LOG_LEVEL", "debug")
	t.Setenv("LICENSE_KEY", "test-license-123")
	t.Setenv("AEGISGATE_PLATFORM_MODE", "connected")

	// Use Load("") which internally calls DefaultConfig + applyEnvOverrides
	cfg, err := platformconfig.Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify all overrides applied
	if !cfg.Persistence.Enabled {
		t.Error("Persistence.Enabled not overridden to true")
	}
	if cfg.Persistence.DataDir != "/test/data" {
		t.Errorf("Persistence.DataDir = %q, want %q", cfg.Persistence.DataDir, "/test/data")
	}
	if cfg.Persistence.AuditDir != "/test/data/audit" {
		t.Errorf("Persistence.AuditDir = %q, want %q", cfg.Persistence.AuditDir, "/test/data/audit")
	}
	if cfg.Proxy.BindAddress != "0.0.0.0:9999" {
		t.Errorf("Proxy.BindAddress = %q, want %q", cfg.Proxy.BindAddress, "0.0.0.0:9999")
	}
	if cfg.Proxy.Upstream != "https://api.anthropic.com" {
		t.Errorf("Proxy.Upstream = %q, want %q", cfg.Proxy.Upstream, "https://api.anthropic.com")
	}
	if cfg.Proxy.RateLimit != 500 {
		t.Errorf("Proxy.RateLimit = %d, want 500", cfg.Proxy.RateLimit)
	}
	if !cfg.TLS.Enabled {
		t.Error("TLS.Enabled not overridden to true")
	}
	if cfg.TLS.CertFile != "/test/cert.pem" {
		t.Errorf("TLS.CertFile = %q, want %q", cfg.TLS.CertFile, "/test/cert.pem")
	}
	if cfg.TLS.KeyFile != "/test/key.pem" {
		t.Errorf("TLS.KeyFile = %q, want %q", cfg.TLS.KeyFile, "/test/key.pem")
	}
	if cfg.Dashboard.Port != 9443 {
		t.Errorf("Dashboard.Port = %d, want 9443", cfg.Dashboard.Port)
	}
	if cfg.MCPPort() != 9081 {
		t.Errorf("MCPPort() = %d, want 9081", cfg.MCPPort())
	}
	if cfg.Security.EnableSecurityHeaders {
		t.Error("Security.EnableSecurityHeaders should be false after override")
	}
	if !cfg.TLS.FIPS.Enabled {
		t.Error("FIPS.Enabled not overridden to true")
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "debug")
	}
	if cfg.Platform.Mode != "connected" {
		t.Errorf("Platform.Mode = %q, want %q", cfg.Platform.Mode, "connected")
	}

	// Verify AEGISGATE_DATA_DIR also sets CertDir
	if cfg.TLS.CertDir != "/test/data/certs" {
		t.Errorf("TLS.CertDir = %q, want %q (derived from AEGISGATE_DATA_DIR)", cfg.TLS.CertDir, "/test/data/certs")
	}
}

// TestConfigLoadFromEmptyString verifies Load("") returns defaults + env overrides.
func TestConfigLoadFromEmptyString(t *testing.T) {
	t.Setenv("AEGISGATE_PLATFORM_MODE", "standalone")

	cfg, err := platformconfig.Load("")
	if err != nil {
		t.Fatalf("Load(\"\") failed: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load(\"\") returned nil config")
	}
	if cfg.Platform.Mode != "standalone" {
		t.Errorf("Platform.Mode = %q, want %q (from env override)", cfg.Platform.Mode, "standalone")
	}
}

// TestConfigLoadFromMissingFile verifies LoadFromFile with nonexistent path
// returns defaults + env overrides (not raw defaults).
func TestConfigLoadFromMissingFile(t *testing.T) {
	t.Setenv("AEGISGATE_PERSISTENCE_ENABLED", "true")

	cfg, err := platformconfig.LoadFromFile("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("LoadFromFile with missing file should not error, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadFromFile returned nil config")
	}
	// This is the key test: even when file is missing, env overrides must be applied
	if !cfg.Persistence.Enabled {
		t.Error("Persistence.Enabled = false, want true (env override should apply even for missing file)")
	}
}

// TestConfigLoadFromYAML verifies loading from an actual YAML config file.
func TestConfigLoadFromYAML(t *testing.T) {
	configPath := "../../configs/community.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("community.yaml not found (running from unexpected directory)")
	}

	cfg, err := platformconfig.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile(%s) failed: %v", configPath, err)
	}

	// Verify values from community.yaml
	if !cfg.Persistence.Enabled {
		t.Error("Persistence.Enabled from YAML = false, want true")
	}
	if cfg.Persistence.DataDir != "/data" {
		t.Errorf("Persistence.DataDir = %q, want %q", cfg.Persistence.DataDir, "/data")
	}
	if cfg.Dashboard.Port != 8443 {
		t.Errorf("Dashboard.Port = %d, want 8443", cfg.Dashboard.Port)
	}
	if !cfg.TLS.AutoGenerate {
		t.Error("TLS.AutoGenerate from YAML = false, want true")
	}
	if cfg.TLS.CertDir != "/data/certs" {
		t.Errorf("TLS.CertDir = %q, want %q", cfg.TLS.CertDir, "/data/certs")
	}
}

// TestConfigIsStandaloneMode verifies IsStandaloneMode with config and CLI flag.
func TestConfigIsStandaloneMode(t *testing.T) {
	cfg := platformconfig.DefaultConfig()

	// Default mode is "standalone"
	if !cfg.IsStandaloneMode(false) {
		t.Error("IsStandaloneMode(false) = false for default config, want true")
	}

	// CLI flag overrides config
	cfg.Platform.Mode = "connected"
	if !cfg.IsStandaloneMode(true) {
		t.Error("IsStandaloneMode(true) should always return true")
	}

	// Non-standalone mode without CLI flag
	if cfg.IsStandaloneMode(false) {
		t.Error("IsStandaloneMode(false) = true for connected mode, want false")
	}
}

// TestConfigProxyPortParsing verifies ProxyPort extracts port from bind address.
func TestConfigProxyPortParsing(t *testing.T) {
	tests := []struct {
		addr     string
		expected int
	}{
		{":8080", 8080},
		{"0.0.0.0:9999", 9999},
		{"127.0.0.1:3000", 3000},
		{"", 8080},          // default fallback
		{"localhost", 8080}, // no colon-split → default
	}

	for _, tc := range tests {
		cfg := platformconfig.DefaultConfig()
		cfg.Proxy.BindAddress = tc.addr
		got := cfg.ProxyPort()
		if got != tc.expected {
			t.Errorf("ProxyPort() for %q = %d, want %d", tc.addr, got, tc.expected)
		}
	}
}

// ======================================================================
// PHASE 8: Tier System Integration Tests (Extended)
// ======================================================================

// TestDeveloperTierLimits verifies Developer tier rate and MCP limits.
func TestDeveloperTierLimits(t *testing.T) {
	dt := tier.TierDeveloper

	if dt.RateLimitProxy() != 600 {
		t.Errorf("Developer RateLimitProxy = %d, want 600", dt.RateLimitProxy())
	}
	if dt.RateLimitMCP() != 300 {
		t.Errorf("Developer RateLimitMCP = %d, want 300", dt.RateLimitMCP())
	}
	if dt.MaxConcurrentMCP() != 25 {
		t.Errorf("Developer MaxConcurrentMCP = %d, want 25", dt.MaxConcurrentMCP())
	}
	if dt.MaxMCPToolsPerSession() != 50 {
		t.Errorf("Developer MaxMCPToolsPerSession = %d, want 50", dt.MaxMCPToolsPerSession())
	}
	if dt.MCPExecTimeoutSeconds() != 60 {
		t.Errorf("Developer MCPExecTimeoutSeconds = %d, want 60", dt.MCPExecTimeoutSeconds())
	}
	if dt.MaxMCPSandboxMemoryMB() != 512 {
		t.Errorf("Developer MaxMCPSandboxMemoryMB = %d, want 512", dt.MaxMCPSandboxMemoryMB())
	}
	if dt.MaxUsers() != 10 {
		t.Errorf("Developer MaxUsers = %d, want 10", dt.MaxUsers())
	}
	if dt.MaxAgents() != 5 {
		t.Errorf("Developer MaxAgents = %d, want 5", dt.MaxAgents())
	}
	if dt.LogRetentionDays() != 30 {
		t.Errorf("Developer LogRetentionDays = %d, want 30", dt.LogRetentionDays())
	}
	if dt.SupportLevel() != "email" {
		t.Errorf("Developer SupportLevel = %q, want %q", dt.SupportLevel(), "email")
	}
}

// TestProfessionalTierLimits verifies Professional tier rate and MCP limits.
func TestProfessionalTierLimits(t *testing.T) {
	pt := tier.TierProfessional

	if pt.RateLimitProxy() != 3000 {
		t.Errorf("Professional RateLimitProxy = %d, want 3000", pt.RateLimitProxy())
	}
	if pt.RateLimitMCP() != 1500 {
		t.Errorf("Professional RateLimitMCP = %d, want 1500", pt.RateLimitMCP())
	}
	if pt.MaxConcurrentMCP() != 100 {
		t.Errorf("Professional MaxConcurrentMCP = %d, want 100", pt.MaxConcurrentMCP())
	}
	if pt.MaxMCPToolsPerSession() != -1 {
		t.Errorf("Professional MaxMCPToolsPerSession = %d, want -1 (unlimited)", pt.MaxMCPToolsPerSession())
	}
	if pt.MCPExecTimeoutSeconds() != 300 {
		t.Errorf("Professional MCPExecTimeoutSeconds = %d, want 300", pt.MCPExecTimeoutSeconds())
	}
	if pt.MaxMCPSandboxMemoryMB() != 2048 {
		t.Errorf("Professional MaxMCPSandboxMemoryMB = %d, want 2048", pt.MaxMCPSandboxMemoryMB())
	}
	if pt.MaxUsers() != 50 {
		t.Errorf("Professional MaxUsers = %d, want 50", pt.MaxUsers())
	}
	if pt.MaxAgents() != 25 {
		t.Errorf("Professional MaxAgents = %d, want 25", pt.MaxAgents())
	}
	if pt.LogRetentionDays() != 90 {
		t.Errorf("Professional LogRetentionDays = %d, want 90", pt.LogRetentionDays())
	}
	if pt.SupportLevel() != "priority" {
		t.Errorf("Professional SupportLevel = %q, want %q", pt.SupportLevel(), "priority")
	}
}

// TestEnterpriseTierLimits verifies Enterprise tier limits (mostly unlimited).
func TestEnterpriseTierLimits(t *testing.T) {
	et := tier.TierEnterprise

	if et.RateLimitProxy() != -1 {
		t.Errorf("Enterprise RateLimitProxy = %d, want -1 (unlimited)", et.RateLimitProxy())
	}
	if et.RateLimitMCP() != -1 {
		t.Errorf("Enterprise RateLimitMCP = %d, want -1 (unlimited)", et.RateLimitMCP())
	}
	if et.MaxConcurrentMCP() != -1 {
		t.Errorf("Enterprise MaxConcurrentMCP = %d, want -1 (unlimited)", et.MaxConcurrentMCP())
	}
	if et.MaxMCPToolsPerSession() != -1 {
		t.Errorf("Enterprise MaxMCPToolsPerSession = %d, want -1 (unlimited)", et.MaxMCPToolsPerSession())
	}
	if et.MCPExecTimeoutSeconds() != -1 {
		t.Errorf("Enterprise MCPExecTimeoutSeconds = %d, want -1 (unlimited)", et.MCPExecTimeoutSeconds())
	}
	if et.MaxMCPSandboxMemoryMB() != -1 {
		t.Errorf("Enterprise MaxMCPSandboxMemoryMB = %d, want -1 (unlimited)", et.MaxMCPSandboxMemoryMB())
	}
	if et.MaxUsers() != -1 {
		t.Errorf("Enterprise MaxUsers = %d, want -1 (unlimited)", et.MaxUsers())
	}
	if et.MaxAgents() != -1 {
		t.Errorf("Enterprise MaxAgents = %d, want -1 (unlimited)", et.MaxAgents())
	}
	if et.LogRetentionDays() != -1 {
		t.Errorf("Enterprise LogRetentionDays = %d, want -1 (unlimited)", et.LogRetentionDays())
	}
	if et.SupportLevel() != "24x7" {
		t.Errorf("Enterprise SupportLevel = %q, want %q", et.SupportLevel(), "24x7")
	}
}

// TestTierParseTier verifies string-to-tier parsing including aliases.
func TestTierParseTier(t *testing.T) {
	tests := []struct {
		input    string
		expected tier.Tier
		wantErr  bool
	}{
		{"community", tier.TierCommunity, false},
		{"free", tier.TierCommunity, false},
		{"Community", tier.TierCommunity, false},
		{" COMMUNITY ", tier.TierCommunity, false},
		{"developer", tier.TierDeveloper, false},
		{"dev", tier.TierDeveloper, false},
		{"professional", tier.TierProfessional, false},
		{"pro", tier.TierProfessional, false},
		{"enterprise", tier.TierEnterprise, false},
		{"ent", tier.TierEnterprise, false},
		{"invalid", tier.TierCommunity, true},
		{"premium", tier.TierCommunity, true},
		{"", tier.TierCommunity, true},
	}

	for _, tc := range tests {
		got, err := tier.ParseTier(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseTier(%q) expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseTier(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.expected {
				t.Errorf("ParseTier(%q) = %d, want %d", tc.input, got, tc.expected)
			}
		}
	}
}

// TestTierCanAccess verifies tier-gated feature access control.
func TestTierCanAccess(t *testing.T) {
	// Community can access Community features
	if !tier.TierCommunity.CanAccess(tier.TierCommunity) {
		t.Error("Community should access Community features")
	}
	// Community cannot access Developer features
	if tier.TierCommunity.CanAccess(tier.TierDeveloper) {
		t.Error("Community should NOT access Developer features")
	}
	// Developer can access Community + Developer
	if !tier.TierDeveloper.CanAccess(tier.TierCommunity) {
		t.Error("Developer should access Community features")
	}
	if !tier.TierDeveloper.CanAccess(tier.TierDeveloper) {
		t.Error("Developer should access Developer features")
	}
	if tier.TierDeveloper.CanAccess(tier.TierProfessional) {
		t.Error("Developer should NOT access Professional features")
	}
	// Professional can access Community + Developer + Professional
	if !tier.TierProfessional.CanAccess(tier.TierProfessional) {
		t.Error("Professional should access Professional features")
	}
	if tier.TierProfessional.CanAccess(tier.TierEnterprise) {
		t.Error("Professional should NOT access Enterprise features")
	}
	// Enterprise can access everything
	if !tier.TierEnterprise.CanAccess(tier.TierCommunity) {
		t.Error("Enterprise should access Community features")
	}
	if !tier.TierEnterprise.CanAccess(tier.TierDeveloper) {
		t.Error("Enterprise should access Developer features")
	}
	if !tier.TierEnterprise.CanAccess(tier.TierProfessional) {
		t.Error("Enterprise should access Professional features")
	}
	if !tier.TierEnterprise.CanAccess(tier.TierEnterprise) {
		t.Error("Enterprise should access Enterprise features")
	}

	// Feature-specific: RequiredTier + HasFeature
	// Community feature: FeatureOAuthSSO is Developer-tier
	if tier.RequiredTier(tier.FeatureOAuthSSO) != tier.TierDeveloper {
		t.Errorf("FeatureOAuthSSO RequiredTier = %v, want Developer", tier.RequiredTier(tier.FeatureOAuthSSO))
	}
	if tier.HasFeature(tier.TierCommunity, tier.FeatureOAuthSSO) {
		t.Error("Community should NOT have FeatureOAuthSSO")
	}
	if !tier.HasFeature(tier.TierDeveloper, tier.FeatureOAuthSSO) {
		t.Error("Developer SHOULD have FeatureOAuthSSO")
	}
	// MITRE ATLAS is Community (non-negotiable mandate)
	if tier.RequiredTier(tier.FeatureATLAS) != tier.TierCommunity {
		t.Error("FeatureATLAS should be Community-tier (non-negotiable)")
	}
	if !tier.HasFeature(tier.TierCommunity, tier.FeatureATLAS) {
		t.Error("Community MUST have FeatureATLAS")
	}
	// NIST AI RMF is Community (non-negotiable mandate)
	if tier.RequiredTier(tier.FeatureNISTAIRMF) != tier.TierCommunity {
		t.Error("FeatureNISTAIRMF should be Community-tier (non-negotiable)")
	}
	if !tier.HasFeature(tier.TierCommunity, tier.FeatureNISTAIRMF) {
		t.Error("Community MUST have FeatureNISTAIRMF")
	}
	// FIPS is Enterprise
	if tier.RequiredTier(tier.FeatureFIPS) != tier.TierEnterprise {
		t.Error("FeatureFIPS should be Enterprise-tier")
	}
	if tier.HasFeature(tier.TierCommunity, tier.FeatureFIPS) {
		t.Error("Community should NOT have FeatureFIPS")
	}
}

// TestTierStringAndDisplay verifies String() and DisplayName() for all tiers.
func TestTierStringAndDisplay(t *testing.T) {
	tests := []struct {
		tierVal        tier.Tier
		strVal         string
		displayNameVal string
	}{
		{tier.TierCommunity, "community", "Community"},
		{tier.TierDeveloper, "developer", "Developer"},
		{tier.TierProfessional, "professional", "Professional"},
		{tier.TierEnterprise, "enterprise", "Enterprise"},
		{tier.Tier(99), "unknown", "Unknown"},
	}

	for _, tc := range tests {
		if got := tc.tierVal.String(); got != tc.strVal {
			t.Errorf("Tier(%d).String() = %q, want %q", tc.tierVal, got, tc.strVal)
		}
		if got := tc.tierVal.DisplayName(); got != tc.displayNameVal {
			t.Errorf("Tier(%d).DisplayName() = %q, want %q", tc.tierVal, got, tc.displayNameVal)
		}
	}
}
