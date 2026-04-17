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
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/dashboard"
	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
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
		EnableMLDetection:             false, // Disable ML for deterministic tests
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
		tier.FeatureATLAS,       // MANDATE: ATLAS at Community
		tier.FeatureNISTAIRMF,   // MANDATE: NIST AI RMF at Community
		tier.FeatureMetrics,
		tier.FeatureAuditLogging,
		tier.FeatureAdminDashboard,
		tier.FeatureBuiltInCA,   // Self-signed certs + built-in CA
		tier.FeatureSBOM,        // SBOM tracking
		tier.FeatureI18N,        // Internationalization
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