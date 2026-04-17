// SPDX-License-Identifier: MIT
// =========================================================================
// AegisGate Security Platform - Main Entry Point
// =========================================================================
//
// Unified entry point that runs ALL platform components in a single process:
//   1. AegisGate HTTP proxy  (secures AI API traffic to LLM providers)
//   2. AegisGuard MCP scanner (secures AI agent operations via MCP protocol)
//   3. Bridge                 (routes AegisGuard LLM calls through AegisGate)
//   4. Admin Dashboard & API  (monitoring, configuration, health checks)
//
// Both services share a common tier system, audit trail, and bridge
// for defense-in-depth security coverage.
// =========================================================================

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/persistence"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

var (
	version     = "2.0.0-dev"
	configFile  = flag.String("config", "aegisgate-platform.yaml", "Configuration file path")
	proxyPort   = flag.Int("proxy-port", 8080, "AegisGate proxy port")
	mcpPort     = flag.Int("mcp-port", 8081, "AegisGuard MCP port")
	dashPort    = flag.Int("dashboard-port", 8443, "Admin dashboard port")
	targetURL   = flag.String("target", "https://api.openai.com", "Upstream LLM provider URL")
	tierName    = flag.String("tier", "community", "License tier (community|developer|professional|enterprise)")
	showVersion   = flag.Bool("version", false, "Show version information")
	embeddedMCP    = flag.Bool("embedded-mcp", false, "Start embedded AegisGuard MCP server (standalone mode)")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("AegisGate Security Platform %s\n", version)
		os.Exit(0)
	}

	log.Printf("AegisGate Security Platform v%s starting...", version)

	// Parse platform tier (our unified tier system)
	platformTier, err := tier.ParseTier(*tierName)
	if err != nil {
		log.Fatalf("Invalid tier %q: %v", *tierName, err)
	}
	log.Printf("Tier: %s (%s)", platformTier.DisplayName(), platformTier.String())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ============================================================
	// Component 0: Persistence Layer (audit storage + retention)
	// ============================================================
	// Initializes file-backed audit storage with tier-based retention.
	// This MUST start before any component that produces audit events.

	persistenceCfg := persistence.DefaultConfig()
	if *configFile != "" {
		// If a config file was provided, try to load persistence settings from it
		// (platformconfig handles file loading, but for --embedded-mcp standalone
		// we allow persistence to work without a config file)
		if _, err := os.Stat(*configFile); err == nil {
			// Config file exists — platformconfig.Parse would load it,
			// but we do a lightweight load here for persistence only
			log.Printf("Loading persistence config from %s", *configFile)
		}
	}

	// Override data dir from environment if set (e.g., Docker: AEGISGATE_DATA_DIR=/data)
	if dataDir := os.Getenv("AEGISGATE_DATA_DIR"); dataDir != "" {
		persistenceCfg.DataDir = dataDir
		persistenceCfg.AuditDir = dataDir + "/audit"
	}

	// Ensure the data directory structure exists
	if err := persistence.EnsureDataDirs(persistenceCfg.DataDir); err != nil {
		log.Fatalf("Failed to create data directories: %v", err)
	}

	persistenceMgr, err := persistence.New(platformTier, persistenceCfg)
	if err != nil {
		log.Fatalf("Failed to initialize persistence: %v", err)
	}
	if err := persistenceMgr.Start(); err != nil {
		log.Fatalf("Failed to start persistence: %v", err)
	}
	defer persistenceMgr.Close()

	log.Printf("Persistence: audit_dir=%s, retention=%d days",
		persistenceCfg.AuditDir, platformTier.LogRetentionDays())

	// ============================================================
	// Component 1: AegisGate HTTP Proxy
	// ============================================================
	// This is the core reverse proxy that secures AI API traffic
	// to LLM providers (OpenAI, Anthropic, etc.)

	log.Printf("Platform tier limits - Proxy RPM: %d, MCP RPM: %d, Max users: %d, Log retention: %d days",
		platformTier.RateLimitProxy(), platformTier.RateLimitMCP(),
		platformTier.MaxUsers(), platformTier.LogRetentionDays())

	proxyOpts := &proxy.Options{
		BindAddress:                    fmt.Sprintf("0.0.0.0:%d", *proxyPort),
		Upstream:                       *targetURL,
		MaxBodySize:                    10 * 1024 * 1024,
		Timeout:                        30 * time.Second,
		RateLimit:                      platformTier.RateLimitProxy(),
		EnableMLDetection:              tier.HasFeature(platformTier, tier.FeatureBasicAnomaly),
		MLSensitivity:                  "medium",
		EnablePromptInjectionDetection: tier.HasFeature(platformTier, tier.FeaturePromptInjection),
		EnableContentAnalysis:          tier.HasFeature(platformTier, tier.FeatureTrafficPattern),
		EnableBehavioralAnalysis:       tier.HasFeature(platformTier, tier.FeatureMLBehavioral),
	}

	proxyServer := proxy.New(proxyOpts)

	// Create mux for AegisGate proxy + management endpoints
	proxyMux := http.NewServeMux()

	// Management endpoints on the proxy port
	proxyMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		health := proxyServer.GetHealth()
		w.Header().Set("Content-Type", "application/json")
		if enabled, ok := health["enabled"].(bool); !ok || !enabled {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","tier":"%s","version":"%s"}`, platformTier.String(), version)
	})

	proxyMux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"%s","component":"aegisgate-proxy"}`, version)
	})

	proxyMux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := proxyServer.GetStats()
		w.Header().Set("Content-Type", "application/json")
		reqCount, _ := stats["request_count"].(int64)
		fmt.Fprintf(w, `{"request_count":%d,"component":"aegisgate-proxy"}`, reqCount)
	})

	// Forward all other requests to the proxy handler
	proxyMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxyServer.ServeHTTP(w, r)
	})

	proxyHTTPServer := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", *proxyPort),
		Handler:      proxyMux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("AegisGate proxy listening on :%d -> %s", *proxyPort, *targetURL)
		if err := proxyHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("AegisGate proxy server error: %v", err)
		}
	}()

	// ============================================================
	// Component 2: Bridge (AegisGuard -> AegisGate routing)
	// ============================================================
	// The bridge routes LLM API calls from AegisGuard through
	// AegisGate for defense-in-depth security scanning.

	platformBridge, err := bridge.NewPlatformBridge(fmt.Sprintf("http://localhost:%d", *proxyPort))
	if err != nil {
		log.Printf("Warning: Failed to create platform bridge: %v", err)
		log.Println("Continuing without bridge - LLM calls won't be routed through AegisGate")
	} else {
		defer platformBridge.Close()
		log.Println("Bridge initialized: AegisGuard LLM calls routed through AegisGate")
	}

	// ============================================================
	// Component 3: AegisGuard MCP Server / Scanner
	// ============================================================
	// In standalone mode (--embedded-mcp), start the MCP server in-process.
	// Otherwise, connect to an external AegisGuard instance as a scanner client.

	var embeddedServer *mcpserver.EmbeddedServer
	var mcpScanner *scanner.AegisGuardMCPScanner

	if *embeddedMCP {
		// STANDALONE MODE: Start the MCP server embedded in this process
		mcpCfg := &mcpserver.Config{
			Address:      fmt.Sprintf(":%d", *mcpPort),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  5 * time.Minute,
		}
		embeddedServer = mcpserver.NewEmbeddedServer(mcpCfg)
		if err := embeddedServer.Start(); err != nil {
			log.Fatalf("Failed to start embedded MCP server: %v", err)
		}
		defer embeddedServer.Stop()
		log.Printf("Embedded MCP server started on :%d (standalone mode)", *mcpPort)

		// In standalone mode, the scanner connects to our own MCP server
		scannerCfg := &scanner.AegisGuardMCPConfig{
			Address:      fmt.Sprintf("localhost:%d", *mcpPort),
			Timeout:      30 * time.Second,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			Debug:        true,
		}
		mcpScanner = scanner.NewAegisGuardMCPScanner(scannerCfg)
	} else {
		// CONNECTED MODE: Connect to external AegisGuard as a scanner client
		scannerCfg := &scanner.AegisGuardMCPConfig{
			Address:      fmt.Sprintf("localhost:%d", *mcpPort),
			Timeout:      30 * time.Second,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			Debug:        true,
		}
		mcpScanner = scanner.NewAegisGuardMCPScanner(scannerCfg)
	}

	// Try to initialize scanner (non-fatal if AegisGuard not running yet)
	if err := mcpScanner.Initialize(); err != nil {
		log.Printf("Warning: AegisGuard MCP scanner not yet available: %v", err)
		log.Println("Scanner will reconnect when AegisGuard becomes available")
	} else {
		log.Println("AegisGuard MCP scanner connected")
	}
	defer mcpScanner.Close()

	// ============================================================
	// Component 4: Admin Dashboard & API Server
	// ============================================================
	dashMux := http.NewServeMux()

	// Dashboard health endpoint
	dashMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scannerHealthy := mcpScanner.Health() == nil
		bridgeStatus := "disabled"
		if platformBridge != nil && platformBridge.IsEnabled() {
			bridgeStatus = "enabled"
		}

		status := "healthy"
		code := http.StatusOK
		if !scannerHealthy {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}

		w.WriteHeader(code)
		fmt.Fprintf(w, `{"status":"%s","version":"%s","tier":"%s","bridge":"%s","scanner":"%v","timestamp":"%s"}`,
			status, version, platformTier.String(), bridgeStatus, scannerHealthy, time.Now().UTC().Format(time.RFC3339))
	})

	dashMux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scannerHealthy := mcpScanner.Health() == nil
		if scannerHealthy {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"ready":true,"scanner":"connected"}`)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"ready":false,"scanner":"disconnected"}`)
		}
	})

	dashMux.HandleFunc("/api/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		scanReq := &scanner.ScanRequest{
			Kind: "chat",
		}
		resp, err := mcpScanner.Scan(r.Context(), scanReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"scan_id":"%s","compliant":%v}`, resp.ScanID, resp.IsCompliant)
	})

	// Bridge status endpoint
	dashMux.HandleFunc("/api/v1/bridge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if platformBridge != nil {
			stats := platformBridge.GetStats()
			fmt.Fprintf(w, `{"enabled":%v,"total_requests":%d,"allowed":%d,"blocked":%d}`,
				platformBridge.IsEnabled(), stats.TotalRequests, stats.AllowedRequests, stats.BlockedRequests)
		} else {
			fmt.Fprintf(w, `{"enabled":false}`)
		}
	})

	// Tier information endpoint
	dashMux.HandleFunc("/api/v1/tier", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		featureCount := len(tier.AllFeatures(platformTier))
		fmt.Fprintf(w, `{"tier":"%s","display_name":"%s","rate_limit_proxy":%d,"rate_limit_mcp":%d,"max_users":%d,"max_agents":%d,"features":%d,"log_retention_days":%d,"mcp_concurrent":%d,"mcp_tools_per_session":%d,"mcp_exec_timeout_s":%d,"mcp_sandbox_mem_mb":%d,"support":"%s"}`,
			platformTier.String(), platformTier.DisplayName(),
			platformTier.RateLimitProxy(), platformTier.RateLimitMCP(),
			platformTier.MaxUsers(), platformTier.MaxAgents(), featureCount,
			platformTier.LogRetentionDays(),
			platformTier.MaxConcurrentMCP(), platformTier.MaxMCPToolsPerSession(),
			platformTier.MCPExecTimeoutSeconds(), platformTier.MaxMCPSandboxMemoryMB(),
			platformTier.SupportLevel())
	})

	// Audit log endpoint — query persisted audit entries
	dashMux.HandleFunc("/api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !persistenceMgr.IsEnabled() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"error":"persistence disabled","entries":[]}`)
			return
		}

		auditLog := persistenceMgr.AuditLog()
		if auditLog == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"error":"audit log unavailable","entries":[]}`)
			return
		}

		filter := opsec.AuditFilter{Limit: 100}
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
				filter.Limit = n
			}
		}
		if v := r.URL.Query().Get("event_type"); v != "" {
			filter.EventTypes = []string{v}
		}

		entries, err := auditLog.Query(r.Context(), filter)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}

		data, err := json.Marshal(entries)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"marshal failed"}`)
			return
		}
		w.Write(data)
	})

	// Compliance export endpoint — tamper-evident audit export
	dashMux.HandleFunc("/api/v1/compliance", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !persistenceMgr.IsEnabled() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"error":"persistence disabled"}`)
			return
		}

		format := r.URL.Query().Get("format")
		if format == "" {
			format = "json"
		}

		data, err := persistenceMgr.ExportForCompliance(r.Context(), format)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}
		w.Write(data)
	})

	// Persistence stats endpoint
	dashMux.HandleFunc("/api/v1/persistence", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := persistenceMgr.Stats()
		data, err := json.Marshal(stats)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	// Static UI file server
	dashMux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.Dir("ui/frontend"))))

	// Serve index.html at dashboard root
	dashMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			http.ServeFile(w, r, "ui/frontend/index.html")
			return
		}
		http.NotFound(w, r)
	})

	dashMux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"%s","component":"aegisgate-platform"}`, version)
	})

	dashHTTPServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *dashPort),
		Handler:      dashMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Dashboard/API server listening on :%d", *dashPort)
		if err := dashHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Dashboard server error: %v", err)
		}
	}()

	// ============================================================
	// Ready
	// ============================================================
	bridgeStatus := "disabled"
	if platformBridge != nil && platformBridge.IsEnabled() {
		bridgeStatus = "enabled"
	}

	log.Printf("AegisGate Security Platform ready (v%s)", version)
	log.Printf("Components:")
	log.Printf("  Proxy:    http://0.0.0.0:%d -> %s (tier: %s)", *proxyPort, *targetURL, platformTier.String())
	if *embeddedMCP {
		log.Printf("  MCP:      :%d (embedded server, standalone mode)", *mcpPort)
	} else {
		log.Printf("  MCP:      localhost:%d (AegisGuard scanner client)", *mcpPort)
	}
	log.Printf("  Bridge:   AegisGuard -> AegisGate (%s)", bridgeStatus)
	log.Printf("  Persistence: %s (retention: %d days)", persistenceCfg.AuditDir, platformTier.LogRetentionDays())
	log.Printf("  Dashboard: http://localhost:%d/health", *dashPort)
	log.Printf("  API:      http://localhost:%d/api/v1/scan", *dashPort)

	// Wait for components to be ready (brief startup grace period)
	_ = ctx

	// ============================================================
	// Graceful shutdown
	// ============================================================
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down AegisGate Security Platform...")

	cancel() // Signal all components to stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Close persistence (flushes audit log, runs final prune, closes storage)
	if err := persistenceMgr.Close(); err != nil {
		log.Printf("Persistence shutdown error: %v", err)
	}

	// Stop the AegisGate proxy
	if err := proxyServer.Stop(shutdownCtx); err != nil {
		log.Printf("Proxy shutdown error: %v", err)
	}

	// Stop the proxy HTTP server
	if err := proxyHTTPServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Proxy HTTP server shutdown error: %v", err)
	}

	// Stop the dashboard HTTP server
	if err := dashHTTPServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Dashboard HTTP server shutdown error: %v", err)
	}

	// Close the bridge
	if platformBridge != nil {
		platformBridge.Close()
	}

	log.Println("Platform stopped gracefully")
}