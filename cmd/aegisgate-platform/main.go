// SPDX-License-Identifier: Apache-2.0
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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"runtime"

	"gopkg.in/yaml.v3"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/certinit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/metrics"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/persistence"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/platformconfig"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/security"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sso"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
)

var (
	version       = "1.3.7"
	commit        = "unknown"
	buildDate     = "unknown"
	startTime     = time.Now()
	configFile    = flag.String("config", "aegisgate-platform.yaml", "Configuration file path")
	proxyPort     = flag.Int("proxy-port", 8080, "AegisGate proxy port")
	mcpPort       = flag.Int("mcp-port", 8081, "AegisGuard MCP port")
	dashPort      = flag.Int("dashboard-port", 8443, "Admin dashboard port")
	targetURL     = flag.String("target", "https://api.openai.com", "Upstream LLM provider URL")
	licenseKey    = flag.String("license", "", "License key (overrides AEGISGATE_LICENSE_KEY env var)")
	licensePubKey = flag.String("license-public-key", "", "Path to alternative public key PEM (dev/test only; production uses embedded key)")
	tierName      = flag.String("tier", "community", "Display tier (read-only; actual tier derived from license)")
	showVersion   = flag.Bool("version", false, "Show version information")
	embeddedMCP   = flag.Bool("embedded-mcp", false, "Start embedded AegisGuard MCP server (standalone mode)")
)

func main() {
	flag.Parse()

	// fileExists helper function for configuration files
	fileExists := func(filename string) bool {
		_, err := os.Stat(filename)
		return !os.IsNotExist(err)
	}

	if *showVersion {
		fmt.Printf("AegisGate Security Platform %s (commit: %s, built: %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	log.Printf("AegisGate Security Platform v%s (commit: %s) starting...", version, commit)

	// Set build info for Prometheus metrics
	metrics.SetBuildInfo(version, runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH, commit)

	// ============================================================
	// License validation — the ONLY source of truth for tier
	// ============================================================
	// The --tier flag is read-only display; actual tier enforcement
	// comes from the license key. Without a valid license, the
	// platform runs as Community tier.

	// Initialize license manager (use custom public key if provided for dev/test)
	var licenseMgr *license.Manager
	if *licensePubKey != "" {
		keyData, err := os.ReadFile(*licensePubKey)
		if err != nil {
			log.Fatalf("Failed to read license public key %s: %v", *licensePubKey, err)
		}
		licenseMgr, err = license.NewManagerWithKey(string(keyData))
		if err != nil {
			log.Fatalf("Failed to initialize license manager with custom key: %v", err)
		}
		log.Printf("[LICENSE] Using custom public key from %s (dev/test mode)", *licensePubKey)
	} else {
		var lerr error
		licenseMgr, lerr = license.NewManager()
		if lerr != nil {
			log.Fatalf("Failed to initialize license manager: %v", lerr)
		}
	}

	// Resolve license key: flag > env var > empty (Community)
	resolvedLicenseKey := *licenseKey
	if resolvedLicenseKey == "" {
		resolvedLicenseKey = os.Getenv("AEGISGATE_LICENSE_KEY")
	}

	// Validate the license key
	licenseResult := licenseMgr.Validate(resolvedLicenseKey)
	platformTier := licenseResult.Tier // License-derived tier

	// Log license status
	if licenseResult.Valid {
		if licenseResult.GracePeriod {
			log.Printf("⚠️  License in grace period: %s (expires %s)", licenseResult.Message, licenseResult.Payload.ExpiresAt.Format(time.RFC3339))
		}
		log.Printf("License: VALID — %s tier (customer: %s)", platformTier.DisplayName(), licenseResult.Payload.Customer)
	} else if resolvedLicenseKey != "" {
		log.Printf("License: INVALID — %s. Falling back to Community tier", licenseResult.Message)
	} else {
		log.Printf("License: No license key provided — running as Community tier")
	}

	// Store the resolved license key for context-aware validation
	licenseMgr.SetLicenseKey(resolvedLicenseKey)

	// Warn if --tier flag conflicts with license-derived tier
	if *tierName != "" && *tierName != "community" && *tierName != platformTier.String() {
		log.Printf("⚠️  --tier flag (%q) ignored: tier is derived from license (%s). Use --license to set tier.", *tierName, platformTier.String())
	}
	log.Printf("Effective tier: %s (%s) [source: %s]", platformTier.DisplayName(), platformTier.String(),
		func() string {
			if resolvedLicenseKey != "" && licenseResult.Valid {
				return "license"
			}
			return "community-default"
		}())

	// Load unified platform configuration
	cfg, err := platformconfig.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ============================================================
	// Component 0: Persistence Layer (audit storage + retention)
	// ============================================================
	// Initializes file-backed audit storage with tier-based retention.
	// This MUST start before any component that produces audit events.

	persistenceCfg := cfg.Persistence

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
	// Component 0b: Certificate Initialization (first-run TLS setup)
	// ============================================================
	// Generates self-signed CA + server certificates on first startup.
	// Idempotent — skips if valid certs already exist in cert_dir.

	certCfg := certinit.DefaultConfig()
	certCfg.CertDir = cfg.TLS.CertDir
	certCfg.AutoGenerate = cfg.TLS.AutoGenerate

	certResult, err := certinit.EnsureCerts(certCfg)
	if err != nil {
		log.Fatalf("Certificate initialization failed: %v", err)
	}
	if certResult.Generated {
		log.Printf("Certificates: generated in %s (CA expires %s, server expires %s)",
			certCfg.CertDir,
			certResult.CAExpiry.Format("2006-01-02"),
			certResult.ServerExpiry.Format("2006-01-02"))
	} else if certResult.Existing {
		log.Printf("Certificates: reusing existing in %s", certCfg.CertDir)
	} else {
		log.Printf("Certificates: auto_generate disabled — using manual certs")
	}
	for _, w := range certResult.Warnings {
		log.Printf("Certificate warning: %s", w)
	}

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
		PromptInjectionSensitivity:     50, // Medium sensitivity (0-100): blocks severity >= 4 by default
		EnableContentAnalysis:          tier.HasFeature(platformTier, tier.FeatureTrafficPattern),
		EnableBehavioralAnalysis:       tier.HasFeature(platformTier, tier.FeatureMLBehavioral),
		OnRateLimited: func(client string) {
			metrics.RecordRateLimitHit(metrics.ServiceProxy, client)
		},
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
		metrics.RecordTierRequest(platformTier.String())
		proxyServer.ServeHTTP(w, r)
	})

	proxyHTTPServer := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", *proxyPort),
		Handler:      security.APIHeadersMiddleware(metrics.WrapHandler("proxy", proxyMux)),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start proxy server with proper synchronization
	proxyReady := make(chan error, 1)
	go func() {
		proxyListener, err := net.Listen("tcp", proxyHTTPServer.Addr)
		if err != nil {
			proxyReady <- fmt.Errorf("failed to bind proxy: %w", err)
			return
		}
		proxyReady <- nil
		log.Printf("AegisGate proxy listening on :%d -> %s", *proxyPort, *targetURL)
		if err := proxyHTTPServer.Serve(proxyListener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("AegisGate proxy server error: %v", err)
		}
	}()
	if err := <-proxyReady; err != nil {
		log.Fatalf("Proxy startup failed: %v", err)
	}

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
	var mcpGuardrails *mcpserver.GuardrailMiddleware
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

		// Initialize tier-aware MCP guardrails with server ID for registration logging
		mcpGuardrails = mcpserver.NewGuardrailMiddleware(mcpserver.DefaultGuardrailConfig(platformTier), "main-server")
		mcpserver.RegisterBuiltInTools(embeddedServer.Handler(), platformTier)

		if err := embeddedServer.Start(); err != nil {
			log.Fatalf("Failed to start embedded MCP server: %v", err)
		}
		defer embeddedServer.Stop()
		defer mcpGuardrails.Close()
		log.Printf("Embedded MCP server started on :%d (standalone mode)", *mcpPort)
		log.Printf("MCP Guardrails active: max_sessions=%d, max_tools/session=%d, timeout=%ds, sandbox_mem=%dMB",
			platformTier.MaxConcurrentMCP(), platformTier.MaxMCPToolsPerSession(),
			platformTier.MCPExecTimeoutSeconds(), platformTier.MaxMCPSandboxMemoryMB())

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
	// Initialize authentication middleware from environment
	authConfig := auth.ConfigFromEnv()

	// Initialize SSO Manager with configuration from YAML file
	var ssoManager *sso.Manager
	var ssoErr error

	// Try to load SSO configuration from YAML file
	ssoConfig := sso.DefaultSSOConfig()
	ssoConfigPath := "configs/sso.yaml"
	if fileExists(ssoConfigPath) {
		yamlData, err := os.ReadFile(ssoConfigPath)
		if err != nil {
			log.Printf("Warning: Failed to read SSO config file %s: %v", ssoConfigPath, err)
		} else {
			var configMap map[string]interface{}
			if err := yaml.Unmarshal(yamlData, &configMap); err == nil {
				// Parse sso section
				if ssoMap, ok := configMap["sso"].(map[string]interface{}); ok {
					if enabled, ok := ssoMap["enabled"].(bool); ok {
						ssoConfig.Enabled = enabled
					}
				}

				// Parse oidc section
				if oidcMap, ok := configMap["oidc"].(map[string]interface{}); ok {
					oidcConfig := &sso.OIDCConfig{}
					if clientID, ok := oidcMap["client_id"].(string); ok {
						oidcConfig.ClientID = clientID
					}
					if clientSecret, ok := oidcMap["client_secret"].(string); ok {
						oidcConfig.ClientSecret = clientSecret
					}
					if issuerURL, ok := oidcMap["issuer_url"].(string); ok {
						oidcConfig.IssuerURL = issuerURL
					}
					if authURL, ok := oidcMap["auth_url"].(string); ok {
						oidcConfig.AuthURL = authURL
					}
					if tokenURL, ok := oidcMap["token_url"].(string); ok {
						oidcConfig.TokenURL = tokenURL
					}
					if userInfoURL, ok := oidcMap["user_info_url"].(string); ok {
						oidcConfig.UserInfoURL = userInfoURL
					}
					if redirectURL, ok := oidcMap["redirect_url"].(string); ok {
						oidcConfig.RedirectURL = redirectURL
					}
					if providerType, ok := oidcMap["provider"].(string); ok {
						oidcConfig.ProviderType = providerType
					}
					ssoConfig.OIDC = oidcConfig
				}

				// Parse saml section
				if samlMap, ok := configMap["saml"].(map[string]interface{}); ok {
					samlConfig := &sso.SAMLConfig{}
					if idpMetadataURL, ok := samlMap["idp_metadata_url"].(string); ok {
						samlConfig.IDPMetadataURL = idpMetadataURL
					}
					if entityID, ok := samlMap["entity_id"].(string); ok {
						samlConfig.EntityID = entityID
					}
					if acsURL, ok := samlMap["acs_url"].(string); ok {
						samlConfig.ACSURL = acsURL
					}
					if nameIDFormat, ok := samlMap["name_id_format"].(string); ok {
						samlConfig.NameIDFormat = nameIDFormat
					}
					if certFile, ok := samlMap["cert_file"].(string); ok {
						samlConfig.CertFile = certFile
					}
					if keyFile, ok := samlMap["key_file"].(string); ok {
						samlConfig.KeyFile = keyFile
					}
					ssoConfig.SAML = samlConfig
				}

				// Parse session section
				if sessionMap, ok := configMap["session"].(map[string]interface{}); ok {
					if durationHours, ok := sessionMap["duration_hours"].(float64); ok {
						ssoConfig.SessionDuration = time.Duration(durationHours) * time.Hour
					}
					if secure, ok := sessionMap["secure"].(bool); ok {
						ssoConfig.CookieSecure = secure
					}
					if sameSite, ok := sessionMap["same_site"].(string); ok {
						ssoConfig.CookieSameSite = sameSite
					}
				}
			}
		}
	}

	// Initialize SSO Manager
	ssoManager, ssoErr = sso.NewManager(&sso.ManagerConfig{
		DefaultConfig: ssoConfig,
	})

	// Create middleware with appropriate auth settings
	var authMiddleware *auth.Middleware
	if ssoErr != nil || !ssoConfig.Enabled {
		log.Printf("Warning: SSO initialization failed or disabled: %v", ssoErr)
		log.Println("SSO: Using basic authentication only")
		authMiddleware = auth.NewMiddleware(authConfig)
	} else {
		authMiddleware = auth.NewMiddlewareWithSSO(authConfig, ssoManager)

		// Log enabled providers
		if ssoConfig.OIDC != nil {
			log.Printf("SSO: OIDC provider configured: %s", ssoConfig.OIDC.IssuerURL)
		}
		if ssoConfig.SAML != nil {
			log.Println("SSO: SAML provider configured")
		}
	}

	log.Printf("Auth middleware: require_auth=%v, sso_enabled=%v", authConfig.RequireAuth, ssoManager != nil)

	dashMux := http.NewServeMux()

	// Metrics endpoint (Prometheus)
	dashMux.Handle("/metrics", metrics.Handler())

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
		fmt.Fprintf(w, `{"status":"%s","version":"%s","tier":"%s","bridge":"%s","scanner":"%v","uptime":%.0f,"timestamp":"%s"}`,
			status, version, platformTier.String(), bridgeStatus, scannerHealthy, time.Since(startTime).Seconds(), time.Now().UTC().Format(time.RFC3339))
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

	dashMux.HandleFunc("/api/v1/scan", authMiddleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
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
	}))

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

	// License status endpoint — show current license and tier info
	dashMux.HandleFunc("/api/v1/license/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		currentResult := licenseMgr.Validate(licenseMgr.GetLicenseKey())
		featureCount := len(tier.AllFeatures(currentResult.Tier))

		resp := map[string]interface{}{
			"valid":        currentResult.Valid,
			"tier":         currentResult.Tier.String(),
			"display_name": currentResult.Tier.DisplayName(),
			"features":     featureCount,
			"grace_period": currentResult.GracePeriod,
			"expired":      currentResult.Expired,
			"message":      currentResult.Message,
			"validated_at": currentResult.ValidatedAt.Format(time.RFC3339),
		}
		if currentResult.Valid {
			resp["license_id"] = currentResult.Payload.LicenseID
			resp["customer"] = currentResult.Payload.Customer
			resp["expires_at"] = currentResult.Payload.ExpiresAt.Format(time.RFC3339)
			resp["max_servers"] = currentResult.Payload.MaxServers
			resp["max_users"] = currentResult.Payload.MaxUsers
		}
		data, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"marshal failed"}`)
			return
		}
		w.Write(data)
	})

	// Audit log endpoint — query persisted audit entries
	dashMux.HandleFunc("/api/v1/audit", authMiddleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !persistenceMgr.IsEnabled() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "persistence disabled", "entries": "[]"})
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
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		data, err := json.Marshal(entries)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "marshal failed"})
			return
		}
		w.Write(data)
	}))

	// Compliance export endpoint — secure audit*
	dashMux.HandleFunc("/api/v1/compliance", authMiddleware.AdminOnly(func(w http.ResponseWriter, r *http.Request) {
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
		// Validate format against allowlist to prevent taint injection
		allowedFormats := map[string]bool{"json": true, "csv": true, "yaml": true, "xml": true}
		if !allowedFormats[format] {
			format = "json"
		}

		data, err := persistenceMgr.ExportForCompliance(r.Context(), format)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Write(data) // #nosec G705 -- format validated against allowlist above
	}))

	// Persistence stats endpoint
	dashMux.HandleFunc("/api/v1/persistence", authMiddleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := persistenceMgr.Stats()
		data, err := json.Marshal(stats)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}))

	// Certificate status endpoint — validate & inspect TLS certificates
	dashMux.HandleFunc("/api/v1/certs", authMiddleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		validation, err := certinit.ValidateCerts(certCfg)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"%s"}`, err.Error())
			return
		}
		data, err := json.Marshal(validation)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}))

	// MCP Guardrails stats endpoint
	dashMux.HandleFunc("/api/v1/guardrails", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if mcpGuardrails == nil {
			w.Write([]byte(`{"error": "guardrails not active (run with --embedded-mcp)"}`))
			return
		}
		stats := mcpGuardrails.Stats()
		data, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"data":    stats,
		})
		w.Write(data)
	})

	// Aggregated dashboard stats endpoint
	dashMux.HandleFunc("/api/v1/stats", authMiddleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"tier":           platformTier.String(),
				"version":        version,
				"uptime_seconds": time.Since(startTime).Seconds(),
				"persistence":    persistenceMgr.Stats(),
			},
		}
		if mcpGuardrails != nil {
			stats["data"].(map[string]interface{})["guardrails"] = mcpGuardrails.Stats()
		}
		certInfo, _ := certinit.ValidateCerts(certCfg)
		if certInfo != nil {
			stats["data"].(map[string]interface{})["certificates"] = certInfo
		}
		data, _ := json.Marshal(stats)
		w.Write(data)
	}))

	// Policy info endpoint — returns policy settings
	dashMux.HandleFunc("/api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		policies := map[string]interface{}{
			"success": true,
			"data": []map[string]interface{}{
				{
					"name":      "rate_limiting",
					"framework": "ATLAS",
					"severity":  "medium",
					"enabled":   true,
					"details":   fmt.Sprintf("Proxy: %d RPM, MCP: %d RPM", platformTier.RateLimitProxy(), platformTier.RateLimitMCP()),
				},
				{
					"name":      "mcp_guardrails",
					"framework": "NIST-AI-RMF",
					"severity":  "high",
					"enabled":   mcpGuardrails != nil,
					"details":   fmt.Sprintf("Max %d concurrent MCP sessions", platformTier.MaxConcurrentMCP()),
				},
				{
					"name":      "audit_logging",
					"framework": "SOC2",
					"severity":  "medium",
					"enabled":   true,
					"details":   fmt.Sprintf("Retention: %d days", platformTier.LogRetentionDays()),
				},
				{
					"name":      "certificate_automation",
					"framework": "PCI-DSS",
					"severity":  "high",
					"enabled":   certCfg.AutoGenerate,
					"details":   "Self-signed CA with auto-generation",
				},
				{
					"name":      "persistence",
					"framework": "HIPAA",
					"severity":  "low",
					"enabled":   true,
					"details":   fmt.Sprintf("File-backed audit storage, %d day retention", platformTier.LogRetentionDays()),
				},
			},
		}
		data, _ := json.Marshal(policies)
		w.Write(data)
	})

	// Static UI file server
	dashMux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.Dir("ui/frontend"))))

	// SSO Authentication Endpoints (Developer+ tiers)
	dashMux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		// Check if SSO is configured and enabled
		if authMiddleware.SSOManager() == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			fmt.Fprintf(w, `{"error":"SSO not configured"}`)
			return
		}

		// Check SSO session for existing authentication
		session, err := authMiddleware.SSOManager().GetSession("default")
		if err == nil && session != nil && !session.IsExpired() && session.Active {
			http.Redirect(w, r, "/ui/", http.StatusFound)
			return
		}

		// Initiate SSO login flow - use first available provider
		providers := authMiddleware.SSOManager().ListProviders()
		if len(providers) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			fmt.Fprintf(w, `{"error":"no SSO providers configured"}`)
			return
		}

		providerName := providers[0] // Default to first provider
		loginURL, _, err := authMiddleware.SSOManager().InitiateLogin(providerName)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"failed to initiate SSO login: %v"}`, err)
			return
		}

		http.Redirect(w, r, loginURL, http.StatusFound)
	})

	dashMux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		// Handle SSO callback (OAuth2/OIDC/SAML)
		if authMiddleware.SSOManager() == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			fmt.Fprintf(w, `{"error":"SSO not configured"}`)
			return
		}

		// Get query params for callback
		params := make(map[string]string)
		for key := range r.URL.Query() {
			params[key] = r.URL.Query().Get(key)
		}

		// Process callback and complete authentication
		result, err := authMiddleware.SSOManager().HandleCallback("default", params)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"SSO callback failed: %v"}`, err)
			return
		}

		// If callback returned redirect URL, use it
		if result != nil && result.RedirectURL != "" {
			http.Redirect(w, r, result.RedirectURL, http.StatusFound)
			return
		}

		// Otherwise redirect to dashboard on success
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	dashMux.HandleFunc("/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		// Handle SSO logout
		if authMiddleware.SSOManager() == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			fmt.Fprintf(w, `{"error":"SSO not configured"}`)
			return
		}

		// Get session ID from cookie or header
		sessionID := r.Header.Get("Authorization")
		if sessionID == "" {
			// Try to get from cookie
			if cookie, err := r.Cookie("session"); err == nil {
				sessionID = cookie.Value
			}
		}

		// Perform logout and redirect
		logoutURL, err := authMiddleware.SSOManager().Logout(sessionID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"SSO logout failed: %v"}`, err)
			return
		}

		if !isSafeRedirectURL(logoutURL, r) {
			http.Redirect(w, r, "/ui/", http.StatusFound) // #nosec G710 -- safe fallback redirect
		} else {
			http.Redirect(w, r, logoutURL, http.StatusFound) // #nosec G710 -- validated by isSafeRedirectURL
		}
	})

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
		Handler:      security.DashboardHeadersMiddleware(metrics.WrapHandler("dashboard", dashMux)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start dashboard server with proper synchronization
	dashReady := make(chan error, 1)
	go func() {
		dashListener, err := net.Listen("tcp", dashHTTPServer.Addr)
		if err != nil {
			dashReady <- fmt.Errorf("failed to bind dashboard: %w", err)
			return
		}
		dashReady <- nil
		log.Printf("Dashboard/API server listening on :%d", *dashPort)
		if err := dashHTTPServer.Serve(dashListener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Dashboard server error: %v", err)
		}
	}()
	if err := <-dashReady; err != nil {
		log.Fatalf("Dashboard startup failed: %v", err)
	}

	// ============================================================
	// Ready
	// ============================================================
	bridgeStatus := "disabled"
	if platformBridge != nil && platformBridge.IsEnabled() {
		bridgeStatus = "enabled"
	}

	// Verify all services are actually listening
	if err := verifyServicesReady(); err != nil {
		log.Printf("Warning: Service verification: %v", err)
	}

	log.Printf("AegisGate Security Platform ready (v%s)", version)
	log.Printf("[STARTUP-COMPLETE] All services initialized")
	log.Printf("Components:")
	log.Printf("  Proxy:    http://0.0.0.0:%d -> %s (tier: %s)", *proxyPort, *targetURL, platformTier.String())
	log.Printf("  License:  %s", func() string {
		if resolvedLicenseKey != "" && licenseResult.Valid {
			return "validated (" + platformTier.String() + ")"
		} else if resolvedLicenseKey != "" {
			return "invalid (falling back to community)"
		}
		return "none (community tier)"
	}())
	if *embeddedMCP {
		log.Printf("  MCP:      :%d (embedded server, standalone mode)", *mcpPort)
	} else {
		log.Printf("  MCP:      localhost:%d (AegisGuard scanner client)", *mcpPort)
	}
	log.Printf("  Bridge:   AegisGuard -> AegisGate (%s)", bridgeStatus)
	log.Printf("  Persistence: %s (retention: %d days)", persistenceCfg.AuditDir, platformTier.LogRetentionDays())
	log.Printf("  Certs:    %s (auto_generate: %v)", certCfg.CertDir, certCfg.AutoGenerate)
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
		if err := platformBridge.Close(); err != nil {
			log.Printf("Bridge close error: %v", err)
		}
	}

	log.Println("Platform stopped gracefully")
}

// isSafeRedirectURL validates that a redirect URL is same-origin or a safe path.
// Prevents open redirect vulnerabilities by ensuring redirect targets are trusted.
func isSafeRedirectURL(rawURL string, r *http.Request) bool {
	// Relative paths starting with "/" are safe (same-origin)
	if strings.HasPrefix(rawURL, "/") && !strings.HasPrefix(rawURL, "//") {
		return true
	}

	// Parse the URL to inspect its host
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// If the URL has no host, it's a relative URL — allow it
	if u.Host == "" {
		return true
	}

	// Check same-origin: the redirect host must match the request host
	if u.Host == r.Host {
		return true
	}

	// Reject external URLs to prevent open redirects
	return false
}

// verifyServicesReady checks that all required services are listening
func verifyServicesReady() error {
	ports := []int{*proxyPort, *dashPort}
	if *embeddedMCP {
		ports = append(ports, *mcpPort)
	}

	for _, port := range ports {
		addr := fmt.Sprintf("localhost:%d", port)
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return fmt.Errorf("port %d not ready: %w", port, err)
		}
		conn.Close()
		log.Printf("[STARTUP-CONFIRM] Port %d ready", port)
	}
	return nil
}
