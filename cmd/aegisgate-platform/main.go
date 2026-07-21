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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"runtime"

	"gopkg.in/yaml.v3"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/a2a"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/acp"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/audit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/bridge"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/certinit"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lensbackend"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/metrics"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/persistence"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/platformconfig"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/security"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sla"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sso"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust"
	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
	"github.com/aegisgatesecurity/aegisgate/pkg/siem"
)

var (
	version    = "3.4.0-beta.1"
	commit     = "unknown"
	buildDate  = "unknown"
	startTime  = time.Now()
	configFile = flag.String("config", "aegisgate-platform.yaml", "Configuration file path")
	proxyPort  = flag.Int("proxy-port", 8080, "AegisGate proxy port")

	// writeJSON writes a JSON response and logs any write errors.
	// This consolidates error handling for http.ResponseWriter writes
	// and satisfies gosec G104 (Errors unhandled).
	writeJSON = func(w http.ResponseWriter, v interface{}) {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			log.Printf("http response write error: %v", err)
		}
	}

	// writeBytes writes raw bytes to the response and logs any write errors.
	// Consolidates error handling for w.Write calls (gosec G104).
	writeBytes = func(w http.ResponseWriter, data []byte) {
		if _, err := w.Write(data); err != nil {
			log.Printf("http response write error: %v", err)
		}
	}
	mcpPort       = flag.Int("mcp-port", 8081, "AegisGuard MCP port")
	dashPort      = flag.Int("dashboard-port", 8443, "Admin dashboard port")
	targetURL     = flag.String("target", "https://api.openai.com", "Upstream LLM provider URL")
	licenseKey    = flag.String("license", "", "License key (overrides AEGISGATE_LICENSE_KEY env var)")
	licensePubKey = flag.String("license-public-key", "", "Path to alternative public key PEM (dev/test only; production uses embedded key)")
	tierName      = flag.String("tier", "community", "Display tier (read-only; actual tier derived from license)")
	showVersion   = flag.Bool("version", false, "Show version information")
	embeddedMCP   = flag.Bool("embedded-mcp", false, "Start embedded AegisGuard MCP server (standalone mode)")
	// Mode of operation: "production" (default), "demo" (sandboxed public demo),
	// "staging" (pre-production testing). Demo mode disables license enforcement,
	// forces the target to a mock upstream, and applies read-only safety
	// restrictions to the admin dashboard. See cmd/aegisgate-platform/demo_mode.go
	// for the full implementation of demo mode behavior.
	mode = flag.String("mode", "production", "Operation mode: production, demo, or staging")

	// IOC (Federated IOC Library v3.5.0+ Track 6 Task 3):
	// opt-in sharing of Indicators of Compromise across instances.
	// --ioc-share enables serving the /api/v1/ioc/manifest endpoint
	// (any tier can share, default off).
	// --ioc-receive enables fetching peer bundles (requires
	// Professional tier or above, default off).
	// Both are also settable via AEGISGATE_IOC_SHARE and
	// AEGISGATE_IOC_RECEIVE env vars; the flag wins.
	iocShare   = flag.Bool("ioc-share", false, "Opt in to serving IOC manifests to peers (AEGISGATE_IOC_SHARE)")
	iocReceive = flag.Bool("ioc-receive", false, "Opt in to fetching IOC manifests from peers; requires Professional+ tier (AEGISGATE_IOC_RECEIVE)")
	iocPeers   = flag.String("ioc-peers", "", "Comma-separated peer base URLs for IOC gossip (e.g. https://aegis-b.example.com:8443,https://aegis-c.example.com:8443). Env: AEGISGATE_IOC_PEERS")
	// iocStoreDir removed in D25 (D25 staticcheck cleanup) - was unused flag.
	// The IOC store path is configured via the IOC subsystem; no top-level
	// --ioc-store-dir flag is needed. Re-add if a future subscriber mode
	// needs explicit path control.
	iocGossipInterval = flag.Duration("ioc-gossip-interval", 5*time.Minute, "Interval between peer IOC fetches in RunReceiver. Env: AEGISGATE_IOC_GOSSIP_INTERVAL (Go duration: 30s, 5m, 1h)")
	iocBootstrapPeers = flag.String("ioc-bootstrap-peers", "", "Comma-separated seed URLs for IOC peer discovery (e.g. https://aegis-primary.example.com:8443). The Discoverer polls each seed and learns about new peers. Env: AEGISGATE_IOC_BOOTSTRAP_PEERS)")
	lensEnabled       = flag.Bool("lens-enabled", false, "Enable the Lens telemetry backend on the proxy port (AEGISGATE_LENS_ENABLED)")
	siemEnabled       = flag.Bool("siem-enabled", false, "Enable the SIEM dispatcher to forward audit events to external SIEM platforms (AEGISGATE_SIEM_ENABLED)")
	lensBearerToken   = flag.String("lens-bearer-token", "", "Bearer token for Lens telemetry endpoints (AEGISGATE_LENS_BEARER_TOKEN)")
	lensIOCStoreDir   = flag.String("lens-ioc-store-dir", "", "Directory for Lens IOC store persistence (default: <DataDir>/lens)")
)

// iocWiringPtr is the package-level pointer to the IOC wiring
// result, populated in main() after the persistence layer is up.
// It is consumed by the proxy mux mount (for the /api/v1/ioc/
// handler) and by the testlab dashboard. nil if the IOC library
// failed to initialize.
var iocWiringPtr *iocWiring

// iocAdminAPIPtr is the package-level pointer to the IOC admin
// API handler, populated in main() after the IOC wiring is up.
// nil if the IOC library failed to initialize. The admin API
// is mounted on the dashboard mux, not the proxy mux.
var iocAdminAPIPtr *iocAdminAPI

// subcommandHelp is the Usage footer that lists the 11 CLI subcommands.
// Without this, "aegisgate --help" only shows top-level flags and users
// have no way to discover the subcommands (audit Finding #9, P1).
const subcommandHelp = `

CLI Subcommands (run "aegisgate <subcommand> --help" for details):

  a2a intent <sign|verify>     Agent intent signing (v3.4.0+ TODO-303)
  aibom <generate|verify>      AI Bill of Materials (v3.4.0+ TODO-302)
  attestation <sign|verify>    Attestation envelope operations (frozen 2026-06-15)
  cve <publish|verify>         CVE-for-AI Entry Publisher (v3.4.0+ TODO-305)
  digest <generate|verify>     CISO Posture Digest (v3.4.0+ TODO-601)
  evaluator <run>              AR-EaaS evaluator (v3.4.0+ TODO-301)
  evidence <build|verify|list> Compliance evidence packages (v3.3.0+)
  posture <check|report>       Platform posture check (v3.3.0 Phase 6.5)
  prompt-cache <audit>         Prompt cache poisoning audit (v3.4.0+ TODO-304)
  report <generate>            Compliance reports (v3.4.0+ TODO-602)
  soc <timeline|list>          SOC incident timeline (v3.4.0+ TODO-502)

  Run "aegisgate <subcommand> help" for verb-level help.
`

// init() overrides Go's default flag.Usage to include the subcommand list.
// D17 (audit Finding #9, P1): without this, users can't discover the 11
// CLI subcommands from --help.
func init() {
	originalUsage := flag.Usage
	flag.Usage = func() {
		// Print the standard flag usage (top-level flags).
		originalUsage()
		// Append the subcommand list.
		fmt.Fprint(flag.CommandLine.Output(), subcommandHelp)
	}
}

func main() {
	flag.Parse()

	// ============================================================
	// Audit ring buffer + global event recorder (v3.3.0+ Track 6)
	// ============================================================
	//
	// The ring buffer is the substrate that compliance evidence
	// packages read from (via the EventSource interface). The recorder
	// is the global hook that the 6 event-emitting subsystems
	// (response, anomaly, mcpserver, a2a, acp, anp) call to record
	// events. Wiring happens here, BEFORE any subsystem can record,
	// to avoid losing the first few events.
	//
	// Capacity: 10K events is the platform default. This holds
	// roughly 1 hour of activity at 3 events/second sustained. If
	// the ring overflows, the oldest events are dropped (acceptable
	// for evidence purposes - we only need a representative sample).
	//
	// On shutdown, the recorder is disabled (SetDefault(nil)) so
	// no more events are added to the (possibly half-flushed) buffer.
	auditRing := logging.NewRingBuffer(logging.DefaultCapacity)
	logging.SetDefault(auditRing)
	defer logging.SetDefault(nil) // disable on shutdown

	// fileExists helper function for configuration files
	fileExists := func(filename string) bool {
		_, err := os.Stat(filename)
		return !os.IsNotExist(err)
	}

	if *showVersion {
		fmt.Printf("AegisGate Security Platform %s (commit: %s, built: %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	// ============================================================
	// Mode handling (production / demo / staging)
	// ============================================================
	// Demo mode is a public-facing sandbox for evaluation purposes.
	// It applies the following safety restrictions:
	//   1. License enforcement is disabled (uses a built-in dev license)
	//   2. Target URL defaults to httpbin.org (mock upstream, no real LLM)
	//   3. Admin dashboard is read-only (no real configuration changes)
	//   4. Rate limits are stricter (100 req/hour per visitor)
	//   5. Sample seed data is loaded at startup (threats, MCP tools, etc.)
	//   6. State is auto-reset every 24 hours (handled by external cron)
	// See cmd/aegisgate-platform/demo_mode.go for the full implementation.
	normalizedMode := strings.ToLower(strings.TrimSpace(*mode))
	switch normalizedMode {
	case "production", "":
		normalizedMode = "production" // default
	case "demo":
		log.Printf("[MODE] Running in DEMO mode (sandboxed, no real LLM calls)")
		// Apply demo mode defaults: force target to mock upstream
		*targetURL = "http://httpbin.org:80"
	case "staging":
		log.Printf("[MODE] Running in STAGING mode (pre-production testing)")
	default:
		log.Printf("[WARN] Unknown mode %q, defaulting to production. Valid modes: production, demo, staging", *mode)
		normalizedMode = "production"
	}

	log.Printf("AegisGate Security Platform v%s (commit: %s) starting in %s mode...", version, commit, normalizedMode)

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
	// Component 0b: PostgreSQL Storage Backend (D1 Phase 1A/1B/1C)
	// ============================================================
	// If AEGISGATE_DATABASE_URL is set and the tier supports
	// FeaturePostgreSQL (Professional/Enterprise), create a shared
	// PostgresStore that backs IOC, audit, RBAC, and license data.
	// If the tier doesn't support PostgreSQL or the URL is missing,
	// fall back to in-memory/file-backed storage (current behavior).

	var pgStore *ioc.PostgresStore
	var rbacMgr *rbac.Manager
	var rbacPgStore *rbac.PostgresRBACStore

	databaseURL := os.Getenv("AEGISGATE_DATABASE_URL")
	if databaseURL != "" && tier.HasFeature(platformTier, tier.FeaturePostgreSQL) {
		pgCfg := ioc.DefaultDatabaseConfig()
		pgCfg.URL = databaseURL

		var pgErr error
		pgStore, pgErr = ioc.NewPostgresStore(ctx, pgCfg)
		if pgErr != nil {
			log.Printf("⚠️  PostgreSQL init failed: %v — falling back to in-memory storage", pgErr)
			pgStore = nil
		} else {
			log.Printf("PostgreSQL: connected to %s (pool: %d-%d conns)",
				truncateDBURL(databaseURL), pgCfg.MinConns, pgCfg.MaxConns)

			// Wire PostgreSQL into persistence (audit storage)
			persistenceMgr, err = persistence.NewWithPostgres(platformTier, persistenceCfg, pgStore)
			if err := persistenceMgr.Start(); err != nil {
				log.Fatalf("Failed to start PostgreSQL-backed persistence: %v", err)
			}

			// Wire PostgreSQL into RBAC (agent/session storage)
			var rbacErr error
			rbacPgStore, rbacErr = rbac.NewPostgresRBACStore(pgStore, nil)
			if rbacErr != nil {
				log.Printf("⚠️  PostgreSQL RBAC init failed: %v — falling back to in-memory RBAC", rbacErr)
				rbacPgStore = nil
			}
		}
	} else {
		if databaseURL != "" {
			log.Printf("⚠️  AEGISGATE_DATABASE_URL set but tier %s does not support PostgreSQL — using in-memory storage", platformTier.String())
		}
	}

	// Initialize RBAC manager (PostgreSQL-backed or in-memory)
	if rbacPgStore != nil {
		var rbacErr error
		rbacMgr, rbacErr = rbac.NewWithPostgres(nil, rbacPgStore)
		if rbacErr != nil {
			log.Fatalf("Failed to initialize RBAC manager with PostgreSQL: %v", rbacErr)
		}
		log.Printf("RBAC: PostgreSQL-backed (session persistence enabled)")
	} else {
		var rbacErr error
		rbacMgr, rbacErr = rbac.NewManager(nil)
		if rbacErr != nil {
			log.Fatalf("Failed to initialize RBAC manager: %v", rbacErr)
		}
		log.Printf("RBAC: in-memory (sessions lost on restart)")
	}
	defer rbacMgr.Close()
	defer licenseMgr.Close()
	if pgStore != nil {
		defer pgStore.Close()
	}

	// Wire PostgreSQL into license cache (if available)
	if pgStore != nil {
		licensePgCache, licensePgErr := license.NewPostgresLicenseCache(pgStore)
		if licensePgErr != nil {
			log.Printf("⚠️  PostgreSQL license cache init failed: %v — using in-memory cache", licensePgErr)
		} else {
			licenseMgr.SetPostgresCache(licensePgCache)
			log.Printf("License: PostgreSQL-backed cache (shared across instances)")
		}
	}

	// ============================================================
	// Component 0a: Federated IOC Library (v3.5.0+ Track 6)
	// ============================================================
	// Initializes the IOC store, signing key, and instance ID
	// on disk under ${DataDir}/ioc/. The producer is then
	// layered on top of the existing audit ring buffer
	// (see installIOCRecorder call below, just before Component 1)
	// so every logging.Record() event flows through the
	// producer's allow-list. Events that pass the allow-list are
	// fingerprinted and written to the IOC store.
	//
	// Opt-in: the share/receive flags are resolved from CLI
	// (--ioc-share / --ioc-receive) or env (AEGISGATE_IOC_SHARE /
	// AEGISGATE_IOC_RECEIVE). Both default to false. The IOC
	// library is always constructed (so /api/v1/ioc/health
	// reports the correct status), but EnableShare / EnableReceive
	// are false unless the operator explicitly opts in.
	//
	// The library is also always constructed (even if both flags
	// are false) so the /api/v1/ioc/health endpoint returns the
	// correct 503 status, and so flipping the flags on at runtime
	// (via a future admin API) works without re-initialization.
	iocW, iocInstanceID, iocErr := wireIOC(persistenceCfg.DataDir, platformTier)
	if iocErr != nil {
		// IOC init failure is non-fatal: log and continue with
		// nil wiring. The /api/v1/ioc/health endpoint will
		// return 500 if a peer tries to fetch a manifest, but
		// the rest of the platform is unaffected.
		log.Printf("⚠️  Federated IOC library init failed: %v (continuing without IOC sharing)", iocErr)
		iocW = nil
	}
	if iocW != nil {
		log.Printf("Federated IOC: instance_id=%s, share=%v, receive=%v, peers=%d, store=%s",
			iocInstanceID,
			iocW.Sync != nil, // EnableShare is implicit; we check via Sync
			iocW.Sync != nil, // same for receive; the Sync is constructed either way
			len(iocW.Sync.Peers()),
			persistenceCfg.DataDir+"/ioc")
		// Resolve the actual share/receive booleans for the
		// install + start logic below.
		share, receive, _ := resolveIOCFlags()
		// Layer the producer on top of the existing audit ring
		// buffer and install as the new default recorder. This
		// MUST happen before Component 1 (proxy) so that the
		// proxy's first record() call is captured as an IOC.
		installIOCRecorder(auditRing, iocW.Producer, share, receive)
		// Start the background goroutines. The flusher is always
		// started (the store may have on-disk state to load).
		// The receiver is only started if receive is enabled
		// (tier gate is enforced inside sync.RunReceiver).
		go iocW.Store.RunFlusher(ctx)
		if receive {
			go iocW.Sync.RunReceiver(ctx)
		}
		// Construct the reputation store and attach to the
		// sync. Persists alongside the IOC store at
		// ${DataDir}/ioc/reputation.json. Threshold defaults
		// to 0.3 (a peer must have >30% acceptance rate to
		// be ingested from).
		rep, repErr := ioc.NewReputationStore(ioc.ReputationConfig{
			Threshold: ioc.DefaultReputationThreshold,
			HalfLife:  ioc.DefaultReputationHalfLife,
			DiskPath:  filepath.Join(persistenceCfg.DataDir, "ioc", "reputation.json"),
		})
		if repErr != nil {
			log.Printf("⚠️  Federated IOC reputation init failed: %v (continuing without reputation)", repErr)
		} else {
			iocW.Sync.SetReputation(rep)
			log.Printf("Federated IOC: reputation store attached (threshold=%.2f, half-life=%s)",
				ioc.DefaultReputationThreshold, ioc.DefaultReputationHalfLife)
		}
		// Construct the bootstrap Discoverer (v3.5.0+ Task 5).
		// Polls the configured seeds and learns about new
		// peers, up to MaxPeers. This is the pragmatic
		// alternative to mDNS / DNS-SD that works in any
		// network environment (cloud, on-prem, hybrid).
		// The Discoverer is opt-in: enabled only if
		// AEGISGATE_IOC_BOOTSTRAP_PEERS is set or
		// --ioc-bootstrap-peers is passed.
		bootstrapPeers := *iocBootstrapPeers
		if bootstrapPeers == "" {
			bootstrapPeers = os.Getenv("AEGISGATE_IOC_BOOTSTRAP_PEERS")
		}
		var bootstrapSeeds []string
		for _, p := range strings.Split(bootstrapPeers, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				bootstrapSeeds = append(bootstrapSeeds, p)
			}
		}
		if len(bootstrapSeeds) > 0 {
			discoverer, derr := ioc.NewDiscoverer(ioc.DiscoveryConfig{
				Seeds: bootstrapSeeds,
				Sync:  iocW.Sync,
			})
			if derr != nil {
				// #nosec G706 -- log injection: the
				// error string is sanitized via the
				// strings.ReplaceAll calls below (the
				// recognized gosec sanitizer for newlines
				// + carriage returns). CodeQL's taint
				// analysis can't follow the value through
				// the function call, so the sanitizer is
				// inlined here.
				sanitized := strings.ReplaceAll(derr.Error(), "\n", " ")
				sanitized = strings.ReplaceAll(sanitized, "\r", " ")
				log.Printf("⚠️  IOC discoverer init failed: %v (continuing without discovery)", sanitized)
			} else {
				go discoverer.Run(ctx)
				// #nosec G706 -- log injection: this
				// log message has no user-controlled
				// values (all args are constants or
				// ints). The false positive is because
				// gosec flags all log.Printf calls that
				// use %d/%s verbs in a function that
				// also has a taint source.
				log.Printf("Federated IOC: bootstrap discovery enabled (seeds=%d, interval=%s, max=%d)",
					len(bootstrapSeeds),
					ioc.DefaultDiscoveryInterval,
					ioc.DefaultMaxDiscoveredPeers)
			}
		}
		// Expose to the rest of main via package-level vars so
		// the mux mount and the testlab handlers can reach it.
		iocWiringPtr = iocW
	}

	// ============================================================
	// Component 0a-2: Lens Telemetry Backend (Phase 3)
	// ============================================================
	// Mounts the Lens telemetry endpoints on the proxy mux so
	// self-hosted Platform users can receive telemetry from Lens
	// extensions without running a separate binary. The Lens backend
	// reuses the same IOC store as the Federated IOC Library.
	//
	// Feature gate: Professional+ tier (same as PostgreSQL).
	// Env vars: AEGISGATE_LENS_ENABLED, AEGISGATE_LENS_BEARER_TOKEN,
	//   AEGISGATE_LENS_IOC_STORE_DIR
	// Flags: --lens-enabled, --lens-bearer-token, --lens-ioc-store-dir

	var lensServer *lensbackend.Server
	lensEnabledFlag := *lensEnabled
	if !lensEnabledFlag {
		if v := os.Getenv("AEGISGATE_LENS_ENABLED"); v == "true" || v == "1" || v == "yes" {
			lensEnabledFlag = true
		}
	}
	if lensEnabledFlag && tier.HasFeature(platformTier, tier.FeaturePostgreSQL) {
		lensBearer := *lensBearerToken
		if lensBearer == "" {
			lensBearer = os.Getenv("AEGISGATE_LENS_BEARER_TOKEN")
		}
		lensStorePath := *lensIOCStoreDir
		if lensStorePath == "" {
			lensStorePath = os.Getenv("AEGISGATE_LENS_IOC_STORE_DIR")
		}
		if lensStorePath == "" {
			lensStorePath = filepath.Join(cfg.Persistence.DataDir, "lens")
		}
		lensCfg := &lensbackend.Config{
			Port:            *proxyPort, // share the proxy port
			BearerToken:     lensBearer,
			IOCStorePath:    lensStorePath,
			RateLimitPerMin: 10000,
		}
		if lensBearer == "" {
			log.Printf("⚠️  Lens backend enabled but AEGISGATE_LENS_BEARER_TOKEN is empty — only /healthz will be reachable")
		}
		var lensErr error
		lensServer, lensErr = lensbackend.NewServer(lensCfg, "aegisgate-platform")
		if lensErr != nil {
			log.Printf("⚠️  Lens backend init failed: %v (continuing without Lens telemetry)", lensErr)
			lensServer = nil
		} else {
			log.Printf("Lens backend: enabled (ioc_store=%s, rate_limit=%d/min)", lensStorePath, lensCfg.RateLimitPerMin)
		}
	} else if lensEnabledFlag {
		log.Printf("⚠️  Lens backend requires Professional+ tier (current: %s); Lens telemetry disabled", platformTier)
	}

	// ============================================================
	// Component 0a-3: SIEM Dispatcher (Phase 4, D15)
	// ============================================================
	// Bridges the platform's audit event stream to external SIEM
	// platforms (Splunk, Elasticsearch, QRadar, Sentinel, etc.).
	// The dispatcher polls the audit ring buffer and forwards
	// aggregated event summaries to the configured SIEM manager.
	//
	// Feature gate: Professional+ tier (same as PostgreSQL).
	// Config: cfg.SIEM (in platformconfig.yaml)
	siemEnabledFlag := *siemEnabled
	if !siemEnabledFlag {
		if v := os.Getenv("AEGISGATE_SIEM_ENABLED"); v == "true" || v == "1" || v == "yes" {
			siemEnabledFlag = true
		}
	}
	if cfg.SIEM.Enabled {
		siemEnabledFlag = true
	}
	var siemMgr *siem.Manager
	var siemDisp *audit.SIEMDispatcher
	var siemPlatformCount int
	if siemEnabledFlag && tier.HasFeature(platformTier, tier.FeaturePostgreSQL) {
		// Convert platformconfig.SIEMConfig to siem.Config
		siemCfg := siem.Config{
			Global: siem.GlobalConfig{
				AppName:     cfg.SIEM.Source,
				Environment: cfg.Platform.Mode,
			},
			Buffer: siem.BufferConfig{
				MaxSize: cfg.SIEM.BufferMaxSize,
			},
		}
		// Convert each platform config
		for _, p := range cfg.SIEM.Platforms {
			if !p.Enabled {
				continue
			}
			pc := siem.PlatformConfig{
				Platform: siem.Platform(p.Platform),
				Enabled:  true,
				Format:   siem.Format(p.Format),
				Endpoint: p.Endpoint,
				Settings: p.Settings,
			}
			pc.Auth.Type = p.Auth.Type
			pc.Auth.APIKey = p.Auth.APIKey
			pc.Auth.APIKeyHeader = p.Auth.APIKeyHeader
			pc.Auth.Username = p.Auth.Username
			pc.Auth.Password = p.Auth.Password
			pc.Auth.TokenURL = p.Auth.TokenURL
			pc.Auth.ClientID = p.Auth.ClientID
			pc.Auth.ClientSecret = p.Auth.ClientSecret
			pc.TLS.Enabled = p.TLS.Enabled
			pc.TLS.InsecureSkipVerify = p.TLS.InsecureSkipVerify
			pc.TLS.CAFile = p.TLS.CAFile
			pc.TLS.ServerName = p.TLS.ServerName
			pc.Retry.Enabled = p.Retry.Enabled
			pc.Retry.MaxAttempts = p.Retry.MaxAttempts
			if p.Retry.InitialBackoff != "" {
				if d, err := time.ParseDuration(p.Retry.InitialBackoff); err == nil {
					pc.Retry.InitialBackoff = d
				}
			}
			if p.Retry.MaxBackoff != "" {
				if d, err := time.ParseDuration(p.Retry.MaxBackoff); err == nil {
					pc.Retry.MaxBackoff = d
				}
			}
			pc.Retry.BackoffMultiplier = p.Retry.BackoffMultiplier
			pc.Batch.Enabled = p.Batch.Enabled
			pc.Batch.MaxSize = p.Batch.MaxSize
			if p.Batch.MaxWait != "" {
				if d, err := time.ParseDuration(p.Batch.MaxWait); err == nil {
					pc.Batch.MaxWait = d
				}
			}
			siemCfg.Platforms = append(siemCfg.Platforms, pc)
		}

		var siemErr error
		siemMgr, siemErr = siem.NewManager(siemCfg)
		if siemErr != nil {
			log.Printf("⚠️  SIEM manager init failed: %v (continuing without SIEM)", siemErr)
		} else {
			siemMgr.Start()
			siemDisp, siemErr = audit.NewSIEMDispatcher(audit.SIEMDispatcherConfig{
				Manager:      siemMgr,
				EventSource:  auditRing,
				PollInterval: cfg.SIEM.PollInterval,
				BatchSize:    cfg.SIEM.BatchSize,
				Source:       cfg.SIEM.Source,
			})
			if siemErr != nil {
				log.Printf("⚠️  SIEM dispatcher init failed: %v (continuing without SIEM)", siemErr)
				siemMgr.Stop()
				siemMgr = nil
			} else {
				go siemDisp.Run(ctx)
				log.Printf("SIEM dispatcher: enabled (platforms=%d, poll=%s, source=%s)",
					len(siemCfg.Platforms), cfg.SIEM.PollInterval, cfg.SIEM.Source)
				siemPlatformCount = len(siemCfg.Platforms)
				defer siemDisp.Stop()
				defer siemMgr.Stop()
			}
		}
	} else if siemEnabledFlag {
		log.Printf("⚠️  SIEM requires Professional+ tier (current: %s); SIEM disabled", platformTier)
	}

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

	// -------------------
	// Federated IOC Library endpoints (v3.5.0+ Track 6)
	// -------------------
	// Mounts the IOC manifest + health endpoints on the proxy mux.
	// The handler enforces the EnableShare gate internally: if
	// --ioc-share is not set, /api/v1/ioc/manifest returns 403
	// and /api/v1/ioc/health returns 503. The handler is mounted
	// unconditionally so the health endpoint can report the
	// current state (healthy / disabled / unavailable).
	//
	// We mount under /api/v1/ioc/ to match the existing platform
	// convention (/api/v1/compliance/, /api/v1/posture/, etc.).
	if iocWiringPtr != nil {
		proxyMux.Handle("/api/v1/ioc/", iocWiringPtr.Sync.Handler())
		log.Printf("Federated IOC: handler mounted at /api/v1/ioc/")
	}

	// Lens telemetry endpoints (Phase 3): mount on the proxy
	// mux so Lens extensions can POST telemetry and FP reports to
	// the same port as the proxy. Self-hosted Platform users point
	// their Lens extension at https://<platform>:8443/api/v1/lens/*
	//
	// The Lens server provides its own auth middleware (bearer token).
	// Routes:
	//   POST /api/v1/lens/telemetry
	//   POST /api/v1/lens/fp-report
	//   GET  /api/v1/lens/check?domain=<hostname>
	//   GET  /api/v1/lens/stats
	//   GET  /api/v1/lens/healthz
	if lensServer != nil {
		lensMux := lensServer.Mux()
		proxyMux.Handle("/api/v1/lens/", lensMux)
		log.Printf("Lens backend: handler mounted at /api/v1/lens/")
	}

	// IOC admin API (v3.5.0+ Track 6 Task 5): mount on the
	// dashboard mux, NOT the proxy mux. The admin endpoints
	// require authentication (provided by the existing
	// dashboard auth) and are not exposed to public proxy
	// traffic. Routes:
	//   GET  /api/v1/ioc/admin/status
	//   POST /api/v1/ioc/admin/share
	//   POST /api/v1/ioc/admin/receive
	//   GET  /api/v1/ioc/admin/keyring
	//   POST /api/v1/ioc/admin/keyring/rotate
	//   GET  /api/v1/ioc/admin/reputation
	// The admin API is mounted later (in the dashboard mux
	// block) so it is reachable on the admin port.
	iocAdminAPIPtr = newIOCAdminAPI(iocWiringPtr)

	// -------------------
	// A2A Guardrails Middleware Integration
	// -------------------
	// Load A2A configuration from the platform config. If A2A is not enabled
	// or the config file is missing, the A2A endpoints are disabled gracefully.
	var a2aMiddleware http.Handler
	if cfg.A2A.Enabled {
		a2aCfg, err := a2a.LoadConfig(cfg.A2A.ConfigFile)
		if err != nil {
			log.Printf("Warning: A2A config load failed (%v) — A2A endpoints disabled", err)
		} else {
			// A2A Persistence: capabilities are stored in /data/a2a_caps.json
			// so they survive pod restarts. On first startup, seed from the YAML config.
			capsFile := filepath.Join(cfg.Persistence.DataDir, "a2a_caps.json")
			capsEnforcer, err := a2a.NewPersistentCapEnforcer(capsFile)
			if err != nil {
				log.Printf("Warning: A2A persistent caps init failed (%v) — falling back to in-memory", err)
				capsEnforcer, _ = a2a.NewPersistentCapEnforcer(capsFile)
			}

			// Load from YAML config on first startup (seeds the persistent store)
			if cfg.A2A.CapsFile != "" {
				if err := capsEnforcer.LoadFromYAML(cfg.A2A.CapsFile); err != nil {
					log.Printf("Warning: A2A YAML caps load failed (%v) — using persisted capabilities", err)
				}
			}

			a2aHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, map[string]string{"status": "a2a-ok"})
			})
			// Wire the A2A middleware with license manager for tier-aware enforcement.
			// Pass the license manager so A2A can validate license headers (Developer+ tiers).
			a2aMiddleware = a2a.NewA2AMiddleware(a2aHandler, []byte(a2aCfg.Secret), licenseMgr, capsEnforcer)
			proxyMux.Handle("/a2a/", a2aMiddleware)
			// Register the echo endpoint specifically for testing/demos
			a2a.RegisterA2AServer(proxyMux, []byte(a2aCfg.Secret), licenseMgr, capsEnforcer)
			log.Printf("A2A: Guardrails active (secret=%d bytes, rate_limit=%d/%d per %s)",
				len(a2aCfg.Secret), a2aCfg.RateLimit.Refill, a2aCfg.RateLimit.Capacity, a2aCfg.RateLimit.Interval)
		}
	}
	if a2aMiddleware == nil {
		// A2A not configured — register a discovery endpoint that reports disabled
		proxyMux.HandleFunc("/a2a/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]string{"status": "disabled", "reason": "a2a not configured"})
		})
		log.Printf("A2A: Guardrails not enabled (set a2a.enabled=true in config or AEGISGATE_A2A_ENABLED=true)")
	}

	// Management endpoints on the proxy port
	// Health check verifies all critical dependencies: proxy, persistence,
	// license manager, and certificate store.
	proxyMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		checks := map[string]map[string]interface{}{}
		allHealthy := true

		// Check 1: Proxy core - check if proxy was configured (started separately via proxyHTTPServer)
		proxyHealth := proxyServer.GetHealth()
		proxyEnabled := false
		// Use bind_address as indicator - if set, proxy was configured and is listening
		if bindAddr, ok := proxyHealth["bind_address"].(string); ok && bindAddr != "" {
			proxyEnabled = true
		}
		if !proxyEnabled {
			allHealthy = false
		}

		// Check 2: Persistence layer
		persistStarted := false
		if started, ok := persistenceMgr.Stats()["started"].(bool); ok && started {
			persistStarted = true
		}
		checks["persistence"] = map[string]interface{}{
			"enabled": persistenceMgr.IsEnabled(),
			"started": persistStarted,
			"healthy": persistStarted,
		}
		if !persistStarted {
			allHealthy = false
		}

		// Check 3: License manager
		licenseResult := licenseMgr.Validate(licenseMgr.GetLicenseKey())
		checks["license"] = map[string]interface{}{
			"valid":   licenseResult.Valid,
			"tier":    licenseResult.Tier.String(),
			"healthy": licenseResult.Valid,
		}
		if !licenseResult.Valid {
			allHealthy = false
		}

		// Check 4: Certificate store
		certValidation, certErr := certinit.ValidateCerts(certinit.Config{
			CertDir:      cfg.TLS.CertDir,
			AutoGenerate: cfg.TLS.AutoGenerate,
			CACertFile:   "ca.crt",
			CAKeyFile:    "ca.key",
			CertFile:     "server.crt",
			KeyFile:      "server.key",
		})
		certHealthy := certErr == nil && certValidation != nil && (certValidation.ServerCertValid || !cfg.TLS.AutoGenerate)
		checks["certificates"] = map[string]interface{}{
			"valid":   certHealthy,
			"healthy": certHealthy,
		}
		if !certHealthy {
			allHealthy = false
		}

		// Check 5: SIEM dispatcher
		siemHealthy := false
		siemPlatforms := 0
		siemStats := audit.DispatcherStats{}
		if siemDisp != nil {
			siemStats = siemDisp.Stats()
			siemHealthy = true
		}
		if siemMgr != nil {
			siemPlatforms = siemPlatformCount
		}
		checks["siem"] = map[string]interface{}{
			"enabled":          siemEnabledFlag,
			"healthy":          siemHealthy,
			"platforms":        siemPlatforms,
			"events_forwarded": siemStats.EventsForwarded,
			"events_dropped":   siemStats.EventsDropped,
		}
		if siemEnabledFlag && !siemHealthy {
			allHealthy = false
		}

		status := "healthy"
		code := http.StatusOK
		if !allHealthy {
			status = "unhealthy"
			code = http.StatusServiceUnavailable
		}

		// Build JSON response manually for deterministic field order
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"status":"%s","tier":"%s","version":"%s","checks":{"proxy":{"enabled":%v,"healthy":%v},"persistence":{"enabled":%v,"started":%v,"healthy":%v},"license":{"valid":%v,"tier":"%s","healthy":%v},"certificates":{"valid":%v,"healthy":%v},"siem":{"enabled":%v,"healthy":%v,"platforms":%d,"events_forwarded":%d,"events_dropped":%d}}}`,
			status, platformTier.String(), version,
			proxyEnabled, proxyEnabled,
			persistenceMgr.IsEnabled(), persistStarted, persistStarted,
			licenseResult.Valid, licenseResult.Tier.String(), licenseResult.Valid,
			certHealthy, certHealthy,
			siemEnabledFlag, siemHealthy, siemPlatforms, siemStats.EventsForwarded, siemStats.EventsDropped)
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

	// F-DOS-1 (D25 pentest): wrap with http.MaxBytesHandler to cap
	// request body size at 10MB. A 10MB+ POST took 205s on the
	// unhardened server; with the cap, the request is rejected
	// at 10MB before the body finishes uploading. 10MB is
	// larger than any legitimate request the platform
	// processes (the largest expected body is a compliance
	// manifest at ~1MB).
	//
	// (Track 6 Task 1) so every proxy request/response is captured in
	// the global ring buffer for compliance evidence packages.
	var innerHandler http.Handler = proxyRecorderMiddleware(
		security.APIHeadersMiddleware(metrics.WrapHandler("proxy", proxyMux)))
	proxyHandler := http.MaxBytesHandler(innerHandler, int64(10<<20))

	// F-DOS-1 (D25 pentest): Add ReadHeaderTimeout to prevent
	// Slowloris-style header-read attacks. The 10MB+ body
	// DoS is mitigated by the existing ReadTimeout (60s)
	// combined with the MaxBytesHandler below.
	proxyHTTPServer := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", *proxyPort),
		Handler:           proxyHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
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

	platformBridge, bridgeErr := bridge.NewPlatformBridge(fmt.Sprintf("http://localhost:%d", *proxyPort))
	if bridgeErr != nil {

		// ============================================================
		// Component 5: ACP (Agent Communication Protocol) Guard
		// ============================================================
		// Gated on cfg.ACP.Enabled (D14: parity with A2A / lens / siem)
		if cfg != nil && cfg.ACP.Enabled {
			var acpMiddleware *acp.Middleware
			_ = acp.NewACPResponseScanner // Reserved for future use

			// Load ACP configuration from file or environment
			acpConfigPath := cfg.ACP.ConfigFile
			if acpConfigPath == "" {
				acpConfigPath = "configs/acp.yaml"
			}
			var acpCfg *acp.ACPGuardConfig

			if _, err := os.Stat(acpConfigPath); err == nil {
				loader := acp.NewConfigLoader()
				acpCfg, err = loader.LoadConfig(acpConfigPath)
				if err != nil {
					log.Printf("Warning: ACP config load failed (%v) - using defaults", err)
					acpCfg = acp.DefaultACPGuardConfig()
				}
			} else {
				acpCfg = acp.LoadConfigFromEnv()
				log.Printf("ACP: No config file found, using env-based config")
			}

			// Create ACP scanner and middleware
			acp.SetGuardEnabled(acpCfg.EnableHMAC || acpCfg.EnableRateLimiting)
			acpMiddleware = acp.NewMiddlewareWithConfig(acpCfg)

			// Register ACP endpoints
			proxyMux.Handle("/acp/", acpMiddleware.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				//nolint:errcheck - ACP endpoint write errors are logged but non-fatal
				if _, err := w.Write([]byte("{\"status\":\"acp-ok\",\"version\":\"" + version + "\"}")); err != nil {
					log.Printf("Warning: Failed to write ACP response: %v", err)
				}
			})))

			log.Printf("ACP: Guardrails active (hmac=%v, rate_limit=%v/min, burst=%d)",
				acpCfg.EnableHMAC, acpCfg.RateLimitPerMinute, acpCfg.RateLimitBurst)
		} else {
			proxyMux.HandleFunc("/acp/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				writeJSON(w, map[string]string{"status": "disabled", "reason": "acp not configured"})
			})
			log.Printf("ACP: Guardrails not enabled (set acp.enabled=true in config or AEGISGATE_ACP_ENABLED=true)")
		}

		// ============================================================
		// Component 6: Trust Framework (6th pillar) HTTP API
		// ============================================================
		// Gated on cfg.Trust.Enabled (Trust audit: parity with A2A/ACP)
		// The Trust Framework provides per-agent identity, capability
		// contracts, real-time trust scoring, anomaly detection, and
		// signed attestations. HTTP API at /api/v1/trust/*.
		// License gate: when cfg.Trust.RequireLicense=true, the
		// manager is wrapped in a tier check (Professional+ per Q3).
		if cfg != nil && cfg.Trust.Enabled {
			trustMgr := trust.NewManager(nil, nil)
			trustAPI := trust.NewAPI(trustMgr, &trust.APIConfig{
				AttestationCap: 1000,
			})
			if cfg.Trust.RequireLicense && licenseMgr != nil {
				// Wrap trustAPI in a tier-gated HandlerFunc via adapter
				gate := license.NewLicenseMiddleware(licenseMgr).RequireTier(tier.TierProfessional)
				proxyMux.HandleFunc("/api/v1/trust/", gate(trustAPI.ServeHTTP))
			} else {
				proxyMux.Handle("/api/v1/trust/", trustAPI)
			}
			log.Printf("Trust Framework: 6th pillar active (manager wired, HTTP API mounted at /api/v1/trust/*, license_gate=%v)", cfg.Trust.RequireLicense)
		} else {
			proxyMux.HandleFunc("/api/v1/trust/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				writeJSON(w, map[string]string{"status": "disabled", "reason": "trust framework not configured"})
			})
			log.Printf("Trust Framework: 6th pillar not enabled (set trust.enabled=true in config or AEGISGATE_TRUST_ENABLED=true)")
		}

		log.Printf("Warning: Failed to create platform bridge: %v - continuing without bridge", bridgeErr)
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

	// Compliance scan engine (v3.2.0 Phase 3.3). Wraps the
	// scanner with the HTTP API at /api/v1/compliance/* (scan,
	// report, health). The license manager is the same one used
	// for tier checks elsewhere; the API uses it to extract the
	// caller's license from the request context. The new routes
	// live alongside the existing /api/v1/compliance (audit
	// export) endpoint; they don't conflict.
	compliance.RegisterBuiltinFrameworks()
	complianceScanner := compliance.NewScanner(nil, &compliance.ScannerOpts{CacheTTL: 5 * time.Minute})
	complianceAPI := compliance.NewAPI(complianceScanner, licenseMgr)
	dashMux.Handle("/api/v1/compliance/", complianceAPI)

	// Evidence Package API (v3.3.0+ Track 2). Constructed from the live
	// Scanner + License manager + a persistent signing key. The API
	// exposes:
	//   POST /api/v1/compliance/evidence          -> build a new manifest
	//   GET  /api/v1/compliance/evidence          -> list stored manifests
	//   GET  /api/v1/compliance/evidence/:id      -> fetch a manifest by ID
	//   GET  /api/v1/compliance/evidence/:id/verify -> verify a manifest
	// Mounted under the same prefix as the compliance API so the
	// existing /api/v1/compliance/* auth context applies.
	// Pass auditRing as the EventSource so evidence packages get real
	// audit anchors (source="ring_buffer") instead of "unavailable".
	evidenceHandler, wellKnownHandler, evErr := newEvidenceAPIForPlatform(complianceScanner, licenseMgr, auditRing, "./var")
	if evErr != nil {
		log.Printf("[EVIDENCE] Failed to initialize evidence API: %v", evErr)
	} else {
		dashMux.Handle("/api/v1/compliance/evidence", evidenceHandler)
		// Well-known public key handler. Mounted on the dashboard
		// mux (NOT /api/v1/) so it's reachable at the canonical
		// /.well-known/aegisgate-evidence-pubkey.pem URL. v3.4.0
		// primitive that closes the verifiable compliance loop.
		dashMux.Handle("/.well-known/aegisgate-evidence-pubkey.pem", wellKnownHandler)
		log.Printf("[EVIDENCE] Compliance evidence API enabled at /api/v1/compliance/evidence and /.well-known/aegisgate-evidence-pubkey.pem")
	}

	// IOC admin API (v3.5.0+ Track 6 Task 5). Mounted on the
	// dashboard mux (admin port) so the runtime share/receive
	// toggles, key rotation, and reputation views are reachable
	// for operators but NOT exposed to public proxy traffic.
	if iocAdminAPIPtr != nil {
		dashMux.Handle("/api/v1/ioc/admin/", iocAdminAPIPtr.Handler())
		log.Printf("[IOC-ADMIN] Federated IOC admin API enabled at /api/v1/ioc/admin/")
	}

	// AR-EaaS HTTP endpoint (v3.7.0+ TODO-301). Mounted on the
	// dashboard mux (admin port) so the run/verify verbs are
	// reachable for operators but NOT exposed to public proxy
	// traffic. The endpoint uses an in-process stub target
	// for v0.1; v0.2 will add a Go-plugin loader for
	// caller-supplied targets.
	if iocW != nil {
		wireEvaluatorHandlers(dashMux, authMiddleware, iocW.KeyRing)
		log.Printf("[EVALUATOR] AR-EaaS HTTP API enabled at /api/v1/evaluator/{run,verify}")
	}

	// AIBOM HTTP endpoint (v3.7.0+ TODO-302). Mounted on the
	// dashboard mux (admin port) so the generate/verify verbs
	// are reachable for operators but NOT exposed to public
	// proxy traffic. v0.1: the generate endpoint produces
	// placeholder data for the 5 protocol pillars. v0.2 will
	// wire the pillars to the live platform config.
	if iocW != nil {
		wireAIBOMHandlers(dashMux, authMiddleware, iocW.KeyRing)
		log.Printf("[AIBOM] AIBOM HTTP API enabled at /api/v1/aibom/{generate,verify}")
	}

	// A2A Intent Signing HTTP endpoint (v3.7.0+ TODO-303).
	// Mounted on the dashboard mux (admin port) so the
	// sign/verify verbs are reachable for operators but
	// NOT exposed to public proxy traffic. v0.1: standalone
	// sign+verify only; v0.2 will integrate with pkg/a2a/
	// middleware (intent becomes an optional header on
	// A2A requests).
	if iocW != nil {
		wireA2AIntentHandlers(dashMux, authMiddleware, iocW.KeyRing)
		log.Printf("[A2A-INTENT] A2A intent HTTP API enabled at /api/v1/a2a/intent/{sign,verify}")
	}

	// Prompt Cache Poisoning Detection HTTP endpoint
	// (v3.7.0+ TODO-304). Mounted on the dashboard mux
	// (admin port) for the same reason as A2A intent: the
	// attest/verify verbs are reachable for operators but
	// NOT exposed to public proxy traffic. v0.1: standalone
	// attest+verify only; v0.2 will integrate with pkg/ioc/
	// (cache-poisoning events become IOCs).
	if iocW != nil {
		wirePromptCacheHandlers(dashMux, authMiddleware, iocW.KeyRing)
		log.Printf("[PROMPT-CACHE] Prompt-cache HTTP API enabled at /api/v1/prompt-cache/{attest,verify}")
	}

	// CVE Entry HTTP endpoint (v3.7.0+ TODO-305).
	// Mounted on the dashboard mux (admin port) for the
	// same reason as the other Tier 5 endpoints. The
	// publish side is Enterprise-only (the tier check is
	// inline in the handler); the verify side is free.
	// v0.1: standalone publish+verify only; the static
	// portal at cve.aegisgatesecurity.io is a separate
	// workstream (deferred).
	if iocW != nil {
		wireCVEHandlers(dashMux, authMiddleware, iocW.KeyRing)
		log.Printf("[CVE] CVE HTTP API enabled at /api/v1/cve/{publish,verify} (publish is Enterprise-only)")
	}

	// Reporting HTTP endpoint (v3.5.0+ TODO-501).
	// PDF generation is FREE (no tier gate). v0.1
	// ships the ad-hoc PDF endpoint only;
	// pdf-from-report is CLI-only.
	wireReportHandlers(dashMux, authMiddleware)
	log.Printf("[REPORT] Reporting HTTP API enabled at /api/v1/reports/pdf")

	// SOC Timeline HTTP endpoint (v3.5.0+ TODO-502).
	// SOC timeline is FREE (no tier gate). v0.1
	// ships the read endpoint only; event recording
	// is the correlation engine's responsibility
	// (and currently has no callers in the platform
	// tree; v0.2 will wire it into the 5 protocol
	// pillars).
	wireSOCHandlers(dashMux, authMiddleware)
	log.Printf("[SOC] SOC Timeline HTTP API enabled at /api/v1/soc/incidents/:id/timeline")

	// CISO Posture Digest HTTP endpoint
	// (v3.6.0+ TODO-601+602). Mounted on the
	// dashboard mux. The generate side is
	// Professional+ (the digest is a
	// customer-facing artifact); the verify side
	// is free. v0.1 ships a stub (BuildDigest
	// with no sources); v0.2 wires the real source
	// pipeline (PostureSource, IOCSource,
	// AuditSource).
	if iocW != nil {
		wireDigestHandlers(dashMux, authMiddleware, WireDigestDeps{
			KeyRing:  iocW.KeyRing,
			IOCStore: iocW.Store,
			AuditLog: auditRing,
			// Posture + SIEMDispatcher are not
			// wired in v0.2; the digest's
			// posture field is "unknown".
		})
		log.Printf("[DIGEST] CISO Digest HTTP API enabled at /api/v1/digest/{generate,verify} (generate is Professional+)")
	}

	// Posture Check HTTP endpoints (D19, P1 #8).
	// Closes the last gap in the v3.4.0+ HTTP feature set.
	// posture_subcommand.go already had a `handlePostureAPI`
	// stub marked `//nolint:unused // reserved for v0.2`; this
	// is the v0.2 refactor that wires it. The HTTP routes are
	// /api/v1/posture (JSON), /api/v1/posture/verbose (verbose
	// JSON, same shape), /api/v1/posture/text (plain text).
	// All 3 require auth. Posture is read-only.
	wirePostureHandlers(dashMux, authMiddleware, licenseMgr, *mode)
	log.Printf("[POSTURE] Posture Check HTTP API enabled at /api/v1/posture/{,verbose,text} (matches `aegisgate status` output)")

	// Attestation Envelope HTTP endpoints (D19, P1 #8).
	// Wires pkg/attestation as the auditor-facing HTTP API
	// counterpart of the CLI `aegisgate attestation verify`
	// subcommand. /api/v1/attestation/verify uses the embedded
	// public key (offline, auditor-on-a-plane scenario);
	// /api/v1/attestation/verify-online fetches the public key
	// from /.well-known/. Both require auth.
	wireAttestationHandlers(dashMux, authMiddleware)
	log.Printf("[ATTESTATION] Attestation HTTP API enabled at /api/v1/attestation/{verify,verify-online}")

	// Dashboard health endpoint — verifies proxy, persistence, license, certs, scanner, and A2A
	dashMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		checks := map[string]map[string]interface{}{}
		allHealthy := true

		// Scanner
		scannerHealthy := mcpScanner.Health() == nil
		checks["scanner"] = map[string]interface{}{"healthy": scannerHealthy}
		if !scannerHealthy {
			allHealthy = false
		}

		// Bridge
		bridgeStatus := "disabled"
		if platformBridge != nil && platformBridge.IsEnabled() {
			bridgeStatus = "enabled"
		}
		checks["bridge"] = map[string]interface{}{"status": bridgeStatus, "healthy": true}

		// Persistence
		persistStarted := false
		if started, ok := persistenceMgr.Stats()["started"].(bool); ok && started {
			persistStarted = true
		}
		checks["persistence"] = map[string]interface{}{"enabled": persistenceMgr.IsEnabled(), "started": persistStarted, "healthy": persistStarted}
		if !persistStarted {
			allHealthy = false
		}

		// License
		licenseResult := licenseMgr.Validate(licenseMgr.GetLicenseKey())
		checks["license"] = map[string]interface{}{"valid": licenseResult.Valid, "tier": licenseResult.Tier.String(), "healthy": licenseResult.Valid}
		if !licenseResult.Valid {
			allHealthy = false
		}

		// Certificates
		certValidation, certErr := certinit.ValidateCerts(certinit.Config{
			CertDir:      cfg.TLS.CertDir,
			AutoGenerate: cfg.TLS.AutoGenerate,
			CACertFile:   "ca.crt",
			CAKeyFile:    "ca.key",
			CertFile:     "server.crt",
			KeyFile:      "server.key",
		})
		certHealthy := certErr == nil && certValidation != nil && (certValidation.ServerCertValid || !cfg.TLS.AutoGenerate)
		checks["certificates"] = map[string]interface{}{"valid": certHealthy, "healthy": certHealthy}
		if !certHealthy {
			allHealthy = false
		}

		// A2A
		a2aHealthy := true
		a2aStatus := "disabled"
		if a2aMiddleware != nil {
			a2aStatus = "active"
		} else {
			a2aHealthy = false // A2A not configured is degraded, not fatal
		}
		checks["a2a"] = map[string]interface{}{"status": a2aStatus, "healthy": a2aHealthy}

		status := "healthy"
		code := http.StatusOK
		if !allHealthy {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}

		w.WriteHeader(code)
		fmt.Fprintf(w, `{"status":"%s","version":"%s","tier":"%s","checks":{"scanner":{"healthy":%v},"bridge":{"status":"%s","healthy":true},"persistence":{"enabled":%v,"started":%v,"healthy":%v},"license":{"valid":%v,"tier":"%s","healthy":%v},"certificates":{"valid":%v,"healthy":%v},"a2a":{"status":"%s","healthy":%v}},"uptime":%.0f,"timestamp":"%s"}`,
			status, version, platformTier.String(),
			scannerHealthy, bridgeStatus,
			persistenceMgr.IsEnabled(), persistStarted, persistStarted,
			licenseResult.Valid, licenseResult.Tier.String(), licenseResult.Valid,
			certHealthy, certHealthy,
			a2aStatus, a2aHealthy,
			time.Since(startTime).Seconds(), time.Now().UTC().Format(time.RFC3339))
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
		writeBytes(w, data)
	})

	// SLA/SLO endpoint — show service level objectives for the current tier
	dashMux.HandleFunc("/api/v1/sla", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		currentSLA := sla.GetSLA(platformTier)

		resp := map[string]interface{}{
			"tier":                platformTier.String(),
			"uptime_target":       currentSLA.UptimeTarget,
			"support_response":    currentSLA.SupportResponse,
			"support_channel":     currentSLA.SupportChannel,
			"incident_response":   currentSLA.IncidentResponse,
			"data_retention_days": currentSLA.DataRetention,
			"slos":                make([]map[string]interface{}, 0, len(sla.SLOs)),
		}

		slos := make([]map[string]interface{}, 0, len(sla.SLOs))
		for _, slo := range sla.SLOs {
			slos = append(slos, map[string]interface{}{
				"name":        slo.Name,
				"target":      slo.Target,
				"window":      slo.Window,
				"metric":      slo.Metric,
				"description": slo.Description,
			})
		}
		resp["slos"] = slos

		data, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error":"marshal failed"}`)
			return
		}
		writeBytes(w, data)
	})

	// Audit log endpoint — query persisted audit entries
	dashMux.HandleFunc("/api/v1/audit", authMiddleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !persistenceMgr.IsEnabled() {
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, map[string]string{"error": "persistence disabled", "entries": "[]"})
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
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}

		data, err := json.Marshal(entries)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]string{"error": "marshal failed"})
			return
		}
		writeBytes(w, data)
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
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeBytes(w, data) // #nosec G705 -- format validated against allowlist above
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
		writeBytes(w, data)
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
		writeBytes(w, data)
	}))

	// MCP Guardrails stats endpoint
	dashMux.HandleFunc("/api/v1/guardrails", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if mcpGuardrails == nil {
			writeBytes(w, []byte(`{"error": "guardrails not active (run with --embedded-mcp)"}`))
			return
		}
		stats := mcpGuardrails.Stats()
		data, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"data":    stats,
		})
		writeBytes(w, data)
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
		writeBytes(w, data)
	}))

	// SIEM status endpoint — shows dispatcher stats and platform config.
	// Requires authentication (dashboard mux, not proxy mux).
	dashMux.HandleFunc("/api/v1/siem/status", authMiddleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		siemStatus := map[string]interface{}{
			"enabled": siemEnabledFlag,
		}
		if siemDisp != nil {
			stats := siemDisp.Stats()
			siemStatus["healthy"] = true
			siemStatus["dispatcher"] = map[string]interface{}{
				"events_polled":    stats.EventsPolled,
				"events_forwarded": stats.EventsForwarded,
				"events_dropped":   stats.EventsDropped,
				"errors":           stats.Errors,
				"last_poll_time":   stats.LastPollTime.Format(time.RFC3339),
			}
		} else {
			siemStatus["healthy"] = false
			siemStatus["dispatcher"] = nil
		}
		if siemMgr != nil {
			siemStatus["platforms"] = siemPlatformCount
			platformList := make([]map[string]interface{}, 0, len(cfg.SIEM.Platforms))
			for _, p := range cfg.SIEM.Platforms {
				platformList = append(platformList, map[string]interface{}{
					"platform": string(p.Platform),
					"enabled":  p.Enabled,
					"format":   string(p.Format),
					"endpoint": p.Endpoint,
				})
			}
			siemStatus["platform_list"] = platformList
		} else {
			siemStatus["platforms"] = 0
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"siem": siemStatus,
		})
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
		writeBytes(w, data)
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
	log.Printf("  A2A:      %s (mTLS + HMAC + capability enforcement)", func() string {
		if a2aMiddleware != nil {
			return "active"
		}
		return "disabled"
	}())
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
// codeql[go/bad-redirect-check] — false positive: all bypass vectors are explicitly handled below.
func isSafeRedirectURL(rawURL string, r *http.Request) bool {
	// Block backslash-based bypass (e.g., "/\evil.com", "\\evil.com")
	if strings.Contains(rawURL, "\\") {
		return false
	}

	// Parse the URL to inspect its structure — never trust prefix checks alone
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Block any URL with a scheme (e.g., "https://evil.com")
	if u.Scheme != "" {
		return false
	}

	// Block any URL with a host — only hostless (relative) URLs are safe
	if u.Host != "" && u.Host != r.Host {
		return false
	}

	// At this point the URL is either:
	// 1. Same-origin (host matches r.Host) — safe
	// 2. Relative path with no host (e.g., "/ui/", "/dashboard") — safe
	return true
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
		_ = conn.Close()
		log.Printf("[STARTUP-CONFIRM] Port %d ready", port)
	}
	return nil
}

// sanitizeForLog strips newlines and control characters
// from a string before it's used in a log message. This
// prevents log injection (G706) when the string contains
// user-controlled values (e.g., peer URLs in error
// messages). ASCII printable characters and common
// Unicode are preserved.
func sanitizeForLog(s string) string {
	// G706 (CodeQL): use strings.ReplaceAll on the
	// known log-injection characters. CodeQL's taint
	// analysis recognizes strings.ReplaceAll as a
	// sanitizer; the manual byte-by-byte loop below
	// (the per-character control-stripping) is the
	// defense-in-depth check that strips additional
	// control characters (0x00-0x1F, 0x7F).
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x20, r == 0x7f:
			// Skip other control characters.
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncateDBURL masks the password in a PostgreSQL connection URL for logging.
// postgres://user:secret@host:5432/db → postgres://user:***@host:5432/db
func truncateDBURL(dbURL string) string {
	u, err := url.Parse(dbURL)
	if err != nil {
		return "***"
	}
	if u.User != nil {
		_, hasPassword := u.User.Password()
		if hasPassword {
			u.User = url.UserPassword(u.User.Username(), "***")
		}
	}
	return u.String()
}
