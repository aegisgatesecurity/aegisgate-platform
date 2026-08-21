// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Deploy Profiles
// =========================================================================
//
// Predefined configuration profiles for common deployment scenarios.
// Each profile returns a fully-populated *platformconfig.Config that can
// be used as-is or overridden by a config file, env vars, or CLI flags.
//
// Profiles eliminate the need to hand-craft a YAML file for common
// use cases. Use --profile <name> on the CLI to select one.
//
// Precedence: CLI flags > env vars > config file (--config) > profile (--profile) > defaults
//
// Available profiles:
//   quickstart    — zero-config trial, no TLS, low limits, auto-certs ready
//   small-team    — 5-50 users, TLS auto-gen, file persistence, moderate limits
//   production    — hardened production, TLS 1.3, detailed audit, CSRF on
//   high-security — enterprise-grade, mTLS, FIPS, strict headers, high limits
//   air-gapped    — no external connections, self-contained, IOC/SIEM off
//
// =========================================================================

package profiles

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/persistence"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/platformconfig"
)

// ProfileID identifies a deploy profile.
type ProfileID string

const (
	ProfileQuickstart   ProfileID = "quickstart"
	ProfileSmallTeam    ProfileID = "small-team"
	ProfileProduction   ProfileID = "production"
	ProfileHighSecurity ProfileID = "high-security"
	ProfileAirGapped    ProfileID = "air-gapped"
)

// Profile describes a deploy profile.
type Profile struct {
	ID          ProfileID
	Name        string
	Description string
	Tier        string // suggested tier: community, developer, professional, enterprise
}

// Profiles is the registry of all available profiles.
var registry = map[ProfileID]Profile{
	ProfileQuickstart: {
		ID:          ProfileQuickstart,
		Name:        "Quickstart",
		Description: "Zero-config trial. No TLS, low rate limits, auto-cert generation. Perfect for evaluating AegisGate in under 30 seconds.",
		Tier:        "community",
	},
	ProfileSmallTeam: {
		ID:          ProfileSmallTeam,
		Name:        "Small Team",
		Description: "5-50 users. TLS auto-generated, file-backed persistence, moderate rate limits. Good defaults for a small org or dev team.",
		Tier:        "community",
	},
	ProfileProduction: {
		ID:          ProfileProduction,
		Name:        "Production",
		Description: "Hardened production deployment. TLS 1.3 required, detailed audit logging, CSRF protection, higher rate limits. Bring your own certs.",
		Tier:        "developer",
	},
	ProfileHighSecurity: {
		ID:          ProfileHighSecurity,
		Name:        "High Security",
		Description: "Enterprise-grade. mTLS, FIPS 140-2, strict security headers, maximum audit retention, high throughput. For regulated environments.",
		Tier:        "enterprise",
	},
	ProfileAirGapped: {
		ID:          ProfileAirGapped,
		Name:        "Air-Gapped",
		Description: "Fully self-contained, no external connections. IOC sharing/receiving disabled, no SIEM forwarding, local persistence only. For isolated networks.",
		Tier:        "enterprise",
	},
}

// List returns all available profiles sorted by ID.
func List() []Profile {
	out := make([]Profile, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns the Profile metadata for the given ID.
// Returns false if the profile doesn't exist.
func Get(id ProfileID) (Profile, bool) {
	p, ok := registry[id]
	return p, ok
}

// IsValid checks whether a profile ID is recognized.
func IsValid(id string) bool {
	_, ok := registry[ProfileID(id)]
	return ok
}

// ConfigFor returns a fully-populated *platformconfig.Config for the
// given profile ID. The config can be used directly or further
// customized via config file, env vars, or CLI flags.
//
// Returns an error if the profile ID is not recognized.
func ConfigFor(id string) (*platformconfig.Config, error) {
	switch ProfileID(id) {
	case ProfileQuickstart:
		return quickstartConfig(), nil
	case ProfileSmallTeam:
		return smallTeamConfig(), nil
	case ProfileProduction:
		return productionConfig(), nil
	case ProfileHighSecurity:
		return highSecurityConfig(), nil
	case ProfileAirGapped:
		return airGappedConfig(), nil
	default:
		return nil, fmt.Errorf("unknown profile %q: valid profiles are %s", id, validProfileNames())
	}
}

// validProfileNames returns a comma-separated list of profile IDs for error messages.
// ValidNames returns a comma-separated list of valid profile names.
// This is the exported version of validProfileNames for API use.
func ValidNames() string {
	return validProfileNames()
}

func validProfileNames() string {
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}

// ---------------------------------------------------------------------------
// Profile configurations
// ---------------------------------------------------------------------------
// Each function returns a *platformconfig.Config tuned for its use case.
// All start from platformconfig.DefaultConfig() and override specific fields.

// quickstartConfig is the zero-config trial profile.
// Goals: fastest possible startup, no external dependencies, minimal resource usage.
func quickstartConfig() *platformconfig.Config {
	cfg := platformconfig.DefaultConfig()

	// Platform: standalone mode (embedded MCP)
	cfg.Platform.Mode = "standalone"
	cfg.Platform.ShutdownTimeout = 10 * time.Second

	// Proxy: low limits, info logging
	cfg.Proxy.BindAddress = ":8080"
	cfg.Proxy.Upstream = "https://api.openai.com"
	cfg.Proxy.RateLimit = 60 // 1 req/sec — enough for trial
	cfg.Proxy.MaxConns = 100
	cfg.Proxy.LogLevel = "info"

	// TLS: off (auto-gen ready if enabled later)
	cfg.TLS.Enabled = false
	cfg.TLS.AutoGenerate = true
	cfg.TLS.MinVersion = "1.2"

	// Dashboard: enabled, default port
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Port = 8443

	// Agent: minimal, quick timeouts
	cfg.Agent.Server.Port = 8081
	cfg.Agent.Server.ReadTimeout = 15 * time.Second
	cfg.Agent.Server.WriteTimeout = 15 * time.Second
	cfg.Agent.RateLimit.RequestsPerMinute = 30
	cfg.Agent.RateLimit.Burst = 10

	// Security: headers on, CSRF off (API-first for trial)
	cfg.Security.EnableSecurityHeaders = true
	cfg.Security.EnableCSRF = false
	cfg.Security.EnableAuditMiddleware = true

	// Persistence: file-backed, short retention (trial data is ephemeral)
	cfg.Persistence.Enabled = true
	cfg.Persistence.DataDir = "/data"
	cfg.Persistence.AuditDir = "/data/audit"
	cfg.Persistence.PruneInterval = 6 * time.Hour

	// Logging: info, json
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"

	// A2A/ACP/Trust: off (not needed for trial)
	cfg.A2A.Enabled = false
	cfg.ACP.Enabled = false
	cfg.Trust.Enabled = false

	return cfg
}

// smallTeamConfig is for 5-50 users in a small org or dev team.
// Goals: sensible defaults with TLS, moderate throughput, file persistence.
func smallTeamConfig() *platformconfig.Config {
	cfg := platformconfig.DefaultConfig()

	// Platform: standalone
	cfg.Platform.Mode = "standalone"
	cfg.Platform.ShutdownTimeout = 20 * time.Second

	// Proxy: moderate limits
	cfg.Proxy.BindAddress = ":8080"
	cfg.Proxy.Upstream = "https://api.openai.com"
	cfg.Proxy.RateLimit = 300 // 5 req/sec
	cfg.Proxy.MaxConns = 500
	cfg.Proxy.Timeout = 30 * time.Second
	cfg.Proxy.LogLevel = "info"

	// TLS: auto-generated self-signed (good enough for internal/small team)
	cfg.TLS.Enabled = false // user can enable with --tls or env var
	cfg.TLS.AutoGenerate = true
	cfg.TLS.MinVersion = "1.2"
	cfg.TLS.CertDir = "/data/certs"

	// Dashboard: enabled
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Port = 8443

	// Agent: moderate limits
	cfg.Agent.Server.Port = 8081
	cfg.Agent.Server.ReadTimeout = 30 * time.Second
	cfg.Agent.Server.WriteTimeout = 30 * time.Second
	cfg.Agent.RateLimit.RequestsPerMinute = 200
	cfg.Agent.RateLimit.Burst = 50

	// Security: headers + CSRF + audit
	cfg.Security.EnableSecurityHeaders = true
	cfg.Security.EnableCSRF = true
	cfg.Security.EnableXSS = true
	cfg.Security.EnableAuditMiddleware = true

	// Persistence: file-backed, daily pruning
	cfg.Persistence.Enabled = true
	cfg.Persistence.DataDir = "/data"
	cfg.Persistence.AuditDir = "/data/audit"
	cfg.Persistence.PruneInterval = 24 * time.Hour
	cfg.Persistence.MaxFileSize = 50 * 1024 * 1024

	// Logging: info, json
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"

	// A2A/ACP: available but off by default
	cfg.A2A.Enabled = false
	cfg.ACP.Enabled = false
	cfg.Trust.Enabled = false

	return cfg
}

// productionConfig is a hardened production deployment.
// Goals: TLS required, detailed audit, CSRF, higher throughput, production-grade timeouts.
func productionConfig() *platformconfig.Config {
	cfg := platformconfig.DefaultConfig()

	// Platform: standalone (or connected if external scanner deployed)
	cfg.Platform.Mode = "standalone"
	cfg.Platform.ShutdownTimeout = 30 * time.Second

	// Proxy: production-grade
	cfg.Proxy.BindAddress = ":8080"
	cfg.Proxy.Upstream = "https://api.openai.com"
	cfg.Proxy.RateLimit = 1000
	cfg.Proxy.MaxConns = 2000
	cfg.Proxy.MaxBodySize = 20 * 1024 * 1024 // 20 MB
	cfg.Proxy.Timeout = 60 * time.Second
	cfg.Proxy.LogLevel = "info"
	cfg.Proxy.CertDir = "/data/certs"

	// TLS: enabled, modern protocol
	cfg.TLS.Enabled = true
	cfg.TLS.AutoGenerate = false // bring your own certs in production
	cfg.TLS.MinVersion = "1.3"
	cfg.TLS.CertDir = "/data/certs"
	cfg.TLS.MutualTLS.Enabled = false
	cfg.TLS.MutualTLS.Mode = "optional"

	// Dashboard: enabled
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Port = 8443

	// Agent: production limits
	cfg.Agent.Server.Port = 8081
	cfg.Agent.Server.ReadTimeout = 30 * time.Second
	cfg.Agent.Server.WriteTimeout = 30 * time.Second
	cfg.Agent.Server.IdleTimeout = 5 * time.Minute
	cfg.Agent.RateLimit.RequestsPerMinute = 1000
	cfg.Agent.RateLimit.Burst = 200
	cfg.Agent.Audit.Enabled = true
	cfg.Agent.Audit.Format = "json"
	cfg.Agent.Logging.Level = "info"
	cfg.Agent.Logging.Format = "json"

	// Security: all protections on
	cfg.Security.EnableSecurityHeaders = true
	cfg.Security.EnableCSRF = true
	cfg.Security.EnableXSS = true
	cfg.Security.EnablePanicRecovery = true
	cfg.Security.EnableAuditMiddleware = true
	cfg.Security.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	cfg.Security.AllowedHeaders = []string{"Content-Type", "Authorization", "X-API-Key", "X-CSRF-Token"}

	// Persistence: file-backed, generous retention
	cfg.Persistence.Enabled = true
	cfg.Persistence.DataDir = "/data"
	cfg.Persistence.AuditDir = "/data/audit"
	cfg.Persistence.PruneInterval = 24 * time.Hour
	cfg.Persistence.MaxFileSize = 100 * 1024 * 1024 // 100 MB

	// Logging: info, json (structured for log aggregation)
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"

	// A2A/ACP: enabled for production agent deployments
	cfg.A2A.Enabled = true
	cfg.A2A.ConfigFile = "configs/a2a.yaml"
	cfg.A2A.CapsFile = "configs/a2a_caps.yaml"
	cfg.ACP.Enabled = true
	cfg.ACP.ConfigFile = "configs/acp.yaml"

	// Trust: available (requires Professional+ license)
	cfg.Trust.Enabled = false
	cfg.Trust.RequireLicense = true

	// SIEM: ready but off by default (enable via env or config)
	cfg.SIEM.Enabled = false
	cfg.SIEM.BatchSize = 200
	cfg.SIEM.BufferMaxSize = 50000

	return cfg
}

// highSecurityConfig is enterprise-grade for regulated environments.
// Goals: mTLS, FIPS, strict headers, maximum audit, high throughput.
func highSecurityConfig() *platformconfig.Config {
	cfg := platformconfig.DefaultConfig()

	// Platform: standalone
	cfg.Platform.Mode = "standalone"
	cfg.Platform.ShutdownTimeout = 60 * time.Second

	// Proxy: enterprise-grade
	cfg.Proxy.BindAddress = ":8080"
	cfg.Proxy.Upstream = "https://api.openai.com"
	cfg.Proxy.RateLimit = 5000
	cfg.Proxy.MaxConns = 5000
	cfg.Proxy.MaxBodySize = 50 * 1024 * 1024 // 50 MB
	cfg.Proxy.Timeout = 90 * time.Second
	cfg.Proxy.LogLevel = "info" // info in prod; debug only on demand
	cfg.Proxy.CertDir = "/data/certs"

	// TLS: enabled, mTLS, FIPS
	cfg.TLS.Enabled = true
	cfg.TLS.AutoGenerate = false // external CA required
	cfg.TLS.MinVersion = "1.3"
	cfg.TLS.CertDir = "/data/certs"
	cfg.TLS.MutualTLS.Enabled = true
	cfg.TLS.MutualTLS.Mode = "required" // require client certs
	cfg.TLS.FIPS.Enabled = true
	cfg.TLS.FIPS.Level = "140-2"

	// Dashboard: enabled, behind TLS
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Port = 8443

	// Agent: enterprise limits
	cfg.Agent.Server.Port = 8081
	cfg.Agent.Server.ReadTimeout = 60 * time.Second
	cfg.Agent.Server.WriteTimeout = 60 * time.Second
	cfg.Agent.Server.IdleTimeout = 10 * time.Minute
	cfg.Agent.RateLimit.RequestsPerMinute = 2000
	cfg.Agent.RateLimit.Burst = 500
	cfg.Agent.Audit.Enabled = true
	cfg.Agent.Audit.Format = "json"
	cfg.Agent.Logging.Level = "info"
	cfg.Agent.Logging.Format = "json"

	// Security: maximum protection
	cfg.Security.EnableSecurityHeaders = true
	cfg.Security.EnableCSRF = true
	cfg.Security.EnableXSS = true
	cfg.Security.EnablePanicRecovery = true
	cfg.Security.EnableAuditMiddleware = true
	cfg.Security.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	cfg.Security.AllowedHeaders = []string{"Content-Type", "Authorization", "X-API-Key", "X-CSRF-Token"}
	cfg.Security.MLThreatDetectionEnabled = false // enable after shadow validation
	cfg.Security.MLShadowMode = true

	// Persistence: file-backed, large retention
	cfg.Persistence.Enabled = true
	cfg.Persistence.DataDir = "/data"
	cfg.Persistence.AuditDir = "/data/audit"
	cfg.Persistence.PruneInterval = 24 * time.Hour
	cfg.Persistence.MaxFileSize = 200 * 1024 * 1024 // 200 MB

	// Logging: info, json
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"

	// A2A/ACP: enabled
	cfg.A2A.Enabled = true
	cfg.A2A.ConfigFile = "configs/a2a.yaml"
	cfg.A2A.CapsFile = "configs/a2a_caps.yaml"
	cfg.ACP.Enabled = true
	cfg.ACP.ConfigFile = "configs/acp.yaml"

	// Trust: enabled (requires enterprise license)
	cfg.Trust.Enabled = true
	cfg.Trust.RequireLicense = true

	// SIEM: enabled for enterprise
	cfg.SIEM.Enabled = true
	cfg.SIEM.BatchSize = 500
	cfg.SIEM.BufferMaxSize = 100000
	cfg.SIEM.PollInterval = 2 * time.Second

	return cfg
}

// airGappedConfig is for isolated networks with no external connectivity.
// Goals: fully self-contained, no phone-home, no IOC sharing, local-only persistence.
func airGappedConfig() *platformconfig.Config {
	cfg := platformconfig.DefaultConfig()

	// Platform: standalone
	cfg.Platform.Mode = "standalone"
	cfg.Platform.ShutdownTimeout = 30 * time.Second

	// Proxy: moderate limits, local upstream (user must set)
	cfg.Proxy.BindAddress = ":8080"
	cfg.Proxy.Upstream = "http://localhost:11434" // default to local LLM (e.g., Ollama)
	cfg.Proxy.RateLimit = 500
	cfg.Proxy.MaxConns = 1000
	cfg.Proxy.MaxBodySize = 20 * 1024 * 1024
	cfg.Proxy.Timeout = 60 * time.Second
	cfg.Proxy.LogLevel = "info"
	cfg.Proxy.CertDir = "/data/certs"

	// TLS: enabled with auto-gen (no external CA available in air-gapped)
	cfg.TLS.Enabled = true
	cfg.TLS.AutoGenerate = true
	cfg.TLS.MinVersion = "1.3"
	cfg.TLS.CertDir = "/data/certs"
	cfg.TLS.MutualTLS.Enabled = false
	cfg.TLS.MutualTLS.Mode = "optional"
	cfg.TLS.FIPS.Enabled = true
	cfg.TLS.FIPS.Level = "140-2"

	// Dashboard: enabled, local only
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.BindAddr = "127.0.0.1" // local only
	cfg.Dashboard.Port = 8443

	// Agent: moderate limits
	cfg.Agent.Server.Port = 8081
	cfg.Agent.Server.ReadTimeout = 30 * time.Second
	cfg.Agent.Server.WriteTimeout = 30 * time.Second
	cfg.Agent.RateLimit.RequestsPerMinute = 500
	cfg.Agent.RateLimit.Burst = 100
	cfg.Agent.Audit.Enabled = true
	cfg.Agent.Audit.Format = "json"
	cfg.Agent.Logging.Level = "info"
	cfg.Agent.Logging.Format = "json"

	// Security: all protections on
	cfg.Security.EnableSecurityHeaders = true
	cfg.Security.EnableCSRF = true
	cfg.Security.EnableXSS = true
	cfg.Security.EnablePanicRecovery = true
	cfg.Security.EnableAuditMiddleware = true

	// Persistence: local file-backed, large retention
	cfg.Persistence = persistence.DefaultConfig()
	cfg.Persistence.Enabled = true
	cfg.Persistence.DataDir = "/data"
	cfg.Persistence.AuditDir = "/data/audit"
	cfg.Persistence.PruneInterval = 24 * time.Hour
	cfg.Persistence.MaxFileSize = 100 * 1024 * 1024

	// Logging: info, json (local only)
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"

	// A2A/ACP: enabled for internal agent deployments
	cfg.A2A.Enabled = true
	cfg.A2A.ConfigFile = "configs/a2a.yaml"
	cfg.A2A.CapsFile = "configs/a2a_caps.yaml"
	cfg.ACP.Enabled = true
	cfg.ACP.ConfigFile = "configs/acp.yaml"

	// Trust: enabled (local attestation, no external calls)
	cfg.Trust.Enabled = true
	cfg.Trust.RequireLicense = true

	// SIEM: off — no external SIEM in air-gapped env
	cfg.SIEM.Enabled = false

	// Note: IOC sharing/receiving is controlled via CLI flags (--ioc-share, --ioc-receive)
	// and defaults to off. In air-gapped mode, these should remain off.

	return cfg
}

// Summary returns a human-readable description of the profile and its key settings.
func Summary(id string) (string, error) {
	profile, ok := Get(ProfileID(id))
	if !ok {
		return "", fmt.Errorf("unknown profile %q: valid profiles are %s", id, validProfileNames())
	}

	cfg, err := ConfigFor(id)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Profile: %s (%s)\n", profile.Name, profile.ID))
	sb.WriteString(fmt.Sprintf("Tier:    %s\n", profile.Tier))
	sb.WriteString(fmt.Sprintf("Desc:    %s\n\n", profile.Description))
	sb.WriteString("Key Settings:\n")
	sb.WriteString(fmt.Sprintf("  Proxy:      %s, rate_limit=%d, timeout=%s\n", cfg.Proxy.BindAddress, cfg.Proxy.RateLimit, cfg.Proxy.Timeout))
	sb.WriteString(fmt.Sprintf("  TLS:        enabled=%v, min_version=%s, auto_generate=%v\n", cfg.TLS.Enabled, cfg.TLS.MinVersion, cfg.TLS.AutoGenerate))
	sb.WriteString(fmt.Sprintf("  mTLS:       enabled=%v, mode=%s\n", cfg.TLS.MutualTLS.Enabled, cfg.TLS.MutualTLS.Mode))
	sb.WriteString(fmt.Sprintf("  FIPS:       enabled=%v, level=%s\n", cfg.TLS.FIPS.Enabled, cfg.TLS.FIPS.Level))
	sb.WriteString(fmt.Sprintf("  Dashboard:  port=%d, bind=%s\n", cfg.Dashboard.Port, cfg.Dashboard.BindAddr))
	sb.WriteString(fmt.Sprintf("  MCP:        port=%d, rpm=%d\n", cfg.Agent.Server.Port, cfg.Agent.RateLimit.RequestsPerMinute))
	sb.WriteString(fmt.Sprintf("  Persistence: dir=%s, audit=%s\n", cfg.Persistence.DataDir, cfg.Persistence.AuditDir))
	sb.WriteString(fmt.Sprintf("  Security:   headers=%v, csrf=%v, xss=%v, audit=%v\n",
		cfg.Security.EnableSecurityHeaders, cfg.Security.EnableCSRF, cfg.Security.EnableXSS, cfg.Security.EnableAuditMiddleware))
	sb.WriteString(fmt.Sprintf("  A2A:        %v\n", cfg.A2A.Enabled))
	sb.WriteString(fmt.Sprintf("  ACP:        %v\n", cfg.ACP.Enabled))
	sb.WriteString(fmt.Sprintf("  Trust:      %v\n", cfg.Trust.Enabled))
	sb.WriteString(fmt.Sprintf("  SIEM:       %v\n", cfg.SIEM.Enabled))

	return sb.String(), nil
}
