// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Config Validation
// =========================================================================
//
// Validates a platformconfig.Config for common deployment errors before
// the platform starts. Used by the `aegisgate config validate` subcommand
// and by the setup wizard.
//
// Validation checks:
//   - Port conflicts (proxy, MCP, dashboard must be distinct)
//   - TLS cert paths exist when TLS is enabled without auto-generate
//   - Required fields are non-empty (upstream, bind addresses)
//   - Log level and format are recognized values
//   - TLS min version is 1.2 or 1.3
//   - FIPS level is 140-2 or 140-3
//   - mTLS mode is "optional" or "required"
//   - A2A/ACP config file paths exist when those subsystems are enabled
//   - SIEM platform entries have endpoints when enabled
//   - Rate limits and buffer sizes are positive
//   - Persistence data dir is non-empty
//
// Each check returns a ValidationWarning (non-fatal) or ValidationError
// (fatal — the config will likely cause a startup failure). The caller
// decides whether to proceed with warnings.
//
// =========================================================================

package platformconfig

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ValidationSeverity classifies a validation finding.
type ValidationSeverity string

const (
	SeverityError   ValidationSeverity = "error"
	SeverityWarning ValidationSeverity = "warning"
)

// ValidationFinding represents a single validation check result.
type ValidationFinding struct {
	Severity   ValidationSeverity
	Field      string // dotted path, e.g. "tls.cert_file"
	Message    string
	Suggestion string
}

// ValidationResult holds all findings from a validation run.
type ValidationResult struct {
	Findings []ValidationFinding
}

// HasErrors returns true if any finding has severity "error".
func (r *ValidationResult) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// HasWarnings returns true if any finding has severity "warning".
func (r *ValidationResult) HasWarnings() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

// Errors returns only the error-severity findings.
func (r *ValidationResult) Errors() []ValidationFinding {
	var errs []ValidationFinding
	for _, f := range r.Findings {
		if f.Severity == SeverityError {
			errs = append(errs, f)
		}
	}
	return errs
}

// Warnings returns only the warning-severity findings.
func (r *ValidationResult) Warnings() []ValidationFinding {
	var warns []ValidationFinding
	for _, f := range r.Findings {
		if f.Severity == SeverityWarning {
			warns = append(warns, f)
		}
	}
	return warns
}

// Summary returns a human-readable summary of the validation result.
func (r *ValidationResult) Summary() string {
	var sb strings.Builder
	errCount := len(r.Errors())
	warnCount := len(r.Warnings())

	if errCount == 0 && warnCount == 0 {
		sb.WriteString("✅ Config validation passed — no errors or warnings.\n")
		return sb.String()
	}

	if errCount > 0 {
		sb.WriteString(fmt.Sprintf("❌ %d error(s):\n", errCount))
		for _, e := range r.Errors() {
			sb.WriteString(fmt.Sprintf("   [%s] %s: %s\n", e.Severity, e.Field, e.Message))
			if e.Suggestion != "" {
				sb.WriteString(fmt.Sprintf("        → %s\n", e.Suggestion))
			}
		}
	}

	if warnCount > 0 {
		if errCount > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("⚠️  %d warning(s):\n", warnCount))
		for _, w := range r.Warnings() {
			sb.WriteString(fmt.Sprintf("   [%s] %s: %s\n", w.Severity, w.Field, w.Message))
			if w.Suggestion != "" {
				sb.WriteString(fmt.Sprintf("        → %s\n", w.Suggestion))
			}
		}
	}

	return sb.String()
}

// Validate checks a Config for common deployment errors and misconfigurations.
// It returns a ValidationResult containing all findings (errors and warnings).
// This is non-destructive — it does not modify the config.
//
// File-existence checks (cert paths, config file paths) are only performed
// when the paths are non-empty. This allows validation of configs that will
// have paths injected at runtime via env vars or volume mounts.
func (c *Config) Validate() *ValidationResult {
	result := &ValidationResult{}

	// ── Port conflict checks ──────────────────────────────────────
	proxyPort := c.ProxyPort()
	mcpPort := c.MCPPort()
	dashPort := c.Dashboard.Port

	if proxyPort == mcpPort {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityError,
			Field:      "proxy.bind_address / agent.server.port",
			Message:    fmt.Sprintf("Proxy port (%d) and MCP port (%d) conflict — they must be different", proxyPort, mcpPort),
			Suggestion: "Set agent.server.port to a different port (e.g. 8081 if proxy is 8080)",
		})
	}
	if proxyPort == dashPort {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityError,
			Field:      "proxy.bind_address / dashboard.port",
			Message:    fmt.Sprintf("Proxy port (%d) and Dashboard port (%d) conflict — they must be different", proxyPort, dashPort),
			Suggestion: "Set dashboard.port to a different port (e.g. 8443 if proxy is 8080)",
		})
	}
	if mcpPort == dashPort {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityError,
			Field:      "agent.server.port / dashboard.port",
			Message:    fmt.Sprintf("MCP port (%d) and Dashboard port (%d) conflict — they must be different", mcpPort, dashPort),
			Suggestion: "Set dashboard.port to a different port (e.g. 8443 if MCP is 8081)",
		})
	}

	// ── Required field checks ─────────────────────────────────────
	if c.Proxy.BindAddress == "" {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityError,
			Field:      "proxy.bind_address",
			Message:    "Proxy bind address is empty",
			Suggestion: "Set proxy.bind_address (e.g. \"0.0.0.0:8080\")",
		})
	}
	if c.Proxy.Upstream == "" {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityError,
			Field:      "proxy.upstream",
			Message:    "Proxy upstream URL is empty — the proxy has no target to forward to",
			Suggestion: "Set proxy.upstream (e.g. \"https://api.openai.com\")",
		})
	}
	if c.Dashboard.Enabled && c.Dashboard.BindAddr == "" {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityWarning,
			Field:      "dashboard.bind_addr",
			Message:    "Dashboard is enabled but bind_addr is empty — will default to 0.0.0.0",
			Suggestion: "Set dashboard.bind_addr explicitly (e.g. \"0.0.0.0\" or \"127.0.0.1\")",
		})
	}

	// ── Rate limit checks ─────────────────────────────────────────
	if c.Proxy.RateLimit < 0 {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityError,
			Field:      "proxy.rate_limit",
			Message:    fmt.Sprintf("Proxy rate limit is negative (%d) — must be 0 (unlimited) or positive", c.Proxy.RateLimit),
			Suggestion: "Set proxy.rate_limit to 0 for unlimited, or a positive number (e.g. 1000)",
		})
	}
	if c.Agent.RateLimit.Enabled && c.Agent.RateLimit.RequestsPerMinute <= 0 {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityError,
			Field:      "agent.rate_limit.requests_per_minute",
			Message:    fmt.Sprintf("Agent rate limit is enabled but requests_per_minute is %d — must be positive", c.Agent.RateLimit.RequestsPerMinute),
			Suggestion: "Set agent.rate_limit.requests_per_minute to a positive number (e.g. 100)",
		})
	}

	// ── TLS checks ────────────────────────────────────────────────
	if c.TLS.Enabled {
		if c.TLS.MinVersion != "" {
			switch c.TLS.MinVersion {
			case "1.2", "1.3":
				// valid
			default:
				result.Findings = append(result.Findings, ValidationFinding{
					Severity:   SeverityError,
					Field:      "tls.min_version",
					Message:    fmt.Sprintf("TLS min_version %q is not recognized — must be \"1.2\" or \"1.3\"", c.TLS.MinVersion),
					Suggestion: "Set tls.min_version to \"1.2\" or \"1.3\"",
				})
			}
		}

		if !c.TLS.AutoGenerate {
			// Cert files must be specified and exist
			if c.TLS.CertFile == "" {
				result.Findings = append(result.Findings, ValidationFinding{
					Severity:   SeverityError,
					Field:      "tls.cert_file",
					Message:    "TLS is enabled with auto_generate=false but cert_file is empty",
					Suggestion: "Set tls.cert_file to the path of your TLS certificate, or enable tls.auto_generate",
				})
			} else if _, err := os.Stat(c.TLS.CertFile); err != nil {
				result.Findings = append(result.Findings, ValidationFinding{
					Severity:   SeverityWarning,
					Field:      "tls.cert_file",
					Message:    fmt.Sprintf("TLS cert_file %q does not exist (will fail at startup if not mounted)", c.TLS.CertFile),
					Suggestion: "Ensure the certificate file is mounted at the configured path before starting the platform",
				})
			}

			if c.TLS.KeyFile == "" {
				result.Findings = append(result.Findings, ValidationFinding{
					Severity:   SeverityError,
					Field:      "tls.key_file",
					Message:    "TLS is enabled with auto_generate=false but key_file is empty",
					Suggestion: "Set tls.key_file to the path of your TLS private key, or enable tls.auto_generate",
				})
			} else if _, err := os.Stat(c.TLS.KeyFile); err != nil {
				result.Findings = append(result.Findings, ValidationFinding{
					Severity:   SeverityWarning,
					Field:      "tls.key_file",
					Message:    fmt.Sprintf("TLS key_file %q does not exist (will fail at startup if not mounted)", c.TLS.KeyFile),
					Suggestion: "Ensure the key file is mounted at the configured path before starting the platform",
				})
			}
		}
	}

	// ── mTLS checks ───────────────────────────────────────────────
	if c.TLS.MutualTLS.Enabled {
		switch c.TLS.MutualTLS.Mode {
		case "optional", "required":
			// valid
		case "":
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityWarning,
				Field:      "tls.mutual_tls.mode",
				Message:    "mTLS is enabled but mode is empty — defaults to \"optional\"",
				Suggestion: "Set tls.mutual_tls.mode to \"optional\" or \"required\"",
			})
		default:
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityError,
				Field:      "tls.mutual_tls.mode",
				Message:    fmt.Sprintf("mTLS mode %q is not recognized — must be \"optional\" or \"required\"", c.TLS.MutualTLS.Mode),
				Suggestion: "Set tls.mutual_tls.mode to \"optional\" or \"required\"",
			})
		}

		if c.TLS.MutualTLS.Mode == "required" && !c.TLS.Enabled {
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityError,
				Field:      "tls.mutual_tls.enabled / tls.enabled",
				Message:    "mTLS mode is \"required\" but TLS is not enabled — mTLS requires TLS to be active",
				Suggestion: "Set tls.enabled: true when using mTLS",
			})
		}
	}

	// ── FIPS checks ───────────────────────────────────────────────
	if c.TLS.FIPS.Enabled {
		switch c.TLS.FIPS.Level {
		case "140-2", "140-3":
			// valid
		case "":
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityWarning,
				Field:      "tls.fips.level",
				Message:    "FIPS is enabled but level is empty — defaults to \"140-2\"",
				Suggestion: "Set tls.fips.level to \"140-2\" or \"140-3\"",
			})
		default:
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityError,
				Field:      "tls.fips.level",
				Message:    fmt.Sprintf("FIPS level %q is not recognized — must be \"140-2\" or \"140-3\"", c.TLS.FIPS.Level),
				Suggestion: "Set tls.fips.level to \"140-2\" or \"140-3\"",
			})
		}
	}

	// ── Logging checks ────────────────────────────────────────────
	switch c.Logging.Level {
	case "debug", "info", "warn", "error", "":
		// valid (empty defaults to "info" at runtime)
	default:
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityError,
			Field:      "logging.level",
			Message:    fmt.Sprintf("Log level %q is not recognized — must be debug, info, warn, or error", c.Logging.Level),
			Suggestion: "Set logging.level to \"debug\", \"info\", \"warn\", or \"error\"",
		})
	}

	switch c.Logging.Format {
	case "json", "text", "":
		// valid (empty defaults to "json" at runtime)
	default:
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityError,
			Field:      "logging.format",
			Message:    fmt.Sprintf("Log format %q is not recognized — must be \"json\" or \"text\"", c.Logging.Format),
			Suggestion: "Set logging.format to \"json\" or \"text\"",
		})
	}

	// ── Platform mode check ───────────────────────────────────────
	switch c.Platform.Mode {
	case "standalone", "connected", "":
		// valid (empty defaults to "standalone")
	default:
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityWarning,
			Field:      "platform.mode",
			Message:    fmt.Sprintf("Platform mode %q is not recognized — should be \"standalone\" or \"connected\"", c.Platform.Mode),
			Suggestion: "Set platform.mode to \"standalone\" (embedded MCP) or \"connected\" (external scanner)",
		})
	}

	// ── A2A checks ────────────────────────────────────────────────
	if c.A2A.Enabled {
		if c.A2A.ConfigFile == "" {
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityWarning,
				Field:      "a2a.config_file",
				Message:    "A2A is enabled but config_file is empty — will use built-in defaults",
				Suggestion: "Set a2a.config_file (e.g. \"configs/a2a.yaml\")",
			})
		} else if _, err := os.Stat(c.A2A.ConfigFile); err != nil {
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityWarning,
				Field:      "a2a.config_file",
				Message:    fmt.Sprintf("A2A config_file %q does not exist — will use built-in defaults", c.A2A.ConfigFile),
				Suggestion: "Ensure the A2A config file is present, or disable a2a.enabled",
			})
		}
	}

	// ── ACP checks ────────────────────────────────────────────────
	if c.ACP.Enabled {
		if c.ACP.ConfigFile == "" {
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityWarning,
				Field:      "acp.config_file",
				Message:    "ACP is enabled but config_file is empty — will use built-in defaults",
				Suggestion: "Set acp.config_file (e.g. \"configs/acp.yaml\")",
			})
		} else if _, err := os.Stat(c.ACP.ConfigFile); err != nil {
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityWarning,
				Field:      "acp.config_file",
				Message:    fmt.Sprintf("ACP config_file %q does not exist — will use built-in defaults", c.ACP.ConfigFile),
				Suggestion: "Ensure the ACP config file is present, or disable acp.enabled",
			})
		}
	}

	// ── Trust checks ──────────────────────────────────────────────
	if c.Trust.Enabled && c.Trust.RequireLicense {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityWarning,
			Field:      "trust.require_license",
			Message:    "Trust Framework is enabled with require_license=true — requires Professional+ tier license",
			Suggestion: "Ensure a valid license key is set via --license or AEGISGATE_LICENSE_KEY",
		})
	}

	// ── Persistence checks ────────────────────────────────────────
	if c.Persistence.Enabled {
		if c.Persistence.DataDir == "" {
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityError,
				Field:      "persistence.data_dir",
				Message:    "Persistence is enabled but data_dir is empty — audit logs cannot be stored",
				Suggestion: "Set persistence.data_dir (e.g. \"/data\")",
			})
		}
		if c.Persistence.AuditDir == "" {
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityWarning,
				Field:      "persistence.audit_dir",
				Message:    "Persistence is enabled but audit_dir is empty — will default to <data_dir>/audit",
				Suggestion: "Set persistence.audit_dir explicitly (e.g. \"/data/audit\")",
			})
		}
	}

	// ── SIEM checks ───────────────────────────────────────────────
	if c.SIEM.Enabled {
		if c.SIEM.BatchSize <= 0 {
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityWarning,
				Field:      "siem.batch_size",
				Message:    fmt.Sprintf("SIEM is enabled but batch_size is %d — should be positive", c.SIEM.BatchSize),
				Suggestion: "Set siem.batch_size to a positive number (e.g. 100)",
			})
		}
		if c.SIEM.BufferMaxSize <= 0 {
			result.Findings = append(result.Findings, ValidationFinding{
				Severity:   SeverityWarning,
				Field:      "siem.buffer_max_size",
				Message:    fmt.Sprintf("SIEM is enabled but buffer_max_size is %d — should be positive", c.SIEM.BufferMaxSize),
				Suggestion: "Set siem.buffer_max_size to a positive number (e.g. 10000)",
			})
		}
		for i, p := range c.SIEM.Platforms {
			if p.Enabled && p.Endpoint == "" {
				result.Findings = append(result.Findings, ValidationFinding{
					Severity:   SeverityError,
					Field:      fmt.Sprintf("siem.platforms[%d].endpoint", i),
					Message:    fmt.Sprintf("SIEM platform %q (index %d) is enabled but has no endpoint", p.Platform, i),
					Suggestion: fmt.Sprintf("Set an endpoint URL for SIEM platform %q, or disable it", p.Platform),
				})
			}
		}
	}

	// ── ML checks ─────────────────────────────────────────────────
	if c.Security.MLThreatDetectionEnabled && !c.Security.MLShadowMode {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityWarning,
			Field:      "security.ml_threat_detection_enabled / security.ml_shadow_mode",
			Message:    "ML threat detection is enabled with shadow_mode=false — traffic will be blocked by the ML model",
			Suggestion: "Keep ml_shadow_mode=true until 7-day shadow validation confirms 0% FPR",
		})
	}

	// ── Shutdown timeout check ────────────────────────────────────
	if c.Platform.ShutdownTimeout > 0 && c.Platform.ShutdownTimeout < 5*time.Second {
		result.Findings = append(result.Findings, ValidationFinding{
			Severity:   SeverityWarning,
			Field:      "platform.shutdown_timeout",
			Message:    fmt.Sprintf("Shutdown timeout is %s — very short, may cause in-flight requests to be dropped", c.Platform.ShutdownTimeout),
			Suggestion: "Set platform.shutdown_timeout to at least 10s for production (30s recommended)",
		})
	}

	return result
}

// ValidateFile loads a config from the given path, applies env overrides,
// and validates it. Returns the validation result and any load error.
func ValidateFile(path string) (*ValidationResult, error) {
	cfg, err := LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	return cfg.Validate(), nil
}
