// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Unified Platform Configuration
// =========================================================================
//
// Platform-wide configuration that composes the AegisGate and AegisGuard
// upstream config systems into a single YAML-loadable structure.
//
// Design principle: One config file to rule them all. The platform
// operator sets config once in configs/aegisgate-platform.yaml, and
// it propagates to both AegisGate (proxy, TLS, security, ML) and
// AegisGuard (MCP, RBAC, audit, policies) subsystems.
//
// Sub-configs (one YAML block each):
//   - platform:         platform-level settings (mode, shutdown timeout)
//   - proxy:            AegisGate proxy (bind_address, upstream, rate limit)
//   - agent:            AegisGuard agent/MCP server
//   - dashboard:        admin UI + API server
//   - tls:              TLS for all listeners (cert, mTLS, FIPS)
//   - security:         security middleware (CSRF, XSS, audit, CORS)
//   - logging:          structured logging (level, format)
//   - a2a:              A2A guardrails (enabled, config file)
//   - acp:              ACP guardrails (enabled, config file)
//   - trust:            Trust Framework (enabled, require_license)
//   - persistence:      audit storage (data_dir, retention)
//   - siem:             SIEM dispatcher (enabled, platforms, batch)
//
// Config-loading features:
//   - Default config:   DefaultConfig() returns a fully-populated Config
//   - YAML loading:     LoadFromFile() reads + validates a yaml file
//   - Legacy key translation: translateLegacyConfigKeys() converts
//     deprecated v3.1.0-era keys (server.*, scanner.*, etc.) to the
//     canonical yaml tags, with a deprecation warning on stderr
//   - Env overrides:    applyEnvOverrides() applies AEGISGATE_* env
//                       vars on top of the yaml (env > yaml > defaults)
//
// See configs/aegisgate-platform.yaml for the canonical schema with
// all fields documented inline. Plans/legacy-keys section at the
// bottom of the yaml shows the deprecated keys and their replacements.
//
// =========================================================================

package platformconfig
