// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package profiles provides deploy profile presets for the AegisGate
// Security Platform.
//
// Profiles simplify initial deployment by bundling sensible defaults
// for common scenarios. Each profile produces a complete
// platformconfig.Config that can be further customized via config file
// or environment variables.
//
// Available profiles:
//   - quickstart:    Zero-config trial (no TLS, low limits)
//   - small-team:    5-50 users (auto-TLS, moderate limits)
//   - production:    Hardened production (TLS 1.3, CSRF, detailed audit)
//   - high-security: Enterprise-grade (mTLS, FIPS, SIEM, high throughput)
//   - air-gapped:    Isolated network (local upstream, no external calls)
//
// Usage: `aegisgate --profile <name>` or AEGISGATE_PROFILE env var.
// Use `aegisgate --profile list` to see all available profiles.
// =========================================================================
package profiles
