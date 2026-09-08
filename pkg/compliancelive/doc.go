// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package compliancelive provides live compliance scanning for the
// AegisGate Security Platform.
//
// The Scanner performs runtime checks against the platform's security
// configuration and operational state, producing a LiveScanReport with
// individual LiveCheckResult items for each control area:
//   - TLS configuration and certificate validity
//   - Authentication enforcement (SSO, session management)
//   - Audit logging completeness and integrity
//   - HTTP security headers (HSTS, CSP, X-Frame-Options)
//   - ML threat detection status (enabled, shadow mode, threshold)
//   - Rate limiting configuration
//
// The package bridges the platform config (pkg/platformconfig) with
// the compliance framework to provide real-time posture assessment
// for the /api/v1/compliance/live endpoint and CISO digest generation.
// =========================================================================
package compliancelive
