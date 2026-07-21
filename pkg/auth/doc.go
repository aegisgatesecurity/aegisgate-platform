// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Authentication Middleware
// =========================================================================
//
// Provides JWT, API token, and SSO authentication for dashboard API
// endpoints. Three-tier auth:
//
//   1. SSO (OIDC/OAuth2) Bearer token  - if SSO is configured
//   2. Bearer JWT for user sessions     - if SSO is not configured
//   3. X-API-Token for service auth     - service-to-service calls
//
// Security-first defaults (v1.3.6+):
//   - REQUIRE_AUTH defaults to TRUE in production
//   - FAIL-CLOSED: if SSO is the only configured auth and SSO fails,
//     requests are denied (no silent cascade to dev-key JWT)
//   - Constant-time token comparison (prevents timing attacks)
//   - Base64 token support for env-var-encoded tokens
//
// Related packages:
//   - pkg/rbac:    role-based access control (used by RequireRole/RequirePermission)
//   - pkg/sso:     SSO/OIDC/SAML provider integration
//   - pkg/license: license-key authentication (for license-gated endpoints)
//
// =========================================================================

package auth
