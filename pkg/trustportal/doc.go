// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Trust Portal (v3.x close-out, Work Item 12)
// =========================================================================
//
// The trust portal is the public, no-auth, customer-facing view of
// AegisGate's live compliance posture. It is served from the platform
// itself at GET /trust, with three JSON endpoints for the page to
// fetch (GET /trust/api/posture, /trust/api/frameworks, /trust/api/uptime).
//
// Design rationale (see plans/TRUST-PORTAL-DESIGN.md for the full doc):
//   - Serve from the platform itself (not a separate static site).
//     Zero new infrastructure, $0 cost, always live data.
//   - 4 routes, all unauthenticated. This is a public marketing/operational
//     page; the data shown is AegisGate's own posture, not customer data.
//   - 60s in-memory cache for the JSON endpoints. The page polls every
//     60s, so the cache serves the same data to all pollers for a minute.
//   - No auth middleware on these routes (the opposite of every other
//     /api/v1/* route in the platform).
//
// v1 scope:
//   - Show overall posture (healthy/degraded/unhealthy)
//   - Show framework coverage table (15 frameworks + Tier 1 status)
//   - Show last-updated timestamp (auto-refreshes every 60s)
//   - Show uptime badge (last 90 days, 1h cache)
//
// Out of scope (v2):
//   - Per-customer data (AegisGate is single-tenant in v3.x)
//   - PDF download (already at /api/v1/reports/pdf, can be linked later)
//   - Multi-region / multi-instance
//
// Architecture:
//   - cache.go: 60s in-memory cache (one per endpoint)
//   - data.go:  adapters over pkg/posture and pkg/compliance
//   - portal.go: 4 HTTP handlers
//   - portal_test.go: handler tests
//
// The wire function in cmd/aegisgate-platform/trust_portal_http.go
// follows the same pattern as wirePostureHandlers / wireAttestationHandlers:
// one package-level var for the source data, the wire function mounts
// the routes with no auth middleware.
// =========================================================================

package trustportal
