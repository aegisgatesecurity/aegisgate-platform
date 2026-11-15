// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Subscription Tier Definitions
// =========================================================================
//
// Defines the 4 subscription tiers and their associated features, rate
// limits, and module ownership.
//
// Mandate Compliance:
//   - MITRE ATLAS and NIST AI RMF are Community-tier features (non-negotiable)
//   - Built-in CA, i18n, SBOM tracking are Community-tier features
//   - Community gets unlimited proxy/MCP RPM (soft-throttle policy), 7-day log retention
//   - RateLimit() is deprecated; use RateLimitProxy()/RateLimitMCP()
//     (see plans/TECHNICAL-DEBT.md — removal target v3.7.0, Q1 2027)
//   - Starter tier was removed in v3.5.0 (footgun: customers could buy Starter
//     but ParseTier would reject "starter", silently falling back
//     to Community). Developer is now the first non-Community tier.
//
// Soft-Throttle Policy (v3.5.0+):
//   AegisGate is a self-hosted security layer. The vendor's cost is zero
//   per free-tier user. Therefore, the security layer NEVER hard-blocks
//   a request for hitting a rate limit; it deprioritizes the request
//   instead. This is enforced in the proxy middleware (pkg/proxy) by
//   mapping RateLimitProxy() and RateLimitMCP() to soft-throttle weights,
//   not hard cutoffs.
//
//   A request that exceeds the soft-throttle threshold is still processed
//   and counted against the customer's quota, but is deprioritized in the
//   proxy request queue (e.g. served from a lower-priority worker pool).
//
// Tiers:
//   Community    Free      7d retention
//   Developer              30d retention, IOC store, basic compliance modules
//   Professional           90d retention, PostgreSQL, advanced compliance, IOC federation
//   Enterprise             unlimited, air-gapped, HSM, custom
//
// =========================================================================

package tier
