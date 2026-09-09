// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Stripe Billing Integration
// =========================================================================
//
// Wraps Stripe's Go SDK for the 4 tier subscriptions and 7 compliance
// modules. Used by the customer portal (cmd/customer-portal/) and the
// license activation webhook (pkg/license/).
//
// Mode:
//   - Mock mode:  default when STRIPE_SECRET_KEY is empty; no network calls
//   - Live mode:  when STRIPE_SECRET_KEY is set (sk_live_ prefix); makes
//                 real Stripe API calls. Stripe integration is LIVE as of
//                 v4.4.1 — billing-config.json contains live publishable
//                 keys and real Stripe product/price IDs.
//
// Pricing (locked 2026-06-04, plans/aegisgate-pricing-decisions-locked-2026-06-04):
//
//   Tier        Monthly   Annual
//   Community   Free      Free
//   Developer   $79/mo    $790/yr
//   Professional $499/mo  $4,990/yr
//   Enterprise  $2,000/mo $24,000/yr
//
// Compliance modules (add-ons, Professional+ required for most):
//   HIPAA, PCI-DSS, SOC 2, ISO 42001, FedRAMP, FIPS 140, EU AI Act.
//
// =========================================================================

package billing
