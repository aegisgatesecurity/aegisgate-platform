// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package maintenance provides maintenance window control for the
// AegisGate Security Platform.
//
// When a maintenance window is active, the middleware returns HTTP 503
// (Service Unavailable) with a Retry-After header for all non-exempt
// requests. This allows operators to perform upgrades, database
// migrations, or configuration changes without accepting user traffic.
//
// The State struct supports:
//   - Enable/Disable: Manual toggle with reason tracking
//   - Schedule: Time-bounded windows with automatic expiry
//   - Custom message and Retry-After seconds
//   - Status query for health endpoints and dashboards
//
// Maintenance state is in-memory and per-instance. In clustered
// deployments, each node maintains its own state — operators should
// enable maintenance on all nodes via the API or CLI.
//
// Exposed via HTTP at /api/v1/maintenance and the `aegisgate maintenance`
// CLI subcommand.
// =========================================================================
package maintenance
