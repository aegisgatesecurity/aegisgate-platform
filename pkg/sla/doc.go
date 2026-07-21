// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SLA (Service Level Agreement) Definitions
// =========================================================================
//
// Per-tier service level objectives. Drives:
//   - The customer-portal SLA display (cmd/customer-portal/)
//   - The /api/v1/sla endpoint (pkg/api/server.go)
//   - The weekly uptime report (pkg/reporting/)
//
// Components:
//   - sla.go:              SLADefinition, SLO, per-tier SLA matrix
//
// Per-Tier SLA (locked 2026-06-04):
//
//   Tier          Uptime    Support Response  Data Retention
//   Community     99.0%     best-effort       7 days
//   Developer     99.5%     48 hours          30 days
//   Professional  99.9%     4 hours           90 days
//   Enterprise    99.99%    1 hour            unlimited
//
// SLO definitions use 30-day rolling windows by default:
//   - api_availability:    successful_requests / total_requests
//   - scan_latency_p99:    99th-percentile scan response time
//   - mcp_availability:    MCP session success rate
//
// Tier gating: SLA definitions are public (no auth). Per-customer SLA
// reporting requires the customer to own the corresponding tier.
//
// =========================================================================

package sla
