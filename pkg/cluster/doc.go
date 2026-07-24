// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Clustering Support (v3.4.1)
// =========================================================================
//
// The cluster package provides horizontal scaling primitives for running
// 3-5 AegisGate instances behind a load balancer (round-robin or
// least-connections).
//
// Architecture:
//
//	┌─────────────┐
//	│ Load Balancer │
//	└──────┬──────┘
//	          │
//	┌────────┼────────┐
//	│        │        │
//	AegisGate AegisGate AegisGate
//	Node 1    Node 2    Node 3
//	└────────┼────────┘
//	         │
//	┌────────┴────────┐
//	│   PostgreSQL     │
//	└─────────────────┘
//
// Components:
//
//   - DistributedRateLimiter: Coordinates rate limiting across instances
//     using PostgreSQL as the shared counter backend. Falls back to
//     per-node token buckets when PostgreSQL is unavailable.
//
//   - NodeInfo: Identifies the current instance in a cluster. Embedded
//     in health check responses and audit events for traceability.
//
//   - ClusterHealth: Aggregates health status from all cluster nodes
//     via the /api/v1/cluster/health endpoint.
//
//   - SessionAffinity: Middleware that sets X-Instance-Id headers so
//     load balancers can implement sticky routing for MCP connections.
//
// Tier gating:
//
//   - Community: Per-node rate limiting, no shared state. Acceptable for
//     small deployments where the LB handles global rate limiting.
//   - Professional+: PostgreSQL-backed distributed rate limiting, shared
//     RBAC sessions, shared IOC store, shared audit logs.
//
// v3.4.1 clustering support.
// =========================================================================
package cluster