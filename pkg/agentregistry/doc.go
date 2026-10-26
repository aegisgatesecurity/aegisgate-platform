// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Registry — unified AI agent lifecycle management (v5.0)
//

// Package agentregistry provides a unified, live inventory of AI agents
// across all AegisGate protocol layers (HTTP, MCP, A2A, ACP, ANP).
//
// The Registry is the central aggregator for AI agent identity, activity,
// and lifecycle state. It solves a problem that no existing tool — ITAM,
// IAM, secret managers, SOAR, or AIBOM — addresses: "Show me every AI
// agent in this environment, its credentials, its permissions, its last
// activity, its owner, and whether it's dormant."
//
// # Architecture
//
// The Registry is a glue layer, not a greenfield detection engine. It reads
// from six existing subsystems and unifies their data into AgentRecords:
//
//   - pkg/rbac/           — agent identity, role, tools, enabled status
//   - pkg/mcpserver/      — MCP session activity (CreatedAt, LastActivity)
//   - pkg/scanner/        — multi-turn session tracker (session timestamps)
//   - pkg/a2a/            — A2A agent identity via mTLS, capabilities
//   - pkg/aibom/          — static AI Bill of Materials for reconciliation
//   - pkg/correlation/    — cross-protocol events for activity tracking
//   - pkg/agentintentsign/— signed intent tuples for attestation
//
// # Lifecycle State Machine
//
// Each agent transitions through lifecycle states:
//
//	provisioned → active → dormant → quarantined → revoked
//
// The DormancyEngine evaluates activity timestamps against configurable
// thresholds. The PolicyEngine executes actions (notify, quarantine,
// revoke) when thresholds are crossed, using existing incident playbooks
// and SOAR integrations.
//
// # AIBOM Reconciliation
//
// The Registry reconciles the static AIBOM (CycloneDX AI Bill of Materials)
// against live runtime observations to detect drift:
//
//   - Agent in AIBOM but not active (declared but not running)
//   - Agent active but not in AIBOM (running but not declared)
//
// # Storage
//
// The Registry supports two storage backends:
//
//   - InMemoryStore — sync.RWMutex + map (default, no PostgreSQL needed)
//   - PostgresStore  — pgx/v5 with RLS-aware tenant isolation
//
// Both implement the Store interface, following the same pattern as
// pkg/rbac, pkg/correlation, and pkg/incident.
//
// # Tier Gating
//
// The entire feature is gated to Professional tier via
// tier.FeatureAgentRegistry. No Community or Developer access.
//
// # Air-Gap Compliance
//
// Zero external dependencies. All data sources are internal. PostgreSQL
// is optional with in-memory fallback. No network egress. No telemetry.
package agentregistry
