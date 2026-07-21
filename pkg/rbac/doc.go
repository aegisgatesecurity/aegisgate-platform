// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Role-Based Access Control (RBAC)
// =========================================================================
//
// Role-Based Access Control Manager for agents and users. Provides
// session-aware authorization, agent management, and permission checking.
//
// Components:
//   - manager.go:           in-memory RBAC Manager (Community, Developer tiers)
//   - postgres_store.go:    PostgreSQL-backed RBAC store (Professional+ tier, D1 Phase 1C)
//   - middleware.go:        HTTP middleware (RequireRole, RequirePermission, RequireToolPermission)
//
// User Roles (locked 2026-05-25, plans/03-commercial-launch-checklist.md):
//   - viewer:  read-only access to dashboard + scan history
//   - analyst:  + trigger scans, view IOC store, view audit log
//   - operator: + manage agents, manage scan policies
//   - admin:   + manage users, manage license, manage platform config
//
// The middleware suite supports:
//   - RequireRole:          enforces minimum role level (403 on insufficient role)
//   - RequirePermission:    gates access by specific permission (403 if missing)
//   - RequireToolPermission: gates tool execution permissions (for MCP agents)
//   - InjectRBACContext:    reads session ID from request context and injects
//                           the Manager and session for downstream handlers
//
// Multi-tenant isolation (D11): RBACTenantContext wraps the Manager
// to enforce tenant filtering on all agent/session CRUD operations.
// IsAdmin: true bypasses filtering (for cross-tenant dashboards).
//
// Tier gating:
//   - In-memory Manager:  all tiers
//   - PostgreSQL store:   Professional+ (FeaturePostgreSQL required)
//
// =========================================================================

package rbac
