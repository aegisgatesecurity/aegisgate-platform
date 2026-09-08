// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package tenant provides multi-tenant management for the AegisGate
// Security Platform.
//
// The Handler exposes a REST API for CRUD operations on tenants:
//   - POST   /api/v1/tenants        — Create a new tenant
//   - GET    /api/v1/tenants        — List all tenants
//   - GET    /api/v1/tenants/{id}   — Get a specific tenant
//   - PUT    /api/v1/tenants/{id}   — Update tenant properties
//   - DELETE /api/v1/tenants/{id}   — Delete a tenant
//
// Each tenant has a name, display name, contact email, license tier,
// and limits (max users, max agents). The Store interface supports
// in-memory (default) and PostgreSQL (optional) backends. The Postgres
// manager wraps all pool access with ioc.WithTenantContextOrPool for
// RLS enforcement.
//
// Tenant context (tenant ID and admin flag) is propagated via
// pkg/ctxkeys through the auth middleware, enabling row-level security
// in all downstream Postgres stores.
// =========================================================================
package tenant
