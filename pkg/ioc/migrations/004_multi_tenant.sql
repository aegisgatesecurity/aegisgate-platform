-- =========================================================================
-- AegisGate Platform — Multi-Tenant Isolation Schema (Migration 004)
-- =========================================================================
-- Adds tenant_id columns to all core tables for multi-tenant isolation.
-- This is required for Professional and Enterprise tiers to ensure
-- complete data isolation between tenants.
--
-- Part of D11: Multi-Tenant Isolation Verification.
-- Requires: 001_initial.sql, 002_audit.sql, 003_sessions.sql
-- =========================================================================

-- Add tenant_id to ioc_fingerprints table.
-- Default to empty string for backward compatibility with existing data.
-- Existing IOCs without tenant_id will be treated as tenant-agnostic
-- (accessible to all tenants until explicitly re-assigned).
ALTER TABLE ioc_fingerprints
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

-- Index for tenant-scoped IOC queries (Professional/Enterprise tier).
-- This is the primary isolation boundary: tenant A cannot see tenant B's IOCs.
CREATE INDEX IF NOT EXISTS idx_fingerprints_tenant
    ON ioc_fingerprints (tenant_id, last_seen DESC);

-- Composite index for tenant + provider + category (Lens multi-tenant queries).
CREATE INDEX IF NOT EXISTS idx_fingerprints_tenant_provider_category
    ON ioc_fingerprints (tenant_id, source_provider, category, last_seen DESC)
    WHERE source_provider != '';

-- Add tenant_id to ioc_events table.
-- Events inherit tenant_id from their parent fingerprint on insert.
ALTER TABLE ioc_events
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

-- Index for tenant-scoped event queries.
CREATE INDEX IF NOT EXISTS idx_events_tenant
    ON ioc_events (tenant_id, event_timestamp DESC);

-- Add tenant_id to rbac_agents table.
-- Agents are scoped to a specific tenant; cross-tenant agent access
-- is not permitted (each tenant manages their own agents).
ALTER TABLE rbac_agents
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

-- Index for tenant-scoped agent queries.
CREATE INDEX IF NOT EXISTS idx_rbac_agents_tenant
    ON rbac_agents (tenant_id, role, updated_at DESC);

-- Add tenant_id to rbac_agent_sessions table.
-- Sessions must belong to the same tenant as their agent.
-- This is enforced at the application layer (FK would be complex).
ALTER TABLE rbac_agent_sessions
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

-- Index for tenant-scoped session queries.
CREATE INDEX IF NOT EXISTS idx_rbac_agent_sessions_tenant
    ON rbac_agent_sessions (tenant_id, agent_id, expires_at DESC);

-- Add tenant_id to rbac_user_sessions table.
-- User sessions are scoped to a tenant; users may have sessions
-- in multiple tenants but each session is tenant-specific.
ALTER TABLE rbac_user_sessions
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

-- Index for tenant-scoped user session queries.
CREATE INDEX IF NOT EXISTS idx_rbac_user_sessions_tenant
    ON rbac_user_sessions (tenant_id, user_id, expires_at DESC);

-- Add tenant_id to license_cache table.
-- License validation is per-tenant; each tenant has their own license.
-- The cache key is now (tenant_id, license_key) composite.
ALTER TABLE license_cache
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';

-- Drop the old primary key and create a new composite primary key.
-- This allows multiple tenants to cache the same license_key independently.
ALTER TABLE license_cache
    DROP CONSTRAINT IF EXISTS license_cache_pkey;

ALTER TABLE license_cache
    ADD PRIMARY KEY (tenant_id, license_key);

-- Index for tenant-scoped license queries.
CREATE INDEX IF NOT EXISTS idx_license_cache_tenant
    ON license_cache (tenant_id, expires_at);

-- Update existing rows to have empty tenant_id (backward compatible).
-- In production, existing data would need to be migrated to specific
-- tenants based on customer assignments. For now, empty tenant_id
-- represents legacy/pre-multi-tenant data.
UPDATE ioc_fingerprints SET tenant_id = '' WHERE tenant_id IS NULL;
UPDATE ioc_events SET tenant_id = '' WHERE tenant_id IS NULL;
UPDATE rbac_agents SET tenant_id = '' WHERE tenant_id IS NULL;
UPDATE rbac_agent_sessions SET tenant_id = '' WHERE tenant_id IS NULL;
UPDATE rbac_user_sessions SET tenant_id = '' WHERE tenant_id IS NULL;
UPDATE license_cache SET tenant_id = '' WHERE tenant_id IS NULL;

-- Record this migration in the shared schema migrations table.
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    4,
    'Multi-tenant isolation: tenant_id columns on ioc_fingerprints, ioc_events, rbac_agents, rbac_agent_sessions, rbac_user_sessions, license_cache',
    NOW()
)
ON CONFLICT (version) DO NOTHING;
