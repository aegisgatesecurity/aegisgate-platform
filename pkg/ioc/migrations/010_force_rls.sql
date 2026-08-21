-- =========================================================================
-- AegisGate Platform — FORCE Row-Level Security (Migration 010)
-- =========================================================================
-- Upgrades RLS from "enabled" to "forced" on all tenant-scoped tables.
--
-- Migration 008 enabled RLS but left it unforced, meaning the table owner
-- (the application database role) bypassed RLS policies. This was
-- intentional for the initial rollout to allow verification of
-- application compatibility.
--
-- Now that all store methods are wired through WithTenantContextOrPool
-- (Step 4 — RLS wiring), which sets SET LOCAL app.tenant_id and
-- app.is_admin session variables, it is safe to FORCE RLS. This ensures
-- that even the table owner is subject to RLS policies, providing true
-- defense-in-depth tenant isolation at the database level.
--
-- Tables forced:
--   ioc_fingerprints       — IOC registry
--   ioc_events             — IOC event log
--   rbac_agents            — Agent registry
--   rbac_agent_sessions    — Agent session store
--   rbac_user_sessions     — User session store
--   license_cache          — License cache
--
-- Requires: 008_rls_tenant_isolation.sql (RLS enabled + policies)
-- =========================================================================

ALTER TABLE ioc_fingerprints FORCE ROW LEVEL SECURITY;
ALTER TABLE ioc_events FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac_agents FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac_agent_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac_user_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE license_cache FORCE ROW LEVEL SECURITY;

-- Record this migration
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    10,
    'FORCE Row-Level Security on all tenant-scoped tables (defense-in-depth enforced)',
    NOW()
)
ON CONFLICT (version) DO NOTHING;