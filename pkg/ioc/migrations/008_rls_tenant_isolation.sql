-- =========================================================================
-- AegisGate Platform — Row-Level Security Policies (Migration 008)
-- =========================================================================
-- Adds PostgreSQL Row-Level Security (RLS) policies as defense-in-depth
-- for multi-tenant isolation. This complements the application-layer
-- tenant filtering already enforced in Go code.
--
-- RLS ensures that even if an application bug skips tenant context,
-- the database itself will prevent cross-tenant data leakage.
--
-- IMPORTANT: RLS policies use a session variable `app.tenant_id` set
-- by the application at connection time. The application MUST call
-- SET LOCAL app.tenant_id = '<tenant>' before querying tenant-scoped
-- tables. Admin operations use SET LOCAL app.is_admin = 'true' to
-- bypass RLS.
--
-- Requires: 004_multi_tenant.sql (tenant_id columns)
-- =========================================================================

-- Enable RLS on all tenant-scoped tables
ALTER TABLE ioc_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE ioc_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE license_cache ENABLE ROW LEVEL SECURITY;

-- ioc_fingerprints: tenants can only see their own IOCs + shared (empty tenant_id)
CREATE POLICY tenant_isolation_fingerprints ON ioc_fingerprints
    USING (
        current_setting('app.is_admin', true) = 'true'
        OR tenant_id = ''
        OR tenant_id = current_setting('app.tenant_id', true)
    );

-- ioc_events: same isolation pattern
CREATE POLICY tenant_isolation_events ON ioc_events
    USING (
        current_setting('app.is_admin', true) = 'true'
        OR tenant_id = ''
        OR tenant_id = current_setting('app.tenant_id', true)
    );

-- rbac_agents: tenants can only manage their own agents
CREATE POLICY tenant_isolation_agents ON rbac_agents
    USING (
        current_setting('app.is_admin', true) = 'true'
        OR tenant_id = ''
        OR tenant_id = current_setting('app.tenant_id', true)
    );

-- rbac_agent_sessions: sessions scoped to tenant
CREATE POLICY tenant_isolation_agent_sessions ON rbac_agent_sessions
    USING (
        current_setting('app.is_admin', true) = 'true'
        OR tenant_id = ''
        OR tenant_id = current_setting('app.tenant_id', true)
    );

-- rbac_user_sessions: user sessions scoped to tenant
CREATE POLICY tenant_isolation_user_sessions ON rbac_user_sessions
    USING (
        current_setting('app.is_admin', true) = 'true'
        OR tenant_id = ''
        OR tenant_id = current_setting('app.tenant_id', true)
    );

-- license_cache: each tenant has their own license entries
CREATE POLICY tenant_isolation_license_cache ON license_cache
    USING (
        current_setting('app.is_admin', true) = 'true'
        OR tenant_id = ''
        OR tenant_id = current_setting('app.tenant_id', true)
    );

-- Note: Table owners (typically the application role) bypass RLS by
-- default. To enforce RLS for the application role, use:
--   ALTER TABLE ioc_fingerprints FORCE ROW LEVEL SECURITY;
-- This should be done ONLY when the application correctly sets
-- app.tenant_id on every connection. For initial rollout, we leave
-- RLS enabled but not forced, so the application can verify
-- compatibility before making it mandatory.

-- Record this migration
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    8,
    'Row-Level Security policies for tenant isolation (defense-in-depth)',
    NOW()
)
ON CONFLICT (version) DO NOTHING;