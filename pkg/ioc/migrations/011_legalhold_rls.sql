-- =========================================================================
-- AegisGate Platform — RLS for Legal Holds Table (Migration 011)
-- =========================================================================
-- Enables and forces Row-Level Security on the legal_holds table.
-- Legal holds are tenant-scoped: a tenant should only see holds
-- placed on entities within their tenant.
--
-- The admin bypass (app.is_admin = 'true') allows system operators
-- to manage holds across all tenants.
--
-- Requires: 008_rls_tenant_isolation.sql (RLS pattern + session vars)
--           010_force_rls.sql (FORCE RLS pattern)
-- =========================================================================

-- Enable RLS
ALTER TABLE legal_holds ENABLE ROW LEVEL SECURITY;

-- Force RLS (even table owner is subject to policies)
ALTER TABLE legal_holds FORCE ROW LEVEL SECURITY;

-- Tenant isolation policy: tenants see only their own holds.
CREATE POLICY legal_holds_tenant_isolation ON legal_holds
    USING (
        current_setting('app.tenant_id', true) = ''
        OR tenant_id = current_setting('app.tenant_id', true)
    );

-- Admin bypass policy: admins can see all holds.
CREATE POLICY legal_holds_admin_bypass ON legal_holds
    USING (
        current_setting('app.is_admin', true) = 'true'
    );

-- Record this migration
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    11,
    'RLS + FORCE on legal_holds table (tenant-scoped e-discovery)',
    NOW()
)
ON CONFLICT (version) DO NOTHING;