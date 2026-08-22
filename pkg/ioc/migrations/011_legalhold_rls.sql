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

-- Only apply if the legal_holds table exists (created by the application at startup).
-- In fresh-database scenarios (e.g. Docker initdb), the table may not exist yet.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_name = 'legal_holds'
    ) THEN
        ALTER TABLE legal_holds ENABLE ROW LEVEL SECURITY;
        ALTER TABLE legal_holds FORCE ROW LEVEL SECURITY;

        -- Drop existing policies if they exist, then recreate
        DROP POLICY IF EXISTS legal_holds_tenant_isolation ON legal_holds;
        CREATE POLICY legal_holds_tenant_isolation ON legal_holds
            USING (
                current_setting('app.tenant_id', true) = ''
                OR tenant_id = current_setting('app.tenant_id', true)
            );

        DROP POLICY IF EXISTS legal_holds_admin_bypass ON legal_holds;
        CREATE POLICY legal_holds_admin_bypass ON legal_holds
            USING (
                current_setting('app.is_admin', true) = 'true'
            );
    END IF;
END $$;

-- Record this migration (always record, even if table didn't exist yet —
-- the app will apply RLS policies via ensureSchema if table is created later)
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    11,
    'RLS + FORCE on legal_holds table (tenant-scoped e-discovery)',
    NOW()
)
ON CONFLICT (version) DO NOTHING;