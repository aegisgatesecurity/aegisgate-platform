-- =========================================================================
-- Migration 012: RLS for Additional Tenant-Scoped Tables
-- =========================================================================
--
-- SECURITY (H-3): Extends Row-Level Security to 7 additional tables that
-- were identified as bypassing RLS in the 2026-08-28 security audit:
--
--   1. sso_sessions        (pkg/sso/postgres_session_store.go)
--   2. sso_requests        (pkg/sso/postgres_session_store.go)
--   3. incidents           (pkg/incident/postgres_store.go)
--   4. detection_rules     (pkg/incident/postgres_store.go)
--   5. playbooks           (pkg/incident/postgres_store.go)
--   6. playbook_runs       (pkg/incident/postgres_store.go)
--   7. tenants             (pkg/tenant/postgres_manager.go)
--   8. audit_entries       (pkg/persistence/postgres_storage_backend.go)
--   9. correlation_events  (pkg/correlation/postgres_store.go)
--  10. attestation_envelopes (pkg/attestation/postgres_store.go)
--  11. cluster_rate_limits (pkg/cluster/ratelimit.go)
--
-- These tables store tenant-scoped data but were missing RLS policies,
-- relying solely on application-layer filtering. This migration adds
-- defense-in-depth RLS policies consistent with migration 008.
--
-- IMPORTANT: Some tables (sso_sessions, sso_requests, cluster_rate_limits)
-- are normally created at runtime by their respective packages. This
-- migration creates them here so RLS policies can be applied at init time.
-- The runtime CREATE TABLE IF NOT EXISTS will be a no-op if they already
-- exist.
--
-- Policies:
--   - tenancy_isolation: Users can only see rows where tenant_id matches
--     the session variable app.tenant_id, OR where app.is_admin = 'true'
--   - Tables without a tenant_id column get a permissive policy (no-op)
--     since they are system-wide (e.g., cluster_rate_limits may be
--     per-cluster, not per-tenant).
--
-- =========================================================================

-- =========================================================================
-- Pre-create runtime tables that may not exist at migration time
-- =========================================================================

-- SSO Sessions table (matches pkg/sso/postgres_session_store.go schema)
CREATE TABLE IF NOT EXISTS sso_sessions (
    id              TEXT        NOT NULL PRIMARY KEY,
    user_id         TEXT        NOT NULL DEFAULT '',
    session_id      TEXT        NOT NULL DEFAULT '',
    provider        TEXT        NOT NULL DEFAULT '',
    provider_name   TEXT        NOT NULL DEFAULT '',
    initial_idp     TEXT        NOT NULL DEFAULT '',
    name_id         TEXT        NOT NULL DEFAULT '',
    session_index   TEXT        NOT NULL DEFAULT '',
    ip_address      TEXT        NOT NULL DEFAULT '',
    user_agent      TEXT        NOT NULL DEFAULT '',
    access_token    TEXT        NOT NULL DEFAULT '',
    refresh_token   TEXT        NOT NULL DEFAULT '',
    id_token        TEXT        NOT NULL DEFAULT '',
    active          BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + interval '24 hours',
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_refreshed  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    token_expires_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01 00:00:00Z',
    user_data      JSONB       NOT NULL DEFAULT '{}',
    flags          JSONB       NOT NULL DEFAULT '{}',
    metadata       JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_sso_sessions_user
    ON sso_sessions (user_id, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_active
    ON sso_sessions (active, expires_at) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_sso_sessions_expiry
    ON sso_sessions (expires_at) WHERE active = TRUE;

-- SSO Requests table (matches pkg/sso/postgres_session_store.go schema)
CREATE TABLE IF NOT EXISTS sso_requests (
    id              TEXT        NOT NULL PRIMARY KEY,
    provider        TEXT        NOT NULL DEFAULT '',
    saml_request    TEXT        NOT NULL DEFAULT '',
    relay_state     TEXT        NOT NULL DEFAULT '',
    destination     TEXT        NOT NULL DEFAULT '',
    protocol_binding TEXT       NOT NULL DEFAULT '',
    state           TEXT        NOT NULL DEFAULT '',
    code_verifier   TEXT        NOT NULL DEFAULT '',
    nonce           TEXT        NOT NULL DEFAULT '',
    redirect_url    TEXT        NOT NULL DEFAULT '',
    ip_address     TEXT        NOT NULL DEFAULT '',
    user_agent     TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ NOT NULL DEFAULT NOW() + interval '1 hour'
);

CREATE INDEX IF NOT EXISTS idx_sso_requests_state
    ON sso_requests (state);
CREATE INDEX IF NOT EXISTS idx_sso_requests_expiry
    ON sso_requests (expires_at);

-- Cluster Rate Limits table (matches pkg/cluster/ratelimit.go schema)
CREATE TABLE IF NOT EXISTS cluster_rate_limits (
    key       TEXT    NOT NULL,
    "window"  BIGINT NOT NULL,
    node_id   TEXT    NOT NULL,
    count     INT    NOT NULL DEFAULT 1,
    PRIMARY KEY (key, "window", node_id)
);

CREATE INDEX IF NOT EXISTS idx_cluster_rate_limits_window
    ON cluster_rate_limits ("window");

-- =========================================================================
-- Apply RLS policies to all tables
-- =========================================================================

-- SSO Sessions (tenant_id column added if not present)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'sso_sessions' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE sso_sessions ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE sso_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_sessions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sso_sessions_tenant_isolation ON sso_sessions;
CREATE POLICY sso_sessions_tenant_isolation ON sso_sessions
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true));

-- SSO Requests
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'sso_requests' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE sso_requests ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE sso_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_requests FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sso_requests_tenant_isolation ON sso_requests;
CREATE POLICY sso_requests_tenant_isolation ON sso_requests
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true));

-- Incidents
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'incidents' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE incidents ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS incidents_tenant_isolation ON incidents;
CREATE POLICY incidents_tenant_isolation ON incidents
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true));

-- Detection Rules
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'detection_rules' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE detection_rules ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS detection_rules_tenant_isolation ON detection_rules;
CREATE POLICY detection_rules_tenant_isolation ON detection_rules
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true));

-- Playbooks
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'playbooks' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE playbooks ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbooks FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS playbooks_tenant_isolation ON playbooks;
CREATE POLICY playbooks_tenant_isolation ON playbooks
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true));

-- Playbook Runs
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'playbook_runs' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE playbook_runs ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE playbook_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_runs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS playbook_runs_tenant_isolation ON playbook_runs;
CREATE POLICY playbook_runs_tenant_isolation ON playbook_runs
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true));

-- Tenants (tenant management — only admins can see all tenants)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tenants' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE tenants ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenants_tenant_isolation ON tenants;
CREATE POLICY tenants_tenant_isolation ON tenants
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true)
           OR id::text = current_setting('app.tenant_id', true));

-- Audit Entries (persistence layer)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_entries' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE audit_entries ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE audit_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_entries FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_entries_tenant_isolation ON audit_entries;
CREATE POLICY audit_entries_tenant_isolation ON audit_entries
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true));

-- Correlation Events
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'correlation_events' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE correlation_events ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE correlation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS correlation_events_tenant_isolation ON correlation_events;
CREATE POLICY correlation_events_tenant_isolation ON correlation_events
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true));

-- Attestation Envelopes
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'attestation_envelopes' AND column_name = 'tenant_id'
    ) THEN
        ALTER TABLE attestation_envelopes ADD COLUMN tenant_id TEXT DEFAULT '';
    END IF;
END $$;

ALTER TABLE attestation_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestation_envelopes FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS attestation_envelopes_tenant_isolation ON attestation_envelopes;
CREATE POLICY attestation_envelopes_tenant_isolation ON attestation_envelopes
    USING (current_setting('app.is_admin', true) = 'true'
           OR tenant_id = current_setting('app.tenant_id', true));

-- Cluster Rate Limits (system-wide, not tenant-scoped — permissive policy)
ALTER TABLE cluster_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE cluster_rate_limits FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS cluster_rate_limits_admin_only ON cluster_rate_limits;
CREATE POLICY cluster_rate_limits_admin_only ON cluster_rate_limits
    USING (current_setting('app.is_admin', true) = 'true'
           OR current_setting('app.tenant_id', true) = '');

-- Record migration
INSERT INTO ioc_schema_migrations (version, description) VALUES ('012', 'RLS for additional tenant-scoped tables (sso, incident, tenant, persistence, correlation, attestation, cluster)')
ON CONFLICT (version) DO NOTHING;