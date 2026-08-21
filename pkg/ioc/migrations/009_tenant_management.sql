-- =========================================================================
-- AegisGate Platform — Tenant Management Table (Migration 009)
-- =========================================================================
-- Creates the tenants table for persistent multi-tenant management.
-- Used by pkg/tenant.PostgresManager to store tenant metadata across
-- restarts, enabling multi-instance deployment.
-- =========================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id           VARCHAR(64) PRIMARY KEY,
    name         VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) DEFAULT '',
    email        VARCHAR(255) DEFAULT '',
    license_tier VARCHAR(32) DEFAULT '',
    max_users    INTEGER DEFAULT 0,
    max_agents   INTEGER DEFAULT 0,
    active       BOOLEAN DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenants_name ON tenants(name);
CREATE INDEX IF NOT EXISTS idx_tenants_active ON tenants(active);

INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (9, 'Tenant management table', NOW())
ON CONFLICT (version) DO NOTHING;