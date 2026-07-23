-- ============================================================================
-- AegisGate Platform — Audit Log Schema (Migration 002)
-- ============================================================================
-- Stores audit entries with hash-chain integrity, tier-based retention,
-- and indexed query support for compliance reporting.
--
-- Part of D1 Phase 1B: Audit Log → PostgreSQL.
-- Requires: 001_initial.sql (ioc_fingerprints, ioc_events must exist first
--   so the audit_schema_migrations table already exists).
-- ============================================================================

-- Audit entries: one row per compliance-auditable event.
-- The hash chain (hash + previous_hash) mirrors the in-memory SecureAuditLog
-- integrity model; any tampering with a row breaks the chain.
CREATE TABLE IF NOT EXISTS audit_entries (
    id              TEXT        NOT NULL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    level           TEXT        NOT NULL,  -- AuditLevel: debug, info, warn, error, critical
    event_type      TEXT        NOT NULL,  -- e.g., "proxy.request", "mcp.tool_call", "auth.login"
    message         TEXT        NOT NULL DEFAULT '',
    source          TEXT        NOT NULL DEFAULT '',
    hash            TEXT        NOT NULL DEFAULT '',   -- SHA-256 of entry + previous hash
    previous_hash   TEXT        NOT NULL DEFAULT '',   -- Links to prior entry for chain integrity
    tenant_id       TEXT        NOT NULL DEFAULT '',

    -- data and compliance_tags are stored as JSONB for flexibility.
    -- data contains arbitrary key-value context; compliance_tags is
    -- a string array of compliance framework identifiers (HIPAA, PCI-DSS, SOC2).
    data            JSONB       NOT NULL DEFAULT '{}',
    compliance_tags JSONB       NOT NULL DEFAULT '[]',

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for time-range queries (most common: "last N days").
CREATE INDEX IF NOT EXISTS idx_audit_entries_timestamp ON audit_entries (timestamp DESC);

-- Index for filtering by event type (e.g., all auth events).
CREATE INDEX IF NOT EXISTS idx_audit_entries_event_type ON audit_entries (event_type, timestamp DESC);

-- Index for compliance reporting: "show me all HIPAA-tagged entries this quarter."
CREATE INDEX IF NOT EXISTS idx_audit_entries_compliance ON audit_entries USING GIN (compliance_tags);

-- Index for tenant isolation (multi-tenant Professional/Enterprise).
CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant ON audit_entries (tenant_id, timestamp DESC);

-- Index for level-based queries (e.g., "all critical events").
CREATE INDEX IF NOT EXISTS idx_audit_entries_level ON audit_entries (level, timestamp DESC);

-- Index for source-based queries (e.g., "all events from the MCP server").
CREATE INDEX IF NOT EXISTS idx_audit_entries_source ON audit_entries (source, timestamp DESC);

-- Helper function for text search across message and data.
-- (tsvector || operator is not allowed directly in CREATE INDEX expressions.)
CREATE OR REPLACE FUNCTION audit_tsvector_search(message TEXT, data JSONB) RETURNS tsvector AS $$
  SELECT setweight(to_tsvector('english', message), 'A') || setweight(to_tsvector('english', COALESCE(data::text, '')), 'B');
$$ LANGUAGE SQL IMMUTABLE;

-- Index for text search across message and data.
CREATE INDEX IF NOT EXISTS idx_audit_entries_search ON audit_entries USING GIN (audit_tsvector_search(message, data));

-- Record this migration in the shared schema migrations table.
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    2,
    'audit_entries table with hash-chain integrity, tier-based retention, and indexed compliance queries',
    NOW()
)
ON CONFLICT (version) DO NOTHING;