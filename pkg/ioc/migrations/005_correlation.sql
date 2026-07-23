-- =========================================================================
-- AegisGate Platform — Correlation Events Schema (Migration 005)
-- =========================================================================
-- Persists cross-protocol correlation events to PostgreSQL for Professional
-- and Enterprise tiers. This enables multi-instance correlation, SOC timeline
-- persistence, and long-term incident analysis.
--
-- The correlation engine's in-memory store is sufficient for Community and
-- Developer tiers (single-instance, in-process). Professional and Enterprise
-- tiers use this table for durability across restarts and correlation across
-- multiple platform instances.
--
-- Design decisions:
--
--   1. event_time is the logical event timestamp (from the Event struct's
--      Timestamp field). created_at is the database insertion time. This
--      separation is critical for replay and audit: the event happened at
--      event_time, but was recorded at created_at.
--
--   2. data and metadata are JSONB columns. data holds arbitrary key-value
--      context (the Event.Data map[string]interface{}); metadata holds
--      string key-value pairs (Event.Metadata map[string]string).
--
--   3. The (agent_id, session_id, event_time) composite index is the primary
--      query path for the SOC timeline and correlation analysis.
--
--   4. tenant_id supports multi-tenant isolation (Professional/Enterprise).
--
-- Part of v3.8 persistence gap closure.
-- Requires: 001_initial.sql (ioc_schema_migrations must exist).
-- =========================================================================

-- Correlation events: one row per security event from any protocol pillar.
CREATE TABLE IF NOT EXISTS correlation_events (
    id            TEXT        NOT NULL PRIMARY KEY,
    protocol      TEXT        NOT NULL,
    agent_id      TEXT        NOT NULL DEFAULT '',
    session_id    TEXT        NOT NULL DEFAULT '',
    event_type    TEXT        NOT NULL DEFAULT '',
    severity      TEXT        NOT NULL DEFAULT 'low',
    decision      TEXT        NOT NULL DEFAULT '',
    data          JSONB       NOT NULL DEFAULT '{}',
    metadata      JSONB       NOT NULL DEFAULT '{}',
    event_time    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id     TEXT        NOT NULL DEFAULT ''
);

-- Primary query path: SOC timeline (session-ordered events).
CREATE INDEX IF NOT EXISTS idx_correlation_events_session
    ON correlation_events (session_id, event_time DESC);

-- Agent-scoped queries (dashboard, per-agent timeline).
CREATE INDEX IF NOT EXISTS idx_correlation_events_agent
    ON correlation_events (agent_id, event_time DESC);

-- Composite: agent + session (correlation analysis hot path).
CREATE INDEX IF NOT EXISTS idx_correlation_events_agent_session
    ON correlation_events (agent_id, session_id, event_time DESC);

-- Protocol + severity (dashboard filters, threat analysis).
CREATE INDEX IF NOT EXISTS idx_correlation_events_protocol_severity
    ON correlation_events (protocol, severity, event_time DESC);

-- Retention pruning (delete events older than X).
CREATE INDEX IF NOT EXISTS idx_correlation_events_created_at
    ON correlation_events (created_at);

-- Multi-tenant isolation (Professional/Enterprise).
CREATE INDEX IF NOT EXISTS idx_correlation_events_tenant
    ON correlation_events (tenant_id, event_time DESC);

-- Record this migration.
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    5,
    'correlation_events table for cross-protocol event persistence and SOC timeline',
    NOW()
)
ON CONFLICT (version) DO NOTHING;