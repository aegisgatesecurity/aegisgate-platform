-- =========================================================================
-- AegisGate Platform - IOC Store Schema (v3.5.0+ D1 Phase 1A)
-- =========================================================================
--
-- This migration creates the two tables that replace the in-memory IOC
-- store for Professional and Enterprise tiers:
--
--   ioc_fingerprints: the core IOC record (one row per unique fingerprint)
--   ioc_events:       individual detection events linked to a fingerprint
--
-- Design decisions:
--
--   1. fingerprint is the primary key. SHA-256 hex (64 chars) is the
--      canonical IOC identifier from pkg/ioc/fingerprint.go.
--
--   2. ioc_events separate the "what was detected" (fingerprint metadata)
--      from the "when and how often" (event stream). This allows:
--        - Efficient "events since X" queries for the /check endpoint
--        - Tier-based retention pruning (delete old events, keep fingerprints)
--        - Future analytics (event volume trends, burst detection)
--
--   3. Partial indexes cover the most common query patterns:
--        - /check by (affects_lens, severity, last_seen)
--        - Lens telemetry by (source_provider, category)
--        - Dashboard by (type, severity)
--
--   4. All timestamps are TIMESTAMPTZ (UTC). The platform stores times
--      in UTC and the Go code uses time.Time with UTC location.
--
--   5. The schema is additive-only for forward compatibility. New columns
--      MUST have DEFAULT values so existing rows are not broken.
-- =========================================================================

-- Create the ioc_fingerprints table.
-- This is the core IOC record. One row per unique fingerprint.
-- The count, first_seen, last_seen, and severity are denormalized
-- from the event stream for fast reads (avoid joining ioc_events
-- on every /check request).
CREATE TABLE IF NOT EXISTS ioc_fingerprints (
    fingerprint      TEXT        PRIMARY KEY,  -- SHA-256 hex, 64 chars
    type             TEXT        NOT NULL,      -- IOCType: proxy_response, anomaly_score, prompt_injection, secret_leak, pii_detected
    severity         TEXT        NOT NULL,      -- Severity: critical, high, medium, low, info
    category         TEXT        DEFAULT '',    -- Lens category (e.g., pii_email, secret_api_key)
    pattern          TEXT        DEFAULT '',    -- Canonicalized pattern name (e.g., aws_access_key_v1)
    source_provider  TEXT        DEFAULT '',    -- AI provider (e.g., chatgpt, claude, gemini)
    affects_lens     BOOLEAN     DEFAULT FALSE, -- Should this IOC be propagated to Lens?
    affects_gateway  BOOLEAN     DEFAULT TRUE,  -- Should this IOC be propagated to Gateway?
    source           TEXT        DEFAULT '',    -- Non-identifying source label (e.g., "proxy", "anomaly")
    count            BIGINT      NOT NULL DEFAULT 1, -- Total observations across all events
    first_seen       TIMESTAMPTZ NOT NULL,      -- UTC timestamp of first observation
    last_seen        TIMESTAMPTZ NOT NULL,      -- UTC timestamp of most recent observation
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial index: IOCs that should be propagated to Lens, sorted by
-- recency and severity. This is the primary /check query path for
-- Lens browser extensions pulling pattern updates.
CREATE INDEX IF NOT EXISTS idx_fingerprints_lens_check
    ON ioc_fingerprints (last_seen DESC, severity DESC)
    WHERE affects_lens = TRUE;

-- Partial index: IOCs filtered by source provider and category.
-- Used by Lens telemetry routing and provider-specific dashboards.
CREATE INDEX IF NOT EXISTS idx_fingerprints_provider_category
    ON ioc_fingerprints (source_provider, category, last_seen DESC)
    WHERE source_provider != '';

-- Index: type + severity for Gateway dashboard queries.
CREATE INDEX IF NOT EXISTS idx_fingerprints_type_severity
    ON ioc_fingerprints (type, severity, last_seen DESC);

-- Index: last_seen for SnapshotSince queries (gossip sync protocol).
CREATE INDEX IF NOT EXISTS idx_fingerprints_last_seen
    ON ioc_fingerprints (last_seen DESC);

-- =========================================================================
-- Create the ioc_events table.
-- Each row is a single detection event. This is the raw telemetry that
-- flows from Lens (via pkg/lensbackend) or Gateway (via pkg/ioc/producer).
-- Events are linked to fingerprints by FK. Events can be pruned
-- independently of fingerprints (tier-based retention).
-- =========================================================================
CREATE TABLE IF NOT EXISTS ioc_events (
    id               BIGSERIAL    PRIMARY KEY,
    fingerprint      TEXT         NOT NULL REFERENCES ioc_fingerprints(fingerprint) ON DELETE CASCADE,
    domain_hash      TEXT         DEFAULT '',    -- SHA-256 truncated to 16 chars (privacy-preserving)
    category         TEXT         DEFAULT '',    -- Lens category at event time
    severity         TEXT         NOT NULL,      -- Severity at event time
    user_action      TEXT         DEFAULT '',    -- User action (allow, block, flag, dismiss)
    event_timestamp  TIMESTAMPTZ  NOT NULL,      -- When the event occurred (from Lens or Gateway)
    model_version    TEXT         DEFAULT '',    -- Detection model version
    lens_version     TEXT         DEFAULT '',    -- Lens extension version (if from Lens)
    confidence       REAL         DEFAULT 0.0,  -- Detection confidence (0.0-1.0)
    source_provider  TEXT         DEFAULT '',    -- AI provider
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Index: events by fingerprint + timestamp (event stream for a single IOC).
CREATE INDEX IF NOT EXISTS idx_events_fingerprint_time
    ON ioc_events (fingerprint, event_timestamp DESC);

-- Index: events by timestamp (for retention pruning and time-range queries).
CREATE INDEX IF NOT EXISTS idx_events_created_at
    ON ioc_events (created_at);

-- Partial index: Lens-sourced events for provider analytics.
CREATE INDEX IF NOT EXISTS idx_events_lens_source
    ON ioc_events (source_provider, event_timestamp DESC)
    WHERE source_provider != '';

-- =========================================================================
-- Migration tracking table (used by the Go migration runner).
-- =========================================================================
CREATE TABLE IF NOT EXISTS ioc_schema_migrations (
    version    INT       PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT      NOT NULL
);

INSERT INTO ioc_schema_migrations (version, description) VALUES
    (1, 'Initial schema: ioc_fingerprints, ioc_events, ioc_schema_migrations');