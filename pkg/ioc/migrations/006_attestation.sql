-- =========================================================================
-- AegisGate Platform — Attestation Envelope Store (Migration 006)
-- =========================================================================
-- Persists signed attestation envelopes to PostgreSQL for Professional and
-- Enterprise tiers. This enables:
--
--   - Long-term audit trail of all signed attestations (SOC 2, benchmarks,
--     AIBOM, intent signing, etc.)
--   - Third-party verification without re-signing
--   - Compliance reporting and evidence collection
--   - Key rotation tracking (which key signed what, when)
--
-- The attestation envelope is the cryptographic backbone of AegisGate.
-- Every signed artifact (evidence manifests, evaluation results, AIBOM,
-- agent intent, SOC 2 workpapers, benchmark reports) wraps its payload
-- in this envelope. Storing them durably is required for SOC 2 Type II
-- evidence retention and FedRAMP audit requirements.
--
-- Design decisions:
--
--   1. The payload is stored as JSONB (not TEXT) to enable indexed queries
--      on the envelope type, subject, and issuer.
--
--   2. The signature is stored as three separate columns (algorithm, key_id,
--      value) rather than a single JSONB column, because verification needs
--      to look up the key_id and algorithm independently.
--
--   3. The public_key is stored as BYTEA (SEC 1 encoded P-256 point) to
--      match the envelope's wire format exactly.
--
--   4. valid_until is nullable; zero/NULL means "does not expire."
--
--   5. tenant_id supports multi-tenant isolation (Professional/Enterprise).
--
-- Part of v3.8 persistence gap closure.
-- Requires: 001_initial.sql (ioc_schema_migrations must exist).
-- =========================================================================

-- Attestation envelopes: one row per signed envelope.
CREATE TABLE IF NOT EXISTS attestation_envelopes (
    id            TEXT        NOT NULL PRIMARY KEY,
    type          TEXT        NOT NULL,       -- e.g. "benchmark.sxc.v1", "audit.soc2.v1"
    subject       TEXT        NOT NULL,       -- e.g. "aegisgate://evaluation/bench-2026-07-23"
    issuer        TEXT        NOT NULL,       -- e.g. "instance-1:key-2026-07-23"
    issued_at     TIMESTAMPTZ NOT NULL,
    valid_until   TIMESTAMPTZ,               -- NULL = does not expire
    payload       JSONB       NOT NULL DEFAULT '{}',
    sig_algorithm TEXT        NOT NULL DEFAULT 'ecdsa-p256',
    sig_key_id    TEXT        NOT NULL DEFAULT '',
    sig_value     BYTEA       NOT NULL,       -- ASN.1 DER ECDSA signature
    sig_public_key BYTEA      NOT NULL,       -- SEC 1 encoded P-256 public key
    sig_signed_at TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id     TEXT        NOT NULL DEFAULT ''
);

-- Query by type (e.g., "find all SOC 2 audit envelopes").
CREATE INDEX IF NOT EXISTS idx_attestation_envelopes_type
    ON attestation_envelopes (type, issued_at DESC);

-- Query by subject (e.g., "find all attestations for this evaluation").
CREATE INDEX IF NOT EXISTS idx_attestation_envelopes_subject
    ON attestation_envelopes (subject, issued_at DESC);

-- Query by issuer/key (e.g., "find all envelopes signed by key X").
CREATE INDEX IF NOT EXISTS idx_attestation_envelopes_key
    ON attestation_envelopes (sig_key_id, issued_at DESC);

-- Retention pruning and time-range queries.
CREATE INDEX IF NOT EXISTS idx_attestation_envelopes_issued_at
    ON attestation_envelopes (issued_at DESC);

-- Multi-tenant isolation.
CREATE INDEX IF NOT EXISTS idx_attestation_envelopes_tenant
    ON attestation_envelopes (tenant_id, type, issued_at DESC);

-- Validity queries (find expired/unexpired envelopes).
CREATE INDEX IF NOT EXISTS idx_attestation_envelopes_validity
    ON attestation_envelopes (valid_until) WHERE valid_until IS NOT NULL;

-- Record this migration.
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    6,
    'attestation_envelopes table for signed attestation persistence and audit trail',
    NOW()
)
ON CONFLICT (version) DO NOTHING;