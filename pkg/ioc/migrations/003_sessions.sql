-- =========================================================================
-- AegisGate Platform — Session & License State Schema (Migration 003)
-- =========================================================================
-- Persists RBAC agent registrations, sessions, and license validation
-- cache to PostgreSQL. Enables multi-instance deployment and session
-- persistence across restarts.
--
-- Part of D1 Phase 1C: Session/License State → PostgreSQL.
-- Requires: 001_initial.sql (ioc_schema_migrations must exist).
-- =========================================================================

-- Agent registrations: persisted across restarts.
-- An agent is an AI system (MCP client, bridge, etc.) with a role and
-- tool permissions. In multi-instance deployments, all instances must
-- see the same agent registry.
CREATE TABLE IF NOT EXISTS rbac_agents (
    id          TEXT        NOT NULL PRIMARY KEY,
    name        TEXT        NOT NULL DEFAULT '',
    description TEXT        NOT NULL DEFAULT '',
    role        TEXT        NOT NULL DEFAULT 'restricted',
    tools       JSONB       NOT NULL DEFAULT '[]',   -- ToolPermission array as JSON strings
    tags        JSONB       NOT NULL DEFAULT '{}',   -- map[string]string
    metadata    JSONB       NOT NULL DEFAULT '{}',   -- map[string]interface{}
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index: agents by role (e.g., list all admin agents)
CREATE INDEX IF NOT EXISTS idx_rbac_agents_role ON rbac_agents (role, updated_at DESC);

-- Agent sessions: one row per active agent session.
-- expires_at enables efficient cleanup of expired sessions.
-- An agent may have multiple sessions (e.g., different tools, different contexts).
CREATE TABLE IF NOT EXISTS rbac_agent_sessions (
    id              TEXT        NOT NULL PRIMARY KEY,
    agent_id        TEXT        NOT NULL REFERENCES rbac_agents(id) ON DELETE CASCADE,
    ip_address      TEXT        NOT NULL DEFAULT '',
    context_hash    TEXT        NOT NULL DEFAULT '',
    tags            JSONB       NOT NULL DEFAULT '{}',
    active          BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index: sessions for a specific agent, sorted by expiry
CREATE INDEX IF NOT EXISTS idx_rbac_agent_sessions_agent
    ON rbac_agent_sessions (agent_id, expires_at DESC);

-- Index: expired sessions for cleanup (partial index on active sessions nearing expiry)
CREATE INDEX IF NOT EXISTS idx_rbac_agent_sessions_expiry
    ON rbac_agent_sessions (expires_at) WHERE active = TRUE;

-- User sessions: dashboard/API user sessions.
-- Users are not persisted separately (they come from SSO/Keycloak),
-- but their sessions are tracked for authorization.
CREATE TABLE IF NOT EXISTS rbac_user_sessions (
    id              TEXT        NOT NULL PRIMARY KEY,
    user_id         TEXT        NOT NULL,
    role            TEXT        NOT NULL DEFAULT 'viewer',
    permissions     JSONB       NOT NULL DEFAULT '[]',  -- Permission array
    ip_address      TEXT        NOT NULL DEFAULT '',
    tags            JSONB       NOT NULL DEFAULT '{}',
    active          BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index: sessions for a specific user
CREATE INDEX IF NOT EXISTS idx_rbac_user_sessions_user
    ON rbac_user_sessions (user_id, expires_at DESC);

-- Index: expired user sessions for cleanup
CREATE INDEX IF NOT EXISTS idx_rbac_user_sessions_expiry
    ON rbac_user_sessions (expires_at) WHERE active = TRUE;

-- License validation cache: shared across instances.
-- Replaces the in-memory map[string]*cachedResult in license.Manager.
-- The 5-minute TTL is enforced by expires_at; stale entries are pruned
-- by the persistence Manager's background goroutine.
CREATE TABLE IF NOT EXISTS license_cache (
    license_key  TEXT        NOT NULL PRIMARY KEY,
    tier         TEXT        NOT NULL,
    valid        BOOLEAN     NOT NULL,
    expired      BOOLEAN     NOT NULL DEFAULT FALSE,
    grace_period BOOLEAN     NOT NULL DEFAULT FALSE,
    payload      JSONB       NOT NULL DEFAULT '{}',
    message      TEXT        NOT NULL DEFAULT '',
    error_msg    TEXT        NOT NULL DEFAULT '',
    validated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL
);

-- Index: prune expired cache entries
CREATE INDEX IF NOT EXISTS idx_license_cache_expiry ON license_cache (expires_at);

-- Record this migration in the shared schema migrations table.
INSERT INTO ioc_schema_migrations (version, description, applied_at)
VALUES (
    3,
    'rbac_agents, rbac_agent_sessions, rbac_user_sessions, license_cache tables for session persistence',
    NOW()
)
ON CONFLICT (version) DO NOTHING;