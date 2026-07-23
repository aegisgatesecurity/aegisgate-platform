-- SPDX-License-Identifier: Apache-2.0
-- AegisGate Platform - Incident Response Schema (Migration 007)
--
-- Tables for incident response automation (v3.8):
--   - incidents: security incidents detected or created
--   - playbook_runs: playbook execution tracking
--   - detection_rules: automated detection rule definitions
--
-- Tier gating: FeaturePostgreSQL required (Professional/Enterprise).
-- Community/Developer use in-memory stores.

-- Incidents table: the core entity of incident response.
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'low'
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'triaged', 'investigating',
                          'contained', 'resolved', 'closed',
                          'false_positive')),
    source TEXT NOT NULL DEFAULT 'correlation'
        CHECK (source IN ('correlation', 'soc', 'auto_rule', 'api')),

    -- Correlation linkage
    session_id TEXT DEFAULT '',
    agent_id TEXT DEFAULT '',
    -- correlation_event_ids stored as JSONB array

    -- Playbook
    playbook_id TEXT DEFAULT '',
    escalation_policy_id TEXT DEFAULT '',
    escalated_to TEXT DEFAULT '',
    assignee TEXT DEFAULT '',

    -- Escalation timestamps
    escalated_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,

    -- Metadata
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    tenant_id TEXT DEFAULT '',

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_agent ON incidents(agent_id);
CREATE INDEX idx_incidents_session ON incidents(session_id);
CREATE INDEX idx_incidents_created ON incidents(created_at DESC);
CREATE INDEX idx_incidents_tenant ON incidents(tenant_id);
CREATE INDEX idx_incidents_source ON incidents(source);

-- Playbook runs table: tracks playbook execution per incident.
CREATE TABLE IF NOT EXISTS playbook_runs (
    id TEXT PRIMARY KEY,
    playbook_id TEXT NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'failed', 'partial')),
    error TEXT DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    step_results JSONB DEFAULT '[]',

    -- Metadata
    tenant_id TEXT DEFAULT ''
);

CREATE INDEX idx_playbook_runs_incident ON playbook_runs(incident_id);
CREATE INDEX idx_playbook_runs_status ON playbook_runs(status);
CREATE INDEX idx_playbook_runs_playbook ON playbook_runs(playbook_id);

-- Detection rules table: automated detection rule definitions.
CREATE TABLE IF NOT EXISTS detection_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',

    -- Trigger conditions
    source TEXT NOT NULL DEFAULT 'correlation'
        CHECK (source IN ('correlation', 'soc', 'auto_rule', 'api')),
    severity TEXT NOT NULL DEFAULT 'low'
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    patterns TEXT[] DEFAULT '{}',
    event_types TEXT[] DEFAULT '{}',
    min_events INT NOT NULL DEFAULT 1,
    time_window INTERVAL DEFAULT INTERVAL '5 minutes',

    -- Response
    playbook_id TEXT DEFAULT '',
    auto_create BOOLEAN NOT NULL DEFAULT true,
    auto_execute BOOLEAN NOT NULL DEFAULT false,
    compliance_mappings JSONB DEFAULT '[]',

    -- State
    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_detection_rules_enabled ON detection_rules(enabled);
CREATE INDEX idx_detection_rules_severity ON detection_rules(severity);
CREATE INDEX idx_detection_rules_source ON detection_rules(source);

-- Playbooks table: incident response playbook templates.
CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'low'
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    source TEXT NOT NULL DEFAULT 'correlation'
        CHECK (source IN ('correlation', 'soc', 'auto_rule', 'api')),
    tags TEXT[] DEFAULT '{}',
    steps JSONB DEFAULT '[]',
    auto_execute BOOLEAN NOT NULL DEFAULT false,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_playbooks_severity ON playbooks(severity);
CREATE INDEX idx_playbooks_source ON playbooks(source);