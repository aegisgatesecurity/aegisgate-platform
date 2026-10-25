// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Agent Registry PostgreSQL Store (v5.0)
// =========================================================================
//
// postgres_store.go implements Store and LifecyclePolicyStore backed by
// PostgreSQL using pgx/v5. This is the persistent storage backend for
// Professional and Enterprise tiers.
//
// Architecture:
//
//   - Connection pooling via shared pgxpool.Pool (NOT owned by this store)
//   - JSONB storage for complex fields (tools, tags, protocols,
//     discovery_sources)
//   - Indexed queries for status, tenant, owner, and protocol lookups
//   - INSERT ON CONFLICT for upsert semantics
//   - RLS policies for tenant isolation (admin bypass OR matching tenant_id)
//
// Lifecycle:
//
//   The pool is shared with the IOC PostgresStore or the persistence
//   manager. Schema creation is handled by ensureSchema() at construction
//   time (idempotent — safe to call on every startup).
//
// Thread safety:
//
//   All pgxpool operations are safe for concurrent use.
//
// RLS (Row-Level Security):
//
//   All pool access is wrapped with ioc.WithTenantContextOrPool so that
//   PostgreSQL RLS policies fire when tenant context is available.
//
// Air-gap compliance: The PostgreSQL store is an OPTIONAL backend. When
// PostgreSQL is not available, the in-memory store (memory_store.go)
// provides full functionality with no external dependencies. The store
// selection happens at wiring time in main.go.
// =========================================================================

package agentregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// Compile-time interface compliance checks.
var (
	_ Store               = (*PostgresStore)(nil)
	_ LifecyclePolicyStore = (*PostgresPolicyStore)(nil)
)

// =====================================================================
// PostgresStore — AgentRecord persistence
// =====================================================================

// PostgresStore implements Store backed by PostgreSQL.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a new PostgreSQL-backed agent registry store.
// It creates the agent_registry table if it doesn't exist.
func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	s := &PostgresStore{pool: pool}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("agentregistry: schema: %w", err)
	}
	return s, nil
}

// ensureSchema creates the agent_registry table with RLS policies.
func (s *PostgresStore) ensureSchema(ctx context.Context) error {
	return ioc.WithTenantContextOrPool(ctx, s.pool, "", true, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS agent_registry (
				id              TEXT PRIMARY KEY,
				name            TEXT NOT NULL DEFAULT '',
				description     TEXT NOT NULL DEFAULT '',
				role            TEXT NOT NULL DEFAULT '',
				tools           JSONB NOT NULL DEFAULT '[]'::jsonb,
				enabled         BOOLEAN NOT NULL DEFAULT TRUE,
				tenant_id       TEXT NOT NULL DEFAULT '',
				status          TEXT NOT NULL DEFAULT 'provisioned',
				status_since    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				owner           TEXT NOT NULL DEFAULT '',
				tags            JSONB NOT NULL DEFAULT '{}'::jsonb,
				protocols       JSONB NOT NULL DEFAULT '[]'::jsonb,
				last_activity   TIMESTAMPTZ,
				active_sessions INTEGER NOT NULL DEFAULT 0,
				total_events    BIGINT NOT NULL DEFAULT 0,
				dormant_since   TIMESTAMPTZ,
				credential_expiry TIMESTAMPTZ,
				last_intent     TEXT NOT NULL DEFAULT '',
				last_intent_at  TIMESTAMPTZ,
				intent_count    BIGINT NOT NULL DEFAULT 0,
				in_aibom        BOOLEAN NOT NULL DEFAULT FALSE,
				aibom_drift     TEXT NOT NULL DEFAULT '',
				discovery_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
				first_seen      TIMESTAMPTZ,
				last_seen       TIMESTAMPTZ,
				created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);

			CREATE INDEX IF NOT EXISTS idx_agent_registry_status ON agent_registry (status);
			CREATE INDEX IF NOT EXISTS idx_agent_registry_tenant ON agent_registry (tenant_id);
			CREATE INDEX IF NOT EXISTS idx_agent_registry_owner ON agent_registry (owner);
			CREATE INDEX IF NOT EXISTS idx_agent_registry_protocol ON agent_registry USING GIN (protocols);

			ALTER TABLE agent_registry ENABLE ROW LEVEL SECURITY;
			ALTER TABLE agent_registry FORCE ROW LEVEL SECURITY;

			DROP POLICY IF EXISTS agent_registry_tenant_isolation ON agent_registry;
			CREATE POLICY agent_registry_tenant_isolation ON agent_registry
				USING (
					current_setting('app.tenant_id', true) = ''
					OR tenant_id = current_setting('app.tenant_id', true)
				);

			DROP POLICY IF EXISTS agent_registry_admin_bypass ON agent_registry;
			CREATE POLICY agent_registry_admin_bypass ON agent_registry
				USING (
					current_setting('app.is_admin', true) = 'true'
				);
		`)
		return err
	})
}

// Get returns a single agent record by ID.
func (s *PostgresStore) Get(ctx context.Context, agentID string) (*AgentRecord, error) {
	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)

	var record AgentRecord
	var toolsJSON, tagsJSON, protocolsJSON, discoverySourcesJSON []byte
	var lastActivity, dormantSince, credentialExpiry, lastIntentAt, firstSeen, lastSeen *time.Time

	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		return q.QueryRow(ctx, `
			SELECT id, name, description, role, tools, enabled, tenant_id,
			       status, status_since, owner, tags, protocols,
			       last_activity, active_sessions, total_events,
			       dormant_since, credential_expiry,
			       last_intent, last_intent_at, intent_count,
			       in_aibom, aibom_drift, discovery_sources,
			       first_seen, last_seen, created_at, updated_at
			FROM agent_registry
			WHERE id = $1
		`, agentID).Scan(
			&record.ID, &record.Name, &record.Description, &record.Role,
			&toolsJSON, &record.Enabled, &record.TenantID,
			&record.Status, &record.StatusSince, &record.Owner,
			&tagsJSON, &protocolsJSON,
			&lastActivity, &record.ActiveSessions, &record.TotalEvents,
			&dormantSince, &credentialExpiry,
			&record.LastIntent, &lastIntentAt, &record.IntentCount,
			&record.InAIBOM, &record.AIBOMDrift, &discoverySourcesJSON,
			&firstSeen, &lastSeen, &record.CreatedAt, &record.UpdatedAt,
		)
	})
	if err != nil {
		return nil, mapPGError(err)
	}

	// Deserialize JSONB fields.
	if err := json.Unmarshal(toolsJSON, &record.Tools); err != nil {
		return nil, fmt.Errorf("agentregistry: unmarshal tools: %w", err)
	}
	if err := json.Unmarshal(tagsJSON, &record.Tags); err != nil {
		return nil, fmt.Errorf("agentregistry: unmarshal tags: %w", err)
	}
	if err := json.Unmarshal(protocolsJSON, &record.Protocols); err != nil {
		return nil, fmt.Errorf("agentregistry: unmarshal protocols: %w", err)
	}
	if err := json.Unmarshal(discoverySourcesJSON, &record.DiscoverySources); err != nil {
		return nil, fmt.Errorf("agentregistry: unmarshal discovery_sources: %w", err)
	}

	// Unpack nullable timestamps.
	if lastActivity != nil {
		record.LastActivity = *lastActivity
	}
	if dormantSince != nil {
		record.DormantSince = *dormantSince
	}
	if credentialExpiry != nil {
		record.CredentialExpiry = *credentialExpiry
	}
	if lastIntentAt != nil {
		record.LastIntentAt = *lastIntentAt
	}
	if firstSeen != nil {
		record.FirstSeen = *firstSeen
	}
	if lastSeen != nil {
		record.LastSeen = *lastSeen
	}

	return &record, nil
}

// List returns all agent records matching the given filter.
func (s *PostgresStore) List(ctx context.Context, filter *ListFilter) ([]*AgentRecord, error) {
	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)

	// Build query with optional filters.
	query := `
		SELECT id, name, description, role, tools, enabled, tenant_id,
		       status, status_since, owner, tags, protocols,
		       last_activity, active_sessions, total_events,
		       dormant_since, credential_expiry,
		       last_intent, last_intent_at, intent_count,
		       in_aibom, aibom_drift, discovery_sources,
		       first_seen, last_seen, created_at, updated_at
		FROM agent_registry
	`
	args := []interface{}{}
	argIdx := 1
	conditions := []string{}

	if filter != nil {
		if filter.Status != "" {
			conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
			args = append(args, string(filter.Status))
			argIdx++
		}
		if filter.Owner != "" {
			conditions = append(conditions, fmt.Sprintf("owner = $%d", argIdx))
			args = append(args, filter.Owner)
			argIdx++
		}
		if filter.TenantID != "" {
			conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
			args = append(args, filter.TenantID)
			argIdx++
		}
		if filter.Protocol != "" {
			conditions = append(conditions, fmt.Sprintf("protocols @> $%d::jsonb", argIdx))
			protoJSON, _ := json.Marshal([]string{string(filter.Protocol)})
			args = append(args, protoJSON)
			argIdx++
		}
	}

	if len(conditions) > 0 {
		query += " WHERE " + joinStrings(conditions, " AND ")
	}
	query += " ORDER BY updated_at DESC"

	var records []*AgentRecord

	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		rows, queryErr := q.Query(ctx, query, args...)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()

		for rows.Next() {
			record := &AgentRecord{}
			var toolsJSON, tagsJSON, protocolsJSON, discoverySourcesJSON []byte
			var lastActivity, dormantSince, credentialExpiry, lastIntentAt, firstSeen, lastSeen *time.Time

			if err := rows.Scan(
				&record.ID, &record.Name, &record.Description, &record.Role,
				&toolsJSON, &record.Enabled, &record.TenantID,
				&record.Status, &record.StatusSince, &record.Owner,
				&tagsJSON, &protocolsJSON,
				&lastActivity, &record.ActiveSessions, &record.TotalEvents,
				&dormantSince, &credentialExpiry,
				&record.LastIntent, &lastIntentAt, &record.IntentCount,
				&record.InAIBOM, &record.AIBOMDrift, &discoverySourcesJSON,
				&firstSeen, &lastSeen, &record.CreatedAt, &record.UpdatedAt,
			); err != nil {
				return fmt.Errorf("agentregistry: scan row: %w", err)
			}

			// Deserialize JSONB fields.
			_ = json.Unmarshal(toolsJSON, &record.Tools)
			_ = json.Unmarshal(tagsJSON, &record.Tags)
			_ = json.Unmarshal(protocolsJSON, &record.Protocols)
			_ = json.Unmarshal(discoverySourcesJSON, &record.DiscoverySources)

			if lastActivity != nil {
				record.LastActivity = *lastActivity
			}
			if dormantSince != nil {
				record.DormantSince = *dormantSince
			}
			if credentialExpiry != nil {
				record.CredentialExpiry = *credentialExpiry
			}
			if lastIntentAt != nil {
				record.LastIntentAt = *lastIntentAt
			}
			if firstSeen != nil {
				record.FirstSeen = *firstSeen
			}
			if lastSeen != nil {
				record.LastSeen = *lastSeen
			}

			records = append(records, record)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if records == nil {
		records = []*AgentRecord{}
	}
	return records, nil
}

// Upsert creates or updates a record.
func (s *PostgresStore) Upsert(ctx context.Context, record *AgentRecord) error {
	tenantID := record.TenantID
	isAdmin := tenantID == ""

	toolsJSON, _ := json.Marshal(record.Tools)
	tagsJSON, _ := json.Marshal(record.Tags)
	protocolsJSON, _ := json.Marshal(record.Protocols)
	discoverySourcesJSON, _ := json.Marshal(record.DiscoverySources)

	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO agent_registry (
				id, name, description, role, tools, enabled, tenant_id,
				status, status_since, owner, tags, protocols,
				last_activity, active_sessions, total_events,
				dormant_since, credential_expiry,
				last_intent, last_intent_at, intent_count,
				in_aibom, aibom_drift, discovery_sources,
				first_seen, last_seen, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7,
				$8, $9, $10, $11, $12,
				$13, $14, $15,
				$16, $17,
				$18, $19, $20,
				$21, $22, $23,
				$24, $25, $26, $27
			)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				role = EXCLUDED.role,
				tools = EXCLUDED.tools,
				enabled = EXCLUDED.enabled,
				tenant_id = EXCLUDED.tenant_id,
				status = EXCLUDED.status,
				status_since = EXCLUDED.status_since,
				owner = EXCLUDED.owner,
				tags = EXCLUDED.tags,
				protocols = EXCLUDED.protocols,
				last_activity = EXCLUDED.last_activity,
				active_sessions = EXCLUDED.active_sessions,
				total_events = EXCLUDED.total_events,
				dormant_since = EXCLUDED.dormant_since,
				credential_expiry = EXCLUDED.credential_expiry,
				last_intent = EXCLUDED.last_intent,
				last_intent_at = EXCLUDED.last_intent_at,
				intent_count = EXCLUDED.intent_count,
				in_aibom = EXCLUDED.in_aibom,
				aibom_drift = EXCLUDED.aibom_drift,
				discovery_sources = EXCLUDED.discovery_sources,
				first_seen = EXCLUDED.first_seen,
				last_seen = EXCLUDED.last_seen,
				updated_at = EXCLUDED.updated_at
		`,
			record.ID, record.Name, record.Description, record.Role,
			toolsJSON, record.Enabled, record.TenantID,
			string(record.Status), record.StatusSince, record.Owner,
			tagsJSON, protocolsJSON,
			nullTime(record.LastActivity), record.ActiveSessions, record.TotalEvents,
			nullTime(record.DormantSince), nullTime(record.CredentialExpiry),
			record.LastIntent, nullTime(record.LastIntentAt), record.IntentCount,
			record.InAIBOM, record.AIBOMDrift, discoverySourcesJSON,
			nullTime(record.FirstSeen), nullTime(record.LastSeen),
			record.CreatedAt, record.UpdatedAt,
		)
		return err
	})
}

// Delete removes a record from the store.
func (s *PostgresStore) Delete(ctx context.Context, agentID string) error {
	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)

	var affected int64
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		tag, err := q.Exec(ctx, `DELETE FROM agent_registry WHERE id = $1`, agentID)
		if err != nil {
			return err
		}
		affected = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// Close is a no-op — the pool lifecycle is managed externally.
func (s *PostgresStore) Close() error { return nil }

// =====================================================================
// PostgresPolicyStore — LifecyclePolicy persistence
// =====================================================================

// PostgresPolicyStore implements LifecyclePolicyStore backed by PostgreSQL.
type PostgresPolicyStore struct {
	pool *pgxpool.Pool
}

// NewPostgresPolicyStore creates a new PostgreSQL-backed policy store.
func NewPostgresPolicyStore(pool *pgxpool.Pool) (*PostgresPolicyStore, error) {
	s := &PostgresPolicyStore{pool: pool}
	if err := s.ensureSchema(context.Background()); err != nil {
		return nil, fmt.Errorf("agentregistry: policy schema: %w", err)
	}
	return s, nil
}

func (s *PostgresPolicyStore) ensureSchema(ctx context.Context) error {
	return ioc.WithTenantContextOrPool(ctx, s.pool, "", true, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS agent_lifecycle_policies (
				id              TEXT PRIMARY KEY,
				name            TEXT NOT NULL,
				description     TEXT NOT NULL DEFAULT '',
				enabled         BOOLEAN NOT NULL DEFAULT TRUE,
				dormancy_threshold   BIGINT NOT NULL,
				auto_revoke_threshold BIGINT NOT NULL DEFAULT 0,
				quarantine_threshold  BIGINT NOT NULL DEFAULT 0,
				credential_expiry_warning BIGINT NOT NULL DEFAULT 0,
				on_dormant       JSONB NOT NULL DEFAULT '[]'::jsonb,
				on_quarantine    JSONB NOT NULL DEFAULT '[]'::jsonb,
				on_revoke        JSONB NOT NULL DEFAULT '[]'::jsonb,
				filters          JSONB NOT NULL DEFAULT '{}'::jsonb,
				tenant_id        TEXT NOT NULL DEFAULT '',
				created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);

			CREATE INDEX IF NOT EXISTS idx_agent_policies_tenant ON agent_lifecycle_policies (tenant_id);
			CREATE INDEX IF NOT EXISTS idx_agent_policies_enabled ON agent_lifecycle_policies (enabled);

			ALTER TABLE agent_lifecycle_policies ENABLE ROW LEVEL SECURITY;
			ALTER TABLE agent_lifecycle_policies FORCE ROW LEVEL SECURITY;

			DROP POLICY IF EXISTS agent_policies_tenant_isolation ON agent_lifecycle_policies;
			CREATE POLICY agent_policies_tenant_isolation ON agent_lifecycle_policies
				USING (
					current_setting('app.tenant_id', true) = ''
					OR tenant_id = current_setting('app.tenant_id', true)
				);

			DROP POLICY IF EXISTS agent_policies_admin_bypass ON agent_lifecycle_policies;
			CREATE POLICY agent_policies_admin_bypass ON agent_lifecycle_policies
				USING (
					current_setting('app.is_admin', true) = 'true'
				);
		`)
		return err
	})
}

// GetPolicy returns a single policy by ID.
func (s *PostgresPolicyStore) GetPolicy(ctx context.Context, policyID string) (*LifecyclePolicy, error) {
	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)

	var policy LifecyclePolicy
	var onDormantJSON, onQuarantineJSON, onRevokeJSON, filtersJSON []byte

	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		return q.QueryRow(ctx, `
			SELECT id, name, description, enabled,
			       dormancy_threshold, auto_revoke_threshold,
			       quarantine_threshold, credential_expiry_warning,
			       on_dormant, on_quarantine, on_revoke, filters,
			       tenant_id, created_at, updated_at
			FROM agent_lifecycle_policies
			WHERE id = $1
		`, policyID).Scan(
			&policy.ID, &policy.Name, &policy.Description, &policy.Enabled,
			&policy.DormancyThreshold, &policy.AutoRevokeThreshold,
			&policy.QuarantineThreshold, &policy.CredentialExpiryWarning,
			&onDormantJSON, &onQuarantineJSON, &onRevokeJSON, &filtersJSON,
			&policy.TenantID, &policy.CreatedAt, &policy.UpdatedAt,
		)
	})
	if err != nil {
		return nil, mapPGError(err)
	}

	_ = json.Unmarshal(onDormantJSON, &policy.OnDormant)
	_ = json.Unmarshal(onQuarantineJSON, &policy.OnQuarantine)
	_ = json.Unmarshal(onRevokeJSON, &policy.OnRevoke)
	_ = json.Unmarshal(filtersJSON, &policy.Filters)

	return &policy, nil
}

// ListPolicies returns all lifecycle policies.
func (s *PostgresPolicyStore) ListPolicies(ctx context.Context) ([]*LifecyclePolicy, error) {
	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)

	var policies []*LifecyclePolicy

	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		rows, queryErr := q.Query(ctx, `
			SELECT id, name, description, enabled,
			       dormancy_threshold, auto_revoke_threshold,
			       quarantine_threshold, credential_expiry_warning,
			       on_dormant, on_quarantine, on_revoke, filters,
			       tenant_id, created_at, updated_at
			FROM agent_lifecycle_policies
			ORDER BY created_at ASC
		`)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()

		for rows.Next() {
			policy := &LifecyclePolicy{}
			var onDormantJSON, onQuarantineJSON, onRevokeJSON, filtersJSON []byte

			if err := rows.Scan(
				&policy.ID, &policy.Name, &policy.Description, &policy.Enabled,
				&policy.DormancyThreshold, &policy.AutoRevokeThreshold,
				&policy.QuarantineThreshold, &policy.CredentialExpiryWarning,
				&onDormantJSON, &onQuarantineJSON, &onRevokeJSON, &filtersJSON,
				&policy.TenantID, &policy.CreatedAt, &policy.UpdatedAt,
			); err != nil {
				return fmt.Errorf("agentregistry: scan policy row: %w", err)
			}

			_ = json.Unmarshal(onDormantJSON, &policy.OnDormant)
			_ = json.Unmarshal(onQuarantineJSON, &policy.OnQuarantine)
			_ = json.Unmarshal(onRevokeJSON, &policy.OnRevoke)
			_ = json.Unmarshal(filtersJSON, &policy.Filters)

			policies = append(policies, policy)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if policies == nil {
		policies = []*LifecyclePolicy{}
	}
	return policies, nil
}

// UpsertPolicy creates or updates a policy.
func (s *PostgresPolicyStore) UpsertPolicy(ctx context.Context, policy *LifecyclePolicy) error {
	tenantID := policy.TenantID
	isAdmin := tenantID == ""

	onDormantJSON, _ := json.Marshal(policy.OnDormant)
	onQuarantineJSON, _ := json.Marshal(policy.OnQuarantine)
	onRevokeJSON, _ := json.Marshal(policy.OnRevoke)
	filtersJSON, _ := json.Marshal(policy.Filters)

	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO agent_lifecycle_policies (
				id, name, description, enabled,
				dormancy_threshold, auto_revoke_threshold,
				quarantine_threshold, credential_expiry_warning,
				on_dormant, on_quarantine, on_revoke, filters,
				tenant_id, created_at, updated_at
			) VALUES (
				$1, $2, $3, $4,
				$5, $6,
				$7, $8,
				$9, $10, $11, $12,
				$13, $14, $15
			)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				enabled = EXCLUDED.enabled,
				dormancy_threshold = EXCLUDED.dormancy_threshold,
				auto_revoke_threshold = EXCLUDED.auto_revoke_threshold,
				quarantine_threshold = EXCLUDED.quarantine_threshold,
				credential_expiry_warning = EXCLUDED.credential_expiry_warning,
				on_dormant = EXCLUDED.on_dormant,
				on_quarantine = EXCLUDED.on_quarantine,
				on_revoke = EXCLUDED.on_revoke,
				filters = EXCLUDED.filters,
				tenant_id = EXCLUDED.tenant_id,
				updated_at = EXCLUDED.updated_at
		`,
			policy.ID, policy.Name, policy.Description, policy.Enabled,
			int64(policy.DormancyThreshold), int64(policy.AutoRevokeThreshold),
			int64(policy.QuarantineThreshold), int64(policy.CredentialExpiryWarning),
			onDormantJSON, onQuarantineJSON, onRevokeJSON, filtersJSON,
			policy.TenantID, policy.CreatedAt, policy.UpdatedAt,
		)
		return err
	})
}

// DeletePolicy removes a policy from the store.
func (s *PostgresPolicyStore) DeletePolicy(ctx context.Context, policyID string) error {
	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)

	var affected int64
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		tag, err := q.Exec(ctx, `DELETE FROM agent_lifecycle_policies WHERE id = $1`, policyID)
		if err != nil {
			return err
		}
		affected = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// Close is a no-op — the pool lifecycle is managed externally.
func (s *PostgresPolicyStore) Close() error { return nil }

// =====================================================================
// Helpers
// =====================================================================

// nullTime returns a pointer to t if t is non-zero, or nil if t is zero.
// This allows pgx to insert NULL for zero-value time.Time fields.
func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

// mapPGError maps pgx errors to agentregistry errors.
func mapPGError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "no rows") {
		return ErrNotFound
	}
	return err
}

// joinStrings joins strings with a separator.
func joinStrings(parts []string, sep string) string {
	return strings.Join(parts, sep)
}