// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Incident Response PostgreSQL Stores (v3.8 Persistence)
// =========================================================================
//
// postgres_store.go implements IncidentStore, PlaybookStore, and
// DetectionRuleStore backed by PostgreSQL using pgx/v5. These are the
// persistent storage backends for Professional and Enterprise tiers.
//
// Architecture:
//
//   - Connection pooling via shared pgxpool.Pool (NOT owned by these stores)
//   - JSONB storage for complex fields (tags, metadata, compliance_mappings,
//     correlation_event_ids, steps, step_results, patterns, event_types)
//   - Indexed queries for status, severity, agent, session, tenant, and
//     time-window lookups
//   - INSERT ON CONFLICT for upsert semantics on Update methods
//   - Cascading deletes for playbook_runs when incidents are deleted
//
// Lifecycle:
//
//   The pool is shared with the IOC PostgresStore or the persistence manager.
//   Migrations are run by the shared migration runner (pkg/ioc/migrations/),
//   NOT by these constructors. Callers must ensure migrations have been applied
//   before using these stores. Migration 007 creates the incidents, playbook_runs,
//   detection_rules, and playbooks tables.
//
// Thread safety:
//
//   All pgxpool operations are safe for concurrent use. The pool manages
//   its own connection lifecycle. The caller does NOT need to hold any
//   additional locks.
//
// RLS (Row-Level Security):
//
//   All pool access is wrapped with ioc.WithTenantContextOrPool so that
//   PostgreSQL RLS policies fire when tenant context is available.
//   Tenant context is extracted from the request context via the auth
//   package, or from the domain object (e.g. incident.TenantID) when
//   the caller already carries it.
//
// Tier gating: FeaturePostgreSQL is required (Professional/Enterprise).
// Community/Developer continue using the in-memory stores.
//
// v3.8 persistence gap closure.
// =========================================================================

package incident

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// Compile-time interface compliance checks.
var (
	_ IncidentStore      = (*PostgresIncidentStore)(nil)
	_ PlaybookStore      = (*PostgresPlaybookStore)(nil)
	_ DetectionRuleStore = (*PostgresDetectionRuleStore)(nil)
)

// =====================================================================
// PostgresIncidentStore
// =====================================================================

// PostgresIncidentStore implements IncidentStore backed by PostgreSQL.
// It shares a connection pool with other PostgreSQL-backed components.
// The pool lifecycle is managed externally (by ioc.PostgresStore or
// the persistence manager).
type PostgresIncidentStore struct {
	pool *pgxpool.Pool
}

// NewPostgresIncidentStore creates a new PostgresIncidentStore using
// the provided pool. The pool is NOT owned by this store; the caller
// is responsible for pool lifecycle (including Close).
//
// Migrations are NOT run here — they are handled by the shared migration
// runner in pkg/ioc/migrations/ (migration 007_incident.sql).
func NewPostgresIncidentStore(pool *pgxpool.Pool) *PostgresIncidentStore {
	return &PostgresIncidentStore{pool: pool}
}

// CreateIncident persists a new incident. Returns an error if an
// incident with the same ID already exists.
func (s *PostgresIncidentStore) CreateIncident(ctx context.Context, incident *Incident) error {
	if incident == nil {
		return fmt.Errorf("incident: CreateIncident: nil incident")
	}
	if incident.ID == "" {
		return fmt.Errorf("incident: CreateIncident: empty ID")
	}

	tagsArray := incident.Tags
	if tagsArray == nil {
		tagsArray = []string{}
	}

	// Merge transient fields (CorrelationEventIDs, ComplianceMappings,
	// PlaybookRuns) into the metadata JSONB column since the incidents
	// table does not have dedicated columns for them.
	metadata := make(map[string]string)
	for k, v := range incident.Metadata {
		metadata[k] = v
	}
	if len(incident.CorrelationEventIDs) > 0 {
		idsJSON, _ := json.Marshal(incident.CorrelationEventIDs)
		metadata["_correlation_event_ids"] = string(idsJSON)
	}
	if len(incident.ComplianceMappings) > 0 {
		mappingsJSON, _ := json.Marshal(incident.ComplianceMappings)
		metadata["_compliance_mappings"] = string(mappingsJSON)
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("incident: marshal metadata: %w", err)
	}

	tenantID := incident.TenantID
	isAdmin := auth.IsAdmin(ctx)
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO incidents (
				id, title, description, severity, status, source,
				session_id, agent_id, playbook_id,
				escalation_policy_id, escalated_to, assignee,
				escalated_at, resolved_at, closed_at,
				tags, metadata, tenant_id,
				created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
			incident.ID, incident.Title, incident.Description,
			string(incident.Severity), string(incident.Status), string(incident.Source),
			incident.SessionID, incident.AgentID, incident.PlaybookID,
			incident.EscalationPolicyID, incident.EscalatedTo, incident.Assignee,
			nullTime(incident.EscalatedAt), nullTime(incident.ResolvedAt), nullTime(incident.ClosedAt),
			tagsArray, metadataJSON, incident.TenantID,
			incident.CreatedAt, incident.UpdatedAt,
		)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "violates unique constraint") {
				return fmt.Errorf("incident: CreateIncident: incident %s already exists", incident.ID)
			}
			return fmt.Errorf("incident: CreateIncident: %w", err)
		}

		// Persist playbook runs as separate rows if any are present.
		for _, run := range incident.PlaybookRuns {
			if err := s.createPlaybookRun(ctx, q, run, incident.ID, incident.TenantID); err != nil {
				// Log but don't fail — incident is already persisted.
				_ = err
			}
		}

		return nil
	})
}

// GetIncident retrieves an incident by ID. Returns nil if not found.
func (s *PostgresIncidentStore) GetIncident(ctx context.Context, id string) (*Incident, error) {
	if id == "" {
		return nil, fmt.Errorf("incident: GetIncident: empty ID")
	}

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	var result *Incident
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		row := q.QueryRow(ctx,
			`SELECT id, title, description, severity, status, source,
				session_id, agent_id, playbook_id,
				escalation_policy_id, escalated_to, assignee,
				escalated_at, resolved_at, closed_at,
				tags, metadata, tenant_id,
				created_at, updated_at
			FROM incidents WHERE id = $1`,
			id,
		)

		inc, err := scanIncident(row)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil
			}
			return fmt.Errorf("incident: GetIncident: %w", err)
		}

		// Load playbook runs for this incident.
		runs, err := s.listPlaybookRunsByIncident(ctx, q, id)
		if err != nil {
			// Non-fatal: return the incident without runs.
			inc.PlaybookRuns = []*PlaybookRun{}
		} else {
			inc.PlaybookRuns = runs
		}

		result = inc
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// UpdateIncident updates an existing incident. Returns an error if
// the incident does not exist.
func (s *PostgresIncidentStore) UpdateIncident(ctx context.Context, incident *Incident) error {
	if incident == nil {
		return fmt.Errorf("incident: UpdateIncident: nil incident")
	}
	if incident.ID == "" {
		return fmt.Errorf("incident: UpdateIncident: empty ID")
	}

	tagsArray := incident.Tags
	if tagsArray == nil {
		tagsArray = []string{}
	}

	// Merge transient fields into metadata.
	metadata := make(map[string]string)
	for k, v := range incident.Metadata {
		metadata[k] = v
	}
	if len(incident.CorrelationEventIDs) > 0 {
		idsJSON, _ := json.Marshal(incident.CorrelationEventIDs)
		metadata["_correlation_event_ids"] = string(idsJSON)
	}
	if len(incident.ComplianceMappings) > 0 {
		mappingsJSON, _ := json.Marshal(incident.ComplianceMappings)
		metadata["_compliance_mappings"] = string(mappingsJSON)
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("incident: marshal metadata: %w", err)
	}

	tenantID := incident.TenantID
	isAdmin := auth.IsAdmin(ctx)
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		tag, err := q.Exec(ctx,
			`UPDATE incidents SET
				title = $2, description = $3, severity = $4, status = $5, source = $6,
				session_id = $7, agent_id = $8, playbook_id = $9,
				escalation_policy_id = $10, escalated_to = $11, assignee = $12,
				escalated_at = $13, resolved_at = $14, closed_at = $15,
				tags = $16, metadata = $17, tenant_id = $18,
				updated_at = $19
			WHERE id = $1`,
			incident.ID, incident.Title, incident.Description,
			string(incident.Severity), string(incident.Status), string(incident.Source),
			incident.SessionID, incident.AgentID, incident.PlaybookID,
			incident.EscalationPolicyID, incident.EscalatedTo, incident.Assignee,
			nullTime(incident.EscalatedAt), nullTime(incident.ResolvedAt), nullTime(incident.ClosedAt),
			tagsArray, metadataJSON, incident.TenantID,
			incident.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("incident: UpdateIncident: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("incident: UpdateIncident: incident %s not found", incident.ID)
		}

		return nil
	})
}

// ListIncidents queries incidents using filter criteria.
// Returns an empty slice (not nil) if no incidents match.
func (s *PostgresIncidentStore) ListIncidents(ctx context.Context, query *IncidentQuery) ([]*Incident, error) {
	if query == nil {
		query = &IncidentQuery{}
	}

	// Build dynamic WHERE clause.
	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if len(query.Status) > 0 {
		placeholders := make([]string, len(query.Status))
		for i, s := range query.Status {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, string(s))
			argIdx++
		}
		where = append(where, "status IN ("+strings.Join(placeholders, ", ")+")")
	}

	if len(query.Severity) > 0 {
		placeholders := make([]string, len(query.Severity))
		for i, sev := range query.Severity {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, string(sev))
			argIdx++
		}
		where = append(where, "severity IN ("+strings.Join(placeholders, ", ")+")")
	}

	if len(query.Source) > 0 {
		placeholders := make([]string, len(query.Source))
		for i, src := range query.Source {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, string(src))
			argIdx++
		}
		where = append(where, "source IN ("+strings.Join(placeholders, ", ")+")")
	}

	if query.AgentID != "" {
		where = append(where, fmt.Sprintf("agent_id = $%d", argIdx))
		args = append(args, query.AgentID)
		argIdx++
	}

	if query.SessionID != "" {
		where = append(where, fmt.Sprintf("session_id = $%d", argIdx))
		args = append(args, query.SessionID)
		argIdx++
	}

	if query.TenantID != "" {
		where = append(where, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, query.TenantID)
		argIdx++
	}

	if !query.From.IsZero() {
		where = append(where, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, query.From)
		argIdx++
	}

	if !query.To.IsZero() {
		where = append(where, fmt.Sprintf("created_at <= $%d", argIdx))
		args = append(args, query.To)
		argIdx++
	}

	// Tags filter: all query tags must be present.
	if len(query.Tags) > 0 {
		where = append(where, fmt.Sprintf("tags @> $%d", argIdx))
		tagsJSON, _ := json.Marshal(query.Tags)
		args = append(args, tagsJSON)
		argIdx++
	}

	sql := fmt.Sprintf(
		`SELECT id, title, description, severity, status, source,
			session_id, agent_id, playbook_id,
			escalation_policy_id, escalated_to, assignee,
			escalated_at, resolved_at, closed_at,
			tags, metadata, tenant_id,
			created_at, updated_at
		FROM incidents WHERE %s
		ORDER BY created_at DESC`,
		strings.Join(where, " AND "),
	)

	// Apply LIMIT and OFFSET.
	if query.Limit > 0 {
		sql += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, query.Limit)
		argIdx++
	}
	if query.Offset > 0 {
		sql += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, query.Offset)
		argIdx++
	}

	tenantID := query.TenantID
	if tenantID == "" {
		tenantID = auth.GetTenantID(ctx)
	}
	isAdmin := auth.IsAdmin(ctx)
	var incidents []*Incident
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("incident: ListIncidents: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			inc, err := scanIncidentFromRows(rows)
			if err != nil {
				return fmt.Errorf("incident: scan incident: %w", err)
			}
			incidents = append(incidents, inc)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("incident: ListIncidents rows: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if incidents == nil {
		incidents = []*Incident{}
	}

	return incidents, nil
}

// Close is a no-op. The pool is shared and its lifecycle is managed
// externally (by the IOC PostgresStore or persistence manager).
func (s *PostgresIncidentStore) Close() error { return nil }

// =====================================================================
// PostgresIncidentStore — Playbook Run helpers
// =====================================================================

// createPlaybookRun persists a single playbook run for an incident.
// The q parameter allows the caller to pass a tenant-scoped DBQuerier
// (from WithTenantContextOrPool) so that RLS policies fire consistently.
func (s *PostgresIncidentStore) createPlaybookRun(ctx context.Context, q ioc.DBQuerier, run *PlaybookRun, incidentID, tenantID string) error {
	if run == nil {
		return nil
	}
	stepResultsJSON, err := json.Marshal(run.StepResults)
	if err != nil {
		stepResultsJSON = []byte("[]")
	}

	_, err = q.Exec(ctx,
		`INSERT INTO playbook_runs (
			id, playbook_id, incident_id, status, error,
			started_at, completed_at, step_results, tenant_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		run.ID, run.PlaybookID, incidentID, run.Status, run.Error,
		run.StartedAt, nullTime(run.CompletedAt), stepResultsJSON, tenantID,
	)
	if err != nil {
		return fmt.Errorf("incident: create playbook run: %w", err)
	}
	return nil
}

// listPlaybookRunsByIncident loads all playbook runs for an incident.
// The q parameter allows the caller to pass a tenant-scoped DBQuerier
// (from WithTenantContextOrPool) so that RLS policies fire consistently.
func (s *PostgresIncidentStore) listPlaybookRunsByIncident(ctx context.Context, q ioc.DBQuerier, incidentID string) ([]*PlaybookRun, error) {
	rows, err := q.Query(ctx,
		`SELECT id, playbook_id, incident_id, status, error,
			started_at, completed_at, step_results
		FROM playbook_runs WHERE incident_id = $1
		ORDER BY started_at ASC`,
		incidentID,
	)
	if err != nil {
		return nil, fmt.Errorf("incident: list playbook runs: %w", err)
	}
	defer rows.Close()

	var runs []*PlaybookRun
	for rows.Next() {
		var run PlaybookRun
		var stepResultsJSON []byte
		var completedAt *time.Time

		if err := rows.Scan(
			&run.ID, &run.PlaybookID, &run.IncidentID, &run.Status, &run.Error,
			&run.StartedAt, &completedAt, &stepResultsJSON,
		); err != nil {
			return nil, fmt.Errorf("incident: scan playbook run: %w", err)
		}

		if completedAt != nil {
			run.CompletedAt = *completedAt
		}

		if err := json.Unmarshal(stepResultsJSON, &run.StepResults); err != nil {
			run.StepResults = []*StepResult{}
		}

		runs = append(runs, &run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("incident: list playbook runs rows: %w", err)
	}

	if runs == nil {
		runs = []*PlaybookRun{}
	}
	return runs, nil
}

// =====================================================================
// PostgresPlaybookStore
// =====================================================================

// PostgresPlaybookStore implements PlaybookStore backed by PostgreSQL.
type PostgresPlaybookStore struct {
	pool *pgxpool.Pool
}

// NewPostgresPlaybookStore creates a new PostgresPlaybookStore using
// the provided pool. The pool is NOT owned by this store.
func NewPostgresPlaybookStore(pool *pgxpool.Pool) *PostgresPlaybookStore {
	return &PostgresPlaybookStore{pool: pool}
}

// CreatePlaybook persists a new playbook.
func (s *PostgresPlaybookStore) CreatePlaybook(ctx context.Context, playbook *Playbook) error {
	if playbook == nil {
		return fmt.Errorf("incident: CreatePlaybook: nil playbook")
	}
	if playbook.ID == "" {
		return fmt.Errorf("incident: CreatePlaybook: empty ID")
	}

	stepsJSON, err := json.Marshal(playbook.Steps)
	if err != nil {
		return fmt.Errorf("incident: marshal steps: %w", err)
	}
	tagsArray := playbook.Tags
	if tagsArray == nil {
		tagsArray = []string{}
	}

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO playbooks (
				id, name, description, severity, source, tags, steps, auto_execute,
				created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			playbook.ID, playbook.Name, playbook.Description,
			string(playbook.Severity), string(playbook.Source),
			tagsArray, stepsJSON, playbook.AutoExecute,
			playbook.CreatedAt, playbook.UpdatedAt,
		)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "violates unique constraint") {
				return fmt.Errorf("incident: CreatePlaybook: playbook %s already exists", playbook.ID)
			}
			return fmt.Errorf("incident: CreatePlaybook: %w", err)
		}
		return nil
	})
}

// GetPlaybook retrieves a playbook by ID.
func (s *PostgresPlaybookStore) GetPlaybook(ctx context.Context, id string) (*Playbook, error) {
	if id == "" {
		return nil, fmt.Errorf("incident: GetPlaybook: empty ID")
	}

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	var result *Playbook
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		row := q.QueryRow(ctx,
			`SELECT id, name, description, severity, source, tags, steps, auto_execute,
				created_at, updated_at
			FROM playbooks WHERE id = $1`,
			id,
		)

		pb, err := scanPlaybook(row)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil
			}
			return fmt.Errorf("incident: GetPlaybook: %w", err)
		}
		result = pb
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListPlaybooks lists playbooks filtered by severity and source.
// Pass zero values to match all.
func (s *PostgresPlaybookStore) ListPlaybooks(ctx context.Context, severity IncidentSeverity, source IncidentSource) ([]*Playbook, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, string(severity))
		argIdx++
	}

	if source != "" {
		where = append(where, fmt.Sprintf("source = $%d", argIdx))
		args = append(args, string(source))
		argIdx++
	}

	sql := fmt.Sprintf(
		`SELECT id, name, description, severity, source, tags, steps, auto_execute,
			created_at, updated_at
		FROM playbooks WHERE %s
		ORDER BY name ASC`,
		strings.Join(where, " AND "),
	)

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	var playbooks []*Playbook
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("incident: ListPlaybooks: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			pb, err := scanPlaybookFromRows(rows)
			if err != nil {
				return fmt.Errorf("incident: scan playbook: %w", err)
			}
			playbooks = append(playbooks, pb)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("incident: ListPlaybooks rows: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if playbooks == nil {
		playbooks = []*Playbook{}
	}
	return playbooks, nil
}

// UpdatePlaybook updates an existing playbook.
func (s *PostgresPlaybookStore) UpdatePlaybook(ctx context.Context, playbook *Playbook) error {
	if playbook == nil {
		return fmt.Errorf("incident: UpdatePlaybook: nil playbook")
	}
	if playbook.ID == "" {
		return fmt.Errorf("incident: UpdatePlaybook: empty ID")
	}

	stepsJSON, err := json.Marshal(playbook.Steps)
	if err != nil {
		return fmt.Errorf("incident: marshal steps: %w", err)
	}
	tagsArray := playbook.Tags
	if tagsArray == nil {
		tagsArray = []string{}
	}

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		tag, err := q.Exec(ctx,
			`UPDATE playbooks SET
				name = $2, description = $3, severity = $4, source = $5,
				tags = $6, steps = $7, auto_execute = $8,
				updated_at = $9
			WHERE id = $1`,
			playbook.ID, playbook.Name, playbook.Description,
			string(playbook.Severity), string(playbook.Source),
			tagsArray, stepsJSON, playbook.AutoExecute,
			playbook.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("incident: UpdatePlaybook: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("incident: UpdatePlaybook: playbook %s not found", playbook.ID)
		}
		return nil
	})
}

// DeletePlaybook removes a playbook by ID.
func (s *PostgresPlaybookStore) DeletePlaybook(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("incident: DeletePlaybook: empty ID")
	}

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		tag, err := q.Exec(ctx, `DELETE FROM playbooks WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("incident: DeletePlaybook: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("incident: DeletePlaybook: playbook %s not found", id)
		}
		return nil
	})
}

// Close is a no-op. The pool is shared.
func (s *PostgresPlaybookStore) Close() error { return nil }

// =====================================================================
// PostgresDetectionRuleStore
// =====================================================================

// PostgresDetectionRuleStore implements DetectionRuleStore backed by PostgreSQL.
type PostgresDetectionRuleStore struct {
	pool *pgxpool.Pool
}

// NewPostgresDetectionRuleStore creates a new PostgresDetectionRuleStore
// using the provided pool. The pool is NOT owned by this store.
func NewPostgresDetectionRuleStore(pool *pgxpool.Pool) *PostgresDetectionRuleStore {
	return &PostgresDetectionRuleStore{pool: pool}
}

// CreateRule persists a new detection rule.
func (s *PostgresDetectionRuleStore) CreateRule(ctx context.Context, rule *DetectionRule) error {
	if rule == nil {
		return fmt.Errorf("incident: CreateRule: nil rule")
	}
	if rule.ID == "" {
		return fmt.Errorf("incident: CreateRule: empty ID")
	}

	patternsArray := rule.Patterns
	if patternsArray == nil {
		patternsArray = []string{}
	}
	eventTypesArray := rule.EventTypes
	if eventTypesArray == nil {
		eventTypesArray = []string{}
	}
	complianceMappingsJSON, err := json.Marshal(rule.ComplianceMappings)
	if err != nil {
		return fmt.Errorf("incident: marshal compliance_mappings: %w", err)
	}

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		_, err := q.Exec(ctx,
			`INSERT INTO detection_rules (
				id, name, description, source, severity,
				patterns, event_types, min_events, time_window,
				playbook_id, auto_create, auto_execute,
				compliance_mappings, enabled,
				created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			rule.ID, rule.Name, rule.Description,
			string(rule.Source), string(rule.Severity),
			patternsArray, eventTypesArray,
			rule.MinEvents, rule.TimeWindow,
			rule.PlaybookID, rule.AutoCreate, rule.AutoExecute,
			complianceMappingsJSON, rule.Enabled,
			rule.CreatedAt, rule.UpdatedAt,
		)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "violates unique constraint") {
				return fmt.Errorf("incident: CreateRule: rule %s already exists", rule.ID)
			}
			return fmt.Errorf("incident: CreateRule: %w", err)
		}
		return nil
	})
}

// GetRule retrieves a detection rule by ID.
func (s *PostgresDetectionRuleStore) GetRule(ctx context.Context, id string) (*DetectionRule, error) {
	if id == "" {
		return nil, fmt.Errorf("incident: GetRule: empty ID")
	}

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	var result *DetectionRule
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		row := q.QueryRow(ctx,
			`SELECT id, name, description, source, severity,
				patterns, event_types, min_events, time_window,
				playbook_id, auto_create, auto_execute,
				compliance_mappings, enabled,
				created_at, updated_at
			FROM detection_rules WHERE id = $1`,
			id,
		)

		rule, err := scanDetectionRule(row)
		if err != nil {
			if err == pgx.ErrNoRows {
				return nil
			}
			return fmt.Errorf("incident: GetRule: %w", err)
		}
		result = rule
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListRules lists detection rules. If enabledOnly is true, only
// enabled rules are returned.
func (s *PostgresDetectionRuleStore) ListRules(ctx context.Context, enabledOnly bool) ([]*DetectionRule, error) {
	query := `SELECT id, name, description, source, severity,
			patterns, event_types, min_events, time_window,
			playbook_id, auto_create, auto_execute,
			compliance_mappings, enabled,
			created_at, updated_at
		FROM detection_rules`

	if enabledOnly {
		query += " WHERE enabled = TRUE"
	}

	query += " ORDER BY name ASC"

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	var rules []*DetectionRule
	err := ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		rows, err := q.Query(ctx, query)
		if err != nil {
			return fmt.Errorf("incident: ListRules: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			rule, err := scanDetectionRuleFromRows(rows)
			if err != nil {
				return fmt.Errorf("incident: scan rule: %w", err)
			}
			rules = append(rules, rule)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("incident: ListRules rows: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if rules == nil {
		rules = []*DetectionRule{}
	}
	return rules, nil
}

// UpdateRule updates an existing detection rule.
func (s *PostgresDetectionRuleStore) UpdateRule(ctx context.Context, rule *DetectionRule) error {
	if rule == nil {
		return fmt.Errorf("incident: UpdateRule: nil rule")
	}
	if rule.ID == "" {
		return fmt.Errorf("incident: UpdateRule: empty ID")
	}

	patternsArray := rule.Patterns
	if patternsArray == nil {
		patternsArray = []string{}
	}
	eventTypesArray := rule.EventTypes
	if eventTypesArray == nil {
		eventTypesArray = []string{}
	}
	complianceMappingsJSON, err := json.Marshal(rule.ComplianceMappings)
	if err != nil {
		return fmt.Errorf("incident: marshal compliance_mappings: %w", err)
	}

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		tag, err := q.Exec(ctx,
			`UPDATE detection_rules SET
				name = $2, description = $3, source = $4, severity = $5,
				patterns = $6, event_types = $7, min_events = $8, time_window = $9,
				playbook_id = $10, auto_create = $11, auto_execute = $12,
				compliance_mappings = $13, enabled = $14,
				updated_at = $15
			WHERE id = $1`,
			rule.ID, rule.Name, rule.Description,
			string(rule.Source), string(rule.Severity),
			patternsArray, eventTypesArray,
			rule.MinEvents, rule.TimeWindow,
			rule.PlaybookID, rule.AutoCreate, rule.AutoExecute,
			complianceMappingsJSON, rule.Enabled,
			rule.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("incident: UpdateRule: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("incident: UpdateRule: rule %s not found", rule.ID)
		}
		return nil
	})
}

// DeleteRule removes a detection rule by ID.
func (s *PostgresDetectionRuleStore) DeleteRule(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("incident: DeleteRule: empty ID")
	}

	tenantID := auth.GetTenantID(ctx)
	isAdmin := auth.IsAdmin(ctx)
	return ioc.WithTenantContextOrPool(ctx, s.pool, tenantID, isAdmin, func(q ioc.DBQuerier) error {
		tag, err := q.Exec(ctx, `DELETE FROM detection_rules WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("incident: DeleteRule: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("incident: DeleteRule: rule %s not found", id)
		}
		return nil
	})
}

// Close is a no-op. The pool is shared.
func (s *PostgresDetectionRuleStore) Close() error { return nil }

// =====================================================================
// Scan helpers
// =====================================================================

// scanIncident scans a single incident from a query row.
func scanIncident(row pgx.Row) (*Incident, error) {
	var inc Incident
	var severity, status, source string
	var escalatedAt, resolvedAt, closedAt *time.Time
	var tagsArray []string
	var metadataJSON []byte

	err := row.Scan(
		&inc.ID, &inc.Title, &inc.Description, &severity, &status, &source,
		&inc.SessionID, &inc.AgentID, &inc.PlaybookID,
		&inc.EscalationPolicyID, &inc.EscalatedTo, &inc.Assignee,
		&escalatedAt, &resolvedAt, &closedAt,
		&tagsArray, &metadataJSON, &inc.TenantID,
		&inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	inc.Severity = IncidentSeverity(severity)
	inc.Status = IncidentStatus(status)
	inc.Source = IncidentSource(source)

	if escalatedAt != nil {
		inc.EscalatedAt = *escalatedAt
	}
	if resolvedAt != nil {
		inc.ResolvedAt = *resolvedAt
	}
	if closedAt != nil {
		inc.ClosedAt = *closedAt
	}

	if tagsArray == nil {
		tagsArray = []string{}
	}
	inc.Tags = tagsArray

	if err := json.Unmarshal(metadataJSON, &inc.Metadata); err != nil {
		inc.Metadata = make(map[string]string)
	}
	if inc.Metadata == nil {
		inc.Metadata = make(map[string]string)
	}

	// Extract correlation_event_ids and compliance_mappings from metadata
	// if they were stored there during UpdateIncident.
	if idsJSON, ok := inc.Metadata["_correlation_event_ids"]; ok {
		var ids []string
		if err := json.Unmarshal([]byte(idsJSON), &ids); err == nil {
			inc.CorrelationEventIDs = ids
		}
		delete(inc.Metadata, "_correlation_event_ids")
	}
	if mappingsJSON, ok := inc.Metadata["_compliance_mappings"]; ok {
		var mappings []ComplianceMapping
		if err := json.Unmarshal([]byte(mappingsJSON), &mappings); err == nil {
			inc.ComplianceMappings = mappings
		}
		delete(inc.Metadata, "_compliance_mappings")
	}

	if inc.CorrelationEventIDs == nil {
		inc.CorrelationEventIDs = []string{}
	}
	if inc.ComplianceMappings == nil {
		inc.ComplianceMappings = []ComplianceMapping{}
	}
	if inc.PlaybookRuns == nil {
		inc.PlaybookRuns = []*PlaybookRun{}
	}

	return &inc, nil
}

// scanIncidentFromRows scans a single incident from an active rows iterator.
func scanIncidentFromRows(rows pgx.Rows) (*Incident, error) {
	var inc Incident
	var severity, status, source string
	var escalatedAt, resolvedAt, closedAt *time.Time
	var tagsArray []string
	var metadataJSON []byte

	err := rows.Scan(
		&inc.ID, &inc.Title, &inc.Description, &severity, &status, &source,
		&inc.SessionID, &inc.AgentID, &inc.PlaybookID,
		&inc.EscalationPolicyID, &inc.EscalatedTo, &inc.Assignee,
		&escalatedAt, &resolvedAt, &closedAt,
		&tagsArray, &metadataJSON, &inc.TenantID,
		&inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	inc.Severity = IncidentSeverity(severity)
	inc.Status = IncidentStatus(status)
	inc.Source = IncidentSource(source)

	if escalatedAt != nil {
		inc.EscalatedAt = *escalatedAt
	}
	if resolvedAt != nil {
		inc.ResolvedAt = *resolvedAt
	}
	if closedAt != nil {
		inc.ClosedAt = *closedAt
	}

	if tagsArray == nil {
		tagsArray = []string{}
	}
	inc.Tags = tagsArray

	if err := json.Unmarshal(metadataJSON, &inc.Metadata); err != nil {
		inc.Metadata = make(map[string]string)
	}
	if inc.Metadata == nil {
		inc.Metadata = make(map[string]string)
	}

	// Extract transient fields from metadata.
	if idsJSON, ok := inc.Metadata["_correlation_event_ids"]; ok {
		var ids []string
		if err := json.Unmarshal([]byte(idsJSON), &ids); err == nil {
			inc.CorrelationEventIDs = ids
		}
		delete(inc.Metadata, "_correlation_event_ids")
	}
	if mappingsJSON, ok := inc.Metadata["_compliance_mappings"]; ok {
		var mappings []ComplianceMapping
		if err := json.Unmarshal([]byte(mappingsJSON), &mappings); err == nil {
			inc.ComplianceMappings = mappings
		}
		delete(inc.Metadata, "_compliance_mappings")
	}

	if inc.CorrelationEventIDs == nil {
		inc.CorrelationEventIDs = []string{}
	}
	if inc.ComplianceMappings == nil {
		inc.ComplianceMappings = []ComplianceMapping{}
	}
	if inc.PlaybookRuns == nil {
		inc.PlaybookRuns = []*PlaybookRun{}
	}

	return &inc, nil
}

// scanPlaybook scans a single playbook from a query row.
func scanPlaybook(row pgx.Row) (*Playbook, error) {
	var pb Playbook
	var severity, source string
	var tagsArray []string
	var stepsJSON []byte

	err := row.Scan(
		&pb.ID, &pb.Name, &pb.Description, &severity, &source,
		&tagsArray, &stepsJSON, &pb.AutoExecute,
		&pb.CreatedAt, &pb.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	pb.Severity = IncidentSeverity(severity)
	pb.Source = IncidentSource(source)

	if tagsArray == nil {
		tagsArray = []string{}
	}
	pb.Tags = tagsArray

	if err := json.Unmarshal(stepsJSON, &pb.Steps); err != nil {
		pb.Steps = []*PlaybookStep{}
	}
	if pb.Steps == nil {
		pb.Steps = []*PlaybookStep{}
	}

	return &pb, nil
}

// scanPlaybookFromRows scans a single playbook from an active rows iterator.
func scanPlaybookFromRows(rows pgx.Rows) (*Playbook, error) {
	var pb Playbook
	var severity, source string
	var tagsArray []string
	var stepsJSON []byte

	err := rows.Scan(
		&pb.ID, &pb.Name, &pb.Description, &severity, &source,
		&tagsArray, &stepsJSON, &pb.AutoExecute,
		&pb.CreatedAt, &pb.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	pb.Severity = IncidentSeverity(severity)
	pb.Source = IncidentSource(source)

	if tagsArray == nil {
		tagsArray = []string{}
	}
	pb.Tags = tagsArray

	if err := json.Unmarshal(stepsJSON, &pb.Steps); err != nil {
		pb.Steps = []*PlaybookStep{}
	}
	if pb.Steps == nil {
		pb.Steps = []*PlaybookStep{}
	}

	return &pb, nil
}

// scanDetectionRule scans a single detection rule from a query row.
func scanDetectionRule(row pgx.Row) (*DetectionRule, error) {
	var rule DetectionRule
	var source, severity string
	var patternsArray, eventTypesArray []string
	var complianceMappingsJSON []byte
	var timeWindow time.Duration

	err := row.Scan(
		&rule.ID, &rule.Name, &rule.Description, &source, &severity,
		&patternsArray, &eventTypesArray, &rule.MinEvents, &timeWindow,
		&rule.PlaybookID, &rule.AutoCreate, &rule.AutoExecute,
		&complianceMappingsJSON, &rule.Enabled,
		&rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	rule.Source = IncidentSource(source)
	rule.Severity = IncidentSeverity(severity)
	rule.TimeWindow = timeWindow

	if patternsArray == nil {
		patternsArray = []string{}
	}
	rule.Patterns = patternsArray

	if eventTypesArray == nil {
		eventTypesArray = []string{}
	}
	rule.EventTypes = eventTypesArray

	if err := json.Unmarshal(complianceMappingsJSON, &rule.ComplianceMappings); err != nil {
		rule.ComplianceMappings = []ComplianceMapping{}
	}
	if rule.ComplianceMappings == nil {
		rule.ComplianceMappings = []ComplianceMapping{}
	}

	return &rule, nil
}

// scanDetectionRuleFromRows scans a single detection rule from an active rows iterator.
func scanDetectionRuleFromRows(rows pgx.Rows) (*DetectionRule, error) {
	var rule DetectionRule
	var source, severity string
	var patternsArray, eventTypesArray []string
	var complianceMappingsJSON []byte
	var timeWindow time.Duration

	err := rows.Scan(
		&rule.ID, &rule.Name, &rule.Description, &source, &severity,
		&patternsArray, &eventTypesArray, &rule.MinEvents, &timeWindow,
		&rule.PlaybookID, &rule.AutoCreate, &rule.AutoExecute,
		&complianceMappingsJSON, &rule.Enabled,
		&rule.CreatedAt, &rule.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	rule.Source = IncidentSource(source)
	rule.Severity = IncidentSeverity(severity)
	rule.TimeWindow = timeWindow

	if patternsArray == nil {
		patternsArray = []string{}
	}
	rule.Patterns = patternsArray

	if eventTypesArray == nil {
		eventTypesArray = []string{}
	}
	rule.EventTypes = eventTypesArray

	if err := json.Unmarshal(complianceMappingsJSON, &rule.ComplianceMappings); err != nil {
		rule.ComplianceMappings = []ComplianceMapping{}
	}
	if rule.ComplianceMappings == nil {
		rule.ComplianceMappings = []ComplianceMapping{}
	}

	return &rule, nil
}

// =====================================================================
// Utility helpers
// =====================================================================

// nullTime returns a *time.Time for nullable timestamp columns.
// Returns nil if t is the zero value.
func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
