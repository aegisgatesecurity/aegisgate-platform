// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Incident Store Interface (v3.8 Persistence)
// =========================================================================
//
// store_interface.go defines the IncidentStore, PlaybookStore, and
// DetectionRuleStore interfaces. Both in-memory and PostgreSQL
// backends implement these interfaces:
//
//   - Community/Developer tiers → InMemoryIncidentStore, etc.
//   - Professional/Enterprise → PostgresIncidentStore (future v2.0)
//
// The in-memory stores are sufficient for single-instance deployments.
// For durability and query scale, use PostgreSQL.
//
// Tier gating: FeaturePostgreSQL is required for PostgreSQL stores.
// v3.8 persistence gap closure.
// =========================================================================

package incident

import (
	"context"
)

// IncidentStore is the interface for persisting incidents. Both
// in-memory and PostgreSQL backends implement this interface.
//
// All methods accept a context for PostgreSQL cancellation and
// timeout support. The in-memory store ignores the context.
type IncidentStore interface {
	// CreateIncident persists a new incident. Returns an error
	// if an incident with the same ID already exists.
	CreateIncident(ctx context.Context, incident *Incident) error

	// GetIncident retrieves an incident by ID. Returns nil if
	// not found.
	GetIncident(ctx context.Context, id string) (*Incident, error)

	// UpdateIncident updates an existing incident. Returns an
	// error if the incident does not exist.
	UpdateIncident(ctx context.Context, incident *Incident) error

	// ListIncidents queries incidents using filter criteria.
	// Returns an empty slice (not nil) if no incidents match.
	ListIncidents(ctx context.Context, query *IncidentQuery) ([]*Incident, error)

	// Close releases resources. For the in-memory store this
	// is a no-op.
	Close() error
}

// PlaybookStore is the interface for persisting playbooks.
type PlaybookStore interface {
	// CreatePlaybook persists a new playbook. Returns an error
	// if a playbook with the same ID already exists.
	CreatePlaybook(ctx context.Context, playbook *Playbook) error

	// GetPlaybook retrieves a playbook by ID. Returns nil if
	// not found.
	GetPlaybook(ctx context.Context, id string) (*Playbook, error)

	// ListPlaybooks lists playbooks filtered by severity and
	// source. Pass zero values to match all.
	ListPlaybooks(ctx context.Context, severity IncidentSeverity, source IncidentSource) ([]*Playbook, error)

	// UpdatePlaybook updates an existing playbook. Returns an
	// error if the playbook does not exist.
	UpdatePlaybook(ctx context.Context, playbook *Playbook) error

	// DeletePlaybook removes a playbook by ID.
	DeletePlaybook(ctx context.Context, id string) error

	// Close releases resources.
	Close() error
}

// DetectionRuleStore is the interface for persisting detection rules.
type DetectionRuleStore interface {
	// CreateRule persists a new detection rule. Returns an error
	// if a rule with the same ID already exists.
	CreateRule(ctx context.Context, rule *DetectionRule) error

	// GetRule retrieves a detection rule by ID. Returns nil if
	// not found.
	GetRule(ctx context.Context, id string) (*DetectionRule, error)

	// ListRules lists detection rules. If enabledOnly is true,
	// only enabled rules are returned.
	ListRules(ctx context.Context, enabledOnly bool) ([]*DetectionRule, error)

	// UpdateRule updates an existing detection rule. Returns an
	// error if the rule does not exist.
	UpdateRule(ctx context.Context, rule *DetectionRule) error

	// DeleteRule removes a detection rule by ID.
	DeleteRule(ctx context.Context, id string) error

	// Close releases resources.
	Close() error
}