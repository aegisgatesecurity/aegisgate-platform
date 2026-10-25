package agentregistry

import (
	"context"
	"time"
)

// Store is the persistence interface for agent registry records.
// Implementations must be safe for concurrent use.
//
// Two implementations are provided:
//   - InMemoryStore (memory_store.go) — default, no PostgreSQL needed
//   - PostgresStore (postgres_store.go) — pgx/v5 with RLS-aware isolation
type Store interface {
	// Get returns a single agent record by ID. Returns ErrNotFound
	// if the agent is not in the registry.
	Get(ctx context.Context, agentID string) (*AgentRecord, error)

	// List returns all agent records matching the given filter.
	// A nil filter returns all records.
	List(ctx context.Context, filter *ListFilter) ([]*AgentRecord, error)

	// Upsert creates or updates a record. If a record with the same
	// ID already exists, it is replaced entirely.
	Upsert(ctx context.Context, record *AgentRecord) error

	// Delete removes a record from the store. Returns ErrNotFound
	// if the agent is not in the registry.
	Delete(ctx context.Context, agentID string) error

	// Close releases any resources held by the store.
	Close() error
}

// ErrNotFound is returned when an agent is not in the registry.
var ErrNotFound = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "agentregistry: agent not found" }
func (errNotFound) Is(target error) bool {
	_, ok := target.(errNotFound)
	return ok
}

// LifecyclePolicyStore is the persistence interface for lifecycle policies.
type LifecyclePolicyStore interface {
	GetPolicy(ctx context.Context, policyID string) (*LifecyclePolicy, error)
	ListPolicies(ctx context.Context) ([]*LifecyclePolicy, error)
	UpsertPolicy(ctx context.Context, policy *LifecyclePolicy) error
	DeletePolicy(ctx context.Context, policyID string) error
	Close() error
}

// nowFunc is the clock used by the registry. Overridden in tests.
var nowFunc = func() time.Time { return time.Now() }
