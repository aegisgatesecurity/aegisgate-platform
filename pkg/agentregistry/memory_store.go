package agentregistry

import (
	"context"
	"sync"
)

// InMemoryStore is the default Store implementation. It uses a
// sync.RWMutex + map and requires no external dependencies.
//
// This is the same pattern used by pkg/rbac (Manager with usePostgres=false),
// pkg/correlation (InMemoryCorrelationStore), and pkg/incident
// (InMemoryIncidentStore).
type InMemoryStore struct {
	mu      sync.RWMutex
	records map[string]*AgentRecord
}

// NewInMemoryStore creates a new in-memory agent registry store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		records: make(map[string]*AgentRecord),
	}
}

// Get returns a single agent record by ID.
func (s *InMemoryStore) Get(_ context.Context, agentID string) (*AgentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.records[agentID]
	if !ok {
		return nil, ErrNotFound
	}
	// Return a copy to prevent callers from mutating the stored record
	// without going through Upsert.
	return cloneRecord(r), nil
}

// List returns all agent records matching the given filter.
func (s *InMemoryStore) List(_ context.Context, filter *ListFilter) ([]*AgentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*AgentRecord, 0, len(s.records))
	for _, r := range s.records {
		if filter.matches(r) {
			result = append(result, cloneRecord(r))
		}
	}
	return result, nil
}

// Upsert creates or updates a record.
func (s *InMemoryStore) Upsert(_ context.Context, record *AgentRecord) error {
	if record == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.ID] = cloneRecord(record)
	return nil
}

// Delete removes a record from the store.
func (s *InMemoryStore) Delete(_ context.Context, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[agentID]; !ok {
		return ErrNotFound
	}
	delete(s.records, agentID)
	return nil
}

// Close is a no-op for the in-memory store.
func (s *InMemoryStore) Close() error { return nil }

// InMemoryPolicyStore is the in-memory implementation of
// LifecyclePolicyStore.
type InMemoryPolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*LifecyclePolicy
}

// NewInMemoryPolicyStore creates a new in-memory policy store.
func NewInMemoryPolicyStore() *InMemoryPolicyStore {
	return &InMemoryPolicyStore{
		policies: make(map[string]*LifecyclePolicy),
	}
}

// GetPolicy returns a single policy by ID.
func (s *InMemoryPolicyStore) GetPolicy(_ context.Context, policyID string) (*LifecyclePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[policyID]
	if !ok {
		return nil, ErrNotFound
	}
	return clonePolicy(p), nil
}

// ListPolicies returns all policies.
func (s *InMemoryPolicyStore) ListPolicies(_ context.Context) ([]*LifecyclePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*LifecyclePolicy, 0, len(s.policies))
	for _, p := range s.policies {
		result = append(result, clonePolicy(p))
	}
	return result, nil
}

// UpsertPolicy creates or updates a policy.
func (s *InMemoryPolicyStore) UpsertPolicy(_ context.Context, policy *LifecyclePolicy) error {
	if policy == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policy.ID] = clonePolicy(policy)
	return nil
}

// DeletePolicy removes a policy.
func (s *InMemoryPolicyStore) DeletePolicy(_ context.Context, policyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[policyID]; !ok {
		return ErrNotFound
	}
	delete(s.policies, policyID)
	return nil
}

// Close is a no-op.
func (s *InMemoryPolicyStore) Close() error { return nil }

// --- Clone helpers ---

func cloneRecord(r *AgentRecord) *AgentRecord {
	if r == nil {
		return nil
	}
	c := *r
	if r.Tools != nil {
		c.Tools = append([]string(nil), r.Tools...)
	}
	if r.Protocols != nil {
		c.Protocols = append([]Protocol(nil), r.Protocols...)
	}
	if r.Tags != nil {
		c.Tags = make(map[string]string, len(r.Tags))
		for k, v := range r.Tags {
			c.Tags[k] = v
		}
	}
	if r.DiscoverySources != nil {
		c.DiscoverySources = append([]string(nil), r.DiscoverySources...)
	}
	return &c
}

func clonePolicy(p *LifecyclePolicy) *LifecyclePolicy {
	if p == nil {
		return nil
	}
	c := *p
	if p.OnDormant != nil {
		c.OnDormant = append([]PolicyAction(nil), p.OnDormant...)
	}
	if p.OnQuarantine != nil {
		c.OnQuarantine = append([]PolicyAction(nil), p.OnQuarantine...)
	}
	if p.OnRevoke != nil {
		c.OnRevoke = append([]PolicyAction(nil), p.OnRevoke...)
	}
	if p.Filters != nil {
		f := *p.Filters
		if f.Protocols != nil {
			f.Protocols = append([]Protocol(nil), p.Filters.Protocols...)
		}
		if f.Roles != nil {
			f.Roles = append([]string(nil), p.Filters.Roles...)
		}
		if f.Tags != nil {
			f.Tags = make(map[string]string, len(p.Filters.Tags))
			for k, v := range p.Filters.Tags {
				f.Tags[k] = v
			}
		}
		if f.TenantIDs != nil {
			f.TenantIDs = append([]string(nil), p.Filters.TenantIDs...)
		}
		c.Filters = &f
	}
	return &c
}