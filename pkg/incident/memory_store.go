// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Incident In-Memory Stores (v3.8 Persistence)
// =========================================================================
//
// memory_store.go implements IncidentStore, PlaybookStore, and
// DetectionRuleStore with in-memory maps. These are the storage
// backends for Community and Developer tiers that do not have
// PostgreSQL configured.
//
// Thread safety: all methods are protected by sync.RWMutex.
// Data is lost on process restart; for durability, use
// PostgresIncidentStore (future v2.0, Professional/Enterprise).
//
// v3.8 persistence gap closure.
// =========================================================================

package incident

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Compile-time interface compliance checks.
var (
	_ IncidentStore      = (*InMemoryIncidentStore)(nil)
	_ PlaybookStore      = (*InMemoryPlaybookStore)(nil)
	_ DetectionRuleStore = (*InMemoryDetectionRuleStore)(nil)
)

// =====================================================================
// InMemoryIncidentStore
// =====================================================================

// InMemoryIncidentStore implements IncidentStore with an in-memory
// map. Safe for concurrent use. Incidents are lost on process restart.
type InMemoryIncidentStore struct {
	mu         sync.RWMutex
	byID       map[string]*Incident
	byStatus   map[string][]string // status -> incident IDs
	bySeverity map[string][]string // severity -> incident IDs
	byAgent    map[string][]string // agent ID -> incident IDs
	bySession  map[string][]string // session ID -> incident IDs
	byTenant   map[string][]string // tenant ID -> incident IDs
}

// NewInMemoryIncidentStore creates a new empty in-memory incident store.
func NewInMemoryIncidentStore() *InMemoryIncidentStore {
	return &InMemoryIncidentStore{
		byID:       make(map[string]*Incident),
		byStatus:   make(map[string][]string),
		bySeverity: make(map[string][]string),
		byAgent:    make(map[string][]string),
		bySession:  make(map[string][]string),
		byTenant:   make(map[string][]string),
	}
}

// CreateIncident persists a new incident. Returns an error if an
// incident with the same ID already exists.
func (s *InMemoryIncidentStore) CreateIncident(_ context.Context, incident *Incident) error {
	if incident == nil {
		return fmt.Errorf("incident: CreateIncident: nil incident")
	}
	if incident.ID == "" {
		return fmt.Errorf("incident: CreateIncident: empty ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[incident.ID]; exists {
		return fmt.Errorf("incident: CreateIncident: incident %s already exists", incident.ID)
	}

	s.byID[incident.ID] = incident
	s.addToIndex(s.byStatus, string(incident.Status), incident.ID)
	s.addToIndex(s.bySeverity, string(incident.Severity), incident.ID)
	if incident.AgentID != "" {
		s.addToIndex(s.byAgent, incident.AgentID, incident.ID)
	}
	if incident.SessionID != "" {
		s.addToIndex(s.bySession, incident.SessionID, incident.ID)
	}
	if incident.TenantID != "" {
		s.addToIndex(s.byTenant, incident.TenantID, incident.ID)
	}

	return nil
}

// GetIncident retrieves an incident by ID. Returns nil if not found.
func (s *InMemoryIncidentStore) GetIncident(_ context.Context, id string) (*Incident, error) {
	if id == "" {
		return nil, fmt.Errorf("incident: GetIncident: empty ID")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.byID[id], nil
}

// UpdateIncident updates an existing incident. Returns an error if
// the incident does not exist.
func (s *InMemoryIncidentStore) UpdateIncident(_ context.Context, incident *Incident) error {
	if incident == nil {
		return fmt.Errorf("incident: UpdateIncident: nil incident")
	}
	if incident.ID == "" {
		return fmt.Errorf("incident: UpdateIncident: empty ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.byID[incident.ID]
	if !ok {
		return fmt.Errorf("incident: UpdateIncident: incident %s not found", incident.ID)
	}

	// Remove old index entries.
	s.removeFromIndex(s.byStatus, string(existing.Status), incident.ID)
	s.removeFromIndex(s.bySeverity, string(existing.Severity), incident.ID)
	if existing.AgentID != "" {
		s.removeFromIndex(s.byAgent, existing.AgentID, incident.ID)
	}
	if existing.SessionID != "" {
		s.removeFromIndex(s.bySession, existing.SessionID, incident.ID)
	}
	if existing.TenantID != "" {
		s.removeFromIndex(s.byTenant, existing.TenantID, incident.ID)
	}

	// Update the stored incident.
	s.byID[incident.ID] = incident

	// Add new index entries.
	s.addToIndex(s.byStatus, string(incident.Status), incident.ID)
	s.addToIndex(s.bySeverity, string(incident.Severity), incident.ID)
	if incident.AgentID != "" {
		s.addToIndex(s.byAgent, incident.AgentID, incident.ID)
	}
	if incident.SessionID != "" {
		s.addToIndex(s.bySession, incident.SessionID, incident.ID)
	}
	if incident.TenantID != "" {
		s.addToIndex(s.byTenant, incident.TenantID, incident.ID)
	}

	return nil
}

// ListIncidents queries incidents using filter criteria.
func (s *InMemoryIncidentStore) ListIncidents(_ context.Context, query *IncidentQuery) ([]*Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if query == nil {
		query = &IncidentQuery{}
	}

	// Start with all incidents.
	candidates := make([]*Incident, 0, len(s.byID))
	for _, inc := range s.byID {
		candidates = append(candidates, inc)
	}

	// Apply filters.
	filtered := make([]*Incident, 0, len(candidates))
	for _, inc := range candidates {
		if !matchesIncidentQuery(inc, query) {
			continue
		}
		filtered = append(filtered, inc)
	}

	// Sort by created_at descending (newest first).
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
	})

	// Apply offset.
	if query.Offset > 0 {
		if query.Offset >= len(filtered) {
			return []*Incident{}, nil
		}
		filtered = filtered[query.Offset:]
	}

	// Apply limit.
	if query.Limit > 0 && len(filtered) > query.Limit {
		filtered = filtered[:query.Limit]
	}

	return filtered, nil
}

// Close is a no-op for the in-memory store.
func (s *InMemoryIncidentStore) Close() error { return nil }

// addToIndex adds an ID to a string -> []string index map.
func (s *InMemoryIncidentStore) addToIndex(idx map[string][]string, key, id string) {
	idx[key] = append(idx[key], id)
}

// removeFromIndex removes an ID from a string -> []string index map.
func (s *InMemoryIncidentStore) removeFromIndex(idx map[string][]string, key, id string) {
	ids := idx[key]
	for i, v := range ids {
		if v == id {
			idx[key] = append(ids[:i], ids[i+1:]...)
			return
		}
	}
}

// matchesIncidentQuery checks if an incident matches the query filter.
func matchesIncidentQuery(inc *Incident, q *IncidentQuery) bool {
	// Status filter.
	if len(q.Status) > 0 && !containsStatus(q.Status, inc.Status) {
		return false
	}

	// Severity filter.
	if len(q.Severity) > 0 && !containsSeverity(q.Severity, inc.Severity) {
		return false
	}

	// Source filter.
	if len(q.Source) > 0 && !containsSource(q.Source, inc.Source) {
		return false
	}

	// Agent ID filter.
	if q.AgentID != "" && inc.AgentID != q.AgentID {
		return false
	}

	// Session ID filter.
	if q.SessionID != "" && inc.SessionID != q.SessionID {
		return false
	}

	// Tenant ID filter.
	if q.TenantID != "" && inc.TenantID != q.TenantID {
		return false
	}

	// Tags filter — all query tags must be present.
	if len(q.Tags) > 0 {
		tagSet := make(map[string]bool, len(inc.Tags))
		for _, t := range inc.Tags {
			tagSet[t] = true
		}
		for _, t := range q.Tags {
			if !tagSet[t] {
				return false
			}
		}
	}

	// Time range filter.
	if !q.From.IsZero() && inc.CreatedAt.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && inc.CreatedAt.After(q.To) {
		return false
	}

	return true
}

func containsStatus(statuses []IncidentStatus, s IncidentStatus) bool {
	for _, st := range statuses {
		if st == s {
			return true
		}
	}
	return false
}

func containsSeverity(severities []IncidentSeverity, s IncidentSeverity) bool {
	for _, se := range severities {
		if se == s {
			return true
		}
	}
	return false
}

func containsSource(sources []IncidentSource, s IncidentSource) bool {
	for _, src := range sources {
		if src == s {
			return true
		}
	}
	return false
}

// =====================================================================
// InMemoryPlaybookStore
// =====================================================================

// InMemoryPlaybookStore implements PlaybookStore with an in-memory map.
// Safe for concurrent use.
type InMemoryPlaybookStore struct {
	mu   sync.RWMutex
	byID map[string]*Playbook
}

// NewInMemoryPlaybookStore creates a new empty in-memory playbook store.
func NewInMemoryPlaybookStore() *InMemoryPlaybookStore {
	return &InMemoryPlaybookStore{
		byID: make(map[string]*Playbook),
	}
}

// CreatePlaybook persists a new playbook.
func (s *InMemoryPlaybookStore) CreatePlaybook(_ context.Context, playbook *Playbook) error {
	if playbook == nil {
		return fmt.Errorf("incident: CreatePlaybook: nil playbook")
	}
	if playbook.ID == "" {
		return fmt.Errorf("incident: CreatePlaybook: empty ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[playbook.ID]; exists {
		return fmt.Errorf("incident: CreatePlaybook: playbook %s already exists", playbook.ID)
	}

	s.byID[playbook.ID] = playbook
	return nil
}

// GetPlaybook retrieves a playbook by ID.
func (s *InMemoryPlaybookStore) GetPlaybook(_ context.Context, id string) (*Playbook, error) {
	if id == "" {
		return nil, fmt.Errorf("incident: GetPlaybook: empty ID")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.byID[id], nil
}

// ListPlaybooks lists playbooks filtered by severity and source.
// Pass zero values to match all.
func (s *InMemoryPlaybookStore) ListPlaybooks(_ context.Context, severity IncidentSeverity, source IncidentSource) ([]*Playbook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Playbook, 0)
	for _, pb := range s.byID {
		if severity != "" && pb.Severity != severity {
			continue
		}
		if source != "" && pb.Source != source {
			continue
		}
		result = append(result, pb)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}

// UpdatePlaybook updates an existing playbook.
func (s *InMemoryPlaybookStore) UpdatePlaybook(_ context.Context, playbook *Playbook) error {
	if playbook == nil {
		return fmt.Errorf("incident: UpdatePlaybook: nil playbook")
	}
	if playbook.ID == "" {
		return fmt.Errorf("incident: UpdatePlaybook: empty ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[playbook.ID]; !exists {
		return fmt.Errorf("incident: UpdatePlaybook: playbook %s not found", playbook.ID)
	}

	s.byID[playbook.ID] = playbook
	return nil
}

// DeletePlaybook removes a playbook by ID.
func (s *InMemoryPlaybookStore) DeletePlaybook(_ context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("incident: DeletePlaybook: empty ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[id]; !exists {
		return fmt.Errorf("incident: DeletePlaybook: playbook %s not found", id)
	}

	delete(s.byID, id)
	return nil
}

// Close is a no-op for the in-memory store.
func (s *InMemoryPlaybookStore) Close() error { return nil }

// =====================================================================
// InMemoryDetectionRuleStore
// =====================================================================

// InMemoryDetectionRuleStore implements DetectionRuleStore with an
// in-memory map. Safe for concurrent use.
type InMemoryDetectionRuleStore struct {
	mu   sync.RWMutex
	byID map[string]*DetectionRule
}

// NewInMemoryDetectionRuleStore creates a new empty in-memory
// detection rule store.
func NewInMemoryDetectionRuleStore() *InMemoryDetectionRuleStore {
	return &InMemoryDetectionRuleStore{
		byID: make(map[string]*DetectionRule),
	}
}

// CreateRule persists a new detection rule.
func (s *InMemoryDetectionRuleStore) CreateRule(_ context.Context, rule *DetectionRule) error {
	if rule == nil {
		return fmt.Errorf("incident: CreateRule: nil rule")
	}
	if rule.ID == "" {
		return fmt.Errorf("incident: CreateRule: empty ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[rule.ID]; exists {
		return fmt.Errorf("incident: CreateRule: rule %s already exists", rule.ID)
	}

	s.byID[rule.ID] = rule
	return nil
}

// GetRule retrieves a detection rule by ID.
func (s *InMemoryDetectionRuleStore) GetRule(_ context.Context, id string) (*DetectionRule, error) {
	if id == "" {
		return nil, fmt.Errorf("incident: GetRule: empty ID")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.byID[id], nil
}

// ListRules lists detection rules. If enabledOnly is true, only
// enabled rules are returned.
func (s *InMemoryDetectionRuleStore) ListRules(_ context.Context, enabledOnly bool) ([]*DetectionRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*DetectionRule, 0)
	for _, rule := range s.byID {
		if enabledOnly && !rule.Enabled {
			continue
		}
		result = append(result, rule)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}

// UpdateRule updates an existing detection rule.
func (s *InMemoryDetectionRuleStore) UpdateRule(_ context.Context, rule *DetectionRule) error {
	if rule == nil {
		return fmt.Errorf("incident: UpdateRule: nil rule")
	}
	if rule.ID == "" {
		return fmt.Errorf("incident: UpdateRule: empty ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[rule.ID]; !exists {
		return fmt.Errorf("incident: UpdateRule: rule %s not found", rule.ID)
	}

	s.byID[rule.ID] = rule
	return nil
}

// DeleteRule removes a detection rule by ID.
func (s *InMemoryDetectionRuleStore) DeleteRule(_ context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("incident: DeleteRule: empty ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[id]; !exists {
		return fmt.Errorf("incident: DeleteRule: rule %s not found", id)
	}

	delete(s.byID, id)
	return nil
}

// Close is a no-op for the in-memory store.
func (s *InMemoryDetectionRuleStore) Close() error { return nil }

// =====================================================================
// InMemoryEscalationPolicyStore (internal, used by Engine)
// =====================================================================

// InMemoryEscalationPolicyStore stores escalation policies in memory.
// Not exposed as an interface since v1.0 only needs in-memory.
type InMemoryEscalationPolicyStore struct {
	mu   sync.RWMutex
	byID map[string]*EscalationPolicy
}

// NewInMemoryEscalationPolicyStore creates a new empty escalation
// policy store.
func NewInMemoryEscalationPolicyStore() *InMemoryEscalationPolicyStore {
	return &InMemoryEscalationPolicyStore{
		byID: make(map[string]*EscalationPolicy),
	}
}

// Create stores a new escalation policy.
func (s *InMemoryEscalationPolicyStore) Create(policy *EscalationPolicy) error {
	if policy == nil {
		return fmt.Errorf("incident: CreateEscalationPolicy: nil policy")
	}
	if policy.ID == "" {
		return fmt.Errorf("incident: CreateEscalationPolicy: empty ID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[policy.ID]; exists {
		return fmt.Errorf("incident: escalation policy %s already exists", policy.ID)
	}

	s.byID[policy.ID] = policy
	return nil
}

// Get retrieves an escalation policy by ID.
func (s *InMemoryEscalationPolicyStore) Get(id string) (*EscalationPolicy, error) {
	if id == "" {
		return nil, fmt.Errorf("incident: GetEscalationPolicy: empty ID")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.byID[id], nil
}

// List returns all escalation policies.
func (s *InMemoryEscalationPolicyStore) List() ([]*EscalationPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*EscalationPolicy, 0, len(s.byID))
	for _, p := range s.byID {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}

// severityOrder maps IncidentSeverity to a numeric value for
// comparison.
var severityOrder = map[IncidentSeverity]int{
	SeverityLow:      0,
	SeverityMedium:   1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

// SeverityAtLeast returns true if s >= threshold.
func SeverityAtLeast(s, threshold IncidentSeverity) bool {
	return severityOrder[s] >= severityOrder[threshold]
}
