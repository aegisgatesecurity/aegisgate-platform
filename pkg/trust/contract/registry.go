// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - In-Memory Contract Registry
// =========================================================================

package contract

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// InMemoryRegistry implements ContractRegistry with in-memory storage
type InMemoryRegistry struct {
	mu        sync.RWMutex
	contracts map[string]*CapabilityContract
	byAgent   map[string]string
	byOwner   map[string][]string
}

// NewInMemoryRegistry creates a new in-memory contract registry
func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{
		contracts: make(map[string]*CapabilityContract),
		byAgent:   make(map[string]string),
		byOwner:   make(map[string][]string),
	}
}

// Create creates a new capability contract
func (r *InMemoryRegistry) Create(ctx context.Context, name, description, agentID, ownerID string, rules []ContractRule) (*CapabilityContract, error) {
	contract, err := NewContract(name, description, agentID, ownerID, rules)
	if err != nil {
		return nil, err
	}
	return r.Store(ctx, contract)
}

// Store stores a contract in the registry
func (r *InMemoryRegistry) Store(ctx context.Context, contract *CapabilityContract) (*CapabilityContract, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	contract.UpdatedAt = time.Now().UTC()
	r.contracts[contract.ID] = contract
	r.byAgent[contract.AgentID] = contract.ID
	r.byOwner[contract.OwnerID] = append(r.byOwner[contract.OwnerID], contract.ID)
	return contract, nil
}

// Get retrieves a contract by ID
func (r *InMemoryRegistry) Get(ctx context.Context, contractID string) (*CapabilityContract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	contract, exists := r.contracts[contractID]
	if !exists {
		return nil, fmt.Errorf("contract not found: %s", contractID)
	}
	return contract, nil
}

// GetByAgent retrieves a contract by agent ID
func (r *InMemoryRegistry) GetByAgent(ctx context.Context, agentID string) (*CapabilityContract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	contractID, exists := r.byAgent[agentID]
	if !exists {
		return nil, fmt.Errorf("no contract found for agent: %s", agentID)
	}
	contract, exists := r.contracts[contractID]
	if !exists {
		return nil, fmt.Errorf("contract found but not in registry: %s", contractID)
	}
	return contract, nil
}

// ListByOwner lists all contracts for an owner
func (r *InMemoryRegistry) ListByOwner(ctx context.Context, ownerID string) ([]*CapabilityContract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	contractIDs := r.byOwner[ownerID]
	result := make([]*CapabilityContract, 0, len(contractIDs))
	for _, id := range contractIDs {
		if contract, exists := r.contracts[id]; exists {
			result = append(result, contract)
		}
	}
	return result, nil
}

// Update updates an existing contract
func (r *InMemoryRegistry) Update(ctx context.Context, contractID string, updates *CapabilityContract) (*CapabilityContract, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	contract, exists := r.contracts[contractID]
	if !exists {
		return nil, fmt.Errorf("contract not found: %s", contractID)
	}

	if updates.Name != "" {
		contract.Name = updates.Name
	}
	if updates.Description != "" {
		contract.Description = updates.Description
	}
	if len(updates.Rules) > 0 {
		contract.Rules = updates.Rules
		contract.Fingerprint = contract.CalculateFingerprint()
	}
	if len(updates.Tags) > 0 {
		contract.Tags = updates.Tags
	}
	if updates.Metadata != nil {
		contract.Metadata = updates.Metadata
	}
	contract.UpdatedAt = time.Now().UTC()

	return contract, nil
}

// UpdateStatus updates the status of a contract
func (r *InMemoryRegistry) UpdateStatus(ctx context.Context, contractID string, status ContractStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	contract, exists := r.contracts[contractID]
	if !exists {
		return fmt.Errorf("contract not found: %s", contractID)
	}
	contract.Status = status
	contract.UpdatedAt = time.Now().UTC()
	return nil
}

// Delete removes a contract from the registry
func (r *InMemoryRegistry) Delete(ctx context.Context, contractID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	contract, exists := r.contracts[contractID]
	if !exists {
		return fmt.Errorf("contract not found: %s", contractID)
	}

	delete(r.contracts, contractID)
	delete(r.byAgent, contract.AgentID)

	// Remove from owner's list
	ids := r.byOwner[contract.OwnerID]
	for i, id := range ids {
		if id == contractID {
			r.byOwner[contract.OwnerID] = append(ids[:i], ids[i+1:]...)
			break
		}
	}

	return nil
}

// List lists all contracts with optional filters
func (r *InMemoryRegistry) List(ctx context.Context, filter *ListFilter) ([]*CapabilityContract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if filter == nil {
		filter = &ListFilter{}
	}
	if filter.Limit == 0 {
		filter.Limit = 100
	}

	var result []*CapabilityContract
	for _, contract := range r.contracts {
		if filter.OwnerID != "" && contract.OwnerID != filter.OwnerID {
			continue
		}
		if filter.AgentID != "" && contract.AgentID != filter.AgentID {
			continue
		}
		if filter.Status != "" && contract.Status != filter.Status {
			continue
		}
		if filter.Tag != "" {
			found := false
			for _, t := range contract.Tags {
				if t == filter.Tag {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if !filter.Since.IsZero() && contract.CreatedAt.Before(filter.Since) {
			continue
		}
		result = append(result, contract)
	}

	if filter.Offset > 0 && filter.Offset < len(result) {
		result = result[filter.Offset:]
	} else if filter.Offset >= len(result) {
		result = []*CapabilityContract{}
	}

	if len(result) > filter.Limit {
		result = result[:filter.Limit]
	}

	return result, nil
}

// ListFilter contains optional filters for listing contracts
type ListFilter struct {
	OwnerID string
	AgentID string
	Status  ContractStatus
	Tag     string
	Since   time.Time
	Limit   int
	Offset  int
}

// SimpleRateLimiter implements RateLimiter with in-memory storage
type SimpleRateLimiter struct {
	mu       sync.Mutex
	counters map[string]map[string]int64 // contractID:capability -> count
	windows  map[string]time.Time        // contractID:capability -> window start
}

// NewSimpleRateLimiter creates a new simple rate limiter
func NewSimpleRateLimiter() *SimpleRateLimiter {
	return &SimpleRateLimiter{
		counters: make(map[string]map[string]int64),
		windows:  make(map[string]time.Time),
	}
}

func (r *SimpleRateLimiter) key(contractID string, cap Capability) string {
	return contractID + ":" + string(cap)
}

// Check checks if a capability is within rate limits
func (r *SimpleRateLimiter) Check(contractID string, cap Capability) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Truncate(time.Hour)
	key := r.key(contractID, cap)

	// Reset counter if we're in a new window
	if lastStart, exists := r.windows[key]; !exists || lastStart.Before(windowStart) {
		r.counters[key] = make(map[string]int64)
		r.windows[key] = windowStart
	}

	count := r.counters[key][contractID]
	// Allow up to 1000 per hour by default
	return count < 1000, nil
}

// Record records a capability usage
func (r *SimpleRateLimiter) Record(contractID string, cap Capability) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Truncate(time.Hour)
	key := r.key(contractID, cap)

	// Reset counter if we're in a new window
	if lastStart, exists := r.windows[key]; !exists || lastStart.Before(windowStart) {
		r.counters[key] = make(map[string]int64)
		r.windows[key] = windowStart
	}

	r.counters[key][contractID]++
	return nil
}
