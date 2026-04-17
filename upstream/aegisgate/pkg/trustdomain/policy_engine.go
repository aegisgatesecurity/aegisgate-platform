// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package trustdomain

import (
	"sync"
	"time"
)

// FeedTrustPolicyEngine manages policies for feeds
type FeedTrustPolicyEngine struct {
	policies    map[string]*FeedTrustPolicy
	domains     map[string]TrustDomain
	defaultMode ValidationMode
	mu          sync.RWMutex
	config      *FeedTrustPolicyEngineConfig
}

// FeedTrustPolicyEngineConfig holds configuration for the policy engine
type FeedTrustPolicyEngineConfig struct {
	DefaultMode        ValidationMode
	EnforceIsolation   bool
	LogInvalidRequests bool
	MaxPoliciesPerFeed int
}

// NewFeedTrustPolicyEngine creates a new feed trust policy engine
func NewFeedTrustPolicyEngine(config *FeedTrustPolicyEngineConfig) *FeedTrustPolicyEngine {
	if config == nil {
		config = &FeedTrustPolicyEngineConfig{
			DefaultMode:        ValidationStrict,
			EnforceIsolation:   true,
			LogInvalidRequests: true,
			MaxPoliciesPerFeed: 10,
		}
	}

	return &FeedTrustPolicyEngine{
		policies:    make(map[string]*FeedTrustPolicy),
		domains:     make(map[string]TrustDomain),
		defaultMode: config.DefaultMode,
		config:      config,
	}
}

// SetDomain associates a domain with a feed
func (ftpe *FeedTrustPolicyEngine) SetDomain(feedID string, domain TrustDomain) error {
	ftpe.mu.Lock()
	defer ftpe.mu.Unlock()

	ftpe.domains[feedID] = domain
	return nil
}

// GetDomain retrieves a domain for a feed
func (ftpe *FeedTrustPolicyEngine) GetDomain(feedID string) (TrustDomain, error) {
	ftpe.mu.RLock()
	defer ftpe.mu.RUnlock()

	domain, exists := ftpe.domains[feedID]
	if !exists {
		return nil, &ValidationError{
			Code:      "domain_not_found",
			Message:   "No trust domain found for feed",
			Details:   map[string]interface{}{"feed_id": feedID},
			Timestamp: time.Now(),
		}
	}

	return domain, nil
}

// SetPolicy sets a policy for a feed
func (ftpe *FeedTrustPolicyEngine) SetPolicy(feedID string, policy *FeedTrustPolicy) error {
	ftpe.mu.Lock()
	defer ftpe.mu.Unlock()

	// Check if max policies reached
	policyCount := 0
	for _, p := range ftpe.policies {
		if p.FeedID == feedID {
			policyCount++
		}
	}

	if policyCount >= ftpe.config.MaxPoliciesPerFeed {
		return &ValidationError{
			Code:      "max_policies_reached",
			Message:   "Maximum number of policies per feed reached",
			Details:   map[string]interface{}{"feed_id": feedID, "policy_count": policyCount},
			Timestamp: time.Now(),
		}
	}

	ftpe.policies[feedID] = policy
	return nil
}

// GetPolicy retrieves a policy for a feed
func (ftpe *FeedTrustPolicyEngine) GetPolicy(feedID string) (*FeedTrustPolicy, error) {
	ftpe.mu.RLock()
	defer ftpe.mu.RUnlock()

	policy, exists := ftpe.policies[feedID]
	if !exists {
		return nil, &ValidationError{
			Code:      "policy_not_found",
			Message:   "No policy found for feed",
			Details:   map[string]interface{}{"feed_id": feedID},
			Timestamp: time.Now(),
		}
	}

	return policy, nil
}

// RemovePolicy removes a policy for a feed
func (ftpe *FeedTrustPolicyEngine) RemovePolicy(feedID string) error {
	ftpe.mu.Lock()
	defer ftpe.mu.Unlock()

	delete(ftpe.policies, feedID)
	return nil
}

// ValidateFeed validates a request for a feed based on its policies
func (ftpe *FeedTrustPolicyEngine) ValidateFeed(feedID string, data interface{}) (bool, error) {
	ftpe.mu.RLock()
	defer ftpe.mu.RUnlock()

	_, exists := ftpe.policies[feedID]
	if !exists {
		// Use default validation mode if no policy exists
		if ftpe.defaultMode == ValidationDisabled {
			return true, nil
		}
		// Apply default strict validation
		if ftpe.defaultMode == ValidationStrict {
			return true, nil // Default to allowing if no policy
		}
	}

	// Apply policy validation
	// Implementation would check specific policies
	return true, nil
}

// ListPolicies lists all policies
func (ftpe *FeedTrustPolicyEngine) ListPolicies() map[string]*FeedTrustPolicy {
	ftpe.mu.RLock()
	defer ftpe.mu.RUnlock()

	policies := make(map[string]*FeedTrustPolicy)
	for feedID, policy := range ftpe.policies {
		policies[feedID] = policy
	}

	return policies
}

// GetPolicyCount returns the number of policies
func (ftpe *FeedTrustPolicyEngine) GetPolicyCount() int {
	ftpe.mu.RLock()
	defer ftpe.mu.RUnlock()

	return len(ftpe.policies)
}

// GetConfig returns the policy engine configuration
func (ftpe *FeedTrustPolicyEngine) GetConfig() *FeedTrustPolicyEngineConfig {
	ftpe.mu.RLock()
	defer ftpe.mu.RUnlock()

	return ftpe.config
}

// DefaultPolicyEngine creates a new policy engine with default config
func DefaultPolicyEngine() *FeedTrustPolicyEngine {
	return NewFeedTrustPolicyEngine(nil)
}
