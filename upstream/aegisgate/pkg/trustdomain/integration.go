package trustdomain

import (
	"fmt"
	"time"
)

// Integration provides integration methods between trust domains and external systems
type Integration struct {
	manager      *TrustDomainManager
	policyEngine *FeedTrustPolicyEngine
}

// IntegrationConfig holds configuration for integration
type IntegrationConfig struct {
	TrustDomainManagerConfig *TrustDomainManagerConfig
	PolicyEngineConfig       *FeedTrustPolicyEngineConfig
}

// NewIntegration creates a new integration instance
func NewIntegration(config *IntegrationConfig) *Integration {
	// Create trust domain manager
	tmConfig := config.TrustDomainManagerConfig
	if tmConfig == nil {
		tmConfig = &TrustDomainManagerConfig{
			DefaultIsolationLevel: IsolationFull,
			MaxTrustDomains:       100,
			EnableAuditLog:        true,
			AuditLogBufferSize:    1000,
			DefaultValidationMode: ValidationStrict,
		}
	}

	// Create policy engine
	peConfig := config.PolicyEngineConfig
	if peConfig == nil {
		peConfig = &FeedTrustPolicyEngineConfig{
			DefaultMode:        ValidationStrict,
			EnforceIsolation:   true,
			LogInvalidRequests: true,
			MaxPoliciesPerFeed: 10,
		}
	}

	return &Integration{
		manager:      NewTrustDomainManager(tmConfig),
		policyEngine: NewFeedTrustPolicyEngine(peConfig),
	}
}

// GetTrustDomainManager returns the trust domain manager
func (i *Integration) GetTrustDomainManager() *TrustDomainManager {
	return i.manager
}

// GetPolicyEngine returns the policy engine
func (i *Integration) GetPolicyEngine() *FeedTrustPolicyEngine {
	return i.policyEngine
}

// SetupForFeed sets up trust domain infrastructure for a feed
func (i *Integration) SetupForFeed(feedID string, domainID TrustDomainID) error {
	// Create trust domain
	domain, err := i.manager.CreateDomain(&TrustDomainConfig{
		ID:             domainID,
		Name:           "domain_" + feedID,
		Enabled:        true,
		IsolationLevel: IsolationFull,
	})
	if err != nil {
		return fmt.Errorf("failed to create trust domain: %w", err)
	}

	// Set domain in policy engine
	if err := i.policyEngine.SetDomain(feedID, domain); err != nil {
		return fmt.Errorf("failed to set domain: %w", err)
	}

	// Create default policy
	defaultPolicy := &FeedTrustPolicy{
		FeedID:         feedID,
		TrustDomainID:  domainID,
		Policies:       make([]Policy, 0),
		ValidationMode: ValidationStrict,
		Parameters: map[string]interface{}{
			"timeout":           30 * time.Second,
			"enable_hash_chain": true,
			"enable_signature":  true,
		},
		CreatedAt: time.Now(),
		CreatedBy: "system",
		UpdatedAt: time.Now(),
		UpdatedBy: "system",
	}

	// Set default policy
	if err := i.policyEngine.SetPolicy(feedID, defaultPolicy); err != nil {
		return fmt.Errorf("failed to set default policy: %w", err)
	}

	return nil
}

// CleanupForFeed cleans up trust domain infrastructure for a feed
func (i *Integration) CleanupForFeed(feedID string, domainID TrustDomainID) error {
	// Remove policy
	if err := i.policyEngine.RemovePolicy(feedID); err != nil {
		return fmt.Errorf("failed to remove policy: %w", err)
	}

	// Remove domain
	if err := i.manager.DeleteDomain(domainID); err != nil {
		return fmt.Errorf("failed to delete domain: %w", err)
	}

	return nil
}

// ValidateFeedRequest validates a request for a feed
func (i *Integration) ValidateFeedRequest(feedID string, data interface{}) (bool, error) {
	return i.policyEngine.ValidateFeed(feedID, data)
}

// GetStats returns integration statistics
func (i *Integration) GetStats() *IntegrationStats {
	return &IntegrationStats{
		DomainCount: i.manager.GetDomainCount(),
		PolicyCount: i.policyEngine.GetPolicyCount(),
		UpTime:      0, // Would track actual uptime
	}
}

// IntegrationStats holds integration statistics
type IntegrationStats struct {
	DomainCount int
	PolicyCount int
	UpTime      time.Duration
}

// UpdateStats updates integration statistics
func (i *Integration) UpdateStats() {
	// Implementation for updating stats
}

// GetAuditLog returns the audit log channel
func (i *Integration) GetAuditLog() <-chan AuditLogEntry {
	return i.manager.GetAuditLog()
}
