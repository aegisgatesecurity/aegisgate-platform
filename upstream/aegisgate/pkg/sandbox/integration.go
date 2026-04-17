package sandbox

import (
	"time"
)

// MissingFeedReference represents an error when feed reference is missing
type MissingFeedReference struct {
	FeedID string
}

func (e *MissingFeedReference) Error() string {
	return "missing feed reference for ID: " + e.FeedID
}

// FeedResult represents the result of feed processing
type FeedResult struct {
	FeedID    string
	Status    string
	Processed time.Time
	Errors    []string
}

// SandboxFactory creates sandboxes for feeds
type SandboxFactory struct {
	manager SandboxManager
	config  *SandboxManagerConfig
}

// NewSandboxFactory creates a new sandbox factory
func NewSandboxFactory(config *SandboxManagerConfig) *SandboxFactory {
	return &SandboxFactory{
		manager: newDefaultManager(config),
		config:  config,
	}
}

// CreateSandbox creates a sandbox for a feed
func (f *SandboxFactory) CreateSandbox(feedID string) (*Sandbox, error) {
	policy := f.buildPolicy(feedID)
	return f.manager.Create(SandboxID(feedID), policy)
}

// buildPolicy builds a sandbox policy for a feed
func (f *SandboxFactory) buildPolicy(feedID string) SandboxPolicy {
	return SandboxPolicy{
		FeedID:         feedID,
		Status:         SandboxStatusCreated,
		ResourceQuota:  f.config.DefaultQuota,
		IsolationLevel: f.config.DefaultIsolation,
		AuditLogging:   f.config.EnableAudit,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
}

// SandboxProcessor processes feeds in a sandbox
type SandboxProcessor struct {
	factory *SandboxFactory
}

// NewSandboxProcessor creates a new sandbox processor
func NewSandboxProcessor(factory *SandboxFactory) *SandboxProcessor {
	return &SandboxProcessor{
		factory: factory,
	}
}

// ProcessFeed processes a feed in a sandbox
func (p *SandboxProcessor) ProcessFeed(feedID string) (*FeedResult, error) {
	// Create sandbox for feed
	sandbox, err := p.factory.CreateSandbox(feedID)
	if err != nil {
		return nil, err
	}

	// Start sandbox
	if err := p.factory.manager.Start(sandbox.ID); err != nil {
		return nil, err
	}

	// Process feed (mock implementation)
	result := &FeedResult{
		FeedID:    feedID,
		Status:    "success",
		Processed: time.Now(),
	}

	// Stop sandbox
	if err := p.factory.manager.Stop(sandbox.ID); err != nil {
		return nil, err
	}

	return result, nil
}
