// Package sandbox provides feed-level sandboxing capabilities
package sandbox

import (
	"fmt"
	"testing"
	"time"
)

// TestSandboxManager tests the sandbox manager
func TestSandboxManager(t *testing.T) {
	config := DefaultConfig()
	// Convert Config to SandboxManagerConfig
	managerConfig := &SandboxManagerConfig{
		DefaultIsolation: config.DefaultIsolationLevel,
		DefaultQuota:     config.DefaultQuota,
		EnableAudit:      config.EnableAudit,
	}
	manager := newDefaultManager(managerConfig)

	feedID := "test-feed"
	policy := SandboxPolicy{
		FeedID:         feedID,
		Status:         SandboxStatusCreated,
		ResourceQuota:  config.DefaultQuota,
		IsolationLevel: config.DefaultIsolationLevel,
		AuditLogging:   config.EnableAudit,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Test create
	sandbox, err := manager.Create(SandboxID(feedID), policy)
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}

	if sandbox == nil {
		t.Fatal("sandbox should not be nil")
	}

	if sandbox.Policy.FeedID != feedID {
		t.Errorf("expected feed ID %s, got %s", feedID, sandbox.Policy.FeedID)
	}

	// Test get
	retrieved, err := manager.Get(sandbox.ID)
	if err != nil {
		t.Fatalf("failed to get sandbox: %v", err)
	}

	if retrieved.ID != sandbox.ID {
		t.Errorf("expected sandbox ID %s, got %s", sandbox.ID, retrieved.ID)
	}

	// Test list
	sandboxes, err := manager.List()
	if err != nil {
		t.Fatalf("failed to list sandboxes: %v", err)
	}

	if len(sandboxes) != 1 {
		t.Errorf("expected 1 sandbox, got %d", len(sandboxes))
	}

	// Test destroy
	err = manager.Destroy(sandbox.ID)
	if err != nil {
		t.Fatalf("failed to destroy sandbox: %v", err)
	}
}

// TestSandboxLifecycle tests the sandbox lifecycle
func TestSandboxLifecycle(t *testing.T) {
	config := DefaultConfig()
	managerConfig := &SandboxManagerConfig{
		DefaultIsolation: config.DefaultIsolationLevel,
		DefaultQuota:     config.DefaultQuota,
		EnableAudit:      config.EnableAudit,
	}
	manager := newDefaultManager(managerConfig)

	feedID := "test-lifecycle-feed"
	policy := SandboxPolicy{
		FeedID:         feedID,
		Status:         SandboxStatusCreated,
		ResourceQuota:  config.DefaultQuota,
		IsolationLevel: config.DefaultIsolationLevel,
		AuditLogging:   config.EnableAudit,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	sandbox, err := manager.Create(SandboxID(feedID), policy)
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}

	// Test start
	err = manager.Start(sandbox.ID)
	if err != nil {
		t.Fatalf("failed to start sandbox: %v", err)
	}

	// Use Stats instead of Monitor (Monitor doesn't exist)
	stats, err := manager.Stats()
	if err != nil {
		t.Fatalf("failed to get sandbox stats: %v", err)
	}

	if len(stats) != 1 || stats[0].Status != SandboxStatusRunning {
		t.Errorf("expected status %s, got %s", SandboxStatusRunning, stats[0].Status)
	}

	// Test stop
	err = manager.Stop(sandbox.ID)
	if err != nil {
		t.Fatalf("failed to stop sandbox: %v", err)
	}

	// Test destroy
	err = manager.Destroy(sandbox.ID)
	if err != nil {
		t.Fatalf("failed to destroy sandbox: %v", err)
	}
}

// TestPolicyEngine tests the policy engine
func TestPolicyEngine(t *testing.T) {
	engine := NewPolicyEngine()

	policy := &SandboxPolicy{
		FeedID: "test-feed",
		Status: SandboxStatusCreated,
		ResourceQuota: ResourceQuota{
			CPU:    1000,
			Memory: 1 << 30,
		},
		IsolationLevel: IsolationFull,
	}

	err := engine.Validate(policy)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}

	// Test invalid isolation level
	invalidPolicy := &SandboxPolicy{
		FeedID:         "test-feed",
		Status:         SandboxStatusCreated,
		ResourceQuota:  ResourceQuota{CPU: 1000},
		IsolationLevel: "invalid",
	}

	err = engine.Validate(invalidPolicy)
	if err == nil {
		t.Error("expected validation error for invalid isolation level")
	}
}

// TestSandboxProcessor tests the sandbox processor
func TestSandboxProcessor(t *testing.T) {
	config := DefaultConfig()
	managerConfig := &SandboxManagerConfig{
		DefaultIsolation: config.DefaultIsolationLevel,
		DefaultQuota:     config.DefaultQuota,
		EnableAudit:      config.EnableAudit,
	}
	factory := NewSandboxFactory(managerConfig)
	processor := NewSandboxProcessor(factory)

	feedID := "test-feed"
	result, err := processor.ProcessFeed(feedID)
	if err != nil {
		t.Fatalf("failed to process feed: %v", err)
	}

	if result == nil {
		t.Fatal("result should not be nil")
	}

	if result.FeedID != feedID {
		t.Errorf("expected feed ID %s, got %s", feedID, result.FeedID)
	}

	// Status is a string in FeedResult
	if result.Status != "success" {
		t.Errorf("expected status %s, got %s", "success", result.Status)
	}
}

// TestSandboxManagerConcurrent tests concurrent sandbox manager operations
func TestSandboxManagerConcurrent(t *testing.T) {
	config := DefaultConfig()
	managerConfig := &SandboxManagerConfig{
		DefaultIsolation: config.DefaultIsolationLevel,
		DefaultQuota:     config.DefaultQuota,
		EnableAudit:      config.EnableAudit,
	}
	manager := newDefaultManager(managerConfig)

	// Create multiple sandboxes concurrently
	done := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(index int) {
			feedID := fmt.Sprintf("concurrent-feed-%d", index)
			policy := SandboxPolicy{
				FeedID:         feedID,
				Status:         SandboxStatusCreated,
				ResourceQuota:  config.DefaultQuota,
				IsolationLevel: config.DefaultIsolationLevel,
				AuditLogging:   config.EnableAudit,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}

			_, err := manager.Create(SandboxID(feedID), policy)
			done <- err
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		err := <-done
		if err != nil {
			t.Errorf("concurrent create failed: %v", err)
		}
	}
}
