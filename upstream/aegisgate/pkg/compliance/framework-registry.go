// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package compliance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
)

// RegisteredFramework holds both the framework instance and its metadata
type RegisteredFramework struct {
	Instance common.Framework
	Tier     Tier
	Metadata map[string]interface{}
	LoadedAt int64
}

// Registry manages all loaded compliance frameworks
type Registry struct {
	mu          sync.RWMutex
	frameworks  map[string]*RegisteredFramework
	tierManager *TierManager
}

// NewRegistry creates a new framework registry with default settings
func NewRegistry() *Registry {
	return &Registry{
		frameworks:  make(map[string]*RegisteredFramework),
		tierManager: NewTierManager(),
	}
}

// NewRegistryWithTierManager creates a registry with a custom tier manager
func NewRegistryWithTierManager(tm *TierManager) *Registry {
	return &Registry{
		frameworks:  make(map[string]*RegisteredFramework),
		tierManager: tm,
	}
}

// Register adds a framework to the registry
func (r *Registry) Register(framework common.Framework) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if framework == nil {
		return fmt.Errorf("framework cannot be nil")
	}

	frameworkID := framework.GetFrameworkID()
	if frameworkID == "" {
		return fmt.Errorf("framework must have an ID")
	}

	// Get tier from tier manager
	ft, exists := r.tierManager.GetFrameworkTier(frameworkID)
	if !exists {
		return fmt.Errorf("framework %s not registered in tier manager", frameworkID)
	}

	rf := &RegisteredFramework{
		Instance: framework,
		Tier:     ft.Tier,
		Metadata: map[string]interface{}{
			"registered_at": time.Now().Unix(),
			"name":          framework.GetName(),
			"version":       framework.GetVersion(),
		},
		LoadedAt: time.Now().Unix(),
	}

	r.frameworks[frameworkID] = rf
	return nil
}

// Unregister removes a framework from the registry
func (r *Registry) Unregister(frameworkID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.frameworks[frameworkID]; !exists {
		return fmt.Errorf("framework %s not found", frameworkID)
	}

	delete(r.frameworks, frameworkID)
	return nil
}

// Get retrieves a framework by ID
func (r *Registry) Get(frameworkID string) (common.Framework, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rf, exists := r.frameworks[frameworkID]
	if !exists {
		return nil, fmt.Errorf("framework %s not found", frameworkID)
	}

	return rf.Instance, nil
}

// GetRegisteredFramework returns the full registration info
func (r *Registry) GetRegisteredFramework(frameworkID string) (*RegisteredFramework, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rf, exists := r.frameworks[frameworkID]
	if !exists {
		return nil, fmt.Errorf("framework %s not found", frameworkID)
	}

	return rf, nil
}

// ListAll returns all registered frameworks
func (r *Registry) ListAll() []common.Framework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	frameworks := make([]common.Framework, 0, len(r.frameworks))
	for _, rf := range r.frameworks {
		frameworks = append(frameworks, rf.Instance)
	}
	return frameworks
}

// ListAllWithMetadata returns all frameworks with their metadata
func (r *Registry) ListAllWithMetadata() []*RegisteredFramework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*RegisteredFramework, 0, len(r.frameworks))
	for _, rf := range r.frameworks {
		result = append(result, rf)
	}
	return result
}

// GetByTier returns all frameworks accessible at the current tier
func (r *Registry) GetByTier() []common.Framework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	currentTier := r.tierManager.GetTier()
	var frameworks []common.Framework

	for _, rf := range r.frameworks {
		if currentTier >= rf.Tier {
			frameworks = append(frameworks, rf.Instance)
		}
	}
	return frameworks
}

// GetAvailableFrameworks returns frameworks available at current tier (alias)
func (r *Registry) GetAvailableFrameworks() []common.Framework {
	return r.GetByTier()
}

// GetByTierID returns frameworks for a specific tier
func (r *Registry) GetByTierID(tier Tier) []common.Framework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var frameworks []common.Framework
	for _, rf := range r.frameworks {
		if rf.Tier == tier {
			frameworks = append(frameworks, rf.Instance)
		}
	}
	return frameworks
}

// CheckAll runs all available frameworks against the input
func (r *Registry) CheckAll(ctx context.Context, input common.CheckInput) ([]*common.CheckResult, error) {
	r.mu.RLock()
	frameworks := r.GetByTier()
	r.mu.RUnlock()

	var results []*common.CheckResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, len(frameworks))

	for _, fw := range frameworks {
		if !fw.IsEnabled() {
			continue
		}

		wg.Add(1)
		go func(framework common.Framework) {
			defer wg.Done()

			result, err := framework.Check(ctx, input)
			if err != nil {
				errChan <- fmt.Errorf("framework %s check failed: %w", framework.GetFrameworkID(), err)
				return
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(fw)
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return results, fmt.Errorf("%d framework checks failed", len(errors))
	}

	return results, nil
}

// CheckFramework runs a specific framework by ID
func (r *Registry) CheckFramework(ctx context.Context, frameworkID string, input common.CheckInput) (*common.CheckResult, error) {
	fw, err := r.Get(frameworkID)
	if err != nil {
		return nil, err
	}

	// Check if framework is enabled
	if !fw.IsEnabled() {
		return nil, fmt.Errorf("framework %s is disabled", frameworkID)
	}

	// Check tier access
	_, err = r.GetRegisteredFramework(frameworkID)
	if err != nil {
		return nil, err
	}

	// Verify current tier allows access
	if !r.tierManager.IsFrameworkAllowed(frameworkID) {
		return nil, fmt.Errorf("framework %s requires higher tier license", frameworkID)
	}

	return fw.Check(ctx, input)
}

// EnableFramework enables a framework
func (r *Registry) EnableFramework(frameworkID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rf, exists := r.frameworks[frameworkID]
	if !exists {
		return fmt.Errorf("framework %s not found", frameworkID)
	}

	rf.Instance.Enable()
	return nil
}

// DisableFramework disables a framework
func (r *Registry) DisableFramework(frameworkID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	rf, exists := r.frameworks[frameworkID]
	if !exists {
		return fmt.Errorf("framework %s not found", frameworkID)
	}

	rf.Instance.Disable()
	return nil
}

// GetEnabledFrameworks returns currently enabled frameworks
func (r *Registry) GetEnabledFrameworks() []common.Framework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var enabled []common.Framework
	for _, rf := range r.frameworks {
		if rf.Instance.IsEnabled() {
			enabled = append(enabled, rf.Instance)
		}
	}
	return enabled
}

// GetDisabledFrameworks returns currently disabled frameworks
func (r *Registry) GetDisabledFrameworks() []common.Framework {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var disabled []common.Framework
	for _, rf := range r.frameworks {
		if !rf.Instance.IsEnabled() {
			disabled = append(disabled, rf.Instance)
		}
	}
	return disabled
}

// Count returns the total number of registered frameworks
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.frameworks)
}

// CountByTier returns the number of frameworks per tier
func (r *Registry) CountByTier() map[Tier]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	counts := make(map[Tier]int)
	for _, rf := range r.frameworks {
		counts[rf.Tier]++
	}
	return counts
}

// GetTierManager returns the tier manager
func (r *Registry) GetTierManager() *TierManager {
	return r.tierManager
}

// SetTier sets the current tier
func (r *Registry) SetTier(tier Tier) {
	r.tierManager.SetTier(tier)
}

// GetTier gets the current tier
func (r *Registry) GetTier() Tier {
	return r.tierManager.GetTier()
}

// Clear removes all frameworks from the registry
func (r *Registry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frameworks = make(map[string]*RegisteredFramework)
}

// GenerateReport generates a comprehensive registry report
func (r *Registry) GenerateReport() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	all := r.ListAllWithMetadata()
	enabled := r.GetEnabledFrameworks()

	report := map[string]interface{}{
		"total_frameworks": len(r.frameworks),
		"enabled_count":    len(enabled),
		"current_tier":     r.tierManager.GetTier().String(),
		"count_by_tier":    r.CountByTier(),
		"frameworks":       all,
	}

	return report
}

// Global singleton instance (optional - for convenience)
var (
	globalRegistry     *Registry
	globalRegistryOnce sync.Once
)

// GetGlobalRegistry returns the global registry instance
func GetGlobalRegistry() *Registry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewRegistry()
	})
	return globalRegistry
}

// ResetGlobalRegistry resets the global registry (mainly for testing)
func ResetGlobalRegistry() {
	globalRegistryOnce = sync.Once{}
	globalRegistry = nil
}
