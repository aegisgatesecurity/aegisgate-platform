// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package sandbox provides feed-level sandboxing capabilities
package sandbox

import (
	"fmt"
	"time"
)

// PolicyEngine evaluates and enforces sandbox policies
type PolicyEngine struct {
	validators []PolicyValidator
}

// PolicyValidator validates sandbox policies
type PolicyValidator interface {
	Validate(policy *SandboxPolicy) error
	Name() string
}

// ResourceQuotaValidator validates resource quotas
type ResourceQuotaValidator struct{}

func (v *ResourceQuotaValidator) Validate(policy *SandboxPolicy) error {
	quota := policy.ResourceQuota

	// Validate CPU quota
	if quota.CPU < 0 {
		return fmt.Errorf("CPU quota cannot be negative")
	}

	// Validate Memory quota
	if quota.Memory < 0 {
		return fmt.Errorf("memory quota cannot be negative")
	}

	// Validate Disk quota
	if quota.Disk < 0 {
		return fmt.Errorf("disk quota cannot be negative")
	}

	return nil
}

func (v *ResourceQuotaValidator) Name() string {
	return "ResourceQuotaValidator"
}

// IsolationLevelValidator validates isolation levels
type IsolationLevelValidator struct{}

func (v *IsolationLevelValidator) Validate(policy *SandboxPolicy) error {
	switch policy.IsolationLevel {
	case IsolationNone, IsolationPartial, IsolationFull:
		return nil
	default:
		return fmt.Errorf("invalid isolation level: %s", policy.IsolationLevel)
	}
}

func (v *IsolationLevelValidator) Name() string {
	return "IsolationLevelValidator"
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine() *PolicyEngine {
	engine := &PolicyEngine{
		validators: []PolicyValidator{
			&ResourceQuotaValidator{},
			&IsolationLevelValidator{},
		},
	}

	return engine
}

// Validate validates a sandbox policy
func (e *PolicyEngine) Validate(policy *SandboxPolicy) error {
	for _, validator := range e.validators {
		if err := validator.Validate(policy); err != nil {
			return fmt.Errorf("%s: %w", validator.Name(), err)
		}
	}
	return nil
}

// ValidateWithTimeout validates a policy with timeout
func (e *PolicyEngine) ValidateWithTimeout(policy *SandboxPolicy, timeout time.Duration) error {
	done := make(chan error, 1)

	go func() {
		done <- e.Validate(policy)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("validation timeout")
	}
}
