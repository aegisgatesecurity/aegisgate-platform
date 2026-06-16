// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ACP Capability Enforcement
// =========================================================================

package acp

import (
	"sync"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// CapabilityEnforcer enforces ACP capabilities
type CapabilityEnforcer struct {
	mu           sync.RWMutex
	capabilities map[string]map[string]bool // identity -> capability -> allowed

	// Default policy
	defaultAllowed bool
}

// NewCapabilityEnforcer creates a new capability enforcer
func NewCapabilityEnforcer() *CapabilityEnforcer {
	return &CapabilityEnforcer{
		capabilities:   make(map[string]map[string]bool),
		defaultAllowed: false, // Fail closed by default
	}
}

// Allow grants a capability to an identity
func (ce *CapabilityEnforcer) Allow(identity, capability string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if ce.capabilities[identity] == nil {
		ce.capabilities[identity] = make(map[string]bool)
	}
	ce.capabilities[identity][capability] = true
}

// Disallow revokes a capability from an identity
func (ce *CapabilityEnforcer) Disallow(identity, capability string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if ce.capabilities[identity] != nil {
		delete(ce.capabilities[identity], capability)
	}
}

// Check verifies if an identity has a capability
func (ce *CapabilityEnforcer) Check(identity, capability string) bool {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	if caps, exists := ce.capabilities[identity]; exists {
		if allowed, exists := caps[capability]; exists {
			if !allowed {
				logging.Record(logging.Event{
					Type:     "acp_capability",
					Severity: logging.SeverityHigh,
					Action:   "deny",
					Message:  "ACP capability denied: identity=" + identity + " capability=" + capability,
					User:     identity,
				})
			}
			return allowed
		}
	}

	if !ce.defaultAllowed {
		logging.Record(logging.Event{
			Type:     "acp_capability",
			Severity: logging.SeverityHigh,
			Action:   "deny",
			Message:  "ACP capability denied (default-deny): identity=" + identity + " capability=" + capability,
			User:     identity,
		})
	}
	return ce.defaultAllowed
}

// GetCapabilities returns all capabilities for an identity
func (ce *CapabilityEnforcer) GetCapabilities(identity string) []string {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	if caps, exists := ce.capabilities[identity]; exists {
		result := make([]string, 0, len(caps))
		for cap, allowed := range caps {
			if allowed {
				result = append(result, cap)
			}
		}
		return result
	}

	return nil
}

// Clear removes all capabilities for an identity
func (ce *CapabilityEnforcer) Clear(identity string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	delete(ce.capabilities, identity)
}

// Common ACP capabilities
const (
	CapabilityExecuteTerminal = "terminal.execute"
	CapabilityWriteFile       = "fs.write"
	CapabilityReadFile        = "fs.read"
	CapabilityHttpRequest     = "http.request"
	CapabilityReadEnv         = "env.read"
)
