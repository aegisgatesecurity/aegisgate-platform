// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Capability Contract System
// =========================================================================

package contract

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Capability represents a specific action an agent can perform
type Capability string

const (
	// File System Capabilities
	CapFileRead    Capability = "file:read"
	CapFileWrite   Capability = "file:write"
	CapFileDelete  Capability = "file:delete"
	CapFileExecute Capability = "file:execute"

	// Network Capabilities
	CapNetHTTP     Capability = "net:http"
	CapNetHTTPS    Capability = "net:https"
	CapNetInternal Capability = "net:internal"
	CapNetExternal Capability = "net:external"

	// Terminal Capabilities
	CapTerminalExec Capability = "terminal:execute"
	CapTerminalSSH  Capability = "terminal:ssh"

	// Database Capabilities
	CapDBRead   Capability = "db:read"
	CapDBWrite  Capability = "db:write"
	CapDBDelete Capability = "db:delete"

	// API Capabilities
	CapAPIInternal Capability = "api:internal"
	CapAPIExternal Capability = "api:external"

	// Agent Capabilities
	CapAgentCall     Capability = "agent:call"
	CapAgentDelegate Capability = "agent:delegate"
	CapAgentSpawn    Capability = "agent:spawn"

	// Data Capabilities
	CapDataPII       Capability = "data:pii"
	CapDataSensitive Capability = "data:sensitive"
	CapDataExport    Capability = "data:export"

	// Admin Capabilities
	CapAdmin Capability = "admin:*"
)

// Scope defines the scope of a capability
type Scope string

const (
	ScopeGlobal   Scope = "global"
	ScopeLocal    Scope = "local"
	ScopeResource Scope = "resource"
)

// Resource represents a specific resource a capability applies to
type Resource struct {
	Type    string   `json:"type"`    // e.g., "file", "database", "api"
	Pattern string   `json:"pattern"` // e.g., "/data/*", "users:table"
	Actions []string `json:"actions"` // specific actions allowed
}

// Condition defines a condition that must be met for a capability
type Condition struct {
	Type     string            `json:"type"`     // "time", "rate", "approval", "context"
	Key      string            `json:"key"`      // condition identifier
	Operator string            `json:"operator"` // "eq", "ne", "gt", "lt", "in", "not_in"
	Value    interface{}       `json:"value"`    // comparison value
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ContractRule defines a single rule within a capability contract
type ContractRule struct {
	ID           string      `json:"id"`
	Capability   Capability  `json:"capability"`
	Scope        Scope       `json:"scope"`
	Resources    []Resource  `json:"resources,omitempty"`
	Conditions   []Condition `json:"conditions,omitempty"`
	RiskLevel    RiskLevel   `json:"riskLevel"`
	RequiresAppr bool        `json:"requiresApproval"`
	MaxPerHour   int         `json:"maxPerHour,omitempty"`
	ExpiresAt    *time.Time  `json:"expiresAt,omitempty"`
}

// RiskLevel represents the risk level of a capability
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// ContractStatus represents the status of a contract
type ContractStatus string

const (
	ContractStatusDraft     ContractStatus = "draft"
	ContractStatusActive    ContractStatus = "active"
	ContractStatusSuspended ContractStatus = "suspended"
	ContractStatusExpired   ContractStatus = "expired"
	ContractStatusRevoked   ContractStatus = "revoked"
)

// CapabilityContract represents a contract defining agent capabilities
type CapabilityContract struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	AgentID     string            `json:"agentId"`
	OwnerID     string            `json:"ownerId"`
	Version     string            `json:"version"`
	Rules       []ContractRule    `json:"rules"`
	Status      ContractStatus    `json:"status"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Fingerprint string            `json:"fingerprint"` // SHA-256 of rules
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
	ExpiresAt   *time.Time        `json:"expiresAt,omitempty"`
}

// NewContract creates a new capability contract
func NewContract(name, description, agentID, ownerID string, rules []ContractRule) (*CapabilityContract, error) {
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if agentID == "" {
		return nil, fmt.Errorf("agentId is required")
	}
	if ownerID == "" {
		return nil, fmt.Errorf("ownerId is required")
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("at least one rule is required")
	}

	now := time.Now().UTC()
	contract := &CapabilityContract{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		AgentID:     agentID,
		OwnerID:     ownerID,
		Version:     "1.0.0",
		Rules:       rules,
		Status:      ContractStatusDraft,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	contract.Fingerprint = contract.CalculateFingerprint()
	return contract, nil
}

// CalculateFingerprint generates a SHA-256 fingerprint of the contract rules
func (c *CapabilityContract) CalculateFingerprint() string {
	data, _ := json.Marshal(c.Rules)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

// HasCapability checks if the contract grants a specific capability
func (c *CapabilityContract) HasCapability(cap Capability) bool {
	if c.Status != ContractStatusActive {
		return false
	}
	for _, rule := range c.Rules {
		if rule.Capability == cap || rule.Capability == CapAdmin {
			return true
		}
	}
	return false
}

// HasCapabilityWithScope checks if the contract grants a capability within a specific scope
func (c *CapabilityContract) HasCapabilityWithScope(cap Capability, scope Scope) bool {
	if c.Status != ContractStatusActive {
		return false
	}
	for _, rule := range c.Rules {
		if rule.Capability == cap && rule.Scope == scope {
			return true
		}
		if rule.Capability == CapAdmin {
			return true
		}
	}
	return false
}

// IsResourceAllowed checks if a resource is allowed for a capability
func (c *CapabilityContract) IsResourceAllowed(cap Capability, resourceType, resourcePattern string) bool {
	if c.Status != ContractStatusActive {
		return false
	}
	for _, rule := range c.Rules {
		if rule.Capability == cap || rule.Capability == CapAdmin {
			if len(rule.Resources) == 0 {
				return true // No specific resources means all are allowed
			}
			for _, res := range rule.Resources {
				if res.Type == resourceType {
					return true
				}
			}
		}
	}
	return false
}

// GetCapabilities returns all capabilities defined in the contract
func (c *CapabilityContract) GetCapabilities() []Capability {
	caps := make(map[Capability]bool)
	for _, rule := range c.Rules {
		caps[rule.Capability] = true
	}
	result := make([]Capability, 0, len(caps))
	for cap := range caps {
		result = append(result, cap)
	}
	return result
}

// GetHighRiskCapabilities returns capabilities with high or critical risk
func (c *CapabilityContract) GetHighRiskCapabilities() []Capability {
	var result []Capability
	for _, rule := range c.Rules {
		if rule.RiskLevel == RiskHigh || rule.RiskLevel == RiskCritical {
			result = append(result, rule.Capability)
		}
	}
	return result
}

// RequiresApproval checks if a capability requires approval
func (c *CapabilityContract) RequiresApproval(cap Capability) bool {
	for _, rule := range c.Rules {
		if rule.Capability == cap || rule.Capability == CapAdmin {
			return rule.RequiresAppr
		}
	}
	return false
}

// IsExpired checks if the contract has expired
func (c *CapabilityContract) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// CanVerify returns true if the contract can be used for verification
func (c *CapabilityContract) CanVerify() bool {
	return c.Status == ContractStatusActive && !c.IsExpired()
}

// ToJSON serializes the contract to JSON
func (c *CapabilityContract) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

// FromJSON deserializes a contract from JSON
func FromJSON(data []byte) (*CapabilityContract, error) {
	var contract CapabilityContract
	if err := json.Unmarshal(data, &contract); err != nil {
		return nil, fmt.Errorf("failed to unmarshal contract: %w", err)
	}
	return &contract, nil
}
