// Package tier provides a unified tier system for the consolidated AegisGuard/AegisGate platform
// This file standardizes the 4-tier system across both products
package tier

import (
	"fmt"
	"strings"
)

// Tier represents a license tier in the unified system
type Tier int

const (
	// TierCommunity represents the free community tier
	TierCommunity Tier = iota
	// TierDeveloper represents the developer tier
	TierDeveloper
	// TierProfessional represents the professional tier  
	TierProfessional
	// TierEnterprise represents the enterprise tier
	TierEnterprise
)

// String returns the tier name
func (t Tier) String() string {
	switch t {
	case TierCommunity:
		return "community"
	case TierDeveloper:
		return "developer"
	case TierProfessional:
		return "professional"
	case TierEnterprise:
		return "enterprise"
	default:
		return "unknown"
	}
}

// DisplayName returns the display name for the tier
func (t Tier) DisplayName() string {
	switch t {
	case TierCommunity:
		return "Community"
	case TierDeveloper:
		return "Developer"
	case TierProfessional:
		return "Professional"
	case TierEnterprise:
		return "Enterprise"
	default:
		return "Unknown"
	}
}

// ParseTier converts a string to a Tier
func ParseTier(name string) (Tier, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "community":
		return TierCommunity, nil
	case "developer":
		return TierDeveloper, nil
	case "professional":
		return TierProfessional, nil
	case "enterprise":
		return TierEnterprise, nil
	default:
		return 0, fmt.Errorf("invalid tier: %s", name)
	}
}

// Features represents the feature flags for a tier
type Features struct {
	// Core Features
	LicenseValidation bool
	Compliance        bool
	Metrics           bool
	AuditLogging      bool
	Certificate       bool
	// RBAC Features
	RBAC              bool
	RBACGroups        bool
	RBACPermissions   bool
	// Tool Features
	ToolRegistry      bool
	ToolExecution     bool
	ToolExecutionLimit int
	// Network Features
	Proxy             bool
	Websocket         bool
	// Security Features
	SecurityScanning  bool
	ThreatIntelligence bool
	MachineLearning   bool
	// Reporting Features
	Reporting         bool
	SIEMIntegration   bool
	// Admin Features
	AdminPanel        bool
	AdminAPI          bool
	// Migration Features
	Migration         bool
}

// GetFeatures returns the features available for a given tier
func GetFeatures(tier Tier) Features {
	var f Features
	
	// Base features (all tiers)
	f.LicenseValidation = true
	f.Compliance = true
	f.Metrics = true
	f.AuditLogging = true
	f.Certificate = true
	
	switch tier {
	case TierCommunity:
		// Community tier features
		f.RBAC = true
		f.RBACGroups = true
		f.ToolRegistry = true
		f.ToolExecution = true
		f.ToolExecutionLimit = 1
		f.Proxy = true
		f.Websocket = true
		f.SecurityScanning = true
		f.Reporting = true
		f.AdminPanel = true
		f.AdminAPI = true
	case TierDeveloper:
		// Developer tier features (enhanced)
		f.RBAC = true
		f.RBACGroups = true
		f.RBACPermissions = true
		f.ToolRegistry = true
		f.ToolExecution = true
		f.ToolExecutionLimit = 5
		f.Proxy = true
		f.Websocket = true
		f.SecurityScanning = true
		f.ThreatIntelligence = true
		f.Reporting = true
		f.SIEMIntegration = true
		f.AdminPanel = true
		f.AdminAPI = true
	case TierProfessional:
		// Professional tier features (full)
		f.RBAC = true
		f.RBACGroups = true
		f.RBACPermissions = true
		f.ToolRegistry = true
		f.ToolExecution = true
		f.ToolExecutionLimit = 20
		f.Proxy = true
		f.Websocket = true
		f.SecurityScanning = true
		f.ThreatIntelligence = true
		f.MachineLearning = true
		f.Reporting = true
		f.SIEMIntegration = true
		f.AdminPanel = true
		f.AdminAPI = true
	case TierEnterprise:
		// Enterprise tier features (all, with unlimited)
		f.RBAC = true
		f.RBACGroups = true
		f.RBACPermissions = true
		f.ToolRegistry = true
		f.ToolExecution = true
		f.ToolExecutionLimit = -1 // Unlimited
		f.Proxy = true
		f.Websocket = true
		f.SecurityScanning = true
		f.ThreatIntelligence = true
		f.MachineLearning = true
		f.Reporting = true
		f.SIEMIntegration = true
		f.AdminPanel = true
		f.AdminAPI = true
	}
	
	return f
}

// HasFeature checks if a tier has a specific feature
func HasFeature(tier Tier, feature string) bool {
	features := GetFeatures(tier)
	
	switch feature {
	case "RBAC":
		return features.RBAC
	case "RBACGroups":
		return features.RBACGroups
	case "RBACPermissions":
		return features.RBACPermissions
	case "ToolRegistry":
		return features.ToolRegistry
	case "ToolExecution":
		return features.ToolExecution
	case "ToolExecutionLimit":
		return features.ToolExecutionLimit > 0
	case "Proxy":
		return features.Proxy
	case "Websocket":
		return features.Websocket
	case "SecurityScanning":
		return features.SecurityScanning
	case "ThreatIntelligence":
		return features.ThreatIntelligence
	case "MachineLearning":
		return features.MachineLearning
	case "Reporting":
		return features.Reporting
	case "SIEMIntegration":
		return features.SIEMIntegration
	case "AdminPanel":
		return features.AdminPanel
	case "AdminAPI":
		return features.AdminAPI
	default:
		return false
	}
}

// TierLimit returns the limit for a feature in a tier
func TierLimit(tier Tier, feature string) int {
	features := GetFeatures(tier)
	
	switch feature {
	case "ToolExecutionLimit":
		return features.ToolExecutionLimit
	default:
		return -1 // No limit or unlimited
	}
}

// IsEnterprise returns true if tier is enterprise or above
func IsEnterprise(tier Tier) bool {
	return tier == TierEnterprise
}

// IsProfessionalOrAbove returns true if tier is professional or above
func IsProfessionalOrAbove(tier Tier) bool {
	return tier >= TierProfessional
}

// IsDeveloperOrAbove returns true if tier is developer or above
func IsDeveloperOrAbove(tier Tier) bool {
	return tier >= TierDeveloper
}
