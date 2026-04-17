// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard License Tier Features
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file defines which features are available in each tier.
// Tiers are cumulative: Enterprise includes all features from all lower tiers.
//
// Tier Hierarchy:
// Community (0) -> Developer (1) -> Professional (2) -> Enterprise (3)

package license

// FeatureTierMapping defines which features are available at each tier
// AegisGuard focuses on security tools for AI agents
var FeatureTierMapping = map[string]Tier{
	// ========================================================================
	// CORE SECURITY TOOLS - Community Tier
	// ========================================================================
	"file_read":        TierCommunity,
	"file_write":       TierDeveloper,    // Higher risk
	"file_delete":      TierProfessional, // Highest risk
	"directory_list":   TierCommunity,
	"directory_create": TierDeveloper,
	"directory_delete": TierProfessional,

	// ========================================================================
	// NETWORK TOOLS - Community + Developer
	// ========================================================================
	"http_get":    TierCommunity,
	"http_post":   TierDeveloper,
	"http_put":    TierProfessional,
	"http_delete": TierProfessional,
	"web_search":  TierCommunity,
	"web_fetch":   TierDeveloper,
	"websocket":   TierProfessional,

	// ========================================================================
	// CODE EXECUTION - Developer+
	// ========================================================================
	"shell_exec":        TierDeveloper,    // Basic shell commands
	"shell_privileged":  TierProfessional, // Sudo/root commands
	"code_execute":      TierDeveloper,    // Sandboxed code execution
	"code_unrestricted": TierEnterprise,   // Unrestricted code execution
	"container_exec":    TierProfessional, // Docker/container commands
	"vm_exec":           TierEnterprise,   // VM execution

	// ========================================================================
	// GIT & VERSION CONTROL - Community+
	// ========================================================================
	"git_status": TierCommunity,
	"git_log":    TierCommunity,
	"git_diff":   TierCommunity,
	"git_commit": TierDeveloper,
	"git_push":   TierProfessional,
	"git_branch": TierDeveloper,
	"git_merge":  TierProfessional,

	// ========================================================================
	// DATABASE TOOLS - Professional+
	// ========================================================================
	"db_query":  TierDeveloper,
	"db_write":  TierProfessional,
	"db_admin":  TierEnterprise,
	"db_schema": TierProfessional,

	// ========================================================================
	// CLOUD PROVIDERS - Professional+
	// ========================================================================
	"aws_basic":   TierDeveloper,
	"aws_full":    TierProfessional,
	"aws_admin":   TierEnterprise,
	"gcp_basic":   TierDeveloper,
	"gcp_full":    TierProfessional,
	"azure_basic": TierDeveloper,
	"azure_full":  TierProfessional,

	// ========================================================================
	// AI PROVIDERS - Developer+
	// ========================================================================
	"ai_openai":    TierCommunity,    // OpenAI API
	"ai_anthropic": TierCommunity,    // Anthropic API
	"ai_google":    TierDeveloper,    // Google AI
	"ai_local":     TierDeveloper,    // Local models
	"ai_custom":    TierProfessional, // Custom AI endpoints

	// ========================================================================
	// BROWSER AUTOMATION - Developer+
	// ========================================================================
	"browser_navigate":   TierCommunity,
	"browser_interact":   TierDeveloper,
	"browser_screenshot": TierCommunity,
	"browser_cookies":    TierProfessional,
	"browser_storage":    TierProfessional,

	// ========================================================================
	// MCP (Model Context Protocol) - Developer+
	// ========================================================================
	"mcp_tools":     TierCommunity,    // Execute MCP tools
	"mcp_resources": TierCommunity,    // Read MCP resources
	"mcp_prompts":   TierDeveloper,    // Use MCP prompts
	"mcp_server":    TierProfessional, // Host MCP server

	// ========================================================================
	// SECURITY & COMPLIANCE - Community+
	// ========================================================================
	"audit_log":             TierCommunity,    // Basic audit logging
	"audit_export":          TierDeveloper,    // Export audit logs
	"audit_advanced":        TierProfessional, // Advanced audit analytics
	"compliance_basic":      TierCommunity,    // OWASP basic checks
	"compliance_standard":   TierDeveloper,    // Standard compliance (GDPR, SOC2 view)
	"compliance_advanced":   TierProfessional, // HIPAA, PCI, SOC2 full
	"compliance_enterprise": TierEnterprise,   // FedRAMP, ISO 42001

	// ========================================================================
	// SANDBOX & ISOLATION - Developer+
	// ========================================================================
	"session_isolation": TierCommunity,    // Basic session isolation
	"context_isolation": TierDeveloper,    // Full context isolation
	"process_sandbox":   TierProfessional, // Process-level sandboxing
	"vm_sandbox":        TierEnterprise,   // VM-level sandboxing

	// ========================================================================
	// PERMISSIONS & AUTHORIZATION - Community+
	// ========================================================================
	"rbac_basic":        TierCommunity,    // Basic RBAC
	"rbac_advanced":     TierDeveloper,    // Advanced RBAC
	"rbac_custom":       TierProfessional, // Custom roles
	"policy_engine":     TierProfessional, // Custom policy engine
	"approval_workflow": TierEnterprise,   // Approval workflows

	// ========================================================================
	// INTEGRATIONS - Developer+
	// ========================================================================
	"github":     TierCommunity,
	"github_org": TierDeveloper,
	"gitlab":     TierDeveloper,
	"bitbucket":  TierDeveloper,
	"jira":       TierDeveloper,
	"slack":      TierCommunity,
	"discord":    TierCommunity,
	"teams":      TierDeveloper,
	"email":      TierCommunity,

	// ========================================================================
	// DEPLOYMENT - Professional+
	// ========================================================================
	"deploy_docker":     TierCommunity,
	"deploy_kubernetes": TierProfessional,
	"deploy_terraform":  TierDeveloper,
	"deploy_helm":       TierProfessional,
	"deploy_airgapped":  TierEnterprise,

	// ========================================================================
	// OBSERVABILITY - Community+
	// ========================================================================
	"metrics":    TierCommunity,
	"logs":       TierCommunity,
	"traces":     TierDeveloper,
	"alerts":     TierDeveloper,
	"dashboards": TierProfessional,
	"grafana":    TierDeveloper,
	"prometheus": TierDeveloper,
	"datadog":    TierProfessional,
	"splunk":     TierEnterprise,

	// ========================================================================
	// RATE LIMITS - Community+
	// ========================================================================
	"rate_limit_basic":     TierCommunity,    // Basic rate limiting
	"rate_limit_custom":    TierDeveloper,    // Custom rate limits
	"rate_limit_tenant":    TierProfessional, // Per-tenant limits
	"rate_limit_unlimited": TierEnterprise,   // Unlimited (with fair use)

	// ========================================================================
	// SUPPORT - Community+
	// ========================================================================
	"support_community": TierCommunity,    // GitHub Issues
	"support_docs":      TierCommunity,    // Documentation
	"support_email":     TierDeveloper,    // Email support
	"support_priority":  TierProfessional, // Priority email
	"support_dedicated": TierEnterprise,   // Dedicated support
	"support_sla":       TierEnterprise,   // SLA guarantees
}

// TierLimits defines resource constraints per tier
type TierLimits struct {
	// Rate Limits
	MaxRequestsPerMinute  int
	MaxConcurrentSessions int
	MaxBurstRequests      int

	// Resource Limits
	MaxUsers    int
	MaxSessions int
	MaxAgents   int

	// Tool Limits
	MaxToolsPerSession int
	MaxExecutionTime   int // seconds
	MaxMemoryMB        int

	// Data Limits
	LogRetentionDays   int
	MaxLogSizeMB       int
	AuditRetentionDays int

	// Feature Limits
	MaxPolicies     int
	MaxCustomRules  int
	MaxIntegrations int

	// Support
	SupportLevel      string
	ResponseTimeHours int
}

// GetTierLimits returns resource limits for a tier
func GetTierLimits(tier Tier) TierLimits {
	switch tier {
	case TierCommunity:
		return TierLimits{
			MaxRequestsPerMinute:  100,
			MaxConcurrentSessions: 5,
			MaxBurstRequests:      25,
			MaxUsers:              3,
			MaxSessions:           10,
			MaxAgents:             1,
			MaxToolsPerSession:    20,
			MaxExecutionTime:      30,
			MaxMemoryMB:           256,
			LogRetentionDays:      1,
			MaxLogSizeMB:          100,
			AuditRetentionDays:    7,
			MaxPolicies:           5,
			MaxCustomRules:        0,
			MaxIntegrations:       3,
			SupportLevel:          "community",
			ResponseTimeHours:     0, // No SLA
		}

	case TierDeveloper:
		return TierLimits{
			MaxRequestsPerMinute:  500,
			MaxConcurrentSessions: 25,
			MaxBurstRequests:      100,
			MaxUsers:              10,
			MaxSessions:           50,
			MaxAgents:             5,
			MaxToolsPerSession:    50,
			MaxExecutionTime:      60,
			MaxMemoryMB:           512,
			LogRetentionDays:      7,
			MaxLogSizeMB:          1024,
			AuditRetentionDays:    30,
			MaxPolicies:           20,
			MaxCustomRules:        10,
			MaxIntegrations:       10,
			SupportLevel:          "email",
			ResponseTimeHours:     48,
		}

	case TierProfessional:
		return TierLimits{
			MaxRequestsPerMinute:  2000,
			MaxConcurrentSessions: 100,
			MaxBurstRequests:      500,
			MaxUsers:              25,
			MaxSessions:           500,
			MaxAgents:             25,
			MaxToolsPerSession:    -1, // Unlimited
			MaxExecutionTime:      300,
			MaxMemoryMB:           2048,
			LogRetentionDays:      30,
			MaxLogSizeMB:          10240,
			AuditRetentionDays:    90,
			MaxPolicies:           100,
			MaxCustomRules:        -1, // Unlimited
			MaxIntegrations:       50,
			SupportLevel:          "priority",
			ResponseTimeHours:     24,
		}

	case TierEnterprise:
		return TierLimits{
			MaxRequestsPerMinute:  -1, // Unlimited
			MaxConcurrentSessions: -1,
			MaxBurstRequests:      -1,
			MaxUsers:              -1,
			MaxSessions:           -1,
			MaxAgents:             -1,
			MaxToolsPerSession:    -1,
			MaxExecutionTime:      -1,
			MaxMemoryMB:           -1,
			LogRetentionDays:      -1,
			MaxLogSizeMB:          -1,
			AuditRetentionDays:    -1,
			MaxPolicies:           -1,
			MaxCustomRules:        -1,
			MaxIntegrations:       -1,
			SupportLevel:          "24x7",
			ResponseTimeHours:     4,
		}

	default:
		return GetTierLimits(TierCommunity)
	}
}

// GetRequiredTier returns the tier required for a feature
func GetRequiredTier(feature string) Tier {
	if tier, ok := FeatureTierMapping[feature]; ok {
		return tier
	}
	return TierCommunity
}

// CanAccess checks if a tier can access a feature
func CanAccess(tier Tier, feature string) bool {
	requiredTier := GetRequiredTier(feature)
	return tier >= requiredTier
}

// GetFeaturesByTier returns all features available at a tier level
func GetFeaturesByTier(tier Tier) []string {
	var features []string
	for feature, requiredTier := range FeatureTierMapping {
		if tier >= requiredTier {
			features = append(features, feature)
		}
	}
	return features
}

// GetCommunityFeatures returns Community tier features
func GetCommunityFeatures() []string {
	return GetFeaturesByTier(TierCommunity)
}

// GetDeveloperFeatures returns Developer tier features
func GetDeveloperFeatures() []string {
	return GetFeaturesByTier(TierDeveloper)
}

// GetProfessionalFeatures returns Professional tier features
func GetProfessionalFeatures() []string {
	return GetFeaturesByTier(TierProfessional)
}

// GetEnterpriseFeatures returns Enterprise tier features
func GetEnterpriseFeatures() []string {
	return GetFeaturesByTier(TierEnterprise)
}

// GetUpgradePath returns the next tier in the upgrade path
func GetUpgradePath(current Tier) Tier {
	switch current {
	case TierCommunity:
		return TierDeveloper
	case TierDeveloper:
		return TierProfessional
	case TierProfessional:
		return TierEnterprise
	default:
		return TierEnterprise
	}
}

// GetAllTiers returns all available tiers in order
func GetAllTiers() []Tier {
	return []Tier{
		TierCommunity,
		TierDeveloper,
		TierProfessional,
		TierEnterprise,
	}
}
