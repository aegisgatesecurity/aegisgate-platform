// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package core provides tier and feature management for AegisGate.
// This file defines the 4-tier system: Community -> Developer -> Professional -> Enterprise
package core

import "fmt"

// FeatureTierMapping defines which features are available in each tier
// Tiers (lowest to highest): Community -> Developer -> Professional -> Enterprise

var FeatureTierMapping = map[string]Tier{
	// ============================================================================
	// AI PROXY & CONNECTIVITY
	// ============================================================================

	// Basic Connectivity
	"ai_proxy":           TierCommunity,
	"openai":             TierCommunity,
	"anthropic":          TierCommunity,
	"cohere":             TierDeveloper,
	"azure_openai":       TierDeveloper,
	"aws_bedrock":        TierProfessional,
	"google_vertex":      TierEnterprise,
	"request_caching":    TierDeveloper,
	"request_dedup":      TierDeveloper,
	"batch_processing":   TierProfessional,
	"connection_pooling": TierProfessional,
	"streaming":          TierCommunity,

	// ============================================================================
	// SECURITY
	// ============================================================================

	"tls_termination":   TierCommunity,
	"mtls":              TierDeveloper,
	"pki_attestation":   TierProfessional,
	"secret_rotation":   TierProfessional,
	"oauth_sso":         TierDeveloper,
	"saml":              TierProfessional,
	"oidc":              TierProfessional,
	"ldap_integration":  TierEnterprise,
	"hardware_token":    TierEnterprise,
	"hsm_integration":   TierEnterprise,
	"audit_encryption":  TierProfessional,
	"fips_compliance":   TierEnterprise,
	"runtime_hardening": TierDeveloper,

	// ============================================================================
	// COMPLIANCE FRAMEWORKS - Community
	// ============================================================================
	"compliance_owasp":     TierCommunity,
	"compliance_soc2_view": TierCommunity,
	"compliance_gdpr_view": TierCommunity,

	// ============================================================================
	// COMPLIANCE FRAMEWORKS - Developer
	// ============================================================================
	"compliance_basic_security": TierDeveloper,
	"compliance_nist_view":      TierDeveloper,

	// ============================================================================
	// COMPLIANCE FRAMEWORKS - Professional
	// ============================================================================
	"compliance_hipaa":            TierProfessional,
	"compliance_pci":              TierProfessional,
	"compliance_soc2":             TierProfessional,
	"compliance_gdpr":             TierProfessional,
	"compliance_nist":             TierProfessional,
	"compliance_iso27001":         TierProfessional,
	"compliance_custom_framework": TierProfessional,

	// ============================================================================
	// COMPLIANCE FRAMEWORKS - Enterprise
	// ============================================================================
	"compliance_iso42001":    TierEnterprise,
	"compliance_nist_ai_rmf": TierEnterprise,
	"compliance_hitrust":     TierEnterprise,
	"compliance_fedramp":     TierEnterprise,
	"compliance_atlas":       TierEnterprise,
	"compliance_cobit":       TierEnterprise,
	"compliance_nist_csf":    TierEnterprise,
	"compliance_glba":        TierEnterprise,
	"compliance_sox":         TierEnterprise,

	// ============================================================================
	// ML & ANOMALY DETECTION
	// ============================================================================
	"ml_basic_anomaly":     TierCommunity,
	"ml_traffic_pattern":   TierCommunity,
	"ml_cost_anomaly":      TierDeveloper,
	"ml_usage_anomaly":     TierDeveloper,
	"ml_behavioral":        TierProfessional,
	"ml_predictive":        TierProfessional,
	"ml_threat_detection":  TierProfessional,
	"ml_custom_models":     TierEnterprise,
	"ml_realtime_response": TierEnterprise,
	"ml_zeroday":           TierEnterprise,

	// ============================================================================
	// MULTI-TENANCY
	// ============================================================================
	"multi_tenant":           TierProfessional,
	"granular_permissions":   TierDeveloper,
	"department_separation":  TierProfessional,
	"custom_roles":           TierDeveloper,
	"policy_engine":          TierProfessional,
	"cross_tenant_analytics": TierEnterprise,
	"whitelabel":             TierEnterprise,
	"custom_domain":          TierEnterprise,

	// ============================================================================
	// OBSERVABILITY
	// ============================================================================
	"metrics":               TierCommunity,
	"request_logging":       TierCommunity,
	"error_tracking":        TierCommunity,
	"grafana":               TierDeveloper,
	"siem_datadog":          TierProfessional, // SIEM integration
	"siem_newrelic":         TierProfessional, // Monitoring integration
	"custom_metrics":        TierProfessional,
	"siem_integration":      TierProfessional,
	"siem_splunk":           TierProfessional, // SIEM integration
	"elastic":               TierProfessional,
	"siem_qradar":           TierEnterprise, // SIEM integration
	"siem_azuresentinel":    TierEnterprise, // SIEM integration
	"monitoring_cloudwatch": TierDeveloper,  // Monitoring integration

	// ============================================================================
	// API & INTEGRATIONS
	// ============================================================================
	"rest_api":          TierCommunity,
	"grpc_api":          TierDeveloper,
	"graphql":           TierEnterprise,
	"webhooks":          TierDeveloper,
	"serverless":        TierEnterprise,
	"terraform":         TierDeveloper,
	"kubernetes":        TierProfessional,
	"helm":              TierProfessional,
	"ansible":           TierProfessional,
	"sdk":               TierProfessional,
	"browser_extension": TierEnterprise,

	// ============================================================================
	// STORAGE
	// ============================================================================
	"storage_inmemory":   TierCommunity,
	"storage_file":       TierCommunity,
	"storage_postgres":   TierDeveloper,
	"storage_mysql":      TierDeveloper,
	"storage_redis":      TierDeveloper,
	"storage_mongo":      TierEnterprise,
	"storage_s3":         TierProfessional,
	"data_encryption":    TierDeveloper,
	"retention_policies": TierProfessional,

	// ============================================================================
	// DEPLOYMENT
	// ============================================================================
	"deploy_docker":       TierCommunity,
	"deploy_compose":      TierCommunity,
	"deploy_kubernetes":   TierProfessional,
	"deploy_terraform":    TierDeveloper,
	"deploy_helm":         TierProfessional,
	"deploy_service_mesh": TierEnterprise,
	"deploy_autoscale":    TierEnterprise,
	"deploy_ha":           TierEnterprise,
	"deploy_multiregion":  TierEnterprise,
	"deploy_onprem":       TierEnterprise,
	"deploy_airgapped":    TierEnterprise,

	// ============================================================================
	// SUPPORT
	// ============================================================================
	"support_docs":      TierCommunity,
	"support_forum":     TierCommunity,
	"support_kb":        TierDeveloper,
	"support_email":     TierDeveloper,
	"support_priority":  TierProfessional,
	"support_dedicated": TierEnterprise,
	"support_phone":     TierEnterprise,
	"support_247":       TierEnterprise,

	// ============================================================================
	// ADMIN & BILLING
	// ============================================================================
	"admin_dashboard":  TierCommunity,
	"admin_advanced":   TierDeveloper,
	"admin_enterprise": TierEnterprise,
	"license_server":   TierProfessional,
	"usage_billing":    TierEnterprise,
	"multi_org":        TierEnterprise,
}

// GetRequiredTier returns the tier required for a feature
func GetRequiredTier(feature string) Tier {
	if tier, ok := FeatureTierMapping[feature]; ok {
		return tier
	}
	return TierCommunity // Default to community if feature not found
}

// CanAccess checks if a tier can access a feature
func (t Tier) CanAccess(requiredTier Tier) bool {
	switch requiredTier {
	case TierCommunity:
		return true
	case TierDeveloper:
		return t >= TierDeveloper
	case TierProfessional:
		return t >= TierProfessional
	case TierEnterprise:
		return t == TierEnterprise
	default:
		return false
	}
}

// IsValid checks if the tier level is valid
func (t Tier) IsValid() bool {
	return t >= TierCommunity && t <= TierEnterprise
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

// GetFeaturesByTier returns all features available to a tier
func GetFeaturesByTier(tier Tier) []string {
	var features []string
	for feature, requiredTier := range FeatureTierMapping {
		if tier.CanAccess(requiredTier) {
			features = append(features, feature)
		}
	}
	return features
}

// GetCommunityFeatures returns all community-available features
func GetCommunityFeatures() []string {
	return GetFeaturesByTier(TierCommunity)
}

// GetDeveloperFeatures returns all developer-available features
func GetDeveloperFeatures() []string {
	return GetFeaturesByTier(TierDeveloper)
}

// GetProfessionalFeatures returns all professional-available features
func GetProfessionalFeatures() []string {
	return GetFeaturesByTier(TierProfessional)
}

// GetEnterpriseFeatures returns all enterprise-available features
func GetEnterpriseFeatures() []string {
	return GetFeaturesByTier(TierEnterprise)
}

// GetUpgradePath returns the next tier to upgrade to
func (t Tier) GetUpgradePath() Tier {
	switch t {
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

// TierLimits defines resource constraints per tier
type TierLimits struct {
	// Rate Limits
	MaxRequestsPerMinute     int
	MaxConcurrentConnections int
	MaxBurstRequests         int

	// Resource Limits
	MaxUsers   int
	MaxAPIKeys int
	MaxTenants int

	// Storage Limits
	LogRetentionDays  int
	MaxLogSizeMB      int
	DataRetentionDays int

	// Feature Limits
	MaxCustomRules   int
	MaxWebhooks      int
	MaxCustomDomains int

	// Support
	SupportLevel string
}

// GetTierLimits returns resource limits for a tier
func (t Tier) GetTierLimits() TierLimits {
	switch t {
	case TierCommunity:
		return TierLimits{
			// Rate Limits - Generous for growth
			MaxRequestsPerMinute:     200,
			MaxConcurrentConnections: 5,
			MaxBurstRequests:         50,

			// Resource Limits
			MaxUsers:   3,
			MaxAPIKeys: 3,
			MaxTenants: 1,

			// Storage Limits
			LogRetentionDays:  1,
			MaxLogSizeMB:      100,
			DataRetentionDays: 7,

			// Feature Limits
			MaxCustomRules:   0,
			MaxWebhooks:      3,
			MaxCustomDomains: 0,

			// Support
			SupportLevel: "community",
		}
	case TierDeveloper:
		return TierLimits{
			// Rate Limits - Production-ready
			MaxRequestsPerMinute:     1000,
			MaxConcurrentConnections: 25,
			MaxBurstRequests:         200,

			// Resource Limits
			MaxUsers:   10,
			MaxAPIKeys: 10,
			MaxTenants: 1,

			// Storage Limits
			LogRetentionDays:  7,
			MaxLogSizeMB:      1024,
			DataRetentionDays: 30,

			// Feature Limits
			MaxCustomRules:   5,
			MaxWebhooks:      10,
			MaxCustomDomains: 0,

			// Support
			SupportLevel: "email",
		}
	case TierProfessional:
		return TierLimits{
			// Rate Limits - High traffic
			MaxRequestsPerMinute:     5000,
			MaxConcurrentConnections: 100,
			MaxBurstRequests:         500,

			// Resource Limits
			MaxUsers:   25,
			MaxAPIKeys: 50,
			MaxTenants: 25,

			// Storage Limits
			LogRetentionDays:  30,
			MaxLogSizeMB:      10240,
			DataRetentionDays: 90,

			// Feature Limits
			MaxCustomRules:   -1, // Unlimited
			MaxWebhooks:      25,
			MaxCustomDomains: 0,

			// Support
			SupportLevel: "priority",
		}
	case TierEnterprise:
		return TierLimits{
			// Rate Limits - Unlimited
			MaxRequestsPerMinute:     -1, // Unlimited
			MaxConcurrentConnections: -1,
			MaxBurstRequests:         -1,

			// Resource Limits
			MaxUsers:   -1, // Unlimited
			MaxAPIKeys: -1,
			MaxTenants: -1,

			// Storage Limits
			LogRetentionDays:  -1, // Unlimited
			MaxLogSizeMB:      -1,
			DataRetentionDays: -1,

			// Feature Limits
			MaxCustomRules:   -1,
			MaxWebhooks:      -1,
			MaxCustomDomains: -1,

			// Support
			SupportLevel: "24x7",
		}
	default:
		return TierLimits{}
	}
}

// FormatLimit returns a human-readable string for a limit
func (l TierLimits) FormatLimit(fieldName string) string {
	switch fieldName {
	case "MaxRequestsPerMinute":
		if l.MaxRequestsPerMinute == -1 {
			return "Unlimited"
		}
		return formatInt(l.MaxRequestsPerMinute) + "/min"
	case "MaxConcurrentConnections":
		if l.MaxConcurrentConnections == -1 {
			return "Unlimited"
		}
		return formatInt(l.MaxConcurrentConnections)
	case "MaxUsers":
		if l.MaxUsers == -1 {
			return "Unlimited"
		}
		return formatInt(l.MaxUsers)
	case "LogRetentionDays":
		if l.LogRetentionDays == -1 {
			return "Unlimited"
		}
		return formatInt(l.LogRetentionDays) + " days"
	default:
		return "N/A"
	}
}

func formatInt(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%dM", n/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%dK", n/1000)
	}
	return fmt.Sprintf("%d", n)
}

// RequiresUpgrade checks if current limits require a tier upgrade
func (l TierLimits) RequiresUpgrade(limitType string, value int) bool {
	current := 0
	switch limitType {
	case "requests_per_minute":
		current = l.MaxRequestsPerMinute
	case "concurrent_connections":
		current = l.MaxConcurrentConnections
	case "users":
		current = l.MaxUsers
	case "api_keys":
		current = l.MaxAPIKeys
	case "tenants":
		current = l.MaxTenants
	case "log_retention_days":
		current = l.LogRetentionDays
	}

	// -1 means unlimited, so no upgrade needed
	if current == -1 {
		return false
	}

	return value > current
}
