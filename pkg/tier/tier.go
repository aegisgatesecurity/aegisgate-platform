// SPDX-License-Identifier: Apache-2.0
// Package tier provides the single-source-of-truth tier system for the
// AegisGate Security Platform. All components (proxy, MCP, dashboard) use
// these definitions for feature gating and rate limiting.
//
// MANDATE COMPLIANCE:
//   - MITRE ATLAS and NIST AI RMF are Community-tier features (non-negotiable)
//   - Built-in CA, i18n, SBOM tracking are Community-tier features
//   - Community gets 120 proxy RPM / 60 MCP RPM, 7-day log retention
//   - RateLimit() is deprecated; use RateLimitProxy()/RateLimitMCP()
package tier

import (
	"fmt"
	"strings"
)

// Tier represents a license tier in the unified platform
type Tier int

const (
	TierCommunity    Tier = iota // Free tier
	TierDeveloper                // Paid tier
	TierProfessional             // Paid tier
	TierEnterprise               // Paid tier
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

// DisplayName returns the human-readable tier name
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
	case "community", "free":
		return TierCommunity, nil
	case "developer", "dev":
		return TierDeveloper, nil
	case "professional", "pro":
		return TierProfessional, nil
	case "enterprise", "ent":
		return TierEnterprise, nil
	default:
		return 0, fmt.Errorf("invalid tier: %s", name)
	}
}

// CanAccess checks if this tier can access a feature requiring the given tier
func (t Tier) CanAccess(required Tier) bool {
	return t >= required
}

// ============================================================
// Rate Limits — split by transport (proxy vs MCP)
// ============================================================

// RateLimitProxy returns the requests-per-minute limit for proxy traffic.
func (t Tier) RateLimitProxy() int {
	switch t {
	case TierCommunity:
		return 120
	case TierDeveloper:
		return 600
	case TierProfessional:
		return 3000
	case TierEnterprise:
		return -1 // Unlimited
	default:
		return 120
	}
}

// RateLimitMCP returns the requests-per-minute limit for MCP tool calls.
func (t Tier) RateLimitMCP() int {
	switch t {
	case TierCommunity:
		return 60
	case TierDeveloper:
		return 300
	case TierProfessional:
		return 1500
	case TierEnterprise:
		return -1 // Unlimited
	default:
		return 60
	}
}

// RateLimit returns the proxy RPM limit for backward compatibility.
// Deprecated: Use RateLimitProxy() or RateLimitMCP() for transport-specific limits.
func (t Tier) RateLimit() int {
	return t.RateLimitProxy()
}

// MaxUsers returns the max concurrent users for this tier
func (t Tier) MaxUsers() int {
	switch t {
	case TierCommunity:
		return 3
	case TierDeveloper:
		return 10
	case TierProfessional:
		return 50
	case TierEnterprise:
		return -1
	default:
		return 3
	}
}

// MaxAgents returns the max concurrent agents for this tier
func (t Tier) MaxAgents() int {
	switch t {
	case TierCommunity:
		return 2
	case TierDeveloper:
		return 5
	case TierProfessional:
		return 25
	case TierEnterprise:
		return -1
	default:
		return 2
	}
}

// LogRetentionDays returns log retention in days
func (t Tier) LogRetentionDays() int {
	switch t {
	case TierCommunity:
		return 7
	case TierDeveloper:
		return 30
	case TierProfessional:
		return 90
	case TierEnterprise:
		return -1 // Unlimited
	default:
		return 7
	}
}

// SupportLevel returns the support level string
func (t Tier) SupportLevel() string {
	switch t {
	case TierCommunity:
		return "community"
	case TierDeveloper:
		return "email"
	case TierProfessional:
		return "priority"
	case TierEnterprise:
		return "24x7"
	default:
		return "community"
	}
}

// ============================================================
// MCP-specific limits
// ============================================================

// MaxConcurrentMCP returns the maximum concurrent MCP sessions.
func (t Tier) MaxConcurrentMCP() int {
	switch t {
	case TierCommunity:
		return 5
	case TierDeveloper:
		return 25
	case TierProfessional:
		return 100
	case TierEnterprise:
		return -1
	default:
		return 5
	}
}

// MaxMCPToolsPerSession returns the max tools allowed per MCP session.
func (t Tier) MaxMCPToolsPerSession() int {
	switch t {
	case TierCommunity:
		return 20
	case TierDeveloper:
		return 50
	case TierProfessional:
		return -1 // Unlimited
	case TierEnterprise:
		return -1
	default:
		return 20
	}
}

// MCPExecTimeoutSeconds returns the max execution time for a single MCP tool call.
func (t Tier) MCPExecTimeoutSeconds() int {
	switch t {
	case TierCommunity:
		return 30
	case TierDeveloper:
		return 60
	case TierProfessional:
		return 300
	case TierEnterprise:
		return -1 // Unlimited
	default:
		return 30
	}
}

// MaxMCPSandboxMemoryMB returns the max memory (MB) for MCP sandbox execution.
func (t Tier) MaxMCPSandboxMemoryMB() int {
	switch t {
	case TierCommunity:
		return 256
	case TierDeveloper:
		return 512
	case TierProfessional:
		return 2048
	case TierEnterprise:
		return -1 // Unlimited
	default:
		return 256
	}
}

// ============================================================
// Feature constants — 91 features across 4 tiers
// ============================================================

// Feature represents a platform feature that can be gated by tier
type Feature string

const (
	// ====================================================================
	// Community (Free) — Non-negotiable mandate features
	// ====================================================================

	// AI Proxy & Connectivity
	FeatureAIProxy   Feature = "ai_proxy"
	FeatureOpenAI    Feature = "openai"
	FeatureAnthropic Feature = "anthropic"
	FeatureStreaming Feature = "streaming"

	// Security Core
	FeatureTLS             Feature = "tls_termination"
	FeatureBuiltInCA       Feature = "builtin_ca"               // Self-signed cert + built-in CA
	FeatureSecretScanning  Feature = "secret_scanning"          // 44-regex secret detection
	FeaturePIIScanning     Feature = "pii_scanning"             // PII detection (GDPR view)
	FeaturePromptInjection Feature = "prompt_injection"         // Prompt injection detection
	FeatureBidirectional   Feature = "bidirectional_inspection" // Request + response scanning
	FeatureCircuitBreaker  Feature = "circuit_breaker"          // Circuit breaker pattern

	// Compliance — MANDATE: ATLAS + NIST AI RMF are Community (non-negotiable)
	FeatureATLAS     Feature = "compliance_atlas"       // MITRE ATLAS 18 techniques / 40+ patterns
	FeatureNISTAIRMF Feature = "compliance_nist_ai_rmf" // NIST AI RMF 1.0 (GV/MP/ME/RG)
	FeatureOWASP     Feature = "compliance_owasp"       // OWASP AI Top 10
	FeatureGDPRView  Feature = "compliance_gdpr_view"   // GDPR view-only (detection, not full compliance)

	// ML Detection
	FeatureBasicAnomaly   Feature = "ml_basic_anomaly"
	FeatureTrafficPattern Feature = "ml_traffic_pattern"

	// Observability
	FeatureMetrics      Feature = "metrics"
	FeatureAuditLogging Feature = "audit_logging"
	FeatureRequestLog   Feature = "request_logging"
	FeatureErrorTrack   Feature = "error_tracking"

	// Storage
	FeatureFileStorage Feature = "storage_file" // FileStorageBackend for Community

	// Deployment
	FeatureDocker  Feature = "deploy_docker"  // Docker container
	FeatureCompose Feature = "deploy_compose" // docker-compose

	// Platform
	FeatureAdminDashboard Feature = "admin_dashboard"
	FeatureRESTAPI        Feature = "rest_api"
	FeatureSBOM           Feature = "sbom_tracking" // SBOM generation/tracking
	FeatureI18N           Feature = "i18n"          // Internationalization

	// MCP Core
	FeatureMCPSessionIsolation Feature = "mcp_session_isolation" // Per-session isolation
	FeatureMCPBasicRBAC        Feature = "mcp_basic_rbac"        // Basic RBAC for MCP tools

	// ====================================================================
	// Developer tier
	// ====================================================================
	FeatureOAuthSSO         Feature = "oauth_sso"
	FeatureOIDC             Feature = "oidc"
	FeatureCohere           Feature = "cohere"
	FeatureAzureOpenAI      Feature = "azure_openai"
	FeatureRequestCache     Feature = "request_caching"
	FeatureRequestDedup     Feature = "request_dedup"
	FeatureMTLS             Feature = "mtls"
	FeatureRuntimeHarden    Feature = "runtime_hardening"
	FeatureCostAnomaly      Feature = "ml_cost_anomaly"
	FeatureUsageAnomaly     Feature = "ml_usage_anomaly"
	FeatureNISTView         Feature = "compliance_nist_view" // Enhanced NIST view
	FeatureBasicSecurity    Feature = "compliance_basic_security"
	FeatureCustomRoles      Feature = "custom_roles"
	FeatureGranularPerms    Feature = "granular_permissions"
	FeatureGrafana          Feature = "grafana"
	FeatureWebhooks         Feature = "webhooks"
	FeatureTerraform        Feature = "deploy_terraform"
	FeatureSQLite           Feature = "storage_sqlite"
	FeatureRedis            Feature = "storage_redis"
	FeatureDataEncryption   Feature = "data_encryption"
	FeatureAdminAdvanced    Feature = "admin_advanced"
	FeatureContextIsolation Feature = "mcp_context_isolation" // Full context isolation
	FeatureCodeExecSandbox  Feature = "code_execute_sandbox"  // Sandboxed code exec (Dev+)

	// ====================================================================
	// Professional tier
	// ====================================================================
	FeatureHIPAA          Feature = "compliance_hipaa"
	FeaturePCI            Feature = "compliance_pci"
	FeatureSOC2Full       Feature = "compliance_soc2"
	FeatureGDPRFull       Feature = "compliance_gdpr"
	FeatureNISTFull       Feature = "compliance_nist"
	FeatureISO27001       Feature = "compliance_iso27001"
	FeatureMLBehavioral   Feature = "ml_behavioral"
	FeatureMLPredictive   Feature = "ml_predictive"
	FeatureMLThreat       Feature = "ml_threat_detection"
	FeatureSIEM           Feature = "siem_integration"
	FeatureMultiTenant    Feature = "multi_tenant"
	FeaturePolicyEngine   Feature = "policy_engine"
	FeatureDeptSeparation Feature = "department_separation"
	FeatureKubernetes     Feature = "deploy_kubernetes"
	FeatureHelm           Feature = "deploy_helm"
	FeaturePostgreSQL     Feature = "storage_postgres"
	FeatureS3             Feature = "storage_s3"
	FeatureRetentionPol   Feature = "retention_policies"
	FeatureVaultSecrets   Feature = "vault_secrets"       // HashiCorp Vault integration
	FeatureProcessSandbox Feature = "mcp_process_sandbox" // Process-level sandboxing

	// ====================================================================
	// Enterprise tier
	// ====================================================================
	FeatureISO42001     Feature = "compliance_iso42001"
	FeatureFedRAMP      Feature = "compliance_fedramp"
	FeatureSOC2Type2    Feature = "compliance_soc2_type2"
	FeatureHITRUST      Feature = "compliance_hitrust"
	FeatureMLCustom     Feature = "ml_custom_models"
	FeatureMLZeroDay    Feature = "ml_zeroday"
	FeatureMLRealtime   Feature = "ml_realtime_response"
	FeatureHSM          Feature = "hsm_integration"
	FeatureLDAP         Feature = "ldap_integration"
	FeatureFIPS         Feature = "fips_compliance"
	FeatureHA           Feature = "deploy_ha"
	FeatureAirGapped    Feature = "deploy_airgapped"
	FeatureAutoScale    Feature = "deploy_autoscale"
	FeatureMultiRegion  Feature = "deploy_multiregion"
	FeatureMongoDB      Feature = "storage_mongo"
	FeatureWhitelabel   Feature = "whitelabel"
	FeatureCustomDomain Feature = "custom_domain"
	FeatureVMSandbox    Feature = "mcp_vm_sandbox" // VM-level sandboxing
)

// RequiredTier returns the minimum tier required for a feature
func RequiredTier(feature Feature) Tier {
	switch feature {
	// Community
	case FeatureAIProxy, FeatureOpenAI, FeatureAnthropic, FeatureStreaming,
		FeatureTLS, FeatureBuiltInCA, FeatureSecretScanning, FeaturePIIScanning,
		FeaturePromptInjection, FeatureBidirectional, FeatureCircuitBreaker,
		FeatureATLAS, FeatureNISTAIRMF, FeatureOWASP, FeatureGDPRView,
		FeatureBasicAnomaly, FeatureTrafficPattern,
		FeatureMetrics, FeatureAuditLogging, FeatureRequestLog, FeatureErrorTrack,
		FeatureFileStorage, FeatureDocker, FeatureCompose,
		FeatureAdminDashboard, FeatureRESTAPI, FeatureSBOM, FeatureI18N,
		FeatureMCPSessionIsolation, FeatureMCPBasicRBAC:
		return TierCommunity

	// Developer
	case FeatureOAuthSSO, FeatureOIDC, FeatureCohere, FeatureAzureOpenAI,
		FeatureRequestCache, FeatureRequestDedup,
		FeatureMTLS, FeatureRuntimeHarden,
		FeatureCostAnomaly, FeatureUsageAnomaly,
		FeatureNISTView, FeatureBasicSecurity,
		FeatureCustomRoles, FeatureGranularPerms,
		FeatureGrafana, FeatureWebhooks, FeatureTerraform,
		FeatureSQLite, FeatureRedis, FeatureDataEncryption,
		FeatureAdminAdvanced, FeatureContextIsolation, FeatureCodeExecSandbox:
		return TierDeveloper

	// Professional
	case FeatureHIPAA, FeaturePCI, FeatureSOC2Full, FeatureGDPRFull,
		FeatureNISTFull, FeatureISO27001,
		FeatureMLBehavioral, FeatureMLPredictive, FeatureMLThreat,
		FeatureSIEM, FeatureMultiTenant, FeaturePolicyEngine, FeatureDeptSeparation,
		FeatureKubernetes, FeatureHelm,
		FeaturePostgreSQL, FeatureS3, FeatureRetentionPol,
		FeatureVaultSecrets, FeatureProcessSandbox:
		return TierProfessional

	// Enterprise
	case FeatureISO42001, FeatureFedRAMP, FeatureSOC2Type2, FeatureHITRUST,
		FeatureMLCustom, FeatureMLZeroDay, FeatureMLRealtime,
		FeatureHSM, FeatureLDAP, FeatureFIPS,
		FeatureHA, FeatureAirGapped, FeatureAutoScale, FeatureMultiRegion,
		FeatureMongoDB, FeatureWhitelabel, FeatureCustomDomain,
		FeatureVMSandbox:
		return TierEnterprise

	default:
		return TierCommunity
	}
}

// HasFeature checks if a tier has access to a feature
func HasFeature(t Tier, feature Feature) bool {
	return t.CanAccess(RequiredTier(feature))
}

// featureKeyMap maps string feature keys (as used in middleware and core.FeatureTierMapping)
// to platform Feature constants. This enables context-aware feature checks by string key.
var featureKeyMap = map[string]Feature{
	// Community
	"ai_proxy": FeatureAIProxy, "openai": FeatureOpenAI, "anthropic": FeatureAnthropic,
	"streaming": FeatureStreaming, "tls_termination": FeatureTLS,
	"builtin_ca": FeatureBuiltInCA, "secret_scanning": FeatureSecretScanning,
	"pii_scanning": FeaturePIIScanning, "prompt_injection": FeaturePromptInjection,
	"bidirectional_inspection": FeatureBidirectional, "circuit_breaker": FeatureCircuitBreaker,
	"compliance_atlas": FeatureATLAS, "compliance_nist_ai_rmf": FeatureNISTAIRMF,
	"compliance_owasp": FeatureOWASP, "compliance_gdpr_view": FeatureGDPRView,
	"ml_basic_anomaly": FeatureBasicAnomaly, "ml_traffic_pattern": FeatureTrafficPattern,
	"metrics": FeatureMetrics, "audit_logging": FeatureAuditLogging,
	"request_logging": FeatureRequestLog, "error_tracking": FeatureErrorTrack,
	"storage_file": FeatureFileStorage, "deploy_docker": FeatureDocker,
	"deploy_compose": FeatureCompose, "admin_dashboard": FeatureAdminDashboard,
	"rest_api": FeatureRESTAPI, "sbom_tracking": FeatureSBOM, "i18n": FeatureI18N,
	"mcp_session_isolation": FeatureMCPSessionIsolation, "mcp_basic_rbac": FeatureMCPBasicRBAC,
	// Developer
	"oauth_sso": FeatureOAuthSSO, "oidc": FeatureOIDC,
	"cohere": FeatureCohere, "azure_openai": FeatureAzureOpenAI,
	"request_caching": FeatureRequestCache, "request_dedup": FeatureRequestDedup,
	"mtls": FeatureMTLS, "runtime_hardening": FeatureRuntimeHarden,
	"ml_cost_anomaly": FeatureCostAnomaly, "ml_usage_anomaly": FeatureUsageAnomaly,
	"compliance_nist_view": FeatureNISTView, "compliance_basic_security": FeatureBasicSecurity,
	"custom_roles": FeatureCustomRoles, "granular_permissions": FeatureGranularPerms,
	"grafana": FeatureGrafana, "webhooks": FeatureWebhooks,
	"deploy_terraform": FeatureTerraform, "storage_sqlite": FeatureSQLite,
	"storage_redis": FeatureRedis, "data_encryption": FeatureDataEncryption,
	"admin_advanced": FeatureAdminAdvanced, "mcp_context_isolation": FeatureContextIsolation,
	"code_execute_sandbox": FeatureCodeExecSandbox,
	// Professional
	"compliance_hipaa": FeatureHIPAA, "compliance_pci": FeaturePCI,
	"compliance_soc2": FeatureSOC2Full, "compliance_gdpr": FeatureGDPRFull,
	"compliance_nist": FeatureNISTFull, "compliance_iso27001": FeatureISO27001,
	"ml_behavioral": FeatureMLBehavioral, "ml_predictive": FeatureMLPredictive,
	"ml_threat_detection": FeatureMLThreat, "siem_integration": FeatureSIEM,
	"multi_tenant": FeatureMultiTenant, "policy_engine": FeaturePolicyEngine,
	"department_separation": FeatureDeptSeparation,
	"deploy_kubernetes": FeatureKubernetes, "deploy_helm": FeatureHelm,
	"storage_postgres": FeaturePostgreSQL, "storage_s3": FeatureS3,
	"retention_policies": FeatureRetentionPol, "vault_secrets": FeatureVaultSecrets,
	"mcp_process_sandbox": FeatureProcessSandbox,
	// Enterprise
	"compliance_iso42001": FeatureISO42001, "compliance_fedramp": FeatureFedRAMP,
	"compliance_soc2_type2": FeatureSOC2Type2, "compliance_hitrust": FeatureHITRUST,
	"ml_custom_models": FeatureMLCustom, "ml_zeroday": FeatureMLZeroDay,
	"ml_realtime_response": FeatureMLRealtime,
	"hsm_integration": FeatureHSM, "ldap_integration": FeatureLDAP,
	"fips_compliance": FeatureFIPS,
	"deploy_ha": FeatureHA, "deploy_airgapped": FeatureAirGapped,
	"deploy_autoscale": FeatureAutoScale, "deploy_multiregion": FeatureMultiRegion,
	"storage_mongo": FeatureMongoDB, "whitelabel": FeatureWhitelabel,
	"custom_domain": FeatureCustomDomain, "mcp_vm_sandbox": FeatureVMSandbox,
}

// TierHasFeatureKey checks if a tier has access to a feature given its string key.
// This is the string-key version of HasFeature, used by middleware that works
// with feature key strings (e.g., "mtls", "compliance_hipaa").
func TierHasFeatureKey(t Tier, key string) bool {
	f, ok := featureKeyMap[key]
	if !ok {
		// Unknown feature keys default to Community tier access
		return t >= TierCommunity
	}
	return t.CanAccess(RequiredTier(f))
}

// IsFeatureCommunity checks if a feature key requires only Community tier.
// Returns true for unknown keys (conservative: allow by default).
func IsFeatureCommunity(key string) bool {
	f, ok := featureKeyMap[key]
	if !ok {
		// Unknown features: unknown → allow as community
		return true
	}
	return RequiredTier(f) == TierCommunity
}

// FeatureForKey resolves a string feature key to a Feature constant.
// Returns the Feature and true if found, or zero value and false.
func FeatureForKey(key string) (Feature, bool) {
	f, ok := featureKeyMap[key]
	return f, ok
}

// AllFeatures returns all features available for a tier
func AllFeatures(t Tier) []Feature {
	var features []Feature
	for _, f := range allFeatures() {
		if t.CanAccess(RequiredTier(f)) {
			features = append(features, f)
		}
	}
	return features
}

func allFeatures() []Feature {
	return []Feature{
		// Community
		FeatureAIProxy, FeatureOpenAI, FeatureAnthropic, FeatureStreaming,
		FeatureTLS, FeatureBuiltInCA, FeatureSecretScanning, FeaturePIIScanning,
		FeaturePromptInjection, FeatureBidirectional, FeatureCircuitBreaker,
		FeatureATLAS, FeatureNISTAIRMF, FeatureOWASP, FeatureGDPRView,
		FeatureBasicAnomaly, FeatureTrafficPattern,
		FeatureMetrics, FeatureAuditLogging, FeatureRequestLog, FeatureErrorTrack,
		FeatureFileStorage, FeatureDocker, FeatureCompose,
		FeatureAdminDashboard, FeatureRESTAPI, FeatureSBOM, FeatureI18N,
		FeatureMCPSessionIsolation, FeatureMCPBasicRBAC,
		// Developer
		FeatureOAuthSSO, FeatureOIDC, FeatureCohere, FeatureAzureOpenAI,
		FeatureRequestCache, FeatureRequestDedup,
		FeatureMTLS, FeatureRuntimeHarden,
		FeatureCostAnomaly, FeatureUsageAnomaly,
		FeatureNISTView, FeatureBasicSecurity,
		FeatureCustomRoles, FeatureGranularPerms,
		FeatureGrafana, FeatureWebhooks, FeatureTerraform,
		FeatureSQLite, FeatureRedis, FeatureDataEncryption,
		FeatureAdminAdvanced, FeatureContextIsolation, FeatureCodeExecSandbox,
		// Professional
		FeatureHIPAA, FeaturePCI, FeatureSOC2Full, FeatureGDPRFull,
		FeatureNISTFull, FeatureISO27001,
		FeatureMLBehavioral, FeatureMLPredictive, FeatureMLThreat,
		FeatureSIEM, FeatureMultiTenant, FeaturePolicyEngine, FeatureDeptSeparation,
		FeatureKubernetes, FeatureHelm,
		FeaturePostgreSQL, FeatureS3, FeatureRetentionPol,
		FeatureVaultSecrets, FeatureProcessSandbox,
		// Enterprise
		FeatureISO42001, FeatureFedRAMP, FeatureSOC2Type2, FeatureHITRUST,
		FeatureMLCustom, FeatureMLZeroDay, FeatureMLRealtime,
		FeatureHSM, FeatureLDAP, FeatureFIPS,
		FeatureHA, FeatureAirGapped, FeatureAutoScale, FeatureMultiRegion,
		FeatureMongoDB, FeatureWhitelabel, FeatureCustomDomain,
		FeatureVMSandbox,
	}
}
