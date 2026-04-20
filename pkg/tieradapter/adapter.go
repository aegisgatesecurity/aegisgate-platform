// SPDX-License-Identifier: Apache-2.0
// Package tieradapter provides bidirectional conversion between the platform's
// unified tier system and the upstream AegisGuard/AegisGate tier types.
// It also maps platform Feature constants to their equivalent feature strings
// in the AegisGate core and AegisGuard license feature registries.
package tieradapter

import (
	"fmt"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
	aglicense "github.com/aegisguardsecurity/aegisguard/pkg/license"
)

// ToAegisGateTier converts a platform tier to AegisGate's core.Tier
func ToAegisGateTier(t tier.Tier) core.Tier {
	switch t {
	case tier.TierCommunity:
		return core.TierCommunity
	case tier.TierDeveloper:
		return core.TierDeveloper
	case tier.TierProfessional:
		return core.TierProfessional
	case tier.TierEnterprise:
		return core.TierEnterprise
	default:
		return core.TierCommunity
	}
}

// FromAegisGateTier converts AegisGate's core.Tier to platform tier
func FromAegisGateTier(t core.Tier) tier.Tier {
	switch t {
	case core.TierCommunity:
		return tier.TierCommunity
	case core.TierDeveloper:
		return tier.TierDeveloper
	case core.TierProfessional:
		return tier.TierProfessional
	case core.TierEnterprise:
		return tier.TierEnterprise
	default:
		return tier.TierCommunity
	}
}

// ToAegisGuardTier converts a platform tier to AegisGuard's license.Tier
func ToAegisGuardTier(t tier.Tier) aglicense.Tier {
	switch t {
	case tier.TierCommunity:
		return aglicense.TierCommunity
	case tier.TierDeveloper:
		return aglicense.TierDeveloper
	case tier.TierProfessional:
		return aglicense.TierProfessional
	case tier.TierEnterprise:
		return aglicense.TierEnterprise
	default:
		return aglicense.TierCommunity
	}
}

// FromAegisGuardTier converts AegisGuard's license.Tier to platform tier
func FromAegisGuardTier(t aglicense.Tier) tier.Tier {
	switch t {
	case aglicense.TierCommunity:
		return tier.TierCommunity
	case aglicense.TierDeveloper:
		return tier.TierDeveloper
	case aglicense.TierProfessional:
		return tier.TierProfessional
	case aglicense.TierEnterprise:
		return tier.TierEnterprise
	default:
		return tier.TierCommunity
	}
}

// ParseAndConvert parses a tier string and converts across all three systems
func ParseAndConvert(name string) (tier.Tier, core.Tier, aglicense.Tier, error) {
	pt, err := tier.ParseTier(name)
	if err != nil {
		return tier.TierCommunity, core.TierCommunity, aglicense.TierCommunity, fmt.Errorf("invalid tier %q: %w", name, err)
	}
	return pt, ToAegisGateTier(pt), ToAegisGuardTier(pt), nil
}

// aegisGateFeatureMap maps platform Feature constants to AegisGate core feature strings.
// Features not present in AegisGate (MCP-specific, platform-only) map to "".
var aegisGateFeatureMap = map[tier.Feature]string{
	// Community - AI Proxy
	tier.FeatureAIProxy:        "ai_proxy",
	tier.FeatureOpenAI:         "openai",
	tier.FeatureAnthropic:      "anthropic",
	tier.FeatureStreaming:      "streaming",
	tier.FeatureTLS:            "tls_termination",
	tier.FeatureATLAS:          "compliance_atlas",
	tier.FeatureNISTAIRMF:      "compliance_nist_ai_rmf",
	tier.FeatureOWASP:          "compliance_owasp",
	tier.FeatureGDPRView:       "compliance_gdpr_view",
	tier.FeatureBasicAnomaly:   "ml_basic_anomaly",
	tier.FeatureTrafficPattern: "ml_traffic_pattern",
	tier.FeatureMetrics:        "metrics",
	tier.FeatureAuditLogging:   "audit_logging",
	tier.FeatureRequestLog:     "request_logging",
	tier.FeatureErrorTrack:     "error_tracking",
	tier.FeatureFileStorage:    "storage_file",
	tier.FeatureDocker:         "deploy_docker",
	tier.FeatureCompose:        "deploy_compose",
	tier.FeatureAdminDashboard: "admin_dashboard",
	tier.FeatureRESTAPI:        "rest_api",
	// Developer
	tier.FeatureOAuthSSO:       "oauth_sso",
	tier.FeatureOIDC:           "oidc",
	tier.FeatureCohere:         "cohere",
	tier.FeatureAzureOpenAI:    "azure_openai",
	tier.FeatureRequestCache:   "request_caching",
	tier.FeatureRequestDedup:   "request_dedup",
	tier.FeatureMTLS:           "mtls",
	tier.FeatureRuntimeHarden:  "runtime_hardening",
	tier.FeatureCostAnomaly:    "ml_cost_anomaly",
	tier.FeatureUsageAnomaly:   "ml_usage_anomaly",
	tier.FeatureNISTView:       "compliance_nist_view",
	tier.FeatureBasicSecurity:  "compliance_basic_security",
	tier.FeatureCustomRoles:    "custom_roles",
	tier.FeatureGranularPerms:  "granular_permissions",
	tier.FeatureGrafana:        "grafana",
	tier.FeatureWebhooks:       "webhooks",
	tier.FeatureTerraform:      "deploy_terraform",
	tier.FeatureDataEncryption: "data_encryption",
	tier.FeatureAdminAdvanced:  "admin_advanced",
	// Professional
	tier.FeatureHIPAA:          "compliance_hipaa",
	tier.FeaturePCI:            "compliance_pci",
	tier.FeatureSOC2Full:       "compliance_soc2",
	tier.FeatureGDPRFull:       "compliance_gdpr",
	tier.FeatureNISTFull:       "compliance_nist",
	tier.FeatureISO27001:       "compliance_iso27001",
	tier.FeatureMLBehavioral:   "ml_behavioral",
	tier.FeatureMLPredictive:   "ml_predictive",
	tier.FeatureMLThreat:       "ml_threat_detection",
	tier.FeatureSIEM:           "siem_integration",
	tier.FeatureMultiTenant:    "multi_tenant",
	tier.FeaturePolicyEngine:   "policy_engine",
	tier.FeatureDeptSeparation: "department_separation",
	tier.FeatureKubernetes:     "deploy_kubernetes",
	tier.FeatureHelm:           "deploy_helm",
	tier.FeaturePostgreSQL:     "storage_postgres",
	tier.FeatureS3:             "storage_s3",
	tier.FeatureRetentionPol:   "retention_policies",
	// Enterprise
	tier.FeatureISO42001:     "compliance_iso42001",
	tier.FeatureFedRAMP:      "compliance_fedramp",
	tier.FeatureHITRUST:      "compliance_hitrust",
	tier.FeatureMLCustom:     "ml_custom_models",
	tier.FeatureMLZeroDay:    "ml_zeroday",
	tier.FeatureMLRealtime:   "ml_realtime_response",
	tier.FeatureHSM:          "hsm_integration",
	tier.FeatureLDAP:         "ldap_integration",
	tier.FeatureHA:           "deploy_ha",
	tier.FeatureAirGapped:    "deploy_airgapped",
	tier.FeatureAutoScale:    "deploy_autoscale",
	tier.FeatureMultiRegion:  "deploy_multiregion",
	tier.FeatureMongoDB:      "storage_mongo",
	tier.FeatureWhitelabel:   "whitelabel",
	tier.FeatureCustomDomain: "custom_domain",
}

// aegisGuardFeatureMap maps platform Feature constants to AegisGuard license feature strings.
var aegisGuardFeatureMap = map[tier.Feature]string{
	tier.FeatureMCPSessionIsolation: "session_isolation",
	tier.FeatureMCPBasicRBAC:        "rbac_basic",
	tier.FeatureContextIsolation:    "context_isolation",
	tier.FeatureCodeExecSandbox:     "code_execute",
	tier.FeatureProcessSandbox:      "process_sandbox",
	tier.FeatureVMSandbox:           "vm_sandbox",
	tier.FeatureAuditLogging:        "audit_log",
	tier.FeatureOWASP:               "compliance_basic",
	tier.FeatureDocker:              "deploy_docker",
	tier.FeatureMetrics:             "metrics",
	tier.FeatureRequestLog:          "logs",
	tier.FeatureErrorTrack:          "logs",
	tier.FeatureOpenAI:              "ai_openai",
	tier.FeatureAnthropic:           "ai_anthropic",
}

// PlatformFeatureToAegisGate maps a platform Feature to its AegisGate core feature string.
// Returns ("", false) if the feature is platform-only or AegisGuard-only.
func PlatformFeatureToAegisGate(f tier.Feature) (string, bool) {
	mapped, ok := aegisGateFeatureMap[f]
	if !ok || mapped == "" {
		return "", false
	}
	return mapped, true
}

// PlatformFeatureToAegisGuard maps a platform Feature to its AegisGuard license feature string.
// Returns ("", false) if the feature is platform-only or AegisGate-only.
func PlatformFeatureToAegisGuard(f tier.Feature) (string, bool) {
	mapped, ok := aegisGuardFeatureMap[f]
	if !ok || mapped == "" {
		return "", false
	}
	return mapped, true
}

// FeatureAccessibleInAll checks if a platform feature is accessible in all three
// tier systems at the given tier level.
func FeatureAccessibleInAll(f tier.Feature, t tier.Tier) bool {
	if !tier.HasFeature(t, f) {
		return false
	}
	if agtFeature, ok := PlatformFeatureToAegisGate(f); ok {
		requiredCoreTier := core.GetRequiredTier(agtFeature)
		if !ToAegisGateTier(t).CanAccess(requiredCoreTier) {
			return false
		}
	}
	if aglFeature, ok := PlatformFeatureToAegisGuard(f); ok {
		if !aglicense.CanAccess(ToAegisGuardTier(t), aglFeature) {
			return false
		}
	}
	return true
}
