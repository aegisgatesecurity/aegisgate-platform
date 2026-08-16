// SPDX-License-Identifier: Apache-2.0
// Package tier provides the single-source-of-truth tier system for the
// AegisGate Security Platform. All components (proxy, MCP, dashboard) use
// these definitions for feature gating and rate limiting.
//
// MANDATE COMPLIANCE:
//   - MITRE ATLAS and NIST AI RMF are Community-tier features (non-negotiable)
//   - Built-in CA, i18n, SBOM tracking are Community-tier features
//   - Community gets unlimited proxy/MCP RPM (soft-throttle policy), 7-day log retention
//   - RateLimit() is deprecated; use RateLimitProxy()/RateLimitMCP()
//     (see plans/TECHNICAL-DEBT.md — removal target v3.7.0, Q1 2027)
//   - Starter tier was removed in v3.5.0 (footgun: customers could buy Starter
//     from Stripe but ParseTier would reject "starter", silently falling back to
//     Community — they paid $29/mo for the free tier). Developer is now the
//     first paid tier at $79/mo.
//
// SOFT-THROTTLE POLICY (v3.5.0+):
//
//	AegisGate is a self-hosted security layer. The vendor's cost is zero per
//	free-tier user. Therefore, the security layer NEVER hard-blocks a request
//	for hitting a rate limit; it deprioritizes the request instead. This is
//	enforced in the proxy middleware (pkg/proxy) by mapping RateLimitProxy()
//	and RateLimitMCP() to soft-throttle weights, not hard cutoffs.
//
//	A request that exceeds the soft-throttle threshold is still processed and
//	scanned for security threats; it is just deprioritized in the work queue.
//	The intent is that the security layer earns its keep by being ON, not by
//	rate-limiting itself.
package tier

import (
	"fmt"
	"strings"
)

// Tier represents a license tier in the unified platform
type Tier int

const (
	TierCommunity    Tier = iota // Free tier
	TierDeveloper                // First paid tier ($79/mo)
	TierProfessional             // Mid-tier ($499/mo)
	TierEnterprise               // Custom pricing
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

// RateLimitProxy returns the proxy rate limit in RPM
func (t Tier) RateLimitProxy() int {
	switch t {
	case TierCommunity:
		return -1 // No hard cap (soft-throttle policy)
	case TierDeveloper:
		return 1000
	case TierProfessional:
		return 10000
	case TierEnterprise:
		return -1
	default:
		return -1
	}
}

// RateLimitMCP returns the MCP rate limit in RPM
func (t Tier) RateLimitMCP() int {
	switch t {
	case TierCommunity:
		return -1 // No hard cap (soft-throttle policy)
	case TierDeveloper:
		return 500
	case TierProfessional:
		return 5000
	case TierEnterprise:
		return -1
	default:
		return -1
	}
}

// RateLimit returns the rate limit in RPM (deprecated; use RateLimitProxy or RateLimitMCP)
//
// Deprecated: Use RateLimitProxy() or RateLimitMCP() for transport-specific
// limits. The transport-agnostic RateLimit() is ambiguous: it always returns
// the proxy rate limit, which confuses callers who expect a unified view.
// Will be removed in v3.7.0 (target Q1 2027). Tracked in
// plans/TECHNICAL-DEBT.md.
func (t Tier) RateLimit() int {
	return t.RateLimitProxy()
}

// MaxUsers returns the max concurrent users for this tier
func (t Tier) MaxUsers() int {
	switch t {
	case TierCommunity:
		return 5 // v3.5.0: 3 → 5 (Lens is free individual seat; Community is free server seat)
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

// MaxAgents returns the max concurrent agents for this tier
func (t Tier) MaxAgents() int {
	switch t {
	case TierCommunity:
		return 5 // v3.5.0: 2 → 5 (matches MaxUsers so all 5 users can run agents)
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
	FeatureOAuthSSO      Feature = "oauth_sso"
	FeatureOIDC          Feature = "oidc"
	FeatureCohere        Feature = "cohere"
	FeatureAzureOpenAI   Feature = "azure_openai"
	FeatureRequestCache  Feature = "request_caching"
	FeatureRequestDedup  Feature = "request_dedup"
	FeatureMTLS          Feature = "mtls"
	FeatureRuntimeHarden Feature = "runtime_hardening"
	FeatureCostAnomaly   Feature = "ml_cost_anomaly"
	FeatureUsageAnomaly  Feature = "ml_usage_anomaly"
	FeatureNISTView      Feature = "compliance_nist_view" // Enhanced NIST view
	FeatureBasicSecurity Feature = "compliance_basic_security"
	FeatureCustomRoles   Feature = "custom_roles"
	FeatureGranularPerms Feature = "granular_permissions"
	FeatureGrafana       Feature = "grafana"
	FeatureWebhooks      Feature = "webhooks"

	// v4.2.0: New subsystem feature gates — previously ungated subsystems.
	// These gate PLATFORM CAPABILITY (not compliance modules — those are in gating.go).
	FeatureCorrelation      Feature = "correlation_engine"     // Event correlation (Community)
	FeatureCVE              Feature = "cve_integration"        // CVE database (Community)
	FeatureBridge           Feature = "protocol_bridge"        // Protocol bridge (Community)
	FeatureANP              Feature = "agent_network_protocol" // ANP (Community)
	FeatureAIBOM            Feature = "aibom_generation"       // AI Bill of Materials (Developer)
	FeaturePromptCache      Feature = "prompt_cache_opt"       // Prompt cache optimization (Developer)
	FeatureIncident         Feature = "incident_response"      // Incident engine (Professional)
	FeatureEvidence         Feature = "evidence_packages"      // Compliance evidence (Professional)
	FeatureA2A              Feature = "a2a_protocol"           // Agent-to-Agent (Professional)
	FeatureACP              Feature = "acp_protocol"           // Agent Communication Protocol (Professional)
	FeatureFederatedIOC     Feature = "federated_ioc"          // Federated IOC sharing (Professional)
	FeatureAttestation      Feature = "attestation_framework"  // Signed attestations (Professional)
	FeaturePosture          Feature = "posture_assessment"     // Security posture (Professional)
	FeatureDigest           Feature = "ciso_digest"            // CISO Posture Digest (Professional)
	FeatureAgentIntentSign  Feature = "agent_intent_signing"   // Non-repudiation (Professional)
	FeatureSOCStream        Feature = "soc_stream"             // SOC operations (Professional)
	FeatureTrustPortal      Feature = "trust_portal"           // Trust dashboard UI (Professional)
	FeatureComputerUse      Feature = "computer_use_detection" // Computer use detection (Professional)
	FeatureSLA              Feature = "sla_enforcement"        // SLA enforcement (Enterprise)
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
	FeatureRetentionPol   Feature = "retention_policies"
	FeatureProcessSandbox Feature = "mcp_process_sandbox" // Process-level sandboxing

	// ====================================================================
	// Enterprise tier
	// ====================================================================
	FeatureISO42001   Feature = "compliance_iso42001"
	FeatureFedRAMP    Feature = "compliance_fedramp"
	FeatureSOC2Type2  Feature = "compliance_soc2_type2"
	FeatureHITRUST    Feature = "compliance_hitrust"
	FeatureMLCustom   Feature = "ml_custom_models"
	FeatureMLZeroDay  Feature = "ml_zeroday"
	FeatureMLRealtime Feature = "ml_realtime_response"
	FeatureHSM        Feature = "hsm_integration"
	FeatureFIPS       Feature = "fips_compliance"
	FeatureClustering Feature = "deploy_clustering" // Clustering support (customer provides LB)
	FeatureAirGapped  Feature = "deploy_airgapped"
	FeatureVMSandbox  Feature = "mcp_vm_sandbox" // VM-level sandboxing
	// v3.2.0 Phase 4: Trust Framework (5th pillar). The Trust pillar is the
	// 5th architectural pillar of the platform (alongside HTTP Proxy, MCP,
	// A2A, and Compliance). It provides cryptographic agent identity,
	// per-session trust scoring, and signed attestations. Gated to
	// Professional+ per the locked decision Q3. The signing primitives
	// (Ed25519/ECDSA) exist in pkg/trust/attestation already; this feature
	// flag enables them in the request lifecycle.
	FeatureTrustPillar Feature = "trust_pillar"
)

// RequiredTier returns the minimum tier required for a feature
func RequiredTier(feature Feature) Tier {
	switch feature {
	// Community — platform capabilities available to all users
	case FeatureAIProxy, FeatureOpenAI, FeatureAnthropic, FeatureStreaming,
		FeatureTLS, FeatureBuiltInCA, FeatureSecretScanning, FeaturePIIScanning,
		FeaturePromptInjection, FeatureBidirectional, FeatureCircuitBreaker,
		FeatureBasicAnomaly, FeatureTrafficPattern,
		FeatureMetrics, FeatureAuditLogging, FeatureRequestLog, FeatureErrorTrack,
		FeatureFileStorage, FeatureDocker, FeatureCompose,
		FeatureAdminDashboard, FeatureRESTAPI, FeatureSBOM, FeatureI18N,
		FeatureMCPSessionIsolation, FeatureMCPBasicRBAC,
		// v4.2.0: Compliance framework VIEW/detection features (not full compliance).
		// Full compliance modules are gated in gating.go (single source of truth).
		FeatureATLAS, FeatureNISTAIRMF, FeatureOWASP, FeatureGDPRView,
		// v4.2.0: New subsystem gates — infrastructure-grade features for all.
		FeatureCorrelation, FeatureCVE, FeatureBridge, FeatureANP:
		return TierCommunity

	// Developer — enhanced platform capabilities
	case FeatureOAuthSSO, FeatureOIDC, FeatureCohere, FeatureAzureOpenAI,
		FeatureRequestCache, FeatureRequestDedup,
		FeatureMTLS, FeatureRuntimeHarden,
		FeatureCostAnomaly, FeatureUsageAnomaly,
		FeatureNISTView, FeatureBasicSecurity,
		FeatureCustomRoles, FeatureGranularPerms,
		FeatureGrafana, FeatureWebhooks,
		FeatureDataEncryption,
		FeatureAdminAdvanced, FeatureContextIsolation, FeatureCodeExecSandbox,
		// v4.2.0: Compliance platform capabilities — Developer tier.
		// (Billing module tier gates are in gating.go — these gate the
		// platform capability to RUN the framework, not the purchase.)
		FeatureHIPAA, FeaturePCI, FeatureSOC2Full, FeatureISO27001,
		// v4.2.0: New subsystem gates — Developer-grade capabilities.
		FeatureAIBOM, FeaturePromptCache:
		return TierDeveloper

	// Professional — advanced platform capabilities
	case FeatureGDPRFull, FeatureNISTFull,
		FeatureMLBehavioral, FeatureMLPredictive, FeatureMLThreat,
		FeatureSIEM, FeatureMultiTenant, FeaturePolicyEngine, FeatureDeptSeparation,
		FeatureKubernetes, FeatureHelm,
		FeaturePostgreSQL, FeatureRetentionPol,
		FeatureProcessSandbox,
		// v4.2.0: Trust Framework (5th pillar — 12K+ lines, 59 files).
		FeatureTrustPillar,
		// v4.2.0: New subsystem gates — Professional-grade capabilities.
		FeatureIncident, FeatureEvidence, FeatureA2A, FeatureACP,
		FeatureFederatedIOC, FeatureAttestation, FeaturePosture,
		FeatureDigest, FeatureAgentIntentSign, FeatureSOCStream,
		FeatureTrustPortal, FeatureComputerUse:
		return TierProfessional

	// Enterprise — regulated-industry platform capabilities
	case FeatureISO42001, FeatureFedRAMP, FeatureSOC2Type2, FeatureHITRUST,
		FeatureMLCustom, FeatureMLZeroDay, FeatureMLRealtime,
		FeatureHSM, FeatureFIPS,
		FeatureClustering, FeatureAirGapped,
		FeatureVMSandbox,
		// v4.2.0: New subsystem gates — Enterprise-grade capabilities.
		FeatureSLA:
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
	// v4.2.0: New subsystem feature mappings.
	"correlation_engine": FeatureCorrelation, "cve_integration": FeatureCVE,
	"protocol_bridge": FeatureBridge, "agent_network_protocol": FeatureANP,
	"aibom_generation": FeatureAIBOM, "prompt_cache_opt": FeaturePromptCache,
	"incident_response": FeatureIncident, "evidence_packages": FeatureEvidence,
	"a2a_protocol": FeatureA2A, "acp_protocol": FeatureACP,
	"federated_ioc": FeatureFederatedIOC, "attestation_framework": FeatureAttestation,
	"posture_assessment": FeaturePosture, "ciso_digest": FeatureDigest,
	"agent_intent_signing": FeatureAgentIntentSign, "soc_stream": FeatureSOCStream,
	"trust_portal": FeatureTrustPortal, "computer_use_detection": FeatureComputerUse,
	"sla_enforcement": FeatureSLA,
	"data_encryption": FeatureDataEncryption,
	"admin_advanced":  FeatureAdminAdvanced, "mcp_context_isolation": FeatureContextIsolation,
	"code_execute_sandbox": FeatureCodeExecSandbox,
	// Professional
	"compliance_hipaa": FeatureHIPAA, "compliance_pci": FeaturePCI,
	"compliance_soc2": FeatureSOC2Full, "compliance_gdpr": FeatureGDPRFull,
	"compliance_nist": FeatureNISTFull, "compliance_iso27001": FeatureISO27001,
	"ml_behavioral": FeatureMLBehavioral, "ml_predictive": FeatureMLPredictive,
	"ml_threat_detection": FeatureMLThreat, "siem_integration": FeatureSIEM,
	"multi_tenant": FeatureMultiTenant, "policy_engine": FeaturePolicyEngine,
	"department_separation": FeatureDeptSeparation,
	"deploy_kubernetes":     FeatureKubernetes, "deploy_helm": FeatureHelm,
	"storage_postgres":    FeaturePostgreSQL,
	"retention_policies":  FeatureRetentionPol,
	"mcp_process_sandbox": FeatureProcessSandbox,
	// Enterprise
	"compliance_iso42001": FeatureISO42001, "compliance_fedramp": FeatureFedRAMP,
	"compliance_soc2_type2": FeatureSOC2Type2, "compliance_hitrust": FeatureHITRUST,
	"ml_custom_models": FeatureMLCustom, "ml_zeroday": FeatureMLZeroDay,
	"ml_realtime_response": FeatureMLRealtime,
	"hsm_integration":      FeatureHSM,
	"fips_compliance":      FeatureFIPS,
	"deploy_clustering":    FeatureClustering, "deploy_airgapped": FeatureAirGapped,
	"mcp_vm_sandbox": FeatureVMSandbox,
	// v3.2.0 Phase 4: Trust Framework pillar
	"trust_pillar": FeatureTrustPillar,
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
		FeatureGrafana, FeatureWebhooks,
		FeatureDataEncryption,
		FeatureAdminAdvanced, FeatureContextIsolation, FeatureCodeExecSandbox,
		// Professional
		FeatureHIPAA, FeaturePCI, FeatureSOC2Full, FeatureGDPRFull,
		FeatureNISTFull, FeatureISO27001,
		FeatureMLBehavioral, FeatureMLPredictive, FeatureMLThreat,
		FeatureSIEM, FeatureMultiTenant, FeaturePolicyEngine, FeatureDeptSeparation,
		FeatureKubernetes, FeatureHelm,
		FeaturePostgreSQL, FeatureRetentionPol,
		FeatureProcessSandbox,
		// Enterprise
		FeatureISO42001, FeatureFedRAMP, FeatureSOC2Type2, FeatureHITRUST,
		FeatureMLCustom, FeatureMLZeroDay, FeatureMLRealtime,
		FeatureHSM, FeatureFIPS,
		FeatureClustering, FeatureAirGapped,
		FeatureVMSandbox,
	}
}
