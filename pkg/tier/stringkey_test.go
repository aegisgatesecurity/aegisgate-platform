// SPDX-License-Identifier: Apache-2.0
// Package tier provides test coverage for the string-key-based feature functions:
//   - TierHasFeatureKey(tier, key string)
//   - IsFeatureCommunity(key string)
//   - FeatureForKey(key string)
package tier

import "testing"

// ---------- TierHasFeatureKey ----------

func TestTierHasFeatureKey_CommunityFeatures(t *testing.T) {
	tests := []struct {
		key  string
		want bool // for TierCommunity
	}{
		// Community features — accessible by Community
		{"ai_proxy", true},
		{"openai", true},
		{"streaming", true},
		{"compliance_atlas", true},
		{"compliance_nist_ai_rmf", true},
	}
	for _, tt := range tests {
		got := TierHasFeatureKey(TierCommunity, tt.key)
		if got != tt.want {
			t.Errorf("TierHasFeatureKey(Community, %q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestTierHasFeatureKey_CommunityBlockedFromHigher(t *testing.T) {
	// Community tier should NOT access Developer+ features
	devOnly := []string{"mtls", "oauth_sso", "grafana"}
	for _, key := range devOnly {
		if TierHasFeatureKey(TierCommunity, key) {
			t.Errorf("TierHasFeatureKey(Community, %q) = true, want false", key)
		}
	}

	// Community tier should NOT access Professional+ features
	proOnly := []string{"compliance_hipaa", "compliance_pci", "multi_tenant"}
	for _, key := range proOnly {
		if TierHasFeatureKey(TierCommunity, key) {
			t.Errorf("TierHasFeatureKey(Community, %q) = true, want false", key)
		}
	}

	// Community tier should NOT access Enterprise features
	entOnly := []string{"hsm_integration", "compliance_fedramp", "deploy_airgapped"}
	for _, key := range entOnly {
		if TierHasFeatureKey(TierCommunity, key) {
			t.Errorf("TierHasFeatureKey(Community, %q) = true, want false", key)
		}
	}
}

func TestTierHasFeatureKey_DeveloperFeatures(t *testing.T) {
	tests := []struct {
		tier Tier
		key  string
		want bool
	}{
		// Developer features accessible by Developer and above
		{TierDeveloper, "mtls", true},
		{TierDeveloper, "oauth_sso", true},
		{TierDeveloper, "storage_redis", true},
		{TierDeveloper, "code_execute_sandbox", true},
		{TierDeveloper, "mcp_context_isolation", true},
		// Community is NOT enough for Developer features
		{TierCommunity, "mtls", false},
		{TierCommunity, "oauth_sso", false},
		// Professional and Enterprise also have access
		{TierProfessional, "mtls", true},
		{TierEnterprise, "mtls", true},
	}
	for _, tt := range tests {
		got := TierHasFeatureKey(tt.tier, tt.key)
		if got != tt.want {
			t.Errorf("TierHasFeatureKey(%s, %q) = %v, want %v", tt.tier, tt.key, got, tt.want)
		}
	}
}

func TestTierHasFeatureKey_ProfessionalFeatures(t *testing.T) {
	tests := []struct {
		tier Tier
		key  string
		want bool
	}{
		// Professional features
		{TierProfessional, "compliance_hipaa", true},
		{TierProfessional, "compliance_soc2", true},
		{TierProfessional, "deploy_kubernetes", true},
		{TierProfessional, "storage_postgres", true},
		{TierProfessional, "vault_secrets", true},
		{TierProfessional, "mcp_process_sandbox", true},
		// Lower tiers blocked
		{TierCommunity, "compliance_hipaa", false},
		{TierDeveloper, "compliance_hipaa", false},
		{TierDeveloper, "multi_tenant", false},
		// Enterprise also has access
		{TierEnterprise, "compliance_hipaa", true},
	}
	for _, tt := range tests {
		got := TierHasFeatureKey(tt.tier, tt.key)
		if got != tt.want {
			t.Errorf("TierHasFeatureKey(%s, %q) = %v, want %v", tt.tier, tt.key, got, tt.want)
		}
	}
}

func TestTierHasFeatureKey_EnterpriseFeatures(t *testing.T) {
	tests := []struct {
		tier Tier
		key  string
		want bool
	}{
		// Enterprise features
		{TierEnterprise, "hsm_integration", true},
		{TierEnterprise, "compliance_fedramp", true},
		{TierEnterprise, "deploy_airgapped", true},
		{TierEnterprise, "mcp_vm_sandbox", true},
		{TierEnterprise, "whitelabel", true},
		{TierEnterprise, "custom_domain", true},
		// Lower tiers blocked
		{TierCommunity, "hsm_integration", false},
		{TierDeveloper, "ldap_integration", false},
		{TierProfessional, "compliance_iso42001", false},
	}
	for _, tt := range tests {
		got := TierHasFeatureKey(tt.tier, tt.key)
		if got != tt.want {
			t.Errorf("TierHasFeatureKey(%s, %q) = %v, want %v", tt.tier, tt.key, got, tt.want)
		}
	}
}

func TestTierHasFeatureKey_UnknownKey(t *testing.T) {
	// Unknown keys default to Community access (conservative allow)
	tests := []struct {
		tier Tier
		key  string
		want bool
	}{
		{TierCommunity, "unknown_feature", true},
		{TierDeveloper, "unknown_feature", true},
		{TierProfessional, "unknown_feature", true},
		{TierEnterprise, "unknown_feature", true},
		{TierCommunity, "", true},
	}
	for _, tt := range tests {
		got := TierHasFeatureKey(tt.tier, tt.key)
		if got != tt.want {
			t.Errorf("TierHasFeatureKey(%s, %q) = %v, want %v", tt.tier, tt.key, got, tt.want)
		}
	}
}

// ---------- IsFeatureCommunity ----------

func TestIsFeatureCommunity_CommunityKeys(t *testing.T) {
	// Spot-check community-tier feature keys
	communityKeys := []string{
		"ai_proxy",
		"openai",
		"anthropic",
		"streaming",
		"tls_termination",
		"builtin_ca",
		"secret_scanning",
		"compliance_atlas",
		"compliance_nist_ai_rmf",
		"ml_basic_anomaly",
		"metrics",
		"audit_logging",
		"mcp_session_isolation",
		"mcp_basic_rbac",
		"sbom_tracking",
		"i18n",
	}
	for _, key := range communityKeys {
		if !IsFeatureCommunity(key) {
			t.Errorf("IsFeatureCommunity(%q) = false, want true", key)
		}
	}
}

func TestIsFeatureCommunity_DeveloperKeys(t *testing.T) {
	devKeys := []string{
		"mtls",
		"oauth_sso",
		"oidc",
		"grafana",
		"request_caching",
		"storage_sqlite",
		"data_encryption",
	}
	for _, key := range devKeys {
		if IsFeatureCommunity(key) {
			t.Errorf("IsFeatureCommunity(%q) = true, want false", key)
		}
	}
}

func TestIsFeatureCommunity_ProfessionalKeys(t *testing.T) {
	proKeys := []string{
		"compliance_hipaa",
		"compliance_pci",
		"multi_tenant",
		"siem_integration",
		"deploy_kubernetes",
		"storage_postgres",
	}
	for _, key := range proKeys {
		if IsFeatureCommunity(key) {
			t.Errorf("IsFeatureCommunity(%q) = true, want false", key)
		}
	}
}

func TestIsFeatureCommunity_EnterpriseKeys(t *testing.T) {
	entKeys := []string{
		"hsm_integration",
		"ldap_integration",
		"compliance_fedramp",
		"deploy_airgapped",
		"whitelabel",
		"mcp_vm_sandbox",
	}
	for _, key := range entKeys {
		if IsFeatureCommunity(key) {
			t.Errorf("IsFeatureCommunity(%q) = true, want false", key)
		}
	}
}

func TestIsFeatureCommunity_UnknownKey(t *testing.T) {
	// Unknown keys default to community (conservative allow)
	if !IsFeatureCommunity("nonexistent_feature_xyz") {
		t.Error("IsFeatureCommunity(unknown) = false, want true (default allow)")
	}
	if !IsFeatureCommunity("") {
		t.Error("IsFeatureCommunity('') = false, want true (default allow)")
	}
}

// ---------- FeatureForKey ----------

func TestFeatureForKey_CommunityKeys(t *testing.T) {
	tests := []struct {
		key      string
		wantFeat Feature
	}{
		{"ai_proxy", FeatureAIProxy},
		{"streaming", FeatureStreaming},
		{"compliance_atlas", FeatureATLAS},
		{"metrics", FeatureMetrics},
		{"mcp_basic_rbac", FeatureMCPBasicRBAC},
	}
	for _, tt := range tests {
		f, ok := FeatureForKey(tt.key)
		if !ok {
			t.Errorf("FeatureForKey(%q) returned ok=false, want true", tt.key)
		}
		if f != tt.wantFeat {
			t.Errorf("FeatureForKey(%q) = %q, want %q", tt.key, f, tt.wantFeat)
		}
	}
}

func TestFeatureForKey_DeveloperKeys(t *testing.T) {
	tests := []struct {
		key      string
		wantFeat Feature
	}{
		{"mtls", FeatureMTLS},
		{"oauth_sso", FeatureOAuthSSO},
		{"grafana", FeatureGrafana},
		{"code_execute_sandbox", FeatureCodeExecSandbox},
		{"mcp_context_isolation", FeatureContextIsolation},
	}
	for _, tt := range tests {
		f, ok := FeatureForKey(tt.key)
		if !ok {
			t.Errorf("FeatureForKey(%q) returned ok=false, want true", tt.key)
		}
		if f != tt.wantFeat {
			t.Errorf("FeatureForKey(%q) = %q, want %q", tt.key, f, tt.wantFeat)
		}
	}
}

func TestFeatureForKey_ProfessionalKeys(t *testing.T) {
	tests := []struct {
		key      string
		wantFeat Feature
	}{
		{"compliance_hipaa", FeatureHIPAA},
		{"multi_tenant", FeatureMultiTenant},
		{"deploy_kubernetes", FeatureKubernetes},
		{"vault_secrets", FeatureVaultSecrets},
		{"mcp_process_sandbox", FeatureProcessSandbox},
	}
	for _, tt := range tests {
		f, ok := FeatureForKey(tt.key)
		if !ok {
			t.Errorf("FeatureForKey(%q) returned ok=false, want true", tt.key)
		}
		if f != tt.wantFeat {
			t.Errorf("FeatureForKey(%q) = %q, want %q", tt.key, f, tt.wantFeat)
		}
	}
}

func TestFeatureForKey_EnterpriseKeys(t *testing.T) {
	tests := []struct {
		key      string
		wantFeat Feature
	}{
		{"hsm_integration", FeatureHSM},
		{"compliance_fedramp", FeatureFedRAMP},
		{"deploy_airgapped", FeatureAirGapped},
		{"mcp_vm_sandbox", FeatureVMSandbox},
		{"whitelabel", FeatureWhitelabel},
	}
	for _, tt := range tests {
		f, ok := FeatureForKey(tt.key)
		if !ok {
			t.Errorf("FeatureForKey(%q) returned ok=false, want true", tt.key)
		}
		if f != tt.wantFeat {
			t.Errorf("FeatureForKey(%q) = %q, want %q", tt.key, f, tt.wantFeat)
		}
	}
}

func TestFeatureForKey_UnknownKey(t *testing.T) {
	f, ok := FeatureForKey("nonexistent_feature_xyz")
	if ok {
		t.Errorf("FeatureForKey(unknown) returned ok=true with feature %q, want ok=false", f)
	}

	f, ok = FeatureForKey("")
	if ok {
		t.Errorf("FeatureForKey('') returned ok=true with feature %q, want ok=false", f)
	}
}

func TestFeatureForKey_ConsistencyWithRequiredTier(t *testing.T) {
	// Verify that FeatureForKey returns features whose RequiredTier matches
	// the expected tier for the key's group
	allCommunityKeys := []string{
		"ai_proxy", "openai", "anthropic", "streaming",
		"tls_termination", "builtin_ca", "secret_scanning",
		"compliance_atlas", "compliance_nist_ai_rmf",
		"ml_basic_anomaly", "metrics", "audit_logging",
	}
	for _, key := range allCommunityKeys {
		f, ok := FeatureForKey(key)
		if !ok {
			t.Errorf("FeatureForKey(%q) not found", key)
			continue
		}
		if RequiredTier(f) != TierCommunity {
			t.Errorf("FeatureForKey(%q) = %q, RequiredTier = %v, want Community", key, f, RequiredTier(f))
		}
	}

	someDevKeys := []string{"mtls", "oauth_sso", "grafana"}
	for _, key := range someDevKeys {
		f, ok := FeatureForKey(key)
		if !ok {
			t.Errorf("FeatureForKey(%q) not found", key)
			continue
		}
		if RequiredTier(f) != TierDeveloper {
			t.Errorf("FeatureForKey(%q) = %q, RequiredTier = %v, want Developer", key, f, RequiredTier(f))
		}
	}

	someProKeys := []string{"compliance_hipaa", "multi_tenant"}
	for _, key := range someProKeys {
		f, ok := FeatureForKey(key)
		if !ok {
			t.Errorf("FeatureForKey(%q) not found", key)
			continue
		}
		if RequiredTier(f) != TierProfessional {
			t.Errorf("FeatureForKey(%q) = %q, RequiredTier = %v, want Professional", key, f, RequiredTier(f))
		}
	}

	someEntKeys := []string{"hsm_integration", "deploy_airgapped"}
	for _, key := range someEntKeys {
		f, ok := FeatureForKey(key)
		if !ok {
			t.Errorf("FeatureForKey(%q) not found", key)
			continue
		}
		if RequiredTier(f) != TierEnterprise {
			t.Errorf("FeatureForKey(%q) = %q, RequiredTier = %v, want Enterprise", key, f, RequiredTier(f))
		}
	}
}