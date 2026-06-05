package tier

import "testing"

func TestParseTier(t *testing.T) {
	tests := []struct {
		input string
		want  Tier
		err   bool
	}{
		{"community", TierCommunity, false},
		{"starter", TierStarter, false}, // v3.1.1: added
		{"developer", TierDeveloper, false},
		{"professional", TierProfessional, false},
		{"enterprise", TierEnterprise, false},
		{"free", TierCommunity, false},
		{"pro", TierProfessional, false},
		{"invalid", TierCommunity, true},
	}
	for _, tt := range tests {
		got, err := ParseTier(tt.input)
		if tt.err && err == nil {
			t.Errorf("ParseTier(%q) expected error, got nil", tt.input)
		}
		if !tt.err && got != tt.want {
			t.Errorf("ParseTier(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestTierString(t *testing.T) {
	if TierCommunity.String() != "community" {
		t.Errorf("TierCommunity.String() = %q, want %q", TierCommunity.String(), "community")
	}
	if TierEnterprise.String() != "enterprise" {
		t.Errorf("TierEnterprise.String() = %q, want %q", TierEnterprise.String(), "enterprise")
	}
}

func TestCanAccess(t *testing.T) {
	if !TierEnterprise.CanAccess(TierCommunity) {
		t.Error("Enterprise should access Community features")
	}
	if TierCommunity.CanAccess(TierEnterprise) {
		t.Error("Community should NOT access Enterprise features")
	}
	if !TierProfessional.CanAccess(TierDeveloper) {
		t.Error("Professional should access Developer features")
	}
	// v3.1.1: Starter tier access checks
	if !TierStarter.CanAccess(TierCommunity) {
		t.Error("Starter should access Community features")
	}
	if TierCommunity.CanAccess(TierStarter) {
		t.Error("Community should NOT access Starter features")
	}
	if !TierDeveloper.CanAccess(TierStarter) {
		t.Error("Developer should access Starter features")
	}
	if TierStarter.CanAccess(TierDeveloper) {
		t.Error("Starter should NOT access Developer features")
	}
	if !TierProfessional.CanAccess(TierStarter) {
		t.Error("Professional should access Starter features")
	}
}

// TestRateLimits tests the deprecated RateLimit() method (backward compat)
func TestRateLimits(t *testing.T) {
	// RateLimit() is deprecated but must return RateLimitProxy() for compat
	if TierCommunity.RateLimit() != 120 {
		t.Errorf("Community rate limit = %d, want 120", TierCommunity.RateLimit())
	}
	if TierEnterprise.RateLimit() != -1 {
		t.Errorf("Enterprise rate limit = %d, want -1 (unlimited)", TierEnterprise.RateLimit())
	}
}

// TestRateLimitProxy tests the new split rate limit for proxy traffic
func TestRateLimitProxy(t *testing.T) {
	tests := []struct {
		tier Tier
		want int
	}{
		{TierCommunity, 120},
		{TierStarter, 600},        // v3.1.1: added
		{TierDeveloper, 1000},     // v3.1.1: 600 → 1000
		{TierProfessional, 10000}, // v3.1.1: 3000 → 10000
		{TierEnterprise, -1},
	}
	for _, tt := range tests {
		got := tt.tier.RateLimitProxy()
		if got != tt.want {
			t.Errorf("RateLimitProxy(%s) = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

// TestRateLimitMCP tests the new split rate limit for MCP tool calls
func TestRateLimitMCP(t *testing.T) {
	tests := []struct {
		tier Tier
		want int
	}{
		{TierCommunity, 60},
		{TierStarter, 300},       // v3.1.1: added
		{TierDeveloper, 500},     // v3.1.1: 300 → 500
		{TierProfessional, 5000}, // v3.1.1: 1500 → 5000
		{TierEnterprise, -1},
	}
	for _, tt := range tests {
		got := tt.tier.RateLimitMCP()
		if got != tt.want {
			t.Errorf("RateLimitMCP(%s) = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

// TestLogRetentionDays tests the updated 7-day Community retention
func TestLogRetentionDays(t *testing.T) {
	tests := []struct {
		tier Tier
		want int
	}{
		{TierCommunity, 7},
		{TierStarter, 30}, // v3.1.1: added
		{TierDeveloper, 30},
		{TierProfessional, 90},
		{TierEnterprise, -1},
	}
	for _, tt := range tests {
		got := tt.tier.LogRetentionDays()
		if got != tt.want {
			t.Errorf("LogRetentionDays(%s) = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

// TestMCPSpecificLimits tests the new MCP guardrail methods
func TestMCPSpecificLimits(t *testing.T) {
	// MaxConcurrentMCP
	if TierCommunity.MaxConcurrentMCP() != 5 {
		t.Errorf("Community MaxConcurrentMCP = %d, want 5", TierCommunity.MaxConcurrentMCP())
	}
	if TierStarter.MaxConcurrentMCP() != 25 {
		t.Errorf("Starter MaxConcurrentMCP = %d, want 25 (v3.1.1 Q3: matches Developer)", TierStarter.MaxConcurrentMCP())
	}
	if TierEnterprise.MaxConcurrentMCP() != -1 {
		t.Errorf("Enterprise MaxConcurrentMCP = %d, want -1", TierEnterprise.MaxConcurrentMCP())
	}

	// MaxMCPToolsPerSession
	if TierCommunity.MaxMCPToolsPerSession() != 20 {
		t.Errorf("Community MaxMCPToolsPerSession = %d, want 20", TierCommunity.MaxMCPToolsPerSession())
	}

	// MCPExecTimeoutSeconds
	if TierCommunity.MCPExecTimeoutSeconds() != 30 {
		t.Errorf("Community MCPExecTimeoutSeconds = %d, want 30", TierCommunity.MCPExecTimeoutSeconds())
	}

	// MaxMCPSandboxMemoryMB
	if TierCommunity.MaxMCPSandboxMemoryMB() != 256 {
		t.Errorf("Community MaxMCPSandboxMemoryMB = %d, want 256", TierCommunity.MaxMCPSandboxMemoryMB())
	}
}

// TestMandateCompliance verifies the non-negotiable mandate: ATLAS + NIST at Community
func TestMandateCompliance(t *testing.T) {
	// MITRE ATLAS MUST be Community tier
	atlasTier := RequiredTier(FeatureATLAS)
	if atlasTier != TierCommunity {
		t.Errorf("FeatureATLAS required tier = %s, want Community (MANDATE VIOLATION)", atlasTier)
	}

	// NIST AI RMF MUST be Community tier
	nistTier := RequiredTier(FeatureNISTAIRMF)
	if nistTier != TierCommunity {
		t.Errorf("FeatureNISTAIRMF required tier = %s, want Community (MANDATE VIOLATION)", nistTier)
	}

	// Verify Community actually has these features
	if !HasFeature(TierCommunity, FeatureATLAS) {
		t.Error("Community tier MUST have ATLAS feature (MANDATE VIOLATION)")
	}
	if !HasFeature(TierCommunity, FeatureNISTAIRMF) {
		t.Error("Community tier MUST have NIST AI RMF feature (MANDATE VIOLATION)")
	}
}

// TestOtherMandateCommunityFeatures verifies other mandate-required Community features
func TestOtherMandateCommunityFeatures(t *testing.T) {
	mandateFeatures := []Feature{
		FeatureBuiltInCA,       // Self-signed certs + built-in CA
		FeatureSBOM,            // SBOM tracking
		FeatureI18N,            // Internationalization
		FeatureDocker,          // Docker containerization
		FeatureCompose,         // docker-compose
		FeatureFileStorage,     // FileStorageBackend
		FeatureSecretScanning,  // 44-regex secret detection
		FeaturePIIScanning,     // PII detection
		FeaturePromptInjection, // Prompt injection detection
		FeatureBidirectional,   // Request + response scanning
		FeatureCircuitBreaker,  // Circuit breaker pattern
	}

	for _, f := range mandateFeatures {
		if !HasFeature(TierCommunity, f) {
			t.Errorf("Community tier MUST have feature %s (MANDATE VIOLATION)", f)
		}
	}
}

func TestHasFeature(t *testing.T) {
	if !HasFeature(TierCommunity, FeatureOWASP) {
		t.Error("Community should have OWASP")
	}
	if HasFeature(TierCommunity, FeatureHIPAA) {
		t.Error("Community should NOT have HIPAA")
	}
	if !HasFeature(TierProfessional, FeatureHIPAA) {
		t.Error("Professional should have HIPAA")
	}
	if !HasFeature(TierEnterprise, FeatureHSM) {
		t.Error("Enterprise should have HSM")
	}
	if HasFeature(TierDeveloper, FeatureHSM) {
		t.Error("Developer should NOT have HSM")
	}
}

func TestAllFeatures(t *testing.T) {
	commFeatures := AllFeatures(TierCommunity)
	// Community now has 30 features (expanded from 10)
	if len(commFeatures) < 25 {
		t.Errorf("Community should have at least 25 features, got %d", len(commFeatures))
	}
	entFeatures := AllFeatures(TierEnterprise)
	if len(entFeatures) <= len(commFeatures) {
		t.Error("Enterprise should have more features than Community")
	}
	// Total features should be at least 50
	all := allFeatures()
	if len(all) < 50 {
		t.Errorf("Total features should be at least 50, got %d", len(all))
	}
}

// TestTrustPillar_TierMapping verifies the v3.2.0 Phase 4 Trust Framework
// feature gate. Per the locked decision Q3, the Trust pillar is
// Professional+ only. The signing primitives (Ed25519/ECDSA) are always
// available as a Go library (pkg/trust/), but the *enforcement* (the
// 5th-pillar runtime behavior) is gated to Professional and above.
func TestTrustPillar_TierMapping(t *testing.T) {
	// RequiredTier is Professional (NOT Enterprise — this is the second
	// pillar after Compliance to land at Pro).
	required := RequiredTier(FeatureTrustPillar)
	if required != TierProfessional {
		t.Errorf("FeatureTrustPillar required tier = %s, want Professional (per Q3 lock)", required)
	}

	// Community and Starter do NOT have the pillar.
	for _, tier := range []Tier{TierCommunity, TierStarter} {
		if HasFeature(tier, FeatureTrustPillar) {
			t.Errorf("tier %s should NOT have FeatureTrustPillar (per Q3 lock)", tier)
		}
	}
	// Developer does NOT have the pillar (gate is at Professional, not Dev).
	if HasFeature(TierDeveloper, FeatureTrustPillar) {
		t.Error("Developer should NOT have FeatureTrustPillar (gate is at Professional)")
	}
	// Professional and Enterprise DO have the pillar.
	for _, tier := range []Tier{TierProfessional, TierEnterprise} {
		if !HasFeature(tier, FeatureTrustPillar) {
			t.Errorf("tier %s should have FeatureTrustPillar (per Q3 lock)", tier)
		}
	}
}

// TestTrustPillar_FeatureKey verifies the string key resolves to the
// expected Feature constant. The key "trust_pillar" is the canonical
// name used in feature negotiation (middleware, contract YAML, etc.).
func TestTrustPillar_FeatureKey(t *testing.T) {
	f, ok := FeatureForKey("trust_pillar")
	if !ok {
		t.Fatal("FeatureForKey(\"trust_pillar\") returned ok=false")
	}
	if f != FeatureTrustPillar {
		t.Errorf("FeatureForKey(\"trust_pillar\") = %v, want FeatureTrustPillar", f)
	}
	// Unknown key returns false.
	if _, ok := FeatureForKey("nonexistent_pillar"); ok {
		t.Error("FeatureForKey(\"nonexistent_pillar\") should return ok=false")
	}
}
