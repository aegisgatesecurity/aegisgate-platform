package tier

import "testing"

func TestParseTier(t *testing.T) {
	tests := []struct {
		input string
		want  Tier
		err   bool
	}{
		{"community", TierCommunity, false},
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
		{TierDeveloper, 600},
		{TierProfessional, 3000},
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
		{TierDeveloper, 300},
		{TierProfessional, 1500},
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
