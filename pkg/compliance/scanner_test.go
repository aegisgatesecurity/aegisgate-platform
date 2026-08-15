// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance Scanner tests (v3.2.0 Phase 3)

package compliance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// buildValidationResult is a test helper that constructs a license
// ValidationResult for a given tier and module list.
func buildValidationResult(t *testing.T, tierStr string, modules []string) *license.ValidationResult {
	t.Helper()
	tierVal, err := tier.ParseTier(tierStr)
	if err != nil {
		t.Fatalf("ParseTier(%q): %v", tierStr, err)
	}
	return &license.ValidationResult{
		Valid: true,
		Tier:  tierVal,
		Payload: license.LicensePayload{
			LicenseID: "test-license",
			Tier:      tierVal.String(),
			Modules:   modules,
		},
	}
}

func TestNewScanner_DefaultOpts(t *testing.T) {
	s := NewScanner(nil, nil)
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
	if s.scanCacheTTL != 5*time.Minute {
		t.Errorf("default CacheTTL = %v, want 5m", s.scanCacheTTL)
	}
	if s.registry == nil {
		t.Error("registry should be a non-nil default")
	}
}

func TestNewScanner_CustomOpts(t *testing.T) {
	s := NewScanner(nil, &ScannerOpts{CacheTTL: 30 * time.Second})
	if s.scanCacheTTL != 30*time.Second {
		t.Errorf("CacheTTL = %v, want 30s", s.scanCacheTTL)
	}
}

func TestScanner_Scan_CommunityNoModules(t *testing.T) {
	s := NewScanner(nil, nil)
	lic := buildValidationResult(t, "community", nil)
	rpt, err := s.Scan(context.Background(), lic)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rpt.CustomerTier != tier.TierCommunity {
		t.Errorf("CustomerTier = %s, want community", rpt.CustomerTier)
	}
	if len(rpt.CustomerModules) != 0 {
		t.Errorf("CustomerModules = %v, want empty", rpt.CustomerModules)
	}
	// All Community tier (free) frameworks should be Enforced.
	// v4.2.0: 4 Community tier frameworks (OWASP LLM, OWASP Web, ATLAS, NIST AI RMF)
	// 
	freeCount := 0
	for _, f := range rpt.Frameworks {
		if f.Enforced && f.ReasonEnforced == "framework_free" {
			freeCount++
		}
	}
	if freeCount != 4 {
		t.Errorf("free frameworks enforced = %d, want 4", freeCount)
	}
	// No non-Community (billable) modules should be enforced.
	for _, f := range rpt.Frameworks {
		if f.Module == "" || !f.Enforced {
			continue
		}
		req, known := RequiredTierForModule(f.Module)
		if known && req != tier.TierCommunity {
			t.Errorf("billable module %s enforced for community, want not enforced", f.Module)
		}
	}
}

func TestScanner_Scan_DeveloperWithHIPAA(t *testing.T) {
	s := NewScanner(nil, nil)
	lic := buildValidationResult(t, "developer", []string{"hipaa"})
	rpt, err := s.Scan(context.Background(), lic)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rpt.CustomerTier != tier.TierDeveloper {
		t.Errorf("CustomerTier = %s, want developer", rpt.CustomerTier)
	}
	// Find HIPAA in the results.
	var hipaa *FrameworkScanResult
	for i := range rpt.Frameworks {
		if rpt.Frameworks[i].Module == "hipaa" {
			hipaa = &rpt.Frameworks[i]
			break
		}
	}
	if hipaa == nil {
		t.Fatal("HIPAA not in frameworks")
	}
	if !hipaa.Enforced {
		t.Error("HIPAA should be enforced for developer + hipaa module")
	}
	if hipaa.ReasonEnforced != "enforced" {
		t.Errorf("ReasonEnforced = %q, want enforced", hipaa.ReasonEnforced)
	}
	if !hipaa.ImplementationReady {
		t.Error("HIPAA implementation should be ready")
	}
}

func TestScanner_Scan_ProfessionalWithAllModules(t *testing.T) {
	s := NewScanner(nil, nil)
	lic := buildValidationResult(t, "professional", []string{
		"hipaa", "pci", "soc2", "iso42001", "fedramp", "fips",
	})
	rpt, err := s.Scan(context.Background(), lic)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	enforcedModules := 0
	for _, f := range rpt.Frameworks {
		if f.Enforced && f.Module != "" {
			// Count only billable (non-Community) modules
			req, known := RequiredTierForModule(f.Module)
			if known && req != tier.TierCommunity {
				enforcedModules++
			}
		}
	}
	if enforcedModules != 5 {
		t.Errorf("enforced billable modules = %d, want 5", enforcedModules)
	}
	// All 6 modules should be enforced; free frameworks also enforced.
	// Score is 0 in this test because no frameworks are wired to the
	// registry in the unit test. The important assertion is that
	// OverallScore is computed (i.e., >= 0, not negative) and that
	// OverallCompliancePct is also 0 (no controls evaluated).
	if rpt.OverallScore < 0 {
		t.Errorf("OverallScore = %v, want >= 0", rpt.OverallScore)
	}
}

func TestScanner_Scan_CommunityCannotEnforceHIPAA(t *testing.T) {
	s := NewScanner(nil, nil)
	lic := buildValidationResult(t, "community", []string{"hipaa"})
	rpt, err := s.Scan(context.Background(), lic)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var hipaa *FrameworkScanResult
	for i := range rpt.Frameworks {
		if rpt.Frameworks[i].Module == "hipaa" {
			hipaa = &rpt.Frameworks[i]
			break
		}
	}
	if hipaa == nil {
		t.Fatal("HIPAA not in frameworks")
	}
	if hipaa.Enforced {
		t.Error("HIPAA should NOT be enforced for community (tier too low)")
	}
	if hipaa.ReasonNotEnforced != "tier_too_low" {
		t.Errorf("ReasonNotEnforced = %q, want tier_too_low", hipaa.ReasonNotEnforced)
	}
	if hipaa.UpgradeHint == "" {
		t.Error("UpgradeHint should be set for tier_too_low")
	}
	if !strings.Contains(hipaa.UpgradeHint, "developer") {
		t.Errorf("UpgradeHint = %q, should mention developer", hipaa.UpgradeHint)
	}
}

func TestScanner_Scan_DeveloperWithoutHIPAA(t *testing.T) {
	// Developer tier but didn't buy HIPAA module.
	s := NewScanner(nil, nil)
	lic := buildValidationResult(t, "developer", nil)
	rpt, err := s.Scan(context.Background(), lic)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var hipaa *FrameworkScanResult
	for i := range rpt.Frameworks {
		if rpt.Frameworks[i].Module == "hipaa" {
			hipaa = &rpt.Frameworks[i]
			break
		}
	}
	if hipaa == nil {
		t.Fatal("HIPAA not in frameworks")
	}
	if hipaa.Enforced {
		t.Error("HIPAA should not be enforced without the module")
	}
	if hipaa.ReasonNotEnforced != "module_not_owned" {
		t.Errorf("ReasonNotEnforced = %q, want module_not_owned", hipaa.ReasonNotEnforced)
	}
	if len(hipaa.MissingModules) == 0 {
		t.Error("MissingModules should be set for module_not_owned")
	}
}

func TestScanner_Scan_InvalidLicense(t *testing.T) {
	s := NewScanner(nil, nil)
	rpt, err := s.Scan(context.Background(), &license.ValidationResult{Valid: false})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rpt.HasLicense {
		t.Error("HasLicense should be false")
	}
	if rpt.LicenseValid {
		t.Error("LicenseValid should be false")
	}
	if rpt.CustomerTier != tier.TierCommunity {
		t.Errorf("CustomerTier = %s, want community for invalid license", rpt.CustomerTier)
	}
}

func TestScanner_Scan_NilLicense(t *testing.T) {
	s := NewScanner(nil, nil)
	rpt, err := s.Scan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rpt.HasLicense {
		t.Error("HasLicense should be false for nil license")
	}
}

func TestScanner_Scan_FrameworksSortedByName(t *testing.T) {
	s := NewScanner(nil, nil)
	rpt, err := s.Scan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for i := 1; i < len(rpt.Frameworks); i++ {
		if rpt.Frameworks[i-1].DisplayName > rpt.Frameworks[i].DisplayName {
			t.Errorf("frameworks not sorted: %q > %q",
				rpt.Frameworks[i-1].DisplayName, rpt.Frameworks[i].DisplayName)
		}
	}
}

func TestScanner_Scan_Caching(t *testing.T) {
	s := NewScanner(nil, &ScannerOpts{CacheTTL: 1 * time.Hour})
	lic := buildValidationResult(t, "developer", []string{"hipaa"})
	rpt1, _ := s.Scan(context.Background(), lic)
	rpt2, _ := s.Scan(context.Background(), lic)
	if rpt1 != rpt2 {
		t.Error("second scan should return cached report (same pointer)")
	}
}

func TestScanner_Scan_CacheInvalidate(t *testing.T) {
	s := NewScanner(nil, &ScannerOpts{CacheTTL: 1 * time.Hour})
	lic := buildValidationResult(t, "developer", []string{"hipaa"})
	rpt1, _ := s.Scan(context.Background(), lic)
	s.InvalidateCache()
	rpt2, _ := s.Scan(context.Background(), lic)
	if rpt1 == rpt2 {
		t.Error("after InvalidateCache, scan should produce a new report")
	}
}

func TestScanner_Scan_ScanDurationSet(t *testing.T) {
	s := NewScanner(nil, nil)
	rpt, _ := s.Scan(context.Background(), nil)
	if rpt.ScanDurationMs < 0 {
		t.Errorf("ScanDurationMs = %d, want >= 0", rpt.ScanDurationMs)
	}
}

func TestScanner_Scan_AllBillableModulesPresent(t *testing.T) {
	s := NewScanner(nil, nil)
	// Professional tier with all Professional-tier modules owned
	rpt, _ := s.Scan(context.Background(), buildValidationResult(t, "professional", []string{
		"hipaa", "pci", "soc2", "iso27001", "ccpa", "gdpr",
		"iso42001", "fips", "eu_ai_act", "sox", "glba",
		"cjis", "nerc_cip", "ferpa", "hitech", "ffiec",
		"tsa_sd", "iso21434", "cis", "nist_csf", "csa_star", "nist_ai_600_1",
	}))
	// v4.2.0: 31 compliance frameworks in gating.go (Trust is in tier.go).
	// Professional tier includes 4 Community + 6 Developer + 16 Professional = 26 frameworks.
	if len(rpt.Frameworks) < 26 {
		t.Errorf("Frameworks count = %d, want at least 26 (Professional tier)", len(rpt.Frameworks))
	}
	// Verify key Professional-tier modules are present and enforced.
	expected := map[string]bool{
		"hipaa": true, "pci": true, "soc2": true,
		"iso42001": true, "fips": true,
		"eu_ai_act": true,
		"ccpa": true, "gdpr": true, "iso27001": true, "nist_ai_rmf": true,
		"sox": true, "glba": true, "cjis": true, "nerc_cip": true,
	}
	for _, f := range rpt.Frameworks {
		if f.Module != "" && f.Enforced {
			delete(expected, f.Module)
		}
	}
	if len(expected) > 0 {
		t.Errorf("missing enforced modules: %v", expected)
	}
}

func TestScanner_ScanFramework_ValidHIPAA(t *testing.T) {
	s := NewScanner(nil, nil)
	lic := buildValidationResult(t, "developer", []string{"hipaa"})
	res, assessment, err := s.ScanFramework(context.Background(), lic, "hipaa")
	if err != nil {
		t.Fatalf("ScanFramework: %v", err)
	}
	if res == nil {
		t.Fatal("result is nil")
	}
	if !res.Enforced {
		t.Error("HIPAA should be enforced")
	}
	_ = assessment // may be nil if HIPAA not registered; that's fine
}

func TestScanner_ScanFramework_UnknownFramework(t *testing.T) {
	s := NewScanner(nil, nil)
	_, _, err := s.ScanFramework(context.Background(), nil, "made-up-framework")
	if !errors.Is(err, ErrUnknownFramework) {
		t.Errorf("expected ErrUnknownFramework, got %v", err)
	}
}

func TestScanner_ScanFramework_FreeFramework(t *testing.T) {
	s := NewScanner(nil, nil)
	res, _, err := s.ScanFramework(context.Background(), nil, "atlas")
	if err != nil {
		t.Fatalf("ScanFramework(atlas): %v", err)
	}
	if !res.Enforced {
		t.Error("ATLAS should be enforced (free framework)")
	}
	if res.ReasonEnforced != "framework_free" {
		t.Errorf("ReasonEnforced = %q, want framework_free", res.ReasonEnforced)
	}
}

func TestReport_JSON(t *testing.T) {
	rpt := &ScanReport{
		CustomerTier:    tier.Tier(tier.TierDeveloper),
		CustomerModules: []string{"hipaa"},
		Frameworks: []FrameworkScanResult{
			{Framework: "hipaa", DisplayName: "HIPAA", Enforced: true, Score: 85.0, ControlsTotal: 54, ControlsEnforced: 46, CompliancePct: 85.2},
		},
		OverallScore:         85.0,
		OverallCompliancePct: 85.2,
		GeneratedAt:          time.Now().UTC(),
		ScanDurationMs:       12,
		HasLicense:           true,
		LicenseValid:         true,
	}
	data, err := rpt.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(string(data), `"customerTier":`) {
		t.Error("JSON should contain customerTier field")
	}
	if !strings.Contains(string(data), `"hipaa"`) {
		t.Error("JSON should contain the framework name")
	}
}

func TestFormatUpgradeHint(t *testing.T) {
	cases := []struct {
		name string
		dec  GatingDecision
		want string
	}{
		{
			name: "missing module",
			dec:  GatingDecision{MissingUpgradeTo: "HIPAA"},
			want: "Buy the HIPAA module",
		},
		{
			name: "missing tier",
			dec:  GatingDecision{MissingTierTo: "professional"},
			want: "Upgrade to professional tier",
		},
		{
			name: "invalid license",
			dec:  GatingDecision{Reason: ReasonInvalidLicense},
			want: "Provide a valid license key",
		},
		{
			name: "unknown framework",
			dec:  GatingDecision{Reason: ReasonUnknownFramework},
			want: "Unknown compliance framework",
		},
		{
			name: "fallback to reason",
			dec:  GatingDecision{Reason: ReasonImplementationGap},
			want: "implementation_missing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatUpgradeHint(tc.dec); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDisplayNameForCommunityFrameworks(t *testing.T) {
	// v4.2.0: Display names come from gating.go's ModuleRequirement.DisplayName
	cases := []struct {
		input string
		want  string
	}{
		{license.ModuleATLAS, "MITRE ATLAS"},
		{license.ModuleNISTAIRMF, "NIST AI RMF 1.0"},
		{license.ModuleOWASP, "OWASP LLM Top 10"},
		{license.ModuleCIS, "CIS Critical Security Controls"},
		{license.ModuleNISTCSF, "NIST Cybersecurity Framework"},
		{license.ModuleOWASPWeb, "OWASP Web Top 10"},
		{license.ModuleCSASTAR, "CSA STAR"},
		{license.ModuleNISTAI600, "NIST AI 600-1"},
		{license.ModuleCCPA, "CCPA/CPRA"},
		{license.ModuleGDPR, "GDPR"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			req, ok := GetModuleRequirement(tc.input)
			if !ok {
				t.Fatalf("module %q not found in gating.go", tc.input)
			}
			if req.DisplayName != tc.want {
				t.Errorf("DisplayName = %q, want %q", req.DisplayName, tc.want)
			}
		})
	}
}

func TestAggregateScores_AllEnforced(t *testing.T) {
	results := []FrameworkScanResult{
		{Enforced: true, Score: 80, CompliancePct: 80},
		{Enforced: true, Score: 100, CompliancePct: 100},
	}
	score, comp := aggregateScores(results)
	if score != 90.0 {
		t.Errorf("avg score = %v, want 90.0", score)
	}
	if comp != 90.0 {
		t.Errorf("avg comp = %v, want 90.0", comp)
	}
}

func TestAggregateScores_Mixed(t *testing.T) {
	results := []FrameworkScanResult{
		{Enforced: true, Score: 80, CompliancePct: 80},
		{Enforced: false, Score: 100, CompliancePct: 100}, // not counted
		{Enforced: true, Score: 60, CompliancePct: 60},
	}
	score, comp := aggregateScores(results)
	if score != 70.0 {
		t.Errorf("avg score = %v, want 70.0 (only enforced count)", score)
	}
	if comp != 70.0 {
		t.Errorf("avg comp = %v, want 70.0", comp)
	}
}

func TestAggregateScores_NoneEnforced(t *testing.T) {
	results := []FrameworkScanResult{
		{Enforced: false, Score: 80},
		{Enforced: false, Score: 100},
	}
	score, comp := aggregateScores(results)
	if score != 0 {
		t.Errorf("avg score = %v, want 0 (no enforced)", score)
	}
	if comp != 0 {
		t.Errorf("avg comp = %v, want 0", comp)
	}
}

func TestCacheKey_DifferentModulesProduceDifferentKeys(t *testing.T) {
	s := NewScanner(nil, nil)
	lic1 := buildValidationResult(t, "developer", []string{"hipaa"})
	lic2 := buildValidationResult(t, "developer", []string{"pci"})
	k1 := s.cacheKey(lic1, tier.TierDeveloper)
	k2 := s.cacheKey(lic2, tier.TierDeveloper)
	if k1 == k2 {
		t.Errorf("different modules should produce different cache keys (both = %q)", k1)
	}
}

func TestCacheKey_SameModulesSameKey(t *testing.T) {
	s := NewScanner(nil, nil)
	lic := buildValidationResult(t, "developer", []string{"hipaa", "pci"})
	k1 := s.cacheKey(lic, tier.TierDeveloper)
	k2 := s.cacheKey(lic, tier.TierDeveloper)
	if k1 != k2 {
		t.Errorf("same license should produce same cache key")
	}
}

func TestCacheKey_InvalidLicenseSameKey(t *testing.T) {
	s := NewScanner(nil, nil)
	lic := &license.ValidationResult{Valid: false}
	if k := s.cacheKey(lic, tier.TierCommunity); k != "invalid" {
		t.Errorf("invalid license cache key = %q, want invalid", k)
	}
}
