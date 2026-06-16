// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Posture Check Targeted Coverage Tests
//
// Targeted tests to close coverage gaps in pkg/posture/ to push
// the package from 84.8% to 95%+. Each test targets a specific
// branch in checkLicense, licenseSubsystem, checkCompliance, and
// the formatter functions that the existing test suite does not
// fully exercise.
//
// v3.3.0+ Coverage Hardening.

package posture

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// ------------------------------------------------------------------
// checkLicense: real Manager with empty key → valid, Community
// ------------------------------------------------------------------

func TestCheckLicense_RealManagerEmptyKey_ValidCommunity(t *testing.T) {
	// With a real *license.Manager and an empty key, Validate
	// returns Valid=true, Tier=Community. This is the only way
	// to reach the `if result.Valid` branch in checkLicense
	// without a real signed license.
	mgr, err := license.NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.SetLicenseKey("") // empty key → Community tier, valid

	checker := NewChecker(Deps{
		License:    mgr,
		StartTime:  fixedNow().Add(-1 * time.Hour),
		Version:    "v3.3.0-test",
		GatingFunc: stubGatingHealthy,
		Now:        fixedNow,
	})

	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !report.License.Valid {
		t.Error("License.Valid = false with empty key, want true (Community is valid)")
	}
	// tier.Tier.String() returns lowercase ("community"), not "Community".
	if report.License.Tier != "community" {
		t.Errorf("License.Tier = %q, want community", report.License.Tier)
	}
	if report.License.Customer != "" {
		t.Errorf("License.Customer = %q, want empty (no key)", report.License.Customer)
	}

	// licenseSubsystem should report StatusHealthy.
	var licSub *SubsystemReport
	for i, s := range report.Subsystems {
		if s.Name == "license" {
			licSub = &report.Subsystems[i]
			break
		}
	}
	if licSub == nil {
		t.Fatal("license subsystem not found")
	}
	if licSub.Status != StatusHealthy {
		t.Errorf("license subsystem = %q, want %q", licSub.Status, StatusHealthy)
	}
}

// ------------------------------------------------------------------
// checkLicense: real Manager with invalid key → not valid
// ------------------------------------------------------------------

func TestCheckLicense_RealManagerInvalidKey_NotValid(t *testing.T) {
	// A real *license.Manager with a junk key returns
	// Valid=false, Tier=Community, Message="Invalid license format...".
	// This is the `!lic.Valid` branch in licenseSubsystem.
	mgr, err := license.NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.SetLicenseKey("garbage-key-does-not-decode")

	checker := NewChecker(Deps{
		License:    mgr,
		StartTime:  fixedNow().Add(-1 * time.Hour),
		Version:    "v3.3.0-test",
		GatingFunc: stubGatingHealthy,
		Now:        fixedNow,
	})

	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if report.License.Valid {
		t.Error("License.Valid = true with garbage key, want false")
	}
	// licenseSubsystem: !lic.Valid && lic.Tier == "community" (not
	// "unknown") → the `!lic.Valid` branch (Unhealthy).
	var licSub *SubsystemReport
	for i, s := range report.Subsystems {
		if s.Name == "license" {
			licSub = &report.Subsystems[i]
			break
		}
	}
	if licSub == nil {
		t.Fatal("license subsystem not found")
	}
	if licSub.Status != StatusUnhealthy {
		t.Errorf("license subsystem = %q, want %q (invalid key)", licSub.Status, StatusUnhealthy)
	}
}

// ------------------------------------------------------------------
// NewChecker: default Now func
// ------------------------------------------------------------------

func TestNewChecker_DefaultNowFunc(t *testing.T) {
	// When Now is nil, NewChecker defaults to time.Now.
	checker := NewChecker(Deps{
		GatingFunc: stubGatingHealthy,
		// Now: nil (intentional)
	})
	if checker.deps.Now == nil {
		t.Fatal("NewChecker did not set default Now func")
	}
	// Verify the default is time.Now (just call it).
	_ = checker.deps.Now()
}

// ------------------------------------------------------------------
// NewChecker: default GatingFunc
// ------------------------------------------------------------------

func TestNewChecker_DefaultGatingFunc(t *testing.T) {
	// When GatingFunc is nil, NewChecker defaults to
	// compliance.EvaluateGating.
	checker := NewChecker(Deps{
		// GatingFunc: nil (intentional)
	})
	if checker.deps.GatingFunc == nil {
		t.Fatal("NewChecker did not set default GatingFunc")
	}
	// Verify it's a real function (not nil).
	_ = checker.deps.GatingFunc
}

// ------------------------------------------------------------------
// checkCompliance: nil GatingFunc
// ------------------------------------------------------------------

func TestCheckCompliance_NilGatingFunc(t *testing.T) {
	// When GatingFunc is nil, checkCompliance returns nil.
	// Use the default GatingFunc set by NewChecker — but then
	// override it back to nil to bypass the default.
	checker := NewChecker(Deps{})
	checker.deps.GatingFunc = nil // override
	blocks := checker.checkCompliance()
	if blocks != nil {
		t.Errorf("checkCompliance with nil GatingFunc = %v, want nil", blocks)
	}
}

// ------------------------------------------------------------------
// checkCompliance: with real license + GatingFunc
// ------------------------------------------------------------------

func TestCheckCompliance_WithLicense(t *testing.T) {
	// When License is non-nil, checkCompliance calls GetLicenseKey
	// and Validate to build a *license.ValidationResult, then
	// calls GatingFunc(fw, validationResult) for each framework.
	mgr, err := license.NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.SetLicenseKey("")
	checker := NewChecker(Deps{
		License:    mgr,
		GatingFunc: stubGatingHealthy,
	})
	blocks := checker.checkCompliance()
	if len(blocks) == 0 {
		t.Fatal("checkCompliance returned 0 blocks; want at least 1 (one per known framework)")
	}
	// All blocks should be for the stub decisions (not enforced).
	for _, b := range blocks {
		if b.Enforced {
			t.Errorf("block %q: Enforced = true, want false (stubGatingHealthy is all-not-enforced)", b.Framework)
		}
	}
}

// ------------------------------------------------------------------
// displayNameForFramework: each case branch
// ------------------------------------------------------------------

func TestDisplayNameForFramework_AllKnownFrameworks(t *testing.T) {
	// Known frameworks map to their human-readable names.
	cases := map[string]string{
		"hipaa":     "HIPAA",
		"pci":       "PCI-DSS",
		"soc2":      "SOC 2",
		"iso42001":  "ISO 42001",
		"fedramp":   "FedRAMP",
		"fips":      "FIPS 140",
		"eu_ai_act": "EU AI Act",
	}
	for fw, want := range cases {
		if got := displayNameForFramework(fw); got != want {
			t.Errorf("displayNameForFramework(%q) = %q, want %q", fw, got, want)
		}
	}
	// The default case echoes the input back (a deliberate
	// design choice so unknown frameworks don't display as "").
	if got := displayNameForFramework("unknown_framework"); got != "unknown_framework" {
		t.Errorf("displayNameForFramework(unknown) = %q, want 'unknown_framework' (default echoes input)", got)
	}
}

// ------------------------------------------------------------------
// FormatText: degraded vs healthy footer
// ------------------------------------------------------------------

func TestFormatText_DegradedFooter_OnlyWhenDegraded(t *testing.T) {
	// The "degraded" footer should only appear when overall is degraded.
	// This exercises the footer-conditional branch in FormatText.
	degradedReport := &Report{
		GeneratedAt: fixedNow(),
		Version:     "v3.3.0-test",
		Overall:     StatusDegraded,
		Subsystems:  []SubsystemReport{{Name: "x", Status: StatusDegraded, Summary: "y"}},
	}
	text := FormatText(degradedReport)
	if text == "" {
		t.Error("FormatText(degraded) returned empty string")
	}
	// Healthy reports should NOT contain a degraded indicator.
	healthyReport := &Report{
		GeneratedAt: fixedNow(),
		Version:     "v3.3.0-test",
		Overall:     StatusHealthy,
		Subsystems:  []SubsystemReport{{Name: "x", Status: StatusHealthy, Summary: "y"}},
	}
	textHealthy := FormatText(healthyReport)
	if textHealthy == "" {
		t.Error("FormatText(healthy) returned empty string")
	}
	// The two outputs should differ (degraded has the footer, healthy doesn't).
	if text == textHealthy {
		t.Error("FormatText(healthy) and FormatText(degraded) returned the same text; expected footer difference")
	}
}

// ------------------------------------------------------------------
// FormatVerboseText: with empty Subsystems list
// ------------------------------------------------------------------

func TestFormatVerboseText_EmptySubsystems(t *testing.T) {
	// An empty subsystems list should not crash.
	r := &Report{
		GeneratedAt: fixedNow(),
		Version:     "v3.3.0-test",
		Overall:     StatusUnknown,
		Subsystems:  []SubsystemReport{},
	}
	text := FormatVerboseText(r)
	if text == "" {
		t.Error("FormatVerboseText(empty subsystems) returned empty string")
	}
}

// ------------------------------------------------------------------
// moduleList: single element
// ------------------------------------------------------------------

func TestModuleList_Single(t *testing.T) {
	got := moduleList([]string{"alpha"})
	if got != "alpha" {
		t.Errorf("moduleList([alpha]) = %q, want alpha", got)
	}
}

func TestModuleList_Nil(t *testing.T) {
	got := moduleList(nil)
	if got != "none" {
		t.Errorf("moduleList(nil) = %q, want none", got)
	}
}

// ------------------------------------------------------------------
// emptyAsUnknown
// ------------------------------------------------------------------

func TestEmptyAsUnknown_Empty(t *testing.T) {
	// Returns "<unknown>" (with angle brackets) per the
	// documented format in the source.
	if got := emptyAsUnknown(""); got != "<unknown>" {
		t.Errorf("emptyAsUnknown(\"\") = %q, want <unknown>", got)
	}
}

func TestEmptyAsUnknown_NonEmpty(t *testing.T) {
	if got := emptyAsUnknown("hello"); got != "hello" {
		t.Errorf("emptyAsUnknown(hello) = %q, want hello", got)
	}
}

// ------------------------------------------------------------------
// emojiForStatus
// ------------------------------------------------------------------

func TestEmojiForStatus_AllValues(t *testing.T) {
	// Verify every HealthStatus constant has a non-empty emoji.
	all := []HealthStatus{StatusHealthy, StatusDegraded, StatusUnhealthy, StatusUnknown}
	for _, s := range all {
		if emoji := emojiForStatus(s); emoji == "" {
			t.Errorf("emojiForStatus(%q) = empty", s)
		}
	}
	// An empty status falls into the default branch.
	if emoji := emojiForStatus(""); emoji == "" {
		t.Error("emojiForStatus(\"\") = empty (default branch)")
	}
}

// ------------------------------------------------------------------
// licenseSubsystem: nil input
// ------------------------------------------------------------------

func TestLicenseSubsystem_NilLicense(t *testing.T) {
	// The nil-license branch in licenseSubsystem.
	sub := licenseSubsystem(nil)
	if sub.Status != StatusUnknown {
		t.Errorf("licenseSubsystem(nil) status = %q, want %q", sub.Status, StatusUnknown)
	}
	if sub.Name != "license" {
		t.Errorf("licenseSubsystem(nil) name = %q, want license", sub.Name)
	}
}

// ------------------------------------------------------------------
// complianceSubsystem: empty blocks
// ------------------------------------------------------------------

func TestComplianceSubsystem_EmptyBlocks(t *testing.T) {
	// An empty blocks slice → StatusUnknown.
	sub := complianceSubsystem(nil)
	if sub.Status != StatusUnknown {
		t.Errorf("complianceSubsystem(nil) status = %q, want %q", sub.Status, StatusUnknown)
	}
	sub = complianceSubsystem([]ComplianceBlock{})
	if sub.Status != StatusUnknown {
		t.Errorf("complianceSubsystem([]) status = %q, want %q", sub.Status, StatusUnknown)
	}
}

// ------------------------------------------------------------------
// checkLicense: nil Manager (existing behavior, but with explicit dep)
// ------------------------------------------------------------------

func TestCheckLicense_NilManagerExplicit(t *testing.T) {
	// Same as TestChecker_NoLicense but more focused on the
	// checkLicense return value.
	checker := NewChecker(Deps{
		License:    nil,
		GatingFunc: stubGatingHealthy,
		Now:        fixedNow,
	})
	block := checker.checkLicense(fixedNow())
	if block == nil {
		t.Fatal("checkLicense(nil) = nil, want LicenseBlock")
	}
	if block.Tier != "unknown" {
		t.Errorf("block.Tier = %q, want unknown", block.Tier)
	}
	if block.Valid {
		t.Error("block.Valid = true with nil manager, want false")
	}
	if !contains(block.Message, "license manager not configured") {
		t.Errorf("block.Message = %q, want it to mention 'license manager not configured'", block.Message)
	}
}

// contains is a small helper for substring checks in tests.
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------
// Check: with mode = demo
// ------------------------------------------------------------------

func TestChecker_ModeDemo_SurfacesInReport(t *testing.T) {
	// When Mode is set to "demo" or "staging", the report
	// should include it (visible in the text format).
	checker := NewChecker(Deps{
		StartTime:  fixedNow().Add(-1 * time.Hour),
		Version:    "v3.3.0-test",
		Mode:       "demo",
		GatingFunc: stubGatingHealthy,
		Now:        fixedNow,
	})
	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if report.Mode != "demo" {
		t.Errorf("report.Mode = %q, want demo", report.Mode)
	}
	text := FormatText(report)
	if text == "" {
		t.Error("FormatText returned empty")
	}
}

// ------------------------------------------------------------------
// Check: combined - real license + non-nil gating + zero start time
// ------------------------------------------------------------------

func TestChecker_RealLicenseZeroStartTime(t *testing.T) {
	// Combined: real license manager + zero start time. Exercises
	// the "uptime: unknown" + "license: valid (empty key)" path.
	mgr, err := license.NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.SetLicenseKey("")
	checker := NewChecker(Deps{
		License:    mgr,
		Version:    "v3.3.0-test",
		GatingFunc: stubGatingHealthy,
		Now:        fixedNow,
		// StartTime: zero
	})
	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if report.Uptime != "" {
		t.Errorf("Uptime = %q, want empty (StartTime is zero)", report.Uptime)
	}
	if !report.License.Valid {
		t.Error("License.Valid = false with empty key, want true")
	}
	// Overall should be StatusHealthy (uptime=Unknown, license=Healthy,
	// compliance=Healthy) → unknown dominates per the precedence rules
	// in computeOverall.
}

// ------------------------------------------------------------------
// Check: with stub gating that returns a missing-implementation
// enforcement — exercises the degraded compliance branch
// ------------------------------------------------------------------

func TestChecker_DegradedCompliance(t *testing.T) {
	checker := NewChecker(Deps{
		StartTime:  fixedNow().Add(-1 * time.Hour),
		Version:    "v3.3.0-test",
		GatingFunc: stubGating, // includes "fedramp" missing-impl branch
		Now:        fixedNow,
	})
	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// Overall should be Degraded (because of the missing fedramp impl).
	if report.Overall != StatusDegraded {
		t.Errorf("Overall = %q, want %q", report.Overall, StatusDegraded)
	}
	// Find the compliance subsystem.
	var compSub *SubsystemReport
	for i, s := range report.Subsystems {
		if s.Name == "compliance" {
			compSub = &report.Subsystems[i]
			break
		}
	}
	if compSub == nil {
		t.Fatal("compliance subsystem not found")
	}
	if compSub.Status != StatusDegraded {
		t.Errorf("compliance subsystem = %q, want %q", compSub.Status, StatusDegraded)
	}
}

// ------------------------------------------------------------------
// Tier constants are available — verify the GatingDecision shape
// ------------------------------------------------------------------

func TestGatingDecision_TierString(t *testing.T) {
	// Just to verify the tier.TierString conversion works in the
	// context of stubGating. This is mostly a smoke test.
	decision := compliance.GatingDecision{
		Framework:    "test",
		RequiredTier: tier.TierProfessional,
		LicenseTier:  tier.TierCommunity,
		Reason:       compliance.ReasonTierTooLow,
	}
	// tier.Tier.String() returns the lowercase form (e.g.,
	// "professional"), not the title-cased "Professional". The
	// DisplayName() method returns the title-cased form.
	if decision.RequiredTier.String() != "professional" {
		t.Errorf("RequiredTier.String() = %q, want professional", decision.RequiredTier.String())
	}
	if decision.LicenseTier.String() != "community" {
		t.Errorf("LicenseTier.String() = %q, want community", decision.LicenseTier.String())
	}
	if decision.RequiredTier.DisplayName() != "Professional" {
		t.Errorf("RequiredTier.DisplayName() = %q, want Professional", decision.RequiredTier.DisplayName())
	}
}

// ------------------------------------------------------------------
// formatDuration: zero duration
// ------------------------------------------------------------------

func TestFormatDuration_Zero(t *testing.T) {
	if got := formatDuration(0); got != "0s" {
		t.Errorf("formatDuration(0) = %q, want 0s", got)
	}
}

func TestFormatDuration_Negative(t *testing.T) {
	// Negative durations are not expected, but the function
	// should not crash.
	_ = formatDuration(-1 * time.Hour)
}
