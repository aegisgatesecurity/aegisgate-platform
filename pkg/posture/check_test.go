// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Posture Check (v3.3.0 Phase 6.5)
//
// check_test.go covers the Checker logic with table-driven tests.
// We avoid touching the real license manager by using a stub
// GatingFunc; license integration is covered separately in
// posture_integration_test.go.
//
// v3.3.0 Phase 6.5.

package posture

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// fixedNow returns a stable time.Time for deterministic tests.
func fixedNow() time.Time {
	return time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
}

// stubGating is a stub compliance gating function that returns
// canned decisions based on framework name. Used in tests that
// don't want to depend on the real compliance.EvaluateGating.
//
// IMPORTANT: this stub must match the REAL GatingDecision field set
// from pkg/compliance/gating.go. As of v3.3.0-beta.2, the fields are:
//
//	Enforced, Framework, RequiredTier, LicenseTier, ModuleOwned,
//	Reason (GatingReason), MissingUpgradeTo, MissingTierTo,
//	HasImplementation. There is NO DisplayName field.
func stubGating(framework string, lic *license.ValidationResult) compliance.GatingDecision {
	switch framework {
	case "hipaa", "pci":
		// Both implemented and enforced for any valid license.
		return compliance.GatingDecision{
			Framework:         framework,
			Enforced:          true,
			HasImplementation: true,
			ModuleOwned:       true,
			RequiredTier:      tier.TierDeveloper,
			LicenseTier:       tier.TierProfessional,
			Reason:            compliance.ReasonEnforced,
		}
	case "fedramp":
		// Enforced but NOT implemented (posture should be degraded).
		return compliance.GatingDecision{
			Framework:         framework,
			Enforced:          true,
			HasImplementation: false,
			ModuleOwned:       true,
			RequiredTier:      tier.TierProfessional,
			LicenseTier:       tier.TierProfessional,
			Reason:            compliance.ReasonImplementationGap,
		}
	default:
		// Not enforced (no module purchased).
		return compliance.GatingDecision{
			Framework:         framework,
			Enforced:          false,
			HasImplementation: false,
			ModuleOwned:       false,
			RequiredTier:      tier.TierProfessional,
			LicenseTier:       tier.TierCommunity,
			Reason:            compliance.ReasonModuleNotOwned,
		}
	}
}

// stubGatingHealthy returns a decision for every framework that is
// EITHER not-enforced (the safe default) OR enforced with a working
// implementation. Used by tests that want to assert the "all good"
// posture path.
func stubGatingHealthy(framework string, lic *license.ValidationResult) compliance.GatingDecision {
	return compliance.GatingDecision{
		Framework:         framework,
		Enforced:          false,
		HasImplementation: false,
		ModuleOwned:       false,
		RequiredTier:      tier.TierProfessional,
		LicenseTier:       tier.TierCommunity,
		Reason:            compliance.ReasonModuleNotOwned,
	}
}

func TestChecker_Healthy(t *testing.T) {
	checker := NewChecker(Deps{
		StartTime:  fixedNow().Add(-72 * time.Hour),
		Version:    "v3.3.0-test",
		Commit:     "abc1234",
		Mode:       "production",
		Now:        fixedNow,
		GatingFunc: stubGatingHealthy,
	})

	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	if report.Overall != StatusHealthy {
		t.Errorf("Overall = %q, want %q", report.Overall, StatusHealthy)
	}
	if report.Version != "v3.3.0-test" {
		t.Errorf("Version = %q, want %q", report.Version, "v3.3.0-test")
	}
	if report.Uptime == "" {
		t.Error("Uptime should be populated when StartTime is provided")
	}
	if !strings.Contains(report.Uptime, "3d") {
		t.Errorf("Uptime = %q, expected to contain 3d", report.Uptime)
	}
	if len(report.Subsystems) < 3 {
		t.Errorf("expected at least 3 subsystems (uptime, license, compliance), got %d", len(report.Subsystems))
	}
}

func TestChecker_DegradedFromMissingImpl(t *testing.T) {
	checker := NewChecker(Deps{
		StartTime:  fixedNow().Add(-1 * time.Hour),
		Version:    "v3.3.0-test",
		GatingFunc: stubGating,
		Now:        fixedNow,
	})

	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	// stubGating marks fedramp as enforced-but-no-impl. That makes
	// the compliance subsystem degraded, which makes overall degraded.
	if report.Overall != StatusDegraded {
		t.Errorf("Overall = %q, want %q (fedramp enforced but not implemented)", report.Overall, StatusDegraded)
	}
	// Find the compliance subsystem and verify its status.
	var comp *SubsystemReport
	for i, s := range report.Subsystems {
		if s.Name == "compliance" {
			comp = &report.Subsystems[i]
			break
		}
	}
	if comp == nil {
		t.Fatal("compliance subsystem not found in report")
	}
	if comp.Status != StatusDegraded {
		t.Errorf("compliance subsystem = %q, want %q", comp.Status, StatusDegraded)
	}
}

func TestChecker_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	checker := NewChecker(Deps{
		StartTime: fixedNow().Add(-1 * time.Hour),
		Version:   "v3.3.0-test",
		Now:       fixedNow,
	})
	_, err := checker.Check(ctx)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if !strings.Contains(err.Error(), "posture check cancelled") {
		t.Errorf("error = %q, want it to mention posture check cancelled", err.Error())
	}
}

func TestChecker_NoLicense(t *testing.T) {
	checker := NewChecker(Deps{
		StartTime:  fixedNow().Add(-1 * time.Hour),
		Version:    "v3.3.0-test",
		GatingFunc: stubGating,
		Now:        fixedNow,
		// License is nil.
	})

	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}

	if report.License == nil {
		t.Fatal("License block should be present even when manager is nil")
	}
	if report.License.Valid {
		t.Error("License should not be valid when manager is nil")
	}
	// Find the license subsystem and verify it's marked unknown.
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
	// Without a license manager, status is unknown (we don't know it's
	// bad - we just have no data).
	if licSub.Status != StatusUnknown {
		t.Errorf("license subsystem = %q, want %q", licSub.Status, StatusUnknown)
	}
}

func TestChecker_NoStartTime(t *testing.T) {
	checker := NewChecker(Deps{
		Version:    "v3.3.0-test",
		GatingFunc: stubGating,
		Now:        fixedNow,
		// StartTime is zero.
	})

	report, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if report.Uptime != "" {
		t.Errorf("Uptime = %q, want empty when StartTime is zero", report.Uptime)
	}
}

func TestComputeOverall(t *testing.T) {
	tests := []struct {
		name string
		subs []SubsystemReport
		want HealthStatus
	}{
		{
			name: "all healthy",
			subs: []SubsystemReport{
				{Status: StatusHealthy},
				{Status: StatusHealthy},
			},
			want: StatusHealthy,
		},
		{
			name: "one degraded => degraded",
			subs: []SubsystemReport{
				{Status: StatusHealthy},
				{Status: StatusDegraded},
			},
			want: StatusDegraded,
		},
		{
			name: "one unhealthy => unhealthy (overrides degraded)",
			subs: []SubsystemReport{
				{Status: StatusDegraded},
				{Status: StatusUnhealthy},
			},
			want: StatusUnhealthy,
		},
		{
			name: "all unknown => unknown",
			subs: []SubsystemReport{
				{Status: StatusUnknown},
				{Status: StatusUnknown},
			},
			want: StatusUnknown,
		},
		{
			name: "healthy + unknown => healthy (healthy wins)",
			subs: []SubsystemReport{
				{Status: StatusHealthy},
				{Status: StatusUnknown},
			},
			want: StatusHealthy,
		},
		{
			name: "degraded + unknown => degraded",
			subs: []SubsystemReport{
				{Status: StatusDegraded},
				{Status: StatusUnknown},
			},
			want: StatusDegraded,
		},
		{
			name: "empty => healthy (vacuously true)",
			subs: []SubsystemReport{},
			want: StatusHealthy,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeOverall(tt.subs)
			if got != tt.want {
				t.Errorf("computeOverall = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"negative", -1 * time.Hour, "0s"},
		{"zero", 0, "0s"},
		{"seconds only", 45 * time.Second, "45s"},
		{"minutes and seconds", 3*time.Minute + 15*time.Second, "3m 15s"},
		{"hours, minutes, seconds", 2*time.Hour + 15*time.Minute + 7*time.Second, "2h 15m 7s"},
		{"days, hours, minutes", 5*24*time.Hour + 3*time.Hour + 12*time.Minute, "5d 3h 12m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.d)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestKnownFrameworks(t *testing.T) {
	fw := knownFrameworks()
	if len(fw) != 7 {
		t.Errorf("expected 7 known frameworks, got %d: %v", len(fw), fw)
	}
	// Verify all 7 from the v3.3.0 roadmap are present.
	expected := map[string]bool{
		"hipaa": false, "pci": false, "soc2": false,
		"iso42001": false, "fedramp": false, "fips": false,
		"eu_ai_act": false,
	}
	for _, f := range fw {
		if _, ok := expected[f]; ok {
			expected[f] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("framework %q missing from knownFrameworks()", name)
		}
	}
}

func TestModuleList(t *testing.T) {
	tests := []struct {
		name    string
		modules []string
		want    string
	}{
		{"nil", nil, "none"},
		{"empty", []string{}, "none"},
		{"one", []string{"hipaa"}, "hipaa"},
		{"many", []string{"hipaa", "pci", "soc2"}, "hipaa, pci, soc2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := moduleList(tt.modules)
			if got != tt.want {
				t.Errorf("moduleList = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEmojiForStatus(t *testing.T) {
	tests := []struct {
		s    HealthStatus
		want string
	}{
		{StatusHealthy, "✅"},
		{StatusDegraded, "⚠️"},
		{StatusUnhealthy, "❌"},
		{StatusUnknown, "❔"},
		{HealthStatus("garbage"), "•"},
	}
	for _, tt := range tests {
		got := emojiForStatus(tt.s)
		if got != tt.want {
			t.Errorf("emojiForStatus(%q) = %q, want %q", tt.s, got, tt.want)
		}
	}
}
