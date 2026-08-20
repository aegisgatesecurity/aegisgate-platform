// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Deploy Profiles Tests
// =========================================================================
//
// Tests that verify:
//   - All 5 profiles return valid, non-nil configs
//   - Each profile has expected key settings
//   - Profile registry (List, Get, IsValid) works correctly
//   - Unknown profile IDs return errors
//   - Summary() produces human-readable output
//   - All configs have sane values (no zero ports, no empty upstream)
//
// =========================================================================

package profiles

import (
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/platformconfig"
)

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

func TestListReturnsAllProfiles(t *testing.T) {
	list := List()
	if len(list) != 5 {
		t.Errorf("List() returned %d profiles, want 5", len(list))
	}

	// Verify all expected IDs are present
	ids := make(map[string]bool, len(list))
	for _, p := range list {
		ids[string(p.ID)] = true
	}

	expected := []string{
		"quickstart", "small-team", "production",
		"high-security", "air-gapped",
	}
	for _, id := range expected {
		if !ids[id] {
			t.Errorf("List() missing profile %q", id)
		}
	}
}

func TestListIsSorted(t *testing.T) {
	list := List()
	for i := 1; i < len(list); i++ {
		if list[i-1].ID > list[i].ID {
			t.Errorf("List() not sorted: %q > %q at index %d", list[i-1].ID, list[i].ID, i)
		}
	}
}

func TestGetKnownProfile(t *testing.T) {
	p, ok := Get(ProfileQuickstart)
	if !ok {
		t.Fatal("Get(Quickstart) returned false")
	}
	if p.Name != "Quickstart" {
		t.Errorf("Get(Quickstart).Name = %q, want 'Quickstart'", p.Name)
	}
	if p.Description == "" {
		t.Error("Get(Quickstart).Description is empty")
	}
	if p.Tier == "" {
		t.Error("Get(Quickstart).Tier is empty")
	}
}

func TestGetUnknownProfile(t *testing.T) {
	_, ok := Get(ProfileID("nonexistent"))
	if ok {
		t.Error("Get(nonexistent) should return false")
	}
}

func TestIsValidKnown(t *testing.T) {
	profiles := []string{
		"quickstart", "small-team", "production",
		"high-security", "air-gapped",
	}
	for _, id := range profiles {
		if !IsValid(id) {
			t.Errorf("IsValid(%q) = false, want true", id)
		}
	}
}

func TestIsValidUnknown(t *testing.T) {
	if IsValid("nonexistent") {
		t.Error("IsValid(\"nonexistent\") = true, want false")
	}
}

func TestGetAllProfilesHaveNonEmptyFields(t *testing.T) {
	list := List()
	for _, p := range list {
		if p.ID == "" {
			t.Error("Profile has empty ID")
		}
		if p.Name == "" {
			t.Errorf("Profile %q has empty Name", p.ID)
		}
		if p.Description == "" {
			t.Errorf("Profile %q has empty Description", p.ID)
		}
		if p.Tier == "" {
			t.Errorf("Profile %q has empty Tier", p.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// ConfigFor tests
// ---------------------------------------------------------------------------

func TestConfigForUnknownReturnsError(t *testing.T) {
	_, err := ConfigFor("nonexistent")
	if err == nil {
		t.Fatal("ConfigFor(\"nonexistent\") should return error")
	}
	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("Error should contain 'unknown profile', got: %v", err)
	}
	// Error message should list valid profiles
	for _, id := range []string{"quickstart", "small-team", "production", "high-security", "air-gapped"} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("Error message should list profile %q, got: %v", id, err)
		}
	}
}

func TestConfigForAllProfilesReturnNonNil(t *testing.T) {
	profiles := []string{
		"quickstart", "small-team", "production",
		"high-security", "air-gapped",
	}
	for _, id := range profiles {
		cfg, err := ConfigFor(id)
		if err != nil {
			t.Errorf("ConfigFor(%q) returned error: %v", id, err)
			continue
		}
		if cfg == nil {
			t.Errorf("ConfigFor(%q) returned nil config", id)
			continue
		}
	}
}

// ---------------------------------------------------------------------------
// Per-profile tests: verify the key distinguishing settings
// ---------------------------------------------------------------------------

func TestQuickstartConfig(t *testing.T) {
	cfg, err := ConfigFor("quickstart")
	if err != nil {
		t.Fatalf("ConfigFor(\"quickstart\") error: %v", err)
	}

	// Quickstart should have low rate limits
	if cfg.Proxy.RateLimit > 100 {
		t.Errorf("Quickstart Proxy.RateLimit = %d, want <= 100", cfg.Proxy.RateLimit)
	}
	// TLS should be off (auto-gen ready)
	if cfg.TLS.Enabled {
		t.Error("Quickstart TLS.Enabled should be false")
	}
	if !cfg.TLS.AutoGenerate {
		t.Error("Quickstart TLS.AutoGenerate should be true (ready for one-click TLS)")
	}
	// CSRF off for API-first trial
	if cfg.Security.EnableCSRF {
		t.Error("Quickstart CSRF should be false (API-first trial)")
	}
	// A2A/ACP/Trust off
	if cfg.A2A.Enabled {
		t.Error("Quickstart A2A should be false")
	}
	if cfg.ACP.Enabled {
		t.Error("Quickstart ACP should be false")
	}
	if cfg.Trust.Enabled {
		t.Error("Quickstart Trust should be false")
	}
}

func TestSmallTeamConfig(t *testing.T) {
	cfg, err := ConfigFor("small-team")
	if err != nil {
		t.Fatalf("ConfigFor(\"small-team\") error: %v", err)
	}

	// Moderate rate limits
	if cfg.Proxy.RateLimit < 100 {
		t.Errorf("SmallTeam Proxy.RateLimit = %d, want >= 100", cfg.Proxy.RateLimit)
	}
	if cfg.Proxy.RateLimit > 1000 {
		t.Errorf("SmallTeam Proxy.RateLimit = %d, want <= 1000", cfg.Proxy.RateLimit)
	}
	// CSRF on
	if !cfg.Security.EnableCSRF {
		t.Error("SmallTeam CSRF should be true")
	}
	// TLS auto-gen ready
	if !cfg.TLS.AutoGenerate {
		t.Error("SmallTeam TLS.AutoGenerate should be true")
	}
	// A2A/ACP off by default
	if cfg.A2A.Enabled {
		t.Error("SmallTeam A2A should be false by default")
	}
}

func TestProductionConfig(t *testing.T) {
	cfg, err := ConfigFor("production")
	if err != nil {
		t.Fatalf("ConfigFor(\"production\") error: %v", err)
	}

	// TLS enabled with 1.3
	if !cfg.TLS.Enabled {
		t.Error("Production TLS.Enabled should be true")
	}
	if cfg.TLS.MinVersion != "1.3" {
		t.Errorf("Production TLS.MinVersion = %q, want '1.3'", cfg.TLS.MinVersion)
	}
	// Auto-generate should be off (bring your own certs)
	if cfg.TLS.AutoGenerate {
		t.Error("Production TLS.AutoGenerate should be false (bring your own certs)")
	}
	// All security protections on
	if !cfg.Security.EnableSecurityHeaders {
		t.Error("Production SecurityHeaders should be true")
	}
	if !cfg.Security.EnableCSRF {
		t.Error("Production CSRF should be true")
	}
	if !cfg.Security.EnableXSS {
		t.Error("Production XSS should be true")
	}
	if !cfg.Security.EnablePanicRecovery {
		t.Error("Production PanicRecovery should be true")
	}
	// A2A/ACP enabled
	if !cfg.A2A.Enabled {
		t.Error("Production A2A should be true")
	}
	if !cfg.ACP.Enabled {
		t.Error("Production ACP should be true")
	}
	// Higher rate limits
	if cfg.Proxy.RateLimit < 500 {
		t.Errorf("Production Proxy.RateLimit = %d, want >= 500", cfg.Proxy.RateLimit)
	}
	// SIEM ready but off
	if cfg.SIEM.Enabled {
		t.Error("Production SIEM should be false by default (enable via config)")
	}
}

func TestHighSecurityConfig(t *testing.T) {
	cfg, err := ConfigFor("high-security")
	if err != nil {
		t.Fatalf("ConfigFor(\"high-security\") error: %v", err)
	}

	// mTLS required
	if !cfg.TLS.MutualTLS.Enabled {
		t.Error("HighSecurity mTLS.Enabled should be true")
	}
	if cfg.TLS.MutualTLS.Mode != "required" {
		t.Errorf("HighSecurity mTLS.Mode = %q, want 'required'", cfg.TLS.MutualTLS.Mode)
	}
	// FIPS enabled
	if !cfg.TLS.FIPS.Enabled {
		t.Error("HighSecurity FIPS.Enabled should be true")
	}
	if cfg.TLS.FIPS.Level != "140-2" {
		t.Errorf("HighSecurity FIPS.Level = %q, want '140-2'", cfg.TLS.FIPS.Level)
	}
	// TLS 1.3
	if cfg.TLS.MinVersion != "1.3" {
		t.Errorf("HighSecurity TLS.MinVersion = %q, want '1.3'", cfg.TLS.MinVersion)
	}
	// Trust enabled
	if !cfg.Trust.Enabled {
		t.Error("HighSecurity Trust.Enabled should be true")
	}
	// SIEM enabled
	if !cfg.SIEM.Enabled {
		t.Error("HighSecurity SIEM.Enabled should be true")
	}
	// High rate limits
	if cfg.Proxy.RateLimit < 1000 {
		t.Errorf("HighSecurity Proxy.RateLimit = %d, want >= 1000", cfg.Proxy.RateLimit)
	}
	if cfg.Proxy.MaxConns < 1000 {
		t.Errorf("HighSecurity Proxy.MaxConns = %d, want >= 1000", cfg.Proxy.MaxConns)
	}
}

func TestAirGappedConfig(t *testing.T) {
	cfg, err := ConfigFor("air-gapped")
	if err != nil {
		t.Fatalf("ConfigFor(\"air-gapped\") error: %v", err)
	}

	// Upstream should be local (not an external URL)
	if strings.Contains(cfg.Proxy.Upstream, "openai.com") {
		t.Errorf("AirGapped Proxy.Upstream = %q, should not point to external service", cfg.Proxy.Upstream)
	}
	// Dashboard bind to localhost only
	if cfg.Dashboard.BindAddr != "127.0.0.1" {
		t.Errorf("AirGapped Dashboard.BindAddr = %q, want '127.0.0.1'", cfg.Dashboard.BindAddr)
	}
	// SIEM off (no external SIEM in air-gapped)
	if cfg.SIEM.Enabled {
		t.Error("AirGapped SIEM.Enabled should be false")
	}
	// TLS enabled (self-contained)
	if !cfg.TLS.Enabled {
		t.Error("AirGapped TLS.Enabled should be true")
	}
	if !cfg.TLS.AutoGenerate {
		t.Error("AirGapped TLS.AutoGenerate should be true (no external CA)")
	}
	// FIPS enabled
	if !cfg.TLS.FIPS.Enabled {
		t.Error("AirGapped FIPS.Enabled should be true")
	}
	// Trust enabled (local attestation)
	if !cfg.Trust.Enabled {
		t.Error("AirGapped Trust.Enabled should be true")
	}
}

// ---------------------------------------------------------------------------
// Common config sanity tests (apply to all profiles)
// ---------------------------------------------------------------------------

func TestAllConfigsHaveValidPorts(t *testing.T) {
	profiles := []string{
		"quickstart", "small-team", "production",
		"high-security", "air-gapped",
	}
	for _, id := range profiles {
		cfg, err := ConfigFor(id)
		if err != nil {
			t.Errorf("ConfigFor(%q) error: %v", id, err)
			continue
		}
		if cfg.Dashboard.Port == 0 {
			t.Errorf("Profile %q: Dashboard.Port is 0", id)
		}
		if cfg.Agent.Server.Port == 0 {
			t.Errorf("Profile %q: Agent.Server.Port is 0", id)
		}
		if cfg.Dashboard.Port == cfg.Agent.Server.Port {
			t.Errorf("Profile %q: Dashboard and MCP ports conflict (%d)", id, cfg.Dashboard.Port)
		}
	}
}

func TestAllConfigsHaveNonEmptyUpstream(t *testing.T) {
	profiles := []string{
		"quickstart", "small-team", "production",
		"high-security", "air-gapped",
	}
	for _, id := range profiles {
		cfg, err := ConfigFor(id)
		if err != nil {
			t.Errorf("ConfigFor(%q) error: %v", id, err)
			continue
		}
		if cfg.Proxy.Upstream == "" {
			t.Errorf("Profile %q: Proxy.Upstream is empty", id)
		}
	}
}

func TestAllConfigsHavePersistenceEnabled(t *testing.T) {
	profiles := []string{
		"quickstart", "small-team", "production",
		"high-security", "air-gapped",
	}
	for _, id := range profiles {
		cfg, err := ConfigFor(id)
		if err != nil {
			t.Errorf("ConfigFor(%q) error: %v", id, err)
			continue
		}
		if !cfg.Persistence.Enabled {
			t.Errorf("Profile %q: Persistence.Enabled should be true", id)
		}
		if cfg.Persistence.DataDir == "" {
			t.Errorf("Profile %q: Persistence.DataDir is empty", id)
		}
	}
}

func TestAllConfigsHaveSecurityHeaders(t *testing.T) {
	profiles := []string{
		"quickstart", "small-team", "production",
		"high-security", "air-gapped",
	}
	for _, id := range profiles {
		cfg, err := ConfigFor(id)
		if err != nil {
			t.Errorf("ConfigFor(%q) error: %v", id, err)
			continue
		}
		if !cfg.Security.EnableSecurityHeaders {
			t.Errorf("Profile %q: SecurityHeaders should be true", id)
		}
	}
}

func TestAllConfigsAreOfTypePlatformConfig(t *testing.T) {
	profiles := []string{
		"quickstart", "small-team", "production",
		"high-security", "air-gapped",
	}
	for _, id := range profiles {
		cfg, err := ConfigFor(id)
		if err != nil {
			t.Errorf("ConfigFor(%q) error: %v", id, err)
			continue
		}
		// Verify it's a *platformconfig.Config by checking a field
		_ = cfg.Platform.Mode
		_ = cfg.Proxy.BindAddress
		_ = cfg.Dashboard.Port
	}
}

func TestAllConfigsReturnDifferentInstances(t *testing.T) {
	// Each call to ConfigFor should return a fresh config
	cfg1, _ := ConfigFor("quickstart")
	cfg2, _ := ConfigFor("quickstart")
	if cfg1 == cfg2 {
		t.Error("ConfigFor returned the same pointer — should return fresh instances")
	}
	cfg1.Proxy.RateLimit = 99999
	if cfg2.Proxy.RateLimit == 99999 {
		t.Error("Modifying cfg1 affected cfg2 — configs should be independent")
	}
}

// ---------------------------------------------------------------------------
// Summary tests
// ---------------------------------------------------------------------------

func TestSummaryKnownProfile(t *testing.T) {
	s, err := Summary("quickstart")
	if err != nil {
		t.Fatalf("Summary(\"quickstart\") error: %v", err)
	}
	if !strings.Contains(s, "Quickstart") {
		t.Errorf("Summary should contain 'Quickstart', got: %s", s)
	}
	if !strings.Contains(s, "Key Settings") {
		t.Error("Summary should contain 'Key Settings'")
	}
	if !strings.Contains(s, "TLS") {
		t.Error("Summary should contain 'TLS'")
	}
	if !strings.Contains(s, "rate_limit") {
		t.Error("Summary should contain 'rate_limit'")
	}
}

func TestSummaryUnknownProfile(t *testing.T) {
	_, err := Summary("nonexistent")
	if err == nil {
		t.Fatal("Summary(\"nonexistent\") should return error")
	}
}

func TestSummaryAllProfiles(t *testing.T) {
	profiles := []string{
		"quickstart", "small-team", "production",
		"high-security", "air-gapped",
	}
	for _, id := range profiles {
		s, err := Summary(id)
		if err != nil {
			t.Errorf("Summary(%q) error: %v", id, err)
			continue
		}
		if len(s) == 0 {
			t.Errorf("Summary(%q) returned empty string", id)
		}
	}
}

// ---------------------------------------------------------------------------
// Profile distinction tests — verify profiles differ from each other
// ---------------------------------------------------------------------------

func TestProfilesAreDistinct(t *testing.T) {
	// Quickstart should be less hardened than production
	quick, _ := ConfigFor("quickstart")
	prod, _ := ConfigFor("production")

	if quick.TLS.Enabled == prod.TLS.Enabled {
		t.Error("Quickstart and Production should differ on TLS.Enabled")
	}
	if quick.Security.EnableCSRF == prod.Security.EnableCSRF {
		t.Error("Quickstart and Production should differ on CSRF")
	}
	if quick.Proxy.RateLimit == prod.Proxy.RateLimit {
		t.Error("Quickstart and Production should differ on RateLimit")
	}
}

func TestHighSecurityMoreHardenedThanProduction(t *testing.T) {
	high, _ := ConfigFor("high-security")
	prod, _ := ConfigFor("production")

	// High security should have mTLS but production should not
	if !high.TLS.MutualTLS.Enabled && prod.TLS.MutualTLS.Enabled {
		t.Error("HighSecurity should have mTLS enabled, Production should not")
	}
	// High security should have FIPS but production should not
	if !high.TLS.FIPS.Enabled && prod.TLS.FIPS.Enabled {
		t.Error("HighSecurity should have FIPS enabled, Production should not")
	}
	// High security should have SIEM enabled
	if !high.SIEM.Enabled && prod.SIEM.Enabled {
		t.Error("HighSecurity should have SIEM, Production should not by default")
	}
}

func TestAirGappedHasLocalUpstream(t *testing.T) {
	air, _ := ConfigFor("air-gapped")
	quick, _ := ConfigFor("quickstart")

	if air.Proxy.Upstream == quick.Proxy.Upstream {
		t.Error("AirGapped should have different upstream than Quickstart")
	}
	if !strings.Contains(air.Proxy.Upstream, "localhost") && !strings.Contains(air.Proxy.Upstream, "127.0.0.1") {
		t.Errorf("AirGapped upstream should be local, got: %s", air.Proxy.Upstream)
	}
}

// ---------------------------------------------------------------------------
// Config type verification (compile-time check)
// ---------------------------------------------------------------------------

func TestConfigForReturnsPlatformConfigPtr(t *testing.T) {
	cfg, err := ConfigFor("quickstart")
	if err != nil {
		t.Fatal(err)
	}
	var _ *platformconfig.Config = cfg
}
