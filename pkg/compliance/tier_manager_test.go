// Copyright 2026 AegisGate Security. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compliance

import (
	"testing"
)

// ============================================================================
// TierManager Tests - Increase coverage from 46.6% to 80%+
// ============================================================================

func TestNewTierManager(t *testing.T) {
	tm := NewTierManager()
	if tm == nil {
		t.Fatal("Expected non-nil TierManager")
	}
	if tm.tiers == nil {
		t.Error("Expected tiers map to be initialized")
	}
}

func TestTierManager_IsFrameworkAllowed(t *testing.T) {
	tm := NewTierManager()
	tm.SetTier(TierCommunity)

	// Community tier should have "atlas", "owasp", "gdpr"
	if !tm.IsFrameworkAllowed("atlas") {
		t.Error("Expected ATLAS to be allowed for Community tier")
	}
	if !tm.IsFrameworkAllowed("owasp") {
		t.Error("Expected OWASP to be allowed for Community tier")
	}
	if !tm.IsFrameworkAllowed("gdpr") {
		t.Error("Expected GDPR to be allowed for Community tier")
	}
	// HIPAA is Premium tier, should not be allowed
	if tm.IsFrameworkAllowed("hipaa") {
		t.Error("HIPAA should not be allowed for Community tier")
	}

	// Switch to Premium tier - should allow everything
	tm.SetTier(TierPremium)
	if !tm.IsFrameworkAllowed("hipaa") {
		t.Error("HIPAA should be allowed for Premium tier")
	}
}

func TestTierManager_SetAndGetTier(t *testing.T) {
	tm := NewTierManager()

	tests := []struct {
		tier Tier
	}{
		{TierCommunity},
		{TierEnterprise},
		{TierPremium},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			tm.SetTier(tt.tier)
			got := tm.GetTier()
			if got != tt.tier {
				t.Errorf("GetTier() = %v, want %v", got, tt.tier)
			}
		})
	}
}

func TestTierManager_GetAvailableFrameworks(t *testing.T) {
	tm := NewTierManager()

	// Test Community tier
	tm.SetTier(TierCommunity)
	communityFrameworks := tm.GetAvailableFrameworks()
	if len(communityFrameworks) == 0 {
		t.Error("Expected Community tier to have available frameworks")
	}

	// Test Premium tier - should have more
	tm.SetTier(TierPremium)
	premiumFrameworks := tm.GetAvailableFrameworks()
	if len(premiumFrameworks) <= len(communityFrameworks) {
		t.Error("Premium tier should have at least as many frameworks as Community")
	}
}

func TestTierManager_GetAllFrameworks(t *testing.T) {
	tm := NewTierManager()
	frameworks := tm.GetAllFrameworks()
	if len(frameworks) == 0 {
		t.Error("Expected GetAllFrameworks to return frameworks")
	}
}

func TestTierManager_GetFrameworksByTier(t *testing.T) {
	tm := NewTierManager()

	tests := []struct {
		tier   Tier
		minLen int
		wantID string
	}{
		{TierCommunity, 3, "atlas"},
		{TierEnterprise, 3, "nist_ai_rmf"},
		{TierPremium, 3, "hipaa"},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			frameworks := tm.GetFrameworksByTier(tt.tier)
			if len(frameworks) < tt.minLen {
				t.Errorf("GetFrameworksByTier(%s) returned %d, want >= %d",
					tt.tier, len(frameworks), tt.minLen)
			}
			found := false
			for _, f := range frameworks {
				if f.FrameworkID == tt.wantID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected framework %s not found in %s tier", tt.wantID, tt.tier)
			}
		})
	}
}

func TestTierManager_GetCommunityFrameworks(t *testing.T) {
	tm := NewTierManager()
	frameworks := tm.GetCommunityFrameworks()
	if len(frameworks) == 0 {
		t.Error("Expected GetCommunityFrameworks to return frameworks")
	}
	found := false
	for _, f := range frameworks {
		if f.FrameworkID == "atlas" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'atlas' framework in Community tier")
	}
}

func TestTierManager_GetEnterpriseFrameworks(t *testing.T) {
	tm := NewTierManager()
	frameworks := tm.GetEnterpriseFrameworks()
	if len(frameworks) == 0 {
		t.Error("Expected GetEnterpriseFrameworks to return frameworks")
	}
}

func TestTierManager_GetPremiumFrameworks(t *testing.T) {
	tm := NewTierManager()
	frameworks := tm.GetPremiumFrameworks()
	if len(frameworks) == 0 {
		t.Error("Expected GetPremiumFrameworks to return frameworks")
	}
	// HIPAA should be in Premium tier
	found := false
	for _, f := range frameworks {
		if f.FrameworkID == "hipaa" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'hipaa' framework in Premium tier")
	}
}

func TestTierManager_ValidateLicense(t *testing.T) {
	tm := NewTierManager()

	tests := []struct {
		license  string
		tier     Tier
		expected bool
	}{
		{"any-key", TierCommunity, true},
		{"key", TierEnterprise, true},
		{"", TierEnterprise, false},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			got := tm.ValidateLicense(tt.license, tt.tier)
			if got != tt.expected {
				t.Errorf("ValidateLicense(%q, %v) = %v, want %v",
					tt.license, tt.tier, got, tt.expected)
			}
		})
	}
}

func TestTierManager_RegisterFramework(t *testing.T) {
	tm := NewTierManager()

	// Register a new framework
	tm.RegisterFramework(FrameworkTier{
		FrameworkID: "custom_framework",
		Name:        "Custom Framework",
		Tier:        TierCommunity,
		Description: "A custom compliance framework",
		Features:    []string{"feature1", "feature2"},
	})

	// Verify it's registered
	ft, exists := tm.GetFrameworkTier("custom_framework")
	if !exists {
		t.Fatal("Expected custom_framework to be registered")
	}
	if ft.Name != "Custom Framework" {
		t.Errorf("Name = %s, want 'Custom Framework'", ft.Name)
	}
}

func TestTierManager_GetFrameworkTier(t *testing.T) {
	tm := NewTierManager()

	// Test existing framework
	ft, exists := tm.GetFrameworkTier("atlas")
	if !exists {
		t.Fatal("Expected 'atlas' framework to exist")
	}
	if ft.Tier != TierCommunity {
		t.Errorf("ATLAS tier = %v, want %v", ft.Tier, TierCommunity)
	}

	// Test non-existent framework
	_, exists = tm.GetFrameworkTier("nonexistent")
	if exists {
		t.Error("Expected nonexistent framework to not exist")
	}
}

// ============================================================================
// Tier String tests
// ============================================================================

func TestTier_String(t *testing.T) {
	tests := []struct {
		tier   Tier
		expect string
	}{
		{TierCommunity, "community"},
		{TierEnterprise, "enterprise"},
		{TierPremium, "premium"},
		{Tier(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			got := tt.tier.String()
			if got != tt.expect {
				t.Errorf("Tier(%d).String() = %s, want %s", tt.tier, got, tt.expect)
			}
		})
	}
}

// ============================================================================
// SOC2 Framework Tests - Currently 0% coverage

// ============================================================================
// Corrected API tests
// ============================================================================

func TestConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if !cfg.EnableAtlas {
		t.Error("ATLAS should be enabled by default")
	}
	if !cfg.EnableNIST1500 {
		t.Error("NIST should be enabled by default")
	}
}

func TestManager_NewManager(t *testing.T) {
	mgr, err := NewManager(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestManager_Check_Pass(t *testing.T) {
	mgr, _ := NewManager(&Config{})
	result, err := mgr.Check("normal content", "inbound")
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("Check returned nil")
	}
	if result.Passed != true {
		t.Error("Expected normal content to pass")
	}
}
