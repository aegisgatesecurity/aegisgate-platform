// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Posture Check (v3.3.0 Phase 6.5)
//
// format_test.go covers FormatText, FormatVerboseText, FormatJSON,
// and the small helpers (emojiForStatus, moduleList, emptyAsUnknown).
//
// The FormatText and FormatVerboseText tests use snapshot-style
// substring matching rather than full-string comparison, so the
// tests do not break on cosmetic wording changes. The FormatJSON
// test uses structural assertions on the parsed output instead of
// string equality.
//
// v3.3.0 Phase 6.5.

package posture

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleReport() *Report {
	return &Report{
		GeneratedAt: time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC),
		Version:     "v3.3.0-test",
		Commit:      "abc1234",
		Mode:        "production",
		Overall:     StatusHealthy,
		Uptime:      "3d 4h 12m",
		License: &LicenseBlock{
			Tier:         "professional",
			DisplayName:  "Professional",
			Valid:        true,
			Customer:     "acme-corp",
			ExpiresAt:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			ModulesOwned: []string{"hipaa", "pci"},
		},
		Compliance: []ComplianceBlock{
			{Framework: "hipaa", DisplayName: "HIPAA", Enforced: true, HasImplementation: true, RequiredTier: "developer", Reason: "enforced"},
			{Framework: "pci", DisplayName: "PCI-DSS", Enforced: true, HasImplementation: true, RequiredTier: "developer", Reason: "enforced"},
			{Framework: "fedramp", DisplayName: "FedRAMP", Enforced: false, HasImplementation: false, RequiredTier: "professional", Reason: "module_not_owned"},
		},
		Subsystems: []SubsystemReport{
			{Name: "uptime", Status: StatusHealthy, Summary: "Process running for 3d 4h 12m"},
			{Name: "license", Status: StatusHealthy, Summary: "license valid (tier=professional, customer=acme-corp, modules=2)"},
			{Name: "compliance", Status: StatusHealthy, Summary: "7 frameworks evaluated, 2 enforced"},
		},
	}
}

func TestFormatText_HappyPath(t *testing.T) {
	r := sampleReport()
	out := FormatText(r)

	// Spot checks: the format must include key signals.
	mustContain := []string{
		"AegisGate is healthy",
		"v3.3.0-test",
		"abc1234",
		"3d 4h 12m",
		"professional",
		"acme-corp",
		"hipaa, pci",
		"uptime:",
		"license:",
		"compliance:",
		"HIPAA",
		"PCI-DSS",
		"FedRAMP",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("FormatText output missing %q, full output:\n%s", s, out)
		}
	}
}

func TestFormatText_NoLicense(t *testing.T) {
	r := sampleReport()
	r.License = nil
	out := FormatText(r)
	if !strings.Contains(out, "AegisGate is healthy") {
		t.Error("expected header even without license")
	}
	if strings.Contains(out, "Tier:") {
		t.Error("should not show 'Tier:' line when license is nil")
	}
}

func TestFormatText_DegradedFooter(t *testing.T) {
	r := sampleReport()
	r.Overall = StatusDegraded
	out := FormatText(r)
	if !strings.Contains(out, "Action required") {
		t.Error("degraded status should show 'Action required' footer")
	}
}

func TestFormatText_HealthyNoFooter(t *testing.T) {
	r := sampleReport()
	r.Overall = StatusHealthy
	out := FormatText(r)
	if strings.Contains(out, "Action required") {
		t.Error("healthy status should not show 'Action required' footer")
	}
}

func TestFormatVerboseText_AddsDetail(t *testing.T) {
	r := sampleReport()
	out := FormatVerboseText(r)

	mustContain := []string{
		"Generated at:",
		"Compliance detail:",
		"framework=hipaa",
		"framework=pci",
		"framework=fedramp",
		"reason=enforced",
		"reason=module_not_owned",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("FormatVerboseText output missing %q", s)
		}
	}
}

func TestFormatVerboseText_NilReport(t *testing.T) {
	out := FormatVerboseText(nil)
	if !strings.Contains(out, "no data") {
		t.Errorf("nil report should produce '<no data>' output, got: %q", out)
	}
}

func TestFormatJSON_StructuralRoundTrip(t *testing.T) {
	r := sampleReport()
	data, err := FormatJSON(r)
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}

	// Parse it back and verify key fields survived.
	var got Report
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}
	if got.Version != "v3.3.0-test" {
		t.Errorf("Version = %q, want %q", got.Version, "v3.3.0-test")
	}
	if got.Overall != StatusHealthy {
		t.Errorf("Overall = %q, want %q", got.Overall, StatusHealthy)
	}
	if got.License == nil || got.License.Tier != "professional" {
		t.Error("License.Tier did not survive JSON round-trip")
	}
	if len(got.Compliance) != 3 {
		t.Errorf("Compliance len = %d, want 3", len(got.Compliance))
	}
	if len(got.Subsystems) != 3 {
		t.Errorf("Subsystems len = %d, want 3", len(got.Subsystems))
	}
}

func TestFormatJSON_NilReport(t *testing.T) {
	data, err := FormatJSON(nil)
	if err != nil {
		t.Fatalf("FormatJSON(nil) error: %v", err)
	}
	if string(data) != "null" {
		t.Errorf("FormatJSON(nil) = %q, want %q", string(data), "null")
	}
}

func TestEmptyAsUnknown(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "<unknown>"},
		{"abc", "abc"},
		{"v3.3.0", "v3.3.0"},
	}
	for _, tt := range tests {
		got := emptyAsUnknown(tt.in)
		if got != tt.want {
			t.Errorf("emptyAsUnknown(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
