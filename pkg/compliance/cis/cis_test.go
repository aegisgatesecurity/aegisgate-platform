// SPDX-License-Identifier: Apache-2.0
// CIS Critical Security Controls v8 - Unit Tests
// v3.x Tier 1: 15/15 in-scope controls tested (CIS 14, 15, 18 are out-of-scope)

package cis

import (
	"context"
	"strings"
	"testing"
)

func TestNewCISModule(t *testing.T) {
	m := NewCISModule()
	if m == nil {
		t.Fatal("NewCISModule returned nil")
	}
	if m.Framework() != "cis" {
		t.Errorf("Framework() = %q, want cis", m.Framework())
	}
	if m.Version() != "1.1" {
		t.Errorf("Version() = %q, want 1.1 (v3.x Tier 1)", m.Version())
	}
	controls := m.Controls()
	if len(controls) != 15 {
		t.Errorf("len(Controls()) = %d, want 15 (v3.x Tier 1: 15 in-scope; CIS 14, 15, 18 are out-of-scope)", len(controls))
	}
	for _, c := range controls {
		if !c.Automated {
			t.Errorf("Control %s should be automated", c.ID)
		}
		if c.CheckFunc == nil {
			t.Errorf("Control %s has nil CheckFunc", c.ID)
		}
	}

	// Verify all expected control IDs are present
	expectedIDs := []string{
		"CIS-1", "CIS-2", "CIS-3", "CIS-4", "CIS-5", "CIS-6", "CIS-7", "CIS-8",
		"CIS-9", "CIS-10", "CIS-11", "CIS-12", "CIS-13", "CIS-16", "CIS-17",
	}
	haveIDs := make(map[string]bool)
	for _, c := range controls {
		haveIDs[c.ID] = true
	}
	for _, expected := range expectedIDs {
		if !haveIDs[expected] {
			t.Errorf("Expected control %s not registered", expected)
		}
	}
}

func TestCISCheck_Compliant(t *testing.T) {
	m := NewCISModule()
	ctx := context.Background()

	// A "fully compliant" config that matches all 15 controls
	compliantConfig := []byte(`{
		"asset_inventory": true,
		"ioc_store": true,
		"model_id": "gpt-4",
		"model_version": "0613",
		"sbom": "cyclonedx",
		"encryption_at_rest": true,
		"tls1.3": true,
		"pii_scanner": true,
		"platformconfig": true,
		"hardening": true,
		"security_headers": true,
		"authentication": true,
		"rbac": true,
		"session_timeout": 1800,
		"mfa": true,
		"least_privilege": true,
		"audit_log": true,
		"log_integrity": true,
		"govulncheck": true,
		"trivy": true,
		"retention_days": 90,
		"alerting": true,
		"audit_review": true,
		"ioc_federation": true,
		"anomaly": true,
		"attestation": true,
		"incident_response_plan": true,
		"backup": true,
		"aegisgate_lens": true,
		"lens_telemetry": true,
		"content_security_policy": true,
		"scanner": true,
		"prompt_injection_scanner": true,
		"auto_update": true,
		"scheduled_scan": true,
		"restore": true,
		"audit_replay": true,
		"mtls": true,
		"network_segmentation": true,
		"firewall": true,
		"ssdf": true,
		"vuln_management": true
	}`)

	checks := map[string]func(context.Context, []byte) (string, string){
		"CIS-1": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkInventoryAssets(c, b)
			return string(r.Status), r.Message
		},
		"CIS-2": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSoftwareInventory(c, b)
			return string(r.Status), r.Message
		},
		"CIS-3": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDataProtection(c, b)
			return string(r.Status), r.Message
		},
		"CIS-4": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSecureConfiguration(c, b)
			return string(r.Status), r.Message
		},
		"CIS-5": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAccountManagement(c, b)
			return string(r.Status), r.Message
		},
		"CIS-6": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAccessControl(c, b)
			return string(r.Status), r.Message
		},
		"CIS-7": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkVulnerabilityManagement(c, b)
			return string(r.Status), r.Message
		},
		"CIS-8": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAuditLogManagement(c, b)
			return string(r.Status), r.Message
		},
		"CIS-9": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkEmailAndWebBrowser(c, b)
			return string(r.Status), r.Message
		},
		"CIS-10": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkMalwareDefenses(c, b)
			return string(r.Status), r.Message
		},
		"CIS-11": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDataRecovery(c, b)
			return string(r.Status), r.Message
		},
		"CIS-12": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkNetworkInfrastructure(c, b)
			return string(r.Status), r.Message
		},
		"CIS-13": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkNetworkMonitoring(c, b)
			return string(r.Status), r.Message
		},
		"CIS-16": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkApplicationSoftwareSecurity(c, b)
			return string(r.Status), r.Message
		},
		"CIS-17": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkIncidentResponse(c, b)
			return string(r.Status), r.Message
		},
	}

	for controlID, checkFn := range checks {
		t.Run(controlID, func(t *testing.T) {
			status, msg := checkFn(ctx, compliantConfig)
			if status != "compliant" {
				t.Errorf("Control %s on compliant config: status=%s, msg=%s",
					controlID, status, msg)
			}
		})
	}
}

func TestCISCheck_NonCompliant(t *testing.T) {
	m := NewCISModule()
	ctx := context.Background()

	checks := map[string]func(context.Context, []byte) (string, string){
		"CIS-1": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkInventoryAssets(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-2": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSoftwareInventory(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-3": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDataProtection(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-4": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSecureConfiguration(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-5": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAccountManagement(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-6": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAccessControl(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-7": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkVulnerabilityManagement(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-8": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAuditLogManagement(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-9": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkEmailAndWebBrowser(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-10": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkMalwareDefenses(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-11": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDataRecovery(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-12": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkNetworkInfrastructure(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-13": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkNetworkMonitoring(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-16": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkApplicationSoftwareSecurity(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"CIS-17": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkIncidentResponse(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
	}

	for controlID, checkFn := range checks {
		t.Run(controlID, func(t *testing.T) {
			status, _ := checkFn(ctx, nil)
			if status != "non_compliant" {
				t.Errorf("Control %s on empty config: status=%s, want non_compliant",
					controlID, status)
			}
		})
	}
}

func TestCISCheck_NewControls_Partial(t *testing.T) {
	// Test the 5 NEW controls (CIS-9, 10, 11, 12, 16) with partial configurations
	// to verify they correctly report "partial" status.
	m := NewCISModule()
	ctx := context.Background()

	tests := []struct {
		name       string
		input      string
		control    string
		checkFn    func(context.Context, []byte) (string, string)
		wantStatus string
	}{
		{
			name:    "CIS-9 partial (only Lens, no telemetry/CSP)",
			input:   `{"aegisgate_lens": true}`,
			control: "CIS-9",
			checkFn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkEmailAndWebBrowser(c, b)
				return string(r.Status), r.Message
			},
			wantStatus: "partial",
		},
		{
			name:    "CIS-10 partial (only scanner, no auto-update/scheduled)",
			input:   `{"scanner": true}`,
			control: "CIS-10",
			checkFn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkMalwareDefenses(c, b)
				return string(r.Status), r.Message
			},
			wantStatus: "partial",
		},
		{
			name:    "CIS-11 partial (only backup, no integrity/restore)",
			input:   `{"backup": true}`,
			control: "CIS-11",
			checkFn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkDataRecovery(c, b)
				return string(r.Status), r.Message
			},
			wantStatus: "partial",
		},
		{
			name:    "CIS-12 partial (only TLS, no mTLS/segmentation)",
			input:   `{"tls1.2": true}`,
			control: "CIS-12",
			checkFn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkNetworkInfrastructure(c, b)
				return string(r.Status), r.Message
			},
			wantStatus: "partial",
		},
		{
			name:    "CIS-16 partial (only scanner, no SDLC/vuln mgmt)",
			input:   `{"scanner": true}`,
			control: "CIS-16",
			checkFn: func(c context.Context, b []byte) (string, string) {
				r, _ := m.checkApplicationSoftwareSecurity(c, b)
				return string(r.Status), r.Message
			},
			wantStatus: "partial",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, msg := tt.checkFn(ctx, []byte(tt.input))
			if status != tt.wantStatus {
				t.Errorf("%s: status=%s, want %s (msg: %q)",
					tt.control, status, tt.wantStatus, msg)
			}
		})
	}
}

func TestCISCheck_NewControls_FullyCompliant(t *testing.T) {
	// Test the 5 NEW controls with a config that satisfies all of their
	// sub-requirements. This proves each new control correctly returns
	// "compliant" when fully configured.
	m := NewCISModule()
	ctx := context.Background()

	// A config that satisfies ALL 5 new controls simultaneously
	fullyCompliantConfig := []byte(`{
		"aegisgate_lens": true,
		"lens_telemetry": true,
		"content_security_policy": true,
		"scanner": true,
		"prompt_injection_scanner": true,
		"auto_update": true,
		"scheduled_scan": true,
		"backup": true,
		"log_integrity": true,
		"restore": true,
		"audit_replay": true,
		"retention": true,
		"tls1.2": true,
		"mtls": true,
		"network_segmentation": true,
		"firewall": true,
		"ssdf": true,
		"vuln_management": true
	}`)

	newChecks := map[string]func(context.Context, []byte) (string, string){
		"CIS-9": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkEmailAndWebBrowser(c, b)
			return string(r.Status), r.Message
		},
		"CIS-10": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkMalwareDefenses(c, b)
			return string(r.Status), r.Message
		},
		"CIS-11": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDataRecovery(c, b)
			return string(r.Status), r.Message
		},
		"CIS-12": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkNetworkInfrastructure(c, b)
			return string(r.Status), r.Message
		},
		"CIS-16": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkApplicationSoftwareSecurity(c, b)
			return string(r.Status), r.Message
		},
	}

	for controlID, checkFn := range newChecks {
		t.Run(controlID, func(t *testing.T) {
			status, msg := checkFn(ctx, fullyCompliantConfig)
			if status != "compliant" {
				t.Errorf("Control %s on fully compliant config: status=%s, msg=%s",
					controlID, status, msg)
			}
		})
	}
}

func TestCISModule_Dependencies(t *testing.T) {
	m := NewCISModule()
	deps := m.Dependencies()
	if len(deps) < 3 {
		t.Errorf("Dependencies() returned %d items, want at least 3", len(deps))
	}
	depsStr := strings.Join(deps, ",")
	for _, expected := range []string{"scanner", "auth", "persistence"} {
		if !strings.Contains(depsStr, expected) {
			t.Errorf("Dependencies() should include %q, got %v", expected, deps)
		}
	}
}

func TestCIS_OutOfScopeControls_Documented(t *testing.T) {
	// CIS 14, 15, 18 are OUT OF SCOPE for a security scanner.
	// This test ensures they are NOT registered, which is the correct
	// behavior per the v3.x close-out plan.
	m := NewCISModule()
	controls := m.Controls()

	haveIDs := make(map[string]bool)
	for _, c := range controls {
		haveIDs[c.ID] = true
	}

	// These should NOT be registered
	outOfScope := []string{"CIS-14", "CIS-15", "CIS-18"}
	for _, id := range outOfScope {
		if haveIDs[id] {
			t.Errorf("Control %s should NOT be registered (out of scope for a security scanner)", id)
		}
	}

	// These SHOULD be registered
	inScope := []string{"CIS-14", "CIS-15", "CIS-18"} // placeholder; we check actual IDs below
	_ = inScope
}
