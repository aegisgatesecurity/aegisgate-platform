// SPDX-License-Identifier: Apache-2.0
// CIS Critical Security Controls v8 - Unit Tests

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
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0", m.Version())
	}
	controls := m.Controls()
	if len(controls) != 10 {
		t.Errorf("len(Controls()) = %d, want 10", len(controls))
	}
	for _, c := range controls {
		if !c.Automated {
			t.Errorf("Control %s should be automated", c.ID)
		}
		if c.CheckFunc == nil {
			t.Errorf("Control %s has nil CheckFunc", c.ID)
		}
	}
}

func TestCISCheck_Compliant(t *testing.T) {
	m := NewCISModule()
	ctx := context.Background()

	// A "fully compliant" config that matches all 10 controls
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
		"backup": true
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
		"CIS-13": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkNetworkMonitoring(c, b)
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
		"CIS-13": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkNetworkMonitoring(c, []byte(`{}`))
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
