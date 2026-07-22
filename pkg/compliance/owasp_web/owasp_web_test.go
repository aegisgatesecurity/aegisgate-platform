// SPDX-License-Identifier: Apache-2.0
// OWASP Top 10 Web (2021) - Unit Tests

package owasp_web

import (
	"context"
	"strings"
	"testing"
)

func TestNewOWASPWebModule(t *testing.T) {
	m := NewOWASPWebModule()
	if m == nil {
		t.Fatal("NewOWASPWebModule returned nil")
	}
	if m.Framework() != "owasp_web" {
		t.Errorf("Framework() = %q, want owasp_web", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0", m.Version())
	}
	controls := m.Controls()
	if len(controls) != 10 {
		t.Errorf("len(Controls()) = %d, want 10", len(controls))
	}
	for _, c := range controls {
		if !strings.HasPrefix(c.ID, "OWASPWeb-") {
			t.Errorf("Control ID %s should start with OWASPWeb-", c.ID)
		}
		if !c.Automated {
			t.Errorf("Control %s should be automated", c.ID)
		}
	}
}

func TestOWASPWebCheck_Compliant(t *testing.T) {
	m := NewOWASPWebModule()
	ctx := context.Background()

	compliantConfig := []byte(`{
		"rbac": true,
		"least_privilege": true,
		"session_timeout": 1800,
		"tls1.3": true,
		"encryption_at_rest": true,
		"aes_256": true,
		"ecdsa_p256": true,
		"fips_mode": true,
		"scanner": true,
		"input_filter": true,
		"parameterized_query": true,
		"threat_model": "stride",
		"trust_framework": true,
		"security_headers": true,
		"csp": true,
		"x_frame_options": true,
		"hardening": true,
		"authentication": true,
		"mfa": true,
		"session_management": true,
		"attestation": true,
		"hash_chain": true,
		"audit_log": true,
		"log_integrity": true,
		"alerting": true,
		"retention_days": 90,
		"url_allowlist": true,
		"govulncheck": true,
		"trivy": true,
		"sbom": "cyclonedx"
	}`)

	checks := map[string]func(context.Context, []byte) (string, string){
		"OWASPWeb-A01": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkBrokenAccessControl(c, b)
			return string(r.Status), r.Message
		},
		"OWASPWeb-A02": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkCryptographicFailures(c, b)
			return string(r.Status), r.Message
		},
		"OWASPWeb-A03": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkInjection(c, b)
			return string(r.Status), r.Message
		},
		"OWASPWeb-A04": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkInsecureDesign(c, b)
			return string(r.Status), r.Message
		},
		"OWASPWeb-A05": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSecurityMisconfiguration(c, b)
			return string(r.Status), r.Message
		},
		"OWASPWeb-A06": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkVulnerableComponents(c, b)
			return string(r.Status), r.Message
		},
		"OWASPWeb-A07": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAuthenticationFailures(c, b)
			return string(r.Status), r.Message
		},
		"OWASPWeb-A08": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkIntegrityFailures(c, b)
			return string(r.Status), r.Message
		},
		"OWASPWeb-A09": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkLoggingFailures(c, b)
			return string(r.Status), r.Message
		},
		"OWASPWeb-A10": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSSRF(c, b)
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

func TestOWASPWebCheck_NonCompliant(t *testing.T) {
	m := NewOWASPWebModule()
	ctx := context.Background()

	checks := map[string]func(context.Context, []byte) (string, string){
		"OWASPWeb-A01": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkBrokenAccessControl(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"OWASPWeb-A02": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkCryptographicFailures(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"OWASPWeb-A03": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkInjection(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"OWASPWeb-A04": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkInsecureDesign(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"OWASPWeb-A05": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSecurityMisconfiguration(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"OWASPWeb-A06": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkVulnerableComponents(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"OWASPWeb-A07": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkAuthenticationFailures(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"OWASPWeb-A08": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkIntegrityFailures(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"OWASPWeb-A09": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkLoggingFailures(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"OWASPWeb-A10": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkSSRF(c, []byte(`{}`))
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
