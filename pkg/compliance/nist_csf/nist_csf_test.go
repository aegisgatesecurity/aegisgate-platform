// SPDX-License-Identifier: Apache-2.0
// NIST CSF 2.0 - Unit Tests

package nist_csf

import (
	"context"
	"testing"
)

func TestNewNISTCSFModule(t *testing.T) {
	m := NewNISTCSFModule()
	if m == nil {
		t.Fatal("NewNISTCSFModule returned nil")
	}
	if m.Framework() != "nist_csf" {
		t.Errorf("Framework() = %q, want nist_csf", m.Framework())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version() = %q, want 1.0", m.Version())
	}
	controls := m.Controls()
	if len(controls) != 6 {
		t.Errorf("len(Controls()) = %d, want 6", len(controls))
	}
	expected := map[string]bool{
		"NIST-CSF-GOVERN":   false,
		"NIST-CSF-IDENTIFY": false,
		"NIST-CSF-PROTECT":  false,
		"NIST-CSF-DETECT":   false,
		"NIST-CSF-RESPOND":  false,
		"NIST-CSF-RECOVER":  false,
	}
	for _, c := range controls {
		if _, ok := expected[c.ID]; ok {
			expected[c.ID] = true
		}
		if !c.Automated {
			t.Errorf("Control %s should be automated", c.ID)
		}
	}
	for id, found := range expected {
		if !found {
			t.Errorf("Control %s not registered", id)
		}
	}
}

func TestNISTCSFCheck_Compliant(t *testing.T) {
	m := NewNISTCSFModule()
	ctx := context.Background()

	// A "fully compliant" config that satisfies all 6 CSF Functions
	compliantConfig := []byte(`{
		"ai_policy": true,
		"security_policy": true,
		"risk_management": true,
		"risk_assessment": true,
		"compliance_scan": true,
		"asset_inventory": true,
		"ioc_store": true,
		"model_id": "gpt-4",
		"threat_model": "stride",
		"authentication": true,
		"rbac": true,
		"mfa": true,
		"session_timeout": 1800,
		"tls1.3": true,
		"encryption_at_rest": true,
		"data_encrypted": true,
		"pii_scanner": true,
		"scanner": true,
		"anomaly": true,
		"ioc_federation": true,
		"alerting": true,
		"attestation": true,
		"trust_attestation": true,
		"kill_switch": true,
		"audit_log": true,
		"incident_response_plan": true,
		"backup": true,
		"audit_replay": true,
		"log_integrity": true,
		"hash_chain": true
	}`)

	checks := map[string]func(context.Context, []byte) (string, string){
		"NIST-CSF-GOVERN": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkGovern(c, b)
			return string(r.Status), r.Message
		},
		"NIST-CSF-IDENTIFY": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkIdentify(c, b)
			return string(r.Status), r.Message
		},
		"NIST-CSF-PROTECT": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkProtect(c, b)
			return string(r.Status), r.Message
		},
		"NIST-CSF-DETECT": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDetect(c, b)
			return string(r.Status), r.Message
		},
		"NIST-CSF-RESPOND": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkRespond(c, b)
			return string(r.Status), r.Message
		},
		"NIST-CSF-RECOVER": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkRecover(c, b)
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

func TestNISTCSFCheck_NonCompliant(t *testing.T) {
	m := NewNISTCSFModule()
	ctx := context.Background()

	checks := map[string]func(context.Context, []byte) (string, string){
		"NIST-CSF-GOVERN": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkGovern(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"NIST-CSF-IDENTIFY": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkIdentify(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"NIST-CSF-PROTECT": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkProtect(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"NIST-CSF-DETECT": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkDetect(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"NIST-CSF-RESPOND": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkRespond(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
		"NIST-CSF-RECOVER": func(c context.Context, b []byte) (string, string) {
			r, _ := m.checkRecover(c, []byte(`{}`))
			return string(r.Status), r.Message
		},
	}

	for controlID, checkFn := range checks {
		t.Run(controlID, func(t *testing.T) {
			status, _ := checkFn(ctx, nil)
			// All 6 should be non_compliant on empty config
			if status == "compliant" {
				t.Errorf("Control %s on empty config: should NOT be compliant",
					controlID)
			}
		})
	}
}
