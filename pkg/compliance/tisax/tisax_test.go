// SPDX-License-Identifier: Apache-2.0
// TISAX AL2 — Unit Tests

package tisax

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewTISAXModule(t *testing.T) {
	m := NewTISAXModule()
	if m == nil {
		t.Fatal("NewTISAXModule returned nil")
	}
	if m.Framework() != "tisax" {
		t.Errorf("Framework() = %q, want tisax", m.Framework())
	}
}

func TestTISAXControlCount(t *testing.T) {
	m := NewTISAXModule()
	controls := m.Controls()
	total := len(controls)
	automated := 0
	evidenceMapped := 0
	for _, c := range controls {
		if c.Automated {
			automated++
		} else {
			evidenceMapped++
		}
	}
	if total != 35 {
		t.Errorf("Controls() returned %d controls, want 35", total)
	}
	if automated != 16 {
		t.Errorf("Automated controls = %d, want 16", automated)
	}
	if evidenceMapped != 19 {
		t.Errorf("Evidence-mapped controls = %d, want 19", evidenceMapped)
	}
}

func TestTISAXAutomatedChecks(t *testing.T) {
	m := NewTISAXModule()
	ctx := context.Background()
	compliantConfig := `{"rbac": true, "mfa": true, "authentication": true, "encryption": true, "tls": true, "audit_log": true, "logging_enabled": true, "vulnerability": true, "patching": true, "monitoring": true, "siem": true, "access_control": true, "endpoint": true, "secure_development": true, "git": true, "compliance": true}`

	automatedIDs := []string{}
	for _, c := range m.Controls() {
		if c.Automated {
			automatedIDs = append(automatedIDs, c.ID)
		}
	}

	for _, id := range automatedIDs {
		t.Run(id, func(t *testing.T) {
			result, err := m.CheckControl(ctx, id, []byte(compliantConfig))
			if err != nil {
				t.Errorf("CheckControl(%s) error: %v", id, err)
			}
			if result == nil {
				t.Errorf("CheckControl(%s) returned nil result", id)
			}
		})
	}
}

func TestTISAXMFA(t *testing.T) {
	m := NewTISAXModule()
	ctx := context.Background()

	result, err := m.CheckControl(ctx, "TISAX-IS-04", []byte(`{"mfa": true, "rbac": true, "authentication": true, "least_privilege": true}`))
	if err != nil {
		t.Fatalf("CheckControl error: %v", err)
	}
	if result.Status != compliance.StatusCompliant {
		t.Errorf("TISAX-IS-04 with MFA+RBAC = %s, want Compliant (message: %s)", result.Status, result.Message)
	}
}

func TestTISAXEvidenceMappedNotAutomated(t *testing.T) {
	m := NewTISAXModule()
	for _, c := range m.Controls() {
		if !c.Automated {
			if c.CheckFunc != nil {
				t.Errorf("%s is evidence-mapped but has CheckFunc", c.ID)
			}
		}
	}
}

func TestTISAXAllControlsHaveFields(t *testing.T) {
	m := NewTISAXModule()
	for _, c := range m.Controls() {
		if c.ID == "" {
			t.Error("Control has empty ID")
		}
		if c.Name == "" {
			t.Errorf("Control %s has empty Name", c.ID)
		}
		if c.Category == "" {
			t.Errorf("Control %s has empty Category", c.ID)
		}
		if c.Severity == "" {
			t.Errorf("Control %s has empty Severity", c.ID)
		}
	}
}
