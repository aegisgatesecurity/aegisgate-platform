// SPDX-License-Identifier: Apache-2.0
// NIST 800-171 — Unit Tests

package nist800171

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewNIST800171Module(t *testing.T) {
	m := NewNIST800171Module()
	if m == nil {
		t.Fatal("NewNIST800171Module returned nil")
	}
	if m.Framework() != "nist800171" {
		t.Errorf("Framework() = %q, want nist800171", m.Framework())
	}
}

func TestNIST800171ControlCount(t *testing.T) {
	m := NewNIST800171Module()
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
	if total < 40 {
		t.Errorf("Controls() returned %d controls, want at least 40", total)
	}
	// Verify all controls have required fields
	for _, c := range controls {
		if c.ID == "" {
			t.Error("Control has empty ID")
		}
		if c.Name == "" {
			t.Errorf("Control %s has empty Name", c.ID)
		}
	}
}

func TestNIST800171AutomatedChecks(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()
	compliantConfig := `{"authentication": true, "auth_enabled": true, "rbac": true, "roles": true, "least_privilege": true, "session_timeout": true, "mfa": true, "monitoring": true, "audit_log": true, "logging_enabled": true, "tls": true, "fips_140": true, "vulnerability": true, "patching": true, "backup": true, "boundary": true, "key_management": true, "encryption_at_rest": true, "incident_response": true, "siem": true, "threat_intel": true, "tracking": true}`

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

func TestNIST800171AccessControl(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	// Test AC-2 Account Management with compliant config
	result, err := m.CheckControl(ctx, "NIST800171-AC-2", []byte(`{"authentication": true, "auth_enabled": true, "rbac": true, "roles": true, "session_timeout": true}`))
	if err != nil {
		t.Fatalf("CheckControl error: %v", err)
	}
	if result.Status != compliance.StatusCompliant {
		t.Errorf("AC-2 with compliant config = %s, want Compliant (message: %s)", result.Status, result.Message)
	}

	// Test AC-2 with non-compliant config
	result, err = m.CheckControl(ctx, "NIST800171-AC-2", []byte(`{}`))
	if err != nil {
		t.Fatalf("CheckControl error: %v", err)
	}
	if result.Status != compliance.StatusNonCompliant {
		t.Errorf("AC-2 with empty config = %s, want NonCompliant (message: %s)", result.Status, result.Message)
	}
}

func TestNIST800171EvidenceMappedNotAutomated(t *testing.T) {
	m := NewNIST800171Module()
	for _, c := range m.Controls() {
		if !c.Automated {
			if c.CheckFunc != nil {
				t.Errorf("%s is evidence-mapped but has CheckFunc", c.ID)
			}
		}
	}
}

func TestNIST800171AllControlsHaveFields(t *testing.T) {
	m := NewNIST800171Module()
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
