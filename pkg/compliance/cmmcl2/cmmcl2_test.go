// SPDX-License-Identifier: Apache-2.0
// CMMC Level 2 — Unit Tests

package cmmcl2

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

func TestNewCMMCL2Module(t *testing.T) {
	m := NewCMMCL2Module()
	if m == nil {
		t.Fatal("NewCMMCL2Module returned nil")
	}
	if m.Framework() != "cmmcl2" {
		t.Errorf("Framework() = %q, want cmmcl2", m.Framework())
	}
}

func TestCMMCL2ControlCount(t *testing.T) {
	m := NewCMMCL2Module()
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
	if total != 150 {
		t.Errorf("Controls() returned %d controls, want 150", total)
	}
	if automated != 106 {
		t.Errorf("Automated controls = %d, want 106", automated)
	}
	if evidenceMapped != 44 {
		t.Errorf("Evidence-mapped controls = %d, want 44", evidenceMapped)
	}
}

func TestCMMCL2AutomatedChecks(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()
	compliantConfig := `{"rbac": true, "mfa": true, "authentication": true, "auth_enabled": true, "roles": true, "least_privilege": true, "session_timeout": true, "audit_log": true, "logging_enabled": true, "encryption": true, "tls": true, "fips_140": true, "vulnerability": true, "patching": true, "monitoring": true, "siem": true, "ioc": true, "incident_response": true, "physical_access": true, "maintenance": true, "sanitization": true, "threat_intel": true, "hash_chain": true, "scanner": true, "access_control": true, "media_access": true, "password_policy": true, "key_management": true, "encryption_at_rest": true, "data_encrypted": true, "lockout": true, "concurrent": true, "audit_review": true, "log_review": true, "audit_analysis": true, "review": true, "audit_protection": true, "log_protection": true, "audit_integrity": true, "log_integrity": true, "authorized_access": true, "audit_reduction": true, "log_aggregation": true, "reporting": true, "report_generation": true, "audit_monitoring": true, "log_monitoring": true, "logging_monitoring": true, "baseline_configuration": true, "config_baseline": true, "baseline": true, "drift_detection": true, "change_detection": true, "change_tracking": true, "config_restrictions": true, "configuration_limits": true, "security_config": true, "settings_enforced": true, "secure_configuration": true, "security_hardening": true, "cis_benchmark": true, "secure_baseline": true, "hardening": true, "configuration_documentation": true, "config_documentation": true, "settings_documentation": true, "configuration_settings": true, "config_settings": true, "security_settings": true, "version_control": true, "documentation": true, "up_to_date": true, "boundary_protection": true, "network_boundary": true, "firewall_boundary": true, "firewall": true, "waf": true, "network_segmentation": true, "segmentation": true, "dmz": true, "network_isolation": true, "vlan": true, "network_architecture": true, "trusted_connection": true, "network_authentication": true, "802_1x": true, "encrypted": true, "risk_response": true, "remediation_tracking": true, "risk_remediation": true, "risk_assessment": true, "risk_analysis": true, "assessment": true, "tracking": true, "remediation": true, "poam": true, "information_handling": true, "data_handling": true, "handling_rules": true, "policy": true, "enforcement": true, "enforced": true, "ir_testing": true, "incident_test": true, "response_testing": true, "ir_plan": true, "incident_plan": true, "scheduled": true, "periodic": true, "testing_schedule": true, "cui_marking": true, "cui_identification": true, "data_labeling": true, "classification_labels": true, "labels": true, "cui": true, "information_sharing": true, "data_sharing": true, "sharing_policy": true, "disk_encryption": true}`

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

func TestCMMCL2MFA(t *testing.T) {
	m := NewCMMCL2Module()
	ctx := context.Background()

	// Test with MFA + TLS + monitoring (AC-04 is Remote Access Control, needs MFA + TLS + monitoring)
	result, err := m.CheckControl(ctx, "CMMCL2-AC-04", []byte(`{"mfa": true, "tls": true, "monitoring": true, "audit_log": true}`))
	if err != nil {
		t.Fatalf("CheckControl error: %v", err)
	}
	if result.Status != compliance.StatusCompliant {
		t.Errorf("CMMCL2-AC-04 with MFA+TLS+monitoring = %s, want Compliant (message: %s)", result.Status, result.Message)
	}

	// Test without MFA (should be non-compliant)
	result, err = m.CheckControl(ctx, "CMMCL2-AC-04", []byte(`{"tls": true, "monitoring": true}`))
	if err != nil {
		t.Fatalf("CheckControl error: %v", err)
	}
	if result.Status != compliance.StatusNonCompliant {
		t.Errorf("CMMCL2-AC-04 without MFA = %s, want NonCompliant (message: %s)", result.Status, result.Message)
	}
}

func TestCMMCL2EvidenceMappedNotAutomated(t *testing.T) {
	m := NewCMMCL2Module()
	for _, c := range m.Controls() {
		if !c.Automated {
			// Evidence-mapped controls should not have a CheckFunc
			if c.CheckFunc != nil {
				t.Errorf("%s is evidence-mapped but has CheckFunc", c.ID)
			}
		}
	}
}

func TestCMMCL2AllControlsHaveFields(t *testing.T) {
	m := NewCMMCL2Module()
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
