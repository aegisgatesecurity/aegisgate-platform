// SPDX-License-Identifier: Apache-2.0
// NIST CSF 2.0 - Unit Tests

package nist_csf

import (
	"context"
	"strings"
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
	if m.Version() != "2.0" {
		t.Errorf("Version() = %q, want 2.0", m.Version())
	}
	controls := m.Controls()
	if len(controls) != 131 {
		t.Errorf("len(Controls()) = %d, want 131", len(controls))
	}
	// Verify a sample of expected IDs
	expectedIDs := []string{
		"GV.OC-01", "GV.RM-01", "GV.RR-01", "GV.PO-01", "GV.OV-01", "GV.SC-01",
		"ID.AM-01", "ID.RA-01", "ID.IM-01",
		"PR.AA-01", "PR.AT-01", "PR.DS-01", "PR.PS-01", "PR.IR-01",
		"DE.CM-01", "DE.AE-01",
		"RS.MA-01", "RS.AN-01", "RS.CO-01", "RS.MI-01",
		"RC.RP-01", "RC.CO-01",
	}
	controlMap := make(map[string]bool)
	for _, c := range controls {
		controlMap[c.ID] = true
	}
	for _, id := range expectedIDs {
		if !controlMap[id] {
			t.Errorf("Control %s not registered", id)
		}
	}
}

func TestNISTCSF_AutomatedCount(t *testing.T) {
	m := NewNISTCSFModule()
	controls := m.Controls()
	automated := 0
	for _, c := range controls {
		if c.Automated {
			automated++
		}
	}
	if automated != 48 {
		t.Errorf("automated controls = %d, want 48", automated)
	}
}

func TestNISTCSF_ManualControlsHaveNoCheckFunc(t *testing.T) {
	m := NewNISTCSFModule()
	controls := m.Controls()
	for _, c := range controls {
		if !c.Automated && c.CheckFunc != nil {
			t.Errorf("Manual control %s should have nil CheckFunc", c.ID)
		}
		if c.Automated && c.CheckFunc == nil {
			t.Errorf("Automated control %s should have non-nil CheckFunc", c.ID)
		}
	}
}

func TestNISTCSF_AllControlsHaveReferences(t *testing.T) {
	m := NewNISTCSFModule()
	controls := m.Controls()
	for _, c := range controls {
		if len(c.References) == 0 {
			t.Errorf("Control %s has no references", c.ID)
		}
	}
}

func TestNISTCSF_AllControlsHaveCategory(t *testing.T) {
	m := NewNISTCSFModule()
	controls := m.Controls()
	for _, c := range controls {
		if c.Category == "" {
			t.Errorf("Control %s has empty category", c.ID)
		}
	}
}

func TestNISTCSF_FunctionCoverage(t *testing.T) {
	m := NewNISTCSFModule()
	controls := m.Controls()
	functions := map[string]bool{"GV": false, "ID": false, "PR": false, "DE": false, "RS": false, "RC": false}
	for _, c := range controls {
		for fn := range functions {
			if strings.HasPrefix(c.ID, fn+".") {
				functions[fn] = true
			}
		}
	}
	for fn, found := range functions {
		if !found {
			t.Errorf("No controls found for function %s", fn)
		}
	}
}

func TestNISTCSF_CheckAllAutomated_Compliant(t *testing.T) {
	m := NewNISTCSFModule()
	ctx := context.Background()

	compliantConfig := []byte(`{
		"risk_management": true,
		"risk_assessment": true,
		"compliance_scan": true,
		"security_policy": true,
		"cybersecurity_policy": true,
		"ai_policy": true,
		"policy": true,
		"asset_inventory": true,
		"ioc_store": true,
		"model_id": "gpt-4",
		"inventory": true,
		"vulnerability": true,
		"vuln_scan": true,
		"cve": true,
		"threat_model": "stride",
		"stride": true,
		"threat_intel": true,
		"risk_register": true,
		"identity": true,
		"identity_management": true,
		"iam": true,
		"mfa": true,
		"multi_factor": true,
		"authenticator": true,
		"totp": true,
		"authentication": true,
		"auth_enabled": true,
		"sso": true,
		"rbac": true,
		"roles": true,
		"permissions": true,
		"access_control": true,
		"encryption": true,
		"encrypt": true,
		"data_security": true,
		"cia": true,
		"integrity": true,
		"encryption_at_rest": true,
		"data_encrypted": true,
		"aes": true,
		"tls1.2": true,
		"tls1.3": true,
		"https": true,
		"encryption_in_transit": true,
		"network_monitor": true,
		"traffic_monitor": true,
		"ids": true,
		"ips": true,
		"anomaly": true,
		"anomaly_detection": true,
		"trust_score": true,
		"vuln_monitor": true,
		"vulnerability_scan": true,
		"patch": true,
		"scanner": true,
		"threat_detection": true,
		"event_detection": true,
		"intrusion": true,
		"siem": true,
		"incident_response": true,
		"ir_plan": true,
		"incident_mgmt": true,
		"alerting": true,
		"notification": true,
		"pagerduty": true,
		"slack": true,
		"kill_switch": true,
		"abort": true,
		"containment": true,
		"backup": true,
		"disaster_recovery": true,
		"recovery_plan": true,
		"audit_replay": true,
		"log_replay": true,
		"hash_chain": true,
		"log_integrity": true,
		"software_inventory": true,
		"data_inventory": true,
		"data_catalog": true,
		"device_inventory": true,
		"data_classification": true,
		"data_sensitivity": true,
		"system_inventory": true,
		"threat_prioritization": true,
		"network_access": true,
		"backup_protection": true,
		"configuration_management": true,
		"integrity_checking": true,
		"file_integrity": true,
		"network_protection": true,
		"data_lifecycle": true,
		"platform_config": true,
		"platform_hardening": true,
		"platform_protection": true,
		"platform_integrity": true,
		"monitoring_report": true,
		"detection_monitoring": true,
		"anomaly_analysis": true,
		"adverse_event": true,
		"incident_assessment": true,
		"incident_management": true,
		"incident_mitigation": true,
		"incident_resolution": true
	}`)

	controls := m.Controls()
	for _, c := range controls {
		if !c.Automated {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			result, err := c.CheckFunc(ctx, compliantConfig)
			if err != nil {
				t.Fatalf("Control %s CheckFunc error: %v", c.ID, err)
			}
			if result.Status != "compliant" {
				t.Errorf("Control %s on compliant config: status=%s, msg=%s",
					c.ID, result.Status, result.Message)
			}
		})
	}
}

func TestNISTCSF_CheckAllAutomated_NonCompliant(t *testing.T) {
	m := NewNISTCSFModule()
	ctx := context.Background()

	emptyConfig := []byte(`{}`)

	controls := m.Controls()
	for _, c := range controls {
		if !c.Automated {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			result, err := c.CheckFunc(ctx, emptyConfig)
			if err != nil {
				t.Fatalf("Control %s CheckFunc error: %v", c.ID, err)
			}
			if result.Status == "compliant" {
				t.Errorf("Control %s on empty config: should NOT be compliant, got %s",
					c.ID, result.Status)
			}
		})
	}
}
