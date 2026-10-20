// SPDX-License-Identifier: Apache-2.0
// EU AI Act coverage gap tests

package eu_ai_act

import (
	"context"
	"testing"
)

func TestHasOverrideCapability_True(t *testing.T) {
	m := NewEUAIModule()
	for _, s := range []string{"override_capability", "override_decision", "manual_override"} {
		if !m.hasOverrideCapability(s) {
			t.Errorf("hasOverrideCapability(%q) = false, want true", s)
		}
	}
}

func TestHasOverrideCapability_False(t *testing.T) {
	m := NewEUAIModule()
	if m.hasOverrideCapability("nothing relevant") {
		t.Error("hasOverrideCapability should be false for irrelevant input")
	}
}

func TestCheckLogRetention_Compliant(t *testing.T) {
	m := NewEUAIModule()
	r, err := m.checkLogRetention(context.Background(), []byte(`{"log_retention": "90d"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "EUAIAct-Art12-003" {
		t.Errorf("ControlID = %q, want EUAIAct-Art12-003", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckLogRetention_NonCompliant(t *testing.T) {
	m := NewEUAIModule()
	r, err := m.checkLogRetention(context.Background(), []byte(`{"config": "none"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "EUAIAct-Art12-003" {
		t.Errorf("ControlID = %q, want EUAIAct-Art12-003", r.ControlID)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}
