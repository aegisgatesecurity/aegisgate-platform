// SPDX-License-Identifier: Apache-2.0
package incident

import "testing"

// TestDormantAgentDetectedPlaybook verifies the v5.0 Agent Registry
// dormant-agent detection playbook structure and fields.
func TestDormantAgentDetectedPlaybook(t *testing.T) {
	pb := DormantAgentDetectedPlaybook()
	if pb.ID != "pb_dormant_agent_detected" {
		t.Errorf("ID = %q; want %q", pb.ID, "pb_dormant_agent_detected")
	}
	if pb.Name == "" {
		t.Error("Name is empty")
	}
	if pb.Severity != SeverityHigh {
		t.Errorf("Severity = %q; want %q", pb.Severity, SeverityHigh)
	}
	if pb.Source != SourceAgentRegistry {
		t.Errorf("Source = %q; want %q", pb.Source, SourceAgentRegistry)
	}
	if len(pb.Steps) != 4 {
		t.Fatalf("Steps = %d; want 4", len(pb.Steps))
	}
	// Step 1: notify
	if pb.Steps[0].Action != "notify" {
		t.Errorf("Step 0 Action = %q; want %q", pb.Steps[0].Action, "notify")
	}
	// Step 2: collect evidence
	if pb.Steps[1].Action != "collect_evidence" {
		t.Errorf("Step 1 Action = %q; want %q", pb.Steps[1].Action, "collect_evidence")
	}
	// Step 3: block_agent (quarantine)
	if pb.Steps[2].Action != "block_agent" {
		t.Errorf("Step 2 Action = %q; want %q", pb.Steps[2].Action, "block_agent")
	}
	if pb.Steps[2].Parameters["target_state"] != "quarantined" {
		t.Errorf("Step 2 target_state = %q; want %q", pb.Steps[2].Parameters["target_state"], "quarantined")
	}
	// Step 4: attestation
	if pb.Steps[3].Action != "create_attestation" {
		t.Errorf("Step 3 Action = %q; want %q", pb.Steps[3].Action, "create_attestation")
	}
	// Verify tags
	tagFound := false
	for _, tag := range pb.Tags {
		if tag == "agent-registry" {
			tagFound = true
			break
		}
	}
	if !tagFound {
		t.Error("Missing 'agent-registry' tag")
	}
}
