// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Incident Store Tests
// =========================================================================

package incident

import (
	"context"
	"testing"
	"time"
)

// =====================================================================
// InMemoryIncidentStore tests
// =====================================================================

func TestInMemoryIncidentStore_CreateAndGet(t *testing.T) {
	store := NewInMemoryIncidentStore()

	inc := NewIncident("Test", "Description", SeverityHigh, SourceSOC)
	inc.AgentID = "agent-1"
	inc.SessionID = "session-1"

	if err := store.CreateIncident(context.Background(), inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	got, err := store.GetIncident(context.Background(), inc.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if got == nil {
		t.Fatal("GetIncident returned nil")
	}
	if got.ID != inc.ID {
		t.Errorf("ID = %q; want %q", got.ID, inc.ID)
	}
	if got.Title != inc.Title {
		t.Errorf("Title = %q; want %q", got.Title, inc.Title)
	}
}

func TestInMemoryIncidentStore_CreateDuplicate(t *testing.T) {
	store := NewInMemoryIncidentStore()

	inc := NewIncident("Test", "Description", SeverityHigh, SourceSOC)
	if err := store.CreateIncident(context.Background(), inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	// Create again with same ID — should fail.
	inc2 := &Incident{ID: inc.ID, Title: "Duplicate", Status: StatusNew}
	if err := store.CreateIncident(context.Background(), inc2); err == nil {
		t.Error("CreateIncident with duplicate ID should return an error")
	}
}

func TestInMemoryIncidentStore_CreateNil(t *testing.T) {
	store := NewInMemoryIncidentStore()
	if err := store.CreateIncident(context.Background(), nil); err == nil {
		t.Error("CreateIncident(nil) should return an error")
	}
}

func TestInMemoryIncidentStore_CreateEmptyID(t *testing.T) {
	store := NewInMemoryIncidentStore()
	inc := &Incident{Title: "No ID", Status: StatusNew}
	if err := store.CreateIncident(context.Background(), inc); err == nil {
		t.Error("CreateIncident with empty ID should return an error")
	}
}

func TestInMemoryIncidentStore_GetNotFound(t *testing.T) {
	store := NewInMemoryIncidentStore()
	got, err := store.GetIncident(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if got != nil {
		t.Error("GetIncident on nonexistent ID should return nil")
	}
}

func TestInMemoryIncidentStore_GetEmptyID(t *testing.T) {
	store := NewInMemoryIncidentStore()
	_, err := store.GetIncident(context.Background(), "")
	if err == nil {
		t.Error("GetIncident with empty ID should return an error")
	}
}

func TestInMemoryIncidentStore_Update(t *testing.T) {
	store := NewInMemoryIncidentStore()

	inc := NewIncident("Original", "Description", SeverityLow, SourceSOC)
	store.CreateIncident(context.Background(), inc)

	inc.Title = "Updated"
	inc.Severity = SeverityHigh
	inc.Status = StatusTriaged
	if err := store.UpdateIncident(context.Background(), inc); err != nil {
		t.Fatalf("UpdateIncident: %v", err)
	}

	got, _ := store.GetIncident(context.Background(), inc.ID)
	if got.Title != "Updated" {
		t.Errorf("Title = %q; want %q", got.Title, "Updated")
	}
	if got.Severity != SeverityHigh {
		t.Errorf("Severity = %q; want %q", got.Severity, SeverityHigh)
	}
	if got.Status != StatusTriaged {
		t.Errorf("Status = %q; want %q", got.Status, StatusTriaged)
	}
}

func TestInMemoryIncidentStore_UpdateNotFound(t *testing.T) {
	store := NewInMemoryIncidentStore()
	inc := &Incident{ID: "nonexistent", Title: "Ghost"}
	if err := store.UpdateIncident(context.Background(), inc); err == nil {
		t.Error("UpdateIncident on nonexistent ID should return an error")
	}
}

func TestInMemoryIncidentStore_UpdateNil(t *testing.T) {
	store := NewInMemoryIncidentStore()
	if err := store.UpdateIncident(context.Background(), nil); err == nil {
		t.Error("UpdateIncident(nil) should return an error")
	}
}

func TestInMemoryIncidentStore_ListByStatus(t *testing.T) {
	store := NewInMemoryIncidentStore()

	inc1 := NewIncident("New 1", "Test", SeverityLow, SourceSOC)
	inc2 := NewIncident("New 2", "Test", SeverityMedium, SourceSOC)
	inc3 := NewIncident("Triaged", "Test", SeverityHigh, SourceSOC)
	inc3.Status = StatusTriaged

	store.CreateIncident(context.Background(), inc1)
	store.CreateIncident(context.Background(), inc2)
	store.CreateIncident(context.Background(), inc3)

	results, err := store.ListIncidents(context.Background(), &IncidentQuery{
		Status: []IncidentStatus{StatusNew},
	})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d; want 2", len(results))
	}
}

func TestInMemoryIncidentStore_ListBySeverity(t *testing.T) {
	store := NewInMemoryIncidentStore()

	inc1 := NewIncident("High", "Test", SeverityHigh, SourceSOC)
	inc2 := NewIncident("Low", "Test", SeverityLow, SourceSOC)
	inc3 := NewIncident("Critical", "Test", SeverityCritical, SourceSOC)

	store.CreateIncident(context.Background(), inc1)
	store.CreateIncident(context.Background(), inc2)
	store.CreateIncident(context.Background(), inc3)

	results, err := store.ListIncidents(context.Background(), &IncidentQuery{
		Severity: []IncidentSeverity{SeverityHigh, SeverityCritical},
	})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d; want 2", len(results))
	}
}

func TestInMemoryIncidentStore_ListByAgentID(t *testing.T) {
	store := NewInMemoryIncidentStore()

	inc1 := NewIncident("Agent 1", "Test", SeverityHigh, SourceSOC)
	inc1.AgentID = "agent-1"
	inc2 := NewIncident("Agent 2", "Test", SeverityMedium, SourceSOC)
	inc2.AgentID = "agent-2"

	store.CreateIncident(context.Background(), inc1)
	store.CreateIncident(context.Background(), inc2)

	results, err := store.ListIncidents(context.Background(), &IncidentQuery{
		AgentID: "agent-1",
	})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("len(results) = %d; want 1", len(results))
	}
	if results[0].AgentID != "agent-1" {
		t.Errorf("AgentID = %q; want %q", results[0].AgentID, "agent-1")
	}
}

func TestInMemoryIncidentStore_ListBySessionID(t *testing.T) {
	store := NewInMemoryIncidentStore()

	inc1 := NewIncident("Session 1", "Test", SeverityHigh, SourceSOC)
	inc1.SessionID = "session-1"
	inc2 := NewIncident("Session 2", "Test", SeverityMedium, SourceSOC)
	inc2.SessionID = "session-2"

	store.CreateIncident(context.Background(), inc1)
	store.CreateIncident(context.Background(), inc2)

	results, err := store.ListIncidents(context.Background(), &IncidentQuery{
		SessionID: "session-1",
	})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("len(results) = %d; want 1", len(results))
	}
}

func TestInMemoryIncidentStore_ListByTimeRange(t *testing.T) {
	store := NewInMemoryIncidentStore()

	now := time.Now().UTC()

	inc1 := NewIncident("Recent", "Test", SeverityHigh, SourceSOC)
	inc1.CreatedAt = now.Add(-1 * time.Hour)
	inc2 := NewIncident("Old", "Test", SeverityMedium, SourceSOC)
	inc2.CreatedAt = now.Add(-48 * time.Hour)

	store.CreateIncident(context.Background(), inc1)
	store.CreateIncident(context.Background(), inc2)

	results, err := store.ListIncidents(context.Background(), &IncidentQuery{
		From: now.Add(-2 * time.Hour),
		To:   now,
	})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("len(results) = %d; want 1 (only recent)", len(results))
	}
}

func TestInMemoryIncidentStore_ListEmpty(t *testing.T) {
	store := NewInMemoryIncidentStore()

	results, err := store.ListIncidents(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("len(results) = %d; want 0", len(results))
	}
}

func TestInMemoryIncidentStore_ListWithLimit(t *testing.T) {
	store := NewInMemoryIncidentStore()

	for i := 0; i < 10; i++ {
		inc := NewIncident("Incident", "Test", SeverityLow, SourceSOC)
		store.CreateIncident(context.Background(), inc)
	}

	results, err := store.ListIncidents(context.Background(), &IncidentQuery{
		Limit: 5,
	})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) > 5 {
		t.Errorf("len(results) = %d; want <= 5", len(results))
	}
}

func TestInMemoryIncidentStore_Close(t *testing.T) {
	store := NewInMemoryIncidentStore()
	if err := store.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

// =====================================================================
// InMemoryPlaybookStore tests
// =====================================================================

func TestInMemoryPlaybookStore_CreateAndGet(t *testing.T) {
	store := NewInMemoryPlaybookStore()

	pb := FedRAMPIR4Playbook()
	if err := store.CreatePlaybook(context.Background(), pb); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	got, err := store.GetPlaybook(context.Background(), pb.ID)
	if err != nil {
		t.Fatalf("GetPlaybook: %v", err)
	}
	if got == nil {
		t.Fatal("GetPlaybook returned nil")
	}
	if got.ID != pb.ID {
		t.Errorf("ID = %q; want %q", got.ID, pb.ID)
	}
}

func TestInMemoryPlaybookStore_CreateDuplicate(t *testing.T) {
	store := NewInMemoryPlaybookStore()

	pb := FedRAMPIR4Playbook()
	store.CreatePlaybook(context.Background(), pb)

	if err := store.CreatePlaybook(context.Background(), pb); err == nil {
		t.Error("CreatePlaybook with duplicate ID should return an error")
	}
}

func TestInMemoryPlaybookStore_GetNotFound(t *testing.T) {
	store := NewInMemoryPlaybookStore()
	got, err := store.GetPlaybook(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("GetPlaybook: %v", err)
	}
	if got != nil {
		t.Error("GetPlaybook on nonexistent ID should return nil")
	}
}

func TestInMemoryPlaybookStore_ListBySeverity(t *testing.T) {
	store := NewInMemoryPlaybookStore()

	pb1 := FedRAMPIR4Playbook() // SeverityHigh
	pb2 := FedRAMPIR5Playbook() // SeverityMedium
	pb3 := SOC2CC61Playbook()   // SeverityHigh

	store.CreatePlaybook(context.Background(), pb1)
	store.CreatePlaybook(context.Background(), pb2)
	store.CreatePlaybook(context.Background(), pb3)

	results, err := store.ListPlaybooks(context.Background(), SeverityHigh, "")
	if err != nil {
		t.Fatalf("ListPlaybooks: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d; want 2", len(results))
	}
}

func TestInMemoryPlaybookStore_ListAll(t *testing.T) {
	store := NewInMemoryPlaybookStore()

	for _, pb := range DefaultPlaybooks() {
		store.CreatePlaybook(context.Background(), pb)
	}

	// Empty severity and source means list all.
	results, err := store.ListPlaybooks(context.Background(), "", "")
	if err != nil {
		t.Fatalf("ListPlaybooks: %v", err)
	}
	if len(results) != 14 {
		t.Errorf("len(results) = %d; want 14", len(results))
	}
}

func TestInMemoryPlaybookStore_Update(t *testing.T) {
	store := NewInMemoryPlaybookStore()

	pb := FedRAMPIR4Playbook()
	store.CreatePlaybook(context.Background(), pb)

	pb.Name = "Updated Name"
	if err := store.UpdatePlaybook(context.Background(), pb); err != nil {
		t.Fatalf("UpdatePlaybook: %v", err)
	}

	got, _ := store.GetPlaybook(context.Background(), pb.ID)
	if got.Name != "Updated Name" {
		t.Errorf("Name = %q; want %q", got.Name, "Updated Name")
	}
}

func TestInMemoryPlaybookStore_Delete(t *testing.T) {
	store := NewInMemoryPlaybookStore()

	pb := FedRAMPIR4Playbook()
	store.CreatePlaybook(context.Background(), pb)

	if err := store.DeletePlaybook(context.Background(), pb.ID); err != nil {
		t.Fatalf("DeletePlaybook: %v", err)
	}

	got, _ := store.GetPlaybook(context.Background(), pb.ID)
	if got != nil {
		t.Error("GetPlaybook after delete should return nil")
	}
}

func TestInMemoryPlaybookStore_DeleteNotFound(t *testing.T) {
	store := NewInMemoryPlaybookStore()
	if err := store.DeletePlaybook(context.Background(), "nonexistent"); err == nil {
		t.Error("DeletePlaybook on nonexistent ID should return an error")
	}
}

func TestInMemoryPlaybookStore_Close(t *testing.T) {
	store := NewInMemoryPlaybookStore()
	if err := store.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

// =====================================================================
// InMemoryDetectionRuleStore tests
// =====================================================================

func TestInMemoryDetectionRuleStore_CreateAndGet(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()

	rule := MCPErrorInjectionRule()
	if err := store.CreateRule(context.Background(), rule); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	got, err := store.GetRule(context.Background(), rule.ID)
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if got == nil {
		t.Fatal("GetRule returned nil")
	}
	if got.ID != rule.ID {
		t.Errorf("ID = %q; want %q", got.ID, rule.ID)
	}
	if got.Name != rule.Name {
		t.Errorf("Name = %q; want %q", got.Name, rule.Name)
	}
}

func TestInMemoryDetectionRuleStore_CreateDuplicate(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()

	rule := MCPErrorInjectionRule()
	store.CreateRule(context.Background(), rule)

	if err := store.CreateRule(context.Background(), rule); err == nil {
		t.Error("CreateRule with duplicate ID should return an error")
	}
}

func TestInMemoryDetectionRuleStore_GetNotFound(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()
	got, err := store.GetRule(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if got != nil {
		t.Error("GetRule on nonexistent ID should return nil")
	}
}

func TestInMemoryDetectionRuleStore_ListAll(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()

	for _, rule := range DefaultDetectionRules() {
		store.CreateRule(context.Background(), rule)
	}

	results, err := store.ListRules(context.Background(), false)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(results) != 5 {
		t.Errorf("len(results) = %d; want 5", len(results))
	}
}

func TestInMemoryDetectionRuleStore_ListEnabledOnly(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()

	for _, rule := range DefaultDetectionRules() {
		store.CreateRule(context.Background(), rule)
	}

	// All default rules are enabled.
	results, err := store.ListRules(context.Background(), true)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(results) != 5 {
		t.Errorf("len(enabled results) = %d; want 5", len(results))
	}

	// Disable one rule and check.
	disabledRule := MCPErrorInjectionRule()
	disabledRule.Enabled = false
	store.UpdateRule(context.Background(), disabledRule)

	results, err = store.ListRules(context.Background(), true)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(results) != 4 {
		t.Errorf("len(enabled results after disable) = %d; want 4", len(results))
	}
}

func TestInMemoryDetectionRuleStore_Update(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()

	rule := MCPErrorInjectionRule()
	store.CreateRule(context.Background(), rule)

	rule.Name = "Updated Rule Name"
	if err := store.UpdateRule(context.Background(), rule); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	got, _ := store.GetRule(context.Background(), rule.ID)
	if got.Name != "Updated Rule Name" {
		t.Errorf("Name = %q; want %q", got.Name, "Updated Rule Name")
	}
}

func TestInMemoryDetectionRuleStore_UpdateNotFound(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()
	rule := &DetectionRule{ID: "nonexistent", Name: "Ghost"}
	if err := store.UpdateRule(context.Background(), rule); err == nil {
		t.Error("UpdateRule on nonexistent ID should return an error")
	}
}

func TestInMemoryDetectionRuleStore_Delete(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()

	rule := MCPErrorInjectionRule()
	store.CreateRule(context.Background(), rule)

	if err := store.DeleteRule(context.Background(), rule.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}

	got, _ := store.GetRule(context.Background(), rule.ID)
	if got != nil {
		t.Error("GetRule after delete should return nil")
	}
}

func TestInMemoryDetectionRuleStore_DeleteNotFound(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()
	if err := store.DeleteRule(context.Background(), "nonexistent"); err == nil {
		t.Error("DeleteRule on nonexistent ID should return an error")
	}
}

func TestInMemoryDetectionRuleStore_Close(t *testing.T) {
	store := NewInMemoryDetectionRuleStore()
	if err := store.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

// =====================================================================
// InMemoryEscalationPolicyStore tests
// =====================================================================

func TestInMemoryEscalationPolicyStore_CreateAndGet(t *testing.T) {
	store := NewInMemoryEscalationPolicyStore()

	policy := &EscalationPolicy{
		ID:                "policy_test",
		Name:              "Test Policy",
		SeverityThreshold: SeverityHigh,
		Recipients:        []string{"security@example.com"},
		RepeatInterval:    5 * time.Minute,
		MaxEscalations:    3,
	}

	if err := store.Create(policy); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get("policy_test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.ID != "policy_test" {
		t.Errorf("ID = %q; want %q", got.ID, "policy_test")
	}
}

func TestInMemoryEscalationPolicyStore_CreateDuplicate(t *testing.T) {
	store := NewInMemoryEscalationPolicyStore()

	policy := &EscalationPolicy{ID: "policy_dup", Name: "Dup"}
	store.Create(policy)

	if err := store.Create(policy); err == nil {
		t.Error("Create with duplicate ID should return an error")
	}
}

func TestInMemoryEscalationPolicyStore_GetNotFound(t *testing.T) {
	store := NewInMemoryEscalationPolicyStore()
	got, err := store.Get("nonexistent")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Error("Get on nonexistent ID should return nil")
	}
}

func TestInMemoryEscalationPolicyStore_List(t *testing.T) {
	store := NewInMemoryEscalationPolicyStore()

	policy1 := &EscalationPolicy{ID: "p1", Name: "Alpha"}
	policy2 := &EscalationPolicy{ID: "p2", Name: "Beta"}

	store.Create(policy1)
	store.Create(policy2)

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len(list) = %d; want 2", len(list))
	}
}

// =====================================================================
// Concurrent access tests
// =====================================================================

func TestInMemoryIncidentStore_Concurrent(t *testing.T) {
	store := NewInMemoryIncidentStore()

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(n int) {
			inc := NewIncident("Concurrent", "Test", SeverityLow, SourceSOC)
			inc.AgentID = "agent-concurrent"
			store.CreateIncident(context.Background(), inc)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	results, err := store.ListIncidents(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 10 {
		t.Errorf("len(results) = %d; want 10", len(results))
	}
}

func TestInMemoryPlaybookStore_Concurrent(t *testing.T) {
	store := NewInMemoryPlaybookStore()

	done := make(chan bool, 4)

	expectedCount := len(DefaultPlaybooks())

	for _, pb := range DefaultPlaybooks() {
		go func(playbook *Playbook) {
			store.CreatePlaybook(context.Background(), playbook)
			done <- true
		}(pb)
	}

	for i := 0; i < expectedCount; i++ {
		<-done
	}

	results, err := store.ListPlaybooks(context.Background(), "", "")
	if err != nil {
		t.Fatalf("ListPlaybooks: %v", err)
	}
	if len(results) != expectedCount {
		t.Errorf("len(results) = %d; want %d", len(results), expectedCount)
	}
}
