// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Incident Response Engine Tests
// =========================================================================

package incident

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
)

// =====================================================================
// Engine creation tests
// =====================================================================

func TestNewEngine(t *testing.T) {
	is := NewInMemoryIncidentStore()
	ps := NewInMemoryPlaybookStore()
	rs := NewInMemoryDetectionRuleStore()

	engine := NewEngine(is, ps, rs)
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if engine.incidentStore == nil {
		t.Error("incidentStore is nil")
	}
	if engine.playbookStore == nil {
		t.Error("playbookStore is nil")
	}
	if engine.ruleStore == nil {
		t.Error("ruleStore is nil")
	}
	if engine.escalationStore == nil {
		t.Error("escalationStore is nil")
	}
}

// =====================================================================
// ProcessEvent tests
// =====================================================================

func TestProcessEvent_MatchingRule(t *testing.T) {
	is := NewInMemoryIncidentStore()
	ps := NewInMemoryPlaybookStore()
	rs := NewInMemoryDetectionRuleStore()

	// Add a detection rule that matches MCP error injection.
	rule := &DetectionRule{
		ID:          "rule_test",
		Name:        "Test Rule",
		Description: "Test detection rule",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityHigh,
		Patterns:    []string{"mcp_error_injection"},
		AutoCreate:  true,
		AutoExecute: false,
		ComplianceMappings: []ComplianceMapping{
			{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling"},
		},
	}
	if err := rs.CreateRule(context.Background(), rule); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	engine := NewEngine(is, ps, rs)

	event := &correlation.Event{
		ID:        "evt_test_1",
		Protocol:  "mcp",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "error",
		Severity:  "high",
		Decision:  "block",
		Timestamp: time.Now().UTC(),
		Metadata:  map[string]string{"matched_patterns": "mcp_error_injection"},
	}

	incident, err := engine.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if incident == nil {
		t.Fatal("ProcessEvent returned nil incident; expected a match")
	}
	if incident.Source != SourceAutoRule {
		t.Errorf("incident.Source = %q; want %q", incident.Source, SourceAutoRule)
	}
	if incident.Severity != SeverityHigh {
		t.Errorf("incident.Severity = %q; want %q", incident.Severity, SeverityHigh)
	}
	if incident.SessionID != "session-1" {
		t.Errorf("incident.SessionID = %q; want %q", incident.SessionID, "session-1")
	}
	if incident.AgentID != "agent-1" {
		t.Errorf("incident.AgentID = %q; want %q", incident.AgentID, "agent-1")
	}
	if len(incident.ComplianceMappings) == 0 {
		t.Error("incident.ComplianceMappings is empty; expected at least 1 mapping")
	}
}

func TestProcessEvent_NoMatchingRule(t *testing.T) {
	is := NewInMemoryIncidentStore()
	ps := NewInMemoryPlaybookStore()
	rs := NewInMemoryDetectionRuleStore()

	// Add a rule that only matches "task_hijacking" pattern.
	rule := &DetectionRule{
		ID:          "rule_no_match",
		Name:        "Task Hijacking Only",
		Description: "Only matches task_hijacking",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityCritical,
		Patterns:    []string{"task_hijacking"},
		AutoCreate:  true,
	}
	if err := rs.CreateRule(context.Background(), rule); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	engine := NewEngine(is, ps, rs)

	// Send an event that does NOT match "task_hijacking".
	event := &correlation.Event{
		ID:        "evt_no_match",
		Protocol:  "http",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "request",
		Severity:  "low",
		Timestamp: time.Now().UTC(),
		Metadata:  map[string]string{"matched_patterns": "mcp_error_injection"},
	}

	incident, err := engine.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if incident != nil {
		t.Errorf("ProcessEvent returned incident; expected nil for no matching rule")
	}
}

func TestProcessEvent_DisabledRule(t *testing.T) {
	is := NewInMemoryIncidentStore()
	ps := NewInMemoryPlaybookStore()
	rs := NewInMemoryDetectionRuleStore()

	rule := &DetectionRule{
		ID:          "rule_disabled",
		Name:        "Disabled Rule",
		Description: "This rule is disabled",
		Enabled:     false,
		Source:      SourceCorrelation,
		Severity:    SeverityHigh,
		Patterns:    []string{"mcp_error_injection"},
		AutoCreate:  true,
	}
	if err := rs.CreateRule(context.Background(), rule); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	engine := NewEngine(is, ps, rs)

	event := &correlation.Event{
		ID:        "evt_disabled",
		Protocol:  "mcp",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "error",
		Severity:  "high",
		Timestamp: time.Now().UTC(),
		Metadata:  map[string]string{"matched_patterns": "mcp_error_injection"},
	}

	incident, err := engine.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if incident != nil {
		t.Errorf("ProcessEvent returned incident for disabled rule; expected nil")
	}
}

func TestProcessEvent_AutoCreateFalse(t *testing.T) {
	is := NewInMemoryIncidentStore()
	ps := NewInMemoryPlaybookStore()
	rs := NewInMemoryDetectionRuleStore()

	rule := &DetectionRule{
		ID:          "rule_no_create",
		Name:        "No Auto-Create Rule",
		Description: "Rule that matches but does not auto-create",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityHigh,
		Patterns:    []string{"mcp_error_injection"},
		AutoCreate:  false,
	}
	if err := rs.CreateRule(context.Background(), rule); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	engine := NewEngine(is, ps, rs)

	event := &correlation.Event{
		ID:        "evt_no_create",
		Protocol:  "mcp",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "error",
		Severity:  "high",
		Timestamp: time.Now().UTC(),
		Metadata:  map[string]string{"matched_patterns": "mcp_error_injection"},
	}

	incident, err := engine.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if incident != nil {
		t.Errorf("ProcessEvent returned incident when AutoCreate=false; expected nil")
	}
}

func TestProcessEvent_AutoExecute(t *testing.T) {
	is := NewInMemoryIncidentStore()
	ps := NewInMemoryPlaybookStore()
	rs := NewInMemoryDetectionRuleStore()

	// Add a playbook.
	playbook := &Playbook{
		ID:          "pb_test",
		Name:        "Test Playbook",
		Description: "Test playbook",
		Severity:    SeverityHigh,
		Steps: []*PlaybookStep{
			{ID: "step1", Name: "Notify", Action: "notify", OnFailure: "continue"},
		},
		AutoExecute: true,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := ps.CreatePlaybook(context.Background(), playbook); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	rule := &DetectionRule{
		ID:          "rule_auto_exec",
		Name:        "Auto-Execute Rule",
		Description: "Rule that auto-executes playbook",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityCritical,
		Patterns:    []string{"task_hijacking"},
		PlaybookID:  "pb_test",
		AutoCreate:  true,
		AutoExecute: true,
	}
	if err := rs.CreateRule(context.Background(), rule); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	engine := NewEngine(is, ps, rs)

	notifyCalled := false
	engine.SetCallbacks(ActionCallbacks{
		OnNotify: func(_ context.Context, _ *Incident, _ []string) error {
			notifyCalled = true
			return nil
		},
	})

	event := &correlation.Event{
		ID:        "evt_auto_exec",
		Protocol:  "a2a",
		AgentID:   "agent-1",
		SessionID: "session-1",
		EventType: "message",
		Severity:  "critical",
		Timestamp: time.Now().UTC(),
		Metadata:  map[string]string{"matched_patterns": "task_hijacking"},
	}

	incident, err := engine.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if incident == nil {
		t.Fatal("ProcessEvent returned nil; expected an incident")
	}
	if !notifyCalled {
		t.Error("Auto-execute playbook did not call OnNotify callback")
	}

	// Verify the incident has a playbook run attached.
	updated, _ := is.GetIncident(context.Background(), incident.ID)
	if len(updated.PlaybookRuns) == 0 {
		t.Error("Incident has no playbook runs after auto-execute")
	}
}

func TestProcessEvent_NilEvent(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	_, err := engine.ProcessEvent(context.Background(), nil)
	if err == nil {
		t.Error("ProcessEvent(nil) should return an error")
	}
}

func TestProcessEvent_CancelledContext(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	event := &correlation.Event{ID: "evt_cancel", Protocol: "mcp", AgentID: "a", SessionID: "s"}
	_, err := engine.ProcessEvent(ctx, event)
	if err == nil {
		t.Error("ProcessEvent with cancelled context should return an error")
	}
}

// =====================================================================
// CreateIncident tests
// =====================================================================

func TestCreateIncident(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	incident := NewIncident("Test incident", "A test description", SeverityHigh, SourceSOC)
	incident.AgentID = "agent-1"
	incident.SessionID = "session-1"

	created, err := engine.CreateIncident(context.Background(), incident)
	if err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	if created.ID == "" {
		t.Error("CreateIncident: ID should be set")
	}
	if created.Status != StatusNew {
		t.Errorf("CreateIncident: status = %q; want %q", created.Status, StatusNew)
	}
	if created.Source != SourceSOC {
		t.Errorf("CreateIncident: source = %q; want %q", created.Source, SourceSOC)
	}
	if created.CreatedAt.IsZero() {
		t.Error("CreateIncident: CreatedAt should be set")
	}
}

func TestCreateIncident_Nil(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	_, err := engine.CreateIncident(context.Background(), nil)
	if err == nil {
		t.Error("CreateIncident(nil) should return an error")
	}
}

func TestCreateIncident_Defaults(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	// Create incident with minimal fields — defaults should fill in.
	incident := &Incident{Title: "Minimal"}
	created, err := engine.CreateIncident(context.Background(), incident)
	if err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	if created.ID == "" {
		t.Error("ID should be auto-generated")
	}
	if created.Status != StatusNew {
		t.Errorf("Status = %q; want %q", created.Status, StatusNew)
	}
	if created.Source != SourceSOC {
		t.Errorf("Source = %q; want %q", created.Source, SourceSOC)
	}
	if created.CorrelationEventIDs == nil {
		t.Error("CorrelationEventIDs should be initialized")
	}
	if created.Metadata == nil {
		t.Error("Metadata should be initialized")
	}
}

// =====================================================================
// TriageIncident tests
// =====================================================================

func TestTriageIncident(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	incident := NewIncident("Triage test", "Test", SeverityLow, SourceSOC)
	created, _ := engine.CreateIncident(context.Background(), incident)

	triaged, err := engine.TriageIncident(context.Background(), created.ID, SeverityHigh, "analyst-1")
	if err != nil {
		t.Fatalf("TriageIncident: %v", err)
	}
	if triaged.Status != StatusTriaged {
		t.Errorf("Status = %q; want %q", triaged.Status, StatusTriaged)
	}
	if triaged.Severity != SeverityHigh {
		t.Errorf("Severity = %q; want %q", triaged.Severity, SeverityHigh)
	}
	if triaged.Assignee != "analyst-1" {
		t.Errorf("Assignee = %q; want %q", triaged.Assignee, "analyst-1")
	}
}

func TestTriageIncident_WrongStatus(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	incident := NewIncident("Already triaged", "Test", SeverityLow, SourceSOC)
	created, _ := engine.CreateIncident(context.Background(), incident)
	_, _ = engine.TriageIncident(context.Background(), created.ID, SeverityHigh, "analyst-1")

	// Try to triage again — should fail.
	_, err := engine.TriageIncident(context.Background(), created.ID, SeverityCritical, "analyst-2")
	if err == nil {
		t.Error("TriageIncident on already-triaged incident should return an error")
	}
}

func TestTriageIncident_NotFound(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	_, err := engine.TriageIncident(context.Background(), "nonexistent", SeverityHigh, "analyst")
	if err == nil {
		t.Error("TriageIncident on nonexistent ID should return an error")
	}
}

func TestTriageIncident_EmptyID(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	_, err := engine.TriageIncident(context.Background(), "", SeverityHigh, "analyst")
	if err == nil {
		t.Error("TriageIncident with empty ID should return an error")
	}
}

// =====================================================================
// ExecutePlaybook tests
// =====================================================================

func TestExecutePlaybook(t *testing.T) {
	is := NewInMemoryIncidentStore()
	ps := NewInMemoryPlaybookStore()
	engine := NewEngine(is, ps, NewInMemoryDetectionRuleStore())

	playbook := &Playbook{
		ID:          "pb_exec_test",
		Name:        "Exec Test",
		Description: "Test playbook",
		Severity:    SeverityHigh,
		Steps: []*PlaybookStep{
			{ID: "s1", Name: "Notify", Action: "notify", OnFailure: "continue"},
			{ID: "s2", Name: "Collect Evidence", Action: "collect_evidence", OnFailure: "continue"},
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := ps.CreatePlaybook(context.Background(), playbook); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	incident := NewIncident("Exec playbook test", "Test", SeverityHigh, SourceSOC)
	created, _ := engine.CreateIncident(context.Background(), incident)

	var notifyCalled, evidenceCalled bool
	engine.SetCallbacks(ActionCallbacks{
		OnNotify: func(_ context.Context, _ *Incident, _ []string) error {
			notifyCalled = true
			return nil
		},
		OnCollectEvidence: func(_ context.Context, _ *Incident) error {
			evidenceCalled = true
			return nil
		},
	})

	run, err := engine.ExecutePlaybook(context.Background(), created.ID, "pb_exec_test")
	if err != nil {
		t.Fatalf("ExecutePlaybook: %v", err)
	}
	if run.Status != "completed" {
		t.Errorf("run.Status = %q; want %q", run.Status, "completed")
	}
	if len(run.StepResults) != 2 {
		t.Errorf("len(StepResults) = %d; want 2", len(run.StepResults))
	}
	if !notifyCalled {
		t.Error("OnNotify was not called")
	}
	if !evidenceCalled {
		t.Error("OnCollectEvidence was not called")
	}

	// Verify incident status changed to investigating.
	updated, _ := is.GetIncident(context.Background(), created.ID)
	if updated.Status != StatusInvestigating {
		t.Errorf("incident status = %q; want %q", updated.Status, StatusInvestigating)
	}
}

func TestExecutePlaybook_StepFailure_Stop(t *testing.T) {
	is := NewInMemoryIncidentStore()
	ps := NewInMemoryPlaybookStore()
	engine := NewEngine(is, ps, NewInMemoryDetectionRuleStore())

	playbook := &Playbook{
		ID:          "pb_fail_stop",
		Name:        "Fail Stop Test",
		Description: "Test",
		Severity:    SeverityHigh,
		Steps: []*PlaybookStep{
			{ID: "s1", Name: "Notify", Action: "notify", OnFailure: "continue"},
			{ID: "s2", Name: "Block Agent", Action: "block_agent", OnFailure: "stop"},
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := ps.CreatePlaybook(context.Background(), playbook); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	incident := NewIncident("Fail stop test", "Test", SeverityHigh, SourceSOC)
	created, _ := engine.CreateIncident(context.Background(), incident)

	engine.SetCallbacks(ActionCallbacks{
		OnNotify:     func(_ context.Context, _ *Incident, _ []string) error { return nil },
		OnBlockAgent: func(_ context.Context, _, _ string) error { return errTestBlockAgent },
	})

	run, err := engine.ExecutePlaybook(context.Background(), created.ID, "pb_fail_stop")
	if err != nil {
		t.Fatalf("ExecutePlaybook: %v", err)
	}
	if run.Status != "failed" {
		t.Errorf("run.Status = %q; want %q", run.Status, "failed")
	}
	if !strings.Contains(run.Error, "failed") {
		t.Errorf("run.Error = %q; should contain 'failed'", run.Error)
	}
}

var errTestBlockAgent = fmt.Errorf("test: block agent failed")

func TestExecutePlaybook_StepFailure_Continue(t *testing.T) {
	is := NewInMemoryIncidentStore()
	ps := NewInMemoryPlaybookStore()
	engine := NewEngine(is, ps, NewInMemoryDetectionRuleStore())

	playbook := &Playbook{
		ID:          "pb_fail_continue",
		Name:        "Fail Continue Test",
		Description: "Test",
		Severity:    SeverityHigh,
		Steps: []*PlaybookStep{
			{ID: "s1", Name: "Notify", Action: "notify", OnFailure: "continue"},
			{ID: "s2", Name: "Collect Evidence", Action: "collect_evidence", OnFailure: "continue"},
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := ps.CreatePlaybook(context.Background(), playbook); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	incident := NewIncident("Fail continue test", "Test", SeverityHigh, SourceSOC)
	created, _ := engine.CreateIncident(context.Background(), incident)

	engine.SetCallbacks(ActionCallbacks{
		OnNotify:          func(_ context.Context, _ *Incident, _ []string) error { return nil },
		OnCollectEvidence: func(_ context.Context, _ *Incident) error { return errTestCollect },
	})

	run, err := engine.ExecutePlaybook(context.Background(), created.ID, "pb_fail_continue")
	if err != nil {
		t.Fatalf("ExecutePlaybook: %v", err)
	}
	if run.Status != "partial" {
		t.Errorf("run.Status = %q; want %q", run.Status, "partial")
	}
}

var errTestCollect = fmt.Errorf("test: evidence collection failed")

func TestExecutePlaybook_NotFound(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	_, err := engine.ExecutePlaybook(context.Background(), "nonexistent-incident", "nonexistent-playbook")
	if err == nil {
		t.Error("ExecutePlaybook with nonexistent IDs should return an error")
	}
}

func TestExecutePlaybook_EmptyIDs(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	_, err := engine.ExecutePlaybook(context.Background(), "", "pb")
	if err == nil {
		t.Error("ExecutePlaybook with empty incident ID should return an error")
	}
	_, err = engine.ExecutePlaybook(context.Background(), "inc", "")
	if err == nil {
		t.Error("ExecutePlaybook with empty playbook ID should return an error")
	}
}

// =====================================================================
// EscalateIncident tests
// =====================================================================

func TestEscalateIncident(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	policy := &EscalationPolicy{
		ID:                "policy_1",
		Name:              "Test Policy",
		SeverityThreshold: SeverityHigh,
		Recipients:        []string{"security@example.com"},
		RepeatInterval:    5 * time.Minute,
		MaxEscalations:    3,
	}
	_ = engine.AddEscalationPolicy(policy)

	incident := NewIncident("Escalation test", "Test", SeverityHigh, SourceSOC)
	created, _ := engine.CreateIncident(context.Background(), incident)

	var notified bool
	engine.SetCallbacks(ActionCallbacks{
		OnNotify: func(_ context.Context, _ *Incident, _ []string) error {
			notified = true
			return nil
		},
	})

	err := engine.EscalateIncident(context.Background(), created.ID, "policy_1")
	if err != nil {
		t.Fatalf("EscalateIncident: %v", err)
	}
	if !notified {
		t.Error("OnNotify was not called during escalation")
	}

	updated, _ := engine.GetIncident(context.Background(), created.ID)
	if updated.Status != StatusInvestigating {
		t.Errorf("Status = %q; want %q", updated.Status, StatusInvestigating)
	}
	if updated.EscalatedAt.IsZero() {
		t.Error("EscalatedAt should be set")
	}
}

func TestEscalateIncident_EmptyID(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	err := engine.EscalateIncident(context.Background(), "", "")
	if err == nil {
		t.Error("EscalateIncident with empty ID should return an error")
	}
}

func TestEscalateIncident_NotFound(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	err := engine.EscalateIncident(context.Background(), "nonexistent", "")
	if err == nil {
		t.Error("EscalateIncident on nonexistent ID should return an error")
	}
}

// =====================================================================
// ResolveIncident tests
// =====================================================================

func TestResolveIncident(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	incident := NewIncident("Resolve test", "Test", SeverityMedium, SourceSOC)
	created, _ := engine.CreateIncident(context.Background(), incident)

	resolved, err := engine.ResolveIncident(context.Background(), created.ID, "False alarm")
	if err != nil {
		t.Fatalf("ResolveIncident: %v", err)
	}
	if resolved.Status != StatusResolved {
		t.Errorf("Status = %q; want %q", resolved.Status, StatusResolved)
	}
	if resolved.ResolvedAt.IsZero() {
		t.Error("ResolvedAt should be set")
	}
	if resolved.Metadata["resolution"] != "False alarm" {
		t.Errorf("Metadata[resolution] = %q; want %q", resolved.Metadata["resolution"], "False alarm")
	}
}

func TestResolveIncident_NotFound(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	_, err := engine.ResolveIncident(context.Background(), "nonexistent", "test")
	if err == nil {
		t.Error("ResolveIncident on nonexistent ID should return an error")
	}
}

// =====================================================================
// ListIncidents tests
// =====================================================================

func TestListIncidents_FilterByStatus(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	inc1 := NewIncident("New incident", "Test", SeverityLow, SourceSOC)
	inc2 := NewIncident("Another new", "Test", SeverityMedium, SourceSOC)
	engine.CreateIncident(context.Background(), inc1)
	engine.CreateIncident(context.Background(), inc2)

	results, err := engine.ListIncidents(context.Background(), &IncidentQuery{
		Status: []IncidentStatus{StatusNew},
	})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d; want 2", len(results))
	}
}

func TestListIncidents_FilterBySeverity(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	inc1 := NewIncident("High severity", "Test", SeverityHigh, SourceSOC)
	inc2 := NewIncident("Low severity", "Test", SeverityLow, SourceSOC)
	engine.CreateIncident(context.Background(), inc1)
	engine.CreateIncident(context.Background(), inc2)

	results, err := engine.ListIncidents(context.Background(), &IncidentQuery{
		Severity: []IncidentSeverity{SeverityHigh},
	})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("len(results) = %d; want 1", len(results))
	}
}

func TestListIncidents_FilterByAgentID(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	inc1 := NewIncident("Agent 1 incident", "Test", SeverityHigh, SourceSOC)
	inc1.AgentID = "agent-1"
	inc2 := NewIncident("Agent 2 incident", "Test", SeverityMedium, SourceSOC)
	inc2.AgentID = "agent-2"
	engine.CreateIncident(context.Background(), inc1)
	engine.CreateIncident(context.Background(), inc2)

	results, err := engine.ListIncidents(context.Background(), &IncidentQuery{
		AgentID: "agent-1",
	})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("len(results) = %d; want 1", len(results))
	}
}

// =====================================================================
// DefaultPlaybooks / DefaultDetectionRules tests
// =====================================================================

func TestDefaultPlaybooks(t *testing.T) {
	playbooks := DefaultPlaybooks()
	if len(playbooks) != 4 {
		t.Fatalf("len(DefaultPlaybooks()) = %d; want 4", len(playbooks))
	}

	ids := make(map[string]bool)
	for _, pb := range playbooks {
		if pb.ID == "" {
			t.Error("Playbook has empty ID")
		}
		if pb.Name == "" {
			t.Error("Playbook has empty Name")
		}
		if len(pb.Steps) == 0 {
			t.Errorf("Playbook %s has no steps", pb.ID)
		}
		ids[pb.ID] = true
	}

	// Verify all expected playbooks are present.
	for _, id := range []string{"pb_fedramp_ir4", "pb_fedramp_ir5", "pb_soc2_cc61", "pb_nist800171_ir1"} {
		if !ids[id] {
			t.Errorf("Missing playbook: %s", id)
		}
	}
}

func TestDefaultDetectionRules(t *testing.T) {
	rules := DefaultDetectionRules()
	if len(rules) != 5 {
		t.Fatalf("len(DefaultDetectionRules()) = %d; want 5", len(rules))
	}

	ids := make(map[string]bool)
	for _, r := range rules {
		if r.ID == "" {
			t.Error("Rule has empty ID")
		}
		if r.Name == "" {
			t.Error("Rule has empty Name")
		}
		if r.Severity == "" {
			t.Error("Rule has empty Severity")
		}
		ids[r.ID] = true
	}

	for _, id := range []string{
		"rule_mcp_error_injection", "rule_task_hijacking",
		"rule_browser_escalation", "rule_rate_anomaly",
		"rule_capability_creep",
	} {
		if !ids[id] {
			t.Errorf("Missing rule: %s", id)
		}
	}
}

// =====================================================================
// Compliance mapping tests
// =====================================================================

func TestMapToCompliance_KnownPattern(t *testing.T) {
	mappings := MapToCompliance(SourceCorrelation, []string{"mcp_error_injection"})
	if len(mappings) == 0 {
		t.Fatal("MapToCompliance returned empty mappings for known pattern")
	}

	frameworks := make(map[string]bool)
	for _, m := range mappings {
		frameworks[m.Framework] = true
	}
	if !frameworks["FedRAMP"] {
		t.Error("Expected FedRAMP mapping for mcp_error_injection")
	}
	if !frameworks["SOC2"] {
		t.Error("Expected SOC2 mapping for mcp_error_injection")
	}
}

func TestMapToCompliance_UnknownPattern(t *testing.T) {
	mappings := MapToCompliance(SourceCorrelation, []string{"unknown_pattern_xyz"})
	if len(mappings) == 0 {
		t.Fatal("MapToCompliance returned empty mappings; expected default mapping")
	}
	// Should get a default mapping based on source.
	if mappings[0].Framework != "FedRAMP" {
		t.Errorf("Default mapping framework = %q; want FedRAMP", mappings[0].Framework)
	}
}

func TestMapToCompliance_EmptyPatterns(t *testing.T) {
	mappings := MapToCompliance(SourceSOC, nil)
	if len(mappings) == 0 {
		t.Fatal("MapToCompliance returned empty mappings for SOC source")
	}
	if mappings[0].ControlID != "CC6.1" {
		t.Errorf("Default SOC mapping ControlID = %q; want CC6.1", mappings[0].ControlID)
	}
}

func TestMapToCompliance_NoDuplicates(t *testing.T) {
	// Supply the same pattern that maps to multiple frameworks.
	mappings := MapToCompliance(SourceCorrelation, []string{"mcp_error_injection", "mcp_error_injection"})
	// Should not duplicate mappings.
	seen := make(map[string]bool)
	for _, m := range mappings {
		key := m.Framework + ":" + m.ControlID
		if seen[key] {
			t.Errorf("Duplicate mapping: %s", key)
		}
		seen[key] = true
	}
}

// =====================================================================
// SeverityAtLeast tests
// =====================================================================

func TestSeverityAtLeast(t *testing.T) {
	tests := []struct {
		s, threshold IncidentSeverity
		want         bool
	}{
		{SeverityCritical, SeverityLow, true},
		{SeverityCritical, SeverityCritical, true},
		{SeverityHigh, SeverityMedium, true},
		{SeverityLow, SeverityHigh, false},
		{SeverityMedium, SeverityHigh, false},
		{SeverityLow, SeverityLow, true},
		{SeverityMedium, SeverityMedium, true},
	}
	for _, tt := range tests {
		got := SeverityAtLeast(tt.s, tt.threshold)
		if got != tt.want {
			t.Errorf("SeverityAtLeast(%q, %q) = %v; want %v", tt.s, tt.threshold, got, tt.want)
		}
	}
}

// =====================================================================
// NewIncident tests
// =====================================================================

func TestNewIncident(t *testing.T) {
	inc := NewIncident("Test Title", "Test Description", SeverityHigh, SourceAPI)
	if inc.ID == "" {
		t.Error("NewIncident: ID should be auto-generated")
	}
	if inc.Status != StatusNew {
		t.Errorf("NewIncident: Status = %q; want %q", inc.Status, StatusNew)
	}
	if inc.Severity != SeverityHigh {
		t.Errorf("NewIncident: Severity = %q; want %q", inc.Severity, SeverityHigh)
	}
	if inc.Source != SourceAPI {
		t.Errorf("NewIncident: Source = %q; want %q", inc.Source, SourceAPI)
	}
	if inc.CreatedAt.IsZero() {
		t.Error("NewIncident: CreatedAt should be set")
	}
	if inc.CorrelationEventIDs == nil {
		t.Error("NewIncident: CorrelationEventIDs should be initialized")
	}
	if inc.Metadata == nil {
		t.Error("NewIncident: Metadata should be initialized")
	}
}

// =====================================================================
// GetIncident tests
// =====================================================================

func TestGetIncident(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)

	incident := NewIncident("Get test", "Test", SeverityMedium, SourceSOC)
	created, _ := engine.CreateIncident(context.Background(), incident)

	found, err := engine.GetIncident(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if found == nil {
		t.Fatal("GetIncident returned nil")
	}
	if found.ID != created.ID {
		t.Errorf("ID = %q; want %q", found.ID, created.ID)
	}
}

func TestGetIncident_NotFound(t *testing.T) {
	engine := NewEngine(
		NewInMemoryIncidentStore(),
		NewInMemoryPlaybookStore(),
		NewInMemoryDetectionRuleStore(),
	)
	found, err := engine.GetIncident(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if found != nil {
		t.Error("GetIncident on nonexistent ID should return nil")
	}
}
