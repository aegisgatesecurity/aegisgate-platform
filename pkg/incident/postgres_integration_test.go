// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Incident Response PostgreSQL Store Integration Tests
// =========================================================================
//
// Integration tests that verify PostgresIncidentStore, PostgresPlaybookStore,
// and PostgresDetectionRuleStore persist data correctly against a real
// PostgreSQL database spun up via testcontainers.
//
// Run:
//
//	go test -v -tags=integration ./pkg/incident/
//
// Requires Docker for testcontainers.
// =========================================================================

//go:build integration

package incident

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/testdb"
)

// =====================================================================
// Helpers
// =====================================================================

// setupIncidentStore creates a PostgresIncidentStore backed by an ephemeral
// testcontainers PostgreSQL instance. Returns the store and a cleanup
// function that must be deferred by the caller.
func setupIncidentStore(t *testing.T) (*PostgresIncidentStore, func()) {
	t.Helper()
	pgStore, cleanup := testdb.SetupTestDB(t)
	store := NewPostgresIncidentStore(pgStore.Pool())
	return store, cleanup
}

// setupPlaybookStore creates a PostgresPlaybookStore backed by an ephemeral
// testcontainers PostgreSQL instance.
func setupPlaybookStore(t *testing.T) (*PostgresPlaybookStore, func()) {
	t.Helper()
	pgStore, cleanup := testdb.SetupTestDB(t)
	store := NewPostgresPlaybookStore(pgStore.Pool())
	return store, cleanup
}

// setupDetectionRuleStore creates a PostgresDetectionRuleStore backed by an
// ephemeral testcontainers PostgreSQL instance.
func setupDetectionRuleStore(t *testing.T) (*PostgresDetectionRuleStore, func()) {
	t.Helper()
	pgStore, cleanup := testdb.SetupTestDB(t)
	store := NewPostgresDetectionRuleStore(pgStore.Pool())
	return store, cleanup
}

// newTestIncident builds a realistic Incident with unique IDs.
func newTestIncident(suffix string) *Incident {
	inc := NewIncident(
		fmt.Sprintf("Test Incident %s", suffix),
		fmt.Sprintf("Description for %s", suffix),
		SeverityHigh,
		SourceSOC,
	)
	inc.AgentID = fmt.Sprintf("agent-%s", suffix)
	inc.SessionID = fmt.Sprintf("session-%s", suffix)
	inc.TenantID = fmt.Sprintf("tenant-%s", suffix)
	inc.Tags = []string{"integration", suffix}
	inc.Metadata = map[string]string{
		"environment": "test",
		"source":      "integration",
	}
	inc.CorrelationEventIDs = []string{fmt.Sprintf("evt-%s-1", suffix), fmt.Sprintf("evt-%s-2", suffix)}
	inc.ComplianceMappings = []ComplianceMapping{
		{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Logical Access", Relevance: "High"},
		{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling", Relevance: "Critical"},
	}
	return inc
}

// newTestPlaybook builds a realistic Playbook with unique IDs.
func newTestPlaybook(suffix string) *Playbook {
	return &Playbook{
		ID:          fmt.Sprintf("pb-%s", suffix),
		Name:        fmt.Sprintf("Test Playbook %s", suffix),
		Description: fmt.Sprintf("Playbook for integration testing (%s)", suffix),
		Severity:    SeverityHigh,
		Source:      SourceSOC,
		Tags:        []string{"integration", suffix},
		Steps: []*PlaybookStep{
			{ID: fmt.Sprintf("step-%s-1", suffix), Name: "Notify SOC", Action: "notify", Parameters: map[string]string{"channel": "slack"}, OnFailure: "continue", Timeout: 5 * time.Minute, Required: true},
			{ID: fmt.Sprintf("step-%s-2", suffix), Name: "Block Agent", Action: "block_agent", OnFailure: "stop", Timeout: 2 * time.Minute, Required: true},
		},
		AutoExecute: false,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
}

// newTestDetectionRule builds a realistic DetectionRule with unique IDs.
func newTestDetectionRule(suffix string) *DetectionRule {
	return &DetectionRule{
		ID:          fmt.Sprintf("rule-%s", suffix),
		Name:        fmt.Sprintf("Test Rule %s", suffix),
		Description: fmt.Sprintf("Detection rule for integration testing (%s)", suffix),
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityCritical,
		Patterns:    []string{fmt.Sprintf("pattern-%s-1", suffix)},
		EventTypes:  []string{"login_failure", "privilege_escalation"},
		MinEvents:   3,
		TimeWindow:  5 * time.Minute,
		PlaybookID:  fmt.Sprintf("pb-%s", suffix),
		AutoCreate:  true,
		AutoExecute: false,
		ComplianceMappings: []ComplianceMapping{
			{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Logical Access"},
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// =====================================================================
// PostgresIncidentStore — CRUD Tests
// =====================================================================

func TestIntegration_Incident_CreateAndGet(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	inc := newTestIncident("crud-1")
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	got, err := store.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if got == nil {
		t.Fatal("GetIncident returned nil — expected incident")
	}

	if got.ID != inc.ID {
		t.Errorf("ID = %q, want %q", got.ID, inc.ID)
	}
	if got.Title != inc.Title {
		t.Errorf("Title = %q, want %q", got.Title, inc.Title)
	}
	if got.Severity != inc.Severity {
		t.Errorf("Severity = %q, want %q", got.Severity, inc.Severity)
	}
	if got.Status != StatusNew {
		t.Errorf("Status = %q, want %q", got.Status, StatusNew)
	}
	if got.Source != inc.Source {
		t.Errorf("Source = %q, want %q", got.Source, inc.Source)
	}
	if got.AgentID != inc.AgentID {
		t.Errorf("AgentID = %q, want %q", got.AgentID, inc.AgentID)
	}
	if got.SessionID != inc.SessionID {
		t.Errorf("SessionID = %q, want %q", got.SessionID, inc.SessionID)
	}
	if got.TenantID != inc.TenantID {
		t.Errorf("TenantID = %q, want %q", got.TenantID, inc.TenantID)
	}
}

func TestIntegration_Incident_CreateWithCorrelationAndCompliance(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	inc := newTestIncident("corr-1")
	// CorrelationEventIDs and ComplianceMappings are stored in metadata JSONB
	// and extracted on read.
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	got, err := store.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if got == nil {
		t.Fatal("GetIncident returned nil")
	}

	if len(got.CorrelationEventIDs) != 2 {
		t.Errorf("CorrelationEventIDs length = %d, want 2", len(got.CorrelationEventIDs))
	}
	if len(got.ComplianceMappings) != 2 {
		t.Errorf("ComplianceMappings length = %d, want 2", len(got.ComplianceMappings))
	}
	if got.ComplianceMappings[0].Framework != "SOC2" {
		t.Errorf("ComplianceMappings[0].Framework = %q, want %q", got.ComplianceMappings[0].Framework, "SOC2")
	}
	if got.ComplianceMappings[1].Framework != "FedRAMP" {
		t.Errorf("ComplianceMappings[1].Framework = %q, want %q", got.ComplianceMappings[1].Framework, "FedRAMP")
	}

	// Verify metadata doesn't contain internal keys (they should be extracted)
	if _, ok := got.Metadata["_correlation_event_ids"]; ok {
		t.Error("Metadata should not contain _correlation_event_ids after extraction")
	}
	if _, ok := got.Metadata["_compliance_mappings"]; ok {
		t.Error("Metadata should not contain _compliance_mappings after extraction")
	}
}

func TestIntegration_Incident_CreateDuplicate(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	inc := newTestIncident("dup-1")
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident (first): %v", err)
	}

	// Create with same ID should fail.
	inc2 := &Incident{ID: inc.ID, Title: "Duplicate", Status: StatusNew}
	if err := store.CreateIncident(ctx, inc2); err == nil {
		t.Error("CreateIncident with duplicate ID should return an error")
	}
}

func TestIntegration_Incident_GetNotFound(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	got, err := store.GetIncident(ctx, "nonexistent-incident-id")
	if err != nil {
		t.Fatalf("GetIncident for nonexistent: %v", err)
	}
	if got != nil {
		t.Error("GetIncident should return nil for nonexistent incident")
	}
}

func TestIntegration_Incident_Update(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	inc := newTestIncident("update-1")
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	// Update fields
	inc.Status = StatusInvestigating
	inc.Severity = SeverityCritical
	inc.Assignee = "analyst@example.com"
	inc.Title = "Updated Title"
	inc.UpdatedAt = time.Now().UTC()
	inc.CorrelationEventIDs = []string{"evt-update-1", "evt-update-2", "evt-update-3"}
	inc.ComplianceMappings = []ComplianceMapping{
		{Framework: "ISO27001", ControlID: "A.16.1", ControlName: "InfoSec Events", Relevance: "Medium"},
	}

	if err := store.UpdateIncident(ctx, inc); err != nil {
		t.Fatalf("UpdateIncident: %v", err)
	}

	got, err := store.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetIncident after update: %v", err)
	}
	if got == nil {
		t.Fatal("GetIncident after update returned nil")
	}
	if got.Status != StatusInvestigating {
		t.Errorf("Status = %q, want %q", got.Status, StatusInvestigating)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want %q", got.Severity, SeverityCritical)
	}
	if got.Assignee != "analyst@example.com" {
		t.Errorf("Assignee = %q, want %q", got.Assignee, "analyst@example.com")
	}
	if got.Title != "Updated Title" {
		t.Errorf("Title = %q, want %q", got.Title, "Updated Title")
	}
	if len(got.CorrelationEventIDs) != 3 {
		t.Errorf("CorrelationEventIDs length = %d, want 3", len(got.CorrelationEventIDs))
	}
	if len(got.ComplianceMappings) != 1 {
		t.Errorf("ComplianceMappings length = %d, want 1", len(got.ComplianceMappings))
	}
	if got.ComplianceMappings[0].Framework != "ISO27001" {
		t.Errorf("ComplianceMappings[0].Framework = %q, want %q", got.ComplianceMappings[0].Framework, "ISO27001")
	}
}

func TestIntegration_Incident_UpdateNotFound(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	inc := &Incident{ID: "nonexistent-incident", Title: "Ghost", Status: StatusNew}
	if err := store.UpdateIncident(ctx, inc); err == nil {
		t.Error("UpdateIncident on nonexistent incident should return error")
	}
}

func TestIntegration_Incident_ListByStatus(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	// Create incidents with different statuses
	for i, status := range []IncidentStatus{StatusNew, StatusNew, StatusInvestigating} {
		inc := newTestIncident(fmt.Sprintf("list-status-%d", i))
		inc.Status = status
		// Create with status: we need to create first, then update
		if err := store.CreateIncident(ctx, inc); err != nil {
			t.Fatalf("CreateIncident %d: %v", i, err)
		}
		if status != StatusNew {
			inc.Status = status
			inc.UpdatedAt = time.Now().UTC()
			if err := store.UpdateIncident(ctx, inc); err != nil {
				t.Fatalf("UpdateIncident %d: %v", i, err)
			}
		}
	}

	// List with StatusNew filter
	results, err := store.ListIncidents(ctx, &IncidentQuery{Status: []IncidentStatus{StatusNew}})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) < 2 {
		t.Errorf("ListIncidents(StatusNew) returned %d, want at least 2", len(results))
	}
}

func TestIntegration_Incident_ListBySeverity(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	// Create incidents with different severities
	for i, sev := range []IncidentSeverity{SeverityHigh, SeverityHigh, SeverityCritical} {
		inc := newTestIncident(fmt.Sprintf("list-sev-%d", i))
		inc.Severity = sev
		if err := store.CreateIncident(ctx, inc); err != nil {
			t.Fatalf("CreateIncident %d: %v", i, err)
		}
	}

	results, err := store.ListIncidents(ctx, &IncidentQuery{Severity: []IncidentSeverity{SeverityCritical}})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) < 1 {
		t.Errorf("ListIncidents(SeverityCritical) returned %d, want at least 1", len(results))
	}
}

func TestIntegration_Incident_ListByAgentID(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	inc := newTestIncident("list-agent-1")
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	results, err := store.ListIncidents(ctx, &IncidentQuery{AgentID: inc.AgentID})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) < 1 {
		t.Errorf("ListIncidents(AgentID=%q) returned %d, want at least 1", inc.AgentID, len(results))
	}
}

func TestIntegration_Incident_ListWithLimit(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	// Create 5 incidents
	for i := 0; i < 5; i++ {
		inc := newTestIncident(fmt.Sprintf("list-limit-%d", i))
		if err := store.CreateIncident(ctx, inc); err != nil {
			t.Fatalf("CreateIncident %d: %v", i, err)
		}
	}

	results, err := store.ListIncidents(ctx, &IncidentQuery{Limit: 3})
	if err != nil {
		t.Fatalf("ListIncidents: %v", err)
	}
	if len(results) > 3 {
		t.Errorf("ListIncidents(Limit=3) returned %d, want at most 3", len(results))
	}
}

func TestIntegration_Incident_ListNilQuery(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	inc := newTestIncident("list-nil-1")
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	// nil query should return all incidents
	results, err := store.ListIncidents(ctx, nil)
	if err != nil {
		t.Fatalf("ListIncidents(nil): %v", err)
	}
	if len(results) < 1 {
		t.Errorf("ListIncidents(nil) returned %d, want at least 1", len(results))
	}
}

func TestIntegration_Incident_InputValidation(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()
	ctx := context.Background()

	// nil incident
	if err := store.CreateIncident(ctx, nil); err == nil {
		t.Error("CreateIncident(nil) should return error")
	}

	// empty ID
	if err := store.CreateIncident(ctx, &Incident{Title: "No ID"}); err == nil {
		t.Error("CreateIncident with empty ID should return error")
	}

	// update nil
	if err := store.UpdateIncident(ctx, nil); err == nil {
		t.Error("UpdateIncident(nil) should return error")
	}

	// update empty ID
	if err := store.UpdateIncident(ctx, &Incident{Title: "No ID"}); err == nil {
		t.Error("UpdateIncident with empty ID should return error")
	}

	// get empty ID
	got, err := store.GetIncident(ctx, "")
	if err != nil {
		t.Logf("GetIncident(empty ID) returned error (expected): %v", err)
	}
	if got != nil {
		t.Error("GetIncident(empty ID) should return nil")
	}
}

func TestIntegration_Incident_Close(t *testing.T) {
	store, cleanup := setupIncidentStore(t)
	defer cleanup()

	// Close is a no-op (pool is shared), should not error
	if err := store.Close(); err != nil {
		t.Errorf("Close should be no-op, got: %v", err)
	}
}

// =====================================================================
// PostgresPlaybookStore — CRUD Tests
// =====================================================================

func TestIntegration_Playbook_CreateAndGet(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	pb := newTestPlaybook("crud-1")
	if err := store.CreatePlaybook(ctx, pb); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	got, err := store.GetPlaybook(ctx, pb.ID)
	if err != nil {
		t.Fatalf("GetPlaybook: %v", err)
	}
	if got == nil {
		t.Fatal("GetPlaybook returned nil")
	}
	if got.ID != pb.ID {
		t.Errorf("ID = %q, want %q", got.ID, pb.ID)
	}
	if got.Name != pb.Name {
		t.Errorf("Name = %q, want %q", got.Name, pb.Name)
	}
	if got.Severity != pb.Severity {
		t.Errorf("Severity = %q, want %q", got.Severity, pb.Severity)
	}
	if got.Source != pb.Source {
		t.Errorf("Source = %q, want %q", got.Source, pb.Source)
	}
	if len(got.Steps) != 2 {
		t.Errorf("Steps length = %d, want 2", len(got.Steps))
	}
	if got.Steps[0].Action != "notify" {
		t.Errorf("Step[0].Action = %q, want %q", got.Steps[0].Action, "notify")
	}
}

func TestIntegration_Playbook_CreateDuplicate(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	pb := newTestPlaybook("dup-1")
	if err := store.CreatePlaybook(ctx, pb); err != nil {
		t.Fatalf("CreatePlaybook (first): %v", err)
	}

	pb2 := &Playbook{ID: pb.ID, Name: "Duplicate", Severity: SeverityHigh, Source: SourceSOC}
	if err := store.CreatePlaybook(ctx, pb2); err == nil {
		t.Error("CreatePlaybook with duplicate ID should return error")
	}
}

func TestIntegration_Playbook_GetNotFound(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	got, err := store.GetPlaybook(ctx, "nonexistent-playbook-id")
	if err != nil {
		t.Fatalf("GetPlaybook: %v", err)
	}
	if got != nil {
		t.Error("GetPlaybook should return nil for nonexistent playbook")
	}
}

func TestIntegration_Playbook_ListBySeverity(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	for i, sev := range []IncidentSeverity{SeverityHigh, SeverityHigh, SeverityCritical} {
		pb := newTestPlaybook(fmt.Sprintf("list-sev-%d", i))
		pb.Severity = sev
		if err := store.CreatePlaybook(ctx, pb); err != nil {
			t.Fatalf("CreatePlaybook %d: %v", i, err)
		}
	}

	results, err := store.ListPlaybooks(ctx, SeverityCritical, "")
	if err != nil {
		t.Fatalf("ListPlaybooks: %v", err)
	}
	if len(results) < 1 {
		t.Errorf("ListPlaybooks(SeverityCritical) returned %d, want at least 1", len(results))
	}
}

func TestIntegration_Playbook_ListAll(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		pb := newTestPlaybook(fmt.Sprintf("list-all-%d", i))
		if err := store.CreatePlaybook(ctx, pb); err != nil {
			t.Fatalf("CreatePlaybook %d: %v", i, err)
		}
	}

	results, err := store.ListPlaybooks(ctx, "", "")
	if err != nil {
		t.Fatalf("ListPlaybooks: %v", err)
	}
	if len(results) < 3 {
		t.Errorf("ListPlaybooks(all) returned %d, want at least 3", len(results))
	}
}

func TestIntegration_Playbook_Update(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	pb := newTestPlaybook("update-1")
	if err := store.CreatePlaybook(ctx, pb); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	pb.Name = "Updated Playbook"
	pb.AutoExecute = true
	pb.UpdatedAt = time.Now().UTC()
	if err := store.UpdatePlaybook(ctx, pb); err != nil {
		t.Fatalf("UpdatePlaybook: %v", err)
	}

	got, err := store.GetPlaybook(ctx, pb.ID)
	if err != nil {
		t.Fatalf("GetPlaybook after update: %v", err)
	}
	if got.Name != "Updated Playbook" {
		t.Errorf("Name = %q, want %q", got.Name, "Updated Playbook")
	}
	if got.AutoExecute != true {
		t.Errorf("AutoExecute = %v, want true", got.AutoExecute)
	}
}

func TestIntegration_Playbook_UpdateNotFound(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	pb := &Playbook{ID: "nonexistent-pb", Name: "Ghost", Severity: SeverityHigh, Source: SourceSOC}
	if err := store.UpdatePlaybook(ctx, pb); err == nil {
		t.Error("UpdatePlaybook on nonexistent playbook should return error")
	}
}

func TestIntegration_Playbook_Delete(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	pb := newTestPlaybook("delete-1")
	if err := store.CreatePlaybook(ctx, pb); err != nil {
		t.Fatalf("CreatePlaybook: %v", err)
	}

	if err := store.DeletePlaybook(ctx, pb.ID); err != nil {
		t.Fatalf("DeletePlaybook: %v", err)
	}

	got, err := store.GetPlaybook(ctx, pb.ID)
	if err != nil {
		t.Fatalf("GetPlaybook after delete: %v", err)
	}
	if got != nil {
		t.Error("GetPlaybook should return nil after delete")
	}
}

func TestIntegration_Playbook_DeleteNotFound(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	if err := store.DeletePlaybook(ctx, "nonexistent-pb"); err == nil {
		t.Error("DeletePlaybook on nonexistent playbook should return error")
	}
}

func TestIntegration_Playbook_InputValidation(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	ctx := context.Background()

	if err := store.CreatePlaybook(ctx, nil); err == nil {
		t.Error("CreatePlaybook(nil) should return error")
	}
	if err := store.CreatePlaybook(ctx, &Playbook{Name: "No ID"}); err == nil {
		t.Error("CreatePlaybook with empty ID should return error")
	}
	if err := store.UpdatePlaybook(ctx, nil); err == nil {
		t.Error("UpdatePlaybook(nil) should return error")
	}
	if err := store.DeletePlaybook(ctx, ""); err == nil {
		t.Error("DeletePlaybook with empty ID should return error")
	}
}

func TestIntegration_Playbook_Close(t *testing.T) {
	store, cleanup := setupPlaybookStore(t)
	defer cleanup()
	if err := store.Close(); err != nil {
		t.Errorf("Close should be no-op, got: %v", err)
	}
}

// =====================================================================
// PostgresDetectionRuleStore — CRUD Tests
// =====================================================================

func TestIntegration_DetectionRule_CreateAndGet(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	rule := newTestDetectionRule("crud-1")
	if err := store.CreateRule(ctx, rule); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	got, err := store.GetRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if got == nil {
		t.Fatal("GetRule returned nil")
	}
	if got.ID != rule.ID {
		t.Errorf("ID = %q, want %q", got.ID, rule.ID)
	}
	if got.Name != rule.Name {
		t.Errorf("Name = %q, want %q", got.Name, rule.Name)
	}
	if got.Source != rule.Source {
		t.Errorf("Source = %q, want %q", got.Source, rule.Source)
	}
	if got.Severity != rule.Severity {
		t.Errorf("Severity = %q, want %q", got.Severity, rule.Severity)
	}
	if got.Enabled != true {
		t.Errorf("Enabled = %v, want true", got.Enabled)
	}
	if len(got.Patterns) != 1 {
		t.Errorf("Patterns length = %d, want 1", len(got.Patterns))
	}
	if len(got.EventTypes) != 2 {
		t.Errorf("EventTypes length = %d, want 2", len(got.EventTypes))
	}
	if got.MinEvents != 3 {
		t.Errorf("MinEvents = %d, want 3", got.MinEvents)
	}
	if len(got.ComplianceMappings) != 1 {
		t.Errorf("ComplianceMappings length = %d, want 1", len(got.ComplianceMappings))
	}
}

func TestIntegration_DetectionRule_CreateDuplicate(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	rule := newTestDetectionRule("dup-1")
	if err := store.CreateRule(ctx, rule); err != nil {
		t.Fatalf("CreateRule (first): %v", err)
	}

	rule2 := &DetectionRule{ID: rule.ID, Name: "Duplicate", Enabled: true}
	if err := store.CreateRule(ctx, rule2); err == nil {
		t.Error("CreateRule with duplicate ID should return error")
	}
}

func TestIntegration_DetectionRule_GetNotFound(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	got, err := store.GetRule(ctx, "nonexistent-rule-id")
	if err != nil {
		t.Fatalf("GetRule: %v", err)
	}
	if got != nil {
		t.Error("GetRule should return nil for nonexistent rule")
	}
}

func TestIntegration_DetectionRule_ListAll(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		rule := newTestDetectionRule(fmt.Sprintf("list-all-%d", i))
		if err := store.CreateRule(ctx, rule); err != nil {
			t.Fatalf("CreateRule %d: %v", i, err)
		}
	}

	results, err := store.ListRules(ctx, false)
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(results) < 3 {
		t.Errorf("ListRules(all) returned %d, want at least 3", len(results))
	}
}

func TestIntegration_DetectionRule_ListEnabledOnly(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	// Create enabled rule
	ruleEnabled := newTestDetectionRule("enabled-1")
	ruleEnabled.Enabled = true
	if err := store.CreateRule(ctx, ruleEnabled); err != nil {
		t.Fatalf("CreateRule (enabled): %v", err)
	}

	// Create disabled rule
	ruleDisabled := newTestDetectionRule("disabled-1")
	ruleDisabled.Enabled = false
	if err := store.CreateRule(ctx, ruleDisabled); err != nil {
		t.Fatalf("CreateRule (disabled): %v", err)
	}

	results, err := store.ListRules(ctx, true)
	if err != nil {
		t.Fatalf("ListRules(enabledOnly): %v", err)
	}
	for _, r := range results {
		if !r.Enabled {
			t.Errorf("ListRules(enabledOnly=true) returned disabled rule %q", r.ID)
		}
	}
}

func TestIntegration_DetectionRule_Update(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	rule := newTestDetectionRule("update-1")
	if err := store.CreateRule(ctx, rule); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	rule.Name = "Updated Rule"
	rule.Enabled = false
	rule.Severity = SeverityLow
	rule.UpdatedAt = time.Now().UTC()
	if err := store.UpdateRule(ctx, rule); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	got, err := store.GetRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetRule after update: %v", err)
	}
	if got.Name != "Updated Rule" {
		t.Errorf("Name = %q, want %q", got.Name, "Updated Rule")
	}
	if got.Enabled != false {
		t.Errorf("Enabled = %v, want false", got.Enabled)
	}
	if got.Severity != SeverityLow {
		t.Errorf("Severity = %q, want %q", got.Severity, SeverityLow)
	}
}

func TestIntegration_DetectionRule_UpdateNotFound(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	rule := &DetectionRule{ID: "nonexistent-rule", Name: "Ghost", Enabled: true}
	if err := store.UpdateRule(ctx, rule); err == nil {
		t.Error("UpdateRule on nonexistent rule should return error")
	}
}

func TestIntegration_DetectionRule_Delete(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	rule := newTestDetectionRule("delete-1")
	if err := store.CreateRule(ctx, rule); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	if err := store.DeleteRule(ctx, rule.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}

	got, err := store.GetRule(ctx, rule.ID)
	if err != nil {
		t.Fatalf("GetRule after delete: %v", err)
	}
	if got != nil {
		t.Error("GetRule should return nil after delete")
	}
}

func TestIntegration_DetectionRule_DeleteNotFound(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	if err := store.DeleteRule(ctx, "nonexistent-rule"); err == nil {
		t.Error("DeleteRule on nonexistent rule should return error")
	}
}

func TestIntegration_DetectionRule_InputValidation(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	ctx := context.Background()

	if err := store.CreateRule(ctx, nil); err == nil {
		t.Error("CreateRule(nil) should return error")
	}
	if err := store.CreateRule(ctx, &DetectionRule{Name: "No ID"}); err == nil {
		t.Error("CreateRule with empty ID should return error")
	}
	if err := store.UpdateRule(ctx, nil); err == nil {
		t.Error("UpdateRule(nil) should return error")
	}
	if err := store.DeleteRule(ctx, ""); err == nil {
		t.Error("DeleteRule with empty ID should return error")
	}
}

func TestIntegration_DetectionRule_Close(t *testing.T) {
	store, cleanup := setupDetectionRuleStore(t)
	defer cleanup()
	if err := store.Close(); err != nil {
		t.Errorf("Close should be no-op, got: %v", err)
	}
}
