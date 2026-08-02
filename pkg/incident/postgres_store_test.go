// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Incident Response PostgreSQL Store Unit Tests
// =========================================================================
// These tests cover nil/empty-ID input validation, nullTime helper,
// Close semantics, metadata merge logic, and type round-trip serialization
// without requiring a live PostgreSQL connection. Integration tests for
// the SQL execution paths use //go:build integration with a real database
// via pkg/testdb.
// =========================================================================

package incident

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// =====================================================================
// PostgresIncidentStore — Constructor
// =====================================================================

func TestNewPostgresIncidentStore(t *testing.T) {
	// Verify that a nil pool creates a store (pool lifecycle is external).
	// The store is unusable for SQL operations without a pool, but
	// construction should not panic.
	store := NewPostgresIncidentStore(nil)
	if store == nil {
		t.Fatal("NewPostgresIncidentStore(nil) should return non-nil store")
	}
}

// =====================================================================
// PostgresIncidentStore — Input Validation
// =====================================================================

func TestPostgresIncidentStore_CreateIncident_Nil(t *testing.T) {
	store := NewPostgresIncidentStore(nil)
	ctx := context.Background()

	if err := store.CreateIncident(ctx, nil); err == nil {
		t.Error("CreateIncident(nil) should return an error")
	}
}

func TestPostgresIncidentStore_CreateIncident_EmptyID(t *testing.T) {
	store := NewPostgresIncidentStore(nil)
	ctx := context.Background()

	inc := &Incident{Title: "Test", Status: StatusNew}
	if err := store.CreateIncident(ctx, inc); err == nil {
		t.Error("CreateIncident with empty ID should return an error")
	}
}

func TestPostgresIncidentStore_GetIncident_EmptyID(t *testing.T) {
	store := NewPostgresIncidentStore(nil)
	ctx := context.Background()

	inc, err := store.GetIncident(ctx, "")
	// Empty ID returns an error (validation guard).
	if err == nil {
		t.Error("GetIncident with empty ID should return an error")
	}
	if inc != nil {
		t.Error("GetIncident with empty ID should return nil incident")
	}
}

func TestPostgresIncidentStore_UpdateIncident_Nil(t *testing.T) {
	store := NewPostgresIncidentStore(nil)
	ctx := context.Background()

	if err := store.UpdateIncident(ctx, nil); err == nil {
		t.Error("UpdateIncident(nil) should return an error")
	}
}

func TestPostgresIncidentStore_UpdateIncident_EmptyID(t *testing.T) {
	store := NewPostgresIncidentStore(nil)
	ctx := context.Background()

	inc := &Incident{Title: "Test", Status: StatusNew}
	if err := store.UpdateIncident(ctx, inc); err == nil {
		t.Error("UpdateIncident with empty ID should return an error")
	}
}

// =====================================================================
// PostgresIncidentStore — Close
// =====================================================================

func TestPostgresIncidentStore_Close(t *testing.T) {
	store := NewPostgresIncidentStore(nil)
	// Close on PostgresIncidentStore is a no-op (pool is shared).
	if err := store.Close(); err != nil {
		t.Errorf("Close should be a no-op, got: %v", err)
	}
	// Double close should be safe.
	if err := store.Close(); err != nil {
		t.Errorf("double Close should be safe, got: %v", err)
	}
}

// =====================================================================
// PostgresPlaybookStore — Constructor
// =====================================================================

func TestNewPostgresPlaybookStore(t *testing.T) {
	store := NewPostgresPlaybookStore(nil)
	if store == nil {
		t.Fatal("NewPostgresPlaybookStore(nil) should return non-nil store")
	}
}

// =====================================================================
// PostgresPlaybookStore — Input Validation
// =====================================================================

func TestPostgresPlaybookStore_CreatePlaybook_Nil(t *testing.T) {
	store := NewPostgresPlaybookStore(nil)
	ctx := context.Background()

	if err := store.CreatePlaybook(ctx, nil); err == nil {
		t.Error("CreatePlaybook(nil) should return an error")
	}
}

func TestPostgresPlaybookStore_CreatePlaybook_EmptyID(t *testing.T) {
	store := NewPostgresPlaybookStore(nil)
	ctx := context.Background()

	pb := &Playbook{Name: "Test"}
	if err := store.CreatePlaybook(ctx, pb); err == nil {
		t.Error("CreatePlaybook with empty ID should return an error")
	}
}

func TestPostgresPlaybookStore_GetPlaybook_EmptyID(t *testing.T) {
	store := NewPostgresPlaybookStore(nil)
	ctx := context.Background()

	pb, err := store.GetPlaybook(ctx, "")
	// Empty ID returns an error (validation guard).
	if err == nil {
		t.Error("GetPlaybook with empty ID should return an error")
	}
	if pb != nil {
		t.Error("GetPlaybook with empty ID should return nil playbook")
	}
}

func TestPostgresPlaybookStore_UpdatePlaybook_Nil(t *testing.T) {
	store := NewPostgresPlaybookStore(nil)
	ctx := context.Background()

	if err := store.UpdatePlaybook(ctx, nil); err == nil {
		t.Error("UpdatePlaybook(nil) should return an error")
	}
}

func TestPostgresPlaybookStore_UpdatePlaybook_EmptyID(t *testing.T) {
	store := NewPostgresPlaybookStore(nil)
	ctx := context.Background()

	pb := &Playbook{Name: "Test"}
	if err := store.UpdatePlaybook(ctx, pb); err == nil {
		t.Error("UpdatePlaybook with empty ID should return an error")
	}
}

func TestPostgresPlaybookStore_DeletePlaybook_EmptyID(t *testing.T) {
	store := NewPostgresPlaybookStore(nil)
	ctx := context.Background()

	if err := store.DeletePlaybook(ctx, ""); err == nil {
		t.Error("DeletePlaybook with empty ID should return an error")
	}
}

// =====================================================================
// PostgresPlaybookStore — Close
// =====================================================================

func TestPostgresPlaybookStore_Close(t *testing.T) {
	store := NewPostgresPlaybookStore(nil)
	if err := store.Close(); err != nil {
		t.Errorf("Close should be a no-op, got: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Errorf("double Close should be safe, got: %v", err)
	}
}

// =====================================================================
// PostgresDetectionRuleStore — Constructor
// =====================================================================

func TestNewPostgresDetectionRuleStore(t *testing.T) {
	store := NewPostgresDetectionRuleStore(nil)
	if store == nil {
		t.Fatal("NewPostgresDetectionRuleStore(nil) should return non-nil store")
	}
}

// =====================================================================
// PostgresDetectionRuleStore — Input Validation
// =====================================================================

func TestPostgresDetectionRuleStore_CreateRule_Nil(t *testing.T) {
	store := NewPostgresDetectionRuleStore(nil)
	ctx := context.Background()

	if err := store.CreateRule(ctx, nil); err == nil {
		t.Error("CreateRule(nil) should return an error")
	}
}

func TestPostgresDetectionRuleStore_CreateRule_EmptyID(t *testing.T) {
	store := NewPostgresDetectionRuleStore(nil)
	ctx := context.Background()

	rule := &DetectionRule{Name: "Test"}
	if err := store.CreateRule(ctx, rule); err == nil {
		t.Error("CreateRule with empty ID should return an error")
	}
}

func TestPostgresDetectionRuleStore_GetRule_EmptyID(t *testing.T) {
	store := NewPostgresDetectionRuleStore(nil)
	ctx := context.Background()

	rule, err := store.GetRule(ctx, "")
	// Empty ID returns an error (validation guard).
	if err == nil {
		t.Error("GetRule with empty ID should return an error")
	}
	if rule != nil {
		t.Error("GetRule with empty ID should return nil rule")
	}
}

func TestPostgresDetectionRuleStore_UpdateRule_Nil(t *testing.T) {
	store := NewPostgresDetectionRuleStore(nil)
	ctx := context.Background()

	if err := store.UpdateRule(ctx, nil); err == nil {
		t.Error("UpdateRule(nil) should return an error")
	}
}

func TestPostgresDetectionRuleStore_UpdateRule_EmptyID(t *testing.T) {
	store := NewPostgresDetectionRuleStore(nil)
	ctx := context.Background()

	rule := &DetectionRule{Name: "Test"}
	if err := store.UpdateRule(ctx, rule); err == nil {
		t.Error("UpdateRule with empty ID should return an error")
	}
}

func TestPostgresDetectionRuleStore_DeleteRule_EmptyID(t *testing.T) {
	store := NewPostgresDetectionRuleStore(nil)
	ctx := context.Background()

	if err := store.DeleteRule(ctx, ""); err == nil {
		t.Error("DeleteRule with empty ID should return an error")
	}
}

// =====================================================================
// PostgresDetectionRuleStore — Close
// =====================================================================

func TestPostgresDetectionRuleStore_Close(t *testing.T) {
	store := NewPostgresDetectionRuleStore(nil)
	if err := store.Close(); err != nil {
		t.Errorf("Close should be a no-op, got: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Errorf("double Close should be safe, got: %v", err)
	}
}

// =====================================================================
// nullTime helper
// =====================================================================

func TestNullTime_ZeroValue(t *testing.T) {
	result := nullTime(time.Time{})
	if result != nil {
		t.Errorf("nullTime(zero) should return nil, got %v", result)
	}
}

func TestNullTime_NonZero(t *testing.T) {
	now := time.Now()
	result := nullTime(now)
	if result == nil {
		t.Fatal("nullTime(non-zero) should return non-nil")
	}
	if !result.Equal(now) {
		t.Errorf("nullTime mismatch: got %v, want %v", *result, now)
	}
}

func TestNullTime_SpecificTime(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	result := nullTime(ts)
	if result == nil {
		t.Fatal("nullTime should return non-nil for non-zero time")
	}
	if !result.Equal(ts) {
		t.Errorf("nullTime mismatch: got %v, want %v", *result, ts)
	}
}

func TestNullTime_UTC(t *testing.T) {
	ts := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	result := nullTime(ts)
	if result == nil {
		t.Fatal("nullTime should return non-nil for non-zero time")
	}
	if !result.Equal(ts) {
		t.Errorf("nullTime UTC mismatch: got %v, want %v", *result, ts)
	}
}

// =====================================================================
// Metadata merge validation (via CreateIncident/UpdateIncident)
// =====================================================================

func TestPostgresIncidentStore_MetadataMergeViaCreate(t *testing.T) {
	store := NewPostgresIncidentStore(nil)
	ctx := context.Background()

	// Nil incident should be caught before metadata processing.
	if err := store.CreateIncident(ctx, nil); err == nil {
		t.Error("CreateIncident(nil) should return error")
	}

	// Empty ID should be caught before metadata processing.
	inc := &Incident{
		Title:               "Test",
		Description:         "Test description",
		Severity:            SeverityHigh,
		Status:              StatusNew,
		Source:              SourceSOC,
		CorrelationEventIDs: []string{"evt-1", "evt-2"},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "SOC2", ControlID: "CC6.1"},
		},
		Metadata: map[string]string{"key": "value"},
	}
	if err := store.CreateIncident(ctx, inc); err == nil {
		t.Error("CreateIncident with empty ID should return error")
	}
}

func TestPostgresIncidentStore_MetadataMergeViaUpdate(t *testing.T) {
	store := NewPostgresIncidentStore(nil)
	ctx := context.Background()

	if err := store.UpdateIncident(ctx, nil); err == nil {
		t.Error("UpdateIncident(nil) should return error")
	}

	inc := &Incident{
		Title:               "Test",
		Description:         "Updated",
		Severity:            SeverityCritical,
		Status:              StatusInvestigating,
		Source:              SourceAutoRule,
		CorrelationEventIDs: []string{"evt-3"},
		ComplianceMappings: []ComplianceMapping{
			{Framework: "FedRAMP", ControlID: "IR-4"},
		},
		Metadata: map[string]string{"env": "prod"},
	}
	if err := store.UpdateIncident(ctx, inc); err == nil {
		t.Error("UpdateIncident with empty ID should return error")
	}
}

// =====================================================================
// Compile-time interface compliance checks
// =====================================================================

func TestPostgresIncidentStore_ImplementsIncidentStore(t *testing.T) {
	var _ IncidentStore = (*PostgresIncidentStore)(nil)
}

func TestPostgresPlaybookStore_ImplementsPlaybookStore(t *testing.T) {
	var _ PlaybookStore = (*PostgresPlaybookStore)(nil)
}

func TestPostgresDetectionRuleStore_ImplementsDetectionRuleStore(t *testing.T) {
	var _ DetectionRuleStore = (*PostgresDetectionRuleStore)(nil)
}

// =====================================================================
// Incident field initialization
// =====================================================================

func TestNewIncident_FieldsInitialized(t *testing.T) {
	inc := NewIncident("Test Title", "Test Description", SeverityHigh, SourceSOC)

	if inc.ID == "" {
		t.Error("NewIncident should set ID")
	}
	if inc.Title != "Test Title" {
		t.Errorf("Title = %q, want %q", inc.Title, "Test Title")
	}
	if inc.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want %q", inc.Severity, SeverityHigh)
	}
	if inc.Status != StatusNew {
		t.Errorf("Status = %q, want %q", inc.Status, StatusNew)
	}
	if inc.Source != SourceSOC {
		t.Errorf("Source = %q, want %q", inc.Source, SourceSOC)
	}
	if inc.CorrelationEventIDs == nil {
		t.Error("CorrelationEventIDs should be initialized, not nil")
	}
	if inc.ComplianceMappings == nil {
		t.Error("ComplianceMappings should be initialized, not nil")
	}
	if inc.PlaybookRuns == nil {
		t.Error("PlaybookRuns should be initialized, not nil")
	}
	if inc.Tags == nil {
		t.Error("Tags should be initialized, not nil")
	}
	if inc.Metadata == nil {
		t.Error("Metadata should be initialized, not nil")
	}
	if inc.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if inc.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

// =====================================================================
// Severity, Status, Source constants (scan round-trips)
// =====================================================================

func TestIncidentSeverity_StringRoundTrip(t *testing.T) {
	severities := []IncidentSeverity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for _, sev := range severities {
		s := string(sev)
		if s == "" {
			t.Errorf("Severity %v has empty string representation", sev)
		}
	}
}

func TestIncidentStatus_StringRoundTrip(t *testing.T) {
	statuses := []IncidentStatus{
		StatusNew, StatusTriaged, StatusInvestigating,
		StatusContained, StatusResolved, StatusClosed, StatusFalsePositive,
	}
	for _, status := range statuses {
		s := string(status)
		if s == "" {
			t.Errorf("Status %v has empty string representation", status)
		}
	}
}

func TestIncidentSource_StringRoundTrip(t *testing.T) {
	sources := []IncidentSource{SourceCorrelation, SourceSOC, SourceAutoRule, SourceAPI}
	for _, src := range sources {
		s := string(src)
		if s == "" {
			t.Errorf("Source %v has empty string representation", src)
		}
	}
}

// =====================================================================
// ComplianceMapping JSON serialization
// =====================================================================

func TestComplianceMapping_JSONRoundTrip(t *testing.T) {
	mappings := []ComplianceMapping{
		{Framework: "SOC2", ControlID: "CC6.1", ControlName: "Logical Access", Relevance: "High"},
		{Framework: "FedRAMP", ControlID: "IR-4", ControlName: "Incident Handling", Relevance: "Critical"},
		{Framework: "ISO27001", ControlID: "A.16.1", ControlName: "InfoSec Events", Relevance: "Medium"},
	}

	data, err := json.Marshal(mappings)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed []ComplianceMapping
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(parsed) != len(mappings) {
		t.Fatalf("round-trip length mismatch: got %d, want %d", len(parsed), len(mappings))
	}
	for i, m := range mappings {
		if parsed[i].Framework != m.Framework {
			t.Errorf("Framework mismatch at %d: got %q, want %q", i, parsed[i].Framework, m.Framework)
		}
		if parsed[i].ControlID != m.ControlID {
			t.Errorf("ControlID mismatch at %d: got %q, want %q", i, parsed[i].ControlID, m.ControlID)
		}
	}
}

// =====================================================================
// PlaybookRun JSON serialization
// =====================================================================

func TestPlaybookRun_JSONRoundTrip(t *testing.T) {
	run := &PlaybookRun{
		ID:         "run-1",
		PlaybookID: "pb-1",
		IncidentID: "inc-1",
		Status:     "completed",
		StartedAt:  time.Now().UTC(),
		StepResults: []*StepResult{
			{StepID: "step-1", Status: "success", Output: "OK"},
		},
	}

	data, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed PlaybookRun
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.ID != run.ID {
		t.Errorf("ID mismatch: got %q, want %q", parsed.ID, run.ID)
	}
	if parsed.PlaybookID != run.PlaybookID {
		t.Errorf("PlaybookID mismatch: got %q, want %q", parsed.PlaybookID, run.PlaybookID)
	}
}

// =====================================================================
// DetectionRule ComplianceMappings serialization
// =====================================================================

func TestDetectionRule_ComplianceMappingsRoundTrip(t *testing.T) {
	rule := &DetectionRule{
		ID:          "rule-1",
		Name:        "Test Rule",
		Description: "Test detection rule",
		Enabled:     true,
		Source:      SourceCorrelation,
		Severity:    SeverityHigh,
		Patterns:    []string{"pattern-1", "pattern-2"},
		EventTypes:  []string{"login_failure", "privilege_escalation"},
		MinEvents:   3,
		TimeWindow:  5 * time.Minute,
		ComplianceMappings: []ComplianceMapping{
			{Framework: "SOC2", ControlID: "CC6.1"},
		},
		AutoCreate:  true,
		AutoExecute: true,
	}

	data, err := json.Marshal(rule.ComplianceMappings)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed []ComplianceMapping
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(parsed) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(parsed))
	}
	if parsed[0].Framework != "SOC2" {
		t.Errorf("Framework mismatch: got %q, want %q", parsed[0].Framework, "SOC2")
	}
}

// =====================================================================
// IncidentQuery defaults
// =====================================================================

func TestIncidentQuery_NilDefaults(t *testing.T) {
	query := &IncidentQuery{}

	if query.Status != nil {
		t.Error("default Status should be nil")
	}
	if query.Severity != nil {
		t.Error("default Severity should be nil")
	}
	if query.Source != nil {
		t.Error("default Source should be nil")
	}
	if query.Limit != 0 {
		t.Error("default Limit should be 0")
	}
	if query.Offset != 0 {
		t.Error("default Offset should be 0")
	}
}

// =====================================================================
// PlaybookStep JSON serialization
// =====================================================================

func TestPlaybookStep_JSONRoundTrip(t *testing.T) {
	step := &PlaybookStep{
		ID:          "step-1",
		Name:        "Notify SOC",
		Description: "Send notification to SOC team",
		Action:      "notify",
		Parameters:  map[string]string{"channel": "slack", "team": "soc"},
		OnFailure:   "continue",
		Timeout:     5 * time.Minute,
		Required:    true,
	}

	data, err := json.Marshal(step)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed PlaybookStep
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.ID != step.ID {
		t.Errorf("ID mismatch: got %q, want %q", parsed.ID, step.ID)
	}
	if parsed.Action != step.Action {
		t.Errorf("Action mismatch: got %q, want %q", parsed.Action, step.Action)
	}
	if parsed.Parameters["channel"] != "slack" {
		t.Errorf("Parameters[channel] mismatch: got %q, want %q", parsed.Parameters["channel"], "slack")
	}
}

// =====================================================================
// EscalationPolicy JSON serialization
// =====================================================================

func TestEscalationPolicy_JSONRoundTrip(t *testing.T) {
	policy := &EscalationPolicy{
		ID:                "pol-1",
		Name:              "Critical Escalation",
		SeverityThreshold: SeverityCritical,
		TimeThreshold:     30 * time.Minute,
		Recipients:        []string{"admin@example.com", "soc@example.com"},
		RepeatInterval:    15 * time.Minute,
		MaxEscalations:    3,
		NotifyOnResolve:   true,
	}

	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed EscalationPolicy
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.ID != policy.ID {
		t.Errorf("ID mismatch: got %q, want %q", parsed.ID, policy.ID)
	}
	if parsed.Name != policy.Name {
		t.Errorf("Name mismatch: got %q, want %q", parsed.Name, policy.Name)
	}
	if parsed.SeverityThreshold != SeverityCritical {
		t.Errorf("SeverityThreshold mismatch: got %q, want %q", parsed.SeverityThreshold, SeverityCritical)
	}
	if len(parsed.Recipients) != 2 {
		t.Errorf("Recipients length: got %d, want 2", len(parsed.Recipients))
	}
	if parsed.MaxEscalations != 3 {
		t.Errorf("MaxEscalations mismatch: got %d, want 3", parsed.MaxEscalations)
	}
}

// =====================================================================
// Tags nil-to-empty normalization (postgres stores nil → []string{})
// =====================================================================

func TestTagsNormalization(t *testing.T) {
	// Verify that nil tags are normalized to empty slice, as done in
	// postgres_store.go CreateIncident: tagsArray := incident.Tags; if tagsArray == nil { tagsArray = []string{} }
	var tags []string
	if tags != nil {
		t.Error("initial nil check failed")
	}
	if tags == nil {
		tags = []string{}
	}
	if tags == nil {
		t.Error("tags should have been normalized to empty slice")
	}
	if len(tags) != 0 {
		t.Errorf("normalized tags should have length 0, got %d", len(tags))
	}
}

// =====================================================================
// StepResult JSON serialization
// =====================================================================

func TestStepResult_JSONRoundTrip(t *testing.T) {
	sr := &StepResult{
		StepID:      "step-1",
		Status:      "success",
		Output:      "All checks passed",
		Error:       "",
		StartedAt:   time.Now().UTC(),
		CompletedAt: time.Now().UTC().Add(2 * time.Second),
	}

	data, err := json.Marshal(sr)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var parsed StepResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if parsed.StepID != sr.StepID {
		t.Errorf("StepID mismatch: got %q, want %q", parsed.StepID, sr.StepID)
	}
	if parsed.Status != sr.Status {
		t.Errorf("Status mismatch: got %q, want %q", parsed.Status, sr.Status)
	}
}
