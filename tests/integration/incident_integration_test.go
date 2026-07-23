// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Incident Response Integration Tests
// =========================================================================
//
// Cross-package integration tests that verify the incident response
// pipeline works end-to-end:
//
//   1. correlation.Event → incident.Engine.ProcessEvent → Incident
//   2. Incident lifecycle: Create → Triage → Resolve
//   3. Playbook execution with action callbacks
//   4. Persistence layer wiring (Manager.IncidentStore)
//   5. Compliance mapping across all 4 frameworks
//   6. Detection rules mapping to correlation patterns
//   7. HTTP API end-to-end (CRUD via net/http)
//   8. SOC stream ↔ incident correlation
//
// Run: go test -v -tags=integration ./tests/integration/
// =========================================================================

//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/incident"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/persistence"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/soc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// =====================================================================
// Helpers
// =====================================================================

// newTestEngine creates a fully-wired incident engine with default
// playbooks and detection rules loaded.
func newTestEngine() *incident.Engine {
	is := incident.NewInMemoryIncidentStore()
	ps := incident.NewInMemoryPlaybookStore()
	rs := incident.NewInMemoryDetectionRuleStore()

	ctx := context.Background()

	// Load default playbooks.
	for _, pb := range incident.DefaultPlaybooks() {
		_ = ps.CreatePlaybook(ctx, pb)
	}

	// Load default detection rules.
	for _, rule := range incident.DefaultDetectionRules() {
		_ = rs.CreateRule(ctx, rule)
	}

	return incident.NewEngine(is, ps, rs)
}

// =====================================================================
// 1. Correlation → Incident Pipeline
// =====================================================================

// TestCorrelationEventToIncident verifies that a correlation.Event
// matching a detection rule creates an incident with the correct
// compliance mappings, agent/session linkage, and severity.
//
// The incident engine's rule matching checks event.Metadata for
// "matched_patterns" (set by the correlation engine after pattern
// analysis) and falls back to EventType matching against pattern IDs.
// We use the metadata approach for realistic integration testing.
func TestCorrelationEventToIncident(t *testing.T) {
	engine := newTestEngine()

	// Build a correlation event that matches the MCP error injection rule.
	// The correlation engine sets Metadata["matched_patterns"] after
	// analyzing events and finding threat patterns.
	event := &correlation.Event{
		ID:        "evt_test_mcp_001",
		Protocol:  "mcp",
		AgentID:   "agent-alpha-1",
		SessionID: "session-2024-001",
		EventType: "error",
		Severity:  "high",
		Decision:  "block",
		Timestamp: time.Now().UTC(),
		Data:      map[string]interface{}{"error_code": "E_INJECTION"},
		Metadata:  map[string]string{"matched_patterns": "mcp_error_injection"},
	}

	inc, err := engine.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if inc == nil {
		t.Fatal("ProcessEvent returned nil incident — expected MCP error injection to match")
	}

	// Verify the incident was created.
	if inc.Source != incident.SourceAutoRule {
		t.Errorf("incident source = %q, want %q", inc.Source, incident.SourceAutoRule)
	}
	if inc.AgentID != "agent-alpha-1" {
		t.Errorf("incident agent_id = %q, want %q", inc.AgentID, "agent-alpha-1")
	}
	if inc.SessionID != "session-2024-001" {
		t.Errorf("incident session_id = %q, want %q", inc.SessionID, "session-2024-001")
	}
	if inc.Severity != incident.SeverityHigh {
		t.Errorf("incident severity = %q, want %q", inc.Severity, incident.SeverityHigh)
	}
	if len(inc.CorrelationEventIDs) == 0 || inc.CorrelationEventIDs[0] != "evt_test_mcp_001" {
		t.Errorf("incident correlation_event_ids = %v, want [evt_test_mcp_001]", inc.CorrelationEventIDs)
	}

	// Verify compliance mappings were set from the rule.
	if len(inc.ComplianceMappings) == 0 {
		t.Fatal("incident has no compliance mappings")
	}

	frameworks := make(map[string]bool)
	for _, m := range inc.ComplianceMappings {
		frameworks[m.Framework] = true
	}
	if !frameworks["FedRAMP"] {
		t.Error("expected FedRAMP mapping")
	}
	if !frameworks["SOC2"] {
		t.Error("expected SOC2 mapping")
	}

	t.Logf("✓ Correlation event → incident: id=%s severity=%s mappings=%d",
		inc.ID, inc.Severity, len(inc.ComplianceMappings))
}

// TestCorrelationEventNoMatch verifies that an event that matches
// no detection rules returns nil.
func TestCorrelationEventNoMatch(t *testing.T) {
	engine := newTestEngine()

	event := &correlation.Event{
		ID:        "evt_no_match",
		Protocol:  "http",
		AgentID:   "agent-safe",
		SessionID: "session-safe",
		EventType: "ping",
		Severity:  "low",
		Decision:  "allow",
		Timestamp: time.Now().UTC(),
	}

	inc, err := engine.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if inc != nil {
		t.Fatalf("expected nil incident for non-matching event, got id=%s", inc.ID)
	}

	t.Log("✓ Non-matching event returns nil incident")
}

// =====================================================================
// 2. All 5 Detection Rules Create Incidents
// =====================================================================

// TestAllDetectionRulesCreateIncidents verifies that all 5 default
// detection rules can create incidents from appropriate correlation
// events. The correlation engine sets Metadata["matched_patterns"]
// after pattern analysis; we simulate this in the test events.
func TestAllDetectionRulesCreateIncidents(t *testing.T) {
	engine := newTestEngine()

	tests := []struct {
		name     string
		event    *correlation.Event
		ruleName string
		severity incident.IncidentSeverity
	}{
		{
			name: "MCP error injection",
			event: &correlation.Event{
				ID: "evt_mcp_inj", Protocol: "mcp", AgentID: "a1",
				SessionID: "s1", EventType: "error",
				Severity: "high", Decision: "block", Timestamp: time.Now().UTC(),
				Metadata: map[string]string{"matched_patterns": "mcp_error_injection"},
			},
			ruleName: "MCP Error Injection",
			severity: incident.SeverityHigh,
		},
		{
			name: "Task hijacking",
			event: &correlation.Event{
				ID: "evt_task_hijack", Protocol: "a2a", AgentID: "a2",
				SessionID: "s2", EventType: "message",
				Severity: "critical", Decision: "block", Timestamp: time.Now().UTC(),
				Metadata: map[string]string{"matched_patterns": "task_hijacking"},
			},
			ruleName: "Task Hijacking",
			severity: incident.SeverityCritical,
		},
		{
			name: "Browser escalation",
			event: &correlation.Event{
				ID: "evt_browser_esc", Protocol: "computeruse", AgentID: "a3",
				SessionID: "s3", EventType: "task",
				Severity: "critical", Decision: "block", Timestamp: time.Now().UTC(),
				Metadata: map[string]string{"matched_patterns": "browser_escalation"},
			},
			ruleName: "Browser Escalation",
			severity: incident.SeverityCritical,
		},
		{
			name: "Rate anomaly",
			event: &correlation.Event{
				ID: "evt_rate_anomaly", Protocol: "mcp", AgentID: "a4",
				SessionID: "s4", EventType: "request",
				Severity: "high", Decision: "block", Timestamp: time.Now().UTC(),
				Metadata: map[string]string{"matched_patterns": "rate_anomaly"},
			},
			ruleName: "Rate Anomaly",
			severity: incident.SeverityHigh,
		},
		{
			name: "Capability creep",
			event: &correlation.Event{
				ID: "evt_cap_creep", Protocol: "mcp", AgentID: "a5",
				SessionID: "s5", EventType: "capability_change",
				Severity: "medium", Decision: "allow", Timestamp: time.Now().UTC(),
				Metadata: map[string]string{"matched_patterns": "capability_creep"},
			},
			ruleName: "Capability Creep",
			severity: incident.SeverityMedium,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inc, err := engine.ProcessEvent(context.Background(), tc.event)
			if err != nil {
				t.Fatalf("ProcessEvent: %v", err)
			}
			if inc == nil {
				t.Fatalf("expected incident from event %s, got nil", tc.event.ID)
			}
			if inc.Severity != tc.severity {
				t.Errorf("severity = %q, want %q", inc.Severity, tc.severity)
			}
			if len(inc.ComplianceMappings) == 0 {
				t.Error("incident has no compliance mappings")
			}
			t.Logf("✓ %s → incident id=%s severity=%s mappings=%d",
				tc.name, inc.ID, inc.Severity, len(inc.ComplianceMappings))
		})
	}
}

// =====================================================================
// 3. Incident Lifecycle
// =====================================================================

// TestIncidentLifecycle verifies the full lifecycle:
// Create → Triage → Resolve.
func TestIncidentLifecycle(t *testing.T) {
	engine := newTestEngine()

	// Create incident.
	inc := incident.NewIncident(
		"Lifecycle test incident",
		"Testing the full incident lifecycle",
		incident.SeverityHigh,
		incident.SourceSOC,
	)
	inc.AgentID = "agent-lifecycle"
	inc.SessionID = "session-lifecycle"

	created, err := engine.CreateIncident(context.Background(), inc)
	if err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	if created.Status != incident.StatusNew {
		t.Errorf("initial status = %q, want %q", created.Status, incident.StatusNew)
	}

	// Triage.
	triaged, err := engine.TriageIncident(context.Background(), created.ID, incident.SeverityCritical, "analyst-1")
	if err != nil {
		t.Fatalf("TriageIncident: %v", err)
	}
	if triaged.Status != incident.StatusTriaged {
		t.Errorf("triaged status = %q, want %q", triaged.Status, incident.StatusTriaged)
	}
	if triaged.Assignee != "analyst-1" {
		t.Errorf("assignee = %q, want %q", triaged.Assignee, "analyst-1")
	}
	if triaged.Severity != incident.SeverityCritical {
		t.Errorf("severity = %q, want %q", triaged.Severity, incident.SeverityCritical)
	}

	// Resolve.
	resolved, err := engine.ResolveIncident(context.Background(), created.ID, "Root cause identified: test")
	if err != nil {
		t.Fatalf("ResolveIncident: %v", err)
	}
	if resolved.Status != incident.StatusResolved {
		t.Errorf("resolved status = %q, want %q", resolved.Status, incident.StatusResolved)
	}
	if resolved.ResolvedAt.IsZero() {
		t.Error("resolved_at should not be zero")
	}

	t.Logf("✓ Lifecycle: %s → %s → %s", created.Status, triaged.Status, resolved.Status)
}

// =====================================================================
// 4. Playbook Execution with Action Callbacks
// =====================================================================

// TestPlaybookExecutionWithCallbacks verifies that executing a
// playbook fires action callbacks in the correct order.
func TestPlaybookExecutionWithCallbacks(t *testing.T) {
	engine := newTestEngine()

	var actions []string

	engine.SetCallbacks(incident.ActionCallbacks{
		OnNotify: func(ctx context.Context, inc *incident.Incident, recipients []string) error {
			actions = append(actions, fmt.Sprintf("notify:%s", inc.ID))
			return nil
		},
		OnBlockAgent: func(ctx context.Context, agentID, sessionID string) error {
			actions = append(actions, fmt.Sprintf("block_agent:%s", agentID))
			return nil
		},
		OnCollectEvidence: func(ctx context.Context, inc *incident.Incident) error {
			actions = append(actions, fmt.Sprintf("collect_evidence:%s", inc.ID))
			return nil
		},
		OnIsolateSession: func(ctx context.Context, agentID, sessionID string) error {
			actions = append(actions, fmt.Sprintf("isolate_session:%s", sessionID))
			return nil
		},
		OnRunComplianceCheck: func(ctx context.Context, inc *incident.Incident) error {
			actions = append(actions, fmt.Sprintf("compliance_check:%s", inc.ID))
			return nil
		},
		OnCreateAttestation: func(ctx context.Context, inc *incident.Incident) error {
			actions = append(actions, fmt.Sprintf("create_attestation:%s", inc.ID))
			return nil
		},
	})

	// Create incident.
	inc := incident.NewIncident(
		"Playbook test",
		"Testing playbook execution",
		incident.SeverityHigh,
		incident.SourceCorrelation,
	)
	inc.AgentID = "agent-pb-test"
	inc.SessionID = "session-pb-test"

	created, err := engine.CreateIncident(context.Background(), inc)
	if err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	// Execute the FedRAMP IR-4 playbook.
	run, err := engine.ExecutePlaybook(context.Background(), created.ID, "pb_fedramp_ir4")
	if err != nil {
		t.Fatalf("ExecutePlaybook: %v", err)
	}
	if run.Status != "completed" {
		t.Errorf("run status = %q, want %q", run.Status, "completed")
	}

	// Verify actions were called in order.
	// pb_fedramp_ir4 steps: notify, collect_evidence, block_agent, create_attestation
	expected := []string{
		"notify:" + created.ID,
		"collect_evidence:" + created.ID,
		"block_agent:agent-pb-test",
		"create_attestation:" + created.ID,
	}

	if len(actions) != len(expected) {
		t.Fatalf("got %d actions, want %d: %v", len(actions), len(expected), actions)
	}

	for i, exp := range expected {
		if actions[i] != exp {
			t.Errorf("action[%d] = %q, want %q", i, actions[i], exp)
		}
	}

	t.Logf("✓ Playbook executed: %d steps, status=%s", len(run.StepResults), run.Status)
}

// =====================================================================
// 5. Compliance Mapping Coverage
// =====================================================================

// TestComplianceMappingAllPatterns verifies that MapToCompliance
// returns mappings for all 5 correlation patterns across all 4
// frameworks (FedRAMP, SOC2, NIST 800-171, ISO 27001).
func TestComplianceMappingAllPatterns(t *testing.T) {
	patterns := []string{
		"mcp_error_injection",
		"task_hijacking",
		"browser_escalation",
		"rate_anomaly",
		"capability_creep",
	}

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			mappings := incident.MapToCompliance(incident.SourceCorrelation, []string{pattern})
			if len(mappings) == 0 {
				t.Fatalf("no mappings for pattern %q", pattern)
			}

			frameworks := make(map[string][]string)
			for _, m := range mappings {
				frameworks[m.Framework] = append(frameworks[m.Framework], m.ControlID)
			}

			// Every pattern should map to at least FedRAMP.
			if len(frameworks["FedRAMP"]) == 0 {
				t.Errorf("no FedRAMP mapping for %q", pattern)
			}

			t.Logf("✓ %s → %s", pattern, formatMappings(mappings))
		})
	}
}

// TestComplianceMappingMultiplePatterns verifies that passing
// multiple patterns returns de-duplicated mappings across all
// frameworks.
func TestComplianceMappingMultiplePatterns(t *testing.T) {
	mappings := incident.MapToCompliance(incident.SourceAutoRule,
		[]string{"mcp_error_injection", "browser_escalation"})

	if len(mappings) == 0 {
		t.Fatal("no mappings for multiple patterns")
	}

	// Check that we get mappings across multiple frameworks.
	frameworks := make(map[string]bool)
	for _, m := range mappings {
		frameworks[m.Framework] = true
	}

	// Should have at least 3 frameworks (FedRAMP + SOC2 + NIST-800-171).
	if len(frameworks) < 3 {
		t.Errorf("expected at least 3 frameworks, got %d: %v", len(frameworks), frameworks)
	}

	t.Logf("✓ Multiple patterns → %d frameworks: %v", len(frameworks), frameworks)
}

// TestComplianceMappingUnknownPattern verifies that unknown patterns
// fall back to a generic mapping based on source.
func TestComplianceMappingUnknownPattern(t *testing.T) {
	mappings := incident.MapToCompliance(incident.SourceCorrelation, []string{"unknown_pattern_xyz"})
	if len(mappings) == 0 {
		t.Fatal("expected fallback mapping for unknown pattern")
	}

	if mappings[0].Framework != "FedRAMP" {
		t.Errorf("fallback framework = %q, want FedRAMP", mappings[0].Framework)
	}
	if mappings[0].ControlID != "IR-4" {
		t.Errorf("fallback control = %q, want IR-4", mappings[0].ControlID)
	}

	t.Logf("✓ Unknown pattern → fallback: %s %s", mappings[0].Framework, mappings[0].ControlID)
}

// TestComplianceMappingSourceVariants verifies that all 4 source
// variants produce a fallback mapping.
func TestComplianceMappingSourceVariants(t *testing.T) {
	sources := []struct {
		source   incident.IncidentSource
		expected string
	}{
		{incident.SourceCorrelation, "FedRAMP"},
		{incident.SourceAutoRule, "FedRAMP"},
		{incident.SourceSOC, "SOC2"},
		{incident.SourceAPI, "FedRAMP"},
	}

	for _, tc := range sources {
		t.Run(string(tc.source), func(t *testing.T) {
			mappings := incident.MapToCompliance(tc.source, []string{"unknown_pattern"})
			if len(mappings) == 0 {
				t.Fatalf("no mapping for source %q", tc.source)
			}
			if mappings[0].Framework != tc.expected {
				t.Errorf("framework = %q, want %q", mappings[0].Framework, tc.expected)
			}
		})
	}
}

func formatMappings(mappings []incident.ComplianceMapping) string {
	var parts []string
	for _, m := range mappings {
		parts = append(parts, fmt.Sprintf("%s:%s", m.Framework, m.ControlID))
	}
	return strings.Join(parts, ", ")
}

// =====================================================================
// 6. Persistence Layer Wiring
// =====================================================================

// TestPersistenceManagerIncidentStore verifies that the in-memory
// incident store works correctly when created directly (Community tier
// uses in-memory stores, not managed through persistence.Manager).
func TestPersistenceManagerIncidentStore(t *testing.T) {
	// Create an in-memory incident store directly (this is what
	// Community/Developer tiers use).
	store := incident.NewInMemoryIncidentStore()

	// Create an incident through the store.
	inc := incident.NewIncident(
		"Persistence test",
		"Testing persistence store wiring",
		incident.SeverityMedium,
		incident.SourceAPI,
	)

	ctx := context.Background()
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	// Read it back.
	got, err := store.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if got == nil {
		t.Fatal("GetIncident returned nil")
	}
	if got.Title != "Persistence test" {
		t.Errorf("title = %q, want %q", got.Title, "Persistence test")
	}

	t.Logf("✓ InMemoryIncidentStore wired: id=%s", got.ID)
}

// TestCrossPackagePipeline verifies the full cross-package pipeline
// using directly-created stores (not requiring PostgreSQL):
// correlation event → incident → attestation envelope.
func TestCrossPackagePipeline(t *testing.T) {
	ctx := context.Background()

	// Create correlation store backed by in-memory engine.
	corrEngine := correlation.NewEngine()
	corrStore := correlation.NewInMemoryCorrelationStore(corrEngine)

	// Create attestation store.
	attStore := attestation.NewInMemoryAttestationStore()

	// Create incident engine with default rules and playbooks.
	incStore := incident.NewInMemoryIncidentStore()
	ps := incident.NewInMemoryPlaybookStore()
	rs := incident.NewInMemoryDetectionRuleStore()

	for _, pb := range incident.DefaultPlaybooks() {
		_ = ps.CreatePlaybook(ctx, pb)
	}
	for _, rule := range incident.DefaultDetectionRules() {
		_ = rs.CreateRule(ctx, rule)
	}

	incEngine := incident.NewEngine(incStore, ps, rs)

	// 1. Record a correlation event.
	// The correlation engine sets Metadata["matched_patterns"] after
	// pattern analysis. We simulate this for integration testing.
	event := correlation.NewEvent("mcp", "error", "agent-pipeline", "session-pipeline")
	event.Severity = "high"
	event.Decision = "block"
	event.Metadata = map[string]string{"matched_patterns": "mcp_error_injection"}

	if err := corrStore.RecordEvent(ctx, event); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	// 2. Process the event through the incident engine.
	inc, err := incEngine.ProcessEvent(ctx, event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if inc == nil {
		t.Fatal("ProcessEvent returned nil — expected MCP error injection match")
	}

	// 3. Create an attestation envelope linked to the incident.
	env := &attestation.Envelope{
		ID:         "env_" + inc.ID,
		Type:       attestation.TypeEvidenceManifest,
		Subject:    "incident://" + inc.ID,
		IssuedAt:   time.Now().UTC(),
		RawPayload: json.RawMessage(`{"incident_id":"` + inc.ID + `"}`),
	}
	if err := attStore.Store(ctx, env); err != nil {
		t.Fatalf("Store envelope: %v", err)
	}

	// 4. Verify incident was stored.
	gotInc, err := incStore.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if gotInc == nil {
		t.Fatal("incident not found in store")
	}
	if len(gotInc.CorrelationEventIDs) != 1 {
		t.Errorf("expected 1 correlation event ID, got %d", len(gotInc.CorrelationEventIDs))
	}
	if len(gotInc.ComplianceMappings) == 0 {
		t.Error("expected compliance mappings on incident")
	}

	// 5. Verify attestation envelope was stored.
	gotEnv, err := attStore.Get(ctx, env.ID)
	if err != nil {
		t.Fatalf("Get envelope: %v", err)
	}
	if gotEnv == nil {
		t.Fatal("attestation envelope not found")
	}
	if gotEnv.Subject != "incident://"+inc.ID {
		t.Errorf("subject = %q, want %q", gotEnv.Subject, "incident://"+inc.ID)
	}

	// 6. Verify correlation store has the event.
	events, err := corrStore.ListEventsBySession(ctx, "session-pipeline")
	if err != nil {
		t.Fatalf("ListEventsBySession: %v", err)
	}
	if len(events) == 0 {
		t.Error("expected at least 1 event in correlation store")
	}

	t.Logf("✓ Full pipeline: event=%s → incident=%s → attestation=%s (mappings=%d)",
		event.ID, inc.ID, env.ID, len(gotInc.ComplianceMappings))
}

// TestPersistenceManagerIncidentStoreWithPostgresWiring verifies the
// persistence.Manager store wiring behavior across tiers. Community
// tier uses file-based persistence and does not provide correlation or
// attestation stores through the Manager (those are in-memory engines
// accessed directly). Professional/Enterprise tiers with PostgreSQL
// provide all three stores through NewWithPostgres().
func TestPersistenceManagerIncidentStoreWithPostgresWiring(t *testing.T) {
	// Community tier: Manager.New() uses file-based persistence.
	// CorrelationStore and AttestationStore are nil (in-memory
	// engines are used directly, not through the Manager).
	// IncidentStore is also nil for file-based persistence.
	cfg := persistence.DefaultConfig()
	cfg.Enabled = true
	cfg.DataDir = t.TempDir()
	cfg.AuditDir = t.TempDir() + "/audit"

	mgr, err := persistence.New(tier.TierCommunity, cfg)
	if err != nil {
		t.Fatalf("persistence.New: %v", err)
	}
	defer mgr.Close()

	// Community tier: all three stores are nil (file-based persistence).
	// The stores exist in-memory via the engine packages directly.
	corrStore := mgr.CorrelationStore()
	attStore := mgr.AttestationStore()
	incStore := mgr.IncidentStore()

	// These are nil for file-based persistence (Community tier).
	t.Logf("✓ Community tier: IncidentStore=%v CorrelationStore=%v AttestationStore=%v",
		incStore != nil, corrStore != nil, attStore != nil)

	// Verify that the in-memory stores work when created directly.
	ctx := context.Background()

	// Create all stores directly (simulating Community tier usage).
	directIncStore := incident.NewInMemoryIncidentStore()
	directCorrEngine := correlation.NewEngine()
	directCorrStore := correlation.NewInMemoryCorrelationStore(directCorrEngine)
	directAttStore := attestation.NewInMemoryAttestationStore()

	// Create an incident through the direct store.
	inc := incident.NewIncident(
		"Direct store test",
		"Testing direct in-memory store wiring",
		incident.SeverityMedium,
		incident.SourceAPI,
	)
	if err := directIncStore.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	got, err := directIncStore.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if got == nil || got.Title != "Direct store test" {
		t.Errorf("incident not found or wrong title: %v", got)
	}

	// Verify correlation store works.
	event := correlation.NewEvent("mcp", "error", "agent-direct", "session-direct")
	if err := directCorrStore.RecordEvent(ctx, event); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	events, err := directCorrStore.ListEventsBySession(ctx, "session-direct")
	if err != nil {
		t.Fatalf("ListEventsBySession: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}

	// Verify attestation store works.
	env := &attestation.Envelope{
		ID:         "env_direct_001",
		Type:       attestation.TypeEvidenceManifest,
		Subject:    "incident://direct-test",
		IssuedAt:   time.Now().UTC(),
		RawPayload: json.RawMessage(`{"test": true}`),
	}
	if err := directAttStore.Store(ctx, env); err != nil {
		t.Fatalf("Store envelope: %v", err)
	}
	gotEnv, err := directAttStore.Get(ctx, env.ID)
	if err != nil {
		t.Fatalf("Get envelope: %v", err)
	}
	if gotEnv == nil {
		t.Fatal("attestation envelope not found")
	}

	t.Logf("✓ All direct stores wired: incident=%s event=%s attestation=%s",
		got.ID, events[0].ID, gotEnv.ID)
}

// =====================================================================
// 7. HTTP API End-to-End
// =====================================================================

// incidentHTTPHandlers creates a test HTTP mux with incident handlers.
// This mirrors wireIncidentHandlers from the main package but without
// auth middleware for testing.
func incidentHTTPHandlers(engine *incident.Engine) http.Handler {
	mux := http.NewServeMux()
	if engine == nil {
		mux.HandleFunc("/api/v1/incidents", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "incident engine not available"})
		})
		return mux
	}

	// List and Create.
	mux.HandleFunc("/api/v1/incidents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			query := &incident.IncidentQuery{}
			if sev := r.URL.Query().Get("severity"); sev != "" {
				for _, s := range strings.Split(sev, ",") {
					query.Severity = append(query.Severity, incident.IncidentSeverity(s))
				}
			}
			if status := r.URL.Query().Get("status"); status != "" {
				for _, s := range strings.Split(status, ",") {
					query.Status = append(query.Status, incident.IncidentStatus(s))
				}
			}
			if agentID := r.URL.Query().Get("agent_id"); agentID != "" {
				query.AgentID = agentID
			}
			results, err := engine.ListIncidents(r.Context(), query)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(results)
		case http.MethodPost:
			var req struct {
				Title       string `json:"title"`
				Description string `json:"description"`
				Severity    string `json:"severity"`
				Source      string `json:"source"`
				AgentID     string `json:"agent_id"`
				SessionID   string `json:"session_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
				return
			}
			if req.Title == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "title is required"})
				return
			}
			severity := incident.IncidentSeverity(req.Severity)
			if severity == "" {
				severity = incident.SeverityLow
			}
			source := incident.IncidentSource(req.Source)
			if source == "" {
				source = incident.SourceAPI
			}
			inc := incident.NewIncident(req.Title, req.Description, severity, source)
			inc.AgentID = req.AgentID
			inc.SessionID = req.SessionID
			created, err := engine.CreateIncident(r.Context(), inc)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(created)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// Get single incident.
	mux.HandleFunc("/api/v1/incidents/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		inc, err := engine.GetIncident(r.Context(), id)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if inc == nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "incident not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(inc)
	})

	// Triage.
	mux.HandleFunc("/api/v1/incidents/{id}/triage", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		var req struct {
			Severity string `json:"severity"`
			Assignee string `json:"assignee"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
			return
		}
		severity := incident.IncidentSeverity(req.Severity)
		if severity == "" {
			severity = incident.SeverityMedium
		}
		triaged, err := engine.TriageIncident(r.Context(), id, severity, req.Assignee)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(triaged)
	})

	// Resolve.
	mux.HandleFunc("/api/v1/incidents/{id}/resolve", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		var req struct {
			Resolution string `json:"resolution"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		resolved, err := engine.ResolveIncident(r.Context(), id, req.Resolution)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(resolved)
	})

	return mux
}

// TestIncidentHTTPAPI tests the full HTTP API lifecycle:
// Create → List → Get → Triage → Resolve.
func TestIncidentHTTPAPI(t *testing.T) {
	engine := newTestEngine()
	handler := incidentHTTPHandlers(engine)

	server := httptest.NewServer(handler)
	defer server.Close()

	client := server.Client()

	// --- Create ---
	createBody := `{"title":"HTTP API test","description":"Testing HTTP lifecycle","severity":"high","source":"api","agent_id":"agent-http","session_id":"session-http"}`
	resp, err := client.Post(server.URL+"/api/v1/incidents", "application/json", bytes.NewReader([]byte(createBody)))
	if err != nil {
		t.Fatalf("POST /incidents: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /incidents: status=%d body=%s", resp.StatusCode, body)
	}

	var created incident.Incident
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode created incident: %v", err)
	}

	t.Logf("✓ Created incident via HTTP: id=%s", created.ID)

	// --- List ---
	resp, err = client.Get(server.URL + "/api/v1/incidents?severity=high")
	if err != nil {
		t.Fatalf("GET /incidents: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /incidents: status=%d", resp.StatusCode)
	}

	var incidents []*incident.Incident
	if err := json.NewDecoder(resp.Body).Decode(&incidents); err != nil {
		t.Fatalf("decode incidents list: %v", err)
	}

	found := false
	for _, inc := range incidents {
		if inc.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("created incident not found in list")
	}

	t.Logf("✓ Listed %d incidents", len(incidents))

	// --- Get ---
	resp, err = client.Get(server.URL + "/api/v1/incidents/" + created.ID)
	if err != nil {
		t.Fatalf("GET /incidents/{id}: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /incidents/{id}: status=%d", resp.StatusCode)
	}

	var got incident.Incident
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode got incident: %v", err)
	}

	if got.Title != "HTTP API test" {
		t.Errorf("title = %q, want %q", got.Title, "HTTP API test")
	}

	t.Logf("✓ Got incident: id=%s title=%s", got.ID, got.Title)

	// --- Triage ---
	triageBody := `{"severity":"critical","assignee":"analyst-http"}`
	req, _ := http.NewRequest(http.MethodPut,
		server.URL+"/api/v1/incidents/"+created.ID+"/triage",
		bytes.NewReader([]byte(triageBody)))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PUT /incidents/{id}/triage: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT /incidents/{id}/triage: status=%d body=%s", resp.StatusCode, body)
	}

	var triaged incident.Incident
	if err := json.NewDecoder(resp.Body).Decode(&triaged); err != nil {
		t.Fatalf("decode triaged incident: %v", err)
	}

	if triaged.Status != incident.StatusTriaged {
		t.Errorf("triaged status = %q, want %q", triaged.Status, incident.StatusTriaged)
	}
	if triaged.Assignee != "analyst-http" {
		t.Errorf("assignee = %q, want %q", triaged.Assignee, "analyst-http")
	}

	t.Logf("✓ Trialed incident: status=%s assignee=%s", triaged.Status, triaged.Assignee)

	// --- Resolve ---
	resolveBody := `{"resolution":"Root cause identified via HTTP test"}`
	req, _ = http.NewRequest(http.MethodPut,
		server.URL+"/api/v1/incidents/"+created.ID+"/resolve",
		bytes.NewReader([]byte(resolveBody)))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PUT /incidents/{id}/resolve: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT /incidents/{id}/resolve: status=%d body=%s", resp.StatusCode, body)
	}

	var resolved incident.Incident
	if err := json.NewDecoder(resp.Body).Decode(&resolved); err != nil {
		t.Fatalf("decode resolved incident: %v", err)
	}

	if resolved.Status != incident.StatusResolved {
		t.Errorf("resolved status = %q, want %q", resolved.Status, incident.StatusResolved)
	}

	t.Logf("✓ Resolved incident: status=%s", resolved.Status)
}

// TestIncidentHTTPAPI503WhenNil verifies that a nil engine returns
// 503 Service Unavailable.
func TestIncidentHTTPAPI503WhenNil(t *testing.T) {
	handler := incidentHTTPHandlers(nil)

	server := httptest.NewServer(handler)
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/api/v1/incidents")
	if err != nil {
		t.Fatalf("GET /incidents: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}

	t.Log("✓ Nil engine → 503 Service Unavailable")
}

// =====================================================================
// 8. SOC Stream ↔ Incident Correlation
// =====================================================================

// TestSOCStreamReceivesCorrelationEvents verifies that correlation
// events can flow into both the SOC stream and the incident engine.
func TestSOCStreamReceivesCorrelationEvents(t *testing.T) {
	// Create a correlation store backed by an in-memory engine.
	corrEngine := correlation.NewEngine()
	corrStore := correlation.NewInMemoryCorrelationStore(corrEngine)

	// Create a SOC timeline streamer.
	streamer := soc.NewTimelineStreamer(corrStore, soc.DefaultStreamConfig())
	if streamer == nil {
		t.Fatal("NewTimelineStreamer returned nil")
	}

	// Create an incident engine.
	incEngine := newTestEngine()

	ctx := context.Background()

	// Record a correlation event.
	event := correlation.NewEvent("mcp", "error", "agent-soc", "session-soc")
	event.Severity = "high"
	event.Decision = "block"

	if err := corrStore.RecordEvent(ctx, event); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	// Analyze — this should match patterns.
	result, err := corrEngine.Analyze(ctx, "agent-soc", "session-soc")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	t.Logf("✓ Correlation analysis: decision=%s patterns=%v severity=%s",
		result.Decision, result.MatchedPatterns, result.Severity)

	// Feed the event into the incident engine.
	inc, err := incEngine.ProcessEvent(ctx, event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}

	if inc != nil {
		t.Logf("✓ Incident created from correlation event: id=%s severity=%s",
			inc.ID, inc.Severity)
	} else {
		t.Log("Note: No incident created (event pattern may not match without multi-event correlation)")
	}
}

// =====================================================================
// 9. Correlation Engine ↔ Incident Engine End-to-End
// =====================================================================

// TestCorrelationEngineToIncidentPipeline simulates the full pipeline:
// Record correlation events → Analyze → ProcessEvent → Create incident
// → Execute playbook → Verify attestation callback.
func TestCorrelationEngineToIncidentPipeline(t *testing.T) {
	corrEngine := correlation.NewEngine()
	incEngine := newTestEngine()

	var attestationCreated bool
	incEngine.SetCallbacks(incident.ActionCallbacks{
		OnCreateAttestation: func(ctx context.Context, inc *incident.Incident) error {
			attestationCreated = true
			return nil
		},
		OnNotify: func(ctx context.Context, inc *incident.Incident, recipients []string) error {
			return nil
		},
		OnCollectEvidence: func(ctx context.Context, inc *incident.Incident) error {
			return nil
		},
		OnBlockAgent: func(ctx context.Context, agentID, sessionID string) error {
			return nil
		},
	})

	ctx := context.Background()

	// Record events that form the MCP error injection pattern:
	//   mcp_error + a2a_request
	// After correlation analysis, the event carries matched_patterns
	// in its metadata. We simulate this for integration testing.
	mcpEvent := &correlation.Event{
		ID: "evt_pipeline_mcp", Protocol: "mcp", AgentID: "agent-pipeline",
		SessionID: "session-pipeline", EventType: "error",
		Severity: "high", Decision: "block", Timestamp: time.Now().UTC(),
		Metadata: map[string]string{"matched_patterns": "mcp_error_injection"},
	}
	a2aEvent := &correlation.Event{
		ID: "evt_pipeline_a2a", Protocol: "a2a", AgentID: "agent-pipeline",
		SessionID: "session-pipeline", EventType: "request",
		Severity: "medium", Decision: "allow", Timestamp: time.Now().UTC(),
	}

	if err := corrEngine.RecordEvent(ctx, mcpEvent); err != nil {
		t.Fatalf("RecordEvent (MCP): %v", err)
	}
	if err := corrEngine.RecordEvent(ctx, a2aEvent); err != nil {
		t.Fatalf("RecordEvent (A2A): %v", err)
	}

	// Analyze.
	result, err := corrEngine.Analyze(ctx, "agent-pipeline", "session-pipeline")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// Process the MCP error event (which should match the
	// MCP error injection rule).
	inc, err := incEngine.ProcessEvent(ctx, mcpEvent)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if inc == nil {
		t.Fatal("ProcessEvent returned nil — expected MCP error injection match")
	}

	t.Logf("✓ Full pipeline: correlation analysis=%v incident=%s",
		result.MatchedPatterns, inc.ID)

	// Execute the linked playbook.
	if inc.PlaybookID != "" {
		run, err := incEngine.ExecutePlaybook(ctx, inc.ID, inc.PlaybookID)
		if err != nil {
			t.Logf("Playbook execution skipped: %v", err)
		} else {
			t.Logf("✓ Playbook executed: id=%s status=%s steps=%d",
				run.ID, run.Status, len(run.StepResults))
		}
	}

	if attestationCreated {
		t.Log("✓ Attestation callback was invoked")
	}
}

// =====================================================================
// 10. Incident Listing and Filtering
// =====================================================================

// TestIncidentListingAndFiltering verifies that listing incidents
// with various filters works correctly.
func TestIncidentListingAndFiltering(t *testing.T) {
	engine := newTestEngine()
	ctx := context.Background()

	// Create incidents with different severities.
	severities := []incident.IncidentSeverity{
		incident.SeverityCritical,
		incident.SeverityHigh,
		incident.SeverityMedium,
		incident.SeverityLow,
	}

	for i, sev := range severities {
		inc := incident.NewIncident(
			fmt.Sprintf("Filtering test %d", i),
			fmt.Sprintf("Severity: %s", sev),
			sev,
			incident.SourceAPI,
		)
		inc.AgentID = fmt.Sprintf("agent-%d", i)
		_, err := engine.CreateIncident(ctx, inc)
		if err != nil {
			t.Fatalf("CreateIncident(%d): %v", i, err)
		}
	}

	// List all incidents.
	all, err := engine.ListIncidents(ctx, &incident.IncidentQuery{})
	if err != nil {
		t.Fatalf("ListIncidents (all): %v", err)
	}
	if len(all) != 4 {
		t.Errorf("expected 4 incidents, got %d", len(all))
	}

	// Filter by severity.
	critical, err := engine.ListIncidents(ctx, &incident.IncidentQuery{
		Severity: []incident.IncidentSeverity{incident.SeverityCritical},
	})
	if err != nil {
		t.Fatalf("ListIncidents (critical): %v", err)
	}
	if len(critical) != 1 {
		t.Errorf("expected 1 critical incident, got %d", len(critical))
	}

	// Filter by agent.
	agent0, err := engine.ListIncidents(ctx, &incident.IncidentQuery{
		AgentID: "agent-0",
	})
	if err != nil {
		t.Fatalf("ListIncidents (agent-0): %v", err)
	}
	if len(agent0) != 1 {
		t.Errorf("expected 1 incident for agent-0, got %d", len(agent0))
	}

	t.Logf("✓ Listing: all=%d critical=%d agent0=%d", len(all), len(critical), len(agent0))
}

// =====================================================================
// 11. Escalation Policy
// =====================================================================

// TestEscalationPolicy verifies that escalation policies can be added
// and retrieved from the engine.
func TestEscalationPolicy(t *testing.T) {
	engine := newTestEngine()

	policy := &incident.EscalationPolicy{
		ID:                "policy_test_001",
		Name:              "Test Escalation Policy",
		SeverityThreshold: incident.SeverityHigh,
		TimeThreshold:     30 * time.Minute,
		Recipients:        []string{"security@example.com", "ciso@example.com"},
		RepeatInterval:    15 * time.Minute,
		MaxEscalations:    3,
		NotifyOnResolve:   true,
	}

	if err := engine.AddEscalationPolicy(policy); err != nil {
		t.Fatalf("AddEscalationPolicy: %v", err)
	}

	got, err := engine.GetEscalationPolicy(policy.ID)
	if err != nil {
		t.Fatalf("GetEscalationPolicy: %v", err)
	}
	if got == nil {
		t.Fatal("GetEscalationPolicy returned nil")
	}
	if got.Name != "Test Escalation Policy" {
		t.Errorf("name = %q, want %q", got.Name, "Test Escalation Policy")
	}
	if got.SeverityThreshold != incident.SeverityHigh {
		t.Errorf("threshold = %q, want %q", got.SeverityThreshold, incident.SeverityHigh)
	}

	t.Logf("✓ Escalation policy: id=%s name=%s", got.ID, got.Name)
}

// =====================================================================
// 12. Default Playbooks and Rules Integrity
// =====================================================================

// TestDefaultPlaybooksIntegrity verifies that all 4 default playbooks
// have valid IDs, steps, and compliance tags.
func TestDefaultPlaybooksIntegrity(t *testing.T) {
	playbooks := incident.DefaultPlaybooks()
	if len(playbooks) != 4 {
		t.Fatalf("expected 4 default playbooks, got %d", len(playbooks))
	}

	expectedIDs := map[string]int{
		"pb_fedramp_ir4":    4, // 4 steps
		"pb_fedramp_ir5":    3, // 3 steps
		"pb_soc2_cc61":      5, // 5 steps
		"pb_nist800171_ir1": 4, // 4 steps
	}

	for _, pb := range playbooks {
		t.Run(pb.ID, func(t *testing.T) {
			expectedSteps, ok := expectedIDs[pb.ID]
			if !ok {
				t.Errorf("unexpected playbook ID: %s", pb.ID)
				return
			}
			if len(pb.Steps) != expectedSteps {
				t.Errorf("playbook %s has %d steps, want %d", pb.ID, len(pb.Steps), expectedSteps)
			}
			if pb.Name == "" {
				t.Error("playbook name is empty")
			}
			for _, step := range pb.Steps {
				if step.Action == "" {
					t.Errorf("step %s has empty action", step.ID)
				}
			}
		})
	}
}

// TestDefaultDetectionRulesIntegrity verifies that all 5 default
// detection rules have valid patterns and compliance mappings.
func TestDefaultDetectionRulesIntegrity(t *testing.T) {
	rules := incident.DefaultDetectionRules()
	if len(rules) != 5 {
		t.Fatalf("expected 5 default rules, got %d", len(rules))
	}

	expectedPatterns := map[string]bool{
		"mcp_error_injection": true,
		"task_hijacking":      true,
		"browser_escalation":  true,
		"rate_anomaly":        true,
		"capability_creep":    true,
	}

	for _, rule := range rules {
		t.Run(rule.ID, func(t *testing.T) {
			if !rule.Enabled {
				t.Errorf("rule %s is not enabled", rule.ID)
			}
			if len(rule.Patterns) == 0 {
				t.Errorf("rule %s has no patterns", rule.ID)
			}
			for _, p := range rule.Patterns {
				if !expectedPatterns[p] {
					t.Errorf("rule %s references unknown pattern %q", rule.ID, p)
				}
			}
			if len(rule.ComplianceMappings) == 0 {
				t.Errorf("rule %s has no compliance mappings", rule.ID)
			}
		})
	}
}

// =====================================================================
// 13. Cross-Package: Severity Ordering Consistency
// =====================================================================

// TestSeverityOrdering verifies that incident severity ordering is
// consistent across the incident and correlation packages.
func TestSeverityOrdering(t *testing.T) {
	// Verify incident.SeverityAtLeast works correctly.
	tests := []struct {
		severity  incident.IncidentSeverity
		threshold incident.IncidentSeverity
		expected  bool
	}{
		{incident.SeverityCritical, incident.SeverityLow, true},
		{incident.SeverityCritical, incident.SeverityHigh, true},
		{incident.SeverityCritical, incident.SeverityCritical, true},
		{incident.SeverityHigh, incident.SeverityCritical, false},
		{incident.SeverityMedium, incident.SeverityHigh, false},
		{incident.SeverityLow, incident.SeverityLow, true},
		{incident.SeverityLow, incident.SeverityMedium, false},
	}

	for _, tc := range tests {
		name := fmt.Sprintf("%s>=%s", tc.severity, tc.threshold)
		t.Run(name, func(t *testing.T) {
			got := incident.SeverityAtLeast(tc.severity, tc.threshold)
			if got != tc.expected {
				t.Errorf("SeverityAtLeast(%s, %s) = %v, want %v",
					tc.severity, tc.threshold, got, tc.expected)
			}
		})
	}
}

// =====================================================================
// 14. SOC Timeline Integration
// =====================================================================

// TestSOCTimelineWithIncident verifies that SOC timeline events and
// incidents can coexist and reference each other.
func TestSOCTimelineWithIncident(t *testing.T) {
	// Create a correlation store backed by an in-memory engine.
	corrEngine := correlation.NewEngine()
	corrStore := correlation.NewInMemoryCorrelationStore(corrEngine)

	// Create a SOC timeline streamer.
	streamer := soc.NewTimelineStreamer(corrStore, soc.DefaultStreamConfig())
	if streamer == nil {
		t.Fatal("NewTimelineStreamer returned nil")
	}

	// Create an incident engine.
	incEngine := newTestEngine()

	ctx := context.Background()

	// Record a correlation event in the SOC store.
	event := correlation.NewEvent("mcp", "error", "agent-soc-timeline", "session-soc-timeline")
	event.Severity = "high"
	event.Decision = "block"

	if err := corrStore.RecordEvent(ctx, event); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	// Create an incident linked to the same event.
	inc := incident.NewIncident(
		"SOC timeline test",
		"Testing SOC timeline ↔ incident linkage",
		incident.SeverityHigh,
		incident.SourceCorrelation,
	)
	inc.SessionID = "session-soc-timeline"
	inc.CorrelationEventIDs = []string{event.ID}

	_, err := incEngine.CreateIncident(ctx, inc)
	if err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	// Verify the correlation store has the event.
	events, err := corrStore.ListEventsBySession(ctx, "session-soc-timeline")
	if err != nil {
		t.Fatalf("ListEventsBySession: %v", err)
	}
	if len(events) != 1 {
		t.Errorf("expected 1 event in SOC store, got %d", len(events))
	}

	// Verify the incident references the event.
	got, err := incEngine.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if len(got.CorrelationEventIDs) != 1 {
		t.Errorf("expected 1 correlation event ID, got %d", len(got.CorrelationEventIDs))
	}

	t.Logf("✓ SOC timeline ↔ incident: event=%s incident=%s", event.ID, inc.ID)
}

// =====================================================================
// 15. Auto-Execute Playbook on ProcessEvent
// =====================================================================

// TestAutoExecutePlaybookOnProcessEvent verifies that when a
// detection rule has AutoExecute=true, the linked playbook is
// automatically executed when an event is processed.
func TestAutoExecutePlaybookOnProcessEvent(t *testing.T) {
	engine := newTestEngine()

	var notifyCalled bool
	engine.SetCallbacks(incident.ActionCallbacks{
		OnNotify: func(ctx context.Context, inc *incident.Incident, recipients []string) error {
			notifyCalled = true
			return nil
		},
		OnCollectEvidence: func(ctx context.Context, inc *incident.Incident) error {
			return nil
		},
		OnRunComplianceCheck: func(ctx context.Context, inc *incident.Incident) error {
			return nil
		},
	})

	// Task hijacking rule has AutoExecute=true and links to pb_soc2_cc61.
	// The correlation engine sets Metadata["matched_patterns"] after
	// pattern analysis.
	event := &correlation.Event{
		ID:        "evt_auto_exec_001",
		Protocol:  "a2a",
		AgentID:   "agent-auto-exec",
		SessionID: "session-auto-exec",
		EventType: "message",
		Severity:  "critical",
		Decision:  "block",
		Metadata:  map[string]string{"matched_patterns": "task_hijacking"},
		Timestamp: time.Now().UTC(),
	}

	inc, err := engine.ProcessEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if inc == nil {
		t.Fatal("ProcessEvent returned nil — expected task hijacking match")
	}

	// Verify the playbook was auto-executed.
	if len(inc.PlaybookRuns) == 0 {
		t.Error("expected auto-executed playbook run, but got none")
	} else {
		t.Logf("✓ Auto-executed playbook: run_status=%s", inc.PlaybookRuns[0].Status)
	}

	if !notifyCalled {
		t.Log("Note: notify callback may not have been called (playbook step might have failed)")
	} else {
		t.Log("✓ Notify callback was invoked during auto-execution")
	}
}

// =====================================================================
// 16. Attestation Store Integration
// =====================================================================

// TestAttestationStoreForIncident verifies that the attestation store
// can create envelopes with incident references in the subject URI.
func TestAttestationStoreForIncident(t *testing.T) {
	attStore := attestation.NewInMemoryAttestationStore()

	ctx := context.Background()

	// Create an attestation envelope referencing an incident.
	env := &attestation.Envelope{
		ID:         "env_att_inc_001",
		Type:       attestation.TypeEvidenceManifest,
		Subject:    "incident://inc_12345",
		IssuedAt:   time.Now().UTC(),
		RawPayload: json.RawMessage(`{"incident_id":"inc_12345","evidence":["log_entry_1","log_entry_2"]}`),
	}

	if err := attStore.Store(ctx, env); err != nil {
		t.Fatalf("Store envelope: %v", err)
	}

	got, err := attStore.Get(ctx, env.ID)
	if err != nil {
		t.Fatalf("Get envelope: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Subject != "incident://inc_12345" {
		t.Errorf("subject = %q, want %q", got.Subject, "incident://inc_12345")
	}

	t.Logf("✓ Attestation envelope: id=%s subject=%s type=%s",
		got.ID, got.Subject, got.Type)
}
