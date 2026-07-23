// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Incident Response Engine
// =========================================================================
//
// engine.go is the central orchestrator for incident response. It
// receives correlation events, matches them against detection rules,
// creates incidents, and executes playbooks.
//
// The Engine integrates with:
//   - pkg/correlation: ProcessEvent receives correlation.Event
//   - pkg/attestation: "create_attestation" step creates envelopes
//   - pkg/compliance: ComplianceMapping links incidents to controls
//   - pkg/soc: SessionID links incidents to SOC timelines
//
// v3.8 incident response automation.
// =========================================================================

package incident

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
)

// ActionCallbacks holds injectable callbacks for playbook step
// execution. This allows testing without side effects.
type ActionCallbacks struct {
	// OnNotify is called for the "notify" action.
	OnNotify func(ctx context.Context, incident *Incident, recipients []string) error

	// OnBlockAgent is called for the "block_agent" action.
	OnBlockAgent func(ctx context.Context, agentID, sessionID string) error

	// OnCollectEvidence is called for the "collect_evidence" action.
	OnCollectEvidence func(ctx context.Context, incident *Incident) error

	// OnIsolateSession is called for the "isolate_session" action.
	OnIsolateSession func(ctx context.Context, agentID, sessionID string) error

	// OnRunComplianceCheck is called for the "run_compliance_check"
	// action.
	OnRunComplianceCheck func(ctx context.Context, incident *Incident) error

	// OnCreateAttestation is called for the "create_attestation"
	// action.
	OnCreateAttestation func(ctx context.Context, incident *Incident) error
}

// Engine is the central orchestrator for incident response.
type Engine struct {
	mu              sync.RWMutex
	incidentStore   IncidentStore
	playbookStore   PlaybookStore
	ruleStore       DetectionRuleStore
	escalationStore *InMemoryEscalationPolicyStore
	logger          *slog.Logger

	// Action callbacks for playbook steps.
	callbacks ActionCallbacks
}

// NewEngine creates the incident response engine. The incident store,
// playbook store, and rule store must not be nil.
func NewEngine(incidentStore IncidentStore, playbookStore PlaybookStore, ruleStore DetectionRuleStore) *Engine {
	return &Engine{
		incidentStore:   incidentStore,
		playbookStore:   playbookStore,
		ruleStore:       ruleStore,
		escalationStore: NewInMemoryEscalationPolicyStore(),
		logger:         slog.Default().With("component", "incident-engine"),
	}
}

// SetCallbacks sets the action callbacks for playbook execution.
// This is primarily for testing.
func (e *Engine) SetCallbacks(callbacks ActionCallbacks) {
	e.callbacks = callbacks
}

// AddEscalationPolicy adds an escalation policy to the engine.
func (e *Engine) AddEscalationPolicy(policy *EscalationPolicy) error {
	return e.escalationStore.Create(policy)
}

// GetEscalationPolicy retrieves an escalation policy by ID.
func (e *Engine) GetEscalationPolicy(id string) (*EscalationPolicy, error) {
	return e.escalationStore.Get(id)
}

// =====================================================================
// ProcessEvent — the key integration point
// =====================================================================

// ProcessEvent takes a correlation event and checks it against
// detection rules. If a rule matches:
//   - If AutoCreate is true, creates an incident
//   - If AutoExecute is true, executes the linked playbook
//   - Returns the created incident (or nil if no rule matched)
func (e *Engine) ProcessEvent(ctx context.Context, event *correlation.Event) (*Incident, error) {
	if event == nil {
		return nil, fmt.Errorf("incident: ProcessEvent: nil event")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("incident: ProcessEvent: context: %w", err)
	}

	// Fetch enabled rules.
	rules, err := e.ruleStore.ListRules(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("incident: ProcessEvent: list rules: %w", err)
	}

	var matchedRule *DetectionRule
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if e.ruleMatchesEvent(rule, event) {
			matchedRule = rule
			break
		}
	}

	if matchedRule == nil {
		e.logger.Debug("No rule matched event",
			"event_id", event.ID,
			"event_type", event.EventType,
		)
		return nil, nil
	}

	e.logger.Info("Rule matched event",
		"rule_id", matchedRule.ID,
		"rule_name", matchedRule.Name,
		"event_id", event.ID,
	)

	if !matchedRule.AutoCreate {
		e.logger.Debug("Rule matched but AutoCreate is false",
			"rule_id", matchedRule.ID,
		)
		return nil, nil
	}

	// Create the incident.
	severity := mapEventSeverity(event.Severity)
	incident := NewIncident(
		fmt.Sprintf("Incident: %s detected", matchedRule.Name),
		fmt.Sprintf("Automated detection: %s. Event ID: %s. Agent: %s.",
			matchedRule.Description, event.ID, event.AgentID),
		severity,
		SourceAutoRule,
	)
	incident.AgentID = event.AgentID
	incident.SessionID = event.SessionID
	incident.CorrelationEventIDs = []string{event.ID}
	incident.PlaybookID = matchedRule.PlaybookID
	incident.ComplianceMappings = matchedRule.ComplianceMappings

	if len(incident.Tags) == 0 {
		incident.Tags = matchedRule.Patterns
	}

	if err := e.incidentStore.CreateIncident(ctx, incident); err != nil {
		return nil, fmt.Errorf("incident: ProcessEvent: create incident: %w", err)
	}

	e.logger.Info("Incident created",
		"incident_id", incident.ID,
		"severity", incident.Severity,
		"rule_id", matchedRule.ID,
	)

	// Auto-execute playbook if configured.
	if matchedRule.AutoExecute && matchedRule.PlaybookID != "" {
		run, err := e.ExecutePlaybook(ctx, incident.ID, matchedRule.PlaybookID)
		if err != nil {
			e.logger.Error("Auto-execute playbook failed",
				"incident_id", incident.ID,
				"playbook_id", matchedRule.PlaybookID,
				"error", err,
			)
		} else {
			e.logger.Info("Auto-executed playbook",
				"incident_id", incident.ID,
				"playbook_id", matchedRule.PlaybookID,
				"run_status", run.Status,
			)
		}
	}

	return incident, nil
}

// =====================================================================
// CreateIncident — manual SOC analyst path
// =====================================================================

// CreateIncident manually creates an incident (SOC analyst path).
// Returns the created incident with a generated ID.
func (e *Engine) CreateIncident(ctx context.Context, incident *Incident) (*Incident, error) {
	if incident == nil {
		return nil, fmt.Errorf("incident: CreateIncident: nil incident")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("incident: CreateIncident: context: %w", err)
	}

	// Set defaults if not provided.
	if incident.ID == "" {
		incident.ID = newID("inc")
	}
	if incident.Status == "" {
		incident.Status = StatusNew
	}
	if incident.Source == "" {
		incident.Source = SourceSOC
	}
	now := time.Now().UTC()
	if incident.CreatedAt.IsZero() {
		incident.CreatedAt = now
	}
	incident.UpdatedAt = now

	if incident.CorrelationEventIDs == nil {
		incident.CorrelationEventIDs = []string{}
	}
	if incident.ComplianceMappings == nil {
		incident.ComplianceMappings = []ComplianceMapping{}
	}
	if incident.PlaybookRuns == nil {
		incident.PlaybookRuns = []*PlaybookRun{}
	}
	if incident.Tags == nil {
		incident.Tags = []string{}
	}
	if incident.Metadata == nil {
		incident.Metadata = make(map[string]string)
	}

	if err := e.incidentStore.CreateIncident(ctx, incident); err != nil {
		return nil, fmt.Errorf("incident: CreateIncident: %w", err)
	}

	e.logger.Info("Incident created manually",
		"incident_id", incident.ID,
		"severity", incident.Severity,
		"source", incident.Source,
	)

	return incident, nil
}

// =====================================================================
// TriageIncident
// =====================================================================

// TriageIncident moves an incident to triaged status with severity
// assessment. Only incidents in "new" status can be triaged.
func (e *Engine) TriageIncident(ctx context.Context, id string, severity IncidentSeverity, assignee string) (*Incident, error) {
	if id == "" {
		return nil, fmt.Errorf("incident: TriageIncident: empty ID")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("incident: TriageIncident: context: %w", err)
	}

	incident, err := e.incidentStore.GetIncident(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("incident: TriageIncident: get: %w", err)
	}
	if incident == nil {
		return nil, fmt.Errorf("incident: TriageIncident: incident %s not found", id)
	}

	if incident.Status != StatusNew {
		return nil, fmt.Errorf("incident: TriageIncident: cannot triage incident in status %s", incident.Status)
	}

	incident.Severity = severity
	incident.Status = StatusTriaged
	incident.Assignee = assignee
	incident.UpdatedAt = time.Now().UTC()

	if err := e.incidentStore.UpdateIncident(ctx, incident); err != nil {
		return nil, fmt.Errorf("incident: TriageIncident: update: %w", err)
	}

	e.logger.Info("Incident triaged",
		"incident_id", id,
		"severity", severity,
		"assignee", assignee,
	)

	return incident, nil
}

// =====================================================================
// ExecutePlaybook
// =====================================================================

// ExecutePlaybook runs a playbook against an incident. Each step is
// executed sequentially. Steps with OnFailure="stop" abort the run on
// failure.
func (e *Engine) ExecutePlaybook(ctx context.Context, incidentID string, playbookID string) (*PlaybookRun, error) {
	if incidentID == "" {
		return nil, fmt.Errorf("incident: ExecutePlaybook: empty incident ID")
	}
	if playbookID == "" {
		return nil, fmt.Errorf("incident: ExecutePlaybook: empty playbook ID")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("incident: ExecutePlaybook: context: %w", err)
	}

	playbook, err := e.playbookStore.GetPlaybook(ctx, playbookID)
	if err != nil {
		return nil, fmt.Errorf("incident: ExecutePlaybook: get playbook: %w", err)
	}
	if playbook == nil {
		return nil, fmt.Errorf("incident: ExecutePlaybook: playbook %s not found", playbookID)
	}

	incident, err := e.incidentStore.GetIncident(ctx, incidentID)
	if err != nil {
		return nil, fmt.Errorf("incident: ExecutePlaybook: get incident: %w", err)
	}
	if incident == nil {
		return nil, fmt.Errorf("incident: ExecutePlaybook: incident %s not found", incidentID)
	}

	now := time.Now().UTC()
	run := &PlaybookRun{
		ID:          newID("pbr"),
		PlaybookID:  playbookID,
		IncidentID:  incidentID,
		Status:      "running",
		StartedAt:   now,
		StepResults: make([]*StepResult, 0),
	}

	// Update the incident status to investigating.
	incident.Status = StatusInvestigating
	incident.UpdatedAt = now
	incident.PlaybookID = playbookID
	if err := e.incidentStore.UpdateIncident(ctx, incident); err != nil {
		return nil, fmt.Errorf("incident: ExecutePlaybook: update incident: %w", err)
	}

	// Execute each step sequentially.
	runFailed := false
	for _, step := range playbook.Steps {
		stepResult := e.executeStep(ctx, step, incident)
		run.StepResults = append(run.StepResults, stepResult)

		if stepResult.Status == "failed" {
			runFailed = true
			if step.OnFailure == "stop" {
				run.Status = "failed"
				run.Error = fmt.Sprintf("Step %s (%s) failed: %s", step.Name, step.ID, stepResult.Error)
				break
			}
			if step.OnFailure == "escalate" {
				// Escalate and continue.
				_ = e.EscalateIncident(ctx, incidentID, "")
			}
			// OnFailure == "continue": keep going.
		}
	}

	if !runFailed {
		run.Status = "completed"
	} else if run.Status != "failed" {
		run.Status = "partial"
	}

	run.CompletedAt = time.Now().UTC()

	// Attach the playbook run to the incident.
	incident, err = e.incidentStore.GetIncident(ctx, incidentID)
	if err != nil {
		return nil, fmt.Errorf("incident: ExecutePlaybook: re-fetch incident: %w", err)
	}
	incident.PlaybookRuns = append(incident.PlaybookRuns, run)
	incident.UpdatedAt = time.Now().UTC()
	if err := e.incidentStore.UpdateIncident(ctx, incident); err != nil {
		return nil, fmt.Errorf("incident: ExecutePlaybook: update incident: %w", err)
	}

	e.logger.Info("Playbook executed",
		"playbook_id", playbookID,
		"incident_id", incidentID,
		"status", run.Status,
		"steps", len(run.StepResults),
	)

	return run, nil
}

// executeStep runs a single playbook step.
func (e *Engine) executeStep(ctx context.Context, step *PlaybookStep, incident *Incident) *StepResult {
	now := time.Now().UTC()
	result := &StepResult{
		StepID:    step.ID,
		Status:    "success",
		StartedAt: now,
	}

	var err error

	switch step.Action {
	case "notify":
		err = e.executeNotify(ctx, step, incident)
	case "block_agent":
		err = e.executeBlockAgent(ctx, step, incident)
	case "isolate_session":
		err = e.executeIsolateSession(ctx, step, incident)
	case "collect_evidence":
		err = e.executeCollectEvidence(ctx, step, incident)
	case "run_compliance_check":
		err = e.executeComplianceCheck(ctx, step, incident)
	case "create_attestation":
		err = e.executeCreateAttestation(ctx, step, incident)
	case "escalate":
		err = e.EscalateIncident(ctx, incident.ID, "")
	default:
		err = fmt.Errorf("unknown action: %s", step.Action)
	}

	result.CompletedAt = time.Now().UTC()
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	}

	return result
}

// =====================================================================
// EscalateIncident
// =====================================================================

// EscalateIncident escalates an incident based on escalation policy.
// If policyID is empty, the first matching policy by severity is used.
func (e *Engine) EscalateIncident(ctx context.Context, id string, policyID string) error {
	if id == "" {
		return fmt.Errorf("incident: EscalateIncident: empty ID")
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("incident: EscalateIncident: context: %w", err)
	}

	incident, err := e.incidentStore.GetIncident(ctx, id)
	if err != nil {
		return fmt.Errorf("incident: EscalateIncident: get: %w", err)
	}
	if incident == nil {
		return fmt.Errorf("incident: EscalateIncident: incident %s not found", id)
	}

	// Find the escalation policy.
	var policy *EscalationPolicy
	if policyID != "" {
		policy, err = e.escalationStore.Get(policyID)
		if err != nil {
			return fmt.Errorf("incident: EscalateIncident: get policy: %w", err)
		}
	} else {
		// Find first matching policy by severity threshold.
		policies, err := e.escalationStore.List()
		if err != nil {
			return fmt.Errorf("incident: EscalateIncident: list policies: %w", err)
		}
		for _, p := range policies {
			if SeverityAtLeast(incident.Severity, p.SeverityThreshold) {
				policy = p
				break
			}
		}
	}

	now := time.Now().UTC()
	incident.EscalatedAt = now
	incident.UpdatedAt = now
	incident.Status = StatusInvestigating

	if policy != nil {
		incident.EscalationPolicyID = policy.ID
		if len(policy.Recipients) > 0 {
			incident.EscalatedTo = policy.Recipients[0]
		}

		// Send notifications via callback.
		if e.callbacks.OnNotify != nil && len(policy.Recipients) > 0 {
			if err := e.callbacks.OnNotify(ctx, incident, policy.Recipients); err != nil {
				e.logger.Error("Escalation notification failed",
					"incident_id", id,
					"error", err,
				)
			}
		}
	}

	if err := e.incidentStore.UpdateIncident(ctx, incident); err != nil {
		return fmt.Errorf("incident: EscalateIncident: update: %w", err)
	}

	e.logger.Info("Incident escalated",
		"incident_id", id,
		"policy_id", policyID,
		"escalated_to", incident.EscalatedTo,
	)

	return nil
}

// =====================================================================
// ResolveIncident
// =====================================================================

// ResolveIncident resolves an incident with an optional resolution
// description (stored in metadata).
func (e *Engine) ResolveIncident(ctx context.Context, id string, resolution string) (*Incident, error) {
	if id == "" {
		return nil, fmt.Errorf("incident: ResolveIncident: empty ID")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("incident: ResolveIncident: context: %w", err)
	}

	incident, err := e.incidentStore.GetIncident(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("incident: ResolveIncident: get: %w", err)
	}
	if incident == nil {
		return nil, fmt.Errorf("incident: ResolveIncident: incident %s not found", id)
	}

	now := time.Now().UTC()
	incident.Status = StatusResolved
	incident.ResolvedAt = now
	incident.UpdatedAt = now
	if resolution != "" {
		if incident.Metadata == nil {
			incident.Metadata = make(map[string]string)
		}
		incident.Metadata["resolution"] = resolution
	}

	if err := e.incidentStore.UpdateIncident(ctx, incident); err != nil {
		return nil, fmt.Errorf("incident: ResolveIncident: update: %w", err)
	}

	e.logger.Info("Incident resolved",
		"incident_id", id,
		"resolution", resolution,
	)

	return incident, nil
}

// =====================================================================
// ListIncidents / GetIncident
// =====================================================================

// ListIncidents queries incidents using filter criteria.
func (e *Engine) ListIncidents(ctx context.Context, query *IncidentQuery) ([]*Incident, error) {
	return e.incidentStore.ListIncidents(ctx, query)
}

// GetIncident retrieves a single incident by ID.
func (e *Engine) GetIncident(ctx context.Context, id string) (*Incident, error) {
	return e.incidentStore.GetIncident(ctx, id)
}

// =====================================================================
// Rule matching helpers
// =====================================================================

// ruleMatchesEvent checks if a detection rule matches a correlation
// event.
func (e *Engine) ruleMatchesEvent(rule *DetectionRule, event *correlation.Event) bool {
	// Check source match.
	if rule.Source != "" && rule.Source != SourceCorrelation {
		// Rules with source=correlation match all events from the
		// correlation engine. Other sources are not matched here.
		if rule.Source != SourceAutoRule {
			return false
		}
	}

	// Check severity match.
	if rule.Severity != "" {
		eventSeverity := IncidentSeverity(event.Severity)
		if !SeverityAtLeast(eventSeverity, rule.Severity) {
			return false
		}
	}

	// Check event type match.
	if len(rule.EventTypes) > 0 {
		matched := false
		for _, et := range rule.EventTypes {
			if event.EventType == et {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check pattern match. Events from the correlation engine
	// carry pattern IDs in the Decision field or Metadata.
	if len(rule.Patterns) > 0 {
		matched := false
		// Check event metadata for matched patterns.
		if event.Metadata != nil {
			if patterns, ok := event.Metadata["matched_patterns"]; ok {
				for _, p := range rule.Patterns {
					if containsStr(patterns, p) {
						matched = true
						break
					}
				}
			}
		}
		// Check event ID prefix as a fallback pattern match.
		if !matched {
			for _, p := range rule.Patterns {
				if event.EventType == p {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// =====================================================================
// Playbook step action implementations
// =====================================================================

func (e *Engine) executeNotify(ctx context.Context, step *PlaybookStep, incident *Incident) error {
	if e.callbacks.OnNotify != nil {
		recipients := []string{}
		if assignee := incident.Assignee; assignee != "" {
			recipients = append(recipients, assignee)
		}
		if r, ok := step.Parameters["recipients"]; ok {
			recipients = append(recipients, r)
		}
		return e.callbacks.OnNotify(ctx, incident, recipients)
	}
	e.logger.Info("Notify step executed (no callback)", "incident_id", incident.ID)
	return nil
}

func (e *Engine) executeBlockAgent(ctx context.Context, step *PlaybookStep, incident *Incident) error {
	if e.callbacks.OnBlockAgent != nil {
		return e.callbacks.OnBlockAgent(ctx, incident.AgentID, incident.SessionID)
	}
	e.logger.Info("Block agent step executed (no callback)", "incident_id", incident.ID, "agent_id", incident.AgentID)
	return nil
}

func (e *Engine) executeIsolateSession(ctx context.Context, step *PlaybookStep, incident *Incident) error {
	if e.callbacks.OnIsolateSession != nil {
		return e.callbacks.OnIsolateSession(ctx, incident.AgentID, incident.SessionID)
	}
	e.logger.Info("Isolate session step executed (no callback)", "incident_id", incident.ID, "session_id", incident.SessionID)
	return nil
}

func (e *Engine) executeCollectEvidence(ctx context.Context, step *PlaybookStep, incident *Incident) error {
	if e.callbacks.OnCollectEvidence != nil {
		return e.callbacks.OnCollectEvidence(ctx, incident)
	}
	e.logger.Info("Collect evidence step executed (no callback)", "incident_id", incident.ID)
	return nil
}

func (e *Engine) executeComplianceCheck(ctx context.Context, step *PlaybookStep, incident *Incident) error {
	if e.callbacks.OnRunComplianceCheck != nil {
		return e.callbacks.OnRunComplianceCheck(ctx, incident)
	}
	e.logger.Info("Compliance check step executed (no callback)", "incident_id", incident.ID)
	return nil
}

func (e *Engine) executeCreateAttestation(ctx context.Context, step *PlaybookStep, incident *Incident) error {
	if e.callbacks.OnCreateAttestation != nil {
		return e.callbacks.OnCreateAttestation(ctx, incident)
	}
	e.logger.Info("Create attestation step executed (no callback)", "incident_id", incident.ID)
	return nil
}

// =====================================================================
// Utility helpers
// =====================================================================

// mapEventSeverity maps a correlation event severity string to an
// IncidentSeverity.
func mapEventSeverity(severity string) IncidentSeverity {
	switch severity {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityMedium // default for unknown severity
	}
}

// containsStr checks if a comma-separated string contains a value.
func containsStr(csv, val string) bool {
	// Simple comma-separated check.
	for i := 0; i < len(csv); i++ {
		j := i
		for j < len(csv) && csv[j] != ',' {
			j++
		}
		if csv[i:j] == val {
			return true
		}
		if j < len(csv) && csv[j] == ',' {
			i = j // will be incremented to j+1
		}
	}
	return false
}