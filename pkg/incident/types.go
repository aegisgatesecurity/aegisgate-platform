// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Incident Response Types
// =========================================================================

package incident

import (
	"fmt"
	"time"
)

// IncidentSeverity maps to correlation engine severity levels.
type IncidentSeverity string

const (
	SeverityLow      IncidentSeverity = "low"
	SeverityMedium   IncidentSeverity = "medium"
	SeverityHigh     IncidentSeverity = "high"
	SeverityCritical IncidentSeverity = "critical"
)

// IncidentStatus tracks the incident lifecycle.
type IncidentStatus string

const (
	StatusNew           IncidentStatus = "new"
	StatusTriaged       IncidentStatus = "triaged"
	StatusInvestigating IncidentStatus = "investigating"
	StatusContained     IncidentStatus = "contained"
	StatusResolved      IncidentStatus = "resolved"
	StatusClosed        IncidentStatus = "closed"
	StatusFalsePositive IncidentStatus = "false_positive"
)

// IncidentSource indicates what created the incident.
type IncidentSource string

const (
	SourceCorrelation IncidentSource = "correlation" // from correlation engine
	SourceSOC         IncidentSource = "soc"          // manual SOC analyst
	SourceAutoRule    IncidentSource = "auto_rule"    // automated detection rule
	SourceAPI         IncidentSource = "api"          // external API
)

// Incident represents a security incident.
type Incident struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    IncidentSeverity `json:"severity"`
	Status      IncidentStatus  `json:"status"`
	Source      IncidentSource  `json:"source"`

	// Correlation linkage.
	SessionID           string   `json:"session_id"`
	AgentID             string   `json:"agent_id"`
	CorrelationEventIDs []string `json:"correlation_event_ids"`

	// Compliance linkage — which frameworks/controls
	// this incident maps to.
	ComplianceMappings []ComplianceMapping `json:"compliance_mappings"`

	// Playbook — what automated response was (or will
	// be) executed.
	PlaybookID   string          `json:"playbook_id"`
	PlaybookRuns []*PlaybookRun  `json:"playbook_runs"`

	// Escalation.
	EscalationPolicyID string    `json:"escalation_policy_id"`
	EscalatedAt        time.Time `json:"escalated_at"`
	EscalatedTo        string    `json:"escalated_to"`

	// Timeline.
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	ResolvedAt time.Time `json:"resolved_at"`
	ClosedAt   time.Time `json:"closed_at"`

	// Metadata.
	Assignee string            `json:"assignee"`
	Tags     []string          `json:"tags"`
	Metadata map[string]string `json:"metadata"`
	TenantID string            `json:"tenant_id"`
}

// NewIncident creates a new incident with a generated ID
// and initial status.
func NewIncident(title, description string, severity IncidentSeverity, source IncidentSource) *Incident {
	now := time.Now().UTC()
	return &Incident{
		ID:                  newID("inc"),
		Title:               title,
		Description:         description,
		Severity:            severity,
		Status:              StatusNew,
		Source:              source,
		CorrelationEventIDs: []string{},
		ComplianceMappings:  []ComplianceMapping{},
		PlaybookRuns:        []*PlaybookRun{},
		Tags:                []string{},
		Metadata:            make(map[string]string),
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

// ComplianceMapping links an incident to a compliance control.
type ComplianceMapping struct {
	Framework   string `json:"framework"`    // e.g., "FedRAMP", "SOC2", "ISO27001"
	ControlID   string `json:"control_id"`   // e.g., "IR-4", "CC6.1"
	ControlName string `json:"control_name"` // e.g., "Incident Handling"
	Relevance   string `json:"relevance"`    // brief description
}

// PlaybookStep is a single step in an incident response playbook.
type PlaybookStep struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Action      string            `json:"action"` // "notify", "block_agent", "isolate_session", "collect_evidence", "run_compliance_check", "create_attestation", "escalate"
	Parameters  map[string]string `json:"parameters"`
	OnFailure   string            `json:"on_failure"` // "continue", "stop", "escalate"
	Timeout     time.Duration     `json:"timeout"`
	Required    bool              `json:"required"`
}

// Playbook is an incident response playbook template.
type Playbook struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    IncidentSeverity  `json:"severity"`
	Source      IncidentSource    `json:"source"`
	Tags        []string          `json:"tags"`
	Steps       []*PlaybookStep   `json:"steps"`
	AutoExecute bool              `json:"auto_execute"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// PlaybookRun tracks a playbook execution against an incident.
type PlaybookRun struct {
	ID          string        `json:"id"`
	PlaybookID  string        `json:"playbook_id"`
	IncidentID  string        `json:"incident_id"`
	Status      string        `json:"status"` // "running", "completed", "failed", "partial"
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	StepResults []*StepResult `json:"step_results"`
	Error       string        `json:"error"`
}

// StepResult tracks the outcome of a single playbook step.
type StepResult struct {
	StepID      string    `json:"step_id"`
	Status      string    `json:"status"` // "success", "failed", "skipped"
	Output      string    `json:"output"`
	Error       string    `json:"error"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

// EscalationPolicy defines when and how to escalate.
type EscalationPolicy struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	SeverityThreshold  IncidentSeverity  `json:"severity_threshold"`
	TimeThreshold      time.Duration     `json:"time_threshold"`
	Recipients         []string          `json:"recipients"`
	RepeatInterval     time.Duration     `json:"repeat_interval"`
	MaxEscalations     int               `json:"max_escalations"`
	NotifyOnResolve    bool              `json:"notify_on_resolve"`
}

// DetectionRule defines an automated incident detection rule.
type DetectionRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`

	// Trigger conditions.
	Source     IncidentSource  `json:"source"`
	Severity  IncidentSeverity `json:"severity"`
	Patterns  []string         `json:"patterns"`    // correlation pattern IDs
	EventTypes []string         `json:"event_types"` // correlation event types
	MinEvents  int              `json:"min_events"`
	TimeWindow time.Duration    `json:"time_window"`

	// Response.
	PlaybookID         string              `json:"playbook_id"`
	AutoCreate         bool                `json:"auto_create"`
	AutoExecute        bool                `json:"auto_execute"`
	ComplianceMappings []ComplianceMapping `json:"compliance_mappings"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IncidentQuery is a filter for listing incidents.
type IncidentQuery struct {
	Status    []IncidentStatus  `json:"status"`
	Severity  []IncidentSeverity `json:"severity"`
	Source    []IncidentSource  `json:"source"`
	AgentID   string            `json:"agent_id"`
	SessionID string            `json:"session_id"`
	Tags      []string          `json:"tags"`
	Limit     int               `json:"limit"`
	Offset    int               `json:"offset"`
	From      time.Time          `json:"from"`
	To        time.Time          `json:"to"`
	TenantID  string            `json:"tenant_id"`
}

// newID generates an ID with a prefix and nanosecond timestamp.
func newID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}