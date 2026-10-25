package agentregistry

import (
	"time"
)

// AgentStatus is the lifecycle state of an AI agent in the registry.
type AgentStatus string

const (
	// StatusProvisioned indicates an agent that is registered in RBAC
	// but has never had any activity across any protocol layer.
	StatusProvisioned AgentStatus = "provisioned"

	// StatusActive indicates an agent with recent activity (within the
	// configured dormancy threshold).
	StatusActive AgentStatus = "active"

	// StatusDormant indicates an agent with no activity beyond the
	// dormancy threshold but not yet quarantined or revoked.
	StatusDormant AgentStatus = "dormant"

	// StatusQuarantined indicates an agent that has been isolated by
	// policy or manual action. Sessions are invalidated; new sessions
	// are blocked.
	StatusQuarantined AgentStatus = "quarantined"

	// StatusRevoked indicates an agent whose credentials have been
	// revoked and is disabled in RBAC.
	StatusRevoked AgentStatus = "revoked"
)

// Protocol identifies which AI communication protocol(s) an agent uses.
type Protocol string

const (
	ProtocolHTTP    Protocol = "http"
	ProtocolMCP     Protocol = "mcp"
	ProtocolA2A     Protocol = "a2a"
	ProtocolACP     Protocol = "acp"
	ProtocolANP     Protocol = "anp"
	ProtocolUnknown Protocol = "unknown"
)

// AgentRecord is the unified view of an AI agent across all protocol
// layers. It is built by aggregating data from RBAC (identity), MCP
// Session Manager (MCP activity), Session Tracker (multi-turn sessions),
// A2A Middleware (A2A identity), AIBOM (static inventory), Correlation
// Engine (cross-protocol events), and Intent Signer (signed intents).
type AgentRecord struct {
	// --- Identity (from RBAC) ---
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Role        string            `json:"role"`
	Tools       []string          `json:"tools,omitempty"`
	Enabled     bool              `json:"enabled"`
	TenantID    string            `json:"tenant_id,omitempty"`

	// --- Lifecycle (managed by Registry) ---
	Status      AgentStatus       `json:"status"`
	StatusSince time.Time         `json:"status_since"`
	Owner       string            `json:"owner,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`

	// --- Activity (aggregated from all sources) ---
	Protocols        []Protocol `json:"protocols"`
	LastActivity     time.Time  `json:"last_activity"`
	ActiveSessions   int        `json:"active_sessions"`
	TotalEvents      int64      `json:"total_events"`
	DormantSince     time.Time  `json:"dormant_since,omitempty"`
	CredentialExpiry time.Time  `json:"credential_expiry,omitempty"`

	// --- Intent signatures (from agentintentsign) ---
	LastIntent   string    `json:"last_intent,omitempty"`
	LastIntentAt time.Time `json:"last_intent_at,omitempty"`
	IntentCount  int64     `json:"intent_count"`

	// --- AIBOM reconciliation ---
	InAIBOM    bool   `json:"in_aibom"`
	AIBOMDrift string `json:"aibom_drift,omitempty"`

	// --- Source tracking ---
	DiscoverySources []string  `json:"discovery_sources"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// ListFilter narrows the results of List and ListByStatus queries.
type ListFilter struct {
	Status    AgentStatus       `json:"status,omitempty"`
	Protocol  Protocol          `json:"protocol,omitempty"`
	Owner     string            `json:"owner,omitempty"`
	Tag       map[string]string `json:"tag,omitempty"`
	TenantID  string            `json:"tenant_id,omitempty"`
}

// matches checks whether a record passes all non-zero filter criteria.
func (f *ListFilter) matches(r *AgentRecord) bool {
	if f == nil {
		return true
	}
	if f.Status != "" && r.Status != f.Status {
		return false
	}
	if f.Protocol != "" && !hasProtocol(r.Protocols, f.Protocol) {
		return false
	}
	if f.Owner != "" && r.Owner != f.Owner {
		return false
	}
	if f.TenantID != "" && r.TenantID != f.TenantID {
		return false
	}
	for k, v := range f.Tag {
		if r.Tags[k] != v {
			return false
		}
	}
	return true
}

// hasProtocol returns true if the record includes the given protocol.
func hasProtocol(protocols []Protocol, p Protocol) bool {
	for _, proto := range protocols {
		if proto == p {
			return true
		}
	}
	return false
}

// LifecyclePolicy defines rules for automated agent lifecycle management.
// When a policy triggers, it executes the configured actions (notify,
// quarantine, revoke, playbook) via existing platform subsystems.
type LifecyclePolicy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`

	// DormancyThreshold is the duration of inactivity after which an
	// agent is classified as dormant. Required.
	DormancyThreshold time.Duration `json:"dormancy_threshold"`

	// AutoRevokeThreshold is the duration of inactivity after which an
	// agent's credentials are automatically revoked. Zero means no
	// auto-revocation.
	AutoRevokeThreshold time.Duration `json:"auto_revoke_threshold,omitempty"`

	// QuarantineThreshold is the duration of inactivity after which an
	// agent is quarantined (sessions invalidated, new sessions blocked)
	// before revocation. Zero means skip quarantine and go straight to
	// revocation if AutoRevokeThreshold is set.
	QuarantineThreshold time.Duration `json:"quarantine_threshold,omitempty"`

	// CredentialExpiryWarning is the window before credential expiry
	// during which the agent is flagged for rotation. Zero means no
	// warning.
	CredentialExpiryWarning time.Duration `json:"credential_expiry_warning,omitempty"`

	// Actions to execute when each threshold is crossed.
	OnDormant    []PolicyAction `json:"on_dormant,omitempty"`
	OnQuarantine []PolicyAction `json:"on_quarantine,omitempty"`
	OnRevoke     []PolicyAction `json:"on_revoke,omitempty"`

	// Filters narrow which agents the policy applies to.
	Filters *PolicyFilters `json:"filters,omitempty"`

	TenantID string `json:"tenant_id,omitempty"`
}

// PolicyAction is a single action to execute when a policy triggers.
type PolicyAction struct {
	Type   string            `json:"type"`   // "notify", "playbook", "quarantine", "revoke", "tag"
	Target string            `json:"target"` // playbook ID, SOAR channel, tag key=value
	Params map[string]string `json:"params,omitempty"`
}

// PolicyFilters narrows which agents a policy applies to.
type PolicyFilters struct {
	Protocols []Protocol        `json:"protocols,omitempty"`
	Roles     []string          `json:"roles,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	TenantIDs []string          `json:"tenant_ids,omitempty"`
}

// DriftReport describes discrepancies between the static AIBOM and the
// live agent registry.
type DriftReport struct {
	GeneratedAt      time.Time    `json:"generated_at"`
	InAIBOMNotActive []DriftEntry `json:"in_aibom_not_active"`
	ActiveNotInAIBOM []DriftEntry `json:"active_not_in_aibom"`
	Matched          int          `json:"matched"`
	TotalAIBOM       int          `json:"total_aibom"`
	TotalActive      int          `json:"total_active"`
}

// DriftEntry is a single drift finding.
type DriftEntry struct {
	AgentID   string    `json:"agent_id"`
	AgentName string    `json:"agent_name,omitempty"`
	Protocol  Protocol  `json:"protocol,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// DormancyReport summarizes the dormancy state of all agents.
type DormancyReport struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Total       int             `json:"total_agents"`
	Active      int             `json:"active"`
	Dormant     int             `json:"dormant"`
	Quarantined int             `json:"quarantined"`
	Revoked     int             `json:"revoked"`
	Provisioned int             `json:"provisioned"`
	Agents      []DormancyEntry `json:"agents"`
}

// DormancyEntry is a single agent's dormancy summary.
type DormancyEntry struct {
	AgentID        string        `json:"agent_id"`
	Name           string        `json:"name"`
	Status         AgentStatus   `json:"status"`
	LastActivity   time.Time     `json:"last_activity"`
	DormantFor     time.Duration `json:"dormant_for"`
	Protocols      []Protocol    `json:"protocols"`
	Owner          string        `json:"owner,omitempty"`
	ActiveSessions int           `json:"active_sessions"`
}

// PolicyEnforcementResult records the outcome of a single policy action.
type PolicyEnforcementResult struct {
	PolicyID  string      `json:"policy_id"`
	AgentID   string      `json:"agent_id"`
	Action    PolicyAction `json:"action"`
	Status    string      `json:"status"` // "executed", "skipped", "failed"
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}