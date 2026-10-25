package agentregistry

import (
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/a2a"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/aibom"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
)

// ============================================================================
// Interface Abstractions
//
// The Registry depends on narrow interfaces rather than concrete types.
// This enables unit testing without spinning up all subsystems — tests
// inject mock implementations.
// ============================================================================

// A2AAgentSource provides A2A agent identities discovered via mTLS.
type A2AAgentSource interface {
	// KnownAgents returns all A2A agents known to the capability enforcer.
	KnownAgents() []A2AAgentInfo
}

// A2AAgentInfo describes a single A2A agent.
type A2AAgentInfo struct {
	AgentID      string
	Capabilities []string
	LastSeen     time.Time
}

// CorrelationSource provides recent correlation events for activity tracking.
type CorrelationSource interface {
	// RecentEventsByAgent returns events for the given agent since the
	// specified time. Used to determine LastActivity and TotalEvents.
	RecentEventsByAgent(agentID string, since time.Time) ([]CorrelationEventInfo, error)
	// AgentEventCount returns the total number of correlation events
	// recorded for the given agent.
	AgentEventCount(agentID string) (int64, error)
}

// CorrelationEventInfo is a simplified view of a correlation event
// for registry purposes.
type CorrelationEventInfo struct {
	EventType string
	Severity  string
	Timestamp time.Time
	Protocol  string
	SessionID string
}

// IntentSource provides signed intent information for agents.
type IntentSource interface {
	// LatestIntent returns the most recent signed intent for the agent,
	// or nil if none exists.
	LatestIntent(agentID string) (*IntentInfo, error)
	// IntentCount returns the total number of signed intents for the agent.
	IntentCount(agentID string) (int64, error)
}

// IntentInfo is a simplified view of a signed intent tuple.
type IntentInfo struct {
	Intent        string
	Justification string
	ValidUntil    time.Time
	SignedAt      time.Time
}

// AIBOMSource provides the static AI Bill of Materials for reconciliation.
type AIBOMSource interface {
	// AgentNames returns the list of agent names declared in the AIBOM.
	AgentNames() []string
	// AIBOMGeneratedAt returns the timestamp of the last AIBOM generation.
	AIBOMGeneratedAt() time.Time
}

// ============================================================================
// Adapter Implementations
//
// These adapters wrap the existing platform subsystems to satisfy the
// Registry's interface dependencies. They are thin wrappers — each just
// calls the existing methods on the underlying package.
// ============================================================================

// A2AAdapter wraps pkg/a2a.InMemoryCapEnforcer to satisfy A2AAgentSource.
type A2AAdapter struct {
	caps *a2a.InMemoryCapEnforcer
}

// NewA2AAdapter creates an adapter for the A2A capability enforcer.
func NewA2AAdapter(caps *a2a.InMemoryCapEnforcer) *A2AAdapter {
	return &A2AAdapter{caps: caps}
}

// KnownAgents returns all A2A agents from the capability enforcer.
func (a *A2AAdapter) KnownAgents() []A2AAgentInfo {
	if a.caps == nil {
		return nil
	}
	agentIDs := a.caps.Agents()
	result := make([]A2AAgentInfo, 0, len(agentIDs))
	for _, id := range agentIDs {
		caps := a.caps.GetCapabilities(id)
		result = append(result, A2AAgentInfo{
			AgentID:      id,
			Capabilities: caps,
		})
	}
	return result
}

// CorrelationAdapter wraps pkg/correlation.Engine to satisfy
// CorrelationSource.
//
// The correlation engine stores events keyed by "agentID:sessionID".
// This adapter iterates all event keys to find events for a given agent.
type CorrelationAdapter struct {
	engine *correlation.Engine
}

// NewCorrelationAdapter creates an adapter for the correlation engine.
func NewCorrelationAdapter(engine *correlation.Engine) *CorrelationAdapter {
	return &CorrelationAdapter{engine: engine}
}

// RecentEventsByAgent returns recent correlation events for the agent.
// This uses ListEventsBySession with a session wildcard approach —
// since the engine keys events by agentID:sessionID, we query by
// iterating available sessions.
//
// Note: In v1, this is a best-effort scan. The correlation engine's
// internal event map is accessed via its public ListEventsBySession
// method. A future enhancement could add a ListEventsByAgent method
// to the engine directly.
func (a *CorrelationAdapter) RecentEventsByAgent(agentID string, since time.Time) ([]CorrelationEventInfo, error) {
	if a.engine == nil {
		return nil, nil
	}
	// The correlation engine does not yet expose a ListEventsByAgent
	// method. For v1, we return an empty list — the Registry will
	// rely on MCP session activity and session tracker timestamps
	// for LastActivity. This is a known limitation documented in
	// the design spec (§5.1.1).
	//
	// When correlation.Engine gains a ListEventsByAgent method,
	// this adapter will call it directly.
	return nil, nil
}

// AgentEventCount returns the total correlation events for the agent.
// Same limitation as RecentEventsByAgent — returns 0 for v1.
func (a *CorrelationAdapter) AgentEventCount(agentID string) (int64, error) {
	if a.engine == nil {
		return 0, nil
	}
	return 0, nil
}

// IntentAdapter is a stub for pkg/agentintentsign. The intent signer
// does not yet expose a query API (it signs and verifies but does not
// store intents for later retrieval). For v1, the adapter returns
// empty results. When a persistent intent store is added, this adapter
// will be updated.
type IntentAdapter struct{}

// NewIntentAdapter creates a new intent source adapter.
func NewIntentAdapter() *IntentAdapter { return &IntentAdapter{} }

// LatestIntent returns nil for v1 (no persistent intent store yet).
func (a *IntentAdapter) LatestIntent(_ string) (*IntentInfo, error) {
	return nil, nil
}

// IntentCount returns 0 for v1.
func (a *IntentAdapter) IntentCount(_ string) (int64, error) {
	return 0, nil
}

// AIBOMAdapter wraps the AIBOM generator output to satisfy AIBOMSource.
type AIBOMAdapter struct {
	agentNames  []string
	generatedAt time.Time
}

// NewAIBOMAdapter creates an adapter from an AIBOM. Call this after
// generating the AIBOM via the platform's normal AIBOM generation flow.
func NewAIBOMAdapter(aibomData *aibom.AIBOM) *AIBOMAdapter {
	if aibomData == nil {
		return &AIBOMAdapter{}
	}
	var names []string
	// A2A agents
	if aibomData.A2A.AgentNames != nil {
		names = append(names, aibomData.A2A.AgentNames...)
	}
	return &AIBOMAdapter{
		agentNames:  names,
		generatedAt: aibomData.GeneratedAt,
	}
}

// AgentNames returns the agent names declared in the AIBOM.
func (a *AIBOMAdapter) AgentNames() []string {
	return a.agentNames
}

// AIBOMGeneratedAt returns the AIBOM generation timestamp.
func (a *AIBOMAdapter) AIBOMGeneratedAt() time.Time {
	return a.generatedAt
}

// ============================================================================
// RBAC Adapter (inline — no separate interface needed)
//
// The Registry uses *rbac.Manager directly since it already exposes
// ListAgents() and GetAgentSessions(). The adapter below normalizes
// RBAC Agent fields into AgentRecord identity fields.
// ============================================================================

// rbacAgentToRecord initializes an AgentRecord from an RBAC Agent.
// Only identity fields are populated; activity and lifecycle fields
// are filled later by the discovery process.
func rbacAgentToRecord(agent *rbac.Agent) *AgentRecord {
	tools := make([]string, 0, len(agent.Tools))
	for _, t := range agent.Tools {
		tools = append(tools, string(t))
	}
	now := nowFunc()
	return &AgentRecord{
		ID:          agent.ID,
		Name:        agent.Name,
		Description: agent.Description,
		Role:        string(agent.Role),
		Tools:       tools,
		Enabled:     agent.Enabled,
		TenantID:    agent.TenantID,
		Tags:        agent.Tags,
		Status:      StatusProvisioned,
		StatusSince: now,
		CreatedAt:   agent.CreatedAt,
		UpdatedAt:   now,
		FirstSeen:   now,
		LastSeen:    now,
		DiscoverySources: []string{"rbac"},
	}
}

// mcpSessionActivity extracts activity info from an MCP session.
type mcpActivity struct {
	AgentID      string
	LastActivity time.Time
	Active       bool
}

// extractMCPActivity scans MCP sessions and returns per-agent activity.
func extractMCPActivity(sm *mcpserver.ConnectionSessionManager) []mcpActivity {
	if sm == nil {
		return nil
	}
	sessions := sm.ListSessions()
	byAgent := make(map[string]*mcpActivity)
	for _, s := range sessions {
		if s.Agent == nil {
			continue
		}
		id := s.Agent.ID
		existing, ok := byAgent[id]
		if !ok {
			byAgent[id] = &mcpActivity{
				AgentID:      id,
				LastActivity: s.LastActivity,
				Active:       true,
			}
		} else {
			if s.LastActivity.After(existing.LastActivity) {
				existing.LastActivity = s.LastActivity
			}
		}
	}
	result := make([]mcpActivity, 0, len(byAgent))
	for _, a := range byAgent {
		result = append(result, *a)
	}
	return result
}

// extractMCPProtocolCount counts active MCP sessions per agent.
func extractMCPProtocolCount(sm *mcpserver.ConnectionSessionManager, agentID string) int {
	if sm == nil {
		return 0
	}
	count := 0
	for _, s := range sm.ListSessions() {
		if s.Agent != nil && s.Agent.ID == agentID {
			count++
		}
	}
	return count
}

// scannerSessionActivity extracts the most recent session activity
// for each agent from the session tracker.
//
// Note: The session tracker keys by SessionID, not AgentID. The
// RBAC AgentSession provides the agent-to-session mapping. For v1,
// we use the RBAC session's LastActivityTime as the primary activity
// signal. The session tracker is consulted for additional multi-turn
// session timestamps.
func scannerSessionActivity(tracker *scanner.SessionTracker, sessions []*rbac.AgentSession) map[string]time.Time {
	if tracker == nil {
		return nil
	}
	// The session tracker does not expose a "list all sessions" method.
	// For v1, we return nil — activity is derived from RBAC sessions
	// and MCP sessions. When the session tracker gains an iteration
	// method, this will be updated.
	_ = sessions
	return nil
}