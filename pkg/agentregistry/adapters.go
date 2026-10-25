package agentregistry

import (
	"context"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/aibom"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
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
// A2ACapReader is the subset of the A2A capability enforcer interface
// needed by the adapter. Both *a2a.InMemoryCapEnforcer and
// *a2a.PersistentCapEnforcer satisfy this interface.
type A2ACapReader interface {
	Agents() []string
	GetCapabilities(agentID string) []string
}

type A2AAdapter struct {
	caps A2ACapReader
}

// NewA2AAdapter creates an adapter for the A2A capability enforcer.
// Accepts any type satisfying A2ACapReader (InMemoryCapEnforcer or
// PersistentCapEnforcer). Pass nil to disable A2A source.
func NewA2AAdapter(caps A2ACapReader) *A2AAdapter {
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
type CorrelationAdapter struct {
	engine *correlation.Engine
}

// NewCorrelationAdapter creates an adapter for the correlation engine.
func NewCorrelationAdapter(engine *correlation.Engine) *CorrelationAdapter {
	return &CorrelationAdapter{engine: engine}
}

// RecentEventsByAgent returns recent correlation events for the agent
// since the specified time, using the engine's ListEventsByAgent method.
func (a *CorrelationAdapter) RecentEventsByAgent(agentID string, since time.Time) ([]CorrelationEventInfo, error) {
	if a.engine == nil {
		return nil, nil
	}
	events, err := a.engine.ListEventsByAgent(context.Background(), agentID)
	if err != nil {
		return nil, err
	}
	result := make([]CorrelationEventInfo, 0, len(events))
	for _, evt := range events {
		if evt.Timestamp.Before(since) {
			continue
		}
		result = append(result, CorrelationEventInfo{
			EventType: evt.EventType,
			Severity:  evt.Severity,
			Timestamp: evt.Timestamp,
			Protocol:  evt.Protocol,
			SessionID: evt.SessionID,
		})
	}
	return result, nil
}

// AgentEventCount returns the total correlation events for the agent.
func (a *CorrelationAdapter) AgentEventCount(agentID string) (int64, error) {
	if a.engine == nil {
		return 0, nil
	}
	events, err := a.engine.ListEventsByAgent(context.Background(), agentID)
	if err != nil {
		return 0, err
	}
	return int64(len(events)), nil
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
// ListAgents() and GetAgentSessions(). The helper below normalizes
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
		ID:               agent.ID,
		Name:             agent.Name,
		Description:      agent.Description,
		Role:             string(agent.Role),
		Tools:            tools,
		Enabled:          agent.Enabled,
		TenantID:         agent.TenantID,
		Tags:             agent.Tags,
		Status:           StatusProvisioned,
		StatusSince:      now,
		CreatedAt:        agent.CreatedAt,
		UpdatedAt:        now,
		FirstSeen:        now,
		LastSeen:         now,
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