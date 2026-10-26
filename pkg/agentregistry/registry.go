package agentregistry

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/mcpserver"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// Registry is the unified AI agent inventory. It aggregates agent
// identity, activity, and lifecycle state from all protocol subsystems
// into a single queryable registry.
//
// The Registry is a glue layer — it reads from existing subsystems
// (RBAC, MCP, A2A, AIBOM, Correlation, Intent Signer) and unifies their
// data into AgentRecords. It does not duplicate detection logic or
// protocol parsing.
//
// Lifecycle states (provisioned → active → dormant → quarantined → revoked)
// are managed by the DormancyEngine and PolicyEngine, which are wired
// after Registry creation.
type Registry struct {
	mu       sync.RWMutex
	store    Store
	policies LifecyclePolicyStore

	// Data sources
	rbac        *rbac.Manager
	mcpSessions *mcpserver.ConnectionSessionManager
	a2aSource   A2AAgentSource
	aibomSource AIBOMSource
	correlation CorrelationSource

	// Callbacks (wired by PolicyEngine and SSE stream)
	onLifecycleEvent func(event LifecycleEvent)

	// Background refresh
	refreshInterval time.Duration
	stopCh          chan struct{}
	running         bool

	logger *slog.Logger
}

// LifecycleEvent is emitted when an agent's lifecycle status changes.
// The Registry calls the onLifecycleEvent callback (if set) so that
// SSE streams, policy engines, and other consumers can react.
type LifecycleEvent struct {
	AgentID   string      `json:"agent_id"`
	OldStatus AgentStatus `json:"old_status"`
	NewStatus AgentStatus `json:"new_status"`
	Timestamp time.Time   `json:"timestamp"`
	Reason    string      `json:"reason,omitempty"`
}

// Config holds the dependencies needed to create a Registry.
type Config struct {
	Store           Store
	PolicyStore     LifecyclePolicyStore
	RBAC            *rbac.Manager
	MCPSessions     *mcpserver.ConnectionSessionManager
	A2ASource       A2AAgentSource
	AIBOMSource     AIBOMSource
	Correlation     CorrelationSource
	RefreshInterval time.Duration
	Logger          *slog.Logger
}

// New creates a new Registry with the given configuration.
// Store and RBAC are required; all other sources are optional (nil
// sources are treated as empty).
func New(cfg Config) (*Registry, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("agentregistry: Store is required")
	}
	if cfg.RBAC == nil {
		return nil, fmt.Errorf("agentregistry: RBAC manager is required")
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 60 * time.Second
	}
	if cfg.PolicyStore == nil {
		cfg.PolicyStore = NewInMemoryPolicyStore()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default().With("component", "agent-registry")
	}
	return &Registry{
		store:           cfg.Store,
		policies:        cfg.PolicyStore,
		rbac:            cfg.RBAC,
		mcpSessions:     cfg.MCPSessions,
		a2aSource:       cfg.A2ASource,
		aibomSource:     cfg.AIBOMSource,
		correlation:     cfg.Correlation,
		refreshInterval: cfg.RefreshInterval,
		stopCh:          make(chan struct{}),
		logger:          cfg.Logger,
	}, nil
}

// SetLifecycleEventCallback registers a callback that is invoked
// whenever an agent's lifecycle status changes. This is used by the
// SSE stream and PolicyEngine to react to status transitions.
func (r *Registry) SetLifecycleEventCallback(fn func(event LifecycleEvent)) {
	r.mu.Lock()
	r.onLifecycleEvent = fn
	r.mu.Unlock()
}

// Discover scans all protocol layers and builds a unified agent inventory.
// This is the primary entry point — called on startup and periodically
// by the background refresh goroutine.
//
// Discovery proceeds in this order:
//  1. RBAC ListAgents() — establishes the identity baseline
//  2. MCP session activity — enriches with MCP protocol + last activity
//  3. RBAC sessions — enriches with HTTP protocol + session activity
//  4. A2A known agents — enriches with A2A protocol + capabilities
//  5. AIBOM reconciliation — marks InAIBOM flag
//  6. Correlation events — enriches with total event count + last activity
//  7. Compute lifecycle status
func (r *Registry) Discover(ctx context.Context) error {
	r.logger.Debug("agentregistry: starting discovery")

	// Step 1: RBAC — identity baseline
	agents := r.rbac.ListAgents()
	r.logger.Debug("agentregistry: RBAC agents discovered", "count", len(agents))

	// Build initial records from RBAC
	records := make(map[string]*AgentRecord, len(agents))
	for _, agent := range agents {
		record := rbacAgentToRecord(agent)
		records[agent.ID] = record
	}

	// Step 2: MCP session activity
	var mcpSessions []*mcpserver.MCPSession
	if r.mcpSessions != nil {
		mcpSessions = r.mcpSessions.ListSessions()
	}
	mcpActivity := extractMCPActivity(mcpSessions)
	r.logger.Debug("agentregistry: MCP activity extracted", "agents_with_mcp", len(mcpActivity))
	for _, ma := range mcpActivity {
		record, ok := records[ma.AgentID]
		if !ok {
			// Agent exists in MCP but not RBAC — create a minimal record.
			// This is a drift condition (active but not registered).
			record = &AgentRecord{
				ID:               ma.AgentID,
				Name:             ma.AgentID,
				Status:           StatusProvisioned,
				StatusSince:      nowFunc(),
				FirstSeen:        nowFunc(),
				CreatedAt:        nowFunc(),
				DiscoverySources: []string{"mcp"},
			}
			records[ma.AgentID] = record
		}
		if !hasProtocol(record.Protocols, ProtocolMCP) {
			record.Protocols = append(record.Protocols, ProtocolMCP)
		}
		if !contains(record.DiscoverySources, "mcp") {
			record.DiscoverySources = append(record.DiscoverySources, "mcp")
		}
		if ma.LastActivity.After(record.LastActivity) {
			record.LastActivity = ma.LastActivity
		}
	}

	// Count active MCP sessions per agent
	for id := range records {
		count := extractMCPProtocolCount(r.mcpSessions, id)
		if count > records[id].ActiveSessions {
			records[id].ActiveSessions = count
		}
	}

	// Step 3: RBAC sessions — enrich with session activity timestamps
	for id, record := range records {
		sessions := r.rbac.GetAgentSessions(id)
		for _, s := range sessions {
			la := s.LastActivityTime()
			if la.IsZero() {
				continue
			}
			if !hasProtocol(record.Protocols, ProtocolHTTP) {
				// RBAC sessions are HTTP-proxied by default
				record.Protocols = append(record.Protocols, ProtocolHTTP)
			}
			if la.After(record.LastActivity) {
				record.LastActivity = la
			}
		}
		if len(sessions) > record.ActiveSessions {
			record.ActiveSessions = len(sessions)
		}
	}

	// Step 4: A2A known agents
	if r.a2aSource != nil {
		a2aAgents := r.a2aSource.KnownAgents()
		for _, info := range a2aAgents {
			record, ok := records[info.AgentID]
			if !ok {
				record = &AgentRecord{
					ID:               info.AgentID,
					Name:             info.AgentID,
					Status:           StatusProvisioned,
					StatusSince:      nowFunc(),
					FirstSeen:        nowFunc(),
					CreatedAt:        nowFunc(),
					DiscoverySources: []string{"a2a"},
				}
				records[info.AgentID] = record
			}
			if !hasProtocol(record.Protocols, ProtocolA2A) {
				record.Protocols = append(record.Protocols, ProtocolA2A)
			}
			if !contains(record.DiscoverySources, "a2a") {
				record.DiscoverySources = append(record.DiscoverySources, "a2a")
			}
			if info.LastSeen.After(record.LastActivity) {
				record.LastActivity = info.LastSeen
			}
		}
		r.logger.Debug("agentregistry: A2A agents discovered", "count", len(a2aAgents))
	}

	// Step 5: AIBOM reconciliation
	if r.aibomSource != nil {
		aibomNames := r.aibomSource.AgentNames()
		aibomSet := make(map[string]bool, len(aibomNames))
		for _, name := range aibomNames {
			aibomSet[name] = true
		}
		for _, record := range records {
			if aibomSet[record.ID] || aibomSet[record.Name] {
				record.InAIBOM = true
			}
		}
		r.logger.Debug("agentregistry: AIBOM agents reconciled", "count", len(aibomNames))
	}

	// Step 6: Correlation events
	if r.correlation != nil {
		for id, record := range records {
			count, _ := r.correlation.AgentEventCount(id)
			if count > 0 {
				record.TotalEvents = count
				if !contains(record.DiscoverySources, "correlation") {
					record.DiscoverySources = append(record.DiscoverySources, "correlation")
				}
			}
			// Enrich LastActivity with most recent correlation event
			events, _ := r.correlation.RecentEventsByAgent(id, time.Time{})
			for _, evt := range events {
				if evt.Timestamp.After(record.LastActivity) {
					record.LastActivity = evt.Timestamp
				}
			}
		}
	}

	// Compute initial lifecycle status for each record
	now := nowFunc()
	for _, record := range records {
		record.LastSeen = now
		record.UpdatedAt = now
		// If the agent has any activity, it's at least active
		if !record.LastActivity.IsZero() && record.Status == StatusProvisioned {
			record.Status = StatusActive
			record.StatusSince = now
		}
	}

	// Persist all records
	upsertErrors := 0
	for _, record := range records {
		if err := r.store.Upsert(ctx, record); err != nil {
			r.logger.Warn("agentregistry: failed to upsert record",
				"agent_id", record.ID, "error", err)
			upsertErrors++
		}
	}

	// If every single upsert failed, the store is likely broken —
	// propagate the error so callers (Start, refreshLoop) can react.
	if len(records) > 0 && upsertErrors == len(records) {
		return fmt.Errorf("agentregistry: all upserts failed (%d records)", upsertErrors)
	}

	// Remove records for agents that no longer exist in RBAC or any source.
	// We do this by checking which stored records were NOT updated in this
	// discovery cycle. Agents may be temporarily offline, so we do not
	// auto-delete — removal is a manual operation via the Delete method.

	r.logger.Info("agentregistry: discovery complete",
		"total_agents", len(records))

	return nil
}

// Refresh is a lightweight re-discovery. It calls Discover with the
// same logic but is intended for periodic background refresh.
func (r *Registry) Refresh(ctx context.Context) error {
	return r.Discover(ctx)
}

// Reconcile compares the live registry against the AIBOM static inventory
// and returns a drift report.
func (r *Registry) Reconcile(ctx context.Context) (*DriftReport, error) {
	now := nowFunc()
	report := &DriftReport{GeneratedAt: now}

	// Get all live records
	records, err := r.store.List(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("agentregistry: reconcile: list records: %w", err)
	}

	// Get AIBOM agent names
	var aibomNames []string
	if r.aibomSource != nil {
		aibomNames = r.aibomSource.AgentNames()
	}
	aibomSet := make(map[string]bool, len(aibomNames))
	for _, name := range aibomNames {
		aibomSet[name] = true
	}

	// Check each live record against AIBOM
	for _, record := range records {
		if aibomSet[record.ID] || aibomSet[record.Name] {
			report.Matched++
			record.InAIBOM = true
			_ = r.store.Upsert(ctx, record)
		} else {
			// Active but not in AIBOM
			report.ActiveNotInAIBOM = append(report.ActiveNotInAIBOM, DriftEntry{
				AgentID:   record.ID,
				AgentName: record.Name,
				LastSeen:  record.LastSeen,
				Note:      "agent active in runtime but not declared in AIBOM",
			})
		}
	}

	// Check AIBOM agents not in live registry
	recordSet := make(map[string]bool, len(records))
	for _, r := range records {
		recordSet[r.ID] = true
		recordSet[r.Name] = true
	}
	for _, name := range aibomNames {
		if !recordSet[name] {
			report.InAIBOMNotActive = append(report.InAIBOMNotActive, DriftEntry{
				AgentID:   name,
				AgentName: name,
				Note:      "agent declared in AIBOM but not active in runtime",
			})
		}
	}

	report.TotalAIBOM = len(aibomNames)
	report.TotalActive = len(records)

	r.logger.Info("agentregistry: reconciliation complete",
		"matched", report.Matched,
		"in_aibom_not_active", len(report.InAIBOMNotActive),
		"active_not_in_aibom", len(report.ActiveNotInAIBOM))

	return report, nil
}

// Get returns a single agent record by ID.
func (r *Registry) Get(agentID string) (*AgentRecord, error) {
	return r.store.Get(context.Background(), agentID)
}

// List returns all agent records, optionally filtered.
func (r *Registry) List(filter *ListFilter) ([]*AgentRecord, error) {
	return r.store.List(context.Background(), filter)
}

// ListByStatus returns agents with the given lifecycle status.
func (r *Registry) ListByStatus(status AgentStatus) ([]*AgentRecord, error) {
	return r.store.List(context.Background(), &ListFilter{Status: status})
}

// Upsert creates or updates an agent record in the store. This is
// used by the PolicyActionExecutor to tag agents and by external
// callers to inject records outside the normal discovery cycle.
func (r *Registry) Upsert(record *AgentRecord) error {
	if record.ID == "" {
		return fmt.Errorf("agentregistry: upsert: empty agent ID")
	}
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = nowFunc()
	}
	return r.store.Upsert(context.Background(), record)
}

// Transition manually changes an agent's lifecycle status. This emits
// a LifecycleEvent if a callback is registered.
func (r *Registry) Transition(agentID string, newStatus AgentStatus, reason string) error {
	ctx := context.Background()
	record, err := r.store.Get(ctx, agentID)
	if err != nil {
		return fmt.Errorf("agentregistry: transition: %w", err)
	}

	oldStatus := record.Status
	if oldStatus == newStatus {
		return nil // No-op
	}

	now := nowFunc()
	record.Status = newStatus
	record.StatusSince = now
	record.UpdatedAt = now

	if newStatus == StatusDormant && record.DormantSince.IsZero() {
		record.DormantSince = now
	}
	if newStatus == StatusActive {
		record.DormantSince = time.Time{}
	}

	if err := r.store.Upsert(ctx, record); err != nil {
		return fmt.Errorf("agentregistry: transition: upsert: %w", err)
	}

	r.emitLifecycleEvent(LifecycleEvent{
		AgentID:   agentID,
		OldStatus: oldStatus,
		NewStatus: newStatus,
		Timestamp: now,
		Reason:    reason,
	})

	r.logger.Info("agentregistry: lifecycle transition",
		"agent_id", agentID,
		"old_status", oldStatus,
		"new_status", newStatus,
		"reason", reason)

	return nil
}

// Start launches the background refresh goroutine.
func (r *Registry) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("agentregistry: already running")
	}
	r.running = true
	r.mu.Unlock()

	// Initial discovery
	if err := r.Discover(ctx); err != nil {
		r.logger.Error("agentregistry: initial discovery failed", "error", err)
	}

	go r.refreshLoop(ctx)

	r.logger.Info("agentregistry: background refresh started",
		"interval", r.refreshInterval)
	return nil
}

// Stop shuts down the background refresh goroutine.
func (r *Registry) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	close(r.stopCh)
	r.mu.Unlock()

	r.logger.Info("agentregistry: background refresh stopped")
}

func (r *Registry) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(r.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := r.Refresh(ctx); err != nil {
				r.logger.Warn("agentregistry: background refresh failed", "error", err)
			}
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// emitLifecycleEvent calls the registered callback if one exists.
func (r *Registry) emitLifecycleEvent(event LifecycleEvent) {
	r.mu.RLock()
	cb := r.onLifecycleEvent
	r.mu.RUnlock()
	if cb != nil {
		cb(event)
	}
}

// contains is a simple string slice membership check.
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
