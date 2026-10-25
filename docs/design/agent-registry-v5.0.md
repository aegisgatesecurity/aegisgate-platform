# Design Spec: Agent Inventory & Lifecycle Management

**Package:** `pkg/agentregistry/`
**Target version:** Platform v5.0.0
**Branch:** `feat/agent-registry-v5.0`
**Tier gate:** Professional (single gate, no free-tier access)
**Patent:** Candidate for #8 (64/XXX,XXX) — **file after proven working**

---

## 1. Problem Statement

The Arrakis Security 2026 report found that **76% of AI agents in enterprise environments are dormant but retain live credentials**. No existing tool — ITAM, IAM, secret managers, SOAR, or AIBOM — provides a unified live registry of AI agents with lifecycle state, dormancy detection, and automated credential revocation.

AegisGate already has every data source needed to solve this:

| Data source | Package | What it knows |
|-------------|---------|---------------|
| Agent identity, role, tools, enabled | `pkg/rbac/` | Agent struct, ListAgents(), GetAgentSessions() |
| MCP session activity | `pkg/mcpserver/session_manager.go` | MCPSession with CreatedAt, LastActivity |
| Multi-turn session tracking | `pkg/scanner/session_tracker.go` | SessionID, turns, UpdatedAt, TTL=30min |
| A2A agent identity | `pkg/a2a/middleware.go` | mTLS CN extraction, capability enforcement |
| AIBOM static inventory | `pkg/aibom/` | CycloneDX enumeration of agents, MCP, models, RAG |
| Cross-protocol events | `pkg/correlation/` | Events with AgentID, queryable by agent_id |
| Intent signatures | `pkg/agentintentsign/` | Signed intent tuples (agent_id, intent, valid_until) |
| Incident response | `pkg/incident/` | 14 playbooks with block_agent, isolate_session |
| SOC real-time stream | `pkg/soc/stream.go` | SSE event streaming |
| Trust portal | `pkg/trustportal/` | Public posture dashboard |

**The gap:** These subsystems independently track pieces of agent state, but nothing unifies them into a single queryable registry with lifecycle state, dormancy detection, and policy-driven automation. There is no `/api/v1/agents` endpoint. There is no "show me every AI agent, its credentials, its last activity, its owner, and whether it's dormant."

---

## 2. Design Principles

1. **Glue, not greenfield** — The Registry reads from existing subsystems. It does not duplicate their data; it aggregates and enriches.
2. **Zero external dependencies** — Uses only existing Platform packages and Go stdlib. Compliant with air-gap-ready standard.
3. **In-memory fallback** — PostgreSQL is optional. Follows the same pattern as RBAC (`usePostgres bool`), correlation (`InMemoryCorrelationStore`), and incident (`InMemoryIncidentStore`).
4. **Single tier gate** — The entire feature is Professional. No Community/Developer carve-out. Protects IP.
5. **Extends existing patterns** — HTTP routes follow the `dashMux.HandleFunc` pattern in main.go. SSE streaming extends `pkg/soc/stream.go`. Incident playbooks extend `pkg/incident/playbooks.go`. Feature gate extends `pkg/tier/tier.go`.
6. **Background refresh** — A goroutine periodically re-discovers agents from all protocol layers. Default interval: 60 seconds. Configurable.
7. **No new network listeners** — Uses the existing dashboard HTTP mux. No new ports.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     pkg/agentregistry/                           │
│                                                                  │
│  ┌──────────────┐   ┌───────────────┐   ┌───────────────────┐  │
│  │  Registry    │   │ DormancyEngine │   │  PolicyEngine     │  │
│  │  (core)      │   │                │   │                   │  │
│  │  - Discover()│   │ - Evaluate()   │   │ - Enforce()       │  │
│  │  - Refresh() │   │ - Classify()   │   │ - ApplyActions()  │  │
│  │  - Reconcile │   │ - Thresholds   │   │ - Notify()        │  │
│  └──────┬───────┘   └───────┬────────┘   └────────┬──────────┘  │
│         │                   │                     │              │
│  ┌──────┴───────────────────┴─────────────────────┴──────────┐  │
│  │                    AgentRecord                              │  │
│  │  (unified struct: identity + lifecycle + activity)         │  │
│  └──────┬────────────────────────────────────────────────────┘  │
│         │                                                        │
│  ┌──────┴──────┐   ┌──────────────┐   ┌────────────────────┐   │
│  │ MemoryStore  │   │ PostgresStore │   │  HTTP Handlers     │   │
│  │ (fallback)   │   │ (optional)    │   │  (/api/v1/agents)  │   │
│  └──────────────┘   └───────────────┘   └────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
         │                │                     │
         ▼                ▼                     ▼
┌─────────────┐  ┌──────────────┐   ┌─────────────────────────┐
│  pkg/rbac/   │  │ PostgreSQL   │   │ cmd/aegisgate-platform/ │
│  (Agent,     │  │ (pgx/v5 —    │   │ main.go (dashMux,       │
│   Sessions)  │  │  existing)   │   │ authMiddleware wiring)  │
└─────────────┘  └──────────────┘   └─────────────────────────┘
```

### Data Flow

```
DISCOVERY (periodic, 60s):
  RBAC ListAgents() ─────────────────┐
  MCP SessionManager active conns ───┤
  SessionTracker active sessions ────┤──→ Registry.Discover()
  A2A middleware known agents ───────┤      │
  AIBOM generator static list ───────┤      ▼
  Correlation recent events ─────────┘  AgentRecord[] (unified)
                                              │
DORMANCY EVALUATION:                          ▼
  AgentRecord.LastActivity ──→ DormancyEngine.Evaluate()
                                    │
                                    ▼
                              LifecycleStatus transition
                              (active → dormant → quarantined → revoked)
                                    │
POLICY ENFORCEMENT:                 ▼
  LifecyclePolicy rules ──→ PolicyEngine.Enforce()
                                    │
                              ┌─────┴─────┐
                              ▼           ▼
                    Incident playbook   SOAR notify
                    (block_agent,       (PagerDuty/Jira/
                     isolate_session)    ServiceNow)
                                    │
RECONCILIATION:                     ▼
  AIBOM static ──→ Registry.Reconcile() ──→ DriftReport
  vs runtime         │
                     ▼
              "agent in AIBOM but not active"
              "agent active but not in AIBOM"
```

---

## 4. Core Types

### 4.1 AgentRecord (`pkg/agentregistry/types.go`)

The unified record that aggregates everything we know about an AI agent from all protocol layers.

```go
// AgentStatus is the lifecycle state of an AI agent.
type AgentStatus string

const (
    StatusProvisioned  AgentStatus = "provisioned"  // Registered but never active
    StatusActive       AgentStatus = "active"        // Has recent activity (within threshold)
    StatusDormant      AgentStatus = "dormant"       // No activity beyond dormancy threshold
    StatusQuarantined  AgentStatus = "quarantined"   // Isolated by policy or manual action
    StatusRevoked      AgentStatus = "revoked"       // Credentials revoked, agent disabled
)

// Protocol identifies which AI communication protocol(s) the agent uses.
type Protocol string

const (
    ProtocolHTTP  Protocol = "http"
    ProtocolMCP   Protocol = "mcp"
    ProtocolA2A   Protocol = "a2a"
    ProtocolACP   Protocol = "acp"
    ProtocolANP   Protocol = "anp"
    ProtocolUnknown Protocol = "unknown"
)

// AgentRecord is the unified view of an AI agent across all protocol layers.
// It is built by aggregating data from RBAC, MCP Session Manager, Session
// Tracker, A2A Middleware, AIBOM, Correlation Engine, and Intent Signer.
type AgentRecord struct {
    // --- Identity (from RBAC) ---
    ID          string            `json:"id"`
    Name        string            `json:"name"`
    Description string            `json:"description,omitempty"`
    Role        string            `json:"role"`           // RBAC AgentRole
    Tools       []string          `json:"tools,omitempty"` // ToolPermission list
    Enabled     bool              `json:"enabled"`
    TenantID    string            `json:"tenant_id,omitempty"`

    // --- Lifecycle (new) ---
    Status      AgentStatus       `json:"status"`
    StatusSince time.Time         `json:"status_since"`   // When current status began
    Owner       string            `json:"owner,omitempty"` // Team or individual responsible
    Tags        map[string]string `json:"tags,omitempty"`

    // --- Activity (aggregated from all sources) ---
    Protocols        []Protocol   `json:"protocols"`         // Which protocols this agent uses
    LastActivity     time.Time    `json:"last_activity"`     // Most recent across all sources
    ActiveSessions   int          `json:"active_sessions"`   // Current session count
    TotalEvents      int64        `json:"total_events"`      // Lifetime correlation events
    DormantSince     time.Time    `json:"dormant_since,omitempty"`
    CredentialExpiry time.Time    `json:"credential_expiry,omitempty"`

    // --- Intent signatures (from agentintentsign) ---
    LastIntent       string       `json:"last_intent,omitempty"`       // Last signed intent
    LastIntentAt     time.Time    `json:"last_intent_at,omitempty"`
    IntentCount      int64        `json:"intent_count"`                // Total signed intents

    // --- AIBOM reconciliation ---
    InAIBOM          bool         `json:"in_aibom"`           // Present in static AIBOM?
    AIBOMDrift       string       `json:"aibom_drift,omitempty"` // Drift description if any

    // --- Source tracking ---
    DiscoverySources []string     `json:"discovery_sources"`  // Which subsystems reported this agent
    FirstSeen        time.Time    `json:"first_seen"`
    LastSeen         time.Time    `json:"last_seen"`          // Last discovered by registry
    CreatedAt        time.Time    `json:"created_at"`         // Agent creation time (from RBAC)
    UpdatedAt        time.Time    `json:"updated_at"`         // Record last updated
}
```

### 4.2 LifecyclePolicy (`pkg/agentregistry/policy.go`)

Configurable rules that drive automated lifecycle transitions.

```go
// LifecyclePolicy defines rules for automated agent lifecycle management.
type LifecyclePolicy struct {
    ID          string        `json:"id"`
    Name        string        `json:"name"`
    Description string        `json:"description,omitempty"`
    Enabled     bool          `json:"enabled"`

    // Dormancy threshold — agents with no activity beyond this duration
    // are classified as dormant.
    DormancyThreshold time.Duration `json:"dormancy_threshold"` // e.g., 60 days

    // Auto-revocation — agents dormant beyond this duration have their
    // credentials automatically revoked.
    AutoRevokeThreshold time.Duration `json:"auto_revoke_threshold,omitempty"` // e.g., 90 days

    // Quarantine — agents dormant beyond this duration are quarantined
    // (sessions invalidated, new sessions blocked) before revocation.
    QuarantineThreshold time.Duration `json:"quarantine_threshold,omitempty"` // e.g., 75 days

    // Credential expiry — agents with credentials expiring within this
    // window are flagged for rotation.
    CredentialExpiryWarning time.Duration `json:"credential_expiry_warning,omitempty"` // e.g., 7 days

    // Actions to take when thresholds are crossed.
    OnDormant    []PolicyAction `json:"on_dormant,omitempty"`
    OnQuarantine []PolicyAction `json:"on_quarantine,omitempty"`
    OnRevoke     []PolicyAction `json:"on_revoke,omitempty"`

    // Scope — apply only to agents matching these filters.
    Filters *PolicyFilters `json:"filters,omitempty"`

    TenantID string `json:"tenant_id,omitempty"`
}

// PolicyAction is a single action to execute when a policy triggers.
type PolicyAction struct {
    Type   string            `json:"type"`    // "notify", "playbook", "quarantine", "revoke", "tag"
    Target string            `json:"target"`  // playbook ID, SOAR channel, tag key=value
    Params map[string]string `json:"params,omitempty"`
}

// PolicyFilters narrows which agents a policy applies to.
type PolicyFilters struct {
    Protocols []Protocol `json:"protocols,omitempty"`
    Roles     []string   `json:"roles,omitempty"`
    Tags      map[string]string `json:"tags,omitempty"`
    TenantIDs []string   `json:"tenant_ids,omitempty"`
}
```

### 4.3 DriftReport (`pkg/agentregistry/reconcile.go`)

Result of reconciling AIBOM static inventory against live runtime observations.

```go
// DriftReport describes discrepancies between the static AIBOM and
// the live agent registry.
type DriftReport struct {
    GeneratedAt       time.Time     `json:"generated_at"`
    InAIBOMNotActive  []DriftEntry  `json:"in_aibom_not_active"`   // Declared but not running
    ActiveNotInAIBOM  []DriftEntry  `json:"active_not_in_aibom"`   // Running but not declared
    Matched           int           `json:"matched"`               // In both, no drift
    TotalAIBOM        int           `json:"total_aibom"`
    TotalActive       int           `json:"total_active"`
}

type DriftEntry struct {
    AgentID    string    `json:"agent_id"`
    AgentName  string    `json:"agent_name,omitempty"`
    Protocol   Protocol  `json:"protocol,omitempty"`
    LastSeen   time.Time `json:"last_seen,omitempty"`
    Note       string    `json:"note,omitempty"`
}
```

### 4.4 DormancyReport (`pkg/agentregistry/dormancy.go`)

```go
// DormancyReport summarizes the dormancy state of all agents.
type DormancyReport struct {
    GeneratedAt  time.Time              `json:"generated_at"`
    Total        int                    `json:"total_agents"`
    Active       int                    `json:"active"`
    Dormant      int                    `json:"dormant"`
    Quarantined  int                    `json:"quarantined"`
    Revoked      int                    `json:"revoked"`
    Provisioned  int                    `json:"provisioned"`
    Agents       []DormancyEntry        `json:"agents"`
}

type DormancyEntry struct {
    AgentID      string        `json:"agent_id"`
    Name         string        `json:"name"`
    Status       AgentStatus   `json:"status"`
    LastActivity time.Time     `json:"last_activity"`
    DormantFor   time.Duration `json:"dormant_for"`      // How long dormant
    Protocols    []Protocol    `json:"protocols"`
    Owner        string        `json:"owner,omitempty"`
    ActiveSessions int         `json:"active_sessions"`
}
```

---

## 5. Core Components

### 5.1 Registry (`pkg/agentregistry/registry.go`)

The central aggregator. Discovers agents from all protocol layers, builds AgentRecords, and maintains the live inventory.

```go
// Registry is the unified AI agent inventory. It aggregates agent identity,
// activity, and lifecycle state from all protocol subsystems.
type Registry struct {
    mu          sync.RWMutex
    records     map[string]*AgentRecord  // keyed by AgentID
    store       Store                     // PostgreSQL or in-memory
    rbac        *rbac.Manager
    mcpSessions *mcpserver.ConnectionSessionManager
    tracker     *scanner.SessionTracker
    a2aAgents   A2AAgentSource            // interface (see 5.1.1)
    aibomGen    *aibom.Generator
    correlation CorrelationSource          // interface
    intentStore IntentSource               // interface
    policy      *PolicyEngine
    dormancy    *DormancyEngine
    logger      *slog.Logger
    refreshInterval time.Duration
    stopCh      chan struct{}
}

// Discover scans all protocol layers and builds a unified agent inventory.
// This is the primary entry point — called on startup and periodically
// by the background refresh goroutine.
func (r *Registry) Discover(ctx context.Context) error

// Refresh is a lightweight re-discovery that updates activity timestamps
// and session counts without rebuilding the full registry from scratch.
func (r *Registry) Refresh(ctx context.Context) error

// Reconcile compares the live registry against the AIBOM static inventory
// and returns a drift report.
func (r *Registry) Reconcile(ctx context.Context) (*DriftReport, error)

// Get returns a single agent record by ID.
func (r *Registry) Get(agentID string) (*AgentRecord, error)

// List returns all agent records, optionally filtered.
func (r *Registry) List(filter *ListFilter) ([]*AgentRecord, error)

// ListByStatus returns agents with the given lifecycle status.
func (r *Registry) ListByStatus(status AgentStatus) ([]*AgentRecord, error)

// Transition manually changes an agent's lifecycle status.
func (r *Registry) Transition(agentID string, newStatus AgentStatus) error

// Start launches the background refresh goroutine.
func (r *Registry) Start(ctx context.Context) error

// Stop shuts down the background refresh goroutine.
func (r *Registry) Stop()
```

#### 5.1.1 Interface Abstractions for Testability

To avoid hard coupling and enable unit testing without spinning up all subsystems, the Registry depends on narrow interfaces rather than concrete types:

```go
// A2AAgentSource provides A2A agent identities discovered via mTLS.
type A2AAgentSource interface {
    KnownAgents() []A2AAgentInfo
}

type A2AAgentInfo struct {
    AgentID      string
    Capabilities []string
    LastSeen     time.Time
}

// CorrelationSource provides recent correlation events for activity tracking.
type CorrelationSource interface {
    RecentEventsByAgent(agentID string, since time.Time) ([]CorrelationEventInfo, error)
    AgentEventCount(agentID string) (int64, error)
}

type CorrelationEventInfo struct {
    EventType  string
    Severity   string
    Timestamp  time.Time
    Protocol   string
    SessionID  string
}

// IntentSource provides signed intent information for agents.
type IntentSource interface {
    LatestIntent(agentID string) (*IntentInfo, error)
    IntentCount(agentID string) (int64, error)
}

type IntentInfo struct {
    Intent      string
    Justification string
    ValidUntil  time.Time
    SignedAt    time.Time
}
```

These interfaces are satisfied by adapter structs that wrap the existing packages. The adapters are ~50-100 LOC each and live in `pkg/agentregistry/adapters.go`.

### 5.2 DormancyEngine (`pkg/agentregistry/dormancy.go`)

Evaluates agent activity against configurable thresholds and transitions lifecycle status.

```go
// DormancyEngine evaluates agent activity patterns and classifies
// agents into lifecycle states based on configurable thresholds.
type DormancyEngine struct {
    defaultThreshold time.Duration  // Default dormancy threshold (e.g., 60 days)
    logger           *slog.Logger
}

// Evaluate checks a single agent record against dormancy thresholds
// and returns the recommended status transition (if any).
func (d *DormancyEngine) Evaluate(record *AgentRecord, policy *LifecyclePolicy) (AgentStatus, time.Duration)

// Classify runs Evaluate across all records and returns a dormancy report.
func (d *DormancyEngine) Classify(records []*AgentRecord, policy *LifecyclePolicy) *DormancyReport
```

The evaluation logic:
1. If `LastActivity` is zero → `StatusProvisioned` (registered but never used)
2. If `LastActivity` is within `DormancyThreshold` → `StatusActive`
3. If `LastActivity` exceeds `DormancyThreshold` but not `QuarantineThreshold` → `StatusDormant`
4. If `LastActivity` exceeds `QuarantineThreshold` but not `AutoRevokeThreshold` → `StatusQuarantined`
5. If `LastActivity` exceeds `AutoRevokeThreshold` → `StatusRevoked`

### 5.3 PolicyEngine (`pkg/agentregistry/policy.go`)

Enforces lifecycle policies by executing actions when thresholds are crossed.

```go
// PolicyEngine evaluates lifecycle policies against agent records
// and executes actions (notify, quarantine, revoke, playbook).
type PolicyEngine struct {
    policies       []LifecyclePolicy
    incidentEngine *incident.Engine   // For triggering playbooks
    soarManager    *soar.Manager       // For notifications
    rbacManager    *rbac.Manager       // For credential revocation
    registry       *Registry           // For status transitions
    logger         *slog.Logger
}

// Enforce evaluates all enabled policies against the current registry
// and executes actions for any threshold violations.
func (p *PolicyEngine) Enforce(ctx context.Context) ([]PolicyEnforcementResult, error)

// AddPolicy adds or updates a lifecycle policy.
func (p *PolicyEngine) AddPolicy(policy *LifecyclePolicy) error

// RemovePolicy removes a policy by ID.
func (p *PolicyEngine) RemovePolicy(policyID string) error

// ListPolicies returns all configured policies.
func (p *PolicyEngine) ListPolicies() []LifecyclePolicy
```

PolicyAction execution maps to existing capabilities:
- `"notify"` → `pkg/soar/` (PagerDuty, Jira, ServiceNow, webhooks)
- `"playbook"` → `pkg/incident/` (trigger playbook by ID, e.g., "dormant_agent_detected")
- `"quarantine"` → `rbacMgr.InvalidateAgentSessions(agentID)` (already wired in incident_callbacks.go)
- `"revoke"` → `rbacMgr.DisableAgent(agentID)` + `rbacMgr.InvalidateAgentSessions(agentID)`
- `"tag"` → Add tag to AgentRecord (e.g., `flagged-for-review=true`)

### 5.4 Store Interface (`pkg/agentregistry/store.go`)

```go
// Store persists agent registry records.
type Store interface {
    Get(ctx context.Context, agentID string) (*AgentRecord, error)
    List(ctx context.Context, filter *ListFilter) ([]*AgentRecord, error)
    Upsert(ctx context.Context, record *AgentRecord) error
    Delete(ctx context.Context, agentID string) error
    Close() error
}
```

Two implementations:

**InMemoryStore** (`pkg/agentregistry/memory_store.go`):
- `sync.RWMutex` + `map[string]*AgentRecord`
- ~150 LOC
- Used when PostgreSQL is not available (Community/Developer tiers, air-gapped without DB)

**PostgresStore** (`pkg/agentregistry/postgres_store.go`):
- Uses `github.com/jackc/pgx/v5` (already in go.mod)
- New table: `agent_registry` (see §6)
- RLS-aware (follows `ioc.WithTenantContextOrPool` pattern from `pkg/rbac/postgres_store.go`)
- ~400 LOC

---

## 6. Database Schema

```sql
CREATE TABLE IF NOT EXISTS agent_registry (
    id                  TEXT        PRIMARY KEY,
    name                TEXT        NOT NULL,
    description         TEXT        DEFAULT '',
    role                TEXT        NOT NULL,
    tools               JSONB       DEFAULT '[]',
    enabled             BOOLEAN     DEFAULT true,
    tenant_id           TEXT        DEFAULT '',

    -- Lifecycle
    status              TEXT        NOT NULL DEFAULT 'provisioned',
    status_since        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    owner               TEXT        DEFAULT '',
    tags                JSONB       DEFAULT '{}',

    -- Activity
    protocols           JSONB       DEFAULT '[]',
    last_activity       TIMESTAMPTZ,
    active_sessions     INTEGER     DEFAULT 0,
    total_events        BIGINT      DEFAULT 0,
    dormant_since       TIMESTAMPTZ,
    credential_expiry   TIMESTAMPTZ,

    -- Intent
    last_intent         TEXT        DEFAULT '',
    last_intent_at      TIMESTAMPTZ,
    intent_count        BIGINT      DEFAULT 0,

    -- AIBOM
    in_aibom            BOOLEAN     DEFAULT false,
    aibom_drift         TEXT        DEFAULT '',

    -- Source tracking
    discovery_sources   JSONB       DEFAULT '[]',
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_agent_registry_status      ON agent_registry(status);
CREATE INDEX IF NOT EXISTS idx_agent_registry_tenant      ON agent_registry(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_registry_last_active ON agent_registry(last_activity);
CREATE INDEX IF NOT EXISTS idx_agent_registry_owner       ON agent_registry(owner);

-- Lifecycle policies table
CREATE TABLE IF NOT EXISTS agent_lifecycle_policies (
    id                          TEXT        PRIMARY KEY,
    name                        TEXT        NOT NULL,
    description                 TEXT        DEFAULT '',
    enabled                     BOOLEAN     DEFAULT true,
    dormancy_threshold_seconds  BIGINT      NOT NULL,
    auto_revoke_threshold_seconds BIGINT    DEFAULT 0,
    quarantine_threshold_seconds  BIGINT    DEFAULT 0,
    credential_expiry_warning_seconds BIGINT DEFAULT 0,
    on_dormant                  JSONB       DEFAULT '[]',
    on_quarantine               JSONB       DEFAULT '[]',
    on_revoke                   JSONB       DEFAULT '[]',
    filters                     JSONB       DEFAULT '{}',
    tenant_id                   TEXT        DEFAULT '',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lifecycle_policies_tenant ON agent_lifecycle_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_lifecycle_policies_enabled ON agent_lifecycle_policies(enabled);
```

---

## 7. HTTP API

All endpoints are mounted on the existing `dashMux` in `cmd/aegisgate-platform/main.go`, following the same pattern as existing handlers (see `wireIncidentHandlers`, `wireAIBOMHandlers`, etc.).

Wiring function: `wireAgentRegistryHandlers(dashMux, authMiddleware, registry, policyEngine)`

### Endpoints

| Method | Path | Description | Permission |
|--------|------|-------------|------------|
| `GET` | `/api/v1/agents` | List all agents (with optional filters) | `rbac.PermAgentRead` |
| `GET` | `/api/v1/agents/{id}` | Get single agent detail | `rbac.PermAgentRead` |
| `POST` | `/api/v1/agents/{id}/lifecycle` | Manual status transition | `rbac.PermAgentManage` |
| `GET` | `/api/v1/agents/dormancy` | Dormancy report | `rbac.PermAgentRead` |
| `GET` | `/api/v1/agents/drift` | AIBOM reconciliation report | `rbac.PermAgentRead` |
| `GET` | `/api/v1/agents/policies` | List lifecycle policies | `rbac.PermAgentRead` |
| `POST` | `/api/v1/agents/policies` | Create/update policy | `rbac.PermAgentManage` |
| `DELETE` | `/api/v1/agents/policies/{id}` | Delete policy | `rbac.PermAgentManage` |
| `POST` | `/api/v1/agents/refresh` | Trigger manual discovery refresh | `rbac.PermAgentManage` |

### New RBAC Permissions

Add to `pkg/rbac/types.go`:

```go
PermAgentRead   ToolPermission = "agent:read"    // View agent inventory
PermAgentManage ToolPermission = "agent:manage"  // Transition lifecycle, manage policies
```

Map to roles:
- `PermAgentRead` → Viewer, Analyst, Operator, Admin
- `PermAgentManage` → Operator, Admin

### Query Parameters for `GET /api/v1/agents`

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by lifecycle status (active, dormant, quarantined, revoked, provisioned) |
| `protocol` | string | Filter by protocol (http, mcp, a2a, acp, anp) |
| `owner` | string | Filter by owner |
| `tag` | string | Filter by tag (key=value) |
| `tenant_id` | string | Filter by tenant (admin only) |

### SSE Integration

Extend `pkg/soc/stream.go` with new event types:

```go
StreamEventAgentLifecycle  StreamEventType = "agent_lifecycle"    // Status transition
StreamEventAgentDiscovered StreamEventType = "agent_discovered"   // New agent found
StreamEventAgentDormant    StreamEventType = "agent_dormant"      // Agent went dormant
StreamEventAgentRevoked    StreamEventType = "agent_revoked"      // Agent credentials revoked
StreamEventAgentDrift      StreamEventType = "agent_drift"        // AIBOM drift detected
```

The Registry emits these events via a callback (same pattern as `incident.Engine` callbacks), which the SOC stream subscribes to.

---

## 8. Incident Playbook

New built-in playbook in `pkg/incident/playbooks.go`:

```go
{
    ID:          "dormant_agent_detected",
    Name:        "Dormant Agent Response",
    Description: "Automated response when an agent exceeds dormancy thresholds",
    Severity:    SeverityLow,
    Steps: []PlaybookStep{
        {
            Name:   "notify_owner",
            Action: "notify",
            Params: map[string]string{
                "channel":   "email",
                "template":  "dormant_agent_alert",
                "severity":  "warning",
            },
        },
        {
            Name:   "collect_evidence",
            Action: "collect_evidence",
            Params: map[string]string{
                "include_session_history": "true",
                "include_intent_log":      "true",
            },
        },
        {
            Name:   "create_attestation",
            Action: "create_attestation",
            Params: map[string]string{
                "attestation_type": "lifecycle_transition",
            },
        },
    },
    // Conditional steps based on severity:
    // - If quarantined: add block_agent step
    // - If revoked: add block_agent + create_attestation steps
}
```

This playbook is triggered by the PolicyEngine when a dormancy threshold is crossed. It follows the exact same pattern as the existing 14 playbooks — uses the same `PlaybookStep` struct, same `executeBlockAgent`/`executeIsolateSession`/`executeCollectEvidence`/`executeCreateAttestation` functions, and is wired through the same incident engine callbacks.

---

## 9. Tier Integration

### Feature Gate (`pkg/tier/tier.go`)

Add new feature constant:

```go
// v5.0.0: Agent Registry — unified AI agent inventory, lifecycle management,
// and credential auto-revocation. Gated to Professional+ as a patented
// capability (patent #8 candidate). No Community/Developer access.
FeatureAgentRegistry Feature = "agent_registry"
```

Add to Professional tier in `RequiredTier()`:

```go
case ...:
    FeatureTrustPillar,
    FeatureIncident, FeatureEvidence, FeatureA2A, FeatureACP,
    FeatureFederatedIOC, FeatureAttestation, FeaturePosture,
    FeatureDigest, FeatureAgentIntentSign, FeatureSOCStream,
    FeatureTrustPortal, FeatureComputerUse,
    FeatureAgentRegistry:  // NEW
    return TierProfessional
```

Add to `featureKeyMap`:

```go
"agent_registry": FeatureAgentRegistry,
```

### Feature Check in HTTP Handlers

All agent registry HTTP handlers check tier access via the existing middleware pattern:

```go
dashMux.HandleFunc("/api/v1/agents", authMiddleware.RequirePermission(
    rbac.Permission{Resource: rbac.ResourceAgent, Action: rbac.ActionRead},
    tierMiddleware.RequireFeature(tier.FeatureAgentRegistry,
        func(w http.ResponseWriter, r *http.Request) {
            // handler
        },
    ),
))
```

This follows the exact same pattern used by incident handlers, AIBOM handlers, and other tier-gated features.

---

## 10. Configuration

Add to `pkg/platformconfig/config.go`:

```go
type AgentRegistryConfig struct {
    Enabled          bool          `yaml:"enabled" json:"enabled"`
    RefreshInterval  time.Duration `yaml:"refresh_interval" json:"refresh_interval"` // default 60s
    DefaultDormancy  time.Duration `yaml:"default_dormancy" json:"default_dormancy"` // default 60 days
    AutoRevoke       time.Duration `yaml:"auto_revoke" json:"auto_revoke"`           // default 90 days
    QuarantineFirst  bool          `yaml:"quarantine_first" json:"quarantine_first"` // default true
}
```

Default config:
```yaml
agent_registry:
  enabled: true
  refresh_interval: 60s
  default_dormancy: 1440h        # 60 days
  auto_revoke: 2160h             # 90 days
  quarantine_first: true
```

---

## 11. Wiring in main.go

The Registry is initialized in `cmd/aegisgate-platform/main.go` during startup, after RBAC, MCP, A2A, correlation, and incident engine are all initialized:

```go
// After incident engine wiring (around line 1925):

// Agent Registry (v5.0)
var agentRegistry *agentregistry.Registry
if tier.HasFeature(currentTier, tier.FeatureAgentRegistry) {
    agentRegistry, err = agentregistry.New(
        agentregistry.Config{
            RBAC:           rbacMgr,
            MCPSessions:    mcpSessionMgr,
            Tracker:        sessionTracker,
            A2ASource:      agentregistry.NewA2AAdapter(a2aMiddleware),
            AIBOMGenerator: aibomGen,
            Correlation:    agentregistry.NewCorrelationAdapter(correlationEngine),
            IntentSource:   agentregistry.NewIntentAdapter(intentSigner),
            Store:          agentRegistryStore,  // PostgresStore or InMemoryStore
            RefreshInterval: cfg.AgentRegistry.RefreshInterval,
            Logger:         logger,
        },
    )
    if err != nil {
        log.Fatalf("Failed to initialize agent registry: %v", err)
    }

    // Wire policy engine
    policyEngine := agentregistry.NewPolicyEngine(
        agentRegistry,
        incidentEngine,
        soarManager,
        rbacMgr,
        logger,
    )

    // Wire HTTP handlers
    wireAgentRegistryHandlers(dashMux, authMiddleware, agentRegistry, policyEngine)

    // Wire SSE events
    agentRegistry.OnLifecycleEvent(socStream.BroadcastAgentEvent)

    // Start background refresh
    if err := agentRegistry.Start(ctx); err != nil {
        log.Printf("⚠️  Agent registry background refresh failed to start: %v", err)
    }
}
```

Store initialization (following existing PostgreSQL pattern):
```go
var agentRegistryStore agentregistry.Store
if pgStore != nil {
    agentRegistryStore, err = agentregistry.NewPostgresStore(pgStore, nil)
    if err != nil {
        log.Printf("⚠️  Agent registry PostgreSQL init failed: %v — using in-memory", err)
        agentRegistryStore = agentregistry.NewInMemoryStore()
    }
} else {
    agentRegistryStore = agentregistry.NewInMemoryStore()
}
```

---

## 12. File Structure

```
pkg/agentregistry/
├── doc.go                      # Package documentation (patent-grade)
├── types.go                    # AgentRecord, AgentStatus, Protocol, etc.
├── registry.go                 # Registry core (Discover, Refresh, Reconcile, Get, List)
├── dormancy.go                 # DormancyEngine (Evaluate, Classify)
├── policy.go                   # PolicyEngine (Enforce, AddPolicy, ListPolicies)
├── reconcile.go                # AIBOM reconciliation (DriftReport)
├── adapters.go                 # Interface adapters for A2A, Correlation, Intent sources
├── store.go                    # Store interface
├── memory_store.go             # In-memory store (fallback)
├── postgres_store.go           # PostgreSQL store (pgx/v5)
├── http.go                     # HTTP handlers (wired via wireAgentRegistryHandlers)
├── sse.go                      # SSE event emission helpers
├── registry_test.go            # Core registry tests
├── dormancy_test.go            # Dormancy engine tests
├── policy_test.go              # Policy engine tests
├── reconcile_test.go           # Reconciliation tests
├── memory_store_test.go        # In-memory store tests
├── postgres_store_test.go      # PostgreSQL store tests (testcontainers)
└── http_test.go                # HTTP handler tests
```

---

## 13. Implementation Phases

### Phase 1: Registry Core (Days 1-4)

| File | Est. LOC | Description |
|------|----------|-------------|
| `doc.go` | ~80 | Package documentation |
| `types.go` | ~120 | AgentRecord, AgentStatus, Protocol, ListFilter |
| `store.go` | ~40 | Store interface |
| `memory_store.go` | ~150 | In-memory store implementation |
| `adapters.go` | ~200 | A2A, Correlation, Intent adapters |
| `registry.go` | ~500 | Registry core: Discover, Refresh, Reconcile, Get, List, Transition, Start, Stop |
| `registry_test.go` | ~600 | Unit tests for registry |
| `memory_store_test.go` | ~200 | In-memory store tests |
| **Phase 1 total** | **~1,890** | |

**Deliverable:** Registry discovers agents from RBAC + MCP + Session Tracker + A2A + AIBOM + Correlation and maintains unified records. In-memory store works. Background refresh goroutine runs.

### Phase 2: Dormancy & Policies (Days 5-7)

| File | Est. LOC | Description |
|------|----------|-------------|
| `dormancy.go` | ~150 | DormancyEngine: Evaluate, Classify |
| `policy.go` | ~300 | PolicyEngine: Enforce, AddPolicy, RemovePolicy, ListPolicies |
| `reconcile.go` | ~100 | AIBOM reconciliation: DriftReport |
| New playbook in `pkg/incident/playbooks.go` | ~50 | dormant_agent_detected playbook |
| `dormancy_test.go` | ~300 | Dormancy evaluation tests |
| `policy_test.go` | ~400 | Policy enforcement tests |
| `reconcile_test.go` | ~200 | Reconciliation tests |
| **Phase 2 total** | **~1,500** | |

**Deliverable:** Dormancy detection works. Policies enforce automatically (notify, quarantine, revoke). AIBOM reconciliation detects drift. New incident playbook triggers on dormancy.

### Phase 3: HTTP API & SSE (Days 8-10)

| File | Est. LOC | Description |
|------|----------|-------------|
| `http.go` | ~400 | 9 REST endpoints |
| `sse.go` | ~100 | SSE event helpers |
| New StreamEventTypes in `pkg/soc/stream.go` | ~30 | 5 new event types |
| New RBAC permissions in `pkg/rbac/types.go` | ~20 | PermAgentRead, PermAgentManage |
| `http_test.go` | ~400 | HTTP handler tests |
| **Phase 3 total** | **~950** | |

**Deliverable:** Full REST API. SSE streams agent lifecycle events to SOC dashboards.

### Phase 4: PostgreSQL Store (Days 11-12)

| File | Est. LOC | Description |
|------|----------|-------------|
| `postgres_store.go` | ~400 | PostgreSQL store with RLS |
| SQL migration | ~60 | agent_registry + agent_lifecycle_policies tables |
| `postgres_store_test.go` | ~400 | PostgreSQL integration tests (testcontainers) |
| **Phase 4 total** | **~860** | |

**Deliverable:** PostgreSQL persistence works. In-memory fallback works. RLS-aware tenant isolation.

### Phase 5: Integration & Polish (Days 13-16)

| Task | Est. LOC | Description |
|------|----------|-------------|
| `main.go` wiring | ~80 | Registry init, store init, handler wiring, background start |
| `pkg/tier/tier.go` | ~15 | FeatureAgentRegistry gate |
| `pkg/platformconfig/config.go` | ~30 | AgentRegistryConfig |
| `pkg/incident/playbooks.go` | ~50 | dormant_agent_detected playbook |
| `cmd/aegisgate-platform/agent_registry_http.go` | ~100 | Wiring helpers |
| Version bump (v5.0.0) | ~10 | VERSION, CHANGELOG, README |
| Integration tests | ~300 | End-to-end: discover → dormancy → policy → playbook → SOAR |
| Documentation | ~200 | doc.go, README section |
| **Phase 5 total** | **~985** | |

### Total Estimate

| Phase | Production LOC | Test LOC | Total |
|-------|---------------|----------|-------|
| 1: Registry Core | ~1,190 | ~800 | ~1,990 |
| 2: Dormancy & Policies | ~600 | ~900 | ~1,500 |
| 3: HTTP API & SSE | ~550 | ~400 | ~950 |
| 4: PostgreSQL Store | ~460 | ~400 | ~860 |
| 5: Integration & Polish | ~485 | ~300 | ~785 |
| **Total** | **~3,285** | **~2,800** | **~6,085** |

### Timeline (with buffer)

| Phase | Working Days |
|-------|-------------|
| 1: Registry Core | 3-4 |
| 2: Dormancy & Policies | 2-3 |
| 3: HTTP API & SSE | 2-3 |
| 4: PostgreSQL Store | 2 |
| 5: Integration & Polish | 3-4 |
| Buffer (edge cases, debugging) | 2-3 |
| **Total** | **14-19 days (~3 weeks)** |

---

## 14. Existing Code That Will Be Modified

| File | Change | LOC delta |
|------|--------|-----------|
| `pkg/tier/tier.go` | Add `FeatureAgentRegistry` constant, add to Professional tier, add to featureKeyMap | +15 |
| `pkg/rbac/types.go` | Add `PermAgentRead`, `PermAgentManage` permissions, map to roles | +20 |
| `pkg/incident/playbooks.go` | Add `dormant_agent_detected` playbook | +50 |
| `pkg/soc/stream.go` | Add 5 new `StreamEventType` constants | +10 |
| `pkg/platformconfig/config.go` | Add `AgentRegistryConfig` struct | +30 |
| `cmd/aegisgate-platform/main.go` | Registry init, store init, handler wiring, background start | +80 |
| `cmd/aegisgate-platform/agent_registry_http.go` (new) | `wireAgentRegistryHandlers` wiring function | +100 |
| `VERSION` | `4.9.0` → `5.0.0` | +1 |
| `CHANGELOG.md` | v5.0.0 entry | +30 |
| `README.md` | Agent Registry section, pattern count update | +50 |

**Total modifications to existing files: ~386 LOC**

---

## 15. Compliance & Standards

### Zero External Dependencies
- **All new code** uses only: existing AegisGate packages, Go stdlib, `github.com/jackc/pgx/v5` (already in go.mod), `github.com/google/uuid` (already in go.mod).
- **Zero new entries** in go.mod.
- **testcontainers** used only in `_test.go` files (not in production binary).

### Air-Gap-Ready
- PostgreSQL is optional (in-memory fallback).
- Zero network egress — all data sources are internal.
- No telemetry, no phone-home, no external API calls.
- Configuration is file-based (YAML), no cloud dependencies.

### Existing Code Quality Standards
- All public functions documented with godoc comments.
- All exported types have JSON tags.
- Error wrapping with `fmt.Errorf("...: %w", err)`.
- Context propagation on all database operations.
- Tenant isolation via RLS (PostgreSQL) and app-layer filtering (in-memory).
- Structured logging via `slog.Logger`.

---

## 16. Patent Strategy

**Candidate:** Patent #8 — "System and Method for Unified AI Agent Inventory, Lifecycle Management, and Credential Auto-Revocation Across Multiple AI Communication Protocols"

**Novel claims:**
1. Cross-protocol AI agent discovery (HTTP, MCP, A2A, ACP, ANP) unified into single registry
2. AIBOM-to-runtime reconciliation for inventory drift detection
3. AI agent dormancy detection with configurable thresholds
4. Automated credential revocation based on dormancy policies
5. Lifecycle state machine (provisioned → active → dormant → quarantined → revoked)
6. Cryptographic intent signature binding for lifecycle transitions (extends Patent #1)
7. Federated agent inventory across clusters (extends Patent #7)

**Filing timeline:** AFTER the feature is built, tested, and demonstrated working. The provisional patent application will reference working code as evidence of reduction to practice.

**Builds on existing patents:**
- Patent #1 (Trust Framework): Agent identity used in registry records
- Patent #2 (Multi-Protocol Interception): All 5 protocol layers feed discovery
- Patent #7 (Federated Detection Gap): Federated inventory extends gap analysis

---

## 17. Testing Strategy

### Unit Tests
- `registry_test.go`: Discovery from each source, record aggregation, refresh logic, background goroutine lifecycle
- `dormancy_test.go`: Each status transition (provisioned→active→dormant→quarantined→revoked), threshold edge cases, zero-activity agents
- `policy_test.go`: Policy enforcement for each action type (notify, quarantine, revoke, playbook, tag), filter matching, multiple policies
- `reconcile_test.go`: AIBOM drift detection (present in AIBOM but not active, active but not in AIBOM, matched), empty AIBOM, empty registry
- `memory_store_test.go`: CRUD, concurrent access, filtering
- `http_test.go`: All 9 endpoints, permission checks, tier gating, query parameters

### Integration Tests
- `postgres_store_test.go`: Using testcontainers (same pattern as existing PostgreSQL stores), RLS isolation, schema migration
- End-to-end test: Register agent in RBAC → Create MCP session → Run correlation event → Trigger discovery → Verify record has all sources → Let dormancy threshold pass → Verify status transition → Verify policy action executed

### Test Data
- Mock implementations of `A2AAgentSource`, `CorrelationSource`, `IntentSource` interfaces
- Test agents with varied activity patterns (active, dormant, never-used, recently-revoked)
- Test policies with various thresholds and action combinations

---

## 18. What This Feature Does NOT Do

To maintain clarity and avoid scope creep:

1. **Does NOT replace RBAC** — The Registry reads from RBAC; it does not modify the RBAC Agent struct. Credential revocation is performed BY calling existing RBAC methods (`InvalidateAgentSessions`, `DisableAgent`).

2. **Does NOT replace AIBOM** — The Registry reads AIBOM output and reconciles it against runtime state. AIBOM remains the static bill of materials.

3. **Does NOT add new detection patterns** — No new regex, ML, or anomaly detection. The Registry aggregates existing detection events for activity tracking.

4. **Does NOT create a new UI framework** — HTTP API returns JSON. Dashboard rendering is handled by the existing trust portal or external SOC dashboards via the REST API.

5. **Does NOT add new protocol interception** — Uses the 5 existing protocol layers. No new protocols.

6. **Does NOT implement its own notification system** — Uses `pkg/soar/` (PagerDuty, Jira, ServiceNow, webhooks) for notifications.

7. **Does NOT implement its own incident response engine** — Uses `pkg/incident/` engine and playbooks.

8. **Does NOT touch Lens, Scanner, Rampart, or MCP SDK** — Platform-only feature.