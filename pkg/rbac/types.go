// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — RBAC Types
// =========================================================================
//
// Role-Based Access Control type definitions for both AI agents and human
// dashboard users. Adapted from AegisGuard's agent-centric RBAC with the
// addition of human user roles, resource-based permissions, and user sessions.
// =========================================================================

package rbac

import (
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// USER ROLES (Dashboard / API access)
// ============================================================================

// UserRole represents a human user's authorization level for dashboard/API
type UserRole string

const (
	// UserRoleViewer - Read-only access to dashboards and reports
	UserRoleViewer UserRole = "viewer"
	// UserRoleAnalyst - Can run scans and view compliance reports
	UserRoleAnalyst UserRole = "analyst"
	// UserRoleAdmin - Full access within tier boundaries
	UserRoleAdmin UserRole = "admin"
	// UserRoleComplianceOfficer - Access to compliance reports and audit data
	UserRoleComplianceOfficer UserRole = "compliance_officer"
)

// AtLeast returns true if this role has at least the required level
func (r UserRole) AtLeast(required UserRole) bool {
	roleLevel := map[UserRole]int{
		UserRoleViewer:            1,
		UserRoleAnalyst:           2,
		UserRoleComplianceOfficer: 3,
		UserRoleAdmin:             4,
	}
	return roleLevel[r] >= roleLevel[required]
}

// String returns the string representation of the user role
func (r UserRole) String() string {
	return string(r)
}

// ParseUserRole parses a string into a UserRole, returning Viewer as default
func ParseUserRole(s string) UserRole {
	switch s {
	case "viewer":
		return UserRoleViewer
	case "analyst":
		return UserRoleAnalyst
	case "admin":
		return UserRoleAdmin
	case "compliance_officer":
		return UserRoleComplianceOfficer
	default:
		return UserRoleViewer
	}
}

// ============================================================================
// AGENT ROLES (MCP tool authorization)
// ============================================================================

// AgentRole represents an AI agent's authorization level
type AgentRole string

const (
	// AgentRoleRestricted - Minimal tools (read-only, no execution)
	AgentRoleRestricted AgentRole = "restricted"
	// AgentRoleStandard - Common development tools
	AgentRoleStandard AgentRole = "standard"
	// AgentRolePrivileged - Sensitive operations with approval
	AgentRolePrivileged AgentRole = "privileged"
	// AgentRoleAdmin - Full access, all tools
	AgentRoleAdmin AgentRole = "admin"
)

// AtLeast returns true if this role has at least the required level
func (r AgentRole) AtLeast(required AgentRole) bool {
	roleLevel := map[AgentRole]int{
		AgentRoleRestricted: 1,
		AgentRoleStandard:   2,
		AgentRolePrivileged: 3,
		AgentRoleAdmin:      4,
	}
	return roleLevel[r] >= roleLevel[required]
}

// String returns the string representation of the agent role
func (r AgentRole) String() string {
	return string(r)
}

// ============================================================================
// RESOURCES AND ACTIONS (resource-based access control)
// ============================================================================

// Resource represents a protected resource in the platform
type Resource string

const (
	ResourceConfig     Resource = "config"
	ResourceAudit      Resource = "audit"
	ResourceCompliance Resource = "compliance"
	ResourceAgent      Resource = "agent"
	ResourceTool       Resource = "tool"
	ResourceLicense    Resource = "license"
	ResourceDashboard  Resource = "dashboard"
	ResourcePolicy     Resource = "policy"
	ResourceMetrics    Resource = "metrics"
	ResourceUser       Resource = "user"
	ResourceSession    Resource = "session"
)

// Action represents an operation on a resource
type Action string

const (
	ActionRead    Action = "read"
	ActionWrite   Action = "write"
	ActionDelete  Action = "delete"
	ActionExecute Action = "execute"
	ActionManage  Action = "manage"
)

// Permission represents a resource+action access right
type Permission struct {
	Resource Resource `json:"resource"`
	Action   Action   `json:"action"`
}

// String returns "resource:action" format
func (p Permission) String() string {
	return string(p.Resource) + ":" + string(p.Action)
}

// ParsePermission parses "resource:action" into a Permission
func ParsePermission(s string) Permission {
	for i, c := range s {
		if c == ':' {
			return Permission{
				Resource: Resource(s[:i]),
				Action:   Action(s[i+1:]),
			}
		}
	}
	return Permission{Resource: Resource(s), Action: ActionRead}
}

// ============================================================================
// TOOL PERMISSIONS (MCP authorization)
// ============================================================================

// ToolPermission represents a specific tool authorization permission
type ToolPermission string

const (
	// File operations
	PermToolFileRead   ToolPermission = "tool:file:read"
	PermToolFileWrite  ToolPermission = "tool:file:write"
	PermToolFileDelete ToolPermission = "tool:file:delete"
	PermToolFileExists ToolPermission = "tool:file:exists"

	// Web operations
	PermToolWebSearch   ToolPermission = "tool:web:search"
	PermToolHTTPRequest ToolPermission = "tool:http:request"
	PermToolJSONFetch   ToolPermission = "tool:json:fetch"

	// Shell operations (HIGH RISK)
	PermToolShellCommand ToolPermission = "tool:shell:command"
	PermToolBash         ToolPermission = "tool:bash"
	PermToolPing         ToolPermission = "tool:ping"

	// Code operations
	PermToolCodeExecuteGo         ToolPermission = "tool:code:execute:go"
	PermToolCodeExecutePython     ToolPermission = "tool:code:execute:python"
	PermToolCodeExecuteJavaScript ToolPermission = "tool:code:execute:javascript"
	PermToolCodeSearch            ToolPermission = "tool:code:search"

	// Database operations
	PermToolDatabaseQuery  ToolPermission = "tool:database:query"
	PermToolDatabaseList   ToolPermission = "tool:database:list"
	PermToolDatabaseSchema ToolPermission = "tool:database:schema"

	// Admin permissions
	PermToolAll     ToolPermission = "tool:*"
	PermAdminManage ToolPermission = "admin:manage"
	PermAdminAudit  ToolPermission = "admin:audit"
	PermAdminConfig ToolPermission = "admin:config"
)

// ============================================================================
// USER TYPE
// ============================================================================

// User represents a human dashboard/API user
type User struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Email       string                 `json:"email"`
	Role        UserRole               `json:"role"`
	Permissions []Permission           `json:"permissions,omitempty"`
	Tags        map[string]string      `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// HasPermission checks if the user has a specific resource:action permission
func (u *User) HasPermission(perm Permission) bool {
	for _, p := range u.Permissions {
		if p == perm {
			return true
		}
		// Check wildcard: resource:* matches any action on that resource
		if p.Resource == perm.Resource && p.Action == "*" {
			return true
		}
		// Check wildcard: *:action matches that action on any resource
		if p.Resource == "*" && p.Action == perm.Action {
			return true
		}
		// Full wildcard
		if p.Resource == "*" && p.Action == "*" {
			return true
		}
	}
	return false
}

// HasRole checks if the user has a specific role
func (u *User) HasRole(role UserRole) bool {
	return u.Role == role
}

// HasMinimumRole checks if the user has at least the required role level
func (u *User) HasMinimumRole(required UserRole) bool {
	return u.Role.AtLeast(required)
}

// ============================================================================
// AGENT TYPE
// ============================================================================

// Agent represents an AI agent in the system
type Agent struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Role        AgentRole              `json:"role"`
	Tools       []ToolPermission       `json:"tools,omitempty"`
	Tags        map[string]string      `json:"tags,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	Session     *AgentSession          `json:"-"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// HasToolPermission checks if the agent has a specific tool permission
func (a *Agent) HasToolPermission(perm ToolPermission) bool {
	for _, p := range a.Tools {
		if p == perm {
			return true
		}
	}
	return false
}

// HasMinimumRole checks if the agent has at least the required role level
func (a *Agent) HasMinimumRole(required AgentRole) bool {
	return a.Role.AtLeast(required)
}

// CanExecuteTool checks if the agent can execute a specific tool
func (a *Agent) CanExecuteTool(toolName string) bool {
	if a.Role == AgentRoleAdmin {
		return true
	}

	for _, perm := range a.Tools {
		if perm == PermToolAll {
			return true
		}
	}

	permNames := []string{
		"tool:" + toolName,
		"tool:" + toColonFormat(toolName),
	}

	for _, toolPermStr := range permNames {
		toolPerm := ToolPermission(toolPermStr)
		for _, perm := range a.Tools {
			if perm == toolPerm {
				return true
			}
		}
	}

	if len(a.Tools) == 0 {
		defaultPerms := GetPermissionsForRole(a.Role)
		for _, dp := range defaultPerms {
			if dp == PermToolAll {
				return true
			}
			for _, toolPermStr := range permNames {
				if string(dp) == toolPermStr {
					return true
				}
			}
		}
	}

	return false
}

// toColonFormat converts underscore format to colon format (e.g., "file_read" -> "file:read")
func toColonFormat(s string) string {
	result := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		if s[i] == '_' {
			result = append(result, ':')
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}

// ============================================================================
// SESSION TYPES
// ============================================================================

// UserSession represents an active dashboard/API user session
type UserSession struct {
	ID           string            `json:"id"`
	UserID       string            `json:"user_id"`
	User         *User             `json:"-"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	lastActivity atomic.Int64      `json:"-"`
	Tags         map[string]string `json:"tags,omitempty"`
	Active       bool              `json:"active"`
	IPAddress    string            `json:"ip_address,omitempty"`
}

// LastActivityTime returns the last activity time
func (s *UserSession) LastActivityTime() time.Time {
	return time.Unix(0, s.lastActivity.Load())
}

// SetLastActivity sets the last activity time
func (s *UserSession) SetLastActivity(t time.Time) {
	s.lastActivity.Store(t.UnixNano())
}

// IsExpired checks if the session has expired
func (s *UserSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValid checks if the session is valid and not expired
func (s *UserSession) IsValid() bool {
	return s.Active && !s.IsExpired()
}

// Refresh updates the session expiration time
func (s *UserSession) Refresh(duration time.Duration) {
	s.SetLastActivity(time.Now())
	s.ExpiresAt = time.Now().Add(duration)
}

// RemainingTTL returns the remaining time-to-live duration
func (s *UserSession) RemainingTTL() time.Duration {
	remaining := time.Until(s.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// AgentSession represents an active agent session
type AgentSession struct {
	ID          string            `json:"id"`
	AgentID     string            `json:"agent_id"`
	Agent       *Agent            `json:"-"`
	CreatedAt   time.Time         `json:"created_at"`
	Tags        map[string]string `json:"tags,omitempty"`
	Active      bool              `json:"active"`
	IPAddress   string            `json:"ip_address,omitempty"`
	ContextHash string            `json:"context_hash,omitempty"`

	mu           sync.RWMutex `json:"-"`
	ExpiresAt    time.Time    `json:"expires_at"`
	lastActivity atomic.Int64 `json:"-"`
}

// LastActivityTime returns the last activity time
func (s *AgentSession) LastActivityTime() time.Time {
	return time.Unix(0, s.lastActivity.Load())
}

// SetLastActivity sets the last activity time
func (s *AgentSession) SetLastActivity(t time.Time) {
	s.lastActivity.Store(t.UnixNano())
}

// IsExpired checks if the session has expired
func (s *AgentSession) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Now().After(s.ExpiresAt)
}

// IsValid checks if the session is valid and not expired
func (s *AgentSession) IsValid() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Active && time.Now().Before(s.ExpiresAt)
}

// Refresh updates the session expiration time
func (s *AgentSession) Refresh(duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity.Store(time.Now().UnixNano())
	s.ExpiresAt = time.Now().Add(duration)
}

// SetExpiresAt safely updates the expiration time with mutex protection
func (s *AgentSession) SetExpiresAt(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ExpiresAt = t
}

// RemainingTTL returns the remaining time-to-live duration
func (s *AgentSession) RemainingTTL() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	remaining := time.Until(s.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ============================================================================
// CONFIGURATION
// ============================================================================

// Config holds RBAC configuration
type Config struct {
	SessionDuration     time.Duration `json:"session_duration"`
	MaxSessionsPerUser  int           `json:"max_sessions_per_user"`
	MaxSessionsPerAgent int           `json:"max_sessions_per_agent"`
	MaxAgents           int           `json:"max_agents"`
	MaxUsers            int           `json:"max_users"`
	DefaultRole         AgentRole     `json:"default_agent_role"`
	DefaultUserRole     UserRole      `json:"default_user_role"`
	RequireApproval     bool          `json:"require_approval_for_privileged"`
	CleanupInterval     time.Duration `json:"cleanup_interval"`
}

// DefaultConfig returns default RBAC configuration
func DefaultConfig() *Config {
	return &Config{
		SessionDuration:     24 * time.Hour,
		MaxSessionsPerUser:  5,
		MaxSessionsPerAgent: 10,
		MaxAgents:           1000,
		MaxUsers:            100,
		DefaultRole:         AgentRoleRestricted,
		DefaultUserRole:     UserRoleViewer,
		RequireApproval:     true,
		CleanupInterval:     5 * time.Minute,
	}
}

// ============================================================================
// ROLE PERMISSION MAPPINGS
// ============================================================================

// UserRolePermissions maps user roles to their resource permissions
var UserRolePermissions = map[UserRole][]Permission{
	UserRoleViewer: {
		{Resource: ResourceDashboard, Action: ActionRead},
		{Resource: ResourceMetrics, Action: ActionRead},
		{Resource: ResourceAudit, Action: ActionRead},
		{Resource: ResourceLicense, Action: ActionRead},
	},
	UserRoleAnalyst: {
		{Resource: ResourceDashboard, Action: ActionRead},
		{Resource: ResourceMetrics, Action: ActionRead},
		{Resource: ResourceAudit, Action: ActionRead},
		{Resource: ResourceCompliance, Action: ActionRead},
		{Resource: ResourceCompliance, Action: ActionExecute},
		{Resource: ResourceLicense, Action: ActionRead},
		{Resource: ResourceAgent, Action: ActionRead},
	},
	UserRoleComplianceOfficer: {
		{Resource: ResourceDashboard, Action: ActionRead},
		{Resource: ResourceMetrics, Action: ActionRead},
		{Resource: ResourceAudit, Action: ActionRead},
		{Resource: ResourceAudit, Action: ActionManage},
		{Resource: ResourceCompliance, Action: ActionRead},
		{Resource: ResourceCompliance, Action: ActionExecute},
		{Resource: ResourceCompliance, Action: ActionWrite},
		{Resource: ResourceLicense, Action: ActionRead},
		{Resource: ResourceAgent, Action: ActionRead},
		{Resource: ResourcePolicy, Action: ActionRead},
	},
	UserRoleAdmin: {
		{Resource: "*", Action: "*"},
	},
}

// GetPermissionsForUserRole returns the default permissions for a user role
func GetPermissionsForUserRole(role UserRole) []Permission {
	if perms, ok := UserRolePermissions[role]; ok {
		return perms
	}
	return []Permission{}
}

// AgentRolePermissions maps agent roles to their default tool permissions
var AgentRolePermissions = map[AgentRole][]ToolPermission{
	AgentRoleRestricted: {
		PermToolFileRead,
		PermToolFileExists,
		PermToolWebSearch,
		PermToolCodeSearch,
	},
	AgentRoleStandard: {
		PermToolFileRead,
		PermToolFileWrite,
		PermToolFileExists,
		PermToolWebSearch,
		PermToolHTTPRequest,
		PermToolJSONFetch,
		PermToolCodeSearch,
		PermToolPing,
	},
	AgentRolePrivileged: {
		PermToolFileRead,
		PermToolFileWrite,
		PermToolFileDelete,
		PermToolFileExists,
		PermToolWebSearch,
		PermToolHTTPRequest,
		PermToolJSONFetch,
		PermToolShellCommand,
		PermToolBash,
		PermToolCodeSearch,
		PermToolCodeExecuteGo,
		PermToolCodeExecutePython,
		PermToolCodeExecuteJavaScript,
		PermToolDatabaseList,
		PermToolDatabaseSchema,
	},
	AgentRoleAdmin: {
		PermToolAll,
		PermAdminManage,
		PermAdminAudit,
		PermAdminConfig,
	},
}

// GetPermissionsForRole returns the default permissions for an agent role
func GetPermissionsForRole(role AgentRole) []ToolPermission {
	if perms, ok := AgentRolePermissions[role]; ok {
		return perms
	}
	return []ToolPermission{}
}
