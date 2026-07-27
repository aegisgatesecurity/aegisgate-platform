// Package rbac - Role-Based Access Control for AegisGuard
// Provides agent-centric RBAC for AI agent tool authorization
package rbac

import (
	"sync/atomic"
	"time"
)

// ============================================================================
// AGENT TYPES (Adapted from AegisGate User types)
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
	// Admin role can execute all tools
	if a.Role == AgentRoleAdmin {
		return true
	}

	// Check for wildcard permission
	for _, perm := range a.Tools {
		if perm == PermToolAll {
			return true
		}
	}

	// Build permission names to check (try both with underscore and colon)
	permNames := []string{
		"tool:" + toolName,                // tool:file_read
		"tool:" + toColonFormat(toolName), // tool:file:read
	}

	for _, toolPermStr := range permNames {
		toolPerm := ToolPermission(toolPermStr)
		for _, perm := range a.Tools {
			if perm == toolPerm {
				return true
			}
		}
	}

	// Check role defaults if agent has no explicit permissions
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

// toColonFormat converts underscore format to colon format
// e.g., "file_read" -> "file:read"
func toColonFormat(s string) string {
	// Simple conversion: insert colon before each uppercase letter or underscore
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
// ROLE TYPES
// ============================================================================

// AgentRole represents an agent's authorization level
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

// String returns the string representation of the role
func (r AgentRole) String() string {
	return string(r)
}

// ============================================================================
// PERMISSION TYPES
// ============================================================================

// ToolPermission represents a specific tool authorization permission
type ToolPermission string

// Common tool permissions
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
// SESSION TYPES
// ============================================================================

// AgentSession represents an active agent session
type AgentSession struct {
	ID           string            `json:"id"`
	AgentID      string            `json:"agent_id"`
	Agent        *Agent            `json:"-"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	lastActivity atomic.Int64      `json:"-"` // Unix nanoseconds, accessed atomically
	Tags         map[string]string `json:"tags,omitempty"`
	Active       bool              `json:"active"`
	IPAddress    string            `json:"ip_address,omitempty"`
	ContextHash  string            `json:"context_hash,omitempty"`
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
	return time.Now().After(s.ExpiresAt)
}

// IsValid checks if the session is valid and not expired
func (s *AgentSession) IsValid() bool {
	return s.Active && !s.IsExpired()
}

// Refresh updates the session expiration time
func (s *AgentSession) Refresh(duration time.Duration) {
	s.SetLastActivity(time.Now())
	s.ExpiresAt = time.Now().Add(duration)
}

// RemainingTTL returns the remaining time-to-live duration
func (s *AgentSession) RemainingTTL() time.Duration {
	remaining := time.Until(s.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ============================================================================
// CONFIGURATION TYPES
// ============================================================================

// Config holds RBAC configuration
type Config struct {
	SessionDuration time.Duration `json:"session_duration"`
	MaxSessions     int           `json:"max_sessions_per_agent"`
	MaxAgents       int           `json:"max_agents"`
	DefaultRole     AgentRole     `json:"default_role"`
	RequireApproval bool          `json:"require_approval_for_privileged"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// DefaultConfig returns default RBAC configuration
func DefaultConfig() *Config {
	return &Config{
		SessionDuration: 24 * time.Hour,
		MaxSessions:     10,
		MaxAgents:       1000,
		DefaultRole:     AgentRoleRestricted,
		RequireApproval: true,
		CleanupInterval: 5 * time.Minute,
	}
}

// ============================================================================
// ROLE PERMISSION MAPPINGS
// ============================================================================

// RolePermissions maps agent roles to their default tool permissions
var RolePermissions = map[AgentRole][]ToolPermission{
	AgentRoleRestricted: {
		// Read-only operations only
		PermToolFileRead,
		PermToolFileExists,
		PermToolWebSearch,
		PermToolCodeSearch,
	},
	AgentRoleStandard: {
		// Common development operations
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
		// Sensitive operations (may require additional approval)
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
		// All operations
		PermToolAll,
		PermAdminManage,
		PermAdminAudit,
		PermAdminConfig,
	},
}

// GetPermissionsForRole returns the default permissions for a role
func GetPermissionsForRole(role AgentRole) []ToolPermission {
	if perms, ok := RolePermissions[role]; ok {
		return perms
	}
	return []ToolPermission{}
}
