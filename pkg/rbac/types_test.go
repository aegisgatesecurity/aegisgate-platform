// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — RBAC Types Tests

package rbac

import (
	"testing"
	"time"
)

// ============================================================================
// USER ROLE TESTS
// ============================================================================

func TestUserRole_AtLeast(t *testing.T) {
	tests := []struct {
		name     string
		role     UserRole
		required UserRole
		want     bool
	}{
		{"viewer >= viewer", UserRoleViewer, UserRoleViewer, true},
		{"analyst >= viewer", UserRoleAnalyst, UserRoleViewer, true},
		{"admin >= viewer", UserRoleAdmin, UserRoleViewer, true},
		{"compliance_officer >= viewer", UserRoleComplianceOfficer, UserRoleViewer, true},
		{"analyst >= analyst", UserRoleAnalyst, UserRoleAnalyst, true},
		{"admin >= analyst", UserRoleAdmin, UserRoleAnalyst, true},
		{"compliance_officer >= analyst", UserRoleComplianceOfficer, UserRoleAnalyst, true},
		{"viewer >= analyst", UserRoleViewer, UserRoleAnalyst, false},
		{"admin >= compliance_officer", UserRoleAdmin, UserRoleComplianceOfficer, true},
		{"analyst >= compliance_officer", UserRoleAnalyst, UserRoleComplianceOfficer, false},
		{"viewer >= admin", UserRoleViewer, UserRoleAdmin, false},
		{"analyst >= admin", UserRoleAnalyst, UserRoleAdmin, false},
		{"compliance_officer >= admin", UserRoleComplianceOfficer, UserRoleAdmin, false},
		{"admin >= admin", UserRoleAdmin, UserRoleAdmin, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.role.AtLeast(tt.required); got != tt.want {
				t.Errorf("UserRole.AtLeast() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserRole_String(t *testing.T) {
	tests := []struct {
		role UserRole
		want string
	}{
		{UserRoleViewer, "viewer"},
		{UserRoleAnalyst, "analyst"},
		{UserRoleAdmin, "admin"},
		{UserRoleComplianceOfficer, "compliance_officer"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.role.String(); got != tt.want {
				t.Errorf("UserRole.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseUserRole(t *testing.T) {
	tests := []struct {
		input string
		want  UserRole
	}{
		{"viewer", UserRoleViewer},
		{"analyst", UserRoleAnalyst},
		{"admin", UserRoleAdmin},
		{"compliance_officer", UserRoleComplianceOfficer},
		{"unknown", UserRoleViewer}, // default
		{"", UserRoleViewer},        // default
		{"ADMIN", UserRoleViewer},   // case sensitive, default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseUserRole(tt.input); got != tt.want {
				t.Errorf("ParseUserRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// AGENT ROLE TESTS
// ============================================================================

func TestAgentRole_AtLeast(t *testing.T) {
	tests := []struct {
		name     string
		role     AgentRole
		required AgentRole
		want     bool
	}{
		{"restricted >= restricted", AgentRoleRestricted, AgentRoleRestricted, true},
		{"standard >= restricted", AgentRoleStandard, AgentRoleRestricted, true},
		{"privileged >= restricted", AgentRolePrivileged, AgentRoleRestricted, true},
		{"admin >= restricted", AgentRoleAdmin, AgentRoleRestricted, true},
		{"standard >= standard", AgentRoleStandard, AgentRoleStandard, true},
		{"privileged >= standard", AgentRolePrivileged, AgentRoleStandard, true},
		{"admin >= standard", AgentRoleAdmin, AgentRoleStandard, true},
		{"restricted >= standard", AgentRoleRestricted, AgentRoleStandard, false},
		{"admin >= privileged", AgentRoleAdmin, AgentRolePrivileged, true},
		{"standard >= privileged", AgentRoleStandard, AgentRolePrivileged, false},
		{"restricted >= admin", AgentRoleRestricted, AgentRoleAdmin, false},
		{"standard >= admin", AgentRoleStandard, AgentRoleAdmin, false},
		{"privileged >= admin", AgentRolePrivileged, AgentRoleAdmin, false},
		{"admin >= admin", AgentRoleAdmin, AgentRoleAdmin, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.role.AtLeast(tt.required); got != tt.want {
				t.Errorf("AgentRole.AtLeast() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgentRole_String(t *testing.T) {
	tests := []struct {
		role AgentRole
		want string
	}{
		{AgentRoleRestricted, "restricted"},
		{AgentRoleStandard, "standard"},
		{AgentRolePrivileged, "privileged"},
		{AgentRoleAdmin, "admin"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.role.String(); got != tt.want {
				t.Errorf("AgentRole.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// PERMISSION TESTS
// ============================================================================

func TestPermission_String(t *testing.T) {
	tests := []struct {
		perm Permission
		want string
	}{
		{Permission{Resource: ResourceConfig, Action: ActionRead}, "config:read"},
		{Permission{Resource: ResourceAudit, Action: ActionWrite}, "audit:write"},
		{Permission{Resource: ResourceDashboard, Action: ActionRead}, "dashboard:read"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.perm.String(); got != tt.want {
				t.Errorf("Permission.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePermission(t *testing.T) {
	tests := []struct {
		input string
		want  Permission
	}{
		{"config:read", Permission{Resource: ResourceConfig, Action: ActionRead}},
		{"audit:write", Permission{Resource: ResourceAudit, Action: ActionWrite}},
		{"tool:execute", Permission{Resource: "tool", Action: "execute"}},
		{"config", Permission{Resource: ResourceConfig, Action: ActionRead}},
		{"dashboard", Permission{Resource: ResourceDashboard, Action: ActionRead}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParsePermission(tt.input); got != tt.want {
				t.Errorf("ParsePermission() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// USER METHOD TESTS
// ============================================================================

func TestUser_HasPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []Permission
		check       Permission
		want        bool
	}{
		{
			"exact match",
			[]Permission{{Resource: ResourceConfig, Action: ActionRead}},
			Permission{Resource: ResourceConfig, Action: ActionRead},
			true,
		},
		{
			"no match",
			[]Permission{{Resource: ResourceConfig, Action: ActionRead}},
			Permission{Resource: ResourceConfig, Action: ActionWrite},
			false,
		},
		{
			"resource wildcard",
			[]Permission{{Resource: ResourceConfig, Action: "*"}},
			Permission{Resource: ResourceConfig, Action: ActionWrite},
			true,
		},
		{
			"action wildcard",
			[]Permission{{Resource: "*", Action: ActionRead}},
			Permission{Resource: ResourceAudit, Action: ActionRead},
			true,
		},
		{
			"full wildcard",
			[]Permission{{Resource: "*", Action: "*"}},
			Permission{Resource: ResourceConfig, Action: ActionDelete},
			true,
		},
		{
			"empty permissions",
			[]Permission{},
			Permission{Resource: ResourceConfig, Action: ActionRead},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Permissions: tt.permissions}
			if got := u.HasPermission(tt.check); got != tt.want {
				t.Errorf("User.HasPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_HasRole(t *testing.T) {
	u := &User{Role: UserRoleAnalyst}

	if !u.HasRole(UserRoleAnalyst) {
		t.Error("User.HasRole() should return true for matching role")
	}
	if u.HasRole(UserRoleAdmin) {
		t.Error("User.HasRole() should return false for non-matching role")
	}
}

func TestUser_HasMinimumRole(t *testing.T) {
	tests := []struct {
		name     string
		role     UserRole
		required UserRole
		want     bool
	}{
		{"analyst >= viewer", UserRoleAnalyst, UserRoleViewer, true},
		{"analyst >= analyst", UserRoleAnalyst, UserRoleAnalyst, true},
		{"analyst >= admin", UserRoleAnalyst, UserRoleAdmin, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Role: tt.role}
			if got := u.HasMinimumRole(tt.required); got != tt.want {
				t.Errorf("User.HasMinimumRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// AGENT METHOD TESTS
// ============================================================================

func TestAgent_HasToolPermission(t *testing.T) {
	tests := []struct {
		name  string
		tools []ToolPermission
		check ToolPermission
		want  bool
	}{
		{
			"exact match",
			[]ToolPermission{PermToolFileRead},
			PermToolFileRead,
			true,
		},
		{
			"no match",
			[]ToolPermission{PermToolFileRead},
			PermToolFileWrite,
			false,
		},
		{
			"multiple tools with match",
			[]ToolPermission{PermToolFileRead, PermToolWebSearch, PermToolShellCommand},
			PermToolWebSearch,
			true,
		},
		{
			"empty tools",
			[]ToolPermission{},
			PermToolFileRead,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{Tools: tt.tools}
			if got := a.HasToolPermission(tt.check); got != tt.want {
				t.Errorf("Agent.HasToolPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_HasMinimumRole(t *testing.T) {
	tests := []struct {
		name     string
		role     AgentRole
		required AgentRole
		want     bool
	}{
		{"standard >= restricted", AgentRoleStandard, AgentRoleRestricted, true},
		{"standard >= standard", AgentRoleStandard, AgentRoleStandard, true},
		{"standard >= admin", AgentRoleStandard, AgentRoleAdmin, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{Role: tt.role}
			if got := a.HasMinimumRole(tt.required); got != tt.want {
				t.Errorf("Agent.HasMinimumRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgent_CanExecuteTool(t *testing.T) {
	tests := []struct {
		name     string
		role     AgentRole
		tools    []ToolPermission
		toolName string
		want     bool
	}{
		{"admin always true", AgentRoleAdmin, []ToolPermission{}, "file:read", true},
		{"tool:* wildcard", AgentRoleStandard, []ToolPermission{PermToolAll}, "shell:command", true},
		{"explicit tool match", AgentRoleStandard, []ToolPermission{PermToolShellCommand}, "shell:command", true},
		{"no match", AgentRoleRestricted, []ToolPermission{PermToolFileRead}, "shell:command", false},
		{"default role perms - restricted", AgentRoleRestricted, []ToolPermission{}, "file:read", true},
		{"default role perms - standard", AgentRoleStandard, []ToolPermission{}, "web:search", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{Role: tt.role, Tools: tt.tools}
			if got := a.CanExecuteTool(tt.toolName); got != tt.want {
				t.Errorf("Agent.CanExecuteTool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_toColonFormat(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"file_read", "file:read"},
		{"web_search", "web:search"},
		{"shell_command", "shell:command"},
		{"code:execute", "code:execute"},
		{"nodelimiter", "nodelimiter"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := toColonFormat(tt.input); got != tt.want {
				t.Errorf("toColonFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// USERSESSION TESTS
// ============================================================================

func TestUserSession_IsExpired(t *testing.T) {
	now := time.Now()
	s := &UserSession{
		ExpiresAt: now.Add(-1 * time.Hour),
		Active:    true,
	}
	if !s.IsExpired() {
		t.Error("UserSession.IsExpired() should return true for expired session")
	}

	s.ExpiresAt = now.Add(1 * time.Hour)
	if s.IsExpired() {
		t.Error("UserSession.IsExpired() should return false for valid session")
	}
}

func TestUserSession_IsValid(t *testing.T) {
	now := time.Now()

	s := &UserSession{ExpiresAt: now.Add(1 * time.Hour), Active: true}
	if !s.IsValid() {
		t.Error("UserSession.IsValid() should return true for active, non-expired session")
	}

	s.Active = false
	if s.IsValid() {
		t.Error("UserSession.IsValid() should return false for inactive session")
	}

	s.Active = true
	s.ExpiresAt = now.Add(-1 * time.Hour)
	if s.IsValid() {
		t.Error("UserSession.IsValid() should return false for expired session")
	}
}

func TestUserSession_Refresh(t *testing.T) {
	s := &UserSession{Active: true}
	before := time.Now()

	s.Refresh(24 * time.Hour)

	after := time.Now()
	if s.LastActivityTime().Before(before) {
		t.Error("UserSession.Refresh() should update last activity")
	}
	if s.ExpiresAt.Before(after.Add(23 * time.Hour)) {
		t.Error("UserSession.Refresh() should set expiration")
	}
}

func TestUserSession_RemainingTTL(t *testing.T) {
	now := time.Now()

	s := &UserSession{ExpiresAt: now.Add(2 * time.Hour)}
	ttl := s.RemainingTTL()
	if ttl < time.Hour {
		t.Errorf("UserSession.RemainingTTL() = %v, expected > 1h", ttl)
	}

	s.ExpiresAt = now.Add(-1 * time.Hour)
	if s.RemainingTTL() != 0 {
		t.Error("UserSession.RemainingTTL() should return 0 for expired session")
	}
}

func TestUserSession_LastActivityTime(t *testing.T) {
	s := &UserSession{}
	now := time.Now()

	s.SetLastActivity(now)
	got := s.LastActivityTime()

	if got.Unix() != now.Unix() {
		t.Errorf("UserSession.LastActivityTime() = %v, want %v", got, now)
	}
}

// ============================================================================
// AGENTSESSION TESTS
// ============================================================================

func TestAgentSession_IsExpired(t *testing.T) {
	now := time.Now()
	s := &AgentSession{
		ExpiresAt: now.Add(-1 * time.Hour),
		Active:    true,
	}
	if !s.IsExpired() {
		t.Error("AgentSession.IsExpired() should return true for expired session")
	}

	s.ExpiresAt = now.Add(1 * time.Hour)
	if s.IsExpired() {
		t.Error("AgentSession.IsExpired() should return false for valid session")
	}
}

func TestAgentSession_IsValid(t *testing.T) {
	now := time.Now()

	s := &AgentSession{ExpiresAt: now.Add(1 * time.Hour), Active: true}
	if !s.IsValid() {
		t.Error("AgentSession.IsValid() should return true for active, non-expired session")
	}

	s.Active = false
	if s.IsValid() {
		t.Error("AgentSession.IsValid() should return false for inactive session")
	}

	s.Active = true
	s.ExpiresAt = now.Add(-1 * time.Hour)
	if s.IsValid() {
		t.Error("AgentSession.IsValid() should return false for expired session")
	}
}

func TestAgentSession_Refresh(t *testing.T) {
	s := &AgentSession{Active: true}
	before := time.Now()

	s.Refresh(24 * time.Hour)

	after := time.Now()
	if s.LastActivityTime().Before(before) {
		t.Error("AgentSession.Refresh() should update last activity")
	}
	if s.ExpiresAt.Before(after.Add(23 * time.Hour)) {
		t.Error("AgentSession.Refresh() should set expiration")
	}
}

func TestAgentSession_RemainingTTL(t *testing.T) {
	now := time.Now()

	s := &AgentSession{ExpiresAt: now.Add(2 * time.Hour)}
	ttl := s.RemainingTTL()
	if ttl < time.Hour {
		t.Errorf("AgentSession.RemainingTTL() = %v, expected > 1h", ttl)
	}

	s.ExpiresAt = now.Add(-1 * time.Hour)
	if s.RemainingTTL() != 0 {
		t.Error("AgentSession.RemainingTTL() should return 0 for expired session")
	}
}

func TestAgentSession_LastActivityTime(t *testing.T) {
	s := &AgentSession{}
	now := time.Now()

	s.SetLastActivity(now)
	got := s.LastActivityTime()

	if got.Unix() != now.Unix() {
		t.Errorf("AgentSession.LastActivityTime() = %v, want %v", got, now)
	}
}

// ============================================================================
// CONFIG TESTS
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.SessionDuration != 24*time.Hour {
		t.Errorf("DefaultConfig().SessionDuration = %v, want 24h", cfg.SessionDuration)
	}
	if cfg.MaxSessionsPerUser != 5 {
		t.Errorf("DefaultConfig().MaxSessionsPerUser = %d, want 5", cfg.MaxSessionsPerUser)
	}
	if cfg.MaxSessionsPerAgent != 10 {
		t.Errorf("DefaultConfig().MaxSessionsPerAgent = %d, want 10", cfg.MaxSessionsPerAgent)
	}
	if cfg.MaxAgents != 1000 {
		t.Errorf("DefaultConfig().MaxAgents = %d, want 1000", cfg.MaxAgents)
	}
	if cfg.MaxUsers != 100 {
		t.Errorf("DefaultConfig().MaxUsers = %d, want 100", cfg.MaxUsers)
	}
	if cfg.DefaultRole != AgentRoleRestricted {
		t.Errorf("DefaultConfig().DefaultRole = %v, want restricted", cfg.DefaultRole)
	}
	if cfg.DefaultUserRole != UserRoleViewer {
		t.Errorf("DefaultConfig().DefaultUserRole = %v, want viewer", cfg.DefaultUserRole)
	}
	if !cfg.RequireApproval {
		t.Error("DefaultConfig().RequireApproval should be true")
	}
	if cfg.CleanupInterval != 5*time.Minute {
		t.Errorf("DefaultConfig().CleanupInterval = %v, want 5m", cfg.CleanupInterval)
	}
}

// ============================================================================
// ROLE PERMISSION MAPPING TESTS
// ============================================================================

func TestGetPermissionsForUserRole(t *testing.T) {
	tests := []struct {
		role         UserRole
		wantLen      int
		wantRead     bool
		wantWildcard bool
	}{
		{UserRoleViewer, 4, true, false},
		{UserRoleAnalyst, 7, true, false},
		{UserRoleComplianceOfficer, 10, true, false},
		{UserRoleAdmin, 1, false, true},
		{"unknown", 0, false, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			perms := GetPermissionsForUserRole(tt.role)
			if len(perms) != tt.wantLen {
				t.Errorf("GetPermissionsForUserRole() returned %d perms, want %d", len(perms), tt.wantLen)
			}
			if tt.wantRead && len(perms) > 0 {
				found := false
				for _, p := range perms {
					if p.Action == ActionRead {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected at least one read permission")
				}
			}
			if tt.wantWildcard {
				found := false
				for _, p := range perms {
					if p.Resource == "*" && p.Action == "*" {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected wildcard permission")
				}
			}
		})
	}
}

func TestGetPermissionsForRole(t *testing.T) {
	tests := []struct {
		role    AgentRole
		wantLen int
	}{
		{AgentRoleRestricted, 4},
		{AgentRoleStandard, 8},
		{AgentRolePrivileged, 15},
		{AgentRoleAdmin, 4},
		{"unknown", 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			perms := GetPermissionsForRole(tt.role)
			if len(perms) != tt.wantLen {
				t.Errorf("GetPermissionsForRole() returned %d perms, want %d", len(perms), tt.wantLen)
			}
		})
	}
}

func TestUserRolePermissions_SpotCheck(t *testing.T) {
	viewerPerms := UserRolePermissions[UserRoleViewer]
	if len(viewerPerms) == 0 {
		t.Fatal("UserRolePermissions[viewer] is empty")
	}

	found := false
	for _, p := range viewerPerms {
		if p.Resource == ResourceDashboard && p.Action == ActionRead {
			found = true
			break
		}
	}
	if !found {
		t.Error("viewer role should have dashboard:read permission")
	}

	adminPerms := UserRolePermissions[UserRoleAdmin]
	if len(adminPerms) != 1 {
		t.Errorf("admin should have 1 wildcard perm, got %d", len(adminPerms))
	}
	if adminPerms[0].Resource != "*" || adminPerms[0].Action != "*" {
		t.Error("admin should have *.* wildcard permission")
	}
}

func TestAgentRolePermissions_SpotCheck(t *testing.T) {
	restrictedPerms := AgentRolePermissions[AgentRoleRestricted]
	if len(restrictedPerms) == 0 {
		t.Fatal("AgentRolePermissions[restricted] is empty")
	}

	found := false
	for _, p := range restrictedPerms {
		if p == PermToolFileRead {
			found = true
			break
		}
	}
	if !found {
		t.Error("restricted role should have tool:file:read permission")
	}

	adminPerms := AgentRolePermissions[AgentRoleAdmin]
	found = false
	for _, p := range adminPerms {
		if p == PermToolAll {
			found = true
			break
		}
	}
	if !found {
		t.Error("admin role should have tool:* permission")
	}
}
