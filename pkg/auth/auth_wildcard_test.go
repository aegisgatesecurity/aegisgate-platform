//go:build !race

// SPDX-License-Identifier: Apache-2.0
// Auth RequirePermission coverage push — targeting nil-permissions and wildcard branches
// Strategy: temporarily modify UserRolePermissions to add wildcard patterns

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// Add wildcard permissions to compliance_officer to trigger resource wildcard branch
// compliance_officer already has compliance:read, compliance:execute, compliance:write
// Adding {Resource: "compliance", Action: "*"} will trigger p.Resource == perm.Resource && p.Action == "*"
// Adding {Resource: "*", Action: "manage"} will trigger p.Resource == "*" && p.Action == perm.Action
func init() {
	// Modify compliance_officer to include resource wildcard
	rbac.UserRolePermissions[rbac.UserRoleComplianceOfficer] = append(
		rbac.UserRolePermissions[rbac.UserRoleComplianceOfficer],
		rbac.Permission{Resource: "compliance", Action: "*"},
		rbac.Permission{Resource: "*", Action: "manage"},
	)
}

// Test: resource wildcard branch (p.Resource == perm.Resource && p.Action == "*")
func TestPermit_ResWildcardBranch(t *testing.T) {
	cfg := &Config{JWTSigningKey: []byte("test-rw"), TokenExpiryHours: 24, RequireAuth: true}
	m := NewMiddleware(cfg)
	token, _ := m.GenerateToken("co-user", "compliance_officer")

	// compliance_officer now has compliance:* and *:manage
	tests := []struct {
		resource string
		action   string
		expected int
	}{
		// compliance:* should match any action on compliance
		{"compliance", "read", http.StatusOK},
		{"compliance", "write", http.StatusOK},
		{"compliance", "execute", http.StatusOK},
		{"compliance", "manage", http.StatusOK},
		// *:manage should match manage on any resource
		{"audit", "manage", http.StatusOK},
		{"policy", "manage", http.StatusOK},
		// dashboard:read still works (explicit permission)
		{"dashboard", "read", http.StatusOK},
		// dashboard:write denied
		{"dashboard", "write", http.StatusForbidden},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		perm := rbac.Permission{Resource: rbac.Resource(tc.resource), Action: rbac.Action(tc.action)}
		m.RequirePermission(perm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rr, req)
		if rr.Code != tc.expected {
			t.Errorf("compliance_officer %s:%s: expected %d, got %d", tc.resource, tc.action, tc.expected, rr.Code)
		}
	}
}
