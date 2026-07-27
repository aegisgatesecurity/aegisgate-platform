package rbac

import "context"

// RBACManager implements role-based access control.
type RBACManager struct {
	roleStore RoleStore
}

// RoleStore defines the interface for storing and retrieving roles.
type RoleStore interface {
	GetRole(userID string) (*UserRole, error)
}

// UserRole represents a user's role and permissions.
type UserRole struct {
	RoleName    string
	Permissions []string
}

// HasMinimumAccess checks if the role has minimum necessary access to a resource.
func (r *UserRole) HasMinimumAccess(resource string) bool {
	for _, perm := range r.Permissions {
		if perm == resource {
			return true
		}
	}
	return false
}

// CheckMinimumNecessary enforces the Minimum Necessary Standard for HIPAA.
func (m *RBACManager) CheckMinimumNecessary(ctx context.Context, userID, resource string) bool {
	role, err := m.roleStore.GetRole(userID)
	if err != nil {
		return false
	}
	return role.HasMinimumAccess(resource)
}
