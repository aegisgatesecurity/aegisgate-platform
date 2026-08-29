// SPDX-License-Identifier: Apache-2.0
// Package ctxkeys provides shared context key definitions for
// request-scoped authentication data. This package exists to break
// import cycles between pkg/auth, pkg/sso, and pkg/ioc — all three
// need to read/write tenant context, but auth imports sso, and sso
// needs ioc's RLS helpers.
//
// The context key type and string values defined here MUST match
// the values used by pkg/auth/middleware.go. Do not change one
// without changing the other.
package ctxkeys

// Key is the context key type for authentication-scoped values.
// It is a string type so that context.Value lookups use the
// same type across packages.
type Key string

const (
	// TenantID is the context key for the authenticated user's
	// tenant identifier. Set by auth middleware, read by RLS
	// helpers and store implementations.
	TenantID Key = "auth_tenant_id"

	// IsAdmin is the context key for the authenticated user's
	// admin flag. Set by auth middleware, read by RLS helpers.
	IsAdmin Key = "auth_is_admin"
)
