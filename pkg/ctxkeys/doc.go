// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package ctxkeys provides shared context key definitions for
// request-scoped authentication data in the AegisGate Security Platform.
//
// This package exists to break import cycles between pkg/auth, pkg/sso,
// and pkg/ioc — all three need to read/write tenant context, but auth
// imports sso, and sso needs ioc's RLS helpers.
//
// The context key type (Key) and string values defined here MUST match
// the values used by pkg/auth/middleware.go. Do not change one without
// changing the other.
//
// Keys:
//   - TenantID: The authenticated user's tenant identifier
//   - IsAdmin:  Whether the authenticated user has admin privileges
//
// RLS helpers in pkg/ioc (TenantFromContext, WithTenantContextOrPool)
// read these keys to set PostgreSQL row-level security session variables.
// =========================================================================
package ctxkeys
