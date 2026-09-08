// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package legalhold implements e-discovery legal holds for the
// AegisGate Security Platform.
//
// Legal holds prevent the erasure of data belonging to entities (users
// or agents) that are subject to active litigation or investigation.
// The DSAR service consults legal hold status before processing any
// erasure request.
//
// The Service manages the full hold lifecycle: creation, release, and
// querying. Holds can be backed by an in-memory store (default) or a
// PostgreSQL store (optional, via the Store interface). All Postgres
// store access is wrapped with RLS for tenant isolation.
//
// Key types:
//   - Service: Manages hold operations and in-memory state
//   - Hold: A legal hold with entity, reason, issuer, and timestamps
//   - Store: Persistence interface (in-memory or Postgres)
//
// Exposed via HTTP at /api/v1/legal-holds and gRPC LegalHoldService.
// =========================================================================
package legalhold
