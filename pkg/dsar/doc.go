// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Package dsar implements GDPR Data Subject Access Requests for the
// AegisGate Security Platform.
//
// The Service orchestrates data export and erasure across multiple
// registered DataProviders. Each provider implements Export and Erase
// for its data domain (audit logs, IOC store, RBAC, SSO sessions, etc.).
//
// Legal hold integration: Before erasure, the service checks the
// LegalHoldChecker interface. If an entity is under legal hold, erasure
// is blocked and the hold ID is returned in the EraseResult.BlockedBy
// field, ensuring compliance with e-discovery obligations.
//
// Key types:
//   - Service: Coordinates export/erase across providers
//   - DataProvider: Interface for pluggable data sources
//   - LegalHoldChecker: Interface to check for active holds
//   - ExportBundle: Aggregated export with per-provider data
//   - EraseResult: Erasure outcome with records affected and blocks
//
// Exposed via HTTP at /api/v1/dsar/{export,erase} and gRPC DSARService.
// =========================================================================
package dsar
