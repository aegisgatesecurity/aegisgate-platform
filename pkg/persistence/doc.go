// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Audit Log Persistence
// =========================================================================
//
// Wires the upstream audit storage (FileStorageBackend, ComplianceAuditLog,
// PruneOldEntries) into the platform lifecycle. Provides PostgreSQL and
// file-backed storage backends with tier-based retention.
//
// Storage Backends:
//   - FileStorageBackend:           flat-file JSON lines (Community, Developer)
//   - postgres_storage_backend.go:  PostgreSQL via pgx/v5 (Professional, Enterprise)
//
// Tier-based retention:
//   - Community:     7 days
//   - Developer:    30 days
//   - Professional: 90 days
//   - Enterprise:  unlimited
//
// Features:
//   - Hash-chain integrity: each entry's hash is verified on read;
//     writes compute hash from entry + previous_hash
//   - Indexed queries: timestamp, event_type, compliance_tags (GIN),
//     tenant_id, level, source, full-text search
//   - Graceful degradation: if PostgreSQL is unavailable at startup,
//     the Manager falls back to FileStorageBackend
//   - Background goroutine for retention-based pruning
//
// Manager responsibilities:
//   - Create file-backed audit storage at startup
//   - Start a background goroutine for retention-based pruning
//   - Provide a ComplianceAuditLog for all platform components to use
//   - Graceful shutdown with pruning completion
//
// =========================================================================

package persistence
