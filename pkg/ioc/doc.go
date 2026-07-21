// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - IOC (Indicator of Compromise) Store
// =========================================================================
//
// The IOC store is the platform's threat intelligence database. It
// records, indexes, and serves Indicators of Compromise observed by
// any AegisGate instance, and supports federated sharing between
// instances via signed bundles (the "1 customer's threat = all
// customers protected" network effect).
//
// Primitives:
//   - attest.go:      IOCAttestation (signed statement "this instance saw this IOC")
//   - bundle.go:      Bundle (signed collection of IOCAttestations)
//   - cleanpath.go:   safe file-path handling (CodeQL G304/G703 linter guard)
//   - keyring.go:     ECDSA P-256 key management for sign/verify
//   - store.go:       in-memory store (Community, Developer tiers)
//   - postgres_store.go: PostgreSQL store (Professional+ tier, D1 Phase 1A)
//   - taxii_integration.go: TAXII 2.1 import from external STIX feeds
//   - ioc_admin_api.go: admin HTTP API at /api/v1/ioc/admin/
//
// Pull-based gossip protocol: instances periodically fetch signed
// bundles from peer instances and verify each IOCAttestation
// before adding to the local store. The same verifyManifestSignature
// path is shared with compliance evidence manifests (single verifier).
//
// Tier retention: Community 7d, Developer 30d, Professional 90d, Enterprise unlimited.
//
// =========================================================================

package ioc
