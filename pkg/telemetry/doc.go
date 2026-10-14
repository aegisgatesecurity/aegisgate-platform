// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Unified Telemetry Receiver
//
// pkg/telemetry implements the unified receiver for detection telemetry
// from all AegisGate products (Lens, Rampart, Scanner, MCP). It replaces
// the per-tool receiver pattern (lensbackend, rampartbackend, etc.) with
// a single endpoint that routes events based on the `source` field.
//
// Architecture:
//
//   POST /api/v1/telemetry    — Accept EventBatch from any source
//   GET  /api/v1/patterns/latest — Return canonical PatternSet (pull model)
//   GET  /api/v1/healthz      — Health check (no auth)
//
// Auth: Standardized on API key (Authorization: Bearer <api_key>).
// All FOSS tools already support this pattern (Rampart pioneered it).
//
// Rate limiting: Per-installation (100/min) + global (10000/min).
// Same pattern as lensbackend, using Platform's existing ratelimit package.
//
// Privacy: METADATA ONLY. No PII values, no credentials, no prompt text.
// Enforced by canonical Event schema — the struct has no field for
// matched text or raw content.
//
// Air-gap behavior: This receiver only runs when Platform is deployed.
// FOSS tools with no platform_url send nothing. FOSS tools with a
// platform_url send opt-in telemetry via outbound HTTP only.
//
// Backward compatibility: The existing lensbackend endpoints
// (/api/v1/lens/telemetry, /api/v1/lens/check, /api/v1/lens/stats)
// continue to work. The unified receiver is additive, not replacement.
// Over time, lensbackend can be migrated to use pkg/telemetry internally.

package telemetry
