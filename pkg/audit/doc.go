// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Audit Event Pipeline
// =========================================================================
//
// The audit package is the bridge between the platform's event-emitting
// subsystems (HTTP proxy, MCP server, A2A, ACP, ANP, response scans,
// anomaly scores) and the SIEM integration layer (11 platforms:
// Splunk, Elasticsearch, QRadar, Sentinel, SumoLogic, LogRhythm,
// CloudWatch, SecurityHub, ArcSight, Syslog, Custom).
//
// Components:
//   - auditring.go:    in-memory ring buffer for hot-path event recording
//   - siem_dispatcher.go: bridges the event stream to /upstream/aegisgate/pkg/siem
//   - ioc_admin_api.go: admin API for IOC store management
//
// The AegisGate -> siem.Event translation is straightforward
// (field-by-field). All platform configuration and HTTP/TCP transport
// is delegated to the siem.Manager (4,828 LOC in the upstream module).
//
// Tier gate: SIEM dispatcher is Professional+ (locked decision Q4).
// Community and Developer tiers record events to the ring buffer
// only; SIEM fan-out is a Professional+ feature.
//
// =========================================================================

package audit
