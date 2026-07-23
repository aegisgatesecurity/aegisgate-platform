// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Incident Response Automation
// =========================================================================
//
// Package incident provides automated incident response for AegisGate.
// It bridges the correlation engine, SOC timeline, attestation, and
// compliance modules into a unified incident lifecycle.
//
// Integration Points
//
//   - Correlation Engine: ProcessEvent() receives correlation.Event
//     objects and checks them against DetectionRule patterns. When a
//     rule matches, an Incident is created automatically.
//
//   - SOC Timeline: Incidents carry a SessionID that links to the SOC
//     timeline (pkg/soc). The SOC analyst can create incidents manually
//     via CreateIncident().
//
//   - Attestation: The "create_attestation" playbook step produces an
//     attestation.Envelope linking the incident to the audit trail.
//
//   - Compliance: ComplianceMapping fields on Incidents and
//     DetectionRules map incidents to FedRAMP, SOC 2, and NIST
//     800-171 controls. MapToCompliance() auto-generates mappings
//     based on the correlation patterns that triggered the incident.
//
// Incident Lifecycle
//
//  1. Detection   — correlation event matches a DetectionRule
//  2. Triage      — severity assessed, assignee designated
//  3. Investigation — root cause analysis, evidence collection
//  4. Containment  — playbook execution (block agent, isolate
//     session, etc.)
//  5. Resolution   — incident resolved, attestation created
//  6. Close        — final review, incident closed
//
// v1.0 Scope
//
//   - InMemoryIncidentStore, InMemoryPlaybookStore,
//     InMemoryDetectionRuleStore (thread-safe, map-backed)
//   - Incident response Engine with ProcessEvent, TriageIncident,
//     ExecutePlaybook, EscalateIncident, ResolveIncident
//   - Built-in playbooks: FedRAMP IR-4, FedRAMP IR-5,
//     SOC2 CC6.1, NIST 800-171 IR.1
//   - Built-in detection rules mapping correlation patterns to
//     incidents
//   - Compliance mapping helpers (FedRAMP, SOC2, NIST 800-171)
//   - PostgreSQL migration (007_incident.sql)
//
// Future (v2.0+)
//
//   - PostgreSQL store (PostgresIncidentStore)
//   - Webhook notifications (Slack, PagerDuty, email)
//   - SIEM integration (Splunk, Elastic, Sentinel)
//   - Incident deduplication and merging
//   - SLA tracking and breach notifications
//   - Rich query API (full-text search, aggregation)
//
// =========================================================================
package incident
