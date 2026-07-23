// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOC 2 Audit Automation (v3.8)
// =========================================================================
//
// Package soc2 provides SOC 2 Type I/II audit automation for the
// AegisGate platform. It composes evidence from existing compliance
// scans, attestation envelopes, and policy templates into structured
// workpapers and audit reports suitable for a SOC 2 examination.
//
// The package produces three artifact types:
//   - ControlEvidence: per-control evidence collections from scans,
//     attestations, benchmarks, audit logs, and policy templates.
//   - Workpaper: per-TSC audit documentation with procedures, results,
//     and conclusions.
//   - SOC2AuditReport: the top-level audit report that aggregates
//     evidence, policies, and workpapers with an optional signed
//     attestation envelope.
//
// Usage:
//
//   collector := soc2.NewEvidenceCollector(config, scanner)
//   evidence, err := collector.Collect(ctx, start, end)
//   workpapers, err := soc2.GenerateWorkpapers(evidence, start, end, org, auditor)
//   report, err := builder.Build(ctx)
//
// The report can be signed with SignReport() using the attestation
// envelope system (Type "audit.soc2.v1"), producing a tamper-evident
// artifact suitable for third-party verification.
//
// References:
//   - AICPA Trust Services Criteria 2017 (revised 2022)
//   - AICPA SOC 2 Type II Examination Guide
//
// =========================================================================

package soc2
