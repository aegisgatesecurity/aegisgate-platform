// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Trust Score Engine
// =========================================================================
//
// The Trust Score Engine calculates real-time trust scores for AI agents
// based on behavioral analysis, compliance history, and anomaly detection.
//
// Trust Score Formula:
//
//	TrustScore = BaseScore × BehaviorMultiplier × ComplianceMultiplier
//
// Where:
//   - BaseScore: 0-100 (starts at 100)
//   - BehaviorMultiplier: 0.0-1.5 (based on deviation from baseline)
//   - ComplianceMultiplier: 0.0-1.5 (based on contract compliance)
//
// =========================================================================

package score
