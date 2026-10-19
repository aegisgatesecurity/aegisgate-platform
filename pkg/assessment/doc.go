// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Posture Assessment Module
// =========================================================================
//
// The assessment package provides continuous security posture assessment
// capabilities for the AegisGate Platform.
//
// Key Features:
//   - Multi-framework compliance mapping (NIST AI RMF, FedRAMP, CMMCL2, etc.)
//   - Scheduled assessment execution with configurable intervals
//   - ML-assisted detection gap analysis (ONNX model, heuristic fallback)
//   - PDF report generation with signed attestations
//   - IOC feed integration for threat-aware scoring
//   - Dashboard data aggregation for real-time posture visibility
//
// The assessment scheduler runs periodically, evaluating the platform's
// detection coverage against known threat patterns and compliance
// requirements. Results are stored with cryptographic attestation
// for audit trail integrity.
//
// =========================================================================

package assessment
